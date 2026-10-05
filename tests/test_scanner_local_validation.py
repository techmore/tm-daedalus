"""Fixtures for real smoke receipt assertions; these never launch a scanner."""
import importlib.util
from pathlib import Path
import unittest

spec = importlib.util.spec_from_file_location("scanner_local_validation", Path(__file__).parents[1] / "scripts" / "validate_scanner_local.py")
validation = importlib.util.module_from_spec(spec)
spec.loader.exec_module(validation)


class ScannerLocalEvidenceTests(unittest.TestCase):
    def test_repeat_coverage_requires_exact_loopback_and_command_provenance(self):
        import copy
        comparison = {"coverage": {"comparable": True, "reasons": [],
            "previous_targets": ["127.0.0.1/32"], "current_targets": ["127.0.0.1/32"]},
            "previous_run": {"covered_targets_source": "successful_daedalus_single_ip_command"},
            "current_run": {"covered_targets_source": "successful_daedalus_single_ip_command"}}
        validation.validate_loopback_comparison_coverage(comparison)
        for change in (lambda c: c['coverage'].update(comparable=False),
                       lambda c: c['coverage'].update(current_targets=['127.0.0.0/8']),
                       lambda c: c['coverage'].update(reasons=['incomplete']),
                       lambda c: c['current_run'].clear()):
            bad = copy.deepcopy(comparison)
            change(bad)
            with self.assertRaises(RuntimeError):
                validation.validate_loopback_comparison_coverage(bad)

    def test_readiness_refuses_exited_process_before_accepting_response(self):
        from unittest.mock import Mock, patch
        process = Mock()
        process.poll.return_value = 1
        predicate = Mock(return_value=True)
        with patch.object(validation.time, 'sleep') as sleep:
            with self.assertRaisesRegex(RuntimeError, 'exited before readiness'):
                validation.wait_for(predicate, process=process)
        predicate.assert_not_called()
        sleep.assert_not_called()

    def test_readiness_accepts_live_owned_process(self):
        from unittest.mock import Mock
        process = Mock()
        process.poll.return_value = None
        self.assertEqual(validation.wait_for(lambda: 'ready', process=process), 'ready')

    def test_managed_validation_refuses_root_or_non_linux_before_manager_operations(self):
        import sys
        from unittest.mock import patch
        for platform, uid in [('darwin', 501), ('linux', 0)]:
            with patch.object(validation.sys, 'platform', platform), patch.object(validation.os, 'getuid', return_value=uid), patch.object(validation.shutil, 'which', return_value='/usr/bin/nmap'), patch.object(validation.subprocess, 'run') as run:
                with self.assertRaisesRegex(RuntimeError, 'disposable non-root Linux'):
                    validation.validate(Path(sys.executable), Path('/unused-receipt'), managed_linux=True)
                run.assert_not_called()

    def test_managed_validation_refuses_existing_installation_without_running_services(self):
        import sys
        import tempfile
        from unittest.mock import patch
        with tempfile.TemporaryDirectory() as temporary:
            home = Path(temporary)
            (home / '.config/daedalus').mkdir(parents=True)
            with patch.object(validation.sys, 'platform', 'linux'), patch.object(validation.os, 'getuid', return_value=1001), patch.object(validation.Path, 'home', return_value=home), patch.object(validation.shutil, 'which', return_value='/usr/bin/nmap'), patch.object(validation.subprocess, 'run') as run:
                with self.assertRaisesRegex(RuntimeError, 'Existing Daedalus'):
                    validation.validate(Path(sys.executable), home / 'receipt', managed_linux=True)
                run.assert_not_called()

    def test_recovery_requires_exact_original_identity_and_single_side_effect(self):
        import copy
        pending = [{'client_event_id': 'event-1', 'occurred_at': '2026-09-29T10:00:00+00:00', 'source_job_id': 'run-one', 'source_job_type': 'scan', 'event_name': 'job_status'}]
        history = copy.deepcopy(pending)
        history[0]['occurred_at'] = '2026-09-29T10:00:00Z'
        invocation = ['nmap', '-sT', '-p', '12345', '127.0.0.1']
        proof = validation.validate_recovery_evidence(pending, history, 'run-one', [invocation], 12345)
        self.assertEqual(proof['pending_events_recovered'], 1)
        for mutation in (lambda rows: rows.append(copy.deepcopy(rows[0])), lambda rows: rows[0].update(source_job_id='other'), lambda rows: rows[0].update(occurred_at='2026-09-29T10:00:01Z'), lambda rows: rows[0].update(client_event_id='other'), lambda rows: rows[0].update(event_name='other')):
            bad = copy.deepcopy(history)
            mutation(bad)
            with self.assertRaises(RuntimeError): validation.validate_recovery_evidence(pending, bad, 'run-one', [invocation], 12345)
        for invocations in ([], [invocation, invocation]):
            with self.assertRaises(RuntimeError): validation.validate_recovery_evidence(pending, history, 'run-one', invocations, 12345)

    def test_saved_hosts_require_exact_loopback_and_actual_port(self):
        hosts, ports = validation.validate_host_evidence([{"ip": "127.0.0.1", "ports": [{"port": "12345", "protocol": "tcp", "state": "open"}]}], 12345)
        self.assertEqual((len(hosts), len(ports)), (1, 1))
        for payload in ([{"ip": "127.0.0.1", "ports": [{"port": "12345"}]}], [{"ip": "127.0.0.1", "ports": [{"port": "12345", "protocol": "udp", "state": "open"}]}], [], [{"ip": "192.168.1.1", "ports": [{"port": "12345", "protocol": "tcp", "state": "open"}]}], [{"ip": "127.0.0.1", "ports": [{"port": "80"}]}]):
            with self.assertRaises(RuntimeError): validation.validate_host_evidence(payload, 12345)

    def test_actual_xml_requires_host_up_and_listener_open(self):
        xml = '<nmaprun><host><status state="up"/><address addr="127.0.0.1"/><ports><port portid="12345" protocol="tcp"><state state="open"/></port></ports></host></nmaprun>'
        validation.validate_xml_evidence(xml.encode(), 12345)
        for bad in (xml.replace('protocol="tcp"', 'protocol="udp"'), xml.replace('state="open"', 'state="closed"'), xml.replace('state="up"', 'state="down"'), xml.replace('127.0.0.1', '192.168.1.1')):
            with self.assertRaises(RuntimeError): validation.validate_xml_evidence(bad.encode(), 12345)

    def test_grouped_history_requires_exact_run_and_saved_completion(self):
        import copy
        event = {"id": 1, "source_job_id": "run-one", "source_job_type": "scan"}
        detail = {"truncated": False, "run": {"source_job_id": "run-one", "event_count": 2, "status": "completed", "status_evidence_event_id": 2}, "events": [event, {"id": 2, "source_job_id": "run-one", "event_name": "job_status", "payload": {"status": "completed"}}]}
        validation.validate_run_evidence(detail, event)
        for mutation in (lambda d: d.update(truncated=True), lambda d: d["run"].update(event_count=3), lambda d: d["run"].update(status="unknown"), lambda d: d["events"][1].update(source_job_id="other"), lambda d: d["events"][1]["payload"].update(status="running"), lambda d: d["run"].update(group_metadata_conflict=True)):
            bad = copy.deepcopy(detail)
            mutation(bad)
            with self.assertRaises(RuntimeError):
                validation.validate_run_evidence(bad, event)
