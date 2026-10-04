import hashlib
import json
from pathlib import Path
import socket
import tempfile
import threading
import time
import unittest
from unittest.mock import patch

from daedalus.nikto_checks import ScopedProxy, parse_report, run_nikto_check
from daedalus.external_checks import ExternalCheckFailure


class NiktoCollectionTests(unittest.TestCase):
    def report(self, **changes):
        report = {'host':'example.org', 'port':'443', 'end_time':'2026-10-04', 'server_banner':'private banner', 'vulnerabilities':[{'id':'1234','method':'GET','url':'/test?token=synthetic-secret','msg':'Missing header token=synthetic-secret'}]}
        report.update(changes)
        return json.dumps([report]).encode()

    def test_normalization_excludes_raw_queries_banners_and_response_messages(self):
        saved = parse_report(self.report(), 'example.org')
        finding = saved['findings'][0]
        self.assertEqual(finding['path'], '/test')
        self.assertEqual(finding['query_sha256'], hashlib.sha256(b'token=synthetic-secret').hexdigest())
        self.assertNotIn('synthetic-secret', json.dumps(saved))
        self.assertNotIn('private', json.dumps(saved))
        self.assertIn('Missing header', finding['description'])

    def test_unknown_host_port_and_multiple_hosts_are_refused(self):
        for content in (self.report(host='other.example.org'), self.report(port=80), b'[{},{}]'):
            with self.subTest(content=content), self.assertRaises(ValueError):
                parse_report(content, 'example.org')

    def test_absolute_urls_and_invalid_identifiers_are_refused(self):
        for field,value in [('url','https://other.example.org/a'),('url','//other.example.org/a'),('url','/a\nheader'),('id','../x'),('method','GET\n')]:
            row={'id':'1','method':'GET','url':'/valid'}
            row[field]=value
            with self.subTest(field=field,value=value), self.assertRaises(ValueError):
                parse_report(self.report(vulnerabilities=[row]), 'example.org')

    def test_duplicate_findings_are_stable_and_sorted(self):
        rows=[{'id':'2','method':'GET','url':'/b'},{'id':'1','method':'GET','url':'/a'},{'id':'2','method':'GET','url':'/b'}]
        result=parse_report(self.report(vulnerabilities=rows), 'example.org')
        self.assertEqual([r['test_id'] for r in result['findings']], ['1','2'])

    def test_https_uri_does_not_include_conflicting_port_argument(self):
        from types import SimpleNamespace
        with tempfile.TemporaryDirectory() as temporary:
            executable=Path(temporary)/'nikto.pl'; executable.write_text('fixture')
            def engine(command, **options):
                self.assertEqual(command[command.index('-host')+1], 'https://example.org')
                self.assertNotIn('-port',command)
                self.assertIn('-useproxy',command)
                self.assertEqual(command[command.index('-Tuning')+1],'x6')
                Path(command[command.index('-output')+1]).write_bytes(self.report(vulnerabilities=[]))
                return SimpleNamespace(returncode=0)
            with patch('daedalus.nikto_checks._public_addresses',return_value=['8.8.8.8']), patch('daedalus.nikto_checks.subprocess.run',side_effect=engine):
                result=run_nikto_check('example.org',executable)
            self.assertNotIn('error_code',result)
            self.assertFalse(result['coverage_complete'])

    def test_missing_report_preserves_safe_failure_diagnostics(self):
        from types import SimpleNamespace
        with tempfile.TemporaryDirectory() as temporary:
            executable=Path(temporary)/'nikto.pl'; executable.write_text('fixture')
            with patch('daedalus.nikto_checks._public_addresses',return_value=['8.8.8.8']), patch('daedalus.nikto_checks.subprocess.run',return_value=SimpleNamespace(returncode=1)):
                result=run_nikto_check('example.org',executable)
            self.assertEqual(result['error_code'],'nikto_report_unavailable')
            self.assertEqual(result['engine_exit_code'],1)
            self.assertEqual(result['proxy_connected_tunnels'],0)
            self.assertEqual(result['proxy_denied_connections'],0)
            self.assertFalse(result['coverage_complete'])

    def test_unavailable_runtime_does_not_resolve_or_start_process(self):
        with patch('daedalus.nikto_checks._public_addresses') as resolve, patch('daedalus.nikto_checks.subprocess.run') as run:
            result=run_nikto_check('example.org',Path('/missing-nikto-fixture'))
        self.assertEqual(result['error_code'],'nikto_runtime_unavailable')
        resolve.assert_not_called(); run.assert_not_called()

    def test_nonpublic_resolution_is_refused_before_process_start(self):
        with tempfile.TemporaryDirectory() as temporary:
            executable=Path(temporary)/'nikto.pl'; executable.write_text('fixture')
            with patch('daedalus.nikto_checks._public_addresses',side_effect=ExternalCheckFailure('private target')), patch('daedalus.nikto_checks.subprocess.run') as run:
                result=run_nikto_check('example.org',executable)
            self.assertEqual(result['error_code'],'public_target_unavailable')
            run.assert_not_called()

    def test_proxy_refuses_private_address_pins(self):
        for address in ('127.0.0.1','10.20.0.117','::1'):
            with self.subTest(address=address), self.assertRaises(ValueError):
                ScopedProxy('example.org',[address],deadline=time.monotonic()+10)

    def test_proxy_refuses_foreign_hosts_ports_and_plain_http(self):
        with ScopedProxy('example.org',['8.8.8.8'],deadline=time.monotonic()+10) as proxy:
            worker=threading.Thread(target=proxy.serve_forever,daemon=True); worker.start()
            try:
                with patch('daedalus.nikto_checks.socket.create_connection') as upstream:
                    for request in (b'CONNECT other.example.org:443 HTTP/1.1',b'CONNECT example.org:80 HTTP/1.1',b'GET http://example.org/ HTTP/1.1'):
                        client=socket.socket(); client.settimeout(2)
                        with client:
                            client.connect(proxy.server_address); client.sendall(request+b'\r\n\r\n')
                            self.assertIn(b'403 Forbidden',client.recv(4096))
                    upstream.assert_not_called()
                self.assertEqual(proxy.denied,3)
            finally:
                proxy.shutdown(); worker.join(timeout=2)

    def test_proxy_uses_only_pinned_address_and_preserves_tunnel_bytes(self):
        upstream,target=socket.socketpair()
        with upstream,target,ScopedProxy('example.org',['8.8.8.8'],deadline=time.monotonic()+10) as proxy:
            worker=threading.Thread(target=proxy.serve_forever,daemon=True); worker.start()
            try:
                with patch('daedalus.nikto_checks.socket.create_connection',return_value=upstream) as connect:
                    client=socket.socket(); client.settimeout(2); target.settimeout(2)
                    with client:
                        client.connect(proxy.server_address)
                        client.sendall(b'CONNECT example.org:443 HTTP/1.1\r\n\r\nTLS-fixture')
                        self.assertIn(b'200 Connection established',client.recv(4096))
                        self.assertEqual(target.recv(4096),b'TLS-fixture')
                        target.sendall(b'TLS-reply')
                        self.assertEqual(client.recv(4096),b'TLS-reply')
                    connect.assert_called_once_with(('8.8.8.8',443),timeout=5)
                self.assertEqual(proxy.connected,1)
            finally:
                proxy.shutdown(); worker.join(timeout=2)
