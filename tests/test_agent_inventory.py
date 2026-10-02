"""Anonymous inventory and bounded journal fixtures; no live host audit."""
import ctypes
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import Mock, patch

import httpx
from daedalus.agent import NmapUIBridge, _host_inventory, _total_memory_bytes, _diagnostics_result


class HostInventoryTests(unittest.TestCase):
    def test_linux_public_scalars_and_custom_kernel_suffix_removed(self):
        with patch('daedalus.agent.platform.system', return_value='Linux'), patch('daedalus.agent.platform.release', return_value='6.8.12-private-hostname'), patch('daedalus.agent.platform.machine', return_value='x86_64'), patch('daedalus.agent.os.cpu_count', return_value=8), patch('daedalus.agent.os.sysconf', side_effect=[1024, 4096]), patch('daedalus.agent.subprocess.run') as run:
            result = _host_inventory()
        self.assertEqual(result, {'platform': 'Linux', 'os_version': '6.8.12', 'architecture': 'x86_64', 'cpu_count': 8, 'total_memory_bytes': 4194304})
        run.assert_not_called()

    def test_macos_fixed_memory_query_no_command_or_identifier(self):
        def query(name, output, size, new_value, new_size):
            self.assertEqual(name, b'hw.memsize')
            self.assertIsNone(new_value)
            self.assertEqual(new_size, 0)
            output._obj.value = 16 * 1024**3
            size._obj.value = ctypes.sizeof(ctypes.c_uint64)
            return 0
        function = Mock(side_effect=query)
        with patch('daedalus.agent.ctypes.CDLL', return_value=Mock(sysctlbyname=function)) as library:
            self.assertEqual(_total_memory_bytes('Darwin'), 16 * 1024**3)
        library.assert_called_once_with('/usr/lib/libSystem.B.dylib', use_errno=True)

    def test_unavailable_and_invalid_scalars_are_unknown(self):
        for system, operation in [('Linux', 'os.sysconf'), ('Darwin', 'ctypes.CDLL')]:
            with patch('daedalus.agent.'+operation, side_effect=OSError('fixture unavailable')):
                self.assertIsNone(_total_memory_bytes(system))
        self.assertIsNone(_total_memory_bytes('Windows'))
        for values in ([-1, 4096], [2**61, 4096]):
            with patch('daedalus.agent.os.sysconf', side_effect=values):
                self.assertIsNone(_total_memory_bytes('Linux'))
        with patch('daedalus.agent.platform.system', side_effect=OSError()), patch('daedalus.agent.platform.machine', side_effect=OSError()), patch('daedalus.agent.os.cpu_count', side_effect=OSError()):
            self.assertEqual(_host_inventory(), {'platform': 'unknown', 'os_version': None, 'architecture': 'unknown', 'cpu_count': None, 'total_memory_bytes': None})

    def test_unknown_architecture_and_non_numeric_version_not_transmitted(self):
        with patch('daedalus.agent.platform.system', return_value='Windows'), patch('daedalus.agent.platform.release', return_value='private-hostname'), patch('daedalus.agent.platform.machine', return_value='private-serial'), patch('daedalus.agent.os.cpu_count', return_value=None):
            result = _host_inventory()
        self.assertEqual(result['architecture'], 'unknown')
        self.assertIsNone(result['os_version'])
        self.assertNotIn('private', json.dumps(result))

    def test_result_over_limit_keeps_complete_versioned_inventory(self):
        evidence = {'schema_version': 1, 'bridge_version': '0.1.0', 'platform': 'Linux', 'os_version': '6.8', 'architecture': 'x86_64', 'cpu_count': 8, 'total_memory_bytes': None, 'nmapui_version': 'x'*1100}
        encoded = _diagnostics_result(evidence)
        self.assertLessEqual(len(encoded), 1000)
        decoded = json.loads(encoded)
        self.assertTrue(decoded['operational_fields_omitted'])
        self.assertEqual(decoded['cpu_count'], 8)
        for unexpected in ['x'*10000, {'unexpected': object()}, 2**5000]:
            oversized = {key: unexpected for key in evidence}
            encoded = _diagnostics_result(oversized)
            self.assertLessEqual(len(encoded), 1000)
            self.assertEqual(json.loads(encoded)['schema_version'], 1)

    def test_diagnostics_command_preserves_json_in_private_journal_and_replays(self):
        with tempfile.TemporaryDirectory(prefix='daedalus-inventory-fixture-') as temporary:
            config = {'agent_id': 7, 'server': 'https://fixture.invalid', 'agent_token': 'synthetic-token'}
            bridge = NmapUIBridge(config, 'http://127.0.0.1:9000', spool_dir=Path(temporary))
            self.addCleanup(bridge.http.close)
            bridge._read_nmapui_health = Mock(return_value={'nmapui_version': 'v2026.9', 'nmapui_ready': True})
            bridge._request = Mock(side_effect=[httpx.Response(200, request=httpx.Request('GET', 'https://fixture.invalid'), json={'command': {'id': 3, 'action': 'collect_diagnostics', 'target': None}}), httpx.ConnectError('fixture offline')])
            with patch('daedalus.agent._host_inventory', return_value={'platform': 'Darwin', 'os_version': '26.0', 'architecture': 'arm64', 'cpu_count': 8, 'total_memory_bytes': 16*1024**3}), patch('daedalus.agent.shutil.disk_usage', return_value=Mock(free=1024)):
                bridge._run_one_command()
            entries = bridge.command_journal.pending()
            self.assertEqual(len(entries), 1)
            result = entries[0][1]['result']
            decoded = json.loads(result)
            self.assertLessEqual(len(result), 1000)
            self.assertEqual(decoded['schema_version'], 1)
            self.assertEqual(decoded['total_memory_bytes'], 16*1024**3)
            self.assertIn('pending_scan_events', decoded)
            self.assertIn('pending_command_results', decoded)
            self.assertNotIn('synthetic-token', result)
            restarted = NmapUIBridge(config, 'http://127.0.0.1:9000', spool_dir=Path(temporary))
            self.addCleanup(restarted.http.close)
            restarted._request = Mock(return_value=httpx.Response(200, json={'ok': True, 'command_id': 3, 'status': 'succeeded'}))
            restarted._flush_command_results()
            self.assertEqual(restarted._request.call_args.kwargs['json']['result'], result)
            self.assertFalse(restarted.command_journal.pending())
