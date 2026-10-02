"""Synthetic source envelopes and HTTP mocks only; never execute Nmap."""
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import Mock
import uuid

import httpx
from daedalus.agent import NmapUIBridge


class AgentRunGroupingTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix='daedalus-run-bridge-')
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)

    def bridge(self):
        bridge = NmapUIBridge({'agent_id': 7, 'server': 'https://fixture.invalid', 'agent_token': 'synthetic-local-token'}, 'http://127.0.0.1:9000', spool_dir=self.root)
        self.addCleanup(bridge.http.close)
        return bridge

    def event(self, **changes):
        return {'client_event_id': str(uuid.uuid4()), 'occurred_at': '2026-09-29T12:00:00+00:00', 'event_name': 'scan_results', 'payload': [{'ip': '127.0.0.1'}], 'source_job_id': str(uuid.uuid4()), 'source_job_type': 'scan', **changes}

    def test_inline_and_large_metadata_survive_offline_restart_and_replay(self):
        bridge = self.bridge()
        receive = bridge.sio.handlers['/']['*']
        source_id = str(uuid.uuid4())
        small = self.event(source_job_id=source_id)
        large = self.event(source_job_id=source_id, payload={'text': 'x' * 600000})
        for event in [small, large, small]: receive('daedalus_event', event)
        self.assertEqual(len(list(self.root.glob('*.json'))), 2)
        bridge._request = Mock(side_effect=httpx.ConnectError('offline fixture'))
        bridge._flush_events()
        restarted = self.bridge()
        restarted._request = Mock(return_value=httpx.Response(200, json={'ok': True, 'event_id': 1}))
        restarted._flush_events()
        calls = restarted._request.call_args_list
        self.assertEqual([call.args[1].rsplit('/', 1)[-1] for call in calls], ['events', 'event-artifacts'])
        self.assertEqual([call.kwargs['json'] for call in calls], [small, large])
        self.assertFalse(list(self.root.glob('*.json')))

    def test_legacy_envelope_stays_ungrouped(self):
        bridge = self.bridge()
        legacy = self.event()
        legacy.pop('source_job_id'); legacy.pop('source_job_type')
        bridge.sio.handlers['/']['*']('daedalus_event', legacy)
        self.assertEqual(json.loads(next(self.root.glob('*.json')).read_text()), legacy)

    def test_malformed_or_half_grouping_is_rejected(self):
        bridge = self.bridge()
        for changes in [{'source_job_id': None}, {'source_job_type': None}, {'source_job_id': 'not-uuid'}, {'source_job_type': 'command'}, {'source_job_type': ['scan']}]:
            bridge.sio.handlers['/']['*']('daedalus_event', self.event(**changes))
        self.assertFalse(list(self.root.glob('*.json')))

    def test_only_modern_metadata_handshake_suppresses_raw_job_status(self):
        bridge = self.bridge()
        receive = bridge.sio.handlers['/']['*']
        receive('daedalus_protocol', {'version': 1})
        receive('job_status', {'status': 'running'})
        self.assertEqual(len(list(self.root.glob('*.json'))), 1)
        receive('daedalus_protocol', {'version': 1, 'source_job_metadata': True})
        receive('job_status', {'status': 'completed'})
        source = self.event(event_name='job_status', payload={'status': 'completed'})
        receive('daedalus_event', source)
        self.assertEqual(len(list(self.root.glob('*.json'))), 2)
        bridge.sio.handlers['/']['disconnect']('synthetic reconnect')
        self.assertFalse(bridge.source_job_metadata)
