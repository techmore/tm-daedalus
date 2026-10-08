"""Exercise shipped event helpers, broadcaster and SQLite replay without Flask."""
import ast
import json
from pathlib import Path
from types import ModuleType
import uuid
import zipfile

import pytest


def runtime():
    path = Path(__file__).parents[1] / 'src/daedalus/agent_bundle/nmapui-source.zip'
    with zipfile.ZipFile(path) as archive:
        def source(name):
            return archive.read('daedalus-nmapui-source/nmapui/' + name).decode()
        jobs = ModuleType('packaged_jobs')
        exec(compile(source('jobs.py'), 'packaged_jobs.py', 'exec'), jobs.__dict__)
        database = ModuleType('packaged_database')
        exec(compile(source('runtime_db.py'), 'packaged_database.py', 'exec'), database.__dict__)
        namespace = {}
        for filename, names in [('scan_runtime.py', {'make_broadcast_emit'}),
                                ('runtime_log.py', {'append_runtime_log'}),
                                ('app_bindings.py', {'_log_runtime_event', 'build_event_helpers'})]:
            tree = ast.parse(source(filename))
            tree.body = [node for node in tree.body if isinstance(node, ast.FunctionDef) and node.name in names]
            exec(compile(tree, filename, 'exec'), namespace)
    namespace['emit_to_client_runtime'] = lambda socketio, sid, event, data=None: socketio.emit(event, data, to=sid)
    def raw_progress(**kwargs):
        raise AssertionError('Progress bypassed grouped source envelopes')
    namespace['update_job_progress_runtime'] = raw_progress
    return jobs, database, namespace['build_event_helpers']


@pytest.mark.parametrize('job_type', ['scan', 'report'])
def test_packaged_progress_reaches_bridge_and_durable_replay(tmp_path, job_type):
    jobs, database, build = runtime()
    path = tmp_path / 'runtime.db'
    store = database.create_runtime_state_store(path)
    registry = jobs.ClientJobRegistry(runtime_store=store)
    broadcaster = jobs.ScanBroadcaster()
    broadcaster.register_client('browser')
    broadcaster.register_client('bridge')
    broadcaster.set_bridge_client('bridge')
    emitted = []
    socket = type('Socket', (), {'emit': lambda self, event, data=None, to=None: emitted.append((to, event, data))})()
    helpers = build(socketio=socket, job_registry=registry, broadcaster=broadcaster, runtime_store=store)
    assert registry.start('owner', job_type, {'target': '127.0.0.1'})
    run_id = registry.get('owner', job_type)['source_job_id']
    broadcaster.start_job('owner', job_type, source_job_id=run_id)
    for progress in [5, 35, 60, 100]:
        helpers['update_job_progress']('owner', job_type, phase=f'phase-{progress}',
                                       message=f'At {progress}', progress=progress, details={'count': 1})
    registry.complete('owner', job_type)
    helpers['emit_job_status']('owner', job_type)
    envelopes = [data for to, event, data in emitted if to == 'bridge' and event == 'daedalus_event']
    assert [row['payload']['details']['progress'] for row in envelopes] == [5, 35, 60, 100, 100]
    assert [row['payload']['status'] for row in envelopes] == ['running'] * 4 + ['completed']
    assert {row['source_job_id'] for row in envelopes} == {run_id}
    assert {row['source_job_type'] for row in envelopes} == {job_type}
    assert len({str(uuid.UUID(row['client_event_id'])) for row in envelopes}) == 5
    assert all(row['occurred_at'].endswith('+00:00') for row in envelopes)
    assert all(row['payload']['details']['target'] == '127.0.0.1' for row in envelopes)
    assert all(row['payload']['details']['count'] == 1 for row in envelopes)
    assert not any(to == 'bridge' and event == 'job_status' for to, event, _ in emitted)
    assert len([1 for to, event, _ in emitted if to == 'browser' and event == 'job_status']) == 5
    replay = broadcaster.get_bridge_replay_buffer('owner', job_type)
    assert replay == envelopes
    reopened = database.create_runtime_state_store(path)
    saved = reopened.list_job_events(job_id=f'source-job:{run_id}')
    assert [row['source_event'] for row in saved] == envelopes
    assert json.loads(json.dumps(envelopes))[0]['payload']['details']['progress'] == 5
