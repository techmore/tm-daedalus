"""Exercise the registry shipped to scanners, rather than a sibling checkout."""
import hashlib
import json
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from threading import Barrier
from types import ModuleType
import zipfile


def bundled_registry():
    path = Path(__file__).parents[1] / 'src/daedalus/agent_bundle/nmapui-source.zip'
    with zipfile.ZipFile(path) as archive:
        source = archive.read('daedalus-nmapui-source/nmapui/jobs.py')
    module = ModuleType('packaged_nmapui_jobs')
    exec(compile(source, 'packaged_nmapui_jobs.py', 'exec'), module.__dict__)
    return module.ClientJobRegistry()


def test_packaged_gate_is_atomic_with_new_job_admission():
    for _ in range(100):
        registry = bundled_registry()
        barrier = Barrier(2)
        def job():
            barrier.wait()
            return registry.start('owner', 'scan')
        def gate():
            barrier.wait()
            return registry.acquire_maintenance()
        with ThreadPoolExecutor(max_workers=2) as pool:
            a, b = pool.submit(job), pool.submit(gate)
            started, token = a.result(), b.result()
        assert bool(started) != bool(token)
        if token:
            assert registry.snapshot()['maintenance_active']
            assert token not in str(registry.snapshot())
            assert not registry.start('other', 'report')
            assert not registry.release_maintenance('0' * 32)
            assert registry.release_maintenance(token)
            assert registry.start('other', 'report')
        else:
            assert registry.cancel('owner', 'scan')
            assert registry.acquire_maintenance() is None
            registry.complete('owner', 'scan')
            registry.attach_process('owner', 'scan', object())
            assert registry.acquire_maintenance() is None
            registry.clear_process('owner', 'scan')
            assert registry.acquire_maintenance()


def test_packaged_source_digest_covers_exact_runtime_bytes():
    path = Path(__file__).parents[1] / 'src/daedalus/agent_bundle/nmapui-source.zip'
    with zipfile.ZipFile(path) as archive:
        files = {n.removeprefix('daedalus-nmapui-source/'): archive.read(n) for n in archive.namelist()}
    manifest = json.loads(files.pop('manifest.json'))
    digest = hashlib.sha256()
    for name, contents in sorted(files.items()):
        digest.update(name.encode()); digest.update(b'\0'); digest.update(contents); digest.update(b'\0')
    assert digest.hexdigest() == manifest['source_tree_sha256']
    assert len(files) == manifest['file_count']
