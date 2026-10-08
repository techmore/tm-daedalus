import hashlib
import io
import json
from pathlib import Path
import stat
import zipfile

import pytest

from daedalus.cis_client_release import FILENAME, ReleaseInvalid, load_release, release_status


def fixture_release(directory: Path, extra=None):
    directory.mkdir(parents=True, exist_ok=True)
    stream = io.BytesIO()
    with zipfile.ZipFile(stream, 'w') as archive:
        archive.writestr('CSP-CIS_Audit.app/Contents/Info.plist', 'integrity fixture; not an Apple-signed release')
        if extra is not None:
            archive.writestr(*extra)
    contents = stream.getvalue()
    manifest = {'schema': 1, 'filename': FILENAME, 'sha256': hashlib.sha256(contents).hexdigest(),
                'signing': 'developer-id-notarized', 'team_id': 'ABCDEFGHIJ',
                'architectures': ['arm64'], 'source_commit': 'a' * 40,
                'verification': {'codesign': True, 'stapler': True, 'gatekeeper': True}}
    (directory / FILENAME).write_bytes(contents)
    (directory / 'manifest.json').write_text(json.dumps(manifest))
    return manifest, contents


def test_installed_release_integrity_and_status(tmp_path):
    manifest, contents = fixture_release(tmp_path)
    assert load_release(tmp_path) == (manifest, contents)
    assert release_status(tmp_path) == {'available': True, 'architectures': ['arm64'],
                                        'source_commit': 'a' * 40, 'sha256': manifest['sha256']}


@pytest.mark.parametrize('field,value', [
    ('schema', True), ('schema', 2), ('filename', '../release.zip'), ('sha256', 'bad'),
    ('signing', 'unsigned'), ('team_id', 'bad'), ('source_commit', 'uncommitted'),
    ('architectures', []), ('architectures', ['arm64', 'arm64']), ('architectures', ['riscv']),
    ('architectures', [True]), ('architectures', 'arm64'), ('verification', None),
    ('verification', {'codesign': True, 'stapler': False, 'gatekeeper': True}),
    ('verification', {'codesign': 1, 'stapler': True, 'gatekeeper': True}),
])
def test_incomplete_or_unsigned_manifest_is_not_distributed(tmp_path, field, value):
    manifest, _ = fixture_release(tmp_path)
    manifest[field] = value
    (tmp_path / 'manifest.json').write_text(json.dumps(manifest))
    with pytest.raises(ReleaseInvalid):
        load_release(tmp_path)
    assert release_status(tmp_path) == {'available': False, 'reason': 'integrity_failed'}


@pytest.mark.parametrize('name', [
    '../outside', '/absolute', 'unexpected/file', 'CSP-CIS_Audit.app/../outside',
    'CSP-CIS_Audit.app/Contents/config.yaml', 'CSP-CIS_Audit.app/Contents/CIS-client.yml',
    'CSP-CIS_Audit.app\\Contents\\file', 'CSP-CIS_Audit.app/Contents/Info.plist',
])
def test_unsafe_duplicate_or_credential_entries_are_rejected(tmp_path, name):
    fixture_release(tmp_path, (name, 'private fixture'))
    with pytest.raises(ReleaseInvalid):
        load_release(tmp_path)


def test_archive_symlinks_are_not_distributed(tmp_path):
    entry = zipfile.ZipInfo('CSP-CIS_Audit.app/Contents/link')
    entry.create_system = 3
    entry.external_attr = (stat.S_IFLNK | 0o777) << 16
    fixture_release(tmp_path, (entry, '../../outside'))
    with pytest.raises(ReleaseInvalid):
        load_release(tmp_path)


@pytest.mark.parametrize('name', ['manifest.json', FILENAME])
def test_release_files_cannot_redirect_to_other_paths(tmp_path, name):
    fixture_release(tmp_path)
    source = tmp_path / name
    moved = tmp_path / ('original-' + name)
    source.rename(moved)
    source.symlink_to(moved)
    with pytest.raises(ReleaseInvalid):
        load_release(tmp_path)


def test_missing_changed_and_partially_installed_releases(tmp_path):
    assert release_status(tmp_path) == {'available': False, 'reason': 'not_published'}
    fixture_release(tmp_path)
    (tmp_path / FILENAME).write_bytes(b'changed')
    assert release_status(tmp_path)['reason'] == 'integrity_failed'
    (tmp_path / FILENAME).unlink()
    assert release_status(tmp_path)['reason'] == 'integrity_failed'


def test_release_integrity_survives_normal_backup_restore(tmp_path, monkeypatch, capsys):
    import sqlite3
    from scripts import backup_data
    from scripts.restore_data import restore_archive, verify_archive
    data = tmp_path / 'data'
    expected = fixture_release(data / 'cis-client-release')
    database = data / 'daedalus.db'
    with sqlite3.connect(database) as connection:
        connection.execute('CREATE TABLE evidence (value TEXT)')
    for name, value in {'DATA_DIR': data, 'BACKUP_DIR': data / 'backups',
                        'DATABASE': database, 'REPORTS': data / 'reports'}.items():
        monkeypatch.setattr(backup_data, name, value)
    assert backup_data.main() == 0
    archive = data / 'backups' / capsys.readouterr().out.strip()
    verify_archive(archive)
    restored = tmp_path / 'restored'
    restore_archive(archive, restored)
    assert load_release(restored / 'cis-client-release') == expected
