#!/usr/bin/env python3
"""Exercise the real root deployment helper in a disposable, offline container."""
from __future__ import annotations

import argparse
from pathlib import Path
import shutil
import subprocess
import tempfile
import uuid

if __package__:
    from .deploy_incus import CREATE_CONTAINER_STAGING
else:
    from deploy_incus import CREATE_CONTAINER_STAGING


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--runtime', choices=('docker', 'podman'), default=None)
    parser.add_argument('--image', default='ubuntu:24.04')
    args = parser.parse_args()
    runtime = args.runtime or shutil.which('docker') or shutil.which('podman')
    if not runtime:
        parser.error('Docker or Podman is required for the isolated fixture')
    root = Path(__file__).resolve().parents[1]
    with tempfile.TemporaryDirectory(prefix='daedalus-staging-fixture-') as directory:
        bootstrap = Path(directory) / 'bootstrap.sh'
        bootstrap.write_text(CREATE_CONTAINER_STAGING)
        name = 'daedalus-staging-fixture-' + uuid.uuid4().hex
        command = [runtime, 'run', '--rm', '--name', name, '--network', 'none',
                   '--cap-drop', 'ALL', '--cap-add', 'CHOWN', '--cap-add', 'DAC_OVERRIDE', '--cap-add', 'FOWNER',
                   '--cap-add', 'SETUID', '--cap-add', 'SETGID',
                   '--security-opt', 'no-new-privileges',
                   '-v', f'{root / "scripts/deploy_incus_remote.sh"}:/fixture/helper.sh:ro',
                   '-v', f'{root / "scripts/fixtures/deploy-staging.sh"}:/fixture/test.sh:ro',
                   '-v', f'{bootstrap}:/fixture/bootstrap.sh:ro',
                   args.image, 'bash', '/fixture/test.sh']
        try:
            return subprocess.run(command, check=False, timeout=120).returncode
        finally:
            # Also remove our disposable fixture if the client was interrupted/timed out.
            subprocess.run([runtime, 'rm', '-f', name], capture_output=True, check=False, timeout=30)


if __name__ == '__main__':
    raise SystemExit(main())
