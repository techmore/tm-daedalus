import os
from pathlib import Path
import subprocess
import sys


def test_clean_linux_install_generates_private_local_credentials(tmp_path):
    root = Path(__file__).resolve().parents[1]
    script = (root / 'src/daedalus/agent_bundle/install-service-linux.sh').read_text()
    prefix = script.split('command -v nmap')[0]
    uname = tmp_path / 'uname'
    uname.write_text('#!/bin/sh\nprintf Linux\n')
    uname.chmod(0o700)
    environment = dict(os.environ, PATH=str(tmp_path) + os.pathsep + os.environ['PATH'], PYTHON_BIN=sys.executable)
    environment.pop('NMAPUI_USERNAME', None)
    environment.pop('NMAPUI_PASSWORD', None)
    # Assert inside the child: never print generated credentials.
    check = '\n"$PYTHON_BIN" -c "import os; assert os.environ[\'NMAPUI_USERNAME\']==\'daedalus-local\'; assert len(os.environ[\'NMAPUI_PASSWORD\']) >= 40"\n'
    result = subprocess.run(['sh', '-c', prefix + check, 'installer', 'https://portal.example', 'test scanner'], env=environment, capture_output=True, text=True)
    assert result.returncode == 0, result.stderr
    assert result.stdout == ''


def test_explicit_local_credentials_are_preserved(tmp_path):
    root = Path(__file__).resolve().parents[1]
    prefix = (root / 'src/daedalus/agent_bundle/install-service-linux.sh').read_text().split('command -v nmap')[0]
    uname = tmp_path / 'uname'
    uname.write_text('#!/bin/sh\nprintf Linux\n')
    uname.chmod(0o700)
    environment = dict(os.environ, PATH=str(tmp_path) + os.pathsep + os.environ['PATH'], PYTHON_BIN=sys.executable, NMAPUI_USERNAME='fixture-user', NMAPUI_PASSWORD='fixture-password')
    check = '\n"$PYTHON_BIN" -c "import os; assert os.environ[\'NMAPUI_USERNAME\']==\'fixture-user\'; assert os.environ[\'NMAPUI_PASSWORD\']==\'fixture-password\'"\n'
    result = subprocess.run(['sh', '-c', prefix + check, 'installer', 'https://portal.example', 'test scanner'], env=environment, capture_output=True, text=True)
    assert result.returncode == 0, result.stderr
