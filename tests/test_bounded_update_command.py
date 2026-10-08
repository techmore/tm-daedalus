import subprocess
import sys
import time
from unittest.mock import patch

import pytest

from daedalus.agent import _bounded_update_command, UpdateOutputIncomplete


def test_capture_keeps_streams_separate_and_waits_for_exit():
    result = _bounded_update_command([sys.executable, '-c',
        'import sys; print("catalog"); print("tool status", file=sys.stderr); sys.exit(7)'], timeout=5)
    assert result.returncode == 7
    assert result.stdout == 'catalog\n'
    assert result.stderr == 'tool status\n'


@pytest.mark.parametrize('stream', ['stdout', 'stderr'])
def test_large_stream_stops_without_retaining_unbounded_data(stream):
    started = time.monotonic()
    with pytest.raises(UpdateOutputIncomplete):
        _bounded_update_command([sys.executable, '-c',
            f'import sys; sys.{stream}.buffer.write(b"x" * (1024 * 1024)); sys.{stream}.flush()'], timeout=5)
    assert time.monotonic() - started < 5


def test_combined_limit_applies_across_both_streams():
    with pytest.raises(UpdateOutputIncomplete):
        _bounded_update_command([sys.executable, '-c',
            'import sys; sys.stdout.buffer.write(b"x" * 80000); sys.stdout.flush(); '
            'sys.stderr.buffer.write(b"y" * 80000); sys.stderr.flush()'], timeout=5)


def test_deadline_covers_a_child_that_retains_the_parent_pipe():
    started = time.monotonic()
    with pytest.raises(subprocess.TimeoutExpired):
        _bounded_update_command([sys.executable, '-c',
            'import os,time; pid=os.fork(); time.sleep(20) if pid==0 else None'], timeout=0.2)
    assert time.monotonic() - started < 3


def test_stdin_is_closed_and_invalid_encoding_is_incomplete():
    result = _bounded_update_command([sys.executable, '-c',
        'import sys; print(len(sys.stdin.read()))'], timeout=5)
    assert result.stdout == '0\n'
    with pytest.raises(UpdateOutputIncomplete):
        _bounded_update_command([sys.executable, '-c',
            'import sys; sys.stdout.buffer.write(b"\\xff")'], timeout=5)


def test_normal_completion_does_not_signal_a_reaped_group():
    with patch('daedalus.agent.os.killpg') as kill:
        result = _bounded_update_command([sys.executable, '-c', 'print("complete")'], timeout=5)
    assert result.stdout == 'complete\n'
    kill.assert_not_called()


@pytest.mark.parametrize('platform_name', ['Darwin', 'Linux'])
def test_incomplete_catalog_never_becomes_no_updates(platform_name):
    from daedalus.agent import NmapUIBridge
    bridge = NmapUIBridge.__new__(NmapUIBridge)
    with patch('daedalus.agent.platform.system', return_value=platform_name), \
         patch('daedalus.agent.Path.is_file', return_value=True), \
         patch('daedalus.agent._bounded_update_command', side_effect=UpdateOutputIncomplete('capture limit')):
        assert bridge._check_os_updates()['status'] == 'unknown'


@pytest.mark.parametrize('output', [
    'No new software available.\nAn unexpected tool error\n',
    'Previous response was: No new software available.\n',
    '* Label: Safari-26.1\nNo new software available.\n',
])
def test_macos_clean_status_requires_an_unambiguous_complete_response(output):
    from daedalus.agent import NmapUIBridge
    bridge = NmapUIBridge.__new__(NmapUIBridge)
    with patch('daedalus.agent.platform.system', return_value='Darwin'), \
         patch('daedalus.agent.Path.is_file', return_value=True), \
         patch('daedalus.agent._bounded_update_command', return_value=subprocess.CompletedProcess([], 0, output, '')):
        assert bridge._check_os_updates()['status'] == 'unknown'


@pytest.mark.parametrize('stderr,status', [
    ('\nWARNING: apt does not have a stable CLI interface. Use with caution in scripts.\n', 'no_updates'),
    ('An unexpected package index error\n', 'unknown'),
])
def test_linux_standard_warning_is_distinct_from_unknown_stderr(stderr, status):
    from daedalus.agent import NmapUIBridge
    bridge = NmapUIBridge.__new__(NmapUIBridge)
    with patch('daedalus.agent.Path.is_file', return_value=True), \
         patch('daedalus.agent._bounded_update_command', return_value=subprocess.CompletedProcess([], 0, 'Listing...\n', stderr)):
        assert bridge._check_linux_updates('now')['status'] == status
