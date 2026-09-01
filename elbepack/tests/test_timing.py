# ELBE - Debian Based Embedded Rootfilesystem Builder
# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: 2026 Linutronix GmbH

import re
import sys

import pytest

from elbepack.log import open_logging
from elbepack.timing import phase

_LINE_RE = re.compile(
    r'ELBE-TIMING ph=(?P<ph>[BE]) ts=(?P<ts>\d+) pid=(?P<pid>\d+) '
    r'tid=(?P<tid>\d+) name=(?P<name>\S+)$'
)


def _run_and_capture(capsys, func):
    cleanup = open_logging(streams=sys.stdout)
    try:
        func()
    finally:
        cleanup()
    return [line for line in capsys.readouterr().out.splitlines() if 'ELBE-TIMING' in line]


def test_phase_emits_matching_begin_end(capsys):
    lines = _run_and_capture(capsys, lambda: None)
    assert lines == []

    def do_phase():
        with phase('test.example'):
            pass

    lines = _run_and_capture(capsys, do_phase)
    assert len(lines) == 2

    begin = _LINE_RE.search(lines[0])
    end = _LINE_RE.search(lines[1])
    assert begin is not None
    assert end is not None

    assert begin.group('ph') == 'B'
    assert end.group('ph') == 'E'
    assert begin.group('name') == end.group('name') == 'test.example'
    assert int(end.group('ts')) >= int(begin.group('ts'))
    assert begin.group('pid') == end.group('pid')
    assert begin.group('tid') == end.group('tid')


def test_phase_emits_end_marker_even_on_exception(capsys):
    def do_phase():
        with pytest.raises(ValueError):
            with phase('test.raises'):
                raise ValueError('boom')

    lines = _run_and_capture(capsys, do_phase)
    assert len(lines) == 2
    assert _LINE_RE.search(lines[0]).group('ph') == 'B'
    assert _LINE_RE.search(lines[1]).group('ph') == 'E'


def test_nested_phases_emit_in_stack_order(capsys):
    def do_phases():
        with phase('outer'):
            with phase('inner'):
                pass

    lines = _run_and_capture(capsys, do_phases)
    names = [_LINE_RE.search(line).group('name') for line in lines]
    phs = [_LINE_RE.search(line).group('ph') for line in lines]
    assert list(zip(names, phs)) == [
        ('outer', 'B'),
        ('inner', 'B'),
        ('inner', 'E'),
        ('outer', 'E'),
    ]
