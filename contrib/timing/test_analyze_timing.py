# ELBE - Debian Based Embedded Rootfilesystem Builder
# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: 2026 Linutronix GmbH

"""
Offline test harness for analyze_timing.py: feeds it a small hand-written
synthetic log -- simulating a real captured build (an outer 'iglos' process
on pid 100 wrapping a nested 'elbe build' subprocess on pid 200, each with
their own thread id) -- so the parsing/tree-reconstruction/summary/trace
logic can be validated without ever running a real container build.
"""

import json

import analyze_timing

# Timeline (all timestamps in microseconds):
#   pid=100 tid=100                          pid=200 tid=200
#   iglos.build            B 1_000_000
#     iglos.build.run_elbe.extend  B 1_000_000
#                                             elbe.build.install_packages.target B 1_010_000
#                                             elbe.build.install_packages.target E 1_050_000
#                                                                                (40_000us)
#     iglos.build.run_elbe.extend  E 1_060_000                                    (60_000us)
#     iglos.build.merge_addons     B 1_060_000
#     iglos.build.merge_addons     E 1_070_000                                    (10_000us)
#   iglos.build             E 1_070_000                                           (70_000us)
FIXTURE_LOG = """\
some unrelated log noise
[TIMING] ELBE-TIMING ph=B ts=1000000 pid=100 tid=100 name=iglos.build
[TIMING] ELBE-TIMING ph=B ts=1000000 pid=100 tid=100 name=iglos.build.run_elbe.extend
[CMD] elbe build ...
[TIMING] ELBE-TIMING ph=B ts=1010000 pid=200 tid=200 name=elbe.build.install_packages.target
[TIMING] ELBE-TIMING ph=E ts=1050000 pid=200 tid=200 name=elbe.build.install_packages.target
[TIMING] ELBE-TIMING ph=E ts=1060000 pid=100 tid=100 name=iglos.build.run_elbe.extend
[TIMING] ELBE-TIMING ph=B ts=1060000 pid=100 tid=100 name=iglos.build.merge_addons
[TIMING] ELBE-TIMING ph=E ts=1070000 pid=100 tid=100 name=iglos.build.merge_addons
[TIMING] ELBE-TIMING ph=E ts=1070000 pid=100 tid=100 name=iglos.build
more unrelated log noise
"""


def _write_fixture(tmp_path, name='build.log', content=FIXTURE_LOG):
    path = tmp_path / name
    path.write_text(content)
    return path


def test_parse_events_ignores_non_timing_lines(tmp_path):
    path = _write_fixture(tmp_path)
    events = analyze_timing.parse_events([path])
    assert len(events) == 8


def test_parse_events_merges_and_sorts_multiple_files(tmp_path):
    # Split the fixture across two files, out of chronological order on
    # disk, to exercise the multi-file merge-and-sort path.
    lines = [line for line in FIXTURE_LOG.splitlines() if 'ELBE-TIMING' in line]
    first = _write_fixture(tmp_path, 'a.log', '\n'.join(lines[4:]) + '\n')
    second = _write_fixture(tmp_path, 'b.log', '\n'.join(lines[:4]) + '\n')

    events = analyze_timing.parse_events([first, second])
    assert [e['ts'] for e in events] == sorted(e['ts'] for e in events)
    assert len(events) == 8


def test_build_forest_nests_only_within_same_pid_tid(tmp_path):
    events = analyze_timing.parse_events([_write_fixture(tmp_path)])
    forest, warnings = analyze_timing.build_forest(events)

    assert warnings == []
    # Two top-level roots: iglos.build (pid 100) and the elbe subprocess's
    # install_packages span (pid 200) -- the latter is NOT nested inside
    # run_elbe.extend because they're different (pid, tid).
    assert {n['name'] for n in forest} == {
        'iglos.build', 'elbe.build.install_packages.target',
    }

    iglos_build = next(n for n in forest if n['name'] == 'iglos.build')
    assert iglos_build['end'] - iglos_build['begin'] == 70_000
    assert [c['name'] for c in iglos_build['children']] == [
        'iglos.build.run_elbe.extend', 'iglos.build.merge_addons',
    ]

    run_elbe = iglos_build['children'][0]
    assert run_elbe['end'] - run_elbe['begin'] == 60_000
    assert run_elbe['children'] == []

    apt = next(n for n in forest if n['name'] == 'elbe.build.install_packages.target')
    assert apt['end'] - apt['begin'] == 40_000


def test_summarize_computes_total_self_and_count(tmp_path):
    events = analyze_timing.parse_events([_write_fixture(tmp_path)])
    forest, _ = analyze_timing.build_forest(events)
    stats = analyze_timing.summarize(forest)

    assert stats['iglos.build']['count'] == 1
    assert stats['iglos.build']['total'] == 70_000
    # self = total (70_000) - children (run_elbe.extend 60_000 + merge_addons 10_000) = 0
    assert stats['iglos.build']['self'] == 0

    assert stats['iglos.build.run_elbe.extend']['total'] == 60_000
    assert stats['iglos.build.run_elbe.extend']['self'] == 60_000

    assert stats['elbe.build.install_packages.target']['total'] == 40_000
    assert stats['elbe.build.install_packages.target']['self'] == 40_000


def test_format_summary_sorts_by_total_duration_descending(tmp_path):
    events = analyze_timing.parse_events([_write_fixture(tmp_path)])
    forest, _ = analyze_timing.build_forest(events)
    text = analyze_timing.format_summary(analyze_timing.summarize(forest))

    lines = [line for line in text.splitlines() if line.strip() and '-' * 5 not in line]
    names_in_order = [line.split()[0] for line in lines[1:]]  # skip header
    assert names_in_order == [
        'iglos.build',
        'iglos.build.run_elbe.extend',
        'elbe.build.install_packages.target',
        'iglos.build.merge_addons',
    ]


def test_to_trace_events_produces_matched_begin_end_pairs(tmp_path):
    events = analyze_timing.parse_events([_write_fixture(tmp_path)])
    forest, _ = analyze_timing.build_forest(events)
    trace_events = analyze_timing.to_trace_events(forest)

    assert len(trace_events) == 8
    assert sum(1 for e in trace_events if e['ph'] == 'B') == 4
    assert sum(1 for e in trace_events if e['ph'] == 'E') == 4
    assert [e['ts'] for e in trace_events] == sorted(e['ts'] for e in trace_events)
    for e in trace_events:
        assert set(e) == {'name', 'ph', 'ts', 'pid', 'tid'}


def test_main_writes_valid_trace_json(tmp_path):
    log_path = _write_fixture(tmp_path)
    out_path = tmp_path / 'trace.json'

    analyze_timing.main(['--trace', str(out_path), str(log_path)])

    data = json.loads(out_path.read_text())
    assert len(data['traceEvents']) == 8


def test_main_prints_summary(tmp_path, capsys):
    log_path = _write_fixture(tmp_path)

    analyze_timing.main(['--summary', str(log_path)])

    out = capsys.readouterr().out
    assert 'iglos.build' in out
    assert 'elbe.build.install_packages.target' in out


def test_main_reports_missing_timing_lines(tmp_path):
    empty = tmp_path / 'empty.log'
    empty.write_text('nothing to see here\n')

    try:
        analyze_timing.main(['--summary', str(empty)])
        raised = False
    except SystemExit:
        raised = True
    assert raised
