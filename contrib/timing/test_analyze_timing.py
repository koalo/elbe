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
import re
import xml.etree.ElementTree as ET

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


# A real captured build log logs the same physical event several times
# over, wrapped in different logger prefixes: elbe attaches both a root
# 'INFO:root:...' handler and a dedicated '[TIMING] ...' handler, and for
# SOAP apt-worker phases the worker's own already-doubled output gets
# relayed and re-logged again under a 'soap' logger on top of that.
DUPLICATE_PREFIXES_LOG = """\
INFO:root:ELBE-TIMING ph=B ts=2000000 pid=7 tid=1 name=elbe.apt.commit
[TIMING] ELBE-TIMING ph=B ts=2000000 pid=7 tid=1 name=elbe.apt.commit
INFO:soap:INFO:root:ELBE-TIMING ph=B ts=2000000 pid=7 tid=1 name=elbe.apt.commit
INFO:soap:INFO:root:ELBE-TIMING ph=E ts=2005000 pid=7 tid=1 name=elbe.apt.commit
INFO:root:ELBE-TIMING ph=E ts=2005000 pid=7 tid=1 name=elbe.apt.commit
[TIMING] ELBE-TIMING ph=E ts=2005000 pid=7 tid=1 name=elbe.apt.commit
"""


def test_parse_events_deduplicates_identical_events_from_multiple_handlers(tmp_path):
    path = _write_fixture(tmp_path, 'dup.log', DUPLICATE_PREFIXES_LOG)
    events = analyze_timing.parse_events([path])

    assert len(events) == 2
    assert [e['ph'] for e in events] == ['B', 'E']
    assert all(e['name'] == 'elbe.apt.commit' for e in events)


def test_parse_events_deduplicates_across_multiple_files(tmp_path):
    # Mirrors combining a captured master log with a project's own log.txt
    # under a build dir (see the module docstring) -- the same doubled
    # event ends up split across two separate files on disk.
    master = _write_fixture(tmp_path, 'master.log', DUPLICATE_PREFIXES_LOG)
    inner = _write_fixture(
        tmp_path, 'inner.log',
        '[TIMING] ELBE-TIMING ph=B ts=2000000 pid=7 tid=1 name=elbe.apt.commit\n'
        '[TIMING] ELBE-TIMING ph=E ts=2005000 pid=7 tid=1 name=elbe.apt.commit\n',
    )

    events = analyze_timing.parse_events([master, inner])
    assert len(events) == 2


# Real captures have occasionally shown two independent, unsynchronized
# writes landing on the same physical line with zero separator between
# them (see analyze_timing.py's _LINE_RE comment) -- e.g. elbe's own
# '[TIMING] ...' handler's write for a begin event gets no newline before
# the SOAP apt-worker relay's 'INFO:soap:...'/'INFO:root:...' write lands
# right after it, sometimes gluing a second complete event onto the same
# line.
GLUED_LINES_LOG = """\
[TIMING] ELBE-TIMING ph=B ts=3000000 pid=7 tid=1 name=elbe.build.install_packages.buildenvINFO:soap:Hit http://cdn-fastly.deb.debian.org/debian trixie InRelease
[TIMING] ELBE-TIMING ph=B ts=3010000 pid=6820 tid=2 name=elbe.shell.mvINFO:root:ELBE-TIMING ph=E ts=3020000 pid=6820 tid=2 name=elbe.shell.mv
[TIMING] ELBE-TIMING ph=B ts=3030000 pid=6820 tid=2 name=elbe.shell.sfdiskINFO:soap:8388608+0 records in
[TIMING] ELBE-TIMING ph=E ts=3040000 pid=6820 tid=2 name=elbe.shell.sfdisk
[TIMING] ELBE-TIMING ph=E ts=3050000 pid=7 tid=1 name=elbe.build.install_packages.buildenv
"""


def test_parse_events_recovers_names_glued_to_trailing_content(tmp_path):
    path = _write_fixture(tmp_path, 'glued.log', GLUED_LINES_LOG)
    events = analyze_timing.parse_events([path])

    names = {e['name'] for e in events}
    assert 'elbe.build.install_packages.buildenv' in names
    assert 'elbe.shell.mv' in names
    assert 'elbe.shell.sfdisk' in names
    assert not any('INFO' in name or ':' in name for name in names)


def test_parse_events_recovers_both_events_glued_onto_one_line(tmp_path):
    path = _write_fixture(tmp_path, 'glued.log', GLUED_LINES_LOG)
    events = analyze_timing.parse_events([path])

    mv_events = [e for e in events if e['name'] == 'elbe.shell.mv']
    assert [e['ph'] for e in mv_events] == ['B', 'E']
    assert [e['ts'] for e in mv_events] == [3010000, 3020000]


def test_build_forest_reports_no_warnings_for_glued_lines(tmp_path):
    events = analyze_timing.parse_events([_write_fixture(tmp_path, 'glued.log', GLUED_LINES_LOG)])
    _, warnings = analyze_timing.build_forest(events)
    assert warnings == []


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


def _svg_fragment(html_text):
    m = re.search(r'<svg.*?</svg>', html_text, re.S)
    assert m is not None, 'no <svg>...</svg> found in flame graph HTML'
    return m.group(0)


def test_flamegraph_html_is_self_contained(tmp_path):
    events = analyze_timing.parse_events([_write_fixture(tmp_path)])
    forest, _ = analyze_timing.build_forest(events)
    html_text = analyze_timing.to_flamegraph_html(forest)

    assert html_text.startswith('<!doctype html>')
    for external in ('http://', 'https://', 'src=', '<script'):
        assert external not in html_text


def test_flamegraph_html_contains_well_formed_svg(tmp_path):
    events = analyze_timing.parse_events([_write_fixture(tmp_path)])
    forest, _ = analyze_timing.build_forest(events)
    html_text = analyze_timing.to_flamegraph_html(forest)

    # Must be valid XML (SVG), not just something a lenient HTML5 parser
    # tolerates -- catches any un-escaped '&'/'<' from a phase name.
    ET.fromstring(_svg_fragment(html_text))


def test_flamegraph_html_shows_every_phase_and_pid_lane(tmp_path):
    events = analyze_timing.parse_events([_write_fixture(tmp_path)])
    forest, _ = analyze_timing.build_forest(events)
    html_text = analyze_timing.to_flamegraph_html(forest)

    for name in [
        'iglos.build', 'iglos.build.run_elbe.extend', 'iglos.build.merge_addons',
        'elbe.build.install_packages.target',
    ]:
        assert name in html_text
    assert 'pid 100' in html_text
    assert 'pid 200' in html_text


def test_flamegraph_html_nested_span_stays_within_parent_bounds(tmp_path):
    # elbe.build.install_packages.target (pid 200) runs entirely inside
    # the time window of iglos.build.run_elbe.extend (pid 100), even
    # though they're in different lanes -- their x positions should
    # reflect that containment.
    events = analyze_timing.parse_events([_write_fixture(tmp_path)])
    forest, _ = analyze_timing.build_forest(events)
    html_text = analyze_timing.to_flamegraph_html(forest, width=1000)

    rects = re.findall(
        r'<rect[^>]*x="([\d.]+)"[^>]*width="([\d.]+)"[^>]*><title>([^\n]+)', html_text,
    )
    by_name = {name: (float(x), float(w)) for x, w, name in rects}

    parent_x, parent_w = by_name['iglos.build.run_elbe.extend']
    child_x, child_w = by_name['elbe.build.install_packages.target']
    assert parent_x <= child_x
    assert child_x + child_w <= parent_x + parent_w


def test_flamegraph_html_handles_empty_forest():
    html_text = analyze_timing.to_flamegraph_html([])
    assert html_text.startswith('<!doctype html>')
    assert 'no completed spans' in html_text


def test_main_writes_flamegraph_html(tmp_path):
    log_path = _write_fixture(tmp_path)
    out_path = tmp_path / 'flame.html'

    analyze_timing.main(['--flamegraph', str(out_path), str(log_path)])

    html_text = out_path.read_text()
    ET.fromstring(_svg_fragment(html_text))
    assert 'iglos.build' in html_text


def test_main_reports_missing_timing_lines(tmp_path):
    empty = tmp_path / 'empty.log'
    empty.write_text('nothing to see here\n')

    try:
        analyze_timing.main(['--summary', str(empty)])
        raised = False
    except SystemExit:
        raised = True
    assert raised
