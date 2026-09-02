#!/usr/bin/env python3
# ELBE - Debian Based Embedded Rootfilesystem Builder
# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: 2026 Linutronix GmbH

"""
Parse ELBE-TIMING lines emitted by elbepack.timing.phase() and iglos.py's
matching self-contained timing emitter, and turn them into either a quick
text summary or a Chrome/Perfetto Trace Event Format JSON file.

Capture a build's output first, e.g.:

    make safelog 2>&1 | tee /tmp/safelog-build.log

then:

    analyze_timing.py --summary /tmp/safelog-build.log
    analyze_timing.py --trace /tmp/trace.json /tmp/safelog-build.log
    analyze_timing.py --flamegraph /tmp/flame.html /tmp/safelog-build.log

Load the resulting trace.json at https://ui.perfetto.dev for a trace view,
or just open flame.html directly in any browser -- it's a single
self-contained file (inline SVG, no JS/CSS/fonts fetched from anywhere),
so it works with no network access at all. Multiple log files may be given
at once (e.g. the captured combined output plus a project's log.txt found
under a build dir); events from all of them are merged and sorted by
timestamp before analysis. Events that are exact repeats of one another
(elbe logs each phase through multiple handlers, see parse_events()) are
deduplicated automatically, so passing overlapping/redundant log files is
safe and does not inflate the resulting counts/totals.
"""

import argparse
import html
import json
import re
import sys
import zlib
from collections import defaultdict

# name= is normally terminated by whitespace/end-of-line. But elbe's two
# unsynchronized logging handlers (see parse_events()'s docstring) can, on
# rare occasions, interleave two independent writes with no separator at
# all -- e.g. 'name=elbe.shell.mvINFO:root:ELBE-TIMING ph=E ts=...' or
# 'name=elbe.shell.sfdiskINFO:soap:8388608+0 records in'. All real phase
# names are lowercase dotted identifiers (see elbepack/timing.py callers),
# so the lookahead also stops name= at the first sign of such glued-on
# content: a log-level prefix ('INFO:', 'WARNING:', ...), a '[TIMING]'/
# '[CMD]'/'[INFO]' handler prefix, or a directly-glued second event.
_LINE_RE = re.compile(
    r'ELBE-TIMING ph=(?P<ph>[BE]) ts=(?P<ts>\d+) pid=(?P<pid>\d+) '
    r'tid=(?P<tid>\d+) name=(?P<name>\S+?)(?=\s|$|\[|ELBE-TIMING|[A-Z][A-Za-z]*:)'
)


def parse_events(paths):
    """Parse ELBE-TIMING lines from one or more log files into an event list.

    elbe emits each phase through more than one logging handler (a root
    'INFO:root:...' handler plus a dedicated '[TIMING] ...' handler), and
    for phases from the SOAP apt-worker subprocess (elbe.apt.*), the
    subprocess's own already-doubled output is captured and relayed
    through a further 'soap' logger on top of that -- so the exact same
    real event can appear several times verbatim (just wrapped in
    different prefixes) in a captured build log. Such repeats are
    deduplicated on the (ph, ts, pid, tid, name) tuple before being
    returned, so callers never see inflated counts/totals from this.

    Those same unsynchronized handlers can also, rarely, interleave two
    independent writes onto one physical line with no separator (see
    _LINE_RE's comment) -- possibly gluing two complete events onto a
    single line. Each line is scanned for every match it contains (not
    just the first), so both events are still recovered.
    """
    events = []
    seen = set()
    for path in paths:
        with open(path, encoding='utf-8', errors='replace') as f:
            for line in f:
                for m in _LINE_RE.finditer(line):
                    key = (
                        m.group('ph'), int(m.group('ts')), int(m.group('pid')),
                        int(m.group('tid')), m.group('name'),
                    )
                    if key in seen:
                        continue
                    seen.add(key)
                    events.append({
                        'ph': key[0], 'ts': key[1], 'pid': key[2],
                        'tid': key[3], 'name': key[4],
                    })
    events.sort(key=lambda e: e['ts'])
    return events


def build_forest(events):
    """Pair begin/end events per (pid, tid) into a forest of span nodes.

    A span's children are only ever other spans logged on the same (pid,
    tid) while it was open -- there is no cross-process/thread parent
    link, so e.g. the outer iglos.py process's span covering a nested
    'elbe build' subprocess call does not contain that subprocess's own
    spans in the tree; they show up as separate top-level entries instead
    (their timestamps still fall inside the outer span, which is enough
    for --trace to render them as visibly nested tracks in Perfetto).

    Returns (forest, warnings); minor interleaving noise from combined
    stdout/stderr capture (an unmatched end, a mismatched name) is
    tolerated and reported as a warning rather than raising.
    """
    stacks = defaultdict(list)
    forest = []
    warnings = []

    for e in events:
        key = (e['pid'], e['tid'])
        if e['ph'] == 'B':
            node = {
                'name': e['name'], 'begin': e['ts'], 'end': None,
                'pid': e['pid'], 'tid': e['tid'], 'children': [],
            }
            if stacks[key]:
                stacks[key][-1]['children'].append(node)
            else:
                forest.append(node)
            stacks[key].append(node)
        else:
            if not stacks[key]:
                warnings.append(
                    f"unmatched end event for {e['name']!r} "
                    f"(pid={e['pid']}, tid={e['tid']})"
                )
                continue
            node = stacks[key].pop()
            node['end'] = e['ts']
            if node['name'] != e['name']:
                warnings.append(
                    f"phase name mismatch: began {node['name']!r}, "
                    f"ended {e['name']!r} (pid={e['pid']}, tid={e['tid']})"
                )

    for key, stack in stacks.items():
        for node in stack:
            warnings.append(
                f"phase {node['name']!r} never ended (pid={key[0]}, tid={key[1]})"
            )

    return forest, warnings


def _walk(forest):
    for node in forest:
        yield node
        yield from _walk(node['children'])


def summarize(forest):
    """Aggregate total/self duration (in microseconds) and call count per phase name."""
    stats = defaultdict(lambda: {'count': 0, 'total': 0, 'self': 0})
    for node in _walk(forest):
        if node['end'] is None:
            continue
        duration = node['end'] - node['begin']
        children_total = sum(
            c['end'] - c['begin'] for c in node['children'] if c['end'] is not None
        )
        s = stats[node['name']]
        s['count'] += 1
        s['total'] += duration
        s['self'] += duration - children_total
    return stats


def format_summary(stats):
    rows = sorted(stats.items(), key=lambda kv: kv[1]['total'], reverse=True)
    name_w = max([len('phase')] + [len(name) for name, _ in rows])
    header = f"{'phase':<{name_w}}  {'count':>6}  {'total(s)':>10}  {'self(s)':>10}"
    lines = [header, '-' * len(header)]
    for name, s in rows:
        lines.append(
            f"{name:<{name_w}}  {s['count']:>6}  "
            f"{s['total'] / 1e6:>10.3f}  {s['self'] / 1e6:>10.3f}"
        )
    return '\n'.join(lines)


def to_trace_events(forest):
    trace_events = []
    for node in _walk(forest):
        if node['end'] is None:
            continue
        trace_events.append({
            'name': node['name'], 'ph': 'B', 'ts': node['begin'],
            'pid': node['pid'], 'tid': node['tid'],
        })
        trace_events.append({
            'name': node['name'], 'ph': 'E', 'ts': node['end'],
            'pid': node['pid'], 'tid': node['tid'],
        })
    trace_events.sort(key=lambda e: e['ts'])
    return trace_events


def _phase_color(name):
    # Deterministic (not Python's salted hash()) so the same phase name
    # always gets the same color across runs/files.
    hue = zlib.crc32(name.encode()) % 360
    return f'hsl({hue}, 55%, 55%)'


def _assign_depths(node, depth, out):
    out.append((node, depth))
    for child in node['children']:
        _assign_depths(child, depth + 1, out)


_NICE_TIME_STEPS_S = [
    0.001, 0.002, 0.005, 0.01, 0.02, 0.05, 0.1, 0.2, 0.5,
    1, 2, 5, 10, 15, 30, 60, 120, 300, 600, 900, 1800, 3600,
]


def _pick_time_step_s(total_s, target_ticks=12):
    if total_s <= 0:
        return _NICE_TIME_STEPS_S[0]
    raw = total_s / target_ticks
    for step in _NICE_TIME_STEPS_S:
        if step >= raw:
            return step
    return _NICE_TIME_STEPS_S[-1]


_FLAMEGRAPH_STYLE = """
body { font: 13px sans-serif; margin: 16px; background: #fff; color: #111; }
h1 { font-size: 16px; margin: 0 0 4px; }
.subtitle { color: #555; margin: 0 0 16px; }
.scroll { overflow-x: auto; border: 1px solid #ddd; }
.lane-label { font: bold 11px sans-serif; fill: #333; }
.tick-label { font: 10px sans-serif; fill: #777; }
.tick-line { stroke: #eee; stroke-width: 1; }
rect.span { stroke: #fff; stroke-width: 0.5; }
rect.span:hover { stroke: #000; stroke-width: 1.5; }
text.span-label { font: 10px monospace; fill: #111; pointer-events: none; }
"""


def to_flamegraph_html(forest, *, pixels_per_second=5, min_width=800, row_height=20):
    """Render a self-contained flame-chart HTML page (inline SVG, no
    external JS/CSS/fonts) -- open the file directly in any browser, no
    network access needed.

    Unlike a classic sampled-profiler flame graph, spans carry real
    timestamps and span multiple processes/threads, so this renders as a
    flame *chart*: the x-axis is wall-clock time (shared across all
    lanes), and each (pid, tid) gets its own horizontal lane in which
    nested calls stack upward from that lane's own top-level spans --
    matching build_forest()'s per-(pid, tid) nesting (see its docstring).

    The time scale (pixels_per_second) is fixed rather than derived from
    the build's total duration, so "1 second" is always the same number
    of pixels -- this keeps flamegraphs from different runs visually
    comparable. The SVG grows wider for longer builds instead (scrollable
    via the surrounding .scroll div).
    """
    ended = [n for n in _walk(forest) if n['end'] is not None]
    if not ended:
        return (
            '<!doctype html><meta charset="utf-8">'
            '<title>ELBE timing flamegraph</title><body>no completed spans to show</body>'
        )

    min_ts = min(n['begin'] for n in ended)
    max_ts = max(n['end'] for n in ended)
    total_us = max(max_ts - min_ts, 1)
    scale = pixels_per_second / 1e6  # fixed pixels per microsecond
    width = max(total_us * scale, min_width)

    lanes = defaultdict(list)
    for node in forest:
        if node['end'] is not None:
            lanes[(node['pid'], node['tid'])].append(node)
    lane_keys = sorted(lanes, key=lambda k: min(n['begin'] for n in lanes[k]))

    ruler_h = 24
    lane_header_h = 18
    lane_gap = 6

    body_parts = [
        f'<g transform="translate(0, {ruler_h})">',
    ]

    total_step_s = _pick_time_step_s(total_us / 1e6)
    tick_us = total_step_s * 1e6
    tick = 0.0
    ruler_parts = []
    while tick <= total_us:
        x = tick * scale
        ruler_parts.append(
            f'<line class="tick-line" x1="{x:.2f}" y1="0" x2="{x:.2f}" '
            f'y2="{ruler_h}" />'
            f'<text class="tick-label" x="{x + 2:.2f}" y="{ruler_h - 8:.2f}">'
            f'{tick / 1e6:.3g}s</text>'
        )
        tick += tick_us

    y = 0
    for key in lane_keys:
        entries = []
        for root in lanes[key]:
            _assign_depths(root, 0, entries)
        max_depth = max(depth for _, depth in entries)
        lane_h = (max_depth + 1) * row_height

        body_parts.append(
            f'<text class="lane-label" x="4" y="{y + lane_header_h - 5:.2f}">'
            f'pid {key[0]} · tid {key[1]}</text>'
        )
        y += lane_header_h

        for node, depth in entries:
            x = (node['begin'] - min_ts) * scale
            w = max((node['end'] - node['begin']) * scale, 0.5)
            ry = y + depth * row_height
            dur_s = (node['end'] - node['begin']) / 1e6
            name = node['name']
            max_chars = max(int(w // 6) - 1, 0)
            label = name if len(name) <= max_chars else name[:max_chars - 1] + '…'
            body_parts.append(
                '<g>'
                f'<rect class="span" x="{x:.2f}" y="{ry:.2f}" width="{w:.2f}" '
                f'height="{row_height - 1}" fill="{_phase_color(name)}">'
                f'<title>{html.escape(name)}\n{dur_s:.3f}s</title></rect>'
                + (
                    f'<text class="span-label" x="{x + 2:.2f}" y="{ry + row_height - 6:.2f}">'
                    f'{html.escape(label)}</text>' if max_chars > 2 else ''
                )
                + '</g>'
            )

        y += lane_h + lane_gap

    body_parts.append('</g>')
    svg_height = ruler_h + y

    total_s = total_us / 1e6
    span_count = len(ended)
    lane_count = len(lane_keys)

    return f"""<!doctype html>
<meta charset="utf-8">
<title>ELBE timing flamegraph</title>
<style>{_FLAMEGRAPH_STYLE}</style>
<h1>ELBE build timing flamegraph</h1>
<p class="subtitle">total wall time {total_s:.3f}s · {span_count} spans · \
{lane_count} process/thread lanes · hover a bar for its exact duration</p>
<div class="scroll">
<svg width="{width}" height="{svg_height:.2f}" viewBox="0 0 {width} {svg_height:.2f}">
{''.join(ruler_parts)}
{''.join(body_parts)}
</svg>
</div>
"""


def main(argv=None):
    parser = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument('logfiles', nargs='+', help='captured build log file(s)')
    parser.add_argument('--summary', action='store_true',
                        help='print a text summary table sorted by total duration')
    parser.add_argument('--trace', metavar='OUT.json',
                        help='write a Chrome/Perfetto Trace Event Format JSON file')
    parser.add_argument('--flamegraph', metavar='OUT.html',
                        help='write a self-contained flame-chart HTML file (no network needed)')
    args = parser.parse_args(argv)

    if not args.summary and not args.trace and not args.flamegraph:
        parser.error('nothing to do: pass --summary, --trace and/or --flamegraph')

    events = parse_events(args.logfiles)
    if not events:
        parser.error(
            'no ELBE-TIMING lines found in the given log file(s); did you '
            'capture the build output with e.g. "make ... 2>&1 | tee logfile"?'
        )

    forest, warnings = build_forest(events)
    for warning in warnings:
        print(f'warning: {warning}', file=sys.stderr)

    if args.summary:
        print(format_summary(summarize(forest)))

    if args.trace:
        with open(args.trace, 'w', encoding='utf-8') as f:
            json.dump({'traceEvents': to_trace_events(forest)}, f)
        print(f'wrote {args.trace}', file=sys.stderr)

    if args.flamegraph:
        with open(args.flamegraph, 'w', encoding='utf-8') as f:
            f.write(to_flamegraph_html(forest))
        print(f'wrote {args.flamegraph}', file=sys.stderr)


if __name__ == '__main__':
    main()
