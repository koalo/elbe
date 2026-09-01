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

Load the resulting trace.json at https://ui.perfetto.dev for a flamegraph.
Multiple log files may be given at once (e.g. the captured combined output
plus a project's log.txt found under a build dir); events from all of them
are merged and sorted by timestamp before analysis.
"""

import argparse
import json
import re
import sys
from collections import defaultdict

_LINE_RE = re.compile(
    r'ELBE-TIMING ph=(?P<ph>[BE]) ts=(?P<ts>\d+) pid=(?P<pid>\d+) '
    r'tid=(?P<tid>\d+) name=(?P<name>\S+)'
)


def parse_events(paths):
    events = []
    for path in paths:
        with open(path, encoding='utf-8', errors='replace') as f:
            for line in f:
                m = _LINE_RE.search(line)
                if m:
                    events.append({
                        'ph': m.group('ph'),
                        'ts': int(m.group('ts')),
                        'pid': int(m.group('pid')),
                        'tid': int(m.group('tid')),
                        'name': m.group('name'),
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


def main(argv=None):
    parser = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument('logfiles', nargs='+', help='captured build log file(s)')
    parser.add_argument('--summary', action='store_true',
                        help='print a text summary table sorted by total duration')
    parser.add_argument('--trace', metavar='OUT.json',
                        help='write a Chrome/Perfetto Trace Event Format JSON file')
    args = parser.parse_args(argv)

    if not args.summary and not args.trace:
        parser.error('nothing to do: pass --summary and/or --trace')

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


if __name__ == '__main__':
    main()
