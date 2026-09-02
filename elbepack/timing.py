# ELBE - Debian Based Embedded Rootfilesystem Builder
# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: 2026 Linutronix GmbH

import logging
import os
import threading
import time
from contextlib import contextmanager


def _emit(ph, name, *, tid=None):
    ts = time.time_ns() // 1000
    tid = threading.get_ident() if tid is None else tid
    extra = {'context': '[TIMING] '}
    if tid != threading.get_ident():
        # elbepack.log's ThreadFilter drops records whose thread doesn't
        # match whichever thread called open_logging() (each thread needs
        # its own pinned handler), unless told to impersonate another
        # thread via this same '_thread' extra -- see AsyncLogging in
        # elbepack/log.py for the precedent. Needed for a helper thread
        # (e.g. one draining a pipe) emitting spans that logically belong
        # to the thread that spawned it.
        extra['_thread'] = tid
    logging.info(
        f'ELBE-TIMING ph={ph} ts={ts} pid={os.getpid()} tid={tid} name={name}',
        extra=extra,
    )


def begin(name, *, tid=None):
    """Emit a single ELBE-TIMING begin marker for name.

    Use this (with a matching end()) instead of phase() when a span's
    start/end don't fall inside one Python block -- e.g. driven by
    externally-arriving events on a callback. Prefer phase() whenever a
    plain `with` block works.

    Pass tid to attribute the span to a different (logical) thread than
    the one actually calling begin() -- see _emit()'s docstring comment.
    """
    _emit('B', name, tid=tid)


def end(name, *, tid=None):
    """Emit a single ELBE-TIMING end marker for name. See begin()."""
    _emit('E', name, tid=tid)


@contextmanager
def phase(name):
    """
    Emit ELBE-TIMING begin/end markers around the wrapped block.

    The markers are logged through the normal logging machinery (like
    everything else in elbepack), so they end up in the same places as any
    other log message: the CLI's live stdout stream and the project's
    log.txt. See contrib/timing/analyze_timing.py for turning captured
    ELBE-TIMING lines into a report or a Perfetto trace.
    """
    begin(name)
    try:
        yield
    finally:
        end(name)
