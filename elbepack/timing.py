# ELBE - Debian Based Embedded Rootfilesystem Builder
# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: 2026 Linutronix GmbH

import logging
import os
import threading
import time
from contextlib import contextmanager


def _emit(ph, name):
    ts = time.time_ns() // 1000
    logging.info(
        f'ELBE-TIMING ph={ph} ts={ts} pid={os.getpid()} tid={threading.get_ident()} name={name}',
        extra={'context': '[TIMING] '},
    )


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
    _emit('B', name)
    try:
        yield
    finally:
        _emit('E', name)
