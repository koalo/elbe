# ELBE - Debian Based Embedded Rootfilesystem Builder
# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: 2026 Linutronix GmbH

"""
EXPERIMENTAL: overlayfs+tmpfs based fsync avoidance, layered on top of
elbepack.rpcaptcache's --force-unsafe-io.

Background (see iglos/TIMING_FINDINGS.md): --force-unsafe-io only covers
dpkg's own unpack/rename fsyncs, not fsyncs made by maintainer scripts and
triggers (ldconfig, mandb, update-alternatives, ...) that commit() also
spawns. Full eatmydata (LD_PRELOAD) covers those too but requires installing
something into the target and extracting a .deb by hand every run.

This module gets the same broad coverage as eatmydata -- every fsync made by
anything commit() spawns becomes free -- without installing anything on the
target and without LD_PRELOAD, by temporarily mounting a self-referential
overlay on top of the chroot directory (lowerdir == the mountpoint itself)
with a tmpfs-backed upper. New/changed files land in the tmpfs upper (so
their fsyncs are free); unchanged files keep being served from the real
lowerdir underneath, so RAM use is bounded by *what this one commit changes*,
not by the whole rootfs.

NOT production-hardened. Opt-in only (see elbeproject.py's use of
ELBE_APT_OVERLAY_TMPFS), heavily instrumented on purpose (both via
elbepack.timing.phase(), so setup/merge/teardown cost shows up in
run_timing_test.py's summary like any other phase, and via DEBUG-OVERLAY
print()s for sizes/counts/timings that phase() doesn't capture) -- this
exists to gather real measurements to decide whether the approach is worth
hardening further, not to ship as-is. Requires CAP_SYS_ADMIN (already
required today for elbepack.shellhelper's /proc,/sys,/dev bind mounts).
"""

import contextlib
import logging
import os
import shutil
import stat
import subprocess
import tempfile
import time

from elbepack.timing import phase

DEFAULT_SIZE_MB = 6144


def _is_whiteout(st):
    return stat.S_ISCHR(st.st_mode) and os.major(st.st_rdev) == 0 and os.minor(st.st_rdev) == 0


def _run(cmd, *, check=False):
    start = time.monotonic()
    result = subprocess.run(cmd, capture_output=True, text=True, check=False)
    elapsed = time.monotonic() - start
    print(f'DEBUG-OVERLAY: {" ".join(cmd)} -> rc={result.returncode} ({elapsed:.3f}s)')
    if result.stdout.strip():
        print(f'DEBUG-OVERLAY:   stdout: {result.stdout.strip()}')
    if result.stderr.strip():
        print(f'DEBUG-OVERLAY:   stderr: {result.stderr.strip()}')
    if check:
        result.check_returncode()
    return result


def _umount_with_retry(target, *, extra_args=None, attempts=5, delay_s=0.5):
    """umount can transiently fail with EBUSY if some other process (e.g.
    RPCAPTCache's manager subprocess, still exiting its chroot()) hasn't
    fully released the mount yet. Retrying, with logging on every attempt,
    turns that race into visible data instead of an outright failure --
    if this is consistently needed (and how many attempts it takes) is
    itself a feasibility signal worth having.
    """
    cmd = ['umount', *(extra_args or []), target]
    for attempt in range(1, attempts + 1):
        result = _run(cmd)
        if result.returncode == 0:
            if attempt > 1:
                print(f'DEBUG-OVERLAY: umount {target} succeeded on attempt {attempt}')
            return True
        if attempt < attempts:
            print(f'DEBUG-OVERLAY: umount {target} busy (attempt {attempt}/{attempts}), '
                 f'retrying in {delay_s}s')
            time.sleep(delay_s)
    print(f'DEBUG-OVERLAY: umount {target} FAILED after {attempts} attempts -- giving up')
    return False


def _dir_stats(path):
    """Best-effort (total_bytes, file_count, whiteout_count) for path, for
    instrumentation only -- never raises."""
    try:
        du = subprocess.run(['du', '-sb', path], capture_output=True, text=True, check=True)
        total_bytes = int(du.stdout.split()[0])
    except Exception:
        logging.exception('DEBUG-OVERLAY: du -sb failed, size instrumentation unavailable')
        total_bytes = -1

    file_count = 0
    whiteout_count = 0
    for root, _dirs, files in os.walk(path):
        for f in files:
            full = os.path.join(root, f)
            try:
                st = os.lstat(full)
            except OSError:
                continue
            if _is_whiteout(st):
                whiteout_count += 1
            else:
                file_count += 1
    return total_bytes, file_count, whiteout_count


def _apply_whiteouts_and_merge(upperdir, real_dir):
    """Merge upperdir's diff onto real_dir, translating overlayfs whiteouts
    (char devices, major:minor 0:0) into real deletions -- a plain
    `rsync -a` would copy the whiteout device node verbatim instead of
    deleting the target file. --checksum is required too: without it,
    rsync's default quick-check (size+mtime) can skip a copy-up'd file that
    happens to match the lower version's size and 1s-resolution mtime.
    Validated standalone in /tmp/.../overlay_poc.sh before wiring in here.
    """
    whiteouts = []
    for root, _dirs, files in os.walk(upperdir):
        for f in files:
            full = os.path.join(root, f)
            st = os.lstat(full)
            if _is_whiteout(st):
                whiteouts.append(os.path.relpath(full, upperdir))

    with tempfile.NamedTemporaryFile('w', suffix='.excludes') as excl:
        excl.write('\n'.join(whiteouts))
        excl.flush()
        _run(['rsync', '-a', '--checksum', f'--exclude-from={excl.name}',
             f'{upperdir}/', f'{real_dir}/'], check=True)

    for rel in whiteouts:
        target = os.path.join(real_dir, rel)
        if os.path.lexists(target):
            os.remove(target)
        print(f'DEBUG-OVERLAY: applied whiteout deletion: {rel}')

    return len(whiteouts)


@contextlib.contextmanager
def overlay_tmpfs(path, *, size_mb=DEFAULT_SIZE_MB, enabled=True, pre_teardown=None):
    """
    EXPERIMENTAL, see module docstring. When enabled, mounts a tmpfs-backed
    overlay on top of `path` (self-referential: `path` is both the overlay's
    lowerdir and its mountpoint) for the duration of the `with` block, then
    merges the diff back onto the real on-disk directory and tears the
    mounts down. When disabled, a no-op passthrough.

    `pre_teardown`, if given, is called unconditionally (success or
    exception, any exit path out of the `with` block) right before the
    merge/unmount sequence starts -- for a caller-side cleanup step (e.g.
    releasing something that's still chroot()ed into `path`, which would
    otherwise make unmounting it fail with EBUSY) that must run no matter
    *why* or *where* the block exited.
    """
    if not enabled:
        yield
        return

    workroot = tempfile.mkdtemp(prefix='elbe-overlay-')
    tmpfs_mnt = os.path.join(workroot, 'tmpfs')
    real_mnt = os.path.join(workroot, 'real')
    upperdir = os.path.join(tmpfs_mnt, 'upper')
    workdir = os.path.join(tmpfs_mnt, 'work')
    os.makedirs(tmpfs_mnt)
    os.makedirs(real_mnt)

    print(f'DEBUG-OVERLAY: enabling for {path}, tmpfs cap={size_mb}MB, workroot={workroot}')

    tmpfs_mounted = False
    real_bound = False
    overlay_mounted = False
    overlay_start = None

    try:
        with phase('elbe.experimental_overlay.mount'):
            _run(['mount', '-t', 'tmpfs', '-o', f'size={size_mb}m', 'tmpfs', tmpfs_mnt],
                check=True)
            tmpfs_mounted = True
            os.makedirs(upperdir)
            os.makedirs(workdir)

            # Bind-mount alias, taken *before* the overlay covers `path`, so
            # the pristine on-disk directory stays reachable (via real_mnt)
            # for the merge-back after the overlay is torn down.
            _run(['mount', '--bind', path, real_mnt], check=True)
            _run(['mount', '--make-rprivate', real_mnt], check=True)
            real_bound = True

            _run(['mount', '-t', 'overlay', 'overlay', '-o',
                 f'lowerdir={path},upperdir={upperdir},workdir={workdir}', path],
                check=True)
            overlay_mounted = True

        overlay_start = time.monotonic()
        yield
    finally:
        active_s = time.monotonic() - overlay_start if overlay_start is not None else -1

        if overlay_mounted and pre_teardown is not None:
            try:
                pre_teardown()
            except Exception:
                logging.exception('DEBUG-OVERLAY: pre_teardown hook failed -- '
                                  'unmount below may hit EBUSY as a result')

        if overlay_mounted:
            with phase('elbe.experimental_overlay.merge'):
                total_bytes, file_count, whiteout_count = _dir_stats(upperdir)
                cap_bytes = size_mb * 1024 * 1024
                headroom = cap_bytes - total_bytes if total_bytes >= 0 else -1
                print(f'DEBUG-OVERLAY: active for {active_s:.1f}s -- upperdir: '
                     f'{total_bytes} bytes, {file_count} files, {whiteout_count} '
                     f'whiteouts (tmpfs cap {cap_bytes} bytes, headroom {headroom} bytes)')
                try:
                    applied = _apply_whiteouts_and_merge(upperdir, real_mnt)
                    print(f'DEBUG-OVERLAY: merge-back complete, {applied} whiteouts applied')
                except Exception:
                    logging.exception('DEBUG-OVERLAY: merge-back FAILED -- '
                                      'real on-disk directory may now be inconsistent '
                                      'with what commit() actually did')
                    raise

        with phase('elbe.experimental_overlay.unmount'):
            if overlay_mounted:
                _umount_with_retry(path)
            if real_bound:
                _umount_with_retry(real_mnt, extra_args=['--lazy'])
            if tmpfs_mounted:
                _umount_with_retry(tmpfs_mnt)

        shutil.rmtree(workroot, ignore_errors=True)
