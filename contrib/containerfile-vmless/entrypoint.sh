#!/bin/sh
# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: 2026 Linutronix GmbH
set -e

register_binfmt() {
    mount -t binfmt_misc binfmt_misc /proc/sys/fs/binfmt_misc 2>/dev/null || return 0
    for f in /usr/lib/binfmt.d/qemu-*.conf; do
        [ -e "$f" ] || continue
        cat "$f" > /proc/sys/fs/binfmt_misc/register 2>/dev/null || true
    done
}

if [ "$1" = --post-unshare ]; then
    shift
    register_binfmt
    exec "$@"
fi

# Check if we already have CAP_SYS_ADMIN
# In that case we assume we are already running rootful,
# so no need for unshare, but this mode also enables usage
# of loop devices, so perform mknod to enable its usage.
capeff=$(grep '^CapEff:' /proc/self/status | cut -f2)
if [ $(( 0x$capeff & 0x200000 )) -ne 0 ]; then
    i=0
    while [ "$i" -lt 64 ]; do
        [ -e "/dev/loop$i" ] || mknod -m 660 "/dev/loop$i" b 7 "$i" 2>/dev/null || true
        i=$((i + 1))
    done
    register_binfmt
    exec "$@"
fi

exec unshare --user --map-root-user --map-users=all --map-groups=all --mount -- \
    "$0" --post-unshare "$@"
