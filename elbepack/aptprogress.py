# ELBE - Debian Based Embedded Rootfilesystem Builder
# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: 2014-2017 Linutronix GmbH

import os
import threading

from apt.progress.base import AcquireProgress, InstallProgress, OpProgress

from apt_pkg import size_to_str

from elbepack.timing import begin, end


class ElbeInstallProgress (InstallProgress):

    def __init__(self, cb=None, fileno=2):
        super().__init__()
        self.cb = cb
        self.fileno = fileno
        self._stage = None

    def write(self, line):
        if line == 'update finished':
            # This is class attribute inherited by InstallProgress.
            # Pylint is confused by this but the attribute does exists
            # on this type!
            #
            self.percent = 100

        line = str(self.percent) + '% ' + line
        line.replace('\f', '')
        if self.cb:
            self.cb(line)
        else:
            print(line)

    def processing(self, pkg, stage):
        self.write('processing: ' + pkg + ' - ' + stage)

    def dpkg_status_change(self, pkg, status):
        self.write(pkg + ' - ' + status)

    def status_change(self, pkg, percent, status):
        self.write(pkg + ' - ' + status + ' ' + str(percent) + '%')

    def run(self, obj):
        """Run obj.do_install(), timestamping dpkg's --status-fd protocol.

        obj.do_install() blocks synchronously (in this thread) until dpkg
        exits, so the fd it writes '--status-fd' data to must be drained
        concurrently or dpkg deadlocks once its pipe buffer fills up. A
        background thread relays that fd to self.fileno unchanged (dpkg's
        own human-readable stdout/stderr, e.g. 'Unpacking ...'/'Setting up
        ...', is a separate stream and untouched by this), while also
        parsing 'processing: <stage>: <pkg>' lines (see InstallProgress.
        processing()'s docstring for the fixed set of stage names) to open
        an elbe.apt.commit.<stage> ELBE-TIMING span for each -- giving a
        breakdown of commit() time across unpack/configure/trigproc/etc.
        that was previously invisible (a single opaque elbe.apt.commit span).
        """
        # Spans opened from the relay thread are logged as belonging to
        # this (the calling) thread -- see timing.begin()'s tid= param --
        # so they nest under whatever phase() (e.g. elbe.apt.commit) is
        # currently open on this thread's stack, instead of appearing on
        # a disconnected lane of their own.
        owner_tid = threading.get_ident()
        read_fd, write_fd = os.pipe()
        relay = threading.Thread(target=self._relay_status_fd, args=(read_fd, owner_tid))
        relay.start()
        try:
            obj.do_install(write_fd)
        except AttributeError:
            print('installing .deb files is not supported by elbe progress')
            raise SystemError
        finally:
            os.close(write_fd)
            relay.join()
            self._close_stage(tid=owner_tid)
        return 0

    def _relay_status_fd(self, read_fd, owner_tid):
        with os.fdopen(read_fd, errors='replace') as f:
            for raw_line in f:
                os.write(self.fileno, raw_line.encode())
                self._handle_status_line(raw_line.rstrip('\n'), owner_tid)

    def _handle_status_line(self, line, owner_tid):
        if not line.startswith('processing:'):
            return
        try:
            _status, stage, _pkg = line.split(':', 2)
        except ValueError:
            return
        self._open_stage(f'elbe.apt.commit.{stage.strip()}', tid=owner_tid)

    def _open_stage(self, name, *, tid):
        self._close_stage(tid=tid)
        self._stage = name
        begin(name, tid=tid)

    def _close_stage(self, *, tid):
        if self._stage is not None:
            end(self._stage, tid=tid)
            self._stage = None

    def fork(self):
        retval = os.fork()
        if retval:
            # This is class attribute inherited by InstallProgress.
            # Pylint is confused by this but the attribute does exists
            # on this type!
            #
            self.child_pid = retval
        return retval

    def finishUpdate(self):
        self.write('update finished')


class ElbeAcquireProgress (AcquireProgress):

    def __init__(self, cb=None):
        super().__init__()
        self._id = 1
        self.cb = cb

    def write(self, line):
        line.replace('\f', '')
        if self.cb:
            self.cb(line)
        else:
            print(line)

    def ims_hit(self, item):
        line = 'Hit ' + item.description
        if item.owner.filesize:
            line += f' [{size_to_str(item.owner.filesize)}B]'
        self.write(line)

    def fail(self, item):
        if item.owner.status == item.owner.STAT_DONE:
            self.write('Ign ' + item.description)

    def fetch(self, item):
        if item.owner.complete:
            return
        item.owner.id = self._id
        self._id += 1
        line = 'Get:' + str(item.owner.id) + ' ' + item.description
        if item.owner.filesize:
            line += (f' [{size_to_str(item.owner.filesize)}B]')

        self.write(line)

    @staticmethod
    def pulse(_owner):
        return True


class ElbeOpProgress (OpProgress):

    def __init__(self, cb=None):
        super().__init__()
        self._id = 1
        self.cb = cb

    def write(self, line):
        line.replace('\f', '')
        if self.cb:
            self.cb(line)
        else:
            print(line)

    def update(self, percent=None):
        pass

    def done(self):
        pass
