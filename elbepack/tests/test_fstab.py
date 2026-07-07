# ELBE - Debian Based Embedded Rootfilesystem Builder
# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: 2026 Linutronix GmbH

import os
import shutil
import subprocess

import pytest

from elbepack.fstab import fstabentry
from elbepack.treeutils import etree


def _which_with_sbin(name):
    path = os.environ.get('PATH', '') + os.pathsep + '/sbin:/usr/sbin:/usr/local/sbin'
    return shutil.which(name, path=path)


requires_vfat_tools = pytest.mark.skipif(
    not all(_which_with_sbin(b) for b in ('mkfs.vfat', 'mcopy', 'mdir')),
    reason='requires dosfstools and mtools',
)


@pytest.fixture(autouse=True)
def _sbin_on_path(monkeypatch):
    # mkfs.vfat lives in /sbin or /usr/sbin, which is not necessarily on
    # PATH; fstabentry.mkfs() runs it through a subprocess that inherits
    # the current environment, so extend PATH for the duration of the test.
    monkeypatch.setenv(
        'PATH', os.environ.get('PATH', '') + os.pathsep + '/sbin:/usr/sbin:/usr/local/sbin')


def _vfat_entry():
    xml = """
    <partition>
      <source>/dev/mmcblk0p1</source>
      <label>esp</label>
      <mountpoint>/boot</mountpoint>
      <fs>
        <type>vfat</type>
      </fs>
    </partition>
    """
    return fstabentry(None, etree(None, string=xml).root)


def _mdir(image):
    return subprocess.run(
        ['mdir', '-i', image, '::'], check=True, capture_output=True, text=True).stdout


@requires_vfat_tools
def test_mkfs_vfat_copies_dotfiles_and_regular_files(tmp_path):
    src = tmp_path / 'src'
    src.mkdir()
    (src / '.hidden').write_text('secret')
    (src / 'visible.txt').write_text('data')

    image = tmp_path / 'image.img'
    subprocess.run(['truncate', '-s', '1M', str(image)], check=True)

    needs_cp = _vfat_entry().mkfs(str(image), str(src) + '/.')

    assert not needs_cp
    listing = _mdir(str(image))
    assert '.hidden' in listing
    assert 'visible' in listing


@requires_vfat_tools
def test_mkfs_vfat_empty_tree_does_not_fail(tmp_path):
    src = tmp_path / 'src'
    src.mkdir()

    image = tmp_path / 'image.img'
    subprocess.run(['truncate', '-s', '1M', str(image)], check=True)

    needs_cp = _vfat_entry().mkfs(str(image), str(src) + '/.')

    assert not needs_cp
    assert 'No files' in _mdir(str(image))
