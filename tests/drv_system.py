#
# Copyright (C) 2016-2017,  Netronome Systems, Inc.  All rights reserved.
#
"""
Driver DUT class
"""

import os
import netro.testinfra
from netro.testinfra.system import *
from netro.testinfra.nti_exceptions import NtiGeneralError

class DrvSystem(System):
    """
    Class for the system where our driver will be loaded (with an NFP).
    """

    def __init__(self, host, grp, quick=False, _noendsec=False):
        System.__init__(self, host, quick, _noendsec)

        self.part_no = None
        self.grp = grp
        self.tmpdir = self.make_temp_dir()

        # Check if XDP is available
        ret, _ = self.cmd('ls ~/xdp/pass.py /lib/modules/`uname -r`/build',
                          fail=False)
        self.has_xdp = ret == 0

        # Check kernel version
        _, self.kernel_ver = self.cmd('uname -r')
        self.kernel_maj = int(self.kernel_ver.split('.')[0])
        self.kernel_min = int(self.kernel_ver.split('.')[1])

        # Find DebugFS
        self.dfs_dir = None
        ret, dfs_mount = self.cmd('mount | grep debugfs', fail=False)
        if ret == 0:
            self.dfs_dir = dfs_mount.split()[2]

        # Copy driver and firmware images
        self.mod = os.path.join(self.tmpdir, 'nfp.ko')
        self.cp_to(self.grp.nfpkmod, self.mod)
        self.mod_nth = os.path.join(self.tmpdir, 'nfp_test_harness.ko')
        self.cp_to(self.grp.nthkmod, self.mod_nth)

        self._mods = set()

    def cp_to(self, src, dst):
        """
        Copy a file from the local machine to the system.

        @src  Path to local file
        @dst  Path to the destination on the system

        This simply throws and exception if there is any error
        """
        if self.local_cmds:
            cmd = 'cp -r {src} {dst}'.format(src=src,dst=dst)
        else:
            cmd = "scp -qr %s %s:%s" % (src, self.rem, dst)

        # print ">>> Copy To : %s" % cmd

        LOG_sec ("CP %s -> %s:%s" % (src, self.host, dst))
        _, _ = cmd_log(cmd)
        LOG_endsec()
        return

    def insmod(self, module=None, netdev=False, params='', fail=True):
        if not module:
            module = self.mod
        elif module == "nth":
            module = self.mod_nth
        if module == self.mod and not netdev is None:
            params += ' nfp_pf_netdev=%d' % netdev

        ret, out = self.cmd('insmod %s %s' % (module, params), fail=fail)
        if ret == 0:
            m = os.path.basename(module)
            m = os.path.splitext(m)[0]
            self._mods.add(m)
        return ret, out

    def rmmod(self, module="nfp"):
        ret, out = self.cmd('rmmod %s' % (module))
        if ret == 0 and module in self._mods:
            self._mods.remove(module)
        return ret, out

    def reset_mods(self):
        while self._mods:
            m = self._mods.pop()
            self.rmmod(module=m)

    def dfs_read(self, path):
        _, data = self.cmd('echo `cat %s`' % (os.path.join(self.dfs_dir, path)))
        return data.strip()

    def dfs_read_raw(self, path):
        _, data = self.cmd('cat %s' % (os.path.join(self.dfs_dir, path)))
        return data

    def dfs_write(self, path, data, do_fail=False):
        ret, data = self.cmd('echo -n "%s" > %s' %
                             (data, os.path.join(self.dfs_dir, path)),
                             fail=False)
        failed = ret != 0
        if failed != do_fail:
            raise NtiGeneralError('DebugFS write fail mismatch for file %s' \
                                  ' (did:%s, wanted:%s)' % \
                                  (path, failed, do_fail))

    def get_hwinfo(self, what):
        _, data = self.cmd('nfp-hwinfo %s' % (what))
        return data.split('=')[1].strip()

    def get_part_no(self):
        if self.part_no:
            return self.part_no
        self.insmod()
        self.part_no = self.get_hwinfo('assembly.partno')
        self.rmmod()
        return self.part_no
