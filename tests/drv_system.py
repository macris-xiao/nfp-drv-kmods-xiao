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

class NfpNfdCtrl:
    VERSION      = 0x30
    RX_OFFSET    = 0x50

class DrvSystem(System):
    """
    Class for the system where our driver will be loaded (with an NFP).
    """

    def __init__(self, host, grp, quick=False, _noendsec=False):
        System.__init__(self, host, quick, _noendsec)

        self.part_no = None
        self.fw_name = None
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

    def kernel_ver_ge(self, major, minor):
        return (self.kernel_maj == major and self.kernel_min >= minor) or \
            self.kernel_maj >= major

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

    def insmod(self, module=None, netdev=False, userspace=None, reset=None,
               params='', fail=True):
        if not module:
            module = self.mod
        elif module == "nth":
            module = self.mod_nth
        if module == self.mod and not netdev is None:
            params += ' nfp_pf_netdev=%d' % netdev
        if module == self.mod and not userspace is None:
            params += ' nfp_dev_cpp=%d' % userspace
        if module == self.mod and not reset is None:
            params += ' nfp_reset=%d' % reset

        ret, out = self.cmd('insmod %s %s' % (module, params), fail=fail)
        # Store the module name for cleanup
        if ret == 0:
            m = os.path.basename(module)
            m = os.path.splitext(m)[0]
            self._mods.add(m)
        # Select the NFP if it's NTH
        if module == self.mod_nth:
            self.dfs_write('nth/id', self.grp.nfp)
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

    def nfd_reg_read_le32(self, ifc, offset, count=1):
        # Dump the NFD BAR using ethtool into a giant hex string
        cmd =  'ethtool -d %s raw on' % (ifc)
        cmd += ' | hexdump -v -e "1/1 \\"%02X\\""'
        _, data = self.cmd(cmd)
        # Cut out the part we need
        val_s = data[offset * 2:(offset + count * 4) * 2]
        # Byte swap
        res = 0
        for val_i in range(0, count):
            # Byte swap one 32bit value
            for byte_i in range(6, -2, -2):
                start = val_i * 8 + byte_i
                res = res << 8 | int('0x' + val_s[start:start + 2], 16)
        return res

    def dfs_read(self, path):
        _, data = self.cmd('echo `cat %s`' % (os.path.join(self.dfs_dir, path)))
        return data.strip()

    def dfs_read_raw(self, path):
        _, data = self.cmd('cat %s' % (os.path.join(self.dfs_dir, path)))
        return data

    def dfs_nn_port_lines(self, method, path):
        port_path = 'nfp_net/0000:%s/port%d' % (self.grp.pci_id, 0)
        path = os.path.join(self.dfs_dir, port_path, path)
        _, data = self.cmd('%s %s | wc -l' % (method, path))
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
        _, data = self.cmd_hwinfo(what)
        return data.split('=')[1].strip()

    def get_part_no(self):
        if self.part_no:
            return self.part_no
        self.insmod()
        self.part_no = self.get_hwinfo('assembly.partno')
        self.rmmod()
        return self.part_no

    def get_fw_name(self):
        if self.fw_name:
            return self.fw_name

        t_tbl = { '10G' : [ 10 ],
                  '25G' : [ 25 ],
                  '4x10G' : [ 10, 10, 10, 10 ],
                  '40G' : [ 40 ] }
        amda = self.get_part_no()

        self.insmod()
        _, media = self.cmd_media()
        self.rmmod()

        links = []
        for phy in media.split('\n'):
            cfg = re.search('=(.*G)', phy)
            if not cfg:
                continue
            links += t_tbl[cfg.groups()[0]]

        self.fw_name = 'nic_' + amda
        i = 0
        while i < len(links):
            j = 1
            while i + j < len(links) and links[i] == links[i + j]:
                j += 1
            self.fw_name += '_%dx%d' % (j, links[i])
            i += j
        self.fw_name += '.nffw'

        return self.fw_name

    def get_rtsym_scalar(self, symbol, fail=True):
        ret, out = self.cmd_rtsym(cmd=symbol, fail=fail)
        if ret:
            return ~0

        vals = out.split()
        return int(vals[1], 16) | (int(vals[2], 16) << 32)

    def nffw_load(self, fw, fail=True):
        return self.cmd('nfp-nffw load -n %d %s' %
                        (self.grp.nfp, fw), fail=fail)

    def nffw_unload(self, fail=True):
        return self.cmd('nfp-nffw unload -n %d' % (self.grp.nfp), fail=fail)

    def cmd_res(self, cmd, fail=True):
        return self.cmd('nfp-res -n %d %s' % (self.grp.nfp, cmd), fail=fail)

    def cmd_rtsym(self, cmd, fail=True):
        return self.cmd('nfp-rtsym -n %d %s' % (self.grp.nfp, cmd), fail=fail)

    def cmd_hwinfo(self, cmd, fail=True):
        return self.cmd('nfp-hwinfo -n %d %s' % (self.grp.nfp, cmd), fail=fail)

    def cmd_phymod(self, cmd, fail=True):
        return self.cmd('nfp-phymod -n %d %s' % (self.grp.nfp, cmd), fail=fail)

    def cmd_nsp(self, cmd, fail=True):
        return self.cmd('nfp-nsp -n %d %s' % (self.grp.nfp, cmd), fail=fail)

    def cmd_media(self, cmd='', fail=True):
        return self.cmd('nfp-media -n %d %s' % (self.grp.nfp, cmd), fail=fail)
