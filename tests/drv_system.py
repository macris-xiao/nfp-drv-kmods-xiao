#
# Copyright (C) 2016-2017,  Netronome Systems, Inc.  All rights reserved.
#
"""
Driver DUT class
"""

import os
import time
import netro.testinfra
from netro.testinfra.system import *
from netro.testinfra.nti_exceptions import NtiError, NtiGeneralError
from common_test import NtiSkip

class NfpNfdCtrl:
    MTU        = 0x18
    FLBUFSZ    = 0x1c
    VERSION    = 0x30
    RX_OFFSET  = 0x50

class DrvSystem(System):
    """
    Class for the system where our driver will be loaded (with an NFP).
    """

    def __init__(self, host, grp, quick=False, _noendsec=False):
        System.__init__(self, host, quick, _noendsec)

        self.part_no = None
        self.fw_name = None
        self.netdevfw_dir = None
        self.grp = grp
        self.tmpdir = self.make_temp_dir()

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
        if self.grp.upstream_drv:
            self.mod = self.grp.nfpkmod
            self.mod_nth = ''
        else:
            self.mod = os.path.join(self.tmpdir, 'nfp.ko')
            self.cp_to(self.grp.nfpkmod, self.mod)
            self.mod_nth = os.path.join(self.tmpdir, 'nfp_test_harness.ko')
            self.cp_to(self.grp.nthkmod, self.mod_nth)

        if self.grp.netdevfw_dir:
            self.netdevfw_dir = os.path.join(self.tmpdir, "netdevfw")
            self.cp_to(self.grp.netdevfw_dir, self.netdevfw_dir)

        self.cmd('modprobe devlink; modprobe vxlan', fail=False)
        self._mods = set()

    def copy_bpf_samples(self):
        if hasattr(self, 'bpf_samples_dir'):
            return

        self.bpf_samples_dir = os.path.join(self.tmpdir, 'bpf')
        self.cmd('mkdir %s' % self.bpf_samples_dir)
        self.cp_to(os.path.join(self.grp.samples_bpf, '*.o'),
                   self.bpf_samples_dir)

        self.xdp_samples_dir = os.path.join(self.tmpdir, 'xdp')
        self.cmd('mkdir %s' % self.xdp_samples_dir)
        self.cp_to(os.path.join(self.grp.samples_xdp, '*.o'),
                   self.xdp_samples_dir)

        return

    def count_our_netdevs(self):
        cmd = 'ls /sys/bus/pci/devices/%s/net/ | wc -l' % self.grp.pci_dbdf

        _, out = self.cmd(cmd)

        return int(out)

    def link_wait(self, ifc, timeout=6):
        tgt_time = time.time() + timeout
        up_time = 0

        while True:
            ret, _ = self.cmd('ip link show dev %s | grep LOWER_UP' %
                              (ifc), fail=False)

            now = time.time()
            # Carbon triggers spurious up events, which are followed by an
            # immediate down.  We need to make sure link is stable for at
            # least half a second.
            if ret == 0:
                if up_time == 0:
                    up_time = now
                if now - up_time >= 0.5:
                    return
            else:
                up_time = 0

            if now >= tgt_time:
                raise NtiError("Timeout waiting for UP on interface %s" % (ifc))
            time.sleep(0.1)

    def devlink_split(self, index, count, fail=True):
        return self.cmd('devlink port split pci/%s/%d count %d' %
                        (self.grp.pci_dbdf, index, count), fail=fail)

    def devlink_unsplit(self, index, fail=True):
        return self.cmd('devlink port unsplit pci/%s/%d' %
                        (self.grp.pci_dbdf, index), fail=fail)

    def ethtool_get_autoneg(self, ifc):
        _, out = self.cmd('ethtool %s | grep Auto-negotiation' % (ifc))

        if out.find(': on') != -1:
            return True
        if out.find(': off') != -1:
            return False
        raise NtiError('Invalid ethtool response: %s' % (out))

    def ethtool_get_speed(self, ifc):
        _, out = self.cmd('ethtool %s' % (ifc))

        speed = re.search('Speed: (\d*)Mb/s', out)

        return int(speed.groups()[0])

    def ethtool_set_speed(self, ifc, speed, fail=True):
        return self.cmd('ifconfig %s down; ethtool -s %s speed %d' %
                        (ifc, ifc, speed),
                        include_stderr=True, fail=fail)

    def get_nsp_ver(self, ifc=None):
        if ifc:
            _, out = self.cmd('ethtool -i %s' % (ifc))

            sp_ver = re.search('sp:([0-9.]*)', out)
            if not sp_ver:
                raise NtiError("Can't get NSP version - ethtool output invalid")

            sp_ver = sp_ver.groups()[0]
        else: # Use userspace
            _, out = self.cmd_nsp("-v")

            sp_ver = out.split()[0]

        sp_ver = sp_ver.split(".")

        if len(sp_ver) != 2:
            raise NtiError("Can't get NSP version - sp ver invalid")
        if sp_ver[0] != "0":
            raise NtiError("Non-0 major version")

        return int(sp_ver[1])

    def kernel_ver_ge(self, major, minor):
        return (self.kernel_maj == major and self.kernel_min >= minor) or \
            self.kernel_maj >= major

    # Reimplement cp_to with -r parameter
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

    def refresh_nfp_id(self, dbdf):
        ret, out = self.cmd('ls /sys/bus/pci/devices/%s/cpp' % (dbdf),
                            fail=False)
        if ret != 0 and not self.grp.nfp is None:
            return

        self.grp.nfp = int(re.search('nfp-dev-cpp\.(\d*)', out).group(1))

    def insmod(self, module=None, netdev=False, userspace=None, reset=None,
               params='', fail=True):
        if not module or module == 'nfp':
            module = self.mod

            if not netdev is None:
                params += ' nfp_pf_netdev=%d' % netdev
            if not userspace is None:
                params += ' nfp_dev_cpp=%d' % userspace
            if not reset is None:
                params += ' nfp_reset=%d' % reset

            if self.grp.upstream_drv and params != '':
                raise NtiSkip("Upstream has no params")

        elif module == "nth":
            module = self.mod_nth

            if self.grp.upstream_drv:
                raise NtiSkip("Upstream has no NTH")

        ret, out = self.cmd('insmod %s %s' % (module, params), fail=fail)
        if ret == 0:
            # Store the module name for cleanup
            m = os.path.basename(module)
            m = os.path.splitext(m)[0]
            self._mods.add(m)

            # Make sure we have up-to-date NFP id
            if m == 'nfp' and hasattr(self.grp, 'pci_dbdf') and \
               (not netdev or userspace):
                self.refresh_nfp_id(self.grp.pci_dbdf)
            # Select the NFP if it's NTH
            elif module == self.mod_nth:
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
        port_path = 'nfp_net/0000:%s/vnic%d' % (self.grp.pci_id, 0)
        path = os.path.join(self.dfs_dir, port_path, path)
        _, data = self.cmd('%s %s | wc -l' % (method, path))
        return data

    def dfs_write(self, path, data, do_fail=False, timeout=None):
        cmd = 'echo -n "%s" > %s' % (data,
                                     os.path.join(self.dfs_dir, path))
        if timeout:
            cmd = ('timeout %d ' % (timeout)) + cmd
        ret, data = self.cmd(cmd, fail=False)
        failed = ret != 0
        if do_fail is not None and failed != do_fail:
            raise NtiGeneralError('DebugFS write fail mismatch for file %s' \
                                  ' (did:%s, wanted:%s)' % \
                                  (path, failed, do_fail))
        return failed != do_fail

    def get_hwinfo(self, what, params=''):
        _, data = self.cmd_hwinfo(params + ' ' + what)
        return data.split('=')[1].strip()

    def get_part_no(self):
        if self.part_no:
            return self.part_no

        load = not 'nfp' in self._mods
        if load:
            self.insmod()
        self.part_no = self.get_hwinfo('assembly.partno')
        if load:
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
            cfg = re.search('=(\d*G)', phy)
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

    def nfp_phymod_get_speed(self, idx):
        _, out = self.cmd_phymod('-E | grep -C1 eth%d | tail -1' % (idx))

        speed = re.search(' *(\d*)G', out)

        return int(speed.groups()[0]) * 1000

    def bsp_cmd(self, cmd, fail):
        return self.cmd(os.path.join(self.grp.bsppath, 'bin', 'nfp-') + cmd,
                        fail=fail)

    def nffw_load(self, fw, fail=True):
        return self.bsp_cmd('nffw load -n %d %s' %
                        (self.grp.nfp, fw), fail=fail)

    def nffw_unload(self, fail=True):
        return self.bsp_cmd('nffw unload -n %d' % (self.grp.nfp), fail=fail)

    def cmd_reg(self, cmd, fail=True):
        return self.bsp_cmd('reg -n %d %s' % (self.grp.nfp, cmd), fail=fail)

    def cmd_res(self, cmd, fail=True):
        return self.bsp_cmd('res -n %d %s' % (self.grp.nfp, cmd), fail=fail)

    def cmd_rtsym(self, cmd, fail=True):
        return self.bsp_cmd('rtsym -n %d %s' % (self.grp.nfp, cmd), fail=fail)

    def cmd_hwinfo(self, cmd, fail=True):
        return self.bsp_cmd('hwinfo -n %d %s' % (self.grp.nfp, cmd), fail=fail)

    def cmd_phymod(self, cmd, fail=True):
        return self.bsp_cmd('phymod -n %d %s' % (self.grp.nfp, cmd), fail=fail)

    def cmd_nsp(self, cmd, fail=True):
        return self.bsp_cmd('nsp -n %d %s' % (self.grp.nfp, cmd), fail=fail)

    def cmd_media(self, cmd='', fail=True):
        return self.bsp_cmd('media -n %d %s' % (self.grp.nfp, cmd), fail=fail)
