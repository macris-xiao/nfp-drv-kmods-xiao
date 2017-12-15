#
# Copyright (C) 2016-2017,  Netronome Systems, Inc.  All rights reserved.
#
"""
Driver DUT class
"""

import json
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
    MAX_MTU    = 0x44
    RX_OFFSET  = 0x50
    BPF_STACK_SZ   = 0x88

class DrvSystem(System):
    """
    Class for the system where our driver will be loaded (with an NFP).
    """

    def __init__(self, host, grp, quick=False, _noendsec=False):
        System.__init__(self, host, quick, _noendsec)

        self.part_no = None
        self.fw_name = None
        self.fw_name_serial = None
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

        if self.grp.netdevfw:
            self.cp_to(self.grp.netdevfw, self.tmpdir)

        if self.grp.netdevfw_dir:
            self.netdevfw_dir = os.path.join(self.tmpdir, "netdevfw")
            self.cp_to(self.grp.netdevfw_dir, self.netdevfw_dir)

        self.cmd('modprobe devlink; modprobe vxlan', fail=False)
        self._mods = set()
        self._dirs = set()

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

        self.c_samples_dir = os.path.join(self.tmpdir, 'c')
        self.cmd('mkdir %s' % self.c_samples_dir)
        self.cp_to(os.path.join(self.grp.samples_c, '*'),
                   self.c_samples_dir)

        return

    def count_our_netdevs(self):
        cmd = 'ls /sys/bus/pci/devices/%s/net/ | wc -l' % self.grp.pci_dbdf

        _, out = self.cmd(cmd)

        return int(out)

    def link_wait(self, ifc, timeout=8, state=True):
        tgt_time = time.time() + timeout
        up_time = 0
        down_time = 0

        while True:
            ret, _ = self.cmd('ip link show dev %s | grep LOWER_UP' %
                              (ifc), fail=False)

            now = time.time()
            # Carbon triggers spurious up events, which are followed by an
            # immediate down.  We need to make sure link is stable for at
            # least half a second.
            if ret == 0:
                down_time = 0
                if up_time == 0:
                    up_time = now
                if state and (now - up_time >= 0.5):
                    return
            else:
                up_time = 0
                if down_time == 0:
                    down_time = now
                if (not state) and (now - down_time >= 0.5):
                    return

            if now >= tgt_time:
                if state:
                    raise NtiError("Timeout waiting for LINK UP on interface %s" % (ifc))
                else:
                    raise NtiError("Timeout waiting for LINK DOWN on interface %s" % (ifc))
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

    def ethtool_set_fec(self, ifc, fec, fail=True):
        return self.cmd('ethtool --set-fec %s encoding %s' %
                        (ifc, fec),
                        include_stderr=True, fail=fail)

    def ethtool_get_fec(self, ifc, fail=True):
        return self.cmd('ethtool --show-fec %s' %
                        (ifc), fail=fail)

    def ip_link_show(self, port=None, ifc=None):
        cmd = "ip -j link show"
        if ifc is not None:
            cmd += " " + ifc
        elif port is not None:
            cmd += " " + self.grp.eth_x[port]
        _, out = self.cmd(cmd)

        return json.loads(out)

    def bpftool(self, param, fail=True):
        ret, out = self.cmd("bpftool -p " + param, fail=fail)
        if len(out) == 0:
            return ret, {}
        return ret, json.loads(out)

    def bpftool_prog_list(self, expect=None, fail=True):
        ret, progs = self.bpftool("prog", fail=fail)
        if expect is not None:
            if len(progs) != expect:
                raise NtiError("System has %d programs, expected %d" %
                               (len(progs), expect))
        return ret, progs

    def bpftool_map_list(self, expect=None, fail=True):
        ret, maps = self.bpftool("map", fail=fail)
        if expect is not None:
            if len(maps) != expect:
                raise NtiError("System has %d maps, expected %d" %
                               (len(maps), expect))
        return ret, maps

    def bpf_wait_progs_clear(self, expected=0, n_retry=30):
        for i in range(n_retry):
            ret, progs = self.bpftool_prog_list(fail=False)
            if ret:
                continue
            nprogs = len(progs)
            if nprogs == expected:
                return
            time.sleep(0.05)
        err = "Timeout waiting for prog count to settle want %d, have %d" % \
              (expected, nprogs)
        raise Exception(err)

    def bpf_wait_maps_clear(self, expected=0, n_retry=30):
        for i in range(n_retry):
            ret, maps = self.bpftool_map_list(fail=False)
            if ret:
                continue
            nmaps = len(maps)
            if nmaps == expected:
                return
            time.sleep(0.05)
        err = "Timeout waiting for map count to settle want %d, have %d" % \
              (expected, nmaps)
        raise Exception(err)

    def get_nsp_ver(self, ifc=None):
        if ifc:
            _, out = self.cmd('ethtool -i %s' % (ifc))

            sp_ver = re.search('firmware-version: [^ ]* (\d*\.\d*)', out)
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

    def get_nsp_flash_ver(self):
        _, out = self.cmd('dmesg | awk -F "." "/BSP/ {print \$5}" | tail -n1 | tr -d "*"')
        if out == "":
            return 0
        return int(out, 16)

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

    def rm_dir_on_clean(self, path):
        self._dirs.add(path)

    def insmod(self, module=None, netdev=False, userspace=None,
               params='', fail=True):
        if not module or module == 'nfp':
            module = self.mod

            if not netdev is None:
                params += ' nfp_pf_netdev=%d' % netdev
            if not userspace is None:
                params += ' nfp_dev_cpp=%d' % userspace

            if self.grp.upstream_drv and params != '':
                LOG_sec ("SKIP nfp.ko %s" % (params))
                LOG_endsec()
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
            if m == 'nfp' and hasattr(self.grp, 'pci_dbdf'):
                # Unbind all the devices apart from the one we are testing
                _, out = self.cmd('ls /sys/bus/pci/drivers/nfp/')
                for s in out.split():
                    if not s.startswith("0000:"):
                        continue
                    if s == self.grp.pci_dbdf:
                        continue
                    self.cmd('echo %s > /sys/bus/pci/drivers/nfp/unbind' % (s),
                             fail=False)

                if netdev == False or userspace:
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

    # Load the driver, with non-upstream mode don't spawn netdev,
    # in upstream mode do, since it's the only way there.
    def drv_load_any(self):
        if not self.grp.upstream_drv:
            self.insmod()
            return

        # Upstream mode
        # Copy the FW over
        if self.grp.netdevfw:
            self.cmd('mkdir -p /lib/firmware/netronome')
            self.cp_to(self.grp.netdevfw,
                       '/lib/firmware/netronome/' + self.get_fw_name_serial())
        else:
            self.cp_to(self.netdevfw_dir, '/lib/firmware/netronome')

        self.rm_dir_on_clean('/lib/firmware/netronome')

        self.insmod(netdev=None)
        self.cmd('udevadm settle')

    # Load the driver for netdev operation.
    def drv_load_netdev_conserving(self, fwname, nth=True):
        # In upstream mode, just load the driver, there are no tricks
        # to pull off.
        if self.grp.upstream_drv:
            self.drv_load_any()
            return

        # With non-upstream driver, load the module, see if FW is already there,
        # if it isn't load it manually so that the driver won't reset it.
        if not fwname:
            fwname = os.path.join(self.tmpdir,
                                  os.path.basename(self.grp.netdevfw))
        else:
            fwname = os.path.join(self.netdevfw_dir, fwname)

        self.insmod(netdev=True, userspace=True)
        ret, _ = self.cmd_rtsym('_pf0_net_bar0', fail=False)
        if ret != 0:
            self.nffw_unload()
            self.nffw_load('%s' % fwname)
            self.rmmod()
            self.insmod(netdev=True, userspace=True)
        self.cmd('udevadm settle')

        if nth:
            self.insmod(module="nth")

    def reset_mods(self):
        while self._mods:
            m = self._mods.pop()
            self.rmmod(module=m)

    def nfp_reset(self):
        self.cmd_nsp("-R")

    def reset_dirs(self):
        while self._dirs:
            d = self._dirs.pop()
            self.cmd('rm -r ' + d)

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

    def dfs_read_bytes(self, path):
        remote_filename = os.path.join(self.dfs_dir, path)
        local_filename = os.path.join(self.grp.tmpdir, "dfs_read.dat")
        self.cp_from(remote_filename, local_filename)
        with open(local_filename, "rb") as local_file:
            data = local_file.read()
        os.remove(local_filename)
        return data

    def dfs_nn_port_lines(self, method, path):
        port_path = 'nfp_net/0000:%s/vnic%d' % (self.grp.pci_id, 0)
        path = os.path.join(self.dfs_dir, port_path, path)
        _, data = self.cmd('%s %s | wc -l' % (method, path))
        return data

    def dfs_write_bytes(self, path, data):
        remote_filename = os.path.join(self.dfs_dir, path)
        local_filename = os.path.join(self.grp.tmpdir, "dfs_write.dat")
        with open(local_filename, "wb") as local_file:
            local_file.write(data)
        self.cp_to(local_filename, remote_filename)
        # clean up tmp file after cp (mv doesn't work for debugfs file)
        os.remove(local_filename)

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
        return ret

    def get_hwinfo(self, what, params=''):
        _, data = self.cmd_hwinfo(params + ' ' + what)
        return data.split('=')[1].strip()

    def get_fw_name_any(self):
        if self.grp.upstream_drv:
            return self.get_fw_name_serial()
        else:
            return self.get_fw_name()

    def get_fw_name_serial(self):
        if self.fw_name_serial:
            return self.fw_name_serial

        _, out = self.cmd('lspci -s %s -vv' % self.grp.pci_id)
        DSN = re.search("Device Serial Number (.*)", out).group(1)

        self.fw_name_serial = "serial-%s.nffw" % (DSN)
        return self.fw_name_serial

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

        value = 0
        words = out.split()
        for word in reversed(words[1:]):
            value = int(word, 16) | value << 32

        LOG_sec("CPP RTsym lookup '%s'" % symbol)
        LOG("value: %d" % value)
        LOG_endsec()

        return value

    def nfp_phymod_get_speed(self, idx):
        _, out = self.cmd_phymod('-E | grep -C1 eth%d | tail -1' % (idx))

        speed = re.search(' *(\d*)G', out)

        return int(speed.groups()[0]) * 1000

    def bsp_cmd(self, cmd, params, fail):
        full_cmd  = os.path.join(self.grp.bsppath, 'bin', 'nfp-') + cmd
        full_cmd += ' -Z %s ' % (self.grp.pci_dbdf)
        full_cmd += params

        return self.cmd(full_cmd, fail=fail)

    def nffw_load(self, fw, fail=True):
        if self.kernel_ver.find("debug") == -1:
            return self.bsp_cmd('nffw load', fw, fail=fail)
        else:
            return self.cmd_nsp('-F ' + fw, fail=fail)

    def nffw_unload(self, fail=True):
        if self.kernel_ver.find("debug") == -1:
            return self.bsp_cmd('nffw unload', '', fail=fail)
        else:
            return self.cmd_nsp('-R', fail=fail)

    def cmd_reg(self, cmd, fail=True):
        return self.bsp_cmd('reg', cmd, fail=fail)

    def cmd_res(self, cmd, fail=True):
        return self.bsp_cmd('res', cmd, fail=fail)

    def cmd_rtsym(self, cmd, fail=True):
        return self.bsp_cmd('rtsym', cmd, fail=fail)

    def cmd_hwinfo(self, cmd, fail=True):
        return self.bsp_cmd('hwinfo', cmd, fail=fail)

    def cmd_phymod(self, cmd, fail=True):
        return self.bsp_cmd('phymod', cmd, fail=fail)

    def cmd_nsp(self, cmd, fail=True):
        return self.bsp_cmd('nsp', cmd, fail=fail)

    def cmd_media(self, cmd='', fail=True):
        return self.bsp_cmd('media', cmd, fail=fail)
