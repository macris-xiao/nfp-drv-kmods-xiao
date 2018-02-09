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
    MAX_RXRINGS	= 0x40
    MAX_MTU    = 0x44
    START_RXQ	= 0x4c
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

        # Copy driver and firmware images if needed
        if self.grp.installed_drv:
            self.mod = 'nfp'
            self.mod_nth = 'nfp_test_harness'
            ret, _ = self.cmd('modinfo nfp 2>/dev/null | grep -q dev_cpp', fail=False)
            if not ret == 0:
                self.grp.upstream_drv = True
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
        self._bck_pids = []

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

    def copy_bpf_perf_samples(self):
        if hasattr(self, 'xdp_perf_dir'):
            return

        self.xdp_perf_dir = os.path.join(self.tmpdir, 'xdp_perf')
        self.cmd('mkdir %s' % self.xdp_perf_dir)
        self.cp_to(os.path.join(self.grp.samples_xdp_perf, '*.o'),
                   self.xdp_perf_dir)

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

    def devlink_eswitch_mode_get(self, fail=True):
        ret, out = self.cmd('devlink -jp dev eswitch show pci/%s' %
                            (self.grp.pci_dbdf), fail=fail)
        if ret == 0:
            out = json.loads(out)["dev"]["pci/" + self.grp.pci_dbdf]["mode"]
        return ret, out

    def devlink_eswitch_mode_set(self, mode, fail=True):
        return self.cmd('devlink dev eswitch set pci/%s mode %s' %
                        (self.grp.pci_dbdf, mode), fail=fail)

    def devlink_any_list(self, param, obj, fail=True):
        devlink = "pci/" + self.grp.pci_dbdf
        ret, out = self.cmd('devlink -jp %s show' % (param), fail=fail)
        if ret == 0:
            out = json.loads(out)[obj]
            if devlink in out:
                out = out[devlink]
            else:
                out = {}
        return ret, out

    def devlink_sb_list(self, fail=True):
        return self.devlink_any_list("sb", "sb", fail=fail)

    def devlink_sb_pool_list(self, fail=True):
        return self.devlink_any_list("sb pool", "pool", fail=fail)

    def devlink_sb_pool_set(self, sb, pool, size, thtype="static", fail=True):
        cmd = 'devlink sb pool set pci/{pci} sb {sb} pool {pool} ' \
              'size {size} thtype {thtype}'
        cmd = cmd.format(pci=self.grp.pci_dbdf, sb=sb, pool=pool, size=size,
                         thtype=thtype)
        return self.cmd(cmd, fail=fail)

        ret, out = self.cmd('devlink -jp sb show', fail=fail)
        if ret == 0:
            out = json.loads(out)["sb"]["pci/" + self.grp.pci_dbdf]
        return ret, out

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

    def ethtool_get_fwdump(self, ifc, level, fail=True):
        self.cmd('ethtool -W %s %d' % (ifc, level), fail=fail)
        self.cmd('ethtool -w %s' % (ifc), fail=fail)

        cmd = ('F=`mktemp -p %s`; '
               'ethtool -w %s data $F && echo -n $F || rm $F' %
               (self.tmpdir, ifc))
        ret, out = self.cmd(cmd, fail=fail)
        if ret != 0:
            return ret, out

        self.mv_from(out, self.grp.tmpdir)
        file_name = os.path.join(self.grp.tmpdir, os.path.basename(out))
        return 0, file_name

    def ip_link_show(self, port=None, ifc=None, details=False):
        cmd = "ip -j"
        if details:
            cmd += ' -d'
        cmd += ' link show'
        if ifc is not None:
            cmd += " dev " + ifc
        elif port is not None:
            cmd += " dev " + self.grp.eth_x[port]
        _, out = self.cmd(cmd)

        res = json.loads(out)
        if ifc is not None or port is not None:
            res = res[0]
        return res

    def bpftool_timed(self, param, fail=True):
        start_time = time.time()
        ret, out = self.cmd("bpftool " + param, fail=fail)
        elaps_time = time.time() - start_time
        return ret, out, elaps_time

    def bpftool(self, param, fail=True):
        ret, out = self.cmd("bpftool -p " + param, fail=fail)
        if len(out) == 0:
            return ret, {}
        return ret, json.loads(out)

    def bpftool_prog_show(self, ident):
        return self.bpftool("prog show id %d" % (ident))

    def bpftool_prog_list(self, fail=True):
        return self.bpftool("prog", fail=fail)

    def bpftool_map_show(self, ident):
        return self.bpftool("map show id %d" % (ident))

    def bpftool_map_list(self, fail=True):
        return self.bpftool("map", fail=fail)

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

        if self.grp.installed_drv:
            ret, out = self.cmd('modprobe %s %s' % (module, params), fail=fail)
        else:
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
                    if s in self.grp.pci_dbdfs:
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

    def __get_mip_info(self, fwpath):
        _, out = self.cmd('readelf -p .note.build_info ' + fwpath)
        return re.search('Name: ([^^]{1,15})(\^JVersion: (.*)\^JBuild Number: (.*)\^J)?\n', out).groups()

    def get_mip_name(self, fwpath):
        return self.__get_mip_info(fwpath)[0]

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
            fwpath = os.path.join(self.tmpdir,
                                  os.path.basename(self.grp.netdevfw))
        else:
            fwpath = os.path.join(self.netdevfw_dir, fwname)

        self.insmod(netdev=True, userspace=True)
        ret, _ = self.cmd_rtsym('_pf0_net_bar0', fail=False)
        if ret != 0:
            self.nffw_unload()
            self.nffw_load('%s' % fwpath)
            self.rmmod()
            self.insmod(netdev=True, userspace=True)
        else:
            # FW is loaded, make sure it's the right one
            fsname = self.get_mip_name(fwpath)
            _, out = self.nffw_status()
            loaded = re.search('Firmware name: (.*)\n', out).groups()[0]
            if fsname != loaded or self.grp.force_fw_reload:
                if fsname != loaded:
                    LOG("FW loaded is '%s' but expected '%s', reloading" %
                        (loaded, fsname))
                else:
                    LOG("Forcing firmware reload")
                self.rmmod()
                self.insmod(netdev=False)
                self.nfp_reset()
                self.reset_mods()
                # Run the same function again
                self.drv_load_netdev_conserving(fwname, nth)
                return

        self.cmd('udevadm settle')

        if nth:
            self.insmod(module="nth")

    def reset_mods(self):
        while self._mods:
            m = self._mods.pop()
            self.rmmod(module=m)

    def background_procs_add(self, pid):
        self._bck_pids.append(pid)

    def background_procs_remove(self, pid):
        self._bck_pids.remove(pid)

    def background_procs_cleanup(self):
        cmds = ""
        for pid in self._bck_pids:
            cmds += 'kill -9 $(cat %s);' % pid
        if cmds:
            self.cmd(cmds, fail=False)
        self._bck_pids = []

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
        res = []
        # Byte swap
        for val_i in range(0, count):
            val = 0
            # Byte swap one 32bit value
            for byte_i in range(6, -2, -2):
                start = val_i * 8 + byte_i
                val = val << 8 | int('0x' + val_s[start:start + 2], 16)
            res.append(val)
        if count == 1:
            return res[0]
        else:
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

    def get_resources(self):
        _, out = self.cmd_res('-L')

        # Iterate over lines skipping header
        resources = []
        for line in out.split('\n')[1:]:
            if not line:
                continue

            fields = line.split()
            name = fields[0]
            cpp_id = fields[2].split(':')[:3]
            addr = fields[2].split(':')[3][2:]
            size = fields[3][3:][:-1]

            cpp_id = "%02x%02x%02x00" % \
                     (int(cpp_id[0]), int(cpp_id[2]), int(cpp_id[1]))

            resources.append((name, cpp_id, addr, size))

        return resources

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

    def nffw_status(self, fail=True):
        return self.bsp_cmd('nffw status', '', fail=fail)

    def nffw_load(self, fw, fail=True):
        if self.kernel_ver.find("debug") == -1:
            return self.bsp_cmd('nffw load', fw, fail=fail)
        else:
            return self.cmd_nsp('-F ' + fw, fail=fail)

    def nffw_unload(self, fail=True):
        return self.cmd_nsp('-R', fail=fail)

    def cmd_reg(self, cmd, fail=True):
        return self.bsp_cmd('reg', cmd, fail=fail)

    def cmd_mem(self, cmd='', fail=True):
        return self.bsp_cmd('mem', cmd, fail=fail)

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
