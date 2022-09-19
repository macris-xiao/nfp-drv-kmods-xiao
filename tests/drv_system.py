#
# Copyright (C) 2016-2017,  Netronome Systems, Inc.  All rights reserved.
#
"""
Driver DUT class
"""

import json
import os
import time
import re
import netro.testinfra
from netro.testinfra.system import *
from netro.testinfra.system import _parse_ethtool
from netro.testinfra.nti_exceptions import NtiError, NtiGeneralError
from common_test import NtiSkip
from linux_system import LinuxSystem
from nfd import NfdBarOff, NfdTlvCap

class DrvSystem(LinuxSystem):
    """
    Class for the system where our driver will be loaded (with an NFP).
    """

    def __init__(self, host, grp, quick=False, _noendsec=False):
        LinuxSystem.__init__(self, host, grp, quick, _noendsec)

        self.part_no = None
        self.fw_name = None
        self.fw_name_serial = None
        self.pci_device_id = None
        self.vendor_id = None
        self.netdevfw_dir = None
        self.grp = grp

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

    def copy_bpf_perf_samples(self):
        if hasattr(self, 'xdp_perf_dir'):
            return

        self.xdp_perf_dir = os.path.join(self.tmpdir, 'xdp_perf')
        self.cmd('mkdir %s' % self.xdp_perf_dir)
        self.cp_to(os.path.join(self.grp.samples_xdp_perf, '*.o'),
                   self.xdp_perf_dir)

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

    def skip_test_if_mode_switchdev(self):
        _, mode = self.devlink_eswitch_mode_get(fail=False)
        if mode == "switchdev":
            raise NtiSkip("Switchdev-only app")

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

    def devlink_param_get(self, param, fail=True):
        ret, out = self.cmd('devlink -jp dev param show pci/%s name %s' %
                            (self.grp.pci_dbdf, param), fail=fail)
        if ret == 0:
            out = json.loads(out)["param"]["pci/" + self.grp.pci_dbdf][0]["values"]
            out = out[0]["value"]
        return ret, out

    def devlink_param_set(self, param, cmode, value, fail=True):
        return self.cmd('devlink dev param set pci/%s name %s cmode %s value %s' %
                        (self.grp.pci_dbdf, param, cmode, value), fail=fail)

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

    def ip_link_xdp_prog_ids(self, ifc):
        res = { "generic" : None, "drv" : None, "offload" : None }
        remap = { 1 : "drv", 2 : "generic", 3 : "offload" }

        links = self.ip_link_show(ifc=ifc)
        if "xdp" not in links or "attached" not in links["xdp"]:
            return res

        for attached in links["xdp"]["attached"]:
            res[remap[attached["mode"]]] = attached["prog"]["id"]

        return res

    def ip_link_xdp_progs(self, ifc):
        res = self.ip_link_xdp_prog_ids(ifc)
        _, progs = self.bpftool_prog_list()

        for k in res.keys():
            for p in progs:
                if res[k] is None:
                    continue
                if p["id"] == res[k]:
                    res[k] = p
                    break

        return res

    def ip_link_xdp_maps(self, ifc, progs=None):
        res = { "generic" : [], "drv" : [], "offload" : [] }

        if progs is None:
            progs = self.ip_link_xdp_progs(ifc=ifc)
        if progs == { "generic" : None, "drv" : None, "offload" : None }:
            return res

        _, maps = self.bpftool_map_list()
        for k in res.keys():
            if progs[k] is None:
                continue

            for m in maps:
                if m["id"] in progs[k]["map_ids"]:
                    res[k].append(m)

        return res

    def tc_filter_show_progs(self, ifc):
        # To do: fix tc command and processing once JSON is fixed upstream
        cmd = 'tc filter show dev %s ingress' % ifc
        _, out = self.cmd(cmd, fail=False)
        res = { "skip_hw" : [], "skip_sw" : [], "no_skip" : [] }
        for line in out.split("\n"):
            search = re.search("(skip_sw|skip_hw)? (?:not_)?in_hw id (\d+)",
                               line)
            if search is not None:
                key = search.group(1) or "no_skip"
                res[key].append(search.group(2))
        return res

    def bpftool_timed(self, param, fail=True):
        start_time = time.time()
        ret, out = self.cmd("bpftool " + param, fail=fail)
        elaps_time = time.time() - start_time
        return ret, out, elaps_time

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
        """
        This function returns the NSP API Version
        """
        if ifc:
            _, out = self.cmd('ethtool -i %s' % (ifc))

            sp_ver = re.search('firmware-version: [^ ]* (\d*\.\d*)', out)
            if not sp_ver:
                raise NtiError("Can't get NSP API version - ethtool output invalid")

            sp_ver = sp_ver.groups()[0]
        else: # Use userspace
            _, out = self.cmd_nsp("-v")

            sp_ver = out.split()[0]

        sp_ver = sp_ver.split(".")

        if len(sp_ver) != 2:
            raise NtiError("Can't get NSP API version - sp ver invalid")
        if sp_ver[0] != "0":
            raise NtiError("Non-0 major version")

        return int(sp_ver[1])

    def get_bsp_ver(self):
        """
        This function returns the BSP Version as a string format,
        e.g. 22.07-1
        """
        _, out = self.cmd('dmesg | awk -F ":" "/BSP/ {print \$5}"'
                          ' | tail -n1 | tr -d "* "')

        # Check for old BSP version e.g. BSP version is
        # 010217.010217.010325, therefore out = 010325
        oldBSP = re.compile(r"[0-9]{6}")
        if out == oldBSP or out == "":
            raise NtiSkip("The BSP version is either outdated for "
                          "these tests or BSP tools is not installed.")

        return out

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

        out = re.search('nfp-dev-cpp\.(\d*)', out)
        if out is None:
            raise NtiGeneralError("Failed to find CPP handle")

        self.grp.nfp = int(out.group(1))

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

            if self.grp.netdevfw_nfd3 and self.get_pci_device_id() == '3800':
                params += ' force_40b_dma=1'

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
        res = re.search('Name=?:? ?([^^]{1,15})', out).groups()
        return [x.strip() if isinstance(x, str) else None for x in res]

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

    def nfd_get_vnic_cap(self, ifc, cap, return_pos=False):
        regs = self.nfd_reg_read_le32(ifc, 0, NfdBarOff.NFD_BAR_OFF_MAX)

        LOG('regs %d %r' % (len(regs), regs))

        pos = NfdBarOff.TLV_BASE / 4
        if regs[pos] == 0:
            return None

        while True:
            l = regs[pos] & 0xffff
            t = (regs[pos] << 1) >> 17

            pos += 1

            if t == cap:
                if return_pos:
                    return pos * 4 - 4
                else:
                    return regs[pos:pos + l / 4]
            if t == NfdTlvCap.UNKNOWN:
                raise NtiError('Parsing vNIC caps failed off:%d - UNKNOWN cap' %
                               (pos))
            if t == NfdTlvCap.END:
                return None

            pos += l / 4

    def dfs_read(self, path):
        _, data = self.cmd('echo `cat %s`' % (os.path.join(self.dfs_dir, path)))
        return data.strip()

    def dfs_read_raw(self, path):
        # Read in single-byte hex format (no line suppression) and discard newlines.
        _, data = self.cmd('od %s -v -t x1 -A n | tr -d " \n"' %
                            (os.path.join(self.dfs_dir, path)))
        data = str(bytearray.fromhex(data))
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

    def dfs_write(self, path, data, do_fail=False, timeout=None,
                  include_stderr=False):
        cmd = '/bin/echo -ne "%s" > %s' % (data,
                                           os.path.join(self.dfs_dir, path))
        if timeout:
            cmd = ('timeout %d ' % (timeout)) + cmd
        ret, data = self.cmd(cmd, fail=False, include_stderr=include_stderr)
        failed = ret != 0
        if do_fail is not None and failed != do_fail:
            raise NtiGeneralError('DebugFS write fail mismatch for file %s' \
                                  ' (did:%s, wanted:%s)' % \
                                  (path, failed, do_fail))
        if include_stderr:
            return ret, data
        return ret

    def get_hwinfo_full(self, what, params=''):
        _, data = self.cmd_hwinfo(params + ' ' + what)
        return [x.split("=") for x in data.split()]

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
        try:
            self.part_no = self.get_hwinfo('nffw.partno')
        except:
            self.part_no = self.get_hwinfo('assembly.partno')
        if load:
            self.rmmod()
        return self.part_no

    def get_amda_only(self):
        # This returns the AMDAXXXX part of the card number
        # for some cards there is different variations.
        # e.g. crypto and no crypto
        return self.get_part_no().split('-')[0]

    def get_pci_device_id(self):
        if self.pci_device_id:
            return self.pci_device_id
        _, pci_device_info = self.cmd('lspci | grep %s' % self.grp.pci_id)
        self.pci_device_id = pci_device_info.split()[-1]
        return self.pci_device_id

    def get_vendor_id(self):
        # Determine vendor ID : 19ee (netronome) or 1da8 (corigine)
        if self.vendor_id:
            return self.vendor_id

        _, out = self.cmd('cat /sys/bus/pci/devices/0000:%s/vendor' %
                          self.group.pci_id, fail=False)
        vendor_id = out.split('x')[1].strip()
        if vendor_id not in ['19ee', '1da8']:
            raise NtiError('Unexpected vendor ID: %s' % (vendor_id))
        else:
            self.vendor_id = vendor_id
        return self.vendor_id

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

    def get_nsp_uptime(self):
        _, out = self.cmd_nsptask("")
        return int(out.split()[1])

    def bsp_cmd(self, cmd, params, fail):
        full_cmd  = os.path.join(self.grp.bsppath, 'bin', 'nfp-') + cmd
        full_cmd += ' -Z %s ' % (self.grp.pci_dbdf)
        full_cmd += params

        return self.cmd(full_cmd, fail=fail)

    def nffw_status(self, fail=True):
        return self.bsp_cmd('nffw status', '', fail=fail)

    def nffw_load(self, fw, fail=True):
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

    def cmd_nsptask(self, cmd, fail=True):
        return self.bsp_cmd('nsptask', cmd, fail=fail)

    def cmd_media(self, cmd='', fail=True):
        return self.bsp_cmd('media', cmd, fail=fail)

    def cmd_fis(self, cmd='', fail=True):
        return self.bsp_cmd('fis', cmd, fail=fail)
