#
# Copyright (C) 2016-2017,  Netronome Systems, Inc.  All rights reserved.
#
"""
Unit test group for the NFP Linux drivers.
"""

import netro.testinfra
from reconfig import ChannelReconfig
from netro.testinfra.test import *
from ..drv_grp import NFPKmodGrp
from ..drv_system import NfpNfdCtrl
from ..ebpf.xdp import XDPTest

###########################################################################
# Unit Tests
###########################################################################


class NFPKmodUnit(NFPKmodGrp):
    """Unit tests for the NFP Linux drivers"""

    summary = "Unit tests used for NFP Linux driver."

    def __init__(self, name, cfg=None, quick=False, dut_object=None,
                 dut=None, nfp=None, nfpkmods=None, mefw=None):

        NFPKmodGrp.__init__(self, name=name, cfg=cfg, quick=quick,
                            dut_object=dut_object)


    def populate_tests(self):
        dut = (self.dut, self.addr_x, self.eth_x, self.addr_v6_x)
        src = (self.host_a, self.addr_a, self.eth_a, self.addr_v6_a)

        T = (('modinfo', Modinfo, "Test if modinfo is correct"),
             ('serial_and_ifc', NFPSerialAndInterface,
              "Read the serial number and interface ID"),
             ('resource', ResourceTest, 'Test in-kernel resource table interface'),
             ('nsp_eth_table', NspEthTable, "Test NSP ETH table functions"),
             ('hwinfo', HWInfoTest, 'Test in-kernel HWInfo interface'),
             ('bsp_version', BspVerTest, "Test NSP BSP Version function"),
             ('sensors', SensorsTest, "Test Hwmon sensors functionality"),
             ('rtsym', RTSymTest, 'Test in-kernel RT-Sym interface'),
             ('fw_names', FwSearchTest, "Test FW requested by the driver"),
             ('sriov', SriovTest, 'Test SR-IOV sysfs interface'),
             ('netdev', NetdevTest, "Test netdev loading"),
             # Tests which assume netdev FW to be loaded
             ('phys_port_name', PhysPortName, "Test port naming"),
             ('params_incompat', ParamsIncompatTest,
              "Test if incompatible parameter combinations are rejected"),
             ('dev_cpp', DevCppTest,
              "Test user space access existence and basic functionality"),
             ('kernel_fw_load', KernelLoadTest, "Test kernel firmware loader"),
             ('bsp_diag', BSPDiag, "Test the basic BSP diagnostics"),
             ('channel_reconfig', ChannelReconfig, "Ethtool channel reconfig"),
             ('ethtool_get_speed', LinkSpeedEthtool, "Ethtool get settings"),
             ('ethtool_aneg', AutonegEthtool,
              "Test setting autonegotiation with ethtool"),
             ('mtu_flbufsz_check', MtuFlbufCheck,
              "Check if driver sets correct fl_bufsz and mtu"),
             ('devlink_port_show', DevlinkPortsShow,
              "Check basic devlink port output"),
             ('port_config', IfConfigDownTest,
              "Check interface operable after FW load with combinations of ifup/ifdown"),
        )

        for t in T:
            self._tests[t[0]] = t[1](src, dut, self, t[0], t[2])


import os
import re
import time
from random import shuffle
from netro.testinfra.nti_exceptions import NtiGeneralError
from netro.testinfra.nrt_result import NrtResult
from netro.testinfra.system import cmd_log
from ..common_test import *

class Modinfo(CommonTest):
    def execute(self):
        # Check if module device table is complete
        entries = ['v000019EEd00006003sv000019EEsd',
                   'v000019EEd00004000sv000019EEsd',
                   'v000019EEd00006000sv000019EEsd',
                   'netronome/nic_AMDA0081-0001_1x40.nffw']

        if not self.group.upstream_drv:
            entries += ['v000019EEd00006010sv000019EEsd',
                        "netronome/%s" % self.dut.get_fw_name()]

        _, out = cmd_log('modinfo %s' % (self.group.nfpkmod))

        for e in entries:
            if out.find(e) == -1:
                raise NtiGeneralError('Entry %s not in the module table' % (e))

class NFPSerialAndInterface(CommonNTHTest):
    def nth_execute(self):
        M = self.dut

        _, out = M.cmd('lspci -s %s -vv' % self.group.pci_id)
        DSN = re.search("Device Serial Number (.*)", out).group(1)
        serial = DSN[0:-6].replace('-', ':')
        interface = DSN[-5:].replace('-', '')

        dfs = M.dfs_read('nth/serial')
        if dfs != serial:
            raise NtiGeneralError("Serial doesn't match debugfs %s vs %s" %
                                  (serial, dfs))
        hwi = M.get_hwinfo('nfp.serial')
        if hwi != serial:
            raise NtiGeneralError("Serial doesn't match HWInfo %s vs %s" %
                                  (serial, hwi))

        dfs = M.dfs_read('nth/interface')
        if dfs != interface:
            raise NtiGeneralError("Interface doesn't match debugfs %s vs %s" %
                                  (interface, dfs))

class ResourceTest(CommonNTHTest):
    def resources_validate(self, want, output, user_space):
        out_lines = output.split('\n')[:-1]

        if len(out_lines) != len(want):
            raise NtiGeneralError("Different resource numbers %d vs %d" %
                                  (len(want), len(out_lines)))

        locked = len(set(i[0] for i in want))
        if user_space.count('LOCKED pci') != locked:
            raise NtiGeneralError("Incorrect number of locked resources %d vs %d" %
                                  (user_space.count('LOCKED pci'), locked))

        for i in range(0, len(want)):
            fields = out_lines[i].split()

            if fields[1] != want[i][0] or fields[3] != want[i][0]:
                raise NtiGeneralError("Bad name %s vs %s %s" %
                                      (want[i][0], fields[1], fields[3]))

            if fields[4] != want[i][1]:
                raise NtiGeneralError("CPP_ID %s vs %s" %
                                      (want[i][1], fields[4]))

            if fields[5] != want[i][2]:
                raise NtiGeneralError("Addr %s vs %s" % (want[i][2], fields[5]))

            if fields[6] != want[i][3]:
                raise NtiGeneralError("Size %s vs %s" % (want[i][3], fields[6]))

            if not re.search("%s.*LOCKED pci" % fields[1], user_space):
                raise NtiGeneralError("Resource %s not locked %s %s" % (want[i][0], "%s.*LOCKED pci" % fields[1], user_space))

    def nth_execute(self):
        M = self.dut

        # Try non-existing resource
        M.dfs_write('resource', "test.xxx", do_fail=True)

        _, out = M.cmd_res('-L')
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

            if name == "nfp.res":
                continue
            resources.append((name, cpp_id, addr, size))

        random.seed(1234)
        random.shuffle(resources)

        locked = []
        for i in range(0, len(resources)):
            name = resources[i][0]

            mismatch = M.dfs_write('nth/resource', name, timeout=5,
                                   do_fail=None)

            rescs = M.dfs_read_raw('nth/resource')
            _, out = M.cmd_res('-L')

            if mismatch and re.search("%s.*LOCKED arm" % name, out):
                self.log("ARM locked %s" % (name),
                         "Skip resource %s, locked by the ARM" % (name))
                continue

            locked.append(resources[i])
            self.resources_validate(locked, rescs, out)

        # Try non-existing resource on filled table
        M.dfs_write('nth/resource', "test.xxx", do_fail=True)

        # Try to lock the table itself
        M.dfs_write('nth/resource', "nfp.res", do_fail=True)

        # Try something already locked
        M.dfs_write('nth/resource', resources[0][0], do_fail=True, timeout=2)

        # Release all resources and see if locks are freed
        for i in range(0, len(locked)):
            M.dfs_write('nth/resource', i)

        _, out = M.cmd_res('-L')
        if out.count("LOCKED pci"):
            raise NtiGeneralError("Locked resources exist on exit")

class NspEthTable(CommonNTHTest):
    def compare_state(self):
        M = self.dut

        tbl = M.dfs_read_raw('nth/eth_table').split('\n')[:-1]
        _, phy = M.cmd_phymod('-E | grep "^eth"')
        phy = phy.strip().split('\n')
        _, nsp = M.cmd_nsp(' -E | grep Configure | tr -d "A-Za-z" | tr +- 10')
        nsp = nsp.strip().split('\n')

        if len(tbl) != len(phy) or len(phy) != len(nsp):
            raise NtiGeneralError("Bad number of items %d %d %d" %
                                  (len(tbl), len(phy), len(nsp)))

        for i in range(0, len(tbl)):
            t = tbl[i].split()
            p = re.match('eth(\d*): NBI[^(]*\((\d)\)\t"([^"]*)" ([^ ]*) (\d*)G',
                         phy[i]).groups()
            n = nsp[i].split()[1:4]

            # First time we run populate the enable_state array
            if len(self.enable_state) <= i:
                self.enable_state += [n[0]]
                self.port2idx += [t[2]]
            # Now force the enable state to what is expected
            n[0] = self.enable_state[i]

            userspace = " ".join((p[0], p[1], p[2], p[3], p[4] + "000") +
                                 tuple(n))
            kernel = " ".join((t[1], t[5], t[8], t[7], t[6]) + tuple(t[9:12]))

            if kernel != userspace:
                raise NtiGeneralError("User space vs kernel mismatch on idx %d | %s vs %s" %
                                      (i, userspace, kernel))

    def flip_state(self, i):
        M = self.dut

        if self.enable_state[i] == '0':
            self.enable_state[i] = '1'
        else:
            self.enable_state[i] = '0'

        LOG ("\nFlip state port %d(%s) from %s\n" % (i, self.port2idx[i],
                                                     self.enable_state[i]))
        M.dfs_write('nth/eth_enable', " ".join((self.port2idx[i],
                                                self.enable_state[i])))

    def nth_execute(self):
        M = self.dut

        self.enable_state = []
        self.port2idx = []

        # Flip there and back (enable order: 0 -> len, disable: len -> 0)
        self.compare_state()
        for i in range(0, len(self.enable_state)):
            self.flip_state(i)
            self.compare_state()
        for i in reversed(range(0, len(self.enable_state))):
            self.flip_state(i)
            self.compare_state()

        # And flip some random ones
        random.seed(1234)
        for i in range(0, len(self.enable_state) / 2 + 1):
            v = random.randrange(len(self.enable_state))
            self.flip_state(v)
            self.compare_state()
            self.flip_state(v)
            self.compare_state()

class HWInfoTest(CommonNTHTest):
    def hwinfo_check(self, keys, vals):
        M = self.dut

        for k in keys:
            M.dfs_write('nth/hwinfo_key', k)
            val = M.dfs_read('nth/hwinfo_val')
            if vals[k] and val != vals[k]:
                raise NtiGeneralError('Value mismatch for key %s: %s != %s' %
                                      (k, vals[k], val))
            hwi = M.get_hwinfo(k)
            if val != hwi:
                raise NtiGeneralError('Value mismatch for key %s: %s != %s' %
                                      (k, vals[k], val))

    def nth_execute(self):
        # We need the keys to be in a specific order
        keys = ["board.exec", "pcie0.type", "platform.setup.version",
                "cpld.version", "arm.mem.base", "board.state"]
        vals = { "board.exec" : "bootloader.bin",
                 "pcie0.type" : "ep",
                 "platform.setup.version" : None,
                 "cpld.version" : None,
                 "arm.mem.base" : None,
                 "board.state" : "15" }

        self.hwinfo_check(keys, vals)
        keys.reverse()
        self.hwinfo_check(keys, vals)
        shuffle(keys)
        self.hwinfo_check(keys, vals)

class BspVerTest(CommonDrvTest):
    def execute(self):
        M = self.dut

        # Clean the old dmesg info
        M.cmd('dmesg -c')

        self.drv_load_any()
        self.nsp_min(16)

        cmd  = 'dmesg | grep "nfp 0000:%s"' % (self.group.pci_id)
        cmd += ' | grep -o "BSP: .*" | cut -c 6- | tr -d "\n"'
        _, ver = M.cmd(cmd)
        comp = ver.split('.')
        if len(comp) != 3:
            raise NtiGeneralError('bad bsp version format: %s %d' %
                                  (ver, len(comp)))
        for i in range(3):
            if len(comp[i]) != 6:
                raise NtiGeneralError('bad bsp version format: %s' % ver)
            if False == all(c in '0123456789abcdefABCDEF' for c in comp[i]):
                raise NtiGeneralError('bad bsp version format (char): %s' % ver)

class SensorsTest(CommonDrvTest):
    def get_attr(self, array, attr):
        for s in array :
            if attr in s :
                return s
        raise NtiError('didn\'t find attr: %s', attr)

    def execute(self):
        M = self.dut

        self.drv_load_any()
        self.nsp_min(15)

        ret, out = M.cmd('sensors -u nfp-pci-%s%s' %
                         (self.group.pci_id[0:2], self.group.pci_id[3:5]))
        if ret != 0:
            raise NtiError('sensors not found')
        lines = out.splitlines()

        temp = float(self.get_attr(lines, "temp1_input").split(':')[1])
        high = float(self.get_attr(lines, "temp1_max").split(':')[1])
        crit = float(self.get_attr(lines, "temp1_crit").split(':')[1])

        if int(high) != 95:
                raise NtiError('invalid high temp val')
        if int(crit) != 105:
                raise NtiError('invalid crit temp val')
        if int(temp) < 15 or int(temp) > 80:
                raise NtiError('invalid temp')

        power = float(self.get_attr(lines, "power1_input").split(':')[1])
        power_lim = float(self.get_attr(lines, "power1_max").split(':')[1])

        if int(power) < 5 or int(power) > 25 :
                raise NtiError('invalid power limit')
        if int(power_lim) != 25:
                raise NtiError('invalid power val')

class RTSymTest(CommonTest):
    def __init__(self, src, dut, group=None, name="", summary=None):
        CommonTest.__init__(self, src, dut, group, name, summary)

        self.fws = [('rm_rts_3', 3), ('rm_rts_17', 17), (None, -22),
                    ('rm1_rts_100', 100),
                    # MIPv2 not supported, yet
                    ('rm2_rts_100', -22),
                    ('rts_100', -22),
                    ('rm_rts_17', 17), ('rm_rts_1', 1),
                    ('rm_rts_0', 0), ('rm_rts_2', 2),
                    ('rm_rts_100', 100)]

        self.syms = ['.mip', '_o', 'i32._two', '_three',
                '_thisisaverylongname000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000end',
        ]
        self.syms += ['_a%d' % i for i in range(5, 101)]

        self.loaded = False
        return

    def check_cnt(self, name, exp):
        val = self.dut.dfs_read('nth/rtsym_count')
        if int(val) != exp:
            self.dut.dfs_read('nth/rtsym_dump')
            raise NtiGeneralError('RTSym count not %d (%s, %s)' % \
                                  (exp, name, val))

    def check_syms(self, name, num):
        M = self.dut

        last = ['_o', '.mip'][num == 1]
        M.dfs_write('nth/rtsym_key', last, do_fail=(num < 1))
        val = M.dfs_read('nth/rtsym_val')
        if val != last and num > 0:
            raise NtiGeneralError('RTSym failed to look at %s (%s, %s)' % \
                                  (last, name, val))

        syms = M.dfs_read('nth/rtsym_dump')
        syms = syms.split().sort()
        dump = self.syms[0:num].sort()
        if syms != dump:
            raise NtiGeneralError('RTSym dump differs for %s (%s, %s)' % \
                                  (name, dump, syms))

    def test_all(self, user_space_load=True):
        M = self.dut

        fwdir_base = os.path.basename(self.group.mefw)
        fwdir = os.path.join('/lib/firmware/netronome/', fwdir_base)

        for tu in self.fws:
            if not tu[0]:
                M.dfs_read('nth/reset')
            elif not user_space_load:
                M.dfs_write('nth/fw_load', 'netronome/%s/%s.nffw' % \
                            (fwdir_base, tu[0]))
            else:
                if self.loaded:
                    M.nffw_unload()
                M.nffw_load('%s.nffw' % (os.path.join(fwdir, tu[0])))
                M.dfs_read('nth/cache_flush')

            self.loaded = bool(tu[0])

            num = tu[1]
            # Account for ".mip" symbol
            if num >= 0:
                num = num + 1
            self.check_cnt(tu[0], num)
            self.check_syms(tu[0], num)


    def execute(self):
        M = self.dut

        M.cmd('mkdir -p /lib/firmware/netronome')
        M.cp_to(self.group.mefw, '/lib/firmware/netronome/')

        M.insmod(reset=True)
        M.insmod(module="nth")

        self.check_cnt('insmod', -22)

        self.test_all()
        self.test_all(user_space_load=False)

    def cleanup(self):
        self.dut.cmd('rm -rf /lib/firmware/netronome')
        self.dut.reset_mods()

class FwSearchTest(CommonDrvTest):
    def prepare(self):
        return self.kernel_min(3, 17)

    def dev_dmesg(self):
        _, out = self.dut.cmd('dmesg -c | grep %s' % (self.group.pci_dbdf))
        return out

    def execute(self):
        M = self.dut

        # Clean the old dmesg info
        M.cmd('dmesg -c')

        names = []
        names.append(M.get_fw_name_serial())
        names.append("pci-%s.nffw" % (self.group.pci_dbdf))
        names.append(M.get_fw_name())

        probe_fail_str = "nfp: probe of %s failed with error -" % \
                         (self.group.pci_dbdf)

        # By default we should not look for FW
        M.insmod()
        out = self.dev_dmesg()
        if out.find('Direct firmware load for ') != -1:
            raise NtiGeneralError('nfp.ko looking for firmware')
        M.rmmod()

        # Request nfp.ko to look for some FW
        M.insmod(params="nfp6000_firmware=_bad_fw_name")
        out = self.dev_dmesg()
        if out.find('Direct firmware load for _bad_fw_name') == -1:
            raise NtiGeneralError('nfp.ko should be looking for firmware')
        M.rmmod()

        # Make load fail
        M.insmod(params="nfp6000_firmware=_bad_fw_name fw_load_required=1")
        out = self.dev_dmesg()
        if out.find(probe_fail_str) == -1:
            raise NtiGeneralError('nfp.ko should fail to load without FW')
        M.rmmod()

        # Check what netdev will look for
        M.insmod(netdev=True, params="fw_load_required=1")
        out = self.dev_dmesg()
        if out.find(probe_fail_str) == -1:
            raise NtiGeneralError('nfp.ko should fail to load without FW')

        for name in names:
            if out.find('netronome/%s: not found' % (name)) == -1:
                raise NtiGeneralError('nfp.ko netdev not looking FW %s' %
                                      (name))
        M.rmmod()

class SriovTest(CommonDrvTest):
    def sriov_set(self, num=0):
        M = self.dut

        M.cmd('echo %s > /sys/bus/pci/devices/0000:%s/sriov_numvfs' %
              (num, self.group.pci_id))
        _, out = M.cmd('lspci -d 19ee:6003 | wc -l')
        got = int(out)
        if got != num:
            raise NtiGeneralError('Incorrect SR-IOV number got:%d want:%d' %
                                  (got, num))

    def execute(self):
        M = self.dut

        # Load vfio_pci first so it binds to the VFs
        M.cmd('modprobe vfio_pci')
        M.cmd('echo 19ee 6003 > /sys/bus/pci/drivers/vfio-pci/new_id')

        M.insmod(reset=True)
        _, out = M.cmd('cat /sys/bus/pci/devices/0000:%s/sriov_totalvfs' %
                       (self.group.pci_id))
        out = out.strip()
        if out != '64':
            raise NtiGeneralError('Incorrect max SR-IOV number %s' % (out))

        # Request various configurations of SR-IOV
        self.sriov_set()
        self.sriov_set(1)
        self.sriov_set()
        self.sriov_set(8)
        self.sriov_set()
        self.sriov_set(64)
        self.sriov_set()

        ret, _ = M.cmd('echo 65 > /sys/bus/pci/devices/0000:%s/sriov_numvfs' %
                       (self.group.pci_id), fail=False)
        if ret == 0:
            raise NtiGeneralError('Incorrect SR-IOV number "65" allowed')

class NetdevTest(CommonDrvTest):
    def execute(self):
        M = self.dut

        # Check FW loading from the user space
        M.insmod(reset=True)
        M.nffw_load('%s' % self.group.netdevfw)
        max_vfs = M.get_rtsym_scalar('nfd_vf_cfg_max_vfs')
        M.rmmod()

        M.refresh()
        netifs_old = len(M._netifs)

        M.insmod(netdev=True)
        time.sleep(1)
        M.refresh()

        netifs_new = len(M._netifs)

        if netifs_new <= netifs_old:
            raise NtiGeneralError('Interfaces was:%s is:%d, expected new ones' %
                                  (netifs_old, netifs_new))

        # See if after kernel load SR-IOV limit was set correctly
        ret, _ = M.cmd('echo %d > /sys/bus/pci/devices/0000:%s/sriov_numvfs' %
                       (max_vfs + 1, self.group.pci_id), fail=False)
        if not ret:
            raise NtiGeneralError('SR-IOV VF limit not obeyed')

        if max_vfs > 0:
            _, out = M.cmd('cat /sys/bus/pci/devices/%s/sriov_totalvfs' %
                           (self.group.pci_dbdf))
            if int(out) != max_vfs:
                raise NtiError("SR-IOV VF limit not reported")

class PhysPortName(CommonNonUpstreamTest):
    def prepare(self):
        return self.kernel_min(4, 1)

    def netdev_execute(self):
        M = self.dut

        cmd =  '''
        cd /sys/class/net/;
        for i in `ls`;
        do
            echo $i $([ -e $i/device ] && basename $(readlink $i/device) || echo no_dev) $(cat $i/phys_port_name || echo no_name) $(ip -o li show dev $i | cut -d" " -f20);
        done
        '''

        _, devs = M.cmd(cmd)

        tbl = M.dfs_read_raw('nth/eth_table')

        devices = devs.split('\n')[:-1]
        found = 0
        for d in devices:
            # <ifname> <pci_id> <phys_port_name> <ethaddr>
            info = d.split()
            ifc = info[0]
            pci_id = info[1]
            port_name = info[2]
            ethaddr = info[3]

            if pci_id[5:] != self.group.pci_id:
                continue
            found += 1

            labels = re.search('%s (\d*)\.(\d*)' % ethaddr, tbl)
            if not labels:
                raise NtiError('MAC addr for interface %s not found in ETH table' %
                               ifc)

            # if label X.1 exists the port is split
            is_split = tbl.find(' %s.1 ' % labels.groups()[0]) != -1
            if is_split:
                want = 'p%ss%s' % labels.groups()
            else:
                want = 'p%s' % labels.groups()[0]

            if want != port_name:
                raise NtiError('Port name incorrect want: %s have: %s' %
                               (want, port_name))

        if found != len(self.group.addr_x):
            raise NtiError('Expected %d interfaces, found %d' %
                           (len(self.group.addr_x), found))

class ParamsIncompatTest(CommonTest):
    def execute(self):
        M = self.dut

        # Check incompatible module param combinations
        bad_combs = ('nfp_pf_netdev=1 nfp6000_firmware="random"',
                     'nfp_pf_netdev=1 nfp_mon_event=1',
                     'nfp_pf_netdev=1 nfp_fallback=1 nfp_dev_cpp=0')

        for p in bad_combs:
            ret, _ = M.insmod(netdev=None, params=p, fail=False)
            if ret == 0:
                M.rmmod()
                raise NtiGeneralError('Combination "%s" loaded' % (p))

class DevCppTest(CommonDrvTest):
    def execute(self):
        M = self.dut

        # Check if user space exists and works by default
        M.insmod()
        M.cmd('ls /dev/nfp-cpp-%d' % self.group.nfp)
        M.cmd_hwinfo('')
        M.rmmod()

        # Check if it doesn't if netdev requested
        M.insmod(netdev=True)
        ret, _ = M.cmd('ls /dev/nfp-cpp-%d' % self.group.nfp, fail=False)
        if ret == 0:
            raise NtiGeneralError('nfp-cpp-dev interface should not exist by default')
        ret, _ = M.cmd_hwinfo('', fail=False)
        if ret == 0:
            raise NtiGeneralError('nfp-cpp-dev should not work by default')
        M.rmmod()

class KernelLoadTest(CommonTest):
    def load_test(self, name):
        M = self.dut

        M.cp_to(self.group.netdevfw, '/lib/firmware/netronome/%s' % name)

        M.refresh()
        netifs_old = M._netifs
        M.insmod(netdev=None)
        time.sleep(1)
        M.refresh()
        netifs_new = M._netifs

        if len(netifs_new) - len(netifs_old) != len(self.dut_addr):
            raise NtiGeneralError('Expected one interface created, got %d' %
                                  (len(netifs_new) - len(netifs_old)))

        new_ifcs = list(set(netifs_new) - set(netifs_old))

        for ifc in new_ifcs:
            if self.dut_ifn.count(ifc) == 0:
                raise NtiError("Interface %s not present after load" % (ifc))

            _, out = M.cmd('ethtool -i %s' % ifc)

            # Ignore other devices if present
            if not re.search(self.group.pci_id, out):
                continue

            i = self.dut_ifn.index(ifc)
            M.cmd('ifconfig %s %s up' % (ifc, self.dut_addr[i]))

        for ifc in new_ifcs:
            self.dut.link_wait(ifc)

        for ifc in new_ifcs:
            i = self.dut_ifn.index(ifc)
            self.ping(i)

        # See if after kernel load SR-IOV limit was set correctly
        max_vfs = self.read_scalar_nffw('nfd_vf_cfg_max_vfs')
        ret, _ = M.cmd('echo %d > /sys/bus/pci/devices/0000:%s/sriov_numvfs' %
                       (max_vfs + 1, self.group.pci_id), fail=False)
        if not ret:
            raise NtiGeneralError('SR-IOV VF limit not obeyed')

        M.rmmod()
        M.cmd('rm /lib/firmware/netronome/%s' % (name))

    def execute(self):
        M = self.dut

        M.cmd('mkdir -p /lib/firmware/netronome')

        self.load_test(M.get_fw_name_any())

    def cleanup(self):
        self.dut.cmd('rm -rf /lib/firmware/netronome')
        self.dut.reset_mods()

class BSPDiag(CommonTest):
    def execute(self):
        M = self.dut

        M.cmd('mkdir -p /lib/firmware/netronome')

        M.cp_to(self.group.netdevfw,
                '/lib/firmware/netronome/%s' % M.get_fw_name_any())

        M.refresh()
        netifs_old = M._netifs

        userspace = None if self.group.upstream_drv else True
        M.insmod(netdev=None, userspace=userspace)
        time.sleep(1)

        M.refresh()
        netifs_new = M._netifs

        regx_sp = re.compile('.*sp:(\d*\.\d*).*', re.M | re.S)
        for ifc in list(set(netifs_new) - set(netifs_old)):
            _, out = M.cmd('ethtool -i %s' % ifc)

            # Ignore other devices if present
            if not re.search(self.group.pci_id, out):
                continue

            ver_m = regx_sp.match(out)
            if not ver_m:
                raise NtiGeneralError("Ethtool does not report NSP ABI")

            if not self.group.upstream_drv:
                ver = ver_m.groups()[0]
                _, cmd_ver = M.cmd_nsp('-v')
                cmd_ver = cmd_ver.split('\n')[0]

                if cmd_ver != ver:
                    raise NtiGeneralError("NSP ABI version does not match ethtool:'%s' user space:'%s'" % (ver, cmd_ver))

            # Try dumps which shouldn't work
            bad_ethtool_dumps = (1, 3, 0xffffffff)
            for flag in bad_ethtool_dumps:
                ret, _ = M.cmd('ethtool -W %s %d' % (ifc, flag), fail=False)
                if ret == 0:
                    raise NtiGeneralError("ethtool allows bad dump flags")

            _, out = M.cmd('ethtool -w %s' % (ifc))
            if out.find('flag: 0, version: 1, length: 8192') == -1:
                raise NtiGeneralError("ethtool dump report unexpected")

            # Just to exercise the code path
            _, out = M.cmd('ethtool -w %s data /dev/null' % (ifc))

    def cleanup(self):
        self.dut.cmd('rm -rf /lib/firmware/netronome')
        self.dut.reset_mods()

class LinkSpeedEthtool(CommonNonUpstreamTest):
    def netdev_execute(self):
        _, phy = self.dut.cmd_phymod('-E | grep "^eth"')
        phy = phy.strip().split('\n')

        self.ifc_skip_if_not_all_up()

        if len(phy) != len(self.dut_ifn):
            raise NtiError("Bad number of items userspace:%d interfaces:%d" %
                           (len(phy), len(self.dut_ifn)))

        for i in range(0, len(phy)):
            p = re.match('eth(\d*): NBI[^(]*\((\d)\)\t"([^"]*)" ([^ ]*) (\d*)G',
                         phy[i]).groups()

            phymod = int(p[4]) * 1000
            ethtool = self.dut.ethtool_get_speed(self.dut_ifn[i])

            if phymod != ethtool:
                raise NtiError("On port %d phymod reports:%d ethtool:%d" %
                               (i, phymod, ethtool))

class AutonegEthtool(CommonNonUpstreamTest):
    def get_hwinfo_status_aneg(self, ifc):
        status = self.dut.get_hwinfo("phy%d.aneg" % (ifc), params='-u')

        if status == 'A' or status == '':
            return True
        if status == 'F':
            return False

        raise NtiError('Invalid hwinfo aneg status: %s' % (status))

    def get_hwinfo_status_cr(self, ifc):
        status = self.dut.get_hwinfo("eth%d.crauto" % (ifc), params='-u')

        if status == 'yes' or status == '':
            return True
        if status == 'no':
            return False

        raise NtiError('Invalid hwinfo aneg status: %s' % (status))

    def get_hwinfo_status(self, ifc):
        if self.dut.get_part_no() == 'AMDA0099-0001':
            return self.get_hwinfo_status_aneg(ifc)
        else:
            return self.get_hwinfo_status_cr(ifc)

    def state_check(self):
        i = 0
        for ifc in self.dut_ifn:
            ethtool = self.dut.ethtool_get_autoneg(ifc)
            hwinfo = self.get_hwinfo_status(i)

            if self.state[ifc] != ethtool:
                raise NtiError('ethtool reports state: %d expeted: %d' %
                               (ethtool, self.state[ifc]))

            if self.state[ifc] != hwinfo:
                raise NtiError('hwinfo reports state: %d expeted: %d' %
                               (hwinfo, self.state[ifc]))

            i += 1

    def flip_autoneg_status(self, ifc):
        want = 'on'
        if self.state[ifc]:
            want = 'off'

        self.dut.cmd('ethtool -s %s autoneg %s' % (ifc, want))
        self.state[ifc] = not self.state[ifc]

    def netdev_execute(self):
        # Check NSP version
        self.nsp_min(15)

        self.state = {}

        for ifc in self.dut_ifn:
            self.state[ifc] = self.dut.ethtool_get_autoneg(ifc)

        self.state_check()

        # We need to bring interfaces down before we change settings
        self.ifc_all_down()

        for ifc in self.dut_ifn:
            self.flip_autoneg_status(ifc)

        self.state_check()

        for ifc in self.dut_ifn:
            self.flip_autoneg_status(ifc)

        self.state_check()

class MtuFlbufCheck(CommonNetdevTest):
    def get_bar_rx_offset(self):
        return self.dut.nfd_reg_read_le32(self.dut_ifn[0], NfpNfdCtrl.RX_OFFSET)

    def get_bar_mtu(self):
        return self.dut.nfd_reg_read_le32(self.dut_ifn[0], NfpNfdCtrl.MTU)

    def get_bar_flbufsz(self):
        return self.dut.nfd_reg_read_le32(self.dut_ifn[0], NfpNfdCtrl.FLBUFSZ)

    def check(self, has_xdp):
        check_mtus = [1500, 1024, 2049, 2047, 2048 - 32, 2048 - 64]

        for mtu in check_mtus:
            self.dut.cmd('ip link set dev %s mtu %d' % (self.dut_ifn[0], mtu))
            bmtu = self.get_bar_mtu()
            bflbufsz = self.get_bar_flbufsz()
            rxoffset = self.get_bar_rx_offset()

            if has_xdp:
                xdp_off = 256 - rxoffset
            else:
                xdp_off = 0

            fl_bufsz = xdp_off + rxoffset + 14 + 8 + mtu
            if rxoffset == 0:
                fl_bufsz += 64

            fl_bufsz = (fl_bufsz + 63) & ~63
            fl_bufsz -= xdp_off

            self.log("vals", [mtu, bmtu, rxoffset, bflbufsz, fl_bufsz])

            if mtu != bmtu:
                raise NtiError("MTU doesn't match BAR (was:%d expect:%d)" %
                               (mtu, bmtu))
            if fl_bufsz != bflbufsz:
                raise NtiError("FL_BUFSZ doesn't match BAR (was:%d expect:%d)" %
                               (fl_bufsz, bflbufsz))

    def netdev_execute(self):
        self.dut.copy_bpf_samples()

        self.check(False)

        self.xdp_start('pass.o')

        self.check(True)

        self.xdp_stop()

class DevlinkPortsShow(CommonNonUpstreamTest):
    def netdev_execute(self):
        if self.kernel_min(4, 6):
            raise NtiSkip("Devlink needs kernel 4.6 or newer")

        dev = "pci/%s" % (self.group.pci_dbdf)

        _, phy = self.dut.cmd_phymod('-E | grep "^eth"')
        ports = [l.split() for l in phy.split('\n') if l != ""]

        _, dl = self.dut.cmd('devlink port show | grep %s' % (dev))
        dl_ports = [l.split() for l in dl.split('\n') if l != ""]

        if len(ports) != len(dl_ports):
            raise NtiError("Unexpected port count bsp:%d vs devlink:%d" %
                           (len(ports), len(dl_ports)))

        for p in ports:
            # Decode phymod output
            ethX  = p[0]
            label = p[2]
            mac   = p[3]

            port = re.match("eth(\d*):", ethX).group(1)

            labels = re.match('"(\d*)\.(\d*)"', label).groups()
            main_port = labels[0]
            subport   = labels[1]

            lane = re.match("NBI\d*.(\d*).*", p[1]).groups()[0]

            # Get netdev and verify it has right MAC addr
            cmd = 'devlink port show %s/%s' % (dev, lane)
            _, dl_port = self.dut.cmd(cmd)

            netdev = re.match(".*netdev (\w*).*", dl_port).group(1)
            self.dut.cmd('ip link show dev %s | grep %s' % (netdev, mac))

            # Check split group
            if dl_port.find('split') != -1:
                split = re.match(".*split_group (\w*).*", dl_port).group(1)
                if split != main_port:
                    raise NtiError("Split group %s, should be %s" %
                                   (split, main_port))
            elif subport != "0":
                raise NtiError("Split group not reported for non-0th subport")

class IfConfigDownTest(CommonNonUpstreamTest):
    def wait_for_link_netdev(self, iface):
        self.dut.link_wait(iface)

    def wait_for_link(self, iface, mac_addr):
        for i in range(0, 16):
            time.sleep(0.5)
            _, nsp_state = self.dut.cmd_nsp(' -E | grep -EA1 "MAC:\s+%s" | grep -o "[+-]Link" | tr -d "\n"' %
                                            mac_addr)
            if nsp_state == "+Link":
                self.wait_for_link_netdev(iface)
                return

        raise NtiError("Timeout waiting for Link on interface %s" % (iface))

    def do_check_port(self, iface, mac_addr, expected_state):
        _, nsp_state = self.dut.cmd_nsp(' -E | grep -EA1 "MAC:\s+%s" | grep -o "[+-]Configured" | tr -d "\n"' %
                                        mac_addr)
        if nsp_state != expected_state:
            raise NtiError('Expected interface %s to be %s, got %s' %
                           (iface, expected_state, nsp_state))

    def check_other_ports(self, entry_to_exclude, list, expected_state):
        for entry in list:
            if entry[0] != entry_to_exclude[0]:
                self.do_check_port(entry[0], entry[1], expected_state)

    def check_other_ports_up(self, entry_to_exclude, list):
        for entry in list:
            if entry[0] != entry_to_exclude[0]:
                self.do_check_port(entry[0], entry[1], "+Configured")
                self.ping(entry[2])

    def check_other_ports_down(self, entry_to_exclude, list):
        for entry in list:
            if entry[0] != entry_to_exclude[0]:
                self.do_check_port(entry[0], entry[1], "-Configured")

    def check_port_up(self, port_tuple):
        iface = port_tuple[0]
        mac_addr = port_tuple[1]
        port = port_tuple[2]

        self.dut.cmd('ifconfig %s up' % iface)
        self.do_check_port(iface, mac_addr, "+Configured")
        self.wait_for_link(iface, mac_addr)
        self.ping(port)

    def check_port_down(self, port_tuple):
        iface = port_tuple[0]
        mac_addr = port_tuple[1]

        self.dut.cmd('ifconfig %s down' % iface)
        self.do_check_port(iface, mac_addr, "-Configured")

    def netdev_execute(self):
        _, bsp_ver = self.dut.cmd_hwinfo('| awk -F "." "/bsp.version=/ {print \$4}" | tr -d "*"')
        if int(bsp_ver,16) < 0x02003c:
            raise NtiSkip("BSP NSP version of at least 0x02003c required to execute test.")

        nsp_ifaces = ""
        for port_index in range(0, len(self.dut_ifn)):
            nsp_ifaces += "eth%d " % port_index

        port_mac_tuple_list = []
        for port in range(0, len(self.dut_ifn)):
            iface = self.dut_ifn[port]
            _, mac_addr = self.dut.cmd('cat /sys/class/net/%s/address | tr -d "\n"' %
                                       iface)
            port_mac_tuple_list.append((iface, mac_addr, port))

        # Check for consistent interaction between userspace tools and netdev
        # state
        _, nsp_state = self.dut.cmd_nsp(' -C -config %s' % nsp_ifaces)
        for entry in port_mac_tuple_list:
            self.check_port_down(entry)

        _, nsp_state = self.dut.cmd_nsp(' -C +config %s' % nsp_ifaces)
        for entry in port_mac_tuple_list:
            self.check_port_up(entry)

        # Check netdev state on each port with other ports expected in the
        # opposite state
        for entry in port_mac_tuple_list:
            self.check_port_down(entry)
            self.check_other_ports_up(entry, port_mac_tuple_list)
            self.check_port_up(entry)

        self.ifc_all_down()
        for entry in port_mac_tuple_list:
            self.check_port_up(entry)
            self.check_other_ports_down(entry, port_mac_tuple_list)
            self.check_port_down(entry)

        # If there is only a single port, the next tests don't test anything
        # different.
        if len(port_mac_tuple_list) == 1:
            return

        # Reorder the tests to check for port dependencies
        for entry in reversed(port_mac_tuple_list):
            self.check_port_up(entry)
            self.check_other_ports_down(entry, port_mac_tuple_list)
            self.check_port_down(entry)

        for entry in reversed(port_mac_tuple_list):
            self.check_port_up(entry)

        for entry in reversed(port_mac_tuple_list):
            self.check_port_down(entry)
            self.check_other_ports_up(entry, port_mac_tuple_list)
            self.check_port_up(entry)

        for entry in reversed(port_mac_tuple_list):
            self.check_port_down(entry)
