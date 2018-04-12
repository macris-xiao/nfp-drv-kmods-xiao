#
# Copyright (C) 2016-2017,  Netronome Systems, Inc.  All rights reserved.
#
"""
Unit test group for the NFP Linux drivers.
"""

import netro.testinfra
from reconfig import ChannelReconfig
from fw_dumps import FwDumpTest
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
             ('rtsym', RTSymTest, 'Test in-kernel RT-Sym interface'),
             ('fw_dump', FwDumpTest, 'Test firmware debug dump'),
             ('fw_names', FwSearchTest, "Test FW requested by the driver"),
             ('vnic_tlv_caps', TLVcapTest, "Test basic parsing of TLV vNIC caps"),
             ('sriov', SriovTest, 'Test SR-IOV sysfs interface'),
             ('netdev', NetdevTest, "Test netdev loading"),
             # Tests which assume netdev FW to be loaded
             ('bsp_version', BspVerTest, "Test NSP BSP Version function"),
             ('sensors', SensorsTest, "Test Hwmon sensors functionality"),
             ('phys_port_name', PhysPortName, "Test port naming"),
             ('params_incompat', ParamsIncompatTest,
              "Test if incompatible parameter combinations are rejected"),
             ('dev_cpp', DevCppTest,
              "Test user space access existence and basic functionality"),
             ('kernel_fw_load', KernelLoadTest, "Test kernel firmware loader"),
             ('bsp_diag', BSPDiag, "Test the basic BSP diagnostics"),
             ('channel_reconfig', ChannelReconfig, "Ethtool channel reconfig"),
             ('ethtool_drvinfo', DrvInfoEthtool, "Ethtool -i test"),
             ('ethtool_get_speed', LinkSpeedEthtool, "Ethtool get settings"),
             ('ethtool_aneg', AutonegEthtool,
              "Test setting autonegotiation with ethtool"),
             ('ethtool_stats', StatsEthtool, "Ethtool stats"),
             ('ethtool_mac_stats', MacStatsEthtool, "Ethtool MAC stats"),
             ('mtu_flbufsz_check', MtuFlbufCheck,
              "Check if driver sets correct fl_bufsz and mtu"),
             ('devlink_port_show', DevlinkPortsShow,
              "Check basic devlink port output"),
             ('port_config', IfConfigDownTest,
              "Check interface operable after FW load with combinations of ifup/ifdown"),
             ('sriov_ndos', SriovNDOs, 'Test SR-IOV VF config NDO functions'),
             ('fec_modes', FECModesTest, 'Test FEC modes configuration'),
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

            ret = M.dfs_write('nth/resource', name, timeout=5, do_fail=None)

            rescs = M.dfs_read_raw('nth/resource')
            _, out = M.cmd_res('-L')

            if ret and re.search("%s.*LOCKED arm" % name, out):
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

        # DACs don't support disabling PHYs in the way this test
        # expects, see NFPBSP-3238.
        _, eth_table = M.cmd_nsp('-E')
        for i in range(0, len(self.enable_state)):
            port_type = re.search('eth%d.*\n.*Phy: ([^ ]+)' % i, eth_table,
                                  re.MULTILINE).group(1)
            if port_type.lower() == 'copper':
                self.enable_state[i] = -1
                LOG('Port #%d not eligible for this test, type is %s' %
                    (i, port_type))

        if self.enable_state.count(-1) == len(self.enable_state):
            raise NtiSkip("Test doesn't support DACs")

        for i in range(0, len(self.enable_state)):
            if self.enable_state[i] == -1:
                continue

            self.flip_state(i)
            self.compare_state()
        for i in reversed(range(0, len(self.enable_state))):
            if self.enable_state[i] == -1:
                continue

            self.flip_state(i)
            self.compare_state()

        # And flip some random ones
        random.seed(1234)
        for i in range(0, len(self.enable_state) / 2 + 1):
            if self.enable_state[i] == -1:
                continue

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

class BspVerTest(CommonNetdevTest):
    def netdev_execute(self):
        self.nsp_min(16)

        cmd  = 'dmesg | tac | sed -n "1,/nfp: NFP PCIe Driver/p"'
        cmd += ' | grep "nfp 0000:%s"' % (self.group.pci_id)
        cmd += ' | grep -o "BSP: .*" | cut -c 6- | tr -d "\n"'
        _, ver = self.dut.cmd(cmd)
        comp = ver.split('.')
        if len(comp) != 3:
            raise NtiError('bad bsp version format: %s %d' % (ver, len(comp)))
        for i in range(3):
            if len(comp[i]) != 6:
                raise NtiError('bad bsp version format: %s' % ver)
            if False == all(c in '0123456789abcdefABCDEF' for c in comp[i]):
                raise NtiError('bad bsp version format (char): %s' % ver)

class SensorsTest(CommonNetdevTest):
    def get_attr(self, array, attr):
        for s in array :
            if attr in s :
                return s
        raise NtiError('didn\'t find attr: %s', attr)

    def netdev_execute(self):
        self.nsp_min(15)

        ret, out = self.dut.cmd('sensors -u nfp-pci-%s%s' %
                                (self.group.pci_id[0:2],
                                 self.group.pci_id[3:5]))
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

        M.insmod()
        M.nfp_reset()
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
        self.dut.cmd('echo %s > /sys/bus/pci/devices/0000:%s/sriov_numvfs' %
                     (num, self.group.pci_id))
        _, out = self.dut.cmd('lspci -d 19ee:6003 | wc -l')
        got = int(out)
        if got != num:
            raise NtiGeneralError('Incorrect SR-IOV number got:%d want:%d' %
                                  (got, num))

    def execute(self):
        M = self.dut

        # Load vfio_pci first so it binds to the VFs
        M.cmd('modprobe vfio_pci')
        M.cmd('echo 19ee 6003 > /sys/bus/pci/drivers/vfio-pci/new_id')

        M.insmod()
        M.nfp_reset()
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

class SriovNDOs(CommonNetdevTest):
    def gen_macs(self, num_macs=10):
        macs = []
        while len(macs) < num_macs:
            bytes = [random.randint(0x0,0xff) for i in range(5)]
            mac = '02:%02x:%02x:%02x:%02x:%02x' % tuple(bytes)
            if mac not in macs:
                macs.append(mac)
        return macs

    def test_sriov_ndo(self, pfn, num_vfs, vf_idx, ndo_param, ndo_arg, regex,
                       report_vf, do_fail=False):
        M = self.dut
        do_fail = do_fail or vf_idx >= num_vfs
        report_vf = report_vf and vf_idx < num_vfs

        cmd = 'ip link set %s vf %d %s %s' % (pfn, vf_idx, ndo_param, ndo_arg)
        ret, _ = M.cmd(cmd, fail=False)
        if bool(ret) != bool(do_fail):
            raise NtiGeneralError('Mismatch with command %s (ret:%d fail:%d)' %
                                  (cmd, ret, bool(do_fail)))

        _, out = M.cmd('ip link show %s' % pfn)

        vf_cfg = re.search(r'vf %d .*$' % vf_idx, out, re.MULTILINE)
        if vf_cfg is None == report_vf:
            raise NtiError("Reporting VF %d expected: %d, was: %d" %
                           (vf_idx, report_vf, not vf_cfg is None))
        if not report_vf:
            return
        vf_cfg = vf_cfg.group(0)
        # Exit early if set failed
        if ret:
            return
        vf_got = re.search(regex, vf_cfg).group(1)
        if vf_got != ndo_arg:
            raise NtiGeneralError('SR-IOV VF NDO(%s) failed got:%s want:%s' %
                                  (ndo_param, vf_got, ndo_arg))

    def test_one_ifc(self, ifc, max_vfs, num_vfs, caps):
        # Whether ip link should report the info
        ret, _ = self.dut.cmd('ls /sys/bus/pci/devices/%s/net/%s' %
                              (self.group.pci_dbdf, ifc), fail=False)
        report = ret == 0
        # Whether interface is the VF
        info = ethtool_drvinfo(self.dut, ifc)
        is_vf = info["driver"] == "nfp_netvf"

        # Test SR-IOV ndo functions
        random.seed(1234)
        vf_macs = self.gen_macs(num_vfs + 1)
        for vf_idx in range(0, num_vfs + 1):
            self.test_sriov_ndo(ifc, num_vfs, vf_idx, 'mac', vf_macs[vf_idx],
                                'MAC ([0-9a-f:]+),', report, ~caps & 1 or is_vf)
            # TODO: test unset vlan (0)?
            self.test_sriov_ndo(ifc, num_vfs, vf_idx, 'vlan',
                                str(random.randint(1,4095)),
                                'vlan (\d+),', report, ~caps & 2 or is_vf)
            self.test_sriov_ndo(ifc, num_vfs, vf_idx, 'spoofchk',
                                random.choice(['on', 'off']),
                                'spoof checking (\w+),', report,
                                ~caps & 4 or is_vf)
            self.test_sriov_ndo(ifc, num_vfs, vf_idx, 'state',
                                random.choice(['auto', 'enable', 'disable']),
                                'link-state (\w+)', report, ~caps & 8 or is_vf)

            bad_cmds = (
                ("mac ff:00:00:00:00:01", "Broadcast MAC accepted"),
                ("vlan 1 proto 802.1ad", "802.1ad proto accepted"),
                ("vlan 1 qos 8", "Invalid QoS accepted: 8"),
                ("vlan 4096", "Invalid VLAN accepted: 4096"),
            )

            for cmd in bad_cmds:
                ret, _ = self.dut.cmd('ip link set %s vf %d %s' %
                                  (ifc, vf_idx, cmd[0]), fail=False)
                if ret == 0:
                    raise NtiError(cmd[1])

        if max_vfs == 0:
            _, out = self.dut.cmd('ip link show %s' % ifc)
            if out.find(' vf ') != -1:
                raise NtiError("ip link reports VFs")

    def netdev_execute(self):
        # We have no way to read the cap upstream right now,
        # hardcode the project capabilities
        sriov_caps = (
            { "name" : "flow", "caps" : 0x03, "reprs" : True },
            { "name" : "cNIC", "caps" : 0x0f, "reprs" : False },
        )

        info = ethtool_drvinfo(self.dut, self.nfp_netdevs[0])
        caps = None
        reprs = 0
        LOG_sec("Checking app name")
        LOG(info["firmware-version"])
        for sc in sriov_caps:
            if info["firmware-version"].find(sc["name"]) != -1:
                caps = sc["caps"]
                reprs = sc["reprs"]
                LOG("Identified as app %s" % sc["name"])
                break
        if caps is None:
            caps = 0
            LOG("App not identified")
        LOG_endsec()

        max_vfs = self.read_scalar_nffw('nfd_vf_cfg_max_vfs')

        if not self.group.upstream_drv and max_vfs > 0:
            rcaps = self.dut.get_rtsym_scalar("_pf0_net_vf_cfg2:0")
            if caps != rcaps:
                raise NtiError("Got caps: %d expected: %d" %
                               (rcaps, caps))

        # Enable VFs if supported
        if max_vfs > 0:
            self.dut.cmd('modprobe -r vfio_pci')
            self.dut.cmd('echo %d > /sys/bus/pci/devices/0000:%s/sriov_numvfs' %
                         (1, self.group.pci_id))

        netifs_old = self.dut._netifs
        self.dut.cmd("udevadm settle")
        self.dut._get_netifs()

        vf_ifcs =  list(set(self.dut._netifs) - set(netifs_old))
        num_vfs = len(vf_ifcs) / (1 + reprs)
        if len(vf_ifcs) != bool(max_vfs) + reprs:
            raise NtiError("max VFs supported: %d, new ifcs: %d has_reprs: %d" %
                           (max_vfs, len(vf_ifcs), reprs))

        for pfn in self.nfp_netdevs:
            self.test_one_ifc(pfn, max_vfs, num_vfs, caps)
        for ifc in vf_ifcs:
            self.test_one_ifc(ifc, max_vfs, num_vfs, caps)


class NetdevTest(CommonDrvTest):
    def execute(self):
        M = self.dut

        # Check FW loading from the user space
        M.insmod()
        M.nfp_reset()
        M.nffw_load(os.path.join(self.dut.tmpdir,
                                 os.path.basename(self.group.netdevfw)))

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
            if not re.match("^p\d*$", port_name) and \
               not re.match("^p\d*s\d*$", port_name):
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
        bad_combs = ('nfp_pf_netdev=1 nfp_mon_event=1',
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

        if len(netifs_new) - len(netifs_old) < len(self.dut_addr):
            raise NtiGeneralError('Expected %d interfaces created, got %d' %
                                  (len(self.dut_addr),
                                   len(netifs_new) - len(netifs_old)))

        new_ifcs = list(set(netifs_new) - set(netifs_old))

        not_present = filter(lambda x: x not in new_ifcs, self.dut_ifn)
        if len(not_present):
            raise NtiError("Interfaces not present after load: " +
                           str(not_present))

        for ifc in new_ifcs:
            # Ignore possible VF/PF representors and vNICs, but bring them up.
            # One of them may be our CPU port.
            if ifc not in self.dut_ifn:
                self.dut.cmd('ifconfig %s up' % (ifc))
                continue

            i = self.dut_ifn.index(ifc)
            M.cmd('ifconfig %s %s up' % (ifc, self.dut_addr[i]))

        for ifc in self.dut_ifn:
            self.dut.link_wait(ifc)

        for ifc in self.dut_ifn:
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

        regx_sp = re.compile('.*firmware-version: [^ ]* (\d*\.\d*).*',
                             re.M | re.S)
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

            _, out = M.cmd('ethtool -w %s' % (ifc))
            if out.find('flag: 0, version: 1, length: 8192') == -1:
                raise NtiGeneralError("ethtool dump report unexpected")

            # Just to exercise the code path
            _, out = M.cmd('ethtool -w %s data /dev/null' % (ifc))

    def cleanup(self):
        self.dut.cmd('rm -rf /lib/firmware/netronome')
        self.dut.reset_mods()

class DrvInfoEthtool(CommonNetdevTest):
    def check_common(self, info):
        yes = [ "supports-statistics" ]
        no = [ "supports-test", "supports-eeprom-access",
               "supports-priv-flags" ]

        for i in yes:
            if info[i] != "yes":
                raise NtiError(i + ": " + info[i] + ", expected yes")
        for i in no:
            if info[i] != "no":
                raise NtiError(i + ": " + info[i] + ", expected no")

        if self.dut.kernel_ver_ge(4, 0) and info["expansion-rom-version"]:
            raise NtiError("Expansion Rom reported")
        if len(info["version"]) < 4:
            raise NtiError("Version not reported")

    def check_common_vnic(self, info):
        if info["supports-register-dump"] != "yes":
            raise NtiError("vNIC without register dump")
        if not info["firmware-version"].startswith("0.0."):
            raise NtiError("Bad NFD version")

        self.check_common(info)

    def check_info_repr(self, info):
        LOG("\n\nChecking Representor Info\n")

        if info["driver"] != "nfp":
            raise NtiError("Driver not reported as nfp")
        if info["supports-register-dump"] != "no":
            raise NtiError("Representor with register dump")
        if info["bus-info"]:
            raise NtiError("Representor with bus info")

        fw_ver = info["firmware-version"].strip().split(' ')
        if len(fw_ver) != 4:
            raise NtiError("FW version has %d items, expected 4" %
                           (len(fw_ver)))

        self.check_common(info)

    def check_info_vf(self, info):
        LOG("\n\nChecking VF Info\n")

        if info["driver"] != "nfp_netvf":
            raise NtiError("Driver not reported as nfp_netvf")
        if not info["bus-info"]:
            raise NtiError("VF without bus info")

        fw_ver = info["firmware-version"].strip().split(' ')
        if len(fw_ver) != 1:
            raise NtiError("FW version has %d items, expected 1" %
                           (len(fw_ver)))

        self.check_common_vnic(info)

    def check_info_pf(self, info):
        LOG("\n\nChecking PF Info\n")

        if info["driver"] != "nfp":
            raise NtiError("Driver not reported as nfp")
        if info["bus-info"] != self.group.pci_dbdf:
            raise NtiError("Incorrect bus info")

        fw_ver = info["firmware-version"].strip().split(' ')
        if len(fw_ver) != 4:
            raise NtiError("FW version has %d items, expected 4" %
                           (len(fw_ver)))

        self.check_common_vnic(info)

    def netdev_execute(self):
        new_ifcs = self.spawn_vf_netdev()

        for ifc in new_ifcs:
            info = ethtool_drvinfo(self.dut, ifc)
            if info["driver"] == "nfp":
                self.check_info_repr(info)
            elif info["driver"] == "nfp_netvf":
                self.check_info_vf(info)
            else:
                raise NtiError("Driver not reported")

        for ifc in self.nfp_netdevs:
            info = ethtool_drvinfo(self.dut, ifc)
            if info["bus-info"]:
                self.check_info_pf(info)
            else:
                self.check_info_repr(info)

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
                raise NtiError('ethtool reports state: %d expected: %d' %
                               (ethtool, self.state[ifc]))

            if self.state[ifc] != hwinfo:
                raise NtiError('hwinfo reports state: %d expected: %d' %
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

class StatsEthtool(CommonNetdevTest):
    def check_sw_stats_present(self, keys):
        if len(filter(lambda x: x.startswith('rvec_'), keys)) < 3:
            raise NtiError("rvec stats missing")
        if 'hw_rx_csum_ok' not in keys:
            raise NtiError("SW stats missing")

    def check_vnic_stats_present(self, keys):
        keys = filter(lambda x: x.startswith('dev_') or x.startswith('bpf_'),
                      keys)
        if len(keys) != 26:
            raise NtiError("Expected 26 vNIC stats, got %d" % (len(keys)))

    def check_vnic_queue_stats_present(self, keys):
        if len(filter(lambda x: x.startswith('txq_'), keys)) < 2:
            raise NtiError("txq stats missing")
        if len(filter(lambda x: x.startswith('rxq_'), keys)) < 2:
            raise NtiError("rxq stats missing")

    def check_mac_stats_present(self, keys):
        keys = filter(lambda x: x.startswith('mac.'), keys)

        expected = 59 if self.mac_stats else 0

        if len(keys) != expected:
            raise NtiError("Expected %d MAC stats, got %d" %
                           (expected, len(keys)))

    def netdev_execute(self):
        # Spawn VFs so that we test the entire gamut
        vf_ifcs = self.spawn_vf_netdev()

        # Check if FW supports MAC stats
        self.mac_stats = self.read_sym_nffw('_mac_stats') is not None

        all_netdevs = vf_ifcs + self.nfp_netdevs
        names = {}
        stats = {}
        infos = {}
        for ifc in all_netdevs:
            _, out = self.dut.cmd('cat /sys/class/net/%s/phys_port_name || echo'
                                  % (ifc))
            names[ifc] = out.strip()

            infos[ifc] = ethtool_drvinfo(self.dut, ifc)
            stats[ifc] = ethtool_stats(self.dut, ifc)

        LOG_sec("Checking statistics")

        for ifc in all_netdevs:
            keys = stats[ifc].keys()

            # VF vNIC or PF vNIC (not a physical port vNIC)
            if names[ifc] == "":
                self.check_sw_stats_present(keys)
                self.check_vnic_stats_present(keys)
                self.check_vnic_queue_stats_present(keys)

                LOG("Bare vNIC (PF representor/VF) OK: " + ifc)
                continue

            # PF/VF representor
            if re.match('^pf\d*', names[ifc]):
                self.check_vnic_stats_present(keys)

                if not all([x.startswith('dev_') or x.startswith('bpf_')
                            for x in keys]):
                    raise NtiError("VF representor has non-BAR stats")

                LOG("VF representor OK: " + ifc)
                continue

            # Physical port representor
            if re.match('^p\d*$', names[ifc]) and infos[ifc]["bus-info"] == "":
                self.check_mac_stats_present(keys)

                if not all([x.startswith('mac.') for x in keys]):
                    raise NtiError("MAC representor has non-MAC stats")

                LOG("Physical port representor OK: " + ifc)
                continue

            # Physical port vNIC
            if re.match('^p\d*$', names[ifc]) and infos[ifc]["bus-info"] != "":
                self.check_sw_stats_present(keys)
                self.check_vnic_stats_present(keys)
                self.check_vnic_queue_stats_present(keys)
                self.check_mac_stats_present(keys)

                LOG("Physical port vNIC OK: " + ifc)
                continue

            raise NtiError("Unknown netdev type: " + ifc)

        LOG_endsec()

class MacStatsEthtool(CommonNetdevTest):
    def test_stat(self, ifidx, stat_name, size,
                  exp_inc=None, prepend=["rx_", "tx_"]):
        if exp_inc is None:
            exp_inc = size

        size -= 46 # Headers
        repeat = 40

        LOG_sec("MAC stat " + self.dut_ifn[ifidx] + ' ' + stat_name)

        before = ethtool_stats(self.dut, self.dut_ifn[ifidx])

        self.ping(ifidx, count=repeat, size=size, ival=0.01)

        after = ethtool_stats(self.dut, self.dut_ifn[ifidx])

        LOG_sec("Stat diff")
        for name in before.keys():
            diff = int(after[name]) - int(before[name])
            if diff:
                LOG("\t" + name + ": " + str(diff))
        LOG_endsec()

        exp = repeat * exp_inc

        for p in prepend:
            name = "mac." +p + stat_name

            diff = int(after[name]) - int(before[name])

            LOG("\nStat: %s  %d >= %d\n" % (name, diff, exp))

            if diff < exp:
                LOG_endsec()
                raise NtiError("Stat %s increased by %d, expected %d" %
                               (name, diff, exp))

        LOG_endsec()

    def test_one_ifc(self, ifidx):
        pkt_stats = (
            ("rx_frames_received_ok",		64),
            ("rx_unicast_pkts",			64),
            ("rx_pkts",				64),
            ("tx_frames_transmitted_ok",	64),
            ("tx_unicast_pkts",			64),
        )

        pkt_stats_bidir = (
            ("pkts_64_octets",			64),
            ("pkts_65_to_127_octets",		65),
            ("pkts_65_to_127_octets",		127),
            ("pkts_128_to_255_octets",		128),
            ("pkts_128_to_255_octets",		255),
            ("pkts_256_to_511_octets",		256),
            ("pkts_256_to_511_octets",		511),
            ("pkts_512_to_1023_octets",		512),
            ("pkts_512_to_1023_octets",		1023),
            ("pkts_1024_to_1518_octets",	1024),
            ("pkts_1024_to_1518_octets",	1518),
        )

        octet_stats = (
            ("octets",				64),
        )

        jumbo_stats = (
            ("pkts_1519_to_max_octets",		1519),
            ("pkts_1519_to_max_octets",		1600),
        )

        self.dut.link_wait(self.dut_ifn[ifidx])
        self.ping(ifidx)

        for t in pkt_stats:
            self.test_stat(ifidx, t[0], t[1], 1, prepend=[""])

        for t in pkt_stats_bidir:
            self.test_stat(ifidx, t[0], t[1], 1)

        for t in octet_stats:
            self.test_stat(ifidx, t[0], t[1])

        for t in pkt_stats_bidir:
            self.test_stat(ifidx, t[0], t[1], 1)

        ret, _ = self.dut.cmd('ip link set dev %s mtu %d' %
                              (self.dut_ifn[ifidx], 1600),
                              fail=False)
        # If we can't do jumbo just skip the jumbo counter tests
        if ret:
            return

        self.src.cmd('ip link set dev %s mtu %d' % (self.src_ifn[ifidx], 1600))

        for t in jumbo_stats:
            self.test_stat(ifidx, t[0], t[1], 1)

        self.src.cmd('ip link set dev %s mtu %d' % (self.src_ifn[ifidx], 1500))

    def netdev_execute(self):
        if self.read_sym_nffw('_mac_stats') is None:
            raise NtiSkip("FW doesn't report MAC stats")

        for i in range(0, len(self.dut_ifn)):
            self.test_one_ifc(i)

class MtuFlbufCheck(CommonNetdevTest):
    def get_bar_rx_offset(self):
        return self.dut.nfd_reg_read_le32(self.vnics[0], NfpNfdCtrl.RX_OFFSET)

    def get_bar_mtu(self):
        return self.dut.nfd_reg_read_le32(self.vnics[0], NfpNfdCtrl.MTU)

    def get_bar_flbufsz(self):
        return self.dut.nfd_reg_read_le32(self.vnics[0], NfpNfdCtrl.FLBUFSZ)

    def check(self, has_xdp):
        check_mtus = [1500, 1024, 2049, 2047, 2048 - 32, 2048 - 64]

        for mtu in check_mtus:
            self.dut.cmd('ip link set dev %s mtu %d' % (self.vnics[0], mtu))
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

        self.check(False)

        if self.kernel_min(4, 8):
            return
        ret, _ = cmd_log('ls %s' % (os.path.join(self.group.samples_xdp,
                                                 'pass.o')),
                         fail=False)
        if ret != 0:
            raise NtiSkip('XDP samples not found')

        self.dut.copy_bpf_samples()

        self.dut.cmd('ethtool -L %s rx 0 tx 0 combined 1' % (self.vnics[0]))
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
            _, nsp_state = self.dut.cmd_nsp(' -E | grep -EA3 "MAC:\s+%s"' %
                                            mac_addr)
            if re.search("\+link", nsp_state.lower()):
                self.wait_for_link_netdev(iface)
                return

        raise NtiError("Timeout waiting for Link on interface %s" % (iface))

    def do_check_port(self, iface, mac_addr, expected_state):
        _, nsp_state = self.dut.cmd_nsp(' -E | grep -EA3 "MAC:\s+%s"' %
                                        mac_addr)
        if not re.search(expected_state.lower(), nsp_state.lower()):
            raise NtiError('Expected interface %s to be %s got:\n%s' %
                           (iface, expected_state, nsp_state))

    def check_other_ports(self, entry_to_exclude, list, expected_state):
        for entry in list:
            if entry[0] != entry_to_exclude[0]:
                self.do_check_port(entry[0], entry[1], expected_state)

    def check_other_ports_up(self, entry_to_exclude, list):
        for entry in list:
            if entry[0] != entry_to_exclude[0]:
                self.do_check_port(entry[0], entry[1], "\+Configured")
                self.ping(entry[2])

    def check_other_ports_down(self, entry_to_exclude, list):
        for entry in list:
            if entry[0] != entry_to_exclude[0]:
                self.do_check_port(entry[0], entry[1], "\-Configured")

    def check_port_up(self, port_tuple):
        iface = port_tuple[0]
        mac_addr = port_tuple[1]
        port = port_tuple[2]

        self.dut.cmd('ifconfig %s up' % iface)
        self.do_check_port(iface, mac_addr, "\+Configured")
        self.wait_for_link(iface, mac_addr)
        self.ping(port)

    def check_port_down(self, port_tuple):
        iface = port_tuple[0]
        mac_addr = port_tuple[1]

        self.dut.cmd('ifconfig %s down' % iface)
        self.do_check_port(iface, mac_addr, "\-Configured")

    def netdev_execute(self):
        self.nsp_flash_min(0x02003c)

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

class FECModesTest(CommonNonUpstreamTest):
    def check_fec_mode(self, iface, mac_addr, expected_nsp_fec, expected_ethtool_fec):
        _, nsp_port = self.dut.cmd_nsp('-E | grep -EA3 "MAC:\s+%s"' % mac_addr)
        nsp_fec = nsp_port.splitlines()[3].split()[1]
        if nsp_fec != expected_nsp_fec:
            raise NtiError('Expected interface %s to be %s, got %s' %
                           (iface, expected_nsp_fec, nsp_fec))

        # This check is not really accurate. The ethtool FEC output is still
        # somewhat vague at this point, so only check for more or less sane
        # state.
        _, ethtool_fec_output = self.dut.ethtool_get_fec(iface)
        if expected_ethtool_fec == "auto":
            expected_ethtool_fec = "auto-negotiation: on"
        if expected_ethtool_fec == "auto off":
            expected_ethtool_fec = "auto-negotiation: off"

        # The 'off' state is not displayed by this patched version of ethtool.
        if expected_ethtool_fec != "off":
            if not re.search(expected_ethtool_fec, ethtool_fec_output.lower(), re.MULTILINE):
                raise NtiError('Expected interface %s to have %s available in FEC config' %
                               (iface, expected_ethtool_fec))

    def check_mode_on_other_ports(self, entry_to_exclude, list):
        for entry in list:
            if entry[0] != entry_to_exclude[0]:
                self.check_fec_mode(entry[0], entry[1], "Fec0", "auto-negotiation: on")

    def set_and_check_fec_mode(self, port_tuple, fec, nsp_fec_mode):
        iface = port_tuple[0]
        mac_addr = port_tuple[1]
        port = port_tuple[2]

        self.dut.ethtool_set_fec(iface, fec)
        self.check_fec_mode(iface, mac_addr, nsp_fec_mode, fec)

        # First we ping with a case that will fail, then we align the
        # endpoint and expect it to pass.
        # However, if the DUT is configured for auto FEC detection, the first
        # ping should succeed.
        if fec == "off":
            self.src.cmd("/opt/netronome/bin/nfp-nsp -n1 -C +fec1 eth0 eth1")
        else:
            self.src.cmd("/opt/netronome/bin/nfp-nsp -n1 -C +fec3 eth0 eth1")

        # Workaround for NFPBSP-2945
        should_fail = True
        if (port == 1) and (fec == "auto"):
            should_fail = False

        time.sleep(3) # Takes time for NSP to action this command
        self.ping(port, should_fail=should_fail)

        self.src.cmd("/opt/netronome/bin/nfp-nsp -n1 -C +%s eth0 eth1" % nsp_fec_mode)

        time.sleep(3) # Takes time for NSP to action this command
        self.ping(port)

    def set_fec_and_expect_to_fail(self, port_tuple, fec):
        iface = port_tuple[0]
        mac_addr = port_tuple[1]

        ret, _ = self.dut.ethtool_set_fec(iface, fec, fail=False)
        if ret == 0:
            raise NtiError('Expected to fail setting interface %s FEC config to %s, but passed' %
                           (iface, fec))

    def fec_cleanup(self):
        if self.dut.get_part_no() == 'AMDA0099-0001':
            self.dut.cmd_nsp('-C +aneg0 eth0 eth1')
            self.dut.cmd_nsp('-C +fec0 eth0 eth1')

            self.src.cmd("/opt/netronome/bin/nfp-nsp -n1 -C +aneg0 eth0 eth1")
            self.src.cmd("/opt/netronome/bin/nfp-nsp -n1 -C +fec0 eth0 eth1")

    def netdev_execute(self):
        self.nsp_min(22)

        # In order to execute this test, one needs to have an ethtool version
        # readily available in the PATH of your system that supports FEC mode
        # configuration. At the time of authoring this test, FEC support in ethtool
        # has not been available upstream yet, barring some experimental RFC
        # patches. Refer to:
        # https://www.mail-archive.com/netdev@vger.kernel.org/msg134138.html
        ret, _ = self.dut.cmd('ethtool --help | grep -q FEC', False)
        if ret != 0:
            raise NtiSkip("Need ethtool FEC support to execute test.")

        port_mac_tuple_list = []
        for port in range(0, len(self.dut_ifn)):
            iface = self.dut_ifn[port]
            _, mac_addr = self.dut.cmd('cat /sys/class/net/%s/address | tr -d "\n"' %
                                       iface)
            port_mac_tuple_list.append((iface, mac_addr, port))

        if self.dut.get_part_no() == 'AMDA0099-0001':
            # Reset the current FEC mode to default, i.e. auto and switch off
            # autoneg
            self.dut.cmd_nsp('-C +aneg4 eth0 eth1')
            self.dut.cmd_nsp('-C +fec0 eth0 eth1')

            # We always disable autoneg on the endpoint.
            # Since 25G isn't prevalent at the moment, and no other NIC vendor we
            # use have this feature, assume that the endpoint will be another Carbon.
            # It assumes that the carbon is NFP #1 on that system.
            self.src.cmd("/opt/netronome/bin/nfp-nsp -n1 -C +aneg4 eth0 eth1")
            self.src.cmd("/opt/netronome/bin/nfp-nsp -n1 -C +fec0 eth0 eth1")

        for entry in port_mac_tuple_list:
            iface = entry[0]
            mac_addr = entry[1]

            # FEC configuration only available on Carbon
            if self.dut.get_part_no() == 'AMDA0099-0001':
                _, supported = self.dut.cmd('ethtool %s | grep -iA2 "Supported FEC"' % iface)
                if not re.search('None', supported, re.MULTILINE):
                    raise NtiError('Expected interface %s to have None as supported FEC mode' %
                                   iface)
                if not re.search('BaseR', supported, re.MULTILINE):
                    raise NtiError('Expected interface %s to have BaseR as supported FEC mode' %
                                   iface)
                if not re.search('RS', supported, re.MULTILINE):
                    raise NtiError('Expected interface %s to have RS as supported FEC mode' %
                                   iface)

                _, advertised = self.dut.cmd('ethtool %s | grep -iA2 "Advertised FEC"' % iface)
                if not re.search('BaseR', advertised, re.MULTILINE):
                    raise NtiError('Expected interface %s to have BaseR as advertised FEC mode' %
                                   iface)
                if not re.search('RS', advertised, re.MULTILINE):
                    raise NtiError('Expected interface %s to have RS as advertised FEC mode' %
                                   iface)

                self.check_fec_mode(iface, mac_addr, "Fec0", "auto")
                self.check_mode_on_other_ports(entry, port_mac_tuple_list)

                self.set_and_check_fec_mode(entry, "baser", "Fec1")
                self.check_mode_on_other_ports(entry, port_mac_tuple_list)

                self.set_and_check_fec_mode(entry, "rs", "Fec2")
                self.check_mode_on_other_ports(entry, port_mac_tuple_list)

                self.set_and_check_fec_mode(entry, "off", "Fec3")
                self.check_mode_on_other_ports(entry, port_mac_tuple_list)

                self.set_and_check_fec_mode(entry, "auto", "Fec0")
                self.check_mode_on_other_ports(entry, port_mac_tuple_list)
            else:
                # Other non-Carbon cards are expected to only show "None" as the
                # supported FEC mode. No FEC mode modification is allowed.
                _, supported = self.dut.cmd('ethtool %s | grep -iA2 "Supported FEC"' % iface)
                if not re.search('None', supported, re.MULTILINE):
                    raise NtiError('Expected interface %s to have None as supported FEC mode' %
                                   iface)
                if re.search('BaseR', supported, re.MULTILINE):
                    raise NtiError('Expected interface %s to have BaseR as supported FEC mode' %
                                   iface)
                if re.search('RS', supported, re.MULTILINE):
                    raise NtiError('Expected interface %s to have RS as supported FEC mode' %
                                   iface)

                _, advertised = self.dut.cmd('ethtool %s | grep -iA2 "Advertised FEC"' % iface)
                if not re.search('None', advertised, re.MULTILINE):
                    raise NtiError('Expected interface %s to have None as advertised FEC mode' %
                                   iface)
                if re.search('BaseR', advertised, re.MULTILINE):
                    raise NtiError('Expected interface %s to have BaseR as advertised FEC mode' %
                                   iface)
                if re.search('RS', advertised, re.MULTILINE):
                    raise NtiError('Expected interface %s to have RS as advertised FEC mode' %
                                   iface)

                self.check_fec_mode(iface, mac_addr, "Fec0", "auto off")
                self.set_fec_and_expect_to_fail(entry, "baser")
                self.set_fec_and_expect_to_fail(entry, "rs")
                self.set_fec_and_expect_to_fail(entry, "off")
                self.set_fec_and_expect_to_fail(entry, "auto")

        self.fec_cleanup()

class TLVcapTest(CommonNonUpstreamTest):
    def prepare(self):
        if self.group.upstream_drv:
            return NrtResult(name=self.name, testtype=self.__class__.__name__,
                             passed=None, comment="Raw BAR write upstream")

    def modify_bar(self, mods):
        for w in mods:
            self.dut.cmd_rtsym("_pf0_net_bar0:%d %d" %
                               (w[0], w[1] << 16 | w[2]))

    def netdev_execute(self):
        # Tests to perform
        tests = [
            ("TLV size not multiple of",	[(0x58, 0, 3)]),
            ("END TLV should be empty",		[(0x58, 2, 4)]),
            ("oversized TLV offset",		[(0x58, 1, 0xf000)]),
            ("unknown TLV type",		[(0x58, 0x8100, 0)]),
            ("NULL TLV at offset",		[(0x58, 1, 0x17a4),
                                                 (0x1800, 0, 0)]),
            # Last entry cleans up the mess
            (None,				[(0x58, 2, 0),
                                                 (0x1800, 0, 0)]),
        ]

        probe_err = "probe of %s failed with error" % (self.group.pci_dbdf)

        try:
            for t in tests:
                LOG_sec("Check for message '%s'" % (t[0]))
                self.dut.reset_mods()
                self.dut.insmod()

                self.modify_bar(t[1])

                self.dut.reset_mods()
                self.dut.cmd("dmesg -c")
                self.dut.insmod(netdev=True, userspace=True)

                _, msgs = self.dut.cmd("dmesg -c")
                if t[0] is not None:
                    if msgs.find(t[0]) == -1:
                        raise NtiError("Error '%s' did not occur" % (t[0]))
                elif msgs.find(probe_err) != -1:
                    raise NtiError("Failed to probe with good TLVs")

                LOG_endsec()
        except:
            LOG_endsec()
            raise

        # Check ME frequency is parsed correctly (add the TLV twice to check
        # multiple TLV parsing)
        self.modify_bar([(0x58, 1, 0x17a4),
                         (0x1800, 3, 4),    # FREQ hdr
                         (0x1804, 0, 777),  # FREQ val
                         (0x1808, 3, 4),    # FREQ hdr
                         (0x180c, 0, 160),  # FREQ val
                         (0x1810, 2, 0),    # END
        ])

        self.dut.reset_mods()
        self.dut.cmd("dmesg -c")
        self.dut.insmod(netdev=True, userspace=True)
        self.ifc_all_up()

        _, msgs = self.dut.cmd("dmesg -c")
        if msgs.find(probe_err) != -1:
            raise NtiError("Failed to probe with good TLVs")

        irqmod_exp = 64 << 16 | 50 * 160 / 16
        irqmod = self.dut.nfd_reg_read_le32(self.dut_ifn[0], 0x0b00)
        if irqmod != irqmod_exp:
            raise NtiError("IRQMOD entry %x, expected %x" %
                           (irqmod, irqmod_exp))

    def cleanup(self):
        self.dut.reset_mods()
        self.dut.insmod()
        self.dut.nffw_unload()
        self.dut.reset_mods()

        CommonNonUpstreamTest.cleanup(self)
