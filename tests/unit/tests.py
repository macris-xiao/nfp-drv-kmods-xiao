#
# Copyright (C) 2016-2017,  Netronome Systems, Inc.  All rights reserved.
#
"""
Unit test group for the NFP Linux drivers.
"""

import netro.testinfra
from reconfig import ChannelReconfig
from fw_dumps import FwDumpTest
from rtsym import RTSymTest, RTSymDataTest
from versions import VersionsTest
from netro.testinfra.test import *
from ..drv_grp import NFPKmodGrp
from ..ebpf.xdp import XDPTest
from ifstats import IFstats

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

    def fail_policy(self):
        return True

    def populate_tests(self):
        dut = (self.dut, self.addr_x, self.eth_x, self.addr_v6_x)
        src = (self.host_a, self.addr_a, self.eth_a, self.addr_v6_a)

        T = (('modinfo', Modinfo, "Test if modinfo is correct"),
             ('serial_and_ifc', NFPSerialAndInterface,
              "Read the serial number and interface ID"),
             ('resource', ResourceTest, 'Test in-kernel resource table interface'),
             ('lock_busting', LockBusting, 'Bust resource locks on init'),
             ('nsp_eth_table', NspEthTable, "Test NSP ETH table functions"),
             ('hwinfo', HWInfoTest, 'Test in-kernel HWInfo interface'),
             ('nsp_hwinfo', HWInfoNspTest, 'Test NSP HWInfo interface'),
             ('rtsym', RTSymTest, 'Test in-kernel RT-Sym interface'),
             ('rtsym_data', RTSymDataTest, 'Test in-kernel RT-Sym data interface'),
             ('fw_dump', FwDumpTest, 'Test firmware debug dump'),
             ('fw_names', FwSearchTest, "Test FW requested by the driver"),
             ('vnic_tlv_caps', TLVcapTest, "Test basic parsing of TLV vNIC caps"),
             ('sriov', SriovTest, 'Test SR-IOV sysfs interface'),
             ('netdev', NetdevTest, "Test netdev loading"),
             # Tests which assume netdev FW to be loaded
             ('params_incompat', ParamsIncompatTest,
              "Test if incompatible parameter combinations are rejected"),
             ('dev_cpp', DevCppTest,
              "Test user space access existence and basic functionality"),
             ('ifstats_reconfig', IFstats, "Interface statstics vs reconfig"),
             ('channel_reconfig', ChannelReconfig, "Ethtool channel reconfig"),
             ('ethtool_aneg', AutonegEthtool,
              "Test setting autonegotiation with ethtool"),
             ('port_config', IfConfigDownTest,
              "Check interface operable after FW load with combinations of ifup/ifdown"),
             ('sriov_ndos', SriovNDOs, 'Test SR-IOV VF config NDO functions'),
             ('fec_modes', FECModesTest, 'Test FEC modes configuration'),
             ('versions', VersionsTest, 'Test devlink dev info (versions)'),
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

        _, out = self.dut.cmd('modinfo %s' % (self.dut.mod))

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

        resources = M.get_resources()
        for r in resources:
            if r[0] == "nfp.res":
                resources.remove(r)

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

class LockBusting(CommonNonUpstreamTest):
    def lock(self, lockid=0, other_ifc=False, unlock=False):
        addr = self.addr + lockid * 0x20

        # Read
        _, out = self.dut.cmd_mem("-w 8 i.emem:0x%x" % (addr))
        vals = out.split()
        val = int(vals[1], 16)
        # Modify
        val >>= 32
        val <<= 32
        if not unlock:
            val |= 0x000f
            self.locks.append(lockid)
        val |= self.interface << 16
        val += other_ifc << 24
        # Write
        self.dut.cmd_mem('-w 8 i.emem:0x%x 0x%x' % (addr, val))

    def unlock_all(self):
        for l in self.locks:
            self.lock(l, unlock=True)

    def execute(self):
        self.locks = []

        # Find out our interface ID
        _, out = self.dut.cmd('lspci -s %s -vv' % self.group.pci_id)
        DSN = re.search("Device Serial Number (.*)", out).group(1)
        interface = DSN[-5:].replace('-', '')
        self.interface = int(interface, 16)

        self.dut.insmod()

        resources = self.dut.get_resources()

        # Find main resource
        for r in resources:
            if r[0] == "nfp.res":
                rtbl = r
                break

        exp_cppid = '07012000'
        if rtbl[1] != exp_cppid:
            raise NtiSkip("Resource table CPP id is '%s' expected '%s'" %
                          (rtbl[1], exp_cppid))


        self.addr = int(rtbl[2], 16)

        # Now lock the table and 2 other resources
        self.lock(0)
        self.lock(1)
        self.lock(3)
        # Pretend someone else has taken lock 4
        self.lock(4, other_ifc=True)

        # For the logs
        self.dut.cmd_res('-L')

        self.dut.reset_mods()

        # Scan dmesg for warnings
        self.dut.cmd('dmesg -c')
        self.dut.insmod()
        _, out = self.dut.cmd('dmesg -c')

        strs = [(0, "nfp: Warning: busted main resource table mutex"),
                (0, "nfp: Warning: busted resource 1 mutex"),
                (0, "nfp: Warning: busted resource 3 mutex"),
                (1, "nfp: Warning: busted resource 4 mutex"),
        ]
        for s in strs:
            assert_neq(s[0], out.count(s[1]), 'Count of "' + s[1] + '"')

    def cleanup(self):
        self.unlock_all()
        self.dut.reset_mods()

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
        keys = ["pcie0.type", "cpld.version", "arm.mem.base", "board.state"]
        vals = { "pcie0.type" : "ep",
                 "cpld.version" : None,
                 "arm.mem.base" : None,
                 "board.state" : "15" }

        self.hwinfo_check(keys, vals)
        keys.reverse()
        self.hwinfo_check(keys, vals)
        shuffle(keys)
        self.hwinfo_check(keys, vals)

class HWInfoNspTest(CommonNTHTest):
    def lookup_padded(self, key):
        # We need at least on '\0', so always add them
        key = key + '\\0' * (8 - len(key) % 8)
        self.dut.dfs_write('nth/hwinfo_key', key)

        return self.dut.dfs_read('nth/hwinfo_val')

    def nth_execute(self):
        self.nsp_min(25)

        # Find something in overwrites to test with
        hwi = self.dut.get_hwinfo_full(what="", params="")
        hwo = self.dut.get_hwinfo_full(what="", params="-u")

        key = None
        hwi = set(x[0] for x in hwi)
        for elemo in hwo:
            if elemo[0] not in hwi:
                key = elemo[0]
                break

        if key:
            # Check we can't get it from the static DB
            self.dut.dfs_write('nth/hwinfo_key', hwi[0][0], do_fail=True)

            # Switch to NSP lookup and try again
            self.dut.dfs_write('nth/hwinfo_static_db', 'n')

            val = self.lookup_padded(hwi[0][0])
            assert_eq(hwi[0][1], val, "Lookup of HWinfo key " + hwi[0][0])
        else:
            self.dut.dfs_write('nth/hwinfo_static_db', 'n')

        # Try to lookup something trivial
        val = self.lookup_padded('board.state')
        assert_eq(self.dut.get_hwinfo('board.state'), val,
                  "Lookup of 'board.state' (non-override key)")

        # Try to lookup something with non-NULL-terminated key
        ret, data = self.dut.dfs_write('nth/hwinfo_key', '01234567',
                                       do_fail=True, include_stderr=True)
        assert_eq(1, data[1].count("Message too long"),
                  "EMSGSIZE message appears")

        # Try to lookup something we just added
        self.nti_key_added = True
        self.dut.cmd_hwinfo('-u nti_test=012345670123456')
        self.dut.dfs_write('nth/hwinfo_key', 'nti_test' + '\\0' * 8)
        val = self.dut.dfs_read('nth/hwinfo_val')
        assert_eq('012345670123456', val, "Test value")

        # Now make the buffer too small
        self.dut.cmd_hwinfo('-u nti_test=0123456701234567')
        ret, data = self.dut.dfs_write('nth/hwinfo_key',
                                       'nti_test' + '\\0' * 8,
                                       do_fail=True, include_stderr=True)
        assert_eq(1, data[1].count("Message too long"),
                  "EMSGSIZE message appears")

    def cleanup(self):
        if hasattr(self, 'nti_key_added'):
            self.dut.cmd_hwinfo('-u nti_test=')
        return super(HWInfoNspTest, self).cleanup()

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

        # Load pci_stub first so it binds to the VFs
        if self.dut.kernel_ver_ge(4, 12):
            cmd = 'echo 0 > /sys/bus/pci/devices/%s/sriov_drivers_autoprobe' % \
                self.group.pci_dbdf
            self.dut.cmd(cmd)
        else:
            self.dut.cmd('modprobe pci_stub')
            cmd = 'echo 19ee 6003 > /sys/bus/pci/drivers/pci-stub/new_id'
            self.dut.cmd(cmd)

        M.insmod()
        # Check NFD FW is not loaded
        nvfs = self.dut.get_rtsym_scalar("nfd_vf_cfg_max_vfs", fail=False)
        if nvfs != ~0:
            M.nfp_reset()
            M.rmmod()
            M.insmod()

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

    def cleanup(self):
        if self.dut.kernel_ver_ge(4, 12):
            cmd = 'echo 1 > /sys/bus/pci/devices/%s/sriov_drivers_autoprobe' % \
                self.group.pci_dbdf
            self.dut.cmd(cmd)
        else:
            self.dut.cmd('modprobe -r pci_stub')
        return super(SriovTest, self).cleanup()

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
        info = self.dut.ethtool_drvinfo(ifc)
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
            self.test_sriov_ndo(ifc, num_vfs, vf_idx, 'trust',
                                random.choice(['off', 'on']),
                                'trust (\w+)', report, ~caps & 0x10 or is_vf)

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
            { "name" : "flow", "caps" : 0x0b, "reprs" : True },
            { "name" : "cNIC", "caps" : 0x0f, "reprs" : False },
            { "name" : "sriov", "caps" : 0x1f, "reprs" : False },
        )

        info = self.dut.ethtool_drvinfo(self.nfp_netdevs[0])
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
        ret, _ = self.dut.cmd('echo %d > /sys/bus/pci/devices/%s/sriov_numvfs' %
                              (1, self.group.pci_dbdf), fail=False)
        assert_eq(ret == 0, max_vfs > 0, 'Status enabling VFs')

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
        self.dut.insmod()
        self.dut.nfp_reset()
        self.dut.nffw_load(os.path.join(self.dut.tmpdir,
                                        os.path.basename(self.group.netdevfw)))

        max_vfs = self.dut.get_rtsym_scalar('nfd_vf_cfg_max_vfs')
        self.dut.rmmod()

        self.dut.refresh()
        netifs_old = len(self.dut._netifs)

        self.dut.insmod(netdev=True)
        self.dut.cmd("udevadm settle")
        time.sleep(1)
        self.dut.refresh()

        netifs_new = len(self.dut._netifs)
        assert_lt(netifs_new, netifs_old,
                  "Interface count after enabling SR-IOV")

        # See if after kernel load SR-IOV limit was set correctly
        ret, _ = self.dut.cmd('echo %d > /sys/bus/pci/devices/%s/sriov_numvfs' %
                              (max_vfs + 1, self.group.pci_dbdf), fail=False)
        assert_neq(0, ret, "SR-IOV VF limit not obeyed")

        if max_vfs > 0 or self.dut.kernel_ver_ge(4, 18):
            _, out = self.dut.cmd('cat /sys/bus/pci/devices/%s/sriov_totalvfs' %
                                  (self.group.pci_dbdf))
            assert_eq(max_vfs, int(out), "SR-IOV VF limit not reported")

        # Check TotalVFs goes back to max after rmmod
        self.dut.rmmod()
        _, out = self.dut.cmd('cat /sys/bus/pci/devices/%s/sriov_totalvfs' %
                              (self.group.pci_dbdf))
        sysfs = int(out)

        _, out = self.dut.cmd('lspci -vv -s %s' % (self.group.pci_dbdf))
        hw = int(re.search(r'Total VFs: (\d*)', out).groups()[0])
        assert_eq(hw, sysfs, "Total VFs without driver loaded")

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
        self.skip_not_ifc_phys()

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

        _, ethtool_fec_output = self.dut.ethtool_get_fec(iface)
        s = re.search("active fec encoding:(.*)\n", ethtool_fec_output.lower(),
                      re.MULTILINE)
        if s:
            active_encoding = s.groups()[0]
        else:
            active_encoding = ""

        if expected_ethtool_fec == "" and active_encoding != "":
                raise NtiError('Expected interface %s to not have any encodings, found %s' %
                               (iface, active_encoding))
        else:
            if not re.search(expected_ethtool_fec, active_encoding):
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

        time.sleep(3) # Takes time for NSP to action this command
        self.ping(port, should_fail=True)

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

    def prepare(self):
        self.is_fec_capable = False

    def cleanup(self):
        if self.is_fec_capable:
            self.dut.cmd_nsp('-C +aneg0 eth0 eth1')
            self.dut.cmd_nsp('-C +fec0 eth0 eth1')

            self.src.cmd("/opt/netronome/bin/nfp-nsp -n1 -C +aneg0 eth0 eth1")
            self.src.cmd("/opt/netronome/bin/nfp-nsp -n1 -C +fec0 eth0 eth1")

        return super(CommonNonUpstreamTest, self).cleanup()

    def netdev_execute(self):
        self.nsp_min(22)
        self.skip_not_ifc_phys()

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
            self.is_fec_capable = True

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
            if self.is_fec_capable:
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

                self.check_fec_mode(iface, mac_addr, "Fec0", "")
                self.set_fec_and_expect_to_fail(entry, "baser")
                self.set_fec_and_expect_to_fail(entry, "rs")
                self.set_fec_and_expect_to_fail(entry, "off")
                self.set_fec_and_expect_to_fail(entry, "auto")

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
        self.dut.ip_link_set_up(self.vnics[0])

        _, msgs = self.dut.cmd("dmesg -c")
        if msgs.find(probe_err) != -1:
            raise NtiError("Failed to probe with good TLVs")

        irqmod_exp = 64 << 16 | 50 * 160 / 16
        irqmod = self.dut.nfd_reg_read_le32(self.vnics[0], 0x0b00)
        if irqmod != irqmod_exp:
            raise NtiError("IRQMOD entry %x, expected %x" %
                           (irqmod, irqmod_exp))

    def cleanup(self):
        self.dut.reset_mods()
        self.dut.insmod()
        self.dut.nffw_unload()
        self.dut.reset_mods()

        CommonNonUpstreamTest.cleanup(self)
