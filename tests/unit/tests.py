#
# Copyright (C) 2016-2017,  Netronome Systems, Inc.  All rights reserved.
#
"""
Unit test group for the NFP Linux drivers.
"""

import netro.testinfra
from netro.testinfra.test import *
from ..drv_grp import NFPKmodGrp

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
             ('fw_names', FwSearchTest, "Test FW requested by the driver"),
             ('sriov', SriovTest, 'Test SR-IOV sysfs interface'),
             ('netdev', NetdevTest, "Test netdev loading"),
             # Tests which assume netdev FW to be loaded
             ('params_incompat', ParamsIncompatTest,
              "Test if incompatible parameter combinations are rejected"),
             ('dev_cpp', DevCppTest,
              "Test user space access existence and basic functionality"),
             ('kernel_fw_load', KernelLoadTest, "Test kernel firmware loader"))

        for t in T:
            self._tests[t[0]] = t[1](src, dut, self, t[0], t[2])


import os
import re
import time
from random import shuffle
from netro.testinfra.nti_exceptions import NtiGeneralError
from netro.testinfra.nrt_result import NrtResult
from netro.testinfra.system import cmd_log
from ..drv_test import *

class Modinfo(CommonTest):
    def execute(self):
        # Check if module device table is complete
        entries = ['v000019EEd00006003sv000019EEsd',
                   'v000019EEd00004000sv000019EEsd',
                   'v000019EEd00006000sv000019EEsd',
                   'v000019EEd00006010sv000019EEsd']

        entries += ["netronome/%s" % self.dut.get_fw_name()]

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

            resources.append((name, cpp_id, addr, size))

        resources *= 3
        random.seed(1234)
        random.shuffle(resources)

        for i in range(0, len(resources)):
            M.dfs_write('nth/resource', resources[i][0])
            rescs = M.dfs_read_raw('nth/resource')
            _, out = M.cmd_res('-L')
            self.resources_validate(resources[:i+1], rescs, out)

        # Try non-existing resource on filled table
        M.dfs_write('resource', "test.xxx", do_fail=True)

        # Release all resources and see if locks are freed
        for i in range(0, len(resources)):
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

class RTSymTest(CommonTest):
    def __init__(self, src, dut, group=None, name="", summary=None):
        CommonTest.__init__(self, src, dut, group, name, summary)

        self.fws = [('rm_rts_3', 3), ('rm_rts_17', 17), (None, -5),
                    ('rm1_rts_100', 100),
                    # MIPv2 not supported, yet
                    ('rm2_rts_100', -5),
                    ('rts_100', -5),
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

        M.insmod(params="nfp_reset=1")
        M.insmod(module="nth")

        self.check_cnt('insmod', -5)

        self.test_all()
        self.test_all(user_space_load=False)

    def cleanup(self):
        self.dut.cmd('rm -rf /lib/firmware/netronome')
        self.dut.reset_mods()

class FwSearchTest(CommonDrvTest):
    def prepare(self):
        return self.kernel_min(3, 17)

    def execute(self):
        M = self.dut

        # Clean the old dmesg info
        M.cmd('dmesg -c')

        # By default we should not look for FW
        M.insmod()
        _, out = M.cmd('dmesg -c')
        if out.find('Direct firmware load for ') != -1:
            raise NtiGeneralError('nfp.ko looking for firmware')

        fw_name = M.get_fw_name()
        M.rmmod()

        # Request nfp.ko to look for some FW
        M.insmod(params="nfp6000_firmware=_bad_fw_name")
        _, out = M.cmd('dmesg -c')
        if out.find('Direct firmware load for _bad_fw_name') == -1:
            raise NtiGeneralError('nfp.ko should be looking for firmware')
        M.rmmod()

        # Make load fail
        M.insmod(params="nfp6000_firmware=_bad_fw_name fw_load_required=1")
        _, out = M.cmd('dmesg -c')
        if out.find('nfp: probe of ') == -1:
            raise NtiGeneralError('nfp.ko should fail to load without FW')
        M.rmmod()

        # Check what netdev will look for
        M.insmod(netdev=True, params="fw_load_required=1")
        _, out = M.cmd('dmesg -c')
        if out.find('nfp: probe of ') == -1:
            raise NtiGeneralError('nfp.ko should fail to load without FW')
        if out.find('Direct firmware load for netronome/%s' % (fw_name)) == -1:
            raise NtiGeneralError('nfp.ko netdev not looking for part FW (%s)' %
                                  (fw_name))
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

class NetdevTest(CommonDrvTest):
    def execute(self):
        M = self.dut

        # Check FW loading from the user space
        M.insmod(params="nfp_reset=1")
        M.nffw_load('%s' % self.group.netdevfw)
        M.rmmod()

        M.refresh()
        netifs_old = len(M._netifs)

        M.insmod(netdev=True)
        time.sleep(1)
        M.refresh()

        netifs_new = len(M._netifs)
        M.rmmod()

        if netifs_new <= netifs_old:
            raise NtiGeneralError('Interfaces was:%s is:%d, expected new ones' %
                                  (netifs_old, netifs_new))

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
        M.insmod(params='fw_load_required=1', netdev=True)
        time.sleep(1)
        M.refresh()
        netifs_new = M._netifs

        if len(netifs_new) - len(netifs_old) != 1:
            raise NtiGeneralError('Expected one interface created, got %d' %
                                  (len(netifs_new) - len(netifs_old)))

        ifc = M.netifs[list(set(netifs_new) - set(netifs_old))[0]]
        M.cmd('ifconfig %s %s up' % (ifc.devn, self.group.addr_x))

        self.ping()
        M.rmmod()
        M.cmd('rm /lib/firmware/netronome/%s' % (name))

    def execute(self):
        M = self.dut

        M.cmd('mkdir -p /lib/firmware/netronome')

        self.load_test(M.get_fw_name())

    def cleanup(self):
        self.dut.cmd('rm -rf /lib/firmware/netronome')
        self.dut.reset_mods()
