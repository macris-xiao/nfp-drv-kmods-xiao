#
# Copyright (C) 2016-2017,  Netronome Systems, Inc.  All rights reserved.
#
"""
Setup test group for the NFP Linux drivers.
"""

import netro.testinfra
from netro.testinfra.test import *
from netro.testinfra.system import cmd_log
from ..common_test import *
from ..drv_grp import NFPKmodGrp

###########################################################################
# Unit Tests
###########################################################################


class NFPKmodSetup(NFPKmodGrp):
    """Setup tests for the NFP Linux drivers"""

    summary = "Check environment for running the NFP Linux driver tests."

    def __init__(self, name, cfg=None, quick=False, dut_object=None,
                 dut=None, nfp=None, nfpkmods=None, mefw=None):

        NFPKmodGrp.__init__(self, name=name, cfg=cfg, quick=quick,
                            dut_object=dut_object)


    def populate_tests(self):
        dut = (self.dut, self.addr_x, self.eth_x, self.addr_v6_x)
        src = (self.host_a, self.addr_a, self.eth_a, self.addr_v6_a)

        self._tests['tools'] = Tools(src, dut, self, 'tools',
                                     "Test if tools are present")
        self._tests['insmod'] = Insmod(src, dut, self, 'insmod',
                                       "Test loading nfp.ko")
        self._tests['debugfs'] = DebugFSSetupTest(src, dut, self, 'debugfs',
                                                  "Test DebugFS is mounted")
        self._tests['mefw'] = Mefw(src, dut, self, 'mefw',
                                   "Test if firmware images are present")
        self._tests['sriov'] = Sriov(src, dut, self, 'sriov',
                                     "Test if SR-IOV can be used")
        self._tests['bpf'] = BPFSetupTest(src, dut, self, 'bpf',
                                          "Test the setup for BPF")
        self._tests['xdp'] = XDPSetupTest(src, dut, self, 'xdp',
                                          "Test the setup for XDP")
        self._tests['python'] = PythonTest(src, dut, self, 'python',
                                           "Test Python installation")
        self._tests['bpf_tools'] = \
                BPFSetupToolsTest(src, dut, self, 'bpf_tools',
                                  "Test if BPF tools are present")
        return


import os
from netro.testinfra.nti_exceptions import NtiError, NtiGeneralError
from netro.testinfra.nrt_result import NrtResult

class Insmod(CommonDrvTest):
    def execute(self):
        ret, _ = self.dut.insmod(fail=False)
        if ret != 0:
            raise NtiGeneralError("Couldn't load the module")

        ret, _ = self.dut.insmod('nth', fail=False)
        if ret != 0:
            raise NtiGeneralError("Couldn't load the test module")

class DebugFSSetupTest(CommonNTHTest):
    def run(self):
        return NrtResult(name=self.name, passed=bool(self.dut.dfs_dir),
                         testtype=self.__class__.__name__)

class Tools(CommonTest):
    def check_tool(self, host, hostname, tool, toolname):
        ret, _ = host.cmd(tool, fail=False)
        if ret:
            raise NtiGeneralError("%s not installed on %s" % (toolname,
                                                              hostname))

    def check_tool_both(self, tool, toolname=None):
        self.check_tool(self.src, "SRC", tool, toolname)
        self.check_tool(self.dut, "DUT", tool, toolname)

    def execute(self):
        # We need to set the NFP id for hwinfo to something, without actually
        # loading the module it will be None
        self.group.nfp = 0
        ret, _ = self.dut.cmd_hwinfo('-h', fail=False)
        if ret:
            raise NtiGeneralError("BSP tools not installed")
        ret, _ = self.dut.cmd_hwinfo('-h 2>&1 | grep " -Z"', fail=False)
        if ret:
            raise NtiGeneralError("BSP tools too old, -Z not supported")

        self.check_tool_both('hping3 -h', 'hping3')
        self.check_tool_both('devlink', 'devlink')
        self.check_tool_both('bash -c "compgen -c netserver"', 'netserver')
        self.check_tool_both('bash -c "compgen -c netperf"', 'netperf')

class Mefw(CommonTest):
    def execute(self):
        def prep_path(s):
            return os.path.join(self.group.mefw, s)

        mefws = ['rts_100',
                 'rm_rts_0',
                 'rm_rts_1',
                 'rm_rts_2',
                 'rm_rts_3',
                 'rm_rts_17',
                 'rm_rts_100',
                 'rm1_rts_100']

        if self.dut.get_pci_device_id() != '3800':
            mefws += ['rm2_rts_100']
            for i in range(len(mefws)):
                mefws[i] += "_nfp-4xxx-b0.nffw"
        else:
            for i in range(len(mefws)):
                mefws[i] += "_nfp-38xxc.nffw"

        mefws = " ".join(map(prep_path, mefws))

        ret, _ = cmd_log('ls %s %s' % (self.group.netdevfw, mefws))

class Sriov(CommonTest):
    def execute(self):
        self.dut.cmd('modinfo pci_stub')
        self.dut.cmd('modprobe pci_stub')
        # make sure it's a module, tests may depend on modprobe -r
        self.dut.cmd('lsmod | grep pci_stub')
        self.dut.cmd('modprobe -r pci_stub')

class BPFSetupTest(CommonTest):
    def run(self):
        ret, _ = self.dut.cmd('bpftool', fail=False)
        if ret:
            raise NtiError("bpftool not installed on DUT")

        return NrtResult(name=self.name, passed=self.group.bpf_capable(),
                         testtype=self.__class__.__name__)

class XDPSetupTest(CommonTest):
    def run(self):
        ret, _ = self.dut.cmd('bpftool', fail=False)
        if ret:
            raise NtiError("bpftool not installed on DUT")

        return NrtResult(name=self.name, passed=self.group.xdp_capable(),
                         testtype=self.__class__.__name__)

class PythonTest(CommonTest):
    def execute(self):
        self.read_sym_nffw('nfd_cfg_pf0_num_ports')
        self.read_sym_nffw('blabla_bad_symbol')

class BPFSetupToolsTest(CommonTest):
    def execute(self):
        ret, _ = self.dut.cmd('ip link help 2>&1 | grep xdpoffload', fail=False)
        if ret != 0:
            raise NtiError("ip link doesn't have xdp offload mode support")
