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
        return


import os
from netro.testinfra.nti_exceptions import NtiGeneralError
from netro.testinfra.nrt_result import NrtResult

class Insmod(CommonDrvTest):
    def execute(self):
        ret, _ = self.dut.cmd('insmod %s' % (self.dut.mod), fail=False)
        if ret != 0:
            raise NtiGeneralError("Couldn't load the module")

        ret, _ = self.dut.cmd('insmod %s' % (self.dut.mod_nth), fail=False)
        if ret != 0:
            raise NtiGeneralError("Couldn't load the test module")

class DebugFSSetupTest(CommonNTHTest):
    def run(self):
        return NrtResult(name=self.name, passed=bool(self.dut.dfs_dir),
                         testtype=self.__class__.__name__)

class Tools(CommonTest):
    def execute(self):
        ret, _ = self.dut.cmd_hwinfo('-h', fail=False)
        if ret:
            raise NtiGeneralError("BSP tools not installed")
        ret, _ = self.src.cmd('hping3 -h', fail=False)
        if ret:
            raise NtiGeneralError("hping3 not installed on SRC")
        ret, _ = self.dut.cmd('hping3 -h', fail=False)
        if ret:
            raise NtiGeneralError("hping3 not installed on DUT")
        ret, _ = self.dut.cmd('devlink', fail=False)
        if ret:
            raise NtiGeneralError("devlink not installed on DUT")

class Mefw(CommonTest):
    def execute(self):
        def prep_path(s):
            return os.path.join(self.group.mefw, s)

        mefws = ('rts_100.nffw',
                 'rm_rts_0.nffw',
                 'rm_rts_1.nffw',
                 'rm_rts_2.nffw',
                 'rm_rts_3.nffw',
                 'rm_rts_17.nffw',
                 'rm_rts_100.nffw',
                 'rm1_rts_100.nffw',
                 'rm2_rts_100.nffw')
        mefws = " ".join(map(prep_path, mefws))

        ret, _ = cmd_log('ls %s %s' % (self.group.netdevfw, mefws))

class Sriov(CommonTest):
    def execute(self):
        _, out = self.dut.cmd('ls /sys/kernel/iommu_groups | wc -l')
        if int(out) < 1:
            raise NtiGeneralError("No IOMMU groups - is IOMMU enabled?")

class BPFSetupTest(CommonTest):
    def run(self):
        return NrtResult(name=self.name, passed=self.group.bpf_capable(),
                         testtype=self.__class__.__name__)

class XDPSetupTest(CommonTest):
    def run(self):
        return NrtResult(name=self.name, passed=self.group.xdp_capable(),
                         testtype=self.__class__.__name__)
