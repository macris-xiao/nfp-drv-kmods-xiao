#
# Copyright (C) 2016-2017,  Netronome Systems, Inc.  All rights reserved.
#

import netro.testinfra
from netro.testinfra.nrt_result import NrtResult
from ..drv_test import *

class XDPSetupTest(CommonTest):
    def run(self):
        return NrtResult(name=self.name, passed=self.dut.has_xdp,
                         testtype=self.__class__.__name__)
