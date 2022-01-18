#
# Copyright (C) 2018,  Netronome Systems, Inc.  All rights reserved.
#

from ..common_test import *
from .xdp import XDPpassAll

class XDPadjustTailPassAll(XDPpassAll):
    def execute(self):
        if self.is_offload_mode() and not self.dut.bpf_caps["adjust_tail"]:
            self.xdp_start(self.get_prog_name(), mode=self.group.xdp_mode(),
                           should_fail=True)
            return

        return super(XDPpassAll, self).execute()

class XDPadjustTail14(XDPadjustTailPassAll):
    def get_exp_pkt(self):
        return self.std_pkt()[:14]

class XDPadjustTailMulti(XDPadjustTailPassAll):
    def get_exp_pkt(self):
        return self.std_pkt()[:-30]

class XDPadjustTailPositive(XDPadjustTailPassAll):
    def execute(self):
        if self.is_offload_mode():
            raise NtiSkip("Current FW doesn't support positive tail adjust")

        return super(XDPadjustTailPassAll, self).execute()
