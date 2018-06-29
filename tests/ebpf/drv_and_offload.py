#
# Copyright (C) 2018,  Netronome Systems, Inc.  All rights reserved.
#

import os
from ..common_test import CommonTest, assert_range, assert_lt
from ..linux_system import int2str, str2int

class XDPDrvOffCnt(CommonTest):
    def check_cnt(self, m, low, high):
        _, elems = self.dut.bpftool_map_dump(m=m)
        cnt = str2int(elems[0]["value"])
        assert_range(low, high, cnt, "Counter value mismatch")
        return cnt

    def execute(self):
        self.port = 0
        self.ifc = self.dut_ifn[self.port]

        # Test with two programs installed
        self.xdp_start("map_atomic.o", port=self.port, mode="drv")
        self.xdp_start("map_atomic.o", port=self.port, mode="offload")

        self.ping(port=self.port, ival="0.02", count=10)

        maps = self.dut.ip_link_xdp_maps(ifc=self.ifc)
        d = self.check_cnt(maps["drv"][0], 10, 18)
        o = self.check_cnt(maps["offload"][0], 10, 18)
        assert_lt(3, abs(d - o), "Pkt count difference between offload and drv")

        # Replace driver with pass
        self.xdp_start("pass.o", port=self.port, mode="drv")
        self.ping(port=self.port, ival="0.02", count=10)

        self.check_cnt(maps["offload"][0], 20, 30)

        # Stop driver XDP
        self.xdp_stop(port=self.port, mode="drv")
        self.ping(port=self.port, ival="0.02", count=10)

        self.check_cnt(maps["offload"][0], 30, 45)

        # Put the count back on the driver
        self.xdp_start("map_atomic.o", port=self.port, mode="drv")
        self.ping(port=self.port, ival="0.02", count=10)

        maps = self.dut.ip_link_xdp_maps(ifc=self.ifc)
        self.check_cnt(maps["drv"][0], 10, 15)
        self.check_cnt(maps["offload"][0], 40, 60)

        # Now pass on offload
        self.xdp_start("pass.o", port=self.port, mode="offload")
        self.ping(port=self.port, ival="0.02", count=10)

        self.check_cnt(maps["drv"][0], 20, 30)

        # Stop offload XDP
        self.xdp_stop(port=self.port, mode="offload")
        self.ping(port=self.port, ival="0.02", count=10)

        self.check_cnt(maps["drv"][0], 30, 45)

        # And try with drop in the offload
        self.xdp_start("drop.o", port=self.port, mode="offload")
        self.ping(port=self.port, ival="0.02", count=10, should_fail=True)

        self.check_cnt(maps["drv"][0], 30, 45)

    def cleanup(self):
        self.xdp_reset()
        return super(XDPDrvOffCnt, self).cleanup()

class XDPDrvOffAdjHead(CommonTest):
    def execute(self):
        self.port = 0
        self.ifc = self.dut_ifn[self.port]

        self.ping(port=self.port, ival="0.02", count=10)

        # Load prepend for offload
        self.xdp_start("adjust_head_push32.o", port=self.port, mode="offload")
        # Now we shouldn't be able to ping, because frames will be mangled
        self.ping(port=self.port, ival="0.02", count=10, should_fail=True)
        # Install the driver program to remove the prepend
        self.xdp_start("adjust_head_pull32.o", port=self.port, mode="drv")
        # And ping should be back to working
        self.ping(port=self.port, ival="0.02", count=10)

    def cleanup(self):
        self.xdp_reset()
        return super(XDPDrvOffAdjHead, self).cleanup()
