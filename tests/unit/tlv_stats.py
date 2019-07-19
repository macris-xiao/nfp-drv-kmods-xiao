#
# Copyright (C) 2019,  Netronome Systems, Inc.  All rights reserved.
#
"""
Unit test for TLV stats.
"""

from netro.testinfra import LOG_sec, LOG, LOG_endsec
from ..common_test import CommonNonUpstreamTest, \
    assert_nin, assert_in, assert_eq
from ..nfd import NfdTlvCap

class TLVstatsTest(CommonNonUpstreamTest):
    def prepare(self):
        if self.group.upstream_drv:
            return NrtResult(name=self.name, testtype=self.__class__.__name__,
                             passed=None, comment="Raw BAR write upstream")
        return super(TLVstatsTest, self).prepare()

    def reprobe(self):
        self.dut.reset_mods()
        self.dut.insmod(netdev=True, userspace=True)
        self.dut.cmd("udevadm settle")

    def modify_bar(self, mods):
        for w in mods:
            self.dut.cmd_rtsym("_pf0_net_bar0:%d %d" %
                               (w[0], w[1] << 16 | w[2]))

    def assert_stat(self, name, stats, val):
        assert_in(name, stats, "Extra stats visible")
        assert_eq(stats[name], val, "Extra stats value")

    def netdev_execute(self):
        ifc = self.group.eth_x[0]

        LOG_sec("Hide existing TLV")
        pos = self.dut.nfd_get_vnic_cap(ifc, NfdTlvCap.VNIC_STATS,
                                        return_pos=True)
        if pos is not None:
            tl = self.nfd_reg_read_le32(ifc, pos)
            self.modify_bar([(pos, NfdTlvCap.RESERVED, tl & 0xffff)])
        LOG_endsec()

        LOG_sec("Find END TLV")
        pos = self.dut.nfd_get_vnic_cap(ifc, NfdTlvCap.END, return_pos=True)
        LOG_endsec()

        LOG_sec("Implant an empty stats TLV")
        if pos % 8 == 0:
            LOG_sec("Align to 4")
            self.modify_bar([(pos +  0, NfdTlvCap.RESERVED, 0)])
            pos += 4
            LOG_endsec()

        self.modify_bar([(pos +  0, NfdTlvCap.VNIC_STATS, 56),
                         (pos +  4, 2, 1000),
                         (pos +  8, 1002, 1001),
                         (pos +  12, 1004, 1003),
                         (pos +  16, 1006, 1005),
                         (pos +  20, 0, 111),
                         (pos +  28, 0, 222),
                         (pos +  36, 0, 333),
                         (pos +  44, 0, 444),
                         (pos +  52, 0, 555),
                         (pos +  60, NfdTlvCap.END, 0)])
        self.reprobe()

        stats = self.dut.ethtool_stats(ifc)
        LOG_endsec()
        assert_nin("dev_rx_discards", stats, "Normal stats hidden")
        self.assert_stat("dev_unknown_stat1000", stats, 111)
        self.assert_stat("dev_rx_errors", stats, 222)
        self.assert_stat("dev_unknown_stat1001", stats, 333)
        self.assert_stat("dev_unknown_stat1002", stats, 444)
        self.assert_stat("dev_unknown_stat1003", stats, 555)
        assert_nin("dev_unknown_stat1004", stats, "Over stats hidden")
        assert_nin("dev_unknown_stat1005", stats, "Over stats hidden")

        LOG_sec("Remove the stats TLV")
        self.modify_bar([(pos +  0, NfdTlvCap.END, 0)])
        self.reprobe()

        stats = self.dut.ethtool_stats(ifc)
        assert_in("dev_rx_discards", stats, "Normal stats visible")
        LOG_endsec()

    def cleanup(self):
        self.dut.reset_mods()
        self.dut.insmod()
        self.dut.nffw_unload()
        self.dut.reset_mods()

        super(TLVstatsTest, self).cleanup()
