#
# Copyright (C) 2018,  Netronome Systems, Inc.  All rights reserved.
#
from netro.testinfra import LOG_sec, LOG, LOG_endsec
from netro.testinfra.nti_exceptions import NtiError
from ..common_test import CommonTest

class MacStatsEthtool(CommonTest):
    info = """
    The purpose of this test is to ensure that the MAC stats reported
    by the driver, via Ethtool, are accurate.

    The test will only test physical interfaces, and will also skip if
    if the installed firmware does not support MAC statistics counting.

    For each interface:
    - `ethtool -S` is used to inspect the values of the MAC statistics
    - The interface is pinged to increment the statistics
    - `ethtool -S` is used to inspect the values of the MAC statistics again

    If the difference between the values obtained from `ethtool -S` is below a
    certain threshold for any of the statistics, the test will fail.
    """
    def test_stat(self, ifidx, stat_name, size,
                  exp_inc=None, prepend=["rx_", "tx_"]):
        if exp_inc is None:
            exp_inc = size

        size -= 46 # Headers
        repeat = 40

        LOG_sec("MAC stat " + self.dut_ifn[ifidx] + ' ' + stat_name)

        before = self.dut.ethtool_stats(self.dut_ifn[ifidx])

        self.ping(ifidx, count=repeat, size=size, ival=0.01)

        after = self.dut.ethtool_stats(self.dut_ifn[ifidx])

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

        ret, _ = self.dut.ip_link_set_mtu(self.dut_ifn[ifidx], 1600, fail=False)
        # If we can't do jumbo just skip the jumbo counter tests
        if ret:
            return
        # For switchdev-only FWs we need to adjust MTU on vNICs, too
        if self.dut_ifn[ifidx] not in self.dut.vnics:
            for vnic in self.dut.vnics:
                ret, _ = self.dut.ip_link_set_mtu(vnic, 1600, fail=False)
                if ret:
                    return

        self.src.ip_link_set_mtu(self.src_ifn[ifidx], 1600)

        for t in jumbo_stats:
            self.test_stat(ifidx, t[0], t[1], 1)

    def execute(self):
        if self.read_sym_nffw('_mac_stats') is None:
            raise NtiSkip("FW doesn't report MAC stats")

        self.skip_not_ifc_phys()

        for i in range(0, len(self.dut_ifn)):
            self.test_one_ifc(i)

    def cleanup(self):
        for ifc in self.src_ifn:
            self.src.ip_link_set_mtu(ifc, 1500)
        return super(MacStatsEthtool, self).cleanup()
