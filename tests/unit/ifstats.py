#
# Copyright (C) 2018,  Netronome Systems, Inc.  All rights reserved.
#
"""
Unit test for interface statistics.
"""

import re
from netro.testinfra.test import *
from netro.testinfra.system import cmd_log
from ..common_test import *

def ethool_stats_add(stats, pattern):
    s = 0
    found = 0
    for k in stats.keys():
        if re.match(pattern, k):
            s += stats[k]
            found += 1
    return found, s

def check_ifstats_etstats(ifstats, etstats, num_rings, is_core_nic_2_0):
    # RX byte counts may or may not include FCS
    # TX may get padded so we have no idea if it's correct
    if ifstats["rx"]["bytes"] != etstats["dev_rx_bytes"] and \
       ifstats["rx"]["bytes"] != etstats["dev_rx_bytes"] - \
                              etstats["dev_rx_pkts"] * 4:
        raise NtiError('RX bytes %d exepected %d or %d' %
                       (ifstats["rx"]["bytes"], etstats["dev_rx_bytes"],
                        etstats["dev_rx_bytes"] - etstats["dev_rx_pkts"] * 4))

    for d in ('rx', 'tx'):
        assert_eq(ifstats[d]["packets"], etstats["dev_" + d + "_pkts"],
                  d + " packet cnt")
        found, s = ethool_stats_add(etstats, d + 'q_\d+_pkts')
        # CoreNIC 2.0 does not update NFD per-queue stats
        if s or not is_core_nic_2_0:
            assert_eq(ifstats[d]["packets"], s, "HWq " + d + " packets")
        assert_eq(num_rings, found, "HWq " + d + " rings")

        found, s = ethool_stats_add(etstats, d + 'q_\d+_bytes')
        # CoreNIC 2.0 does not update NFD per-queue stats
        if s or not is_core_nic_2_0:
            assert_eq(ifstats[d]["bytes"], s, "HWq " + d + " bytes")
        assert_eq(num_rings, found, "HWq " + d + " rings")

        found, s = ethool_stats_add(etstats, 'rvec_\d+_' + d + '_pkts')
        assert_eq(ifstats[d]["packets"], s, "SWq " + d + " packets")
        assert_eq(num_rings, found, "HWq " + d + " rings")

class IFstats(CommonNetdevTest):
    def ifstat(self, ifc):
        _, linkinfo = self.dut.ip_link_stats(ifc)
        return linkinfo["stats64"]

    def netdev_execute(self):
        pkt_cnt = 100

        self.dut.skip_test_if_mode_switchdev()

        ret, _ = cmd_log('ls %s' % (os.path.join(self.group.samples_xdp,
                                                 'pass.o')),
                         fail=False)
        has_xdp = not ret
        if has_xdp:
            self.dut.copy_bpf_samples()

        drvinfo = self.dut.ethtool_drvinfo(self.vnics[0])
        is_core_nic_2_0 = bool(drvinfo["firmware-version"].count("nic-2.0.") or
                               drvinfo["firmware-version"].count("abm"))

        for ifc in self.vnics:
            port = self.dut_ifn.index(ifc)

            chan_settings = self.dut.ethtool_channels_get(ifc)
            queue_cfgs = ({ "rx" : 0, "tx" : 0, "combined" : 1, },
                          { "rx" : 0, "tx" : 0,
                            "combined" : chan_settings["max"]["rx"], },
                          { "rx" : 1, "tx" : 0, "combined" : 1, },
                          chan_settings["current"])

            for tidx in range(len(queue_cfgs)):
                self.src.link_wait(self.src_ifn[port])

                # Spray some traffic in both directions
                self.dut.tcpping(addr=self.src_addr[port][:-3],
                                 ifc=self.dut_ifn[port], count=pkt_cnt,
                                 speed="faster", keep=False)
                self.src.tcpping(addr=self.dut_addr[port][:-3],
                                 ifc=self.src_ifn[port], count=pkt_cnt,
                                 speed="faster", keep=False)

                # Take the link down on source to prevent counter increments
                self.src.ip_link_set_down(self.src_ifn[port])

                # Snapshot stats, retry until we have a stable one
                LOG_sec("Get stats snapshot")
                try:
                    ifstats = self.ifstat(ifc)
                    etstats = self.dut.ethtool_stats(ifc)
                    for i in range(30):
                        ifstats2 = self.ifstat(ifc)
                        etstats2 = self.dut.ethtool_stats(ifc)
                        if etstats == etstats2 and ifstats == ifstats2:
                            break
                        etstats = etstats2
                        ifstats = ifstats2
                    else:
                        raise NtiSkip("ERROR: stats didn't stabilize")
                finally:
                    LOG_endsec()

                # Validate stats make sense with generated traffic
                assert_ge(pkt_cnt * (tidx + 1), ifstats["rx"]["packets"],
                          "rx pkts")
                assert_ge(pkt_cnt * (tidx + 1), ifstats["tx"]["packets"],
                          "tx pkts")

                # Validate ifstats vs ethtool stats
                check_ifstats_etstats(ifstats, etstats,
                                      chan_settings["max"]["rx"],
                                      is_core_nic_2_0)

                # Do bunch of reconfigurations
                self.dut.ip_link_set_down(ifc)
                self.dut.ip_link_set_up(ifc)

                # XDP may fail if there isn't enough rings
                qcfg = queue_cfgs[tidx - 1]
                if has_xdp and \
                   qcfg['rx'] + qcfg["tx"] > chan_settings["max"]["rx"]:
                    self.xdp_start('pass.o', port=port)
                    self.xdp_stop(port=port)

                self.dut.ethtool_channels_set(ifc, queue_cfgs[tidx])

                rings = self.dut.ethtool_rings_get(ifc)["current"]
                rings2 = {}
                for k in rings.keys():
                    rings2[k] = rings[k] * 2
                self.dut.ethtool_rings_set(ifc, rings2)
                self.dut.ethtool_rings_set(ifc, rings)

                # Get new snapshot of stats
                _, linkinfo = self.dut.ip_link_stats(ifc)
                ifstats2 = linkinfo["stats64"]
                etstats2 = self.dut.ethtool_stats(ifc)

                # Make sure snapshots are equal, we need wiggle room, because
                # most sources will generate spurious frames even though we
                # took the link down.
                for d in ('rx', 'tx'):
                    for k in ifstats[d].keys():
                        room = 3000 if k == 'bytes' else 15
                        assert_range(ifstats[d][k], ifstats[d][k] + room,
                                     ifstats2[d][k], "ifstat %s %s" % (d, k))
                for k in etstats.keys():
                    room = 3000 if k.count('bytes') or k.count('octet') else 15
                    assert_range(etstats[k], etstats[k] + room,
                                 etstats2[k], "etstat %s" % (k))

                # Restore source link state
                self.src.ip_link_set_up(self.src_ifn[port])

    def cleanup(self):
        for ifc in self.src_ifn:
            self.src.ip_link_set_up(ifc)
        return super(IFstats, self).cleanup()
