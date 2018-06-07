#
# Copyright (C) 2018,  Netronome Systems, Inc.  All rights reserved.
#

import json
import os
import netro.testinfra
from netro.testinfra.nti_exceptions import NtiError
from netro.testinfra.system import cmd_log
from netro.testinfra.test import *
from ..common_test import *
from defs import *
from maps import MapTest
from xdp import xdp_test_name_to_prog

class QueueSelectTest(MapTest):
    def test_one(self, prog, pcap_src, src_ifc, dst_ifc, qidx):
        LOG_sec("Test with prog:%s expect on Q:%d" % (prog, qidx))
        try:
            if prog:
                self.xdp_start(prog, mode=self.group.xdp_mode())

            before = self.dut.ethtool_stats(dst_ifc)
            self.src.cmd("tcpreplay --intf1=%s --pps=100 %s " %
                         (src_ifc, pcap_src))
            after = self.dut.ethtool_stats(dst_ifc)

            for i in range(64):
                s = 'rvec_%u_rx_pkts' % i
                if s not in after:
                    continue

                diff = after[s] - before[s]
                if i == qidx:
                    assert_ge(100, diff, "Number of packet in expected queue")
                else:
                    assert_lt(60, diff, "Number of packet in other queue")
        finally:
            LOG_endsec()

    def execute(self):
        # In driver mode or without the cap load should fail
        if self.group.xdp_mode() != "offload" or \
           self.dut.bpf_caps["qsel"] == False:
            self.xdp_start("queue_select_q1.o", mode=self.group.xdp_mode(),
                           should_fail=True)
            return

        src_ifc = self.src_ifn[0]
        dst_ifc = self.dut_ifn[0]
        pkt = self.std_pkt()
        pcap_src = self.prep_pcap(pkt)

        # We have a funky Ethtype, all traffic should go to queue 0
        self.test_one(None, pcap_src, src_ifc, dst_ifc, 0)
        self.test_one("queue_select_q1.o", pcap_src, src_ifc, dst_ifc, 1)
        # Queue over limit, so normal RSS -> q0 because of Ethertype
        self.test_one("queue_select_q63.o", pcap_src, src_ifc,  dst_ifc, 0)
        self.test_one("queue_select_q123456.o", pcap_src, src_ifc,  dst_ifc, 0)
        self.test_one("queue_select_q-1.o", pcap_src, src_ifc,  dst_ifc, 0)

    def cleanup(self):
        self.xdp_stop(mode=self.group.xdp_mode())
