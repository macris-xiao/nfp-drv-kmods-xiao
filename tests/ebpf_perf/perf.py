#
# Copyright (C) 2018,  Netronome Systems, Inc.  All rights reserved.
#
import csv
import os
import struct
import time
import netro.testinfra
from netro.testinfra.test import *
from netro.testinfra.nrt_result import NrtResult
from netro.testinfra.nti_exceptions import NtiError
from ..common_test import *
from ..ebpf.maps import *

################################################################################
# Actual test classes - control path
################################################################################

class BPFPerf(MapTest):
    def get_ethtool_rate(self, host, interface, sample_period, port=0):
        rate = {}

        t0 = time.time()
        bef = host.ethtool_stats(self.dut_ifn[port])

        sleeptime = sample_period - (time.time() - t0)
        time.sleep(sleeptime)

        aft = host.ethtool_stats(self.dut_ifn[port])

        for key in aft:
                rate[key] = (int(aft[key]) - int(bef[key])) / sample_period
        return rate

    def baseline_lookup(self):
        target_pps = -1
        target_mapwrite = -1

        if self.group.ebpf_baseline_file != None:
            csvfile = csv.reader(open(self.group.ebpf_baseline_file, "rb"))
            for line in csvfile:
                if line[0] == self.name:
                    target_pps = float(line[7])
                    target_mapwrite = float(line[8])
                    break
        return target_pps, target_mapwrite

    def cleanup(self):
        self.xdp_stop(mode=self.group.xdp_mode())

class XDPperf(BPFPerf):
    def __init__(self, *args, **kwargs):
        self.filename = kwargs.pop('objfile')
        self.drv_cntr = kwargs.pop('drv_pkt_cntr')
        self.offload_cntr = kwargs.pop('off_pkt_cntr')
        super(XDPperf, self).__init__(*args, **kwargs)

    def load_xdp(self):
        self.xdp_start(self.filename, mode=self.group.xdp_mode())

    def execute(self):
        self.load_xdp()
        eth_data = self.get_ethtool_rate(self.dut, self.dut_ifn[0], 3)

        if self.group.xdp_mode() == "offload":
            packets = eth_data[self.offload_cntr]
        else:
            packets = eth_data[self.drv_cntr]

        self.test_metrics.append(packets)
        self.test_metrics.append(0) # no mapwrites

        target_pps, target_mapwrite = self.baseline_lookup()

        if target_pps != -1:
            pps_perc = packets / target_pps * 100

            if pps_perc < 98:
                self.test_result = False
            self.test_comment += ("pps: %.2f%%" % pps_perc)
        else:
            self.test_comment += ("new test")

class RANDperf(XDPperf):
    def prepare(self):
        if self.group.xdp_mode() == "offload" and \
           not self.dut.bpf_caps["random"]:
            return NrtResult(name=self.name, testtype=self.__class__.__name__,
                             passed=None, comment="no FW random cap")

    def load_xdp(self):
        self.xdp_start(self.filename, mode=self.group.xdp_mode(),
                       progdir=self.dut.xdp_perf_dir)
