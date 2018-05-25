#
# Copyright (C) 2018,  Netronome Systems, Inc.  All rights reserved.
#
import netro.testinfra
from netro.testinfra.test import *
from netro.testinfra.nrt_result import NrtResult
from netro.testinfra.nti_exceptions import NtiError
from ..common_test import *
from perf import BPFPerf

################################################################################
# Actual test classes - control path
################################################################################

class SyntheticProg(BPFPerf):
    shared_results = []

    def __init__(self, *args, **kwargs):
        self.filename = kwargs.pop('objfile')
        self.packet_extend = kwargs.pop('packet_extend')
        self.map_records = kwargs.pop('map_records')
        super(SyntheticProg, self).__init__(*args, **kwargs)

    def map_fill(self, maps, entries):
        batch = ""
        numberofmaps = len(maps)
        for i in range(0, entries + 1):
                key0 = str((i & 0xFF000000) >> 24)
                key1 = str((i & 0x00FF0000) >> 16)
                key2 = str((i & 0x0000FF00) >> 8)
                key3 = str(i & 0x000000FF)

                # fill rxcnt
                batch += ("map update id %d key %s %s %s %s "
                          "value 3 0 0 0 0 0 0 0 \n" %
                          (maps[0]['id'], key3, key2, key1, key0))
                # fill rand
                if numberofmaps == 2:
                        batch += ("map update id %d key %s %s %s %s "
                                  "value %s 6 %s 4 %s 2 %s %s \n" %
                                 (maps[1]['id'], key3, key2, key1, key0,
                                  key3, key3, key2, key1, key0))
        write_time = self.bpftool_batch(batch, log_cmds=False)
        write_rate = (entries * numberofmaps) / write_time
        return write_rate

    def update_run_avg(self, new_result):
        if self.shared_results:
            self.shared_results[0] += 1
            self.shared_results[1] += new_result
        else:
            self.shared_results.append(1)
            self.shared_results.append(new_result)
        return self.shared_results[1] / self.shared_results[0]

    def execute(self):
        sampletime = 3
        filename = self.filename
        _, maps = self.dut.bpftool_map_list()
        self.n_start_maps = len(maps)

        self.xdp_start(filename, mode=self.group.xdp_mode(),
                       progdir=self.dut.xdp_perf_dir)
        m = self.bpftool_maps_get()
        write_rate = int(self.map_fill(m, self.map_records))

        eth_data = self.get_ethtool_rate(self.dut, self.dut_ifn[0], sampletime)
        tx_packets = eth_data['dev_tx_pkts']
        tx_mbytes = float(eth_data['dev_tx_bytes'])
        assert_neq(0, tx_packets, "Zero TX packets")
        avg_packet_size = tx_mbytes / tx_packets

        if self.packet_extend == 1:
            assert_approx(80, 0.1, avg_packet_size, "TX packet size")
        else:
            assert_approx(60, 0.1, avg_packet_size, "TX packet size")

        assert_equal(0, eth_data['bpf_app1_pkts'], "xdp_drop packets")
        assert_equal(0, eth_data['bpf_app3_pkts'], "xdp_abort packets")

        self.test_metrics.append(tx_packets)
        self.test_metrics.append(write_rate)
        target_pps, target_mapwrite = self.baseline_lookup()

        if target_pps == -1:
            self.test_comment = "new test"
        else:
            if self.group.xdp_mode() == "offload":
                pps_pass_limit = 98
                write_pass_limit = 97
            else:
                pps_pass_limit = 90
                write_pass_limit = 75

            pps_perf_perc = tx_packets / target_pps * 100
            mapwrite_perf_perc = write_rate / target_mapwrite * 100
            running_avg = self.update_run_avg(pps_perf_perc)

            if pps_perf_perc < pps_pass_limit:
                self.test_result = False
                self.test_comment += ("TX fail: %.2f%% "
                                      % pps_perf_perc)

            if self.map_records >= 65535: # only larger maps are reliable
                if mapwrite_perf_perc < write_pass_limit:
                    self.test_result = False
                    self.test_comment += ("Write/s fail: %.2f%% "
                                          % mapwrite_perf_perc)

            self.test_comment += "avg pps:%.2f%%" % running_avg

    def cleanup(self):
        self.xdp_stop(mode=self.group.xdp_mode())
        self.dut.bpf_wait_maps_clear(expected=self.n_start_maps)
