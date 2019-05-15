#
# Copyright (C) 2019,  Netronome Systems, Inc.  All rights reserved.
#

import json
import time

from netro.testinfra import LOG_sec, LOG, LOG_endsec

from .base import KTLSTestBase

class KTLSConnStress(KTLSTestBase):
    def check_time(self, exp_max, out, k):
        if out[k] <= exp_max:
            LOG("%s: %.2f <= %.2f usec" % (k, out[k], exp_max))
        else:
            self.time_violation = True
            LOG("%s: %.2f > %.2f usec violation!!" % (k, out[k], exp_max))

    def run_stress_test(self, ifc, port, v6, t, proc, conn, max_time,
                        direction="both", keep_conn=0):
        if not v6:
            src_addr = self.group.addr_a[0][:-3]
        else:
            src_addr = self.group.addr_v6_a[0][:-3]

        self.time_violation = False

        sec_name = "#{} {:,} proc, {:,} conn".format(t, proc, conn)
        if direction != "both":
            sec_name += ", {}-only".format(direction)
        if keep_conn:
            sec_name += ", {:,} keep".format(keep_conn)
        LOG_sec(sec_name)

        try:
            start = time.time()
            _, out = self.run_ktls_conn_stress(self.dut, src_addr, port,
                                               procs=proc, conns=conn,
                                               keep_conn=keep_conn, v6=v6,
                                               direction=direction, tag=ifc)
            end = time.time()

            out = json.loads(out)
            out["run_time"] = (end - start) * 1000 * 1000

            LOG_sec("Timing")
            self.check_time(max_time[0], out, "run_time")
            self.check_time(max_time[1], out, "usec_max_ktls_ulp")
            self.check_time(max_time[2], out, "usec_max_ktls_tx")
            self.check_time(max_time[3], out, "usec_max_ktls_rx")
            LOG_endsec()
        finally:
            if self.time_violation:
                self.test_comment += "#{} overtime|".format(t)
            LOG_endsec()

    # Targetting < 60 sec runtime, the function is called 2 times,
    # so we have 30 sec to run
    def test_all(self, ifc, port, off, v6):
        # All times in usecs
        max_times = (4 * 10 ** 6, 75, 750, 750)
        self.run_stress_test(ifc, port, v6, off + 1,  4, 2500, max_times)
        max_times = (4 * 10 ** 6, 75, 1000, 1000)
        self.run_stress_test(ifc, port, v6, off + 2,  8, 2000, max_times)
        max_times = (4 * 10 ** 6, 500, 3000, 2000)
        self.run_stress_test(ifc, port, v6, off + 3, 20, 1000, max_times)

        max_times = (4 * 10 ** 6, 100, 1500, 1500)
        self.run_stress_test(ifc, port, v6, off + 4, 10, 2000, max_times,
                             keep_conn=200)

        max_times = (4 * 10 ** 6, 100, 75, 1500)
        self.run_stress_test(ifc, port, v6, off + 5, 10, 2000, max_times,
                             direction="rx", keep_conn=200)

        max_times = (4 * 10 ** 6, 100, 1500, 75)
        self.run_stress_test(ifc, port, v6, off + 6, 10, 2000, max_times,
                             direction="tx", keep_conn=200)
        return 6

    def execute(self):
        ifc = self.group.eth_x[0]

        self.dut.copy_c_samples()
        self.src.copy_c_samples()

        # Make sure all are enabled
        self.tls_enable_all_feats()

        # Start acceptor
        self.procs[self.src], port = \
            self.spawn_tcp_acceptor(self.src, tag=ifc)

        n = 0
        # IPv4
        n += self.test_all(ifc, port, n, False)
        self.kill_procs()

        # IPv6
        self.procs[self.src], port = \
            self.spawn_tcp_acceptor(self.src, v6=True, tag=ifc)
        n += self.test_all(ifc, port, 6, True)
