#
# Copyright (C) 2019,  Netronome Systems, Inc.  All rights reserved.
#

from .base_traffic import KTLSTrafficTestBase

class KTLSMixedThroughput(KTLSTrafficTestBase):
    def prepare(self):
        self.netperf = dict()
        self.netperf[self.dut] = None
        self.netperf[self.src] = None

        return super(KTLSMixedThroughput, self).prepare()

    def execute(self):
        ifc_dut = self.dut_ifn[0]
        ifc_src = self.src_ifn[0]

        self.src.cmd('netserver', fail=False)
        self.dut.cmd('netserver', fail=False)

        src_addr = self.group.addr_a[0][:-3]
        dut_addr = self.group.addr_x[0][:-3]

        self.netperf[self.src] = self.src.spawn_netperfs(dut_addr)
        self.netperf[self.dut] = self.dut.spawn_netperfs(src_addr)

        return self.run_traffic_test(100, 100)

    def cleanup(self):
        ifc_dut = self.dut_ifn[0]
        ifc_src = self.src_ifn[0]

        for k in self.netperf.keys():
            if self.netperf[k]:
                self.kill_pidfile(k, self.netperf[k])

        return super(KTLSMixedThroughput, self).cleanup()
