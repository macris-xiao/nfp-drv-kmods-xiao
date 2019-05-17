#
# Copyright (C) 2019,  Netronome Systems, Inc.  All rights reserved.
#

from .base_traffic import KTLSTrafficTestBase

class KTLSDropsThroughput(KTLSTrafficTestBase):
    def prepare(self):
        self.tc_set = dict()
        self.tc_set[self.dut] = False
        self.tc_set[self.src] = False

        return super(KTLSDropsThroughput, self).prepare()

    def execute(self):
        ifc_dut = self.dut_ifn[0]
        ifc_src = self.src_ifn[0]

        self.dut.cmd('tc qdisc replace dev %s root netem drop 0.1' % (ifc_dut))
        self.tc_set[self.dut] = True
        self.dut.cmd('tc -s qdisc show dev %s' % (ifc_dut))

        self.src.cmd('tc qdisc replace dev %s root netem drop 0.1' % (ifc_src))
        self.tc_set[self.src] = True
        self.src.cmd('tc -s qdisc show dev %s' % (ifc_src))

        return self.run_traffic_test(100, 100, 50000000, 20)

    def cleanup(self):
        ifc_dut = self.dut_ifn[0]
        ifc_src = self.src_ifn[0]

        if self.tc_set[self.dut]:
            self.dut.cmd('tc qdisc delete dev %s root' % (ifc_dut))
            self.dut.cmd('tc -s qdisc show dev %s' % (ifc_dut))

        if self.tc_set[self.src]:
            self.src.cmd('tc qdisc delete dev %s root' % (ifc_src))
            self.src.cmd('tc -s qdisc show dev %s' % (ifc_src))

        return super(KTLSDropsThroughput, self).cleanup()
