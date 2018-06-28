#
# Copyright (C) 2018,  Netronome Systems, Inc.  All rights reserved.
#

import os
from ..linux_system import int2str, str2int
from ..common_test import CommonTest, NtiSkip, \
    assert_lt, assert_ge, assert_range

class XDPProgMapShare(CommonTest):
    def check_with_ping(self, port, m):
        self.ping(port=port, ival="0.02", count=self.ping_cnt)

        _, elems = self.dut.bpftool_map_dump(m=m)
        cnt = str2int(elems[0]["value"])
        i = port + 1
        assert_range(self.ping_cnt * i, (self.ping_cnt + 2) * i + 8, cnt,
                     "Counter value mismatch")

    def execute(self):
        self.ping_cnt = 10
        self.prog_path = '/sys/fs/bpf/' + os.path.basename(self.group.tmpdir)

        n_ports = len(self.dut_ifn)

        if n_ports < 2:
            raise NtiSkip("single port card")

        # Install the same program on all interfaces, first install on one
        self.xdp_start('map_atomic.o', mode="offload", port=0)
        progs = self.dut.ip_link_xdp_progs(ifc=self.dut_ifn[0])
        # Pin it so iproute2 can access it
        self.dut.cmd('bpftool prog pin id %d %s' %
                     (progs["offload"]["id"], self.prog_path))

        # Install on all the other ones
        for i in range(1, n_ports):
            self.dut.cmd('ip -force link set dev %s xdpoffload pinned %s' %
                         (self.dut_ifn[i], self.prog_path))

        maps = self.dut.ip_link_xdp_maps(ifc=None, progs=progs)
        # Run ping on all interfaces and see if the same map gets the count
        for i in range(n_ports):
            self.check_with_ping(i, maps["offload"][0])

    def cleanup(self):
        for ifc in self.dut_ifn:
            self.dut.cmd('ip -force link set dev %s xdpoffload off' % (ifc))
        self.xdp_reset()
        self.dut.cmd('rm -f ' + self.prog_path)
        return super(XDPProgMapShare, self).cleanup()
