#
# Copyright (C) 2018,  Netronome Systems, Inc.  All rights reserved.
#

import os
from ..common_test import assert_neq, assert_ge, CommonTest, NtiSkip

class XDPReplaceTest(CommonTest):
    def check_with_ping(self):
        ifc = self.dut_ifn[self.port]

        s = self.dut.ethtool_stats(ifc=ifc)
        self.ping(port=self.port, count=10)
        diff = self.dut.ethtool_stats_diff(ifc=ifc, old_stats=s)

        assert_ge(10, diff['bpf_pass_pkts'], "BPF passed packets")

    def execute(self):
        self.port = 0
        self.nsim_name = "nsim_" + os.path.basename(self.group.tmpdir)
        self.nsim_prog = '/sys/fs/bpf/' + self.nsim_name

        # Create netdevsim device to have a program offloaded to a diff netdev
        ret, _ = self.dut.cmd('modprobe netdevsim', fail=False)
        if ret:
            raise NtiSkip('netdevsim module not available')

        self.dut.cmd('echo "1 1" > /sys/bus/netdevsim/new_device')

        if self.group.xdp_mode() != "offload":
            raise NtiSkip("Only support xdpoffload mode")

        ret, out = self.dut.cmd('ls /sys/bus/netdevsim/devices/netdevsim1/net')
        netdevsim = out.strip().split(' ')[-1]
        self.dut.ip_link_set_down(netdevsim)
        self.dut.cmd('ip link set %s name %s' % (netdevsim, self.nsim_name))
        self.dut.ip_link_set_up(self.nsim_name)

        self.xdp_start('pass.o', ifc=self.nsim_name, mode="offload")

        # Pin netdevsim's prog so we can refer to it in iproute2
        link = self.dut.ip_link_show(ifc=self.nsim_name)
        self.dut.cmd('bpftool prog pin id %d %s' %
                     (link["xdp"]["prog"]["id"], self.nsim_prog))

        # Check we have XDP counters working
        self.xdp_start('pass.o', mode="offload", port=self.port)
        self.check_with_ping()

        # Replace
        ret, _ = self.dut.cmd('ip -force link set dev %s xdpoffload pinned %s' %
                              (self.dut_ifn[self.port], self.nsim_prog),
                              fail=False)
        assert_neq(0, ret,
                   "Replace with program from another device should fail")
        self.check_with_ping()

    def cleanup(self):
        self.xdp_reset()
        self.dut.cmd('echo "1 1" > /sys/bus/netdevsim/del_device', fail=False)
        self.dut.cmd('rm -f ' + self.nsim_prog)
        return super(XDPReplaceTest, self).cleanup()
