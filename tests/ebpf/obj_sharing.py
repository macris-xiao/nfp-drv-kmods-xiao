#
# Copyright (C) 2018,  Netronome Systems, Inc.  All rights reserved.
#

import json
import os
from netro.testinfra import LOG_sec, LOG, LOG_endsec
from netro.testinfra.system import cmd_log
from ..linux_system import int2str, str2int
from ..common_test import CommonTest, NtiSkip, \
    assert_lt, assert_ge, assert_range, assert_neq
from defs import *
from perf_event_output import stack_data

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

# Install different programs on two interfaces, then swap them around
class XDPProgXIfc(CommonTest):
    def prepare(self):
        res = require_helper(self, BPF_HELPER.PERF_EVENT_OUTPUT, "event output")
        if res:
            return res
        if len(self.dut_ifn) < 2:
            return NrtResult(name=self.name, testtype=self.__class__.__name__,
                             passed=None, comment="single port card")
        return super(XDPProgXIfc, self).prepare()

    def execute(self):
        self.ping_cnt = 10
        self.prog_path = '/sys/fs/bpf/' + os.path.basename(self.group.tmpdir)

        if len(self.dut_ifn) < 2:
            raise NtiSkip("single port card")

        # Load the programs for interfaces 0 and 1
        self.dut.bpftool_prog_load_xdp('map_atomic.o', self.prog_path + '_0',
                                       ifc=self.dut_ifn[0])
        self.dut.bpftool_prog_load_xdp('perf_event_output_stack.o',
                                       self.prog_path + '_1',
                                       ifc=self.dut_ifn[1])
        # Install on the opposite port
        self.dut.cmd('ip -force link set dev %s xdpoffload pinned %s' %
                     (self.dut_ifn[0], self.prog_path + '_1'))
        self.dut.cmd('ip -force link set dev %s xdpoffload pinned %s' %
                     (self.dut_ifn[1], self.prog_path + '_0'))

        perf_map = self.dut.ip_link_xdp_maps(ifc=self.dut_ifn[0])["offload"][0]
        cnt_map = self.dut.ip_link_xdp_maps(ifc=self.dut_ifn[1])["offload"][0]

        # Run ping on first interface and expect perf events
        events, pid = self.dut.bpftool_map_perf_capture_start(m=perf_map)
        self.ping(port=0, ival="0.02", count=20)
        events_out = self.dut.bpftool_map_perf_capture_stop(events, pid)

        # Pinged on the perf interface, counter should not move much
        _, elems = self.dut.bpftool_map_dump(m=cnt_map)
        cnt = str2int(elems[0]["value"])
        assert_lt(10, cnt, "Counter value mismatch")

        # We should have all the events
        self.bpftool_map_perf_capture_validate(events_out, stack_data,
                                               exp_num=20)

        # Run ping on second interface and expect map counter
        events, pid = self.dut.bpftool_map_perf_capture_start(m=perf_map)
        self.ping(port=1, ival="0.02", count=20)
        events_out = self.dut.bpftool_map_perf_capture_stop(events, pid)

        _, elems = self.dut.bpftool_map_dump(m=cnt_map)
        cnt = str2int(elems[0]["value"])
        assert_ge(20, cnt, "Counter value mismatch")

        # Manually check we got few perf events now
        LOG_sec('Events from: ' + events_out)
        cmd_log('cat ' + events_out)
        LOG_endsec()

        events = json.load(open(events_out))
        assert_lt(10, len(events), 'Number of events')

    def cleanup(self):
        for ifc in self.dut_ifn:
            self.dut.cmd('ip -force link set dev %s xdpoffload off' % (ifc))
        self.dut.cmd('rm -f ' + self.prog_path + '*')
        self.dut.bg_proc_stop_all()
        return super(XDPProgXIfc, self).cleanup()

# Install different programs on two interfaces, then swap them around
class XDPProgXIfcCheck(CommonTest):
    def prepare(self):
        if self.group.upstream_drv:
            return NrtResult(name=self.name, testtype=self.__class__.__name__,
                             passed=None, comment="upstream driver")
        return super(XDPProgXIfcCheck, self).prepare()

    def execute(self):
        self.orig_bar = {}

        self.prog_path = '/sys/fs/bpf/' + os.path.basename(self.group.tmpdir)

        # Read the real caps
        for off in (0x80, 0x88):
            _, out = self.dut.cmd_rtsym('_pf%d_net_bar0:0x%x' %
                                        (self.group.pf_id, off))
            self.orig_bar[off] = int(out.split()[1], 16)

        # Load a program which uses maps
        self.dut.bpftool_prog_load_xdp('map_atomic.o', self.prog_path,
                                       ifc=self.dut_ifn[0])

        # Set the program length to 8, attach should fail
        cap_80 = self.orig_bar[0x80] & 0xffff
        cap_80 |= 8 << 16

        self.dut.cmd_rtsym('_pf%d_net_bar0:0x%x 0x%x' %
                           (self.group.pf_id, 0x80, cap_80))


        ret, _ = self.dut.cmd('ip -force link set dev %s xdpoffload pinned %s' %
                              (self.dut_ifn[0], self.prog_path), fail=False)
        assert_neq(0, ret, 'Offload with prog len = 8')

        # Fix prog len
        self.dut.cmd_rtsym('_pf%d_net_bar0:0x%x 0x%x' %
                           (self.group.pf_id, 0x80, self.orig_bar[0x80]))
        self.orig_bar.pop(0x80, None)

        # Now set the stack size to 0
        cap_88 = self.orig_bar[0x88] & 0xffffff00

        self.dut.cmd_rtsym('_pf%d_net_bar0:0x%x 0x%x' %
                           (self.group.pf_id, 0x88, cap_88))


        ret, _ = self.dut.cmd('ip -force link set dev %s xdpoffload pinned %s' %
                              (self.dut_ifn[0], self.prog_path), fail=False)
        assert_neq(0, ret, 'Offload with stack size = 0')

        # Fix stack size
        self.dut.cmd_rtsym('_pf%d_net_bar0:0x%x 0x%x' %
                           (self.group.pf_id, 0x88, self.orig_bar[0x88]))
        self.orig_bar.pop(0x88, None)

    def cleanup(self):
        self.dut.cmd('rm -f ' + self.prog_path)
        for key in self.orig_bar:
            self.dut.cmd_rtsym('_pf%d_net_bar0:0x%x 0x%x' %
                               (self.group.pf_id, key, self.orig_bar[key]))
        for ifc in self.dut_ifn:
            self.dut.cmd('ip -force link set dev %s xdpoffload off' % (ifc))
        return super(XDPProgXIfcCheck, self).cleanup()
