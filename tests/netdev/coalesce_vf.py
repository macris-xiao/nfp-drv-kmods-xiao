#
# Copyright (C) 2021,  Corigine, Inc.  All rights reserved.
#
"""
Netdev test for coalesce based on VF.
"""

import time
from netro.testinfra.nti_exceptions import NtiError
from ..common_test import CommonTest, NtiSkip


class CoalesceVF(CommonTest):

    def __init__(self, src, dut, group=None, name="", summary=None):
        """
        @dut:        A tuple of System and interface name of DUT
        @src:        A tuple of System and interface name of srcoint
        @group:      Test group this test belongs to
        @name:       Name for this test instance
        @summary:    Optional one line summary for the test
        """
        CommonTest.__init__(self, src, dut, group, name, summary)
        self.result_off_latency = []
        self.result_off_throughput = []

    def check_prereq(self, check, description, on_src=False):
        if on_src:
            res, _ = self.src.cmd(check, fail=False)
        else:
            res, _ = self.dut.cmd(check, fail=False)

        if res == 1:
            if on_src:
                raise NtiSkip('SRC does not support feature: %s' % description)
            else:
                raise NtiSkip('DUT does not support feature: %s' % description)

    def netns_cmd(self, cmd, ns):
        nscmd = "ip netns exec {} {}".format(ns, cmd)
        return self.dut.cmd(nscmd)

    def check_coalesce(self, vstatus='off', vport='vf1', ns='ns1', d_usecs='50', d_frames='64'):
        if vstatus == 'off':
            cmd = 'ethtool --show-coalesce %s | grep rx-usecs:' % vport
            ret, out = self.netns_cmd(cmd, ns)
            rx_usecs = out.strip().split()[-1]
            cmd = 'ethtool --show-coalesce %s | grep rx-frames:' % vport
            ret, out = self.netns_cmd(cmd, ns)
            rx_frames = out.strip().split()[-1]
            if((rx_usecs != d_usecs) | (rx_frames != d_frames)):
                raise NtiError("Failed to set coalesce:rx-usecs(s/d)=(%s:%s), \
                rx-frames(s/d)=(%s/%s)" % (rx_usecs, d_usecs, rx_frames, d_frames))
        else:
            #cmd = 'ip netns exec %s ethtool --show-coalesce %s | grep Adaptive' % (ns, vport)
            #ret, out = self.dut.cmd(cmd)
            cmd = 'ethtool --show-coalesce %s | grep Adaptive' % (ns, vport)
            ret, out = self.netns_cmd(cmd, ns)
            adaptive_rx = out.strip().split()[2]
            adaptive_tx = out.strip().split()[-1]
            if((adaptive_rx != 'on') | (adaptive_tx != 'on')):
                raise NtiError("Failed to enable coalesce !")

    def execute(self):
        self.check_prereq("netserver -h 2>&1 | grep Usage:",
                          'netserver missing', on_src=False)
        self.check_prereq("netperf -h 2>&1 | grep Usage:", 'netperf missing')
        netperf_ip_1 = '20.0.0.10'
        netperf_ip_2 = '20.0.0.20'
        vf1 = "".join(self.spawn_vf_netdev()[0])
        vf2 = "".join(self.spawn_vf_netdev()[0])

        iface = self.dut_ifn[0]
        if not iface[:-1].endswith('np') or not iface.startswith('en'):
            raise NtiSkip('Cannot determine PF interface name')

        self.dut.cmd('ip link set dev %s up' % (iface), fail=False)
        # Create namespaces
        self.dut.cmd('ip netns add ns1')
        self.dut.cmd('ip link set %s netns ns1' % vf1)
        self.dut.cmd('ip netns add ns2')
        self.dut.cmd('ip link set %s netns ns2' % vf2)
        # Prepare namespace for coalesce test
        cmd = "ip addr add %s/24 dev %s" % (netperf_ip_1, vf1)
        self.netns_cmd(cmd, 'ns1')
        cmd = "ip link set dev %s up" % vf1
        self.netns_cmd(cmd, 'ns1')
        cmd = 'ip addr add %s/24 dev %s' % (netperf_ip_2, vf2)
        self.netns_cmd(cmd, 'ns2')
        cmd = 'ip link set dev %s up' % vf2
        self.netns_cmd(cmd, 'ns2')
        # Disable coalesce , set rx-usecs/rx-frames is default
        cmd = 'ethtool -C %s adaptive-rx off adaptive-tx off rx-usecs 50 rx-frames 64' % vf1
        self.netns_cmd(cmd, 'ns1')
        cmd = 'ethtool -C %s adaptive-rx off adaptive-tx off rx-usecs 50 rx-frames 64' % vf2
        self.netns_cmd(cmd, 'ns2')
        self.check_coalesce(vport=vf1, ns='ns1')
        self.check_coalesce(vport=vf2, ns='ns2')

        # Start netserver in ns2
        self.netns_cmd('netserver', 'ns2')
        # Start netperf , test latency and throughput of coalesce(off-50/64)
        cmd = 'netperf -H %s -l 60  -t omni -- -d rr -O "THROUGHPUT, THROUGHPUT_UNITS, \
        MIN_LATENCY, MAX_LATENCY, MEAN_LATENCY"' % netperf_ip_2
        ret, out = self.netns_cmd(cmd, 'ns1')
        line = "".join(out).split('\n')[-2].strip()
        self.result_off_latency.append(float(line.split()[-1]))
        cmd = 'netperf -H %s -l 60' % netperf_ip_2
        ret, out = self.netns_cmd(cmd, 'ns1')
        line = "".join(out).split('\n')[-2].strip()
        self.result_off_throughput.append(float(line.split()[-1]))

        # Start netperf , test latency and throughput of coalesce(off-0/1)
        time.sleep(5)
        cmd = 'ethtool -C %s adaptive-rx off adaptive-tx off rx-usecs 1 rx-frames 0' % vf1
        ret, out = self.netns_cmd(cmd, 'ns1')
        cmd = 'ethtool -C %s adaptive-rx off adaptive-tx off rx-usecs 1 rx-frames 0' % vf2
        ret, out = self.netns_cmd(cmd, 'ns2')
        self.check_coalesce(vport=vf1, ns='ns1', d_usecs='1', d_frames='0')
        self.check_coalesce(vport=vf2, ns='ns2', d_usecs='1', d_frames='0')
        cmd = 'netperf -H %s -l 60' % netperf_ip_2
        ret, out = self.netns_cmd(cmd, 'ns1')
        line = "".join(out).split('\n')[-2].strip()
        self.result_off_throughput.append(float(line.split()[-1]))
        cmd = 'netperf -H %s -l 60  -t omni -- -d rr -O "THROUGHPUT, THROUGHPUT_UNITS, \
        MIN_LATENCY, MAX_LATENCY, MEAN_LATENCY"' % netperf_ip_2
        ret, out = self.netns_cmd(cmd, 'ns1')
        line = "".join(out).split('\n')[-2].strip()
        self.result_off_latency.append(float(line.split()[-1]))

        # Enable coalesce
        time.sleep(5)
        cmd = 'ethtool -C %s adaptive-rx on adaptive-tx on' % vf1
        self.netns_cmd(cmd, 'ns1')
        cmd = 'ethtool -C %s adaptive-rx on adaptive-tx on' % vf2
        self.netns_cmd(cmd, 'ns2')
        self.check_coalesce(vstatus='on', vport=vf1, ns='ns1')
        self.check_coalesce(vstatus='on', vport=vf2, ns='ns2')

        # Start netperf , test latency and throughput of coalesce(on)
        cmd = 'netperf -H %s -l 60  -t omni -- -d rr -O "THROUGHPUT, THROUGHPUT_UNITS, \
        MIN_LATENCY, MAX_LATENCY, MEAN_LATENCY"' % netperf_ip_2
        ret, out = self.netns_cmd(cmd, 'ns1')
        result_o = "".join(out).split('\n')[-2].strip()
        result_on_latency = float(result_o.split()[-1])
        cmd = 'netperf -H %s -l 60' % netperf_ip_2
        ret, out = self.netns_cmd(cmd, 'ns1')
        result_o = "".join(out).split('\n')[-2].strip()
        result_on_throughput = float(result_o.split()[-1])

        # Result compare
        default_off_latency = 0.5 * self.result_off_latency[0]
        default_off_throughput = 0.9 * self.result_off_throughput[1]
        if result_on_latency >= default_off_latency:
            raise NtiError("Latency is not reasonable,Failed to test coalesce !")
        if result_on_throughput < default_off_throughput:
            raise NtiError("Throughout is not reasonable,Failed to test coalesce !")
        if default_off_latency < self.result_off_latency[1]:
            raise NtiError("Latency is not reasonable,off_latency of 1/0 setting is big !")

    def cleanup(self):
        self.dut.cmd('ip netns exec ns1 pkill netserver', fail=False)
        self.dut.cmd('ip netns del ns1', fail=False)
        self.dut.cmd('ip netns del ns2', fail=False)
        self.dut.cmd('echo 0 > /sys/bus/pci/devices/%s/sriov_numvfs' %
                     self.group.pci_dbdf)
