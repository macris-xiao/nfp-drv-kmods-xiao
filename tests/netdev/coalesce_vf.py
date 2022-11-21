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
    info = """
    Test the ethtool -c command on VF interfaces.

    The test requires SRIOV firmware, it will be skipped
    if another firmware type is installed.

    Netserver is started and configured with set values before
    `ethtool --coalesce` is run and the rx_usecs and rx_frames values
    are set.

    These coalesce settings are then retrieved to determine if they were
    correctly set. Thereafter, the latency and throughput values for each
    interface are checked against a maximum acceptable error rate.

    This process is repeated for rx-usecs/rx-frames combinations:
    - 50/64
    - 0/1
    as well as for adaptive rx/tx
    """

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

    def check_coalesce(self, vstatus='off', vport='vf1', ns='ns1', d_usecs='50', d_frames='64'):
        M = self.dut
        c_settings = M.ethtool_get_coalesce(vport, ns)

        if vstatus == 'off':
            rx_usecs = c_settings['rx-usecs']
            rx_frames = c_settings['rx-frames']
            if((rx_usecs != d_usecs) | (rx_frames != d_frames)):
                raise NtiError("Failed to set coalesce:rx-usecs(s/d)=(%s:%s), \
                rx-frames(s/d)=(%s/%s)" % (rx_usecs, d_usecs, rx_frames, d_frames))
        else:
            adaptive_rx = c_settings['Adaptive RX']
            adaptive_tx = c_settings['Adaptive TX']
            if((adaptive_rx != 'on') | (adaptive_tx != 'on')):
                raise NtiError("Failed to enable coalesce !")

    def execute(self):

        for ifc in self.dut.nfp_netdevs:
            info = self.dut.ethtool_drvinfo(ifc)

            ver_m = info['firmware-version']
            if not "sriov" in ver_m:
                raise NtiSkip("Change to SRIOV firmware")

        self.check_prereq("netserver -h 2>&1 | grep Usage:",
                          'netserver missing', on_src=False)
        self.check_prereq("netperf -h 2>&1 | grep Usage:", 'netperf missing')
        netperf_ip_1 = '20.0.0.10'
        netperf_ip_2 = '20.0.0.20'

        vfs = self.spawn_vf_netdev(2)
        vf1 = vfs[0]["name"]
        vf2 = vfs[1]["name"]

        iface = self.dut_ifn[0]
        if not iface[:-1].endswith('np') or not iface.startswith('en'):
            raise NtiSkip('Cannot determine PF interface name')

        self.dut.cmd('ip link set dev %s up' % (iface), fail=False)
        # Create namespaces
        self.dut.netns_add('ns1')
        self.dut.netns_add_iface('ns1', vf1)
        self.dut.netns_add('ns2')
        self.dut.netns_add_iface('ns2', vf2)
        # Prepare namespace for coalesce test
        cmd = "ip addr add %s/24 dev %s" % (netperf_ip_1, vf1)
        self.dut.netns_cmd(cmd, 'ns1')
        cmd = "ip link set dev %s up" % vf1
        self.dut.netns_cmd(cmd, 'ns1')
        cmd = 'ip addr add %s/24 dev %s' % (netperf_ip_2, vf2)
        self.dut.netns_cmd(cmd, 'ns2')
        cmd = 'ip link set dev %s up' % vf2
        self.dut.netns_cmd(cmd, 'ns2')
        # Disable coalesce , set rx-usecs/rx-frames is default
        cmd = 'ethtool -C %s adaptive-rx off adaptive-tx off rx-usecs 50 rx-frames 64' % vf1
        self.dut.netns_cmd(cmd, 'ns1')
        cmd = 'ethtool -C %s adaptive-rx off adaptive-tx off rx-usecs 50 rx-frames 64' % vf2
        self.dut.netns_cmd(cmd, 'ns2')
        self.check_coalesce(vport=vf1, ns='ns1')
        self.check_coalesce(vport=vf2, ns='ns2')

        # Start netserver in ns2
        self.dut.netns_cmd('netserver', 'ns2')
        # Start netperf , test latency and throughput of coalesce(off-50/64)
        cmd = 'netperf -H %s -l 60  -t omni -- -d rr -O "THROUGHPUT, THROUGHPUT_UNITS, \
        MIN_LATENCY, MAX_LATENCY, MEAN_LATENCY"' % netperf_ip_2
        ret, out = self.dut.netns_cmd(cmd, 'ns1')
        line = "".join(out).split('\n')[-2].strip()
        self.result_off_latency.append(float(line.split()[-1]))
        cmd = 'netperf -H %s -l 60' % netperf_ip_2
        ret, out = self.dut.netns_cmd(cmd, 'ns1')
        line = "".join(out).split('\n')[-2].strip()
        self.result_off_throughput.append(float(line.split()[-1]))

        # Start netperf , test latency and throughput of coalesce(off-0/1)
        time.sleep(5)
        cmd = 'ethtool -C %s adaptive-rx off adaptive-tx off rx-usecs 1 rx-frames 0' % vf1
        ret, out = self.dut.netns_cmd(cmd, 'ns1')
        cmd = 'ethtool -C %s adaptive-rx off adaptive-tx off rx-usecs 1 rx-frames 0' % vf2
        ret, out = self.dut.netns_cmd(cmd, 'ns2')
        self.check_coalesce(vport=vf1, ns='ns1', d_usecs='1', d_frames='0')
        self.check_coalesce(vport=vf2, ns='ns2', d_usecs='1', d_frames='0')
        cmd = 'netperf -H %s -l 60' % netperf_ip_2
        ret, out = self.dut.netns_cmd(cmd, 'ns1')
        line = "".join(out).split('\n')[-2].strip()
        self.result_off_throughput.append(float(line.split()[-1]))
        cmd = 'netperf -H %s -l 60  -t omni -- -d rr -O "THROUGHPUT, THROUGHPUT_UNITS, \
        MIN_LATENCY, MAX_LATENCY, MEAN_LATENCY"' % netperf_ip_2
        ret, out = self.dut.netns_cmd(cmd, 'ns1')
        line = "".join(out).split('\n')[-2].strip()
        self.result_off_latency.append(float(line.split()[-1]))

        # Enable coalesce
        time.sleep(5)
        cmd = 'ethtool -C %s adaptive-rx on adaptive-tx on' % vf1
        self.dut.netns_cmd(cmd, 'ns1')
        cmd = 'ethtool -C %s adaptive-rx on adaptive-tx on' % vf2
        self.dut.netns_cmd(cmd, 'ns2')
        self.check_coalesce(vstatus='on', vport=vf1, ns='ns1')
        self.check_coalesce(vstatus='on', vport=vf2, ns='ns2')

        # Start netperf , test latency and throughput of coalesce(on)
        cmd = 'netperf -H %s -l 60  -t omni -- -d rr -O "THROUGHPUT, THROUGHPUT_UNITS, \
        MIN_LATENCY, MAX_LATENCY, MEAN_LATENCY"' % netperf_ip_2
        ret, out = self.dut.netns_cmd(cmd, 'ns1')
        result_o = "".join(out).split('\n')[-2].strip()
        result_on_latency = float(result_o.split()[-1])
        cmd = 'netperf -H %s -l 60' % netperf_ip_2
        ret, out = self.dut.netns_cmd(cmd, 'ns1')
        result_o = "".join(out).split('\n')[-2].strip()
        result_on_throughput = float(result_o.split()[-1])

        # Result compare
        default_off_latency = 0.65 * self.result_off_latency[0]
        default_off_throughput = 0.9 * self.result_off_throughput[1]
        if result_on_latency >= default_off_latency:
            raise NtiError("Latency is not reasonable,Failed to test coalesce !")
        if result_on_throughput < default_off_throughput:
            raise NtiError("Throughout is not reasonable,Failed to test coalesce !")
        if default_off_latency < self.result_off_latency[1]:
            raise NtiError("Latency is not reasonable,off_latency of 1/0 setting is big !")

    def cleanup(self):
        self.dut.netns_cmd('pkill netserver', 'ns1', fail=False)
        self.dut.netns_del('ns1', fail=False)
        self.dut.netns_del('ns2', fail=False)
        self.dut.cmd('echo 0 > /sys/bus/pci/devices/%s/sriov_numvfs' %
                     self.group.pci_dbdf)
