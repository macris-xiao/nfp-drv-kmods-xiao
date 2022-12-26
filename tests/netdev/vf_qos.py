#
# Copyright (C) 2022,  Corigine, Inc.  All rights reserved.
#
from netro.testinfra.nti_exceptions import NtiError
from ..common_test import CommonTest, NtiSkip
from time import sleep


class VfQoS(CommonTest):
    info = """
            Tests the vf qos feature by setting the max rate
            and reading the netperf output. A check is done
            to see if the rate (throughput/max_rate) is within
            10 percent of the max_rate.
           """

    def config_rate_limit(self, iface, max_rate, vf_num, min_rate=0, fail=True):
        """
        Sets the max_rate and min_rate.
        """
        cmd = 'ip link set %s vf %s max_tx_rate %s min_tx_rate %s' \
               % (iface, vf_num, max_rate, min_rate)
        out = self.dut.cmd(cmd, fail=fail)

        return out

    def get_rate(self, max_rate, netperf_ip_1):
        """
        Reads the output from netperf.
        The throughput is extracted and returned as a rate,
        calculated as: (throughput/max_rate).
        """
        ret, out = self.dut.netns_cmd('netperf -t TCP_STREAM -H %s -l 60'
                                      % netperf_ip_1, 'ns2')

        rate_line = out.split('\n')[6]
        self.log('output', rate_line)
        rate = float((rate_line.split())[4])/max_rate

        return rate

    def rate_check(self, max_rate, rate):
        """
        Checks if the rate (throughput/max_rate) is within 10% of
        the max_rate.
        """
        if rate > 1.10:
            raise NtiError("The rate for max_rate %s, equals more than 10%% \
                            the expected rate: %.2f" % (max_rate, rate))
        elif rate < 0.90:
            raise NtiError("The rate for max_rate %s, equals less than 10%% \
                            the expected rate: %.2f" % (max_rate, rate))

    def execute(self):
        for ifc in self.dut.nfp_netdevs:
            info = self.dut.ethtool_drvinfo(ifc)

            ver_m = info['firmware-version']
            if "sri" not in ver_m:
                raise NtiSkip("Change to SRIOV firmware")

        self.check_prereq("netserver -h 2>&1 | grep Usage:",
                          'netserver missing', on_src=False)
        self.check_prereq("netperf -h 2>&1 | grep Usage:", 'netperf missing')

        # System set up
        netperf_ip_1 = '20.0.0.10'
        netperf_ip_2 = '20.0.0.20'

        vfs = self.spawn_vf_netdev(2)
        vf1 = vfs[0]["name"]
        vf2 = vfs[1]["name"]

        vf1_num = vfs[0]["vf_number"]
        vf2_num = vfs[1]["vf_number"]

        iface = self.dut_ifn[0]

        self.dut.ip_link_set_up(iface, fail=False)

        # Create namespaces
        self.dut.netns_add('ns1')
        self.dut.netns_add_iface('ns1', vf1)
        self.dut.netns_add('ns2')
        self.dut.netns_add_iface('ns2', vf2)

        # Prepare namespace for netperf
        cmd = "ip addr add %s/24 dev %s" % (netperf_ip_1, vf1)
        self.dut.netns_cmd(cmd, 'ns1')
        cmd = "ip link set dev %s up" % vf1
        self.dut.netns_cmd(cmd, 'ns1')
        cmd = 'ip addr add %s/24 dev %s' % (netperf_ip_2, vf2)
        self.dut.netns_cmd(cmd, 'ns2')
        cmd = 'ip link set dev %s up' % vf2
        self.dut.netns_cmd(cmd, 'ns2')

        # Wait for VFs to up
        sleep(2)

        # Start server on vf
        self.dut.cmd('ip netns exec ns1 netserver')
        sleep(1)

        # Testing with a max rate of 1000
        max_rate = 1000
        self.config_rate_limit(iface, max_rate, vf2_num)
        rate = self.get_rate(max_rate, netperf_ip_1)
        self.rate_check(max_rate, rate)

        # Testing with a max rate of 10000
        max_rate = 10000
        self.config_rate_limit(iface, max_rate, vf2_num)
        rate = self.get_rate(max_rate, netperf_ip_1)
        self.rate_check(max_rate, rate)

        # Testing with a max rate higher than 63000
        # 63Gbps is the maximum value max_rate can be set to.
        max_rate = 70000
        out = self.config_rate_limit(iface, max_rate, vf2_num, fail=False)
        if(out[0] == 0):
            raise NtiError('Expected to fail setting the \
            max rate to a value higher than 63Gbps but got a pass.')

        # Testing with a min rate higher than 0
        # 0Gbps is the only value min_rate can be set to.
        max_rate = 10000
        min_rate = 1000
        out = self.config_rate_limit(iface, vf2_num, max_rate, min_rate, fail=False)
        if(out[0] == 0):
            raise NtiError('Expected to fail setting the \
                            minimum rate but got a pass.')

    def cleanup(self):
        self.dut.netns_cmd('pkill netserver', 'ns1', fail=False)
        self.dut.netns_del('ns1', fail=False)
        self.dut.netns_del('ns2', fail=False)
        self.dut.cmd('echo 0 > /sys/bus/pci/devices/%s/sriov_numvfs' %
                     self.group.pci_dbdf)
