#
# Copyright (C) 2021,  Corigine, Inc.  All rights reserved.
#
"""
Netdev test for coalesce based on PF.
"""

from netro.testinfra.nti_exceptions import NtiError
from ..common_test import CommonTest, NtiSkip

class coalescePF(CommonTest):
    info = """
    Test the ethtool -c command on PF interfaces.

    The test requires either SRIOV or NIC firmware, it will be skipped
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
        @src:	     A tuple of System and interface name of srcoint
        @group:      Test group this test belongs to
        @name:       Name for this test instance
        @summary:    Optional one line summary for the test
        """
        CommonTest.__init__(self, src, dut, group, name, summary)
        self.throughput_off = []
        self.latency_off = []
        self.throughput_on = []
        self.latency_on = []

    def config_coalesce(self, ifc, src_on=False, status='off',
                        req_rx_usecs='50', req_rx_frames='64'):

        M = self.dut
        if src_on is True:
            M = self.src

        if status == 'off':
            M.ethtool_set_coalesce(ifc,
                                   {"adaptive-rx": 'off',
                                    "adaptive-tx": 'off'},
                                   {"rx-usecs": req_rx_usecs,
                                    "rx-frames": req_rx_frames})
        else:
            M.ethtool_set_coalesce(ifc,
                                   {"adaptive-rx": 'on',
                                    "adaptive-tx": 'on'},
                                   {})

    def check_coalesce(self, ifc, src_on=False, status='off', check='post',
                       req_rx_usecs='50', req_rx_frames='64'):
        M = self.dut
        if src_on is True:
            M = self.src
        c_settings = M.ethtool_get_coalesce(ifc)

        if status == 'off':
            cur_rx_usecs = c_settings['rx-usecs']
            cur_rx_frames = c_settings['rx-frames']
            if ((cur_rx_usecs != req_rx_usecs) |
               (cur_rx_frames != req_rx_frames)):

                if check == 'pre':
                    return False
                else:
                    raise NtiError("Failed to set coalesce:rx-usecs(s/d)=(%s:%s), \
                    rx-frames(s/d) = (%s/%s)" % (cur_rx_usecs, req_rx_usecs,
                                                 cur_rx_frames, req_rx_frames))
        else:
            adaptiverx = c_settings['Adaptive RX']
            adaptivetx = c_settings['Adaptive TX']
            if ((adaptiverx != 'on') | (adaptivetx != 'on')):
                if check == 'pre':
                    return False
                else:
                    raise NtiError("Failed to enable coalesce !")

        return True

    def execute(self):

        for ifc in self.dut.nfp_netdevs:
            info = self.dut.ethtool_drvinfo(ifc)

            ver_m = info['firmware-version']
            if "sri" not in ver_m and "nic" not in ver_m:
                raise NtiSkip("Change to SRIOV or NIC firmware")

        self.check_prereq("netserver -h 2>&1 | grep Usage:",
                          'netserver missing', on_src=False)
        self.check_prereq("netperf -h 2>&1 | grep Usage:", 'netperf missing')

        # set coalesce rx-usecs/rx-frames is 50/64 test throughput and latency
        self.src.cmd('netserver', fail=False)
        for i in range(len(self.src_ifn)):
            pre_check = self.check_coalesce(self.src_ifn[i], src_on=True,
                                            status='off', check='pre',
                                            req_rx_usecs='50',
                                            req_rx_frames='64')
            if(pre_check is False):
                self.config_coalesce(self.src_ifn[i], src_on=True,
                                     status='off',
                                     req_rx_usecs='50',
                                     req_rx_frames='64')
            self.check_coalesce(self.src_ifn[i], src_on=True, status='off',
                                req_rx_usecs='50', req_rx_frames='64')
        for i in range(len(self.dut_ifn)):
            self.config_coalesce(self.dut_ifn[i], status='off',
                                 req_rx_usecs='50', req_rx_frames='64')
            self.check_coalesce(self.dut_ifn[i], status='off',
                                req_rx_usecs='50', req_rx_frames='64')
            cmd = 'netperf -H %s -l 30 -t omni -- -d rr -O "THROUGHPUT"' % \
                self.src_addr[i][:-3]
            ret, out = self.dut.cmd(cmd)
            line = "".join(out).split('\n')[-2].strip()
            self.throughput_off.append(float(line.split()[-1]))
            cmd = 'netperf -H %s -l 30 -t omni -- -d rr -O "MEAN_LATENCY"' % \
                self.src_addr[i][:-3]
            ret, out = self.dut.cmd(cmd)
            line = "".join(out).split('\n')[-2].strip()
            self.latency_off.append(float(line.split()[-1]))

        # set coalesce rx-usecs/rx-frames is 0/1 test throughput and latency
        for i in range(len(self.src_ifn)):
            self.config_coalesce(self.src_ifn[i], src_on=True, status='off',
                                 req_rx_usecs='1', req_rx_frames='0')
            self.check_coalesce(self.src_ifn[i], src_on=True, status='off',
                                req_rx_usecs='1', req_rx_frames='0')
        for i in range(len(self.dut_ifn)):
            self.config_coalesce(self.dut_ifn[i], status='off',
                                 req_rx_usecs='1', req_rx_frames='0')
            self.check_coalesce(self.dut_ifn[i], status='off',
                                req_rx_usecs='1', req_rx_frames='0')
            cmd = 'netperf -H %s -l 30 -t omni -- -d rr -O "THROUGHPUT"' % \
                self.src_addr[i][:-3]
            ret, out = self.dut.cmd(cmd)
            line = "".join(out).split('\n')[-2].strip()
            self.throughput_off.append(float(line.split()[-1]))
            cmd = 'netperf -H %s -l 30 -t omni -- -d rr -O "MEAN_LATENCY"' % \
                self.src_addr[i][:-3]
            ret, out = self.dut.cmd(cmd)
            line = "".join(out).split('\n')[-2].strip()
            self.latency_off.append(float(line.split()[-1]))

        # set coalesce adaptive-rx/tx is on test throughput and latency
        for i in range(len(self.src_ifn)):
            self.config_coalesce(self.src_ifn[i], src_on=True, status='on')
            self.check_coalesce(self.src_ifn[i], src_on=True, status='on')
        for i in range(len(self.dut_ifn)):
            self.config_coalesce(self.dut_ifn[i], status='on')
            self.check_coalesce(self.dut_ifn[i], status='on')
            cmd = 'netperf -H %s -l 30 -t omni -- -d rr -O "THROUGHPUT"' % \
                self.src_addr[i][:-3]
            ret, out = self.dut.cmd(cmd)
            line = "".join(out).split('\n')[-2].strip()
            self.throughput_on.append(float(line.split()[-1]))
            cmd = 'netperf -H %s -l 30 -t omni -- -d rr -O "MEAN_LATENCY"' % \
                self.src_addr[i][:-3]
            ret, out = self.dut.cmd(cmd)
            line = "".join(out).split('\n')[-2].strip()
            self.latency_on.append(float(line.split()[-1]))

        for i in range(len(self.dut_ifn)):
            default_off_latency = 0.65 * self.latency_off[i]
            result_on_latency = self.latency_on[i]
            default_off_throughput = 0.9 * self.throughput_off[i]
            result_on_throughput = self.throughput_on[i]
            if default_off_latency <= result_on_latency:
                raise NtiError("Latency default: %f , Latency adaptive: %f" %
                               (default_off_latency,
                                result_on_latency))
            if result_on_throughput < default_off_throughput:
                raise NtiError("Throughput default: %f , Throughput adaptive: \
                               %f" % (default_off_throughput,
                                      result_on_throughput))
            if default_off_latency < self.latency_off[len(self.dut_ifn)+i]:
                raise NtiError("Latency default: %f , Latency 0/1: %f" %
                               (default_off_latency,
                                self.latency_off[len(self.dut_ifn)+i]))

    def cleanup(self):
        self.src.cmd('pkill netserver', fail=False)
        for i in range(len(self.src_ifn)):
            self.config_coalesce(self.src_ifn[i], src_on=True, status='off',
                                 req_rx_usecs='50', req_rx_frames='64')
            self.check_coalesce(self.src_ifn[i], src_on=True, status='off',
                                req_rx_usecs='50', req_rx_frames='64')
        for i in range(len(self.dut_ifn)):
            self.config_coalesce(self.dut_ifn[i], status='off',
                                 req_rx_usecs='50', req_rx_frames='64')
            self.check_coalesce(self.dut_ifn[i], status='off',
                                req_rx_usecs='50', req_rx_frames='64')
