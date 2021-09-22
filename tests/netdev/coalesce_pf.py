#
# Copyright (C) 2021,  Corigine, Inc.  All rights reserved.
#
"""
Netdev test for coalesce based on PF.
"""

from netro.testinfra.nti_exceptions import NtiError
from ..common_test import CommonTest, NtiSkip

class coalescePF(CommonTest):

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

    def config_coalesce(self, ifc, src_on=False, status='off', rxusecs='50', rxframes='64'):

        if src_on == False:
            cmd = 'ethtool --coalesce %s '%(ifc)
            if status == 'off':
                cmd += 'adaptive-rx off adaptive-tx off rx-usecs %s \
                rx-frames %s' % (rxusecs, rxframes)
                self.dut.cmd(cmd)
            else:
                cmd += 'adaptive-rx on adaptive-tx on'
                self.dut.cmd(cmd)

        if src_on == True:
            cmd = 'ethtool --coalesce %s '% (ifc)
            if status == 'off':
                cmd += 'adaptive-rx off adaptive-tx off rx-usecs %s \
                rx-frames %s' % (rxusecs, rxframes)
                self.src.cmd(cmd)
            else:
                cmd += 'adaptive-rx on adaptive-tx on'
                self.src.cmd(cmd)

    def check_coalesce(self, ifc, src_on=False, status='off', rxusecs='50', rxframes='64'):

        cmd = ''
        cmd += 'ethtool --show-coalesce %s' % (ifc)
        if status == 'off':
            if src_on == False:
                ret, out = self.dut.cmd('ethtool --show-coalesce %s | grep rx-usecs:' % (ifc))
                rx_usecs = out.strip().split(' ')[-1]
                ret, out = self.dut.cmd('ethtool --show-coalesce %s | grep rx-frames:' % (ifc))
                rx_frames = out.strip().split(' ')[-1]
            else:
                ret, out = self.src.cmd('ethtool --show-coalesce %s | grep rx-usecs:' % (ifc))
                rx_usecs = out.strip().split(' ')[-1]
                ret, out = self.src.cmd('ethtool --show-coalesce %s | grep rx-frames:' % (ifc))
                rx_frames = out.strip().split(' ')[-1]
        else:
            if src_on == False:
                ret, out = self.dut.cmd('ethtool --show-coalesce %s | grep Adaptive' % (ifc))
                adaptive_rx = out.strip().split()[2]
                adaptive_tx = out.strip().split()[-1]
            else:
                ret, out = self.src.cmd('ethtool --show-coalesce %s | grep Adaptive' % (ifc))
                adaptive_rx = out.strip().split()[2]
                adaptive_tx = out.strip().split()[-1]

        if status == 'off':
            if ((rx_usecs != rxusecs) | (rx_frames != rxframes)):
                raise NtiError("Failed to set coalesce:rx-usecs(s/d)=(%s:%s), \
                rx-frames(s/d) = (%s/%s)" % (rx_usecs, rxusecs, rx_frames, rxframes))
        else:
            if ((adaptive_rx != 'on')|(adaptive_tx != 'on')):
                raise NtiError("Failed to enable coalesce !")

    def check_prereq(self, check, description, on_src=False):
        if on_src:
            res, _ = self.src.cmd(check, fail=False)
        else:
            res, _ = self.dut.cmd(check, fail=False)

        if res == 1:
            if on_src:
                raise NtiSkip('SRC does not support feature:%s' % description)
            else:
                raise NtiSkip('DUT does not support feature:%s' % description)

    def execute(self):

        self.check_prereq("netserver -h 2>&1 | grep Usage:",
                          'netserver missing', on_src=False)
        self.check_prereq("netperf -h 2>&1 | grep Usage:", 'netperf missing')

        # set coalesce rx-usecs/rx-frames is 50/64 test throughput and latency
        self.src.cmd('netserver', fail=False)
        for i in range(len(self.src_ifn)):
            self.config_coalesce(self.src_ifn[i], src_on=True, status='off', rxusecs='50', rxframes='64')
            self.check_coalesce(self.src_ifn[i], src_on=True, status='off', rxusecs='50', rxframes='64')
        for i in range(len(self.dut_ifn)):
            self.config_coalesce(self.dut_ifn[i], status='off', rxusecs='50', rxframes='64')
            self.check_coalesce(self.dut_ifn[i], status='off', rxusecs='50', rxframes='64')
            ret, out = self.dut.cmd('netperf -H %s -l 60' % self.src_addr[i][:-3])
            line = "".join(out).split('\n')[-2].strip()
            self.throughput_off.append(float(line.split()[-1]))
            cmd = 'netperf -H %s -l 60  -t omni -- -d rr -O "THROUGHPUT, THROUGHPUT_UNITS, \
            MIN_LATENCY, MAX_LATENCY, MEAN_LATENCY"' % self.src_addr[i][:-3]
            ret, out = self.dut.cmd(cmd)
            line = "".join(out).split('\n')[-2].strip()
            self.latency_off.append(float(line.split()[-1]))

        # set coalesce rx-usecs/rx-frames is 0/1 test throughput and latency
        for i in range(len(self.src_ifn)):
            self.config_coalesce(self.src_ifn[i], src_on=True, status='off', rxusecs='1', rxframes='0')
            self.check_coalesce(self.src_ifn[i], src_on=True, status='off', rxusecs='1', rxframes='0')
        for i in range(len(self.dut_ifn)):
            self.config_coalesce(self.dut_ifn[i], status='off', rxusecs='1', rxframes='0')
            self.check_coalesce(self.dut_ifn[i], status='off', rxusecs='1', rxframes='0')
            ret, out = self.dut.cmd('netperf -H %s -l 60' % self.src_addr[i][:-3])
            line = "".join(out).split('\n')[-2].strip()
            self.throughput_off.append(float(line.split()[-1]))
            cmd = 'netperf -H %s -l 60  -t omni -- -d rr -O "THROUGHPUT, THROUGHPUT_UNITS, \
            MIN_LATENCY, MAX_LATENCY, MEAN_LATENCY"'% self.src_addr[i][:-3]
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
            ret, out = self.dut.cmd('netperf -H %s -l 60' % self.src_addr[i][:-3])
            line = "".join(out).split('\n')[-2].strip()
            self.throughput_on.append(float(line.split()[-1]))
            cmd = 'netperf -H %s -l 60  -t omni -- -d rr -O "THROUGHPUT, THROUGHPUT_UNITS, \
            MIN_LATENCY, MAX_LATENCY, MEAN_LATENCY"' % self.src_addr[i][:-3]
            ret, out = self.dut.cmd(cmd)
            line = "".join(out).split('\n')[-2].strip()
            self.latency_on.append(float(line.split()[-1]))

        for i in range(len(self.dut_ifn)):
            default_off_latency = 0.5 * self.latency_off[i]
            result_on_latency = self.latency_on[i]
            default_off_throughput = 0.9 * self.throughput_off[i]
            result_on_throughput = self.throughput_on[i]
            if default_off_latency <= result_on_latency:
                raise NtiError("Latency is not reasonable,Failed to test coalesce !")
            if result_on_throughput < default_off_throughput:
                raise NtiError("Throughout is not reasonable,Failed to test coalesce !")
            if default_off_latency < self.latency_off[len(self.dut_ifn)+i]:
                raise NtiError("Latency is not reasonable,latency of 1/0 setting is big !")

    def cleanup(self):
        self.src.cmd('pkill netserver', fail=False)
        for i in range(len(self.src_ifn)):
            self.config_coalesce(self.src_ifn[i], src_on=True, status='off', rxusecs='50', rxframes='64')
            self.check_coalesce(self.src_ifn[i], src_on=True, status='off', rxusecs='50', rxframes='64')
        for i in range(len(self.dut_ifn)):
            self.config_coalesce(self.dut_ifn[i], status='off', rxusecs='50', rxframes='64')
            self.check_coalesce(self.dut_ifn[i], status='off', rxusecs='50', rxframes='64')
