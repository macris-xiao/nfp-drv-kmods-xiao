#
# Copyright (C) 2017,  Netronome Systems, Inc.  All rights reserved.
#
"""
BPF base test class
"""

import netro.testinfra
from netro.testinfra.test import *
from netro.testinfra.nrt_result import NrtResult
from netro.testinfra.nti_exceptions import NtiError
from common_test import *

class eBPFtest(CommonTest):
    """Test class for eBPF"""
    # Information applicable to all subclasses
    _gen_info = """
    simple eBPF test
    """

    def __init__(self, src, dut, obj_name="pass.o", tc_flags="skip_sw",
                 act="action drop", should_fail=False, group=None, name="",
                 summary=None):
        """
        @dut:        A tuple of System and interface name of DUT
        @src:	     A tuple of System and interface name of srcoint
        @obj_name    Name of the filter to load
        @tc_flags    TC BPF flags for installing the filter
        @group:      Test group this test belongs to
        @name:       Name for this test instance
        @summary:    Optional one line summary for the test
        """
        CommonTest.__init__(self, src, dut, group, name, summary)

        self.act = act

        if dut[0]:
            # src and dst maybe None if called without config file for list
            self.obj_name = obj_name
            self.tc_flags = tc_flags
            self.should_fail = should_fail
        return

    def validate_cntr(self, d, name, t0, t1):
        if not d[name] in range(t0, t1):
            raise NtiError("%s stat is wrong (%d, %d) -> %d" %
                           (name, t0, t1, d[name]))

    def validate_cntr_pair(self, d, name, t):
        self.validate_cntr(d, '%s_pkts' % name, t[0], t[1])
        self.validate_cntr(d, '%s_bytes' % name, t[2], t[3])

    def validate_cntr_e2e(self, diff, e_name, t_name):
        if diff.ethtool[e_name] != diff.ethtool[t_name]:
            raise NtiError("e2e %s != %s (%d, %d)" %
                           (e_name, t_name, diff.ethtool[e_name],
                            diff.ethtool[t_name]))

    def validate_cntr_e2e_pair(self, diff, e_name, t_name):
        self.validate_cntr_e2e(diff, '%s_pkts' % e_name, '%s_pkts' % t_name)
        self.validate_cntr_e2e(diff, '%s_bytes' % e_name, '%s_bytes' % t_name)

    def validate_cntr_e2t(self, diff, e_name, t_name):
        if diff.ethtool[e_name] != diff.tc_ing[t_name]:
            raise NtiError("e2t %s != %s (%d, %d)" %
                           (e_name, t_name, diff.ethtool[e_name],
                            diff.tc_ing[t_name]))

    def validate_cntr_e2t_pair(self, diff, e_name, t_name):
        self.validate_cntr_e2t(diff, '%s_pkts' % e_name, '%s_pkts' % t_name)
        self.validate_cntr_e2t(diff, '%s_bytes' % e_name, '%s_bytes' % t_name)

    def validate_cntrs(self, rx_t, pass_all=False,
                       app1_all=False, app2_all=False, app3_all=False,
                       mark_all=False, exact_filter=False):
        NO_PKTS=(0, 1, 0, 1)

        new_stats = self.dut.netifs[self.dut_ifn[0]].stats(get_tc_ing=True)
        diff = new_stats - self.stats
        self.stats = new_stats

        self.validate_cntr_pair(diff.ethtool, 'dev_rx', rx_t)

        # Exact filter means we want exactly lower bound dropped, the rest ignored
        if exact_filter:
            filter_t=(rx_t[0], rx_t[0] + 1, rx_t[2], rx_t[2] + 1)
            self.validate_cntr_pair(diff.ethtool, 'bpf_app1', filter_t)
            self.validate_cntr_pair(diff.tc_ing, 'tc_49151', filter_t)
            return

        if pass_all:
            self.validate_cntr_e2e_pair(diff, 'dev_rx', 'bpf_pass')
        else:
            self.validate_cntr_pair(diff.ethtool, 'bpf_pass', NO_PKTS)

        if app1_all:
            self.validate_cntr_e2e_pair(diff, 'dev_rx', 'bpf_app1')
        else:
            self.validate_cntr_pair(diff.ethtool, 'bpf_app1', NO_PKTS)

        if app2_all:
            self.validate_cntr_e2e_pair(diff, 'dev_rx', 'bpf_app2')
        else:
            self.validate_cntr_pair(diff.ethtool, 'bpf_app2', NO_PKTS)

        if app3_all:
            self.validate_cntr_e2e_pair(diff, 'dev_rx', 'bpf_app3')
        else:
            self.validate_cntr_pair(diff.ethtool, 'bpf_app3', NO_PKTS)

        if mark_all:
            self.validate_cntr_e2t_pair(diff, 'dev_rx', 'tc_49152')
        else:
            self.validate_cntr_pair(diff.tc_ing, 'tc_49152', NO_PKTS)

        # Check the TC actions stats
        if self.act:
            if app1_all:
                self.validate_cntr_e2t_pair(diff, 'dev_rx', 'tc_49151')
            else:
                self.validate_cntr_pair(diff.tc_ing, 'tc_49151', NO_PKTS)


    def prepare(self):
        """
        Prepare for running eBPF test
        """
        passed = True
        comment = ''

        self.dut.cmd('ethtool -K %s hw-tc-offload on' % (self.dut_ifn[0]))
        self.dut.cmd('tc qdisc add dev %s ingress' % (self.dut_ifn[0]))
        self.dut.cmd('tc filter add dev %s parent ffff:  handle 0xcafe fw action pass' % (self.dut_ifn[0]))

        ret = self.tc_bpf_load()

        if ret and not self.should_fail:
            self.cleanup()
            return NrtResult(name=self.name, testtype=self.__class__.__name__,
                             passed=False, comment="Unable to load filter")
        if not ret and self.should_fail:
            self.cleanup()
            return NrtResult(name=self.name, testtype=self.__class__.__name__,
                             passed=False, comment="Loading this filter should fail")

        self.stats = self.dut.netifs[self.dut_ifn[0]].stats(get_tc_ing=True)

        return None


    def cleanup(self):
        """
        Clean up after eBPF test
        """
        self.dut.cmd('tc qdisc del dev %s ingress' % self.dut_ifn[0])
