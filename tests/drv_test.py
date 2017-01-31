#
# Copyright (C) 2016-2017,  Netronome Systems, Inc.  All rights reserved.
#
"""
Base for all driver tests.
"""

import netro.testinfra
from netro.testinfra.test import *
from common_test import *


class DrvTest(CommonTest):
    """Base class for all driver tests"""
    # Information applicable to all subclasses
    _gen_info = """
    Linux Driver Test
    """

    def log(self, text, thing):
        LOG_sec(text)
        LOG(thing.pp())
        LOG_endsec()


    def log_stat_diff(self, diff):
        self.log("Interface stats difference", diff)


    def ifup(self):
        ret, _ = self.dut.cmd('ip link set up dev %s' % self.dut_ifn,
                              fail=self.fail_policy)
        if ret == 0:
            self.ifstate = True


    def ifdown(self):
        self.dut.cmd('ip link set down dev %s' % self.dut_ifn,
                     fail=self.fail_policy)
        self.ifstate = False


    def set_ring_config(self, config):
        # Setting the same thing again will cause an error,
        # make sure we don't do that
        if self.ring_curr == config:
            return 0, ""
        ret, out = self.dut.cmd('ethtool -L %s rx %d tx %d combined %d' %
                                (self.dut_ifn, config[0], config[1], config[2]),
                                fail=False)
        if ret == 0:
            self.ring_curr = config
        return ret, out


    def refresh_ring_config(self):
        _, out = self.dut.cmd('ethtool -l %s' % (self.dut_ifn))
        params = out.split()
        self.curr['ring_max_rx'] = int(params[7])
        self.curr['ring_max_tx'] = int(params[9])
        self.curr['ring_max_comb'] = int(params[13])
        self.curr['ring_rx'] = int(params[18])
        self.curr['ring_tx'] = int(params[20])
        self.curr['ring_comb'] = int(params[24])


    def set_desc_config(self, config):
        # Setting the same thing again will cause an error,
        # make sure we don't do that
        if self.desc_curr == config:
            return 0, ""
        ret, out = self.dut.cmd('ethtool -G %s rx %d tx %d' %
                                (self.dut_ifn, config[0], config[1]), fail=False)
        if ret == 0:
            self.desc_curr = config
        return ret, out


    def refresh_desc_config(self):
        _, out = self.dut.cmd('ethtool -g %s' % (self.dut_ifn))
        params = out.split()
        self.curr['rxd_max'] = int(params[7])
        self.curr['txd_max'] = int(params[15])
        self.curr['rxd'] = int(params[20])
        self.curr['txd'] = int(params[28])


    def set_xdp_prog(self, name=None):
        if not name:
            name = "stop"
        _, out = self.dut.cmd('~/xdp/%s.py %s' % (name, self.dut_ifn),
                              fail=False, include_stderr=True)
        # XDP load is sort of broken in bcc and always returns 1, we have to look
        # at the output instead of just looking at the ret code
        if out[1].count("KeyError"):
            self.xdp_loaded = name != "stop"


    def check_ring_config(self):
        if not self.ifstate:
            return

        self.refresh_ring_config()

        t = self.ring_curr
        c = (self.curr['ring_rx'], self.curr['ring_tx'], self.curr['ring_comb'])

        # Check reported numbers
        if t != c:
            raise NtiGeneralError("Set values don't match what was read %d %d %d %d %d %d" %
                                  (c[0], t[0], c[1], t[1], c[2], t[2]))

        # Check the stack queues
        _, out = self.dut.cmd('ls -v /sys/class/net/%s/queues/' % (self.dut_ifn))
        expected_list = ["rx-%d" % x for x in range(0, t[0] + t[2])] + \
                        ["tx-%d" % x for x in range(0, t[1] + t[2])]
        if out.split() != expected_list:
            raise NtiGeneralError("Stack queues don't match expected %s vs %s" %
                               (out.split(), expected_list))

        # Check indirection table (should get updated at this point)
        _, out = self.dut.cmd('ethtool -x %s | sed -n "s/^[^:]*:\\([^:]*\\)$/\\1/p"' %
                              (self.dut_ifn))
        indir_tb = map(int, out.split())
        if max(indir_tb) != t[0] + t[2] - 1:
            raise NtiGeneralError("Indirection table entry bad max:%d expected:%d" %
                               (max(indir_tb), t[0] + t[2]))
        if min(indir_tb) != 0:
            raise NtiGeneralError("Indirection table entries don't contain 0")

        self.check_desc_config()


    def check_desc_config(self):
        if not self.ifstate:
            return

        # Check if DebugFS descriptor numbers are OK
        _, out = self.dut.cmd('cat /sys/kernel/debug/nfp_net/%s/port0/queue/rx/* | wc -l' %
                              (self.dut_if.bus))
        want = (self.ring_curr[0] + self.ring_curr[2]) * (self.desc_curr[0] + 1)
        if int(out) != want:
            raise NtiGeneralError("DebugFS wrong desc cnt:%s expect:%d" % (out, want))

        _, out = self.dut.cmd('cat /sys/kernel/debug/nfp_net/%s/port0/queue/tx/* | wc -l' %
                              (self.dut_if.bus))
        want = (self.ring_curr[1] + self.ring_curr[2]) * (self.desc_curr[1] + 1)
        if int(out) != want:
            raise NtiGeneralError("DebugFS wrong desc cnt:%s expect:%d" % (out, want))

        _, out = self.dut.cmd('cat /sys/kernel/debug/nfp_net/%s/port0/queue/xdp/* | wc -l' %
                              (self.dut_if.bus))
        want = (self.ring_curr[0] + self.ring_curr[2]) * (self.desc_curr[1] + 1) * self.xdp_loaded
        if int(out) != want:
            raise NtiGeneralError("DebugFS wrong desc cnt:%s expect:%d" % (out, want))


    def prepare(self):
        self.ifstate = True
        self.xdp_loaded = False
        self.curr = {}
        self.refresh_desc_config()
        self.refresh_ring_config()
        self.orig = self.curr.copy()
        # Init current config
        self.ring_curr = (self.orig['ring_rx'], self.orig['ring_tx'], self.orig['ring_comb'])
        self.desc_curr = (self.orig['rxd'], self.orig['txd'])
        # Get PCI bus name
        _, out = self.dut.cmd('basename $(readlink /sys/class/net/%s/device)' %
                              (self.dut_ifn))
        self.dut_if.bus = out.strip()
        # Get real max tx queues
        _, out = self.dut.cmd('dmesg | grep TxQs | tail -1')
        self.total_tx_rings = int(re.search('TxQs=[0-9]*/([0-9]*)', out).groups()[0])
        # Check if XDP is available
        ret, _ = self.dut.cmd('ls ~/xdp/pass.py /lib/modules/`uname -r`/build', fail=False)
        self.has_xdp = ret == 0


    def cleanup(self):
        if self.xdp_loaded:
            self.set_xdp_prog()
        self.set_desc_config((self.orig['rxd'], self.orig['txd']))
        self.set_ring_config((self.orig['ring_rx'], self.orig['ring_tx'], self.orig['ring_comb']))
