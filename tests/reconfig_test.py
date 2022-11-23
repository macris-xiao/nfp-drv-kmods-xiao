#
# Copyright (C) 2016-2017,  Netronome Systems, Inc.  All rights reserved.
#
"""
Base for all driver tests.
"""

import netro.testinfra
from netro.testinfra.test import *
from common_test import *

class ReconfigTest(CommonNetdevTest):
    """Base class for all driver tests"""
    # Information applicable to all subclasses
    _gen_info = """
    Linux Driver Test
    """

    def __init__(self, src, dst, group=None, name="", summary=None):
        """
        @src:        A tuple of System and interface name from which to send
        @dst:        A tuple of System and interface name which should receive
        @group:      Test group this test belongs to
        @name:       Name for this test instance
        @summary:    Optional one line summary for the test
        """
        CommonNetdevTest.__init__(self, src, dst, group, name, summary)

        self.fail_policy = group.fail_policy()

    def netdev_wait(self):
        # Wait for netdev to appear
        ret = 1
        while ret != 0:
            ret, _ = self.dut.cmd('ls /sys/class/net/%s' % (self.dut_ifn[0]),
                                  fail=False)

    def reload_mod(self):
        self.dut.reset_mods()
        self.dut.insmod(netdev=True, userspace=True)
        self.dut.insmod(module="nth")

        self.netdev_wait()

        self.state_init()
        self.state_refresh()

    def ifup(self):
        ret, _ = self.dut.ip_link_set_up(self.dut_ifn[0],
                              fail=self.fail_policy)
        if ret == 0:
            self.ifstate = True
            ret, _ = self.dut.cmd('ip addr replace %s dev %s' %
                                  (self.dut_addr[0], self.dut_ifn[0]))

    def ifdown(self):
        self.dut.ip_link_set_down(self.dut_ifn[0],
                     fail=self.fail_policy)
        self.ifstate = False

    def set_ring_config(self, config):
        # Setting the same thing again will cause an error,
        # make sure we don't do that
        if self.ring_curr == config:
            return 0, ""
        ret, out = self.dut.cmd('ethtool -L %s rx %d tx %d combined %d' %
                                (self.dut_ifn[0],
                                 config[0], config[1], config[2]), fail=False)
        if ret == 0:
            self.ring_curr = config
        return ret, out

    def refresh_ring_config(self):
        _, out = self.dut.cmd('ethtool -l %s' % (self.dut_ifn[0]))
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
                                (self.dut_ifn[0], config[0], config[1]),
                                fail=False)
        if ret == 0:
            self.desc_curr = (config[0], config[1] * \
                              self.tx_desc_per_simple_pkt)
        return ret, out

    def refresh_desc_config(self):
        _, out = self.dut.cmd('ethtool -g %s' % (self.dut_ifn[0]))
        params = out.split()
        self.curr['rxd_max'] = int(params[7])
        self.curr['txd_max'] = int(params[15])
        self.curr['rxd'] = int(params[20])
        self.curr['txd'] = int(params[28])

    def mtu_should_fail(self, mtu, xdp_loaded):
        return (mtu not in range(68, 9217)) or \
            (xdp_loaded and (mtu not in range(68, 3950))) or \
            (xdp_loaded and (self.total_tx_rings <
                             self.curr['ring_rx'] +
                             self.curr['ring_tx'] +
                             self.curr['ring_comb'] * 2))

    def mtu_may_fail(self, mtu, xdp_loaded):
        ''' In driver, rings are reconfigured when loading xdp on xdpdrv mode which causes
        check of freelist buffer size(dp->fl_bufsz < PAGE_SIZE). "fl_bufsz" is calculated
        in "nfp_net_calc_fl_bufsz".
        fl_bufsz = SKB_DATA_ALIGN(NFP_NET_RX_BUF_HEADROOM + dp->rx_dma_off +
                                  NFP_NET_MAX_PREPEND/dp->rx_offset +
                                  ETH_HLEN + VLAN_HLEN * 2 + dp->mtu) +
                   SKB_DATA_ALIGN(sizeof(struct skb_shared_info))
        '''
        return self.mtu_should_fail(mtu, xdp_loaded) or \
            (xdp_loaded and (mtu not in range(68, 3371)))

    def set_xdp_prog(self, name=None):
        should_fail = False
        may_fail = False
        force = ""
        if name and name != "stop":
            what = 'obj %s sec ".text"' % os.path.join(self.group.samples_xdp, \
                                                      '%s.o' % name)
            should_fail = self.mtu_should_fail(self.mtu, True)
            may_fail = self.mtu_may_fail(self.mtu, True)
            if self.xdp_loaded:
                force = "-force"
        else:
            what = 'off'
        self.log("XDP set", "should:%d may:%d  mtu:%d total:%d rx:%d tx:%d" %
                 (should_fail, may_fail, self.mtu, self.total_tx_rings,
                  self.curr['ring_comb'] + self.curr['ring_rx'],
                  self.curr['ring_comb'] + self.curr['ring_tx']))
        ret, _ = self.dut.cmd('ip %s link set dev %s xdp %s' %
                              (force, self.dut_ifn[0], what),
                              fail=(self.fail_policy and not may_fail))
        if ret == 0:
            if should_fail:
                raise NtiError("XDP set did not fail when it should have")
            self.xdp_loaded = what != "off"

    def check_ring_config(self):
        self.refresh_ring_config()

        if not self.ifstate:
            return

        t = self.ring_curr
        c = (self.curr['ring_rx'], self.curr['ring_tx'], self.curr['ring_comb'])

        # Check reported numbers
        if t != c:
            raise NtiGeneralError("Set values don't match what was read " +
                                  "%d %d %d %d %d %d" %
                                  (c[0], t[0], c[1], t[1], c[2], t[2]))

        # Check the stack queues
        _, out = self.dut.cmd('ls -v /sys/class/net/%s/queues/' %
                              (self.dut_ifn[0]))
        expected_list = ["rx-%d" % x for x in range(0, t[0] + t[2])] + \
                        ["tx-%d" % x for x in range(0, t[1] + t[2])]
        if out.split() != expected_list:
            raise NtiGeneralError("Stack queues don't match expected %s vs %s" %
                               (out.split(), expected_list))

        # Check indirection table (should get updated at this point)
        _, out = self.dut.cmd('ethtool -x %s | sed -n "s/^[^:]*:\\([ 0-9]*\\)$/\\1/p"' %
                              (self.dut_ifn[0]))
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
        out = self.dut.dfs_nn_port_lines('cat', 'queue/rx/*')
        want = (self.ring_curr[0] + self.ring_curr[2]) * (self.desc_curr[0] + 1)
        if int(out) != want:
            raise NtiGeneralError("DebugFS wrong desc cnt:%s expect:%d" %
                                  (out, want))

        out = self.dut.dfs_nn_port_lines('cat', 'queue/tx/*')
        want = (self.ring_curr[1] + self.ring_curr[2]) * (self.desc_curr[1] + 1)
        if int(out) != want:
            raise NtiGeneralError("DebugFS wrong desc cnt:%s expect:%d" %
                                  (out, want))

        out = self.dut.dfs_nn_port_lines('cat', 'queue/xdp/*')
        want = (self.ring_curr[0] + self.ring_curr[2]) * \
               (self.desc_curr[1] + 1) * self.xdp_loaded
        if int(out) != want:
            raise NtiGeneralError("DebugFS wrong desc cnt:%s expect:%d" %
                                  (out, want))

    def set_mtu(self, mtu):
        # We don't really know the exact buffer size calculation here
        # unfortunately because prepend may vary
        should_fail = self.mtu_should_fail(mtu, self.xdp_loaded)
        may_fail = self.mtu_may_fail(mtu, self.xdp_loaded)

        ret, _ = self.dut.cmd('ip link set mtu %d dev %s' %
                              (mtu, self.dut_ifn[0]),
                              fail=(self.fail_policy and not may_fail))
        if ret == 0:
            if should_fail:
                raise NtiGeneralError("Setting MTU %d should have failed" % mtu)
            self.mtu = mtu

    def state_init(self):
        self.mtu = 1500
        self.ifstate = False
        self.xdp_loaded = False
        self.curr = {}

    def state_refresh(self):
        self.refresh_desc_config()
        self.refresh_ring_config()
        self.orig = self.curr.copy()
        # Init current config
        self.ring_curr = (self.orig['ring_rx'], self.orig['ring_tx'],
                          self.orig['ring_comb'])
        self.desc_curr = (self.orig['rxd'], self.orig['txd'] * \
                          self.tx_desc_per_simple_pkt)

    def state_dump(self):
        LOG_sec('Exit dump')
        LOG("Original settings:\n")
        LOG(str(self.orig).replace(",", "\n"))
        LOG("\n")
        LOG("Current settings:\n")
        LOG(str(self.curr).replace(",", "\n"))
        LOG("\n")
        LOG("MTU: %d\n" % self.mtu)
        LOG("ifstate: %d\n" % self.ifstate)
        LOG("xdp: %d\n" % self.xdp_loaded)
        LOG_endsec()

    def prepare(self):
        self.state_init()

        # Check if XDP is available
        ret, _ = self.dut.cmd('ls %s' % (os.path.join(self.group.samples_xdp, 'pass.o')),
                              fail=False)
        self.has_xdp = ret == 0

    def netdev_execute(self):
        if len(self.vnics) != len(self.nfp_netdevs):
            raise NtiSkip("Can't deal with representors")

        self.netdev_wait()

        drvinfo = self.dut.ethtool_drvinfo(self.dut_ifn[0])
        if drvinfo["firmware-version"][0] == "1":
            self.tx_desc_per_simple_pkt = 2
        else:
            self.tx_desc_per_simple_pkt = 1

        # Get real max tx queues
        if (len(self.dut_ifn) == 2):
            _, out = self.dut.cmd('dmesg | grep %s | grep TxQs | tail -2 | head -1' %
                                  self.group.pci_id)
        elif (len(self.dut_ifn) == 1):
            _, out = self.dut.cmd('dmesg | grep %s | grep TxQs | tail -1' %
                                  self.group.pci_id)
        else:
            raise NtiSkip("Breakout mode unsupported")
        self.total_tx_rings = int(re.search('TxQs=\d*/(\d*)', out).groups()[0])

        self.ifup()
        self.state_refresh()

        self.reconfig_execute()

    def cleanup(self):
        if hasattr(self, "orig"):
            self.state_dump()
        CommonNetdevTest.cleanup(self)
