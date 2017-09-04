#
# Copyright (C) 2017,  Netronome Systems, Inc.  All rights reserved.
#
"""
Flower test group for the NFP Linux drivers.
"""

from netro.testinfra.nti_exceptions import NtiError
from scapy.all import Raw, Ether, wrpcap
from ..common_test import CommonNetdevTest
from ..drv_grp import NFPKmodGrp
import os

#pylint cannot find TCP, IP, IPv6, Dot1Q in scapy for some reason
#pylint: disable=no-name-in-module
from scapy.all import TCP, IP, IPv6, Dot1Q

###########################################################################
# Flower Unit Tests
###########################################################################

class NFPKmodFlower(NFPKmodGrp):
    """Flower tests for the NFP Linux drivers"""

    summary = "Basic flower tests of NFP Linux driver."

    def __init__(self, name, cfg=None, quick=False, dut_object=None,
                 dut=None, nfp=None, nfpkmods=None, mefw=None):
        #pylint: disable=unused-argument
        NFPKmodGrp.__init__(self, name=name, cfg=cfg, quick=quick,
                            dut_object=dut_object)

    def populate_tests(self):
        dut = (self.dut, self.addr_x, self.eth_x, self.addr_v6_x)
        src = (self.host_a, self.addr_a, self.eth_a, self.addr_v6_a)

        T = (('flower_match_mac', FlowerMatchMAC, "Checks basic flower mac match capabilities"),
             ('flower_match_vlan', FlowerMatchVLAN, "Checks basic flower vlan match capabilities"),
             ('flower_match_ipv4', FlowerMatchIPv4, "Checks basic flower ipv4 match capabilities"),
             ('flower_match_ipv6', FlowerMatchIPv6, "Checks basic flower ipv6 match capabilities"),
        )

        for t in T:
            self._tests[t[0]] = t[1](src, dut, self, t[0], t[2])

class FlowerBase(CommonNetdevTest):
    def configure_flower(self):
        M = self.dut
        iface = self.dut_ifn[0]
        ret, _ = self.dut.cmd('cat /sys/class/net/%s/phys_port_name' % (iface), fail=False)
        if ret:
            raise NtiError('interface %s is not a valid port' % iface)

        M.cmd('tc qdisc del dev %s handle ffff: ingress' % iface, fail=False)
        M.cmd('tc qdisc add dev %s handle ffff: ingress' % iface)

        ingress = self.src_ifn[0]
        M.refresh()
        return iface, ingress

    def install_filter(self, iface, match, action):
        M = self.dut
        M.cmd('tc filter add dev %s parent ffff: protocol %s action %s' % (iface, match, action))

        _, ret_str = M.cmd('tc filter show dev %s parent ffff: | grep not_in_hw' % iface, fail=False)
        if 'not_in_hw' in ret_str:
            raise NtiError('match: %s; action: %s. Not installed in hardware.' % (match, action))

    def cleanup_filter(self, iface):
        M = self.dut
        M.cmd('tc filter del dev %s parent ffff:' % iface)

    def test_filter(self, interface, ingress, pkt, send_cnt, exp_cnt):
        M = self.dut
        A = self.src
        pcap_local = os.path.join(self.group.tmpdir, 'pcap')
        pcap_src = os.path.join('/tmp/', 'pcap')

        #Here we could consider using sendp(pkt, iface=ingress, count=send_cnt) instead
        wrpcap(pcap_local, pkt)
        self.src.mv_to(pcap_local, pcap_src)
        A.cmd("tcpreplay --intf1=%s --pps=100 --loop=%s -K %s " % (ingress, send_cnt, pcap_src))

        exp_bytes = (len(pkt) + len(Ether()))*exp_cnt
        stats = M.netifs[interface].stats(get_tc_ing=True)
        if int(stats.tc_ing['tc_49152_pkts']) != exp_cnt:
            raise NtiError('Counter missmatch. Expected: %s, Got: %s' % (exp_cnt, stats.tc_ing['tc_49152_pkt']))
        if int(stats.tc_ing['tc_49152_bytes']) != exp_bytes:
            raise NtiError('Counter missmatch. Expected: %s, Got: %s' % (exp_bytes, stats.tc_ing['tc_49152_bytes']))

class FlowerMatchMAC(FlowerBase):
    def netdev_execute(self):
        iface, ingress = self.configure_flower()

        # Hit test
        match = 'ip flower dst_mac 02:12:23:34:45:56'
        action = 'mirred egress redirect dev %s' % iface
        self.install_filter(iface, match, action)

        pkt_cnt = 100
        exp_pkt_cnt = 100
        pkt = Ether(src="02:01:01:02:02:01",dst="02:12:23:34:45:56")/IP()/TCP()/Raw('\x00'*64)
        self.test_filter(iface, ingress, pkt, pkt_cnt, exp_pkt_cnt)

        self.cleanup_filter(iface)

        # Miss test
        match = 'ip flower dst_mac 02:42:42:42:42:42'
        action = 'mirred egress redirect dev %s' % iface
        self.install_filter(iface, match, action)

        pkt_cnt = 100
        exp_pkt_cnt = 0
        pkt = Ether(src="02:01:01:02:02:01",dst="02:12:23:34:45:56")/IP()/TCP()/Raw('\x00'*64)
        self.test_filter(iface, ingress, pkt, pkt_cnt, exp_pkt_cnt)

        self.cleanup_filter(iface)

class FlowerMatchVLAN(FlowerBase):
    def netdev_execute(self):
        iface, ingress = self.configure_flower()

        # Hit test
        match = '802.1Q flower vlan_id 600'
        action = 'mirred egress redirect dev %s' % iface
        self.install_filter(iface, match, action)

        pkt_cnt = 100
        exp_pkt_cnt = 100
        pkt = Ether(src="02:01:01:02:02:01",dst="02:12:23:34:45:56")/Dot1Q(vlan=600)/IP()/TCP()/Raw('\x00'*64)
        self.test_filter(iface, ingress, pkt, pkt_cnt, exp_pkt_cnt)

        self.cleanup_filter(iface)

        # Miss test
        match = '802.1Q flower vlan_id 1200'
        action = 'mirred egress redirect dev %s' % iface
        self.install_filter(iface, match, action)

        pkt_cnt = 100
        exp_pkt_cnt = 0
        pkt = Ether(src="02:01:01:02:02:01",dst="02:12:23:34:45:56")/Dot1Q(vlan=600)/IP()/TCP()/Raw('\x00'*64)
        self.test_filter(iface, ingress, pkt, pkt_cnt, exp_pkt_cnt)

        self.cleanup_filter(iface)

class FlowerMatchIPv4(FlowerBase):
    def netdev_execute(self):
        iface, ingress = self.configure_flower()

        # Hit test
        match = 'ip flower dst_ip 11.0.0.11'
        action = 'mirred egress redirect dev %s' % iface
        self.install_filter(iface, match, action)

        pkt_cnt = 100
        exp_pkt_cnt = 100
        pkt = Ether(src="02:01:01:02:02:01",dst="02:12:23:34:45:56")/IP(src='10.0.0.10', dst='11.0.0.11')/TCP()/Raw('\x00'*64)
        self.test_filter(iface, ingress, pkt, pkt_cnt, exp_pkt_cnt)

        self.cleanup_filter(iface)

        # Miss test
        match = 'ip flower dst_ip 22.0.0.22'
        action = 'mirred egress redirect dev %s' % iface
        self.install_filter(iface, match, action)

        pkt_cnt = 100
        exp_pkt_cnt = 0
        pkt = Ether(src="02:01:01:02:02:01",dst="02:12:23:34:45:56")/IP(src='10.0.0.10', dst='11.0.0.11')/TCP()/Raw('\x00'*64)
        self.test_filter(iface, ingress, pkt, pkt_cnt, exp_pkt_cnt)

        self.cleanup_filter(iface)

class FlowerMatchIPv6(FlowerBase):
    def netdev_execute(self):
        iface, ingress = self.configure_flower()

        # Hit test
        match = 'ipv6 flower dst_ip 11::11'
        action = 'mirred egress redirect dev %s' % iface
        self.install_filter(iface, match, action)

        pkt_cnt = 100
        exp_pkt_cnt = 100
        pkt = Ether(src="02:01:01:02:02:01",dst="02:12:23:34:45:56")/IPv6(src='10::10', dst='11::11')/TCP()/Raw('\x00'*64)
        self.test_filter(iface, ingress, pkt, pkt_cnt, exp_pkt_cnt)

        self.cleanup_filter(iface)

        # Miss test
        match = 'ipv6 flower dst_ip 22::22'
        action = 'mirred egress redirect dev %s' % iface
        self.install_filter(iface, match, action)

        pkt_cnt = 100
        exp_pkt_cnt = 0
        pkt = Ether(src="02:01:01:02:02:01",dst="02:12:23:34:45:56")/IPv6(src='10::10', dst='11::11')/TCP()/Raw('\x00'*64)
        self.test_filter(iface, ingress, pkt, pkt_cnt, exp_pkt_cnt)

        self.cleanup_filter(iface)
