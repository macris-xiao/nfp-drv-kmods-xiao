#
# Copyright (C) 2017,  Netronome Systems, Inc.  All rights reserved.
#
"""
Flower test group for the NFP Linux drivers.
"""

from netro.testinfra.nti_exceptions import NtiError
from netro.testinfra.system import cmd_log
from ..common_test import CommonNetdevTest
from ..drv_grp import NFPKmodGrp
from time import sleep
import os

#pylint cannot find TCP, UDP, IP, IPv6, Dot1Q in scapy for some reason
#pylint: disable=no-name-in-module
from scapy.all import Raw, Ether, rdpcap, wrpcap, TCP, UDP, IP, IPv6, Dot1Q
#You need latest scapy to import from contrib
from scapy.contrib.mpls import MPLS

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
             ('flower_match_tcp', FlowerMatchTCP, "Checks basic flower tcp match capabilities"),
             ('flower_match_udp', FlowerMatchUDP, "Checks basic flower udp match capabilities"),
             ('flower_match_mpls', FlowerMatchMPLS, "Checks basic flower mpls match capabilities"),
             ('flower_match_ttl', FlowerMatchTTL, "Checks basic flower ttl match capabilities"),
             ('flower_match_tos', FlowerMatchTOS, "Checks basic flower tos match capabilities"),
             ('flower_match_vxlan', FlowerMatchVXLAN, "Checks basic flower vxlan match capabilities"),
             ('flower_match_whitelist', FlowerMatchWhitelist, "Checks basic flower match whitelisting"),
             ('flower_vxlan_whitelist', FlowerVxlanWhitelist, "Checks that unsupported vxlan rules are not offloaded"),
             ('flower_action_encap_vxlan', FlowerActionVXLAN, "Checks basic flower vxlan encapsulation action capabilities"),
             ('flower_action_set_ether', FlowerActionSetEth, "Checks basic flower set ethernet action capabilities"),
             ('flower_action_set_ipv4', FlowerActionSetIPv4, "Checks basic flower set IPv4 action capabilities"),
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

    def install_filter(self, iface, match, action, in_hw=True):
        M = self.dut
        M.cmd('tc filter add dev %s parent ffff: protocol %s action %s' % (iface, match, action))

        _, ret_str = M.cmd('tc filter show dev %s parent ffff: | grep not_in_hw' % iface, fail=False)
        if 'not_in_hw' in ret_str:
            if in_hw:
                raise NtiError('match: %s; action: %s. Not installed in hardware.' % (match, action))
        else:
            if not in_hw:
                raise NtiError('match: %s; action: %s. Installed in hardware.' % (match, action))

    def cleanup_filter(self, iface):
        M = self.dut
        M.cmd('tc filter del dev %s parent ffff:' % iface)

    def test_filter(self, interface, ingress, pkt, send_cnt, exp_cnt, pkt_len_diff=0):
        M = self.dut
        A = self.src
        pcap_local = os.path.join(self.group.tmpdir, 'pcap')
        pcap_src = os.path.join('/tmp/', 'pcap')

        #Here we could consider using sendp(pkt, iface=ingress, count=send_cnt) instead
        wrpcap(pcap_local, pkt)
        cmd_log('scp -q %s %s:%s' % (pcap_local, A.rem, pcap_src))
        A.cmd("tcpreplay --intf1=%s --pps=100 --loop=%s -K %s " % (ingress, send_cnt, pcap_src))

        exp_bytes = (len(pkt) + len(Ether()))*exp_cnt
        lo_exp_cnt = exp_cnt - 10
        lo_exp_exp_bytes = (len(pkt) + len(Ether()))*(exp_cnt - 10)
        stats = M.netifs[interface].stats(get_tc_ing=True)
        if int(stats.tc_ing['tc_49152_pkts']) < lo_exp_cnt or int(stats.tc_ing['tc_49152_pkts']) > exp_cnt:
            raise NtiError('Counter missmatch. Expected: %s, Got: %s' % (exp_cnt, stats.tc_ing['tc_49152_pkts']))
        if int(stats.tc_ing['tc_49152_bytes']) < lo_exp_exp_bytes or int(stats.tc_ing['tc_49152_bytes']) > exp_bytes:
            raise NtiError('Counter missmatch. Expected: %s, Got: %s' % (exp_bytes, stats.tc_ing['tc_49152_bytes']))

    def test_packet(self, ingress, send_pkt, exp_pkt, dump_filter=''):
        M = self.dut
        A = self.src
        dump_local = os.path.join('/tmp/', 'pcap-dump-%s' % (self.name))
        self.capture_packs(ingress, send_pkt, dump_local, dump_filter)
        test_pkt = rdpcap(dump_local)
        A.cmd("rm %s" % dump_local)
        if str(exp_pkt) != str(test_pkt[0]):
            print "Expected:"
            exp_pkt.show()
            print "Got:"
            test_pkt[0].show()
            raise NtiError('Packet missmatch')

    def capture_packs(self, ingress, send_pkt, pack_dump, dump_filter=''):
        M = self.dut
        A = self.src
        pcap_local = os.path.join(self.group.tmpdir, 'pcap_%s_input' %(self.name))
        pcap_src = os.path.join('/tmp/', 'pcap_%s_src' %(self.name))

        # Grab packets on egress interface - Assume packets are being mirrored
        # Start TCPdump - Would want to use built-in NTI class here,
        # but it does not provide us with al the required features
        A.cmd("tcpdump -U -i %s -w %s -Q in %s " % (ingress, pack_dump, dump_filter), background=True)

        wrpcap(pcap_local, send_pkt)
        cmd_log('scp -q %s %s:%s' % (pcap_local, A.rem, pcap_src))
        sleep(1)
        A.cmd("tcpreplay --intf1=%s --pps=100 --loop=100 -K %s " % (ingress, pcap_src))
        sleep(1)

        A.cmd("killall -KILL tcpdump")
        A.cmd("rm %s" % pcap_src)

    def pcap_check_bytes(self, exp_cnt, cap_packs, pkt, pkt_len_diff=0):
        if len(cap_packs) != exp_cnt:
            raise NtiError('Pcap count missmatch. Expected: %s, Got: %s' % (exp_cnt, len(cap_packs)))
        exp_bytes = (len(pkt) + len(Ether()) + pkt_len_diff)*exp_cnt
        total_bytes = 0
        for p in cap_packs:
            total_bytes += len(p) + len(Ether())
        if total_bytes != exp_bytes:
            raise NtiError('Pcap byte missmatch. Expected: %s, Got: %s' % (exp_bytes, total_bytes))

    def pcap_cmp_pkt_bytes(self, pack_cap, exp_field, offset):
        # offset is in bytes but packet treated as hex string so double offset
        offset *= 2
        for p in pack_cap:
            if str(p).encode("hex")[offset:offset+len(exp_field)] != exp_field:
                raise NtiError('Bad byte match for %s at offset %s  - %s' % (exp_field, offset, str(p).encode("hex")[offset:offset+len(exp_field)]))

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

class FlowerMatchTCP(FlowerBase):
    def netdev_execute(self):
        iface, ingress = self.configure_flower()

        # Hit test
        match = 'ip flower ip_proto tcp dst_port 2000'
        action = 'mirred egress redirect dev %s' % iface
        self.install_filter(iface, match, action)

        pkt_cnt = 100
        exp_pkt_cnt = 100
        pkt = Ether(src="02:01:01:02:02:01",dst="02:12:23:34:45:56")/IP(src='10.0.0.10', dst='11.0.0.11')/TCP(dport=2000)/Raw('\x00'*64)
        self.test_filter(iface, ingress, pkt, pkt_cnt, exp_pkt_cnt)

        self.cleanup_filter(iface)

        # Miss test - miss on port number
        match = 'ip flower ip_proto tcp dst_port 4000'
        action = 'mirred egress redirect dev %s' % iface
        self.install_filter(iface, match, action)

        pkt_cnt = 100
        exp_pkt_cnt = 0
        pkt = Ether(src="02:01:01:02:02:01",dst="02:12:23:34:45:56")/IP(src='10.0.0.10', dst='11.0.0.11')/TCP(dport=2000)/Raw('\x00'*64)
        self.test_filter(iface, ingress, pkt, pkt_cnt, exp_pkt_cnt)

        self.cleanup_filter(iface)

        # Miss test - miss on prototype
        match = 'ip flower ip_proto tcp dst_port 2000'
        action = 'mirred egress redirect dev %s' % iface
        self.install_filter(iface, match, action)

        pkt_cnt = 100
        exp_pkt_cnt = 0
        pkt = Ether(src="02:01:01:02:02:01",dst="02:12:23:34:45:56")/IP(src='10.0.0.10', dst='11.0.0.11')/UDP(dport=2000)/Raw('\x00'*64)
        self.test_filter(iface, ingress, pkt, pkt_cnt, exp_pkt_cnt)

        self.cleanup_filter(iface)

class FlowerMatchUDP(FlowerBase):
    def netdev_execute(self):
        iface, ingress = self.configure_flower()

        # Hit test
        match = 'ip flower ip_proto udp dst_port 4000'
        action = 'mirred egress redirect dev %s' % iface
        self.install_filter(iface, match, action)

        pkt_cnt = 100
        exp_pkt_cnt = 100
        pkt = Ether(src="02:01:01:02:02:01",dst="02:12:23:34:45:56")/IP(src='10.0.0.10', dst='11.0.0.11')/UDP(dport=4000)/Raw('\x00'*64)
        self.test_filter(iface, ingress, pkt, pkt_cnt, exp_pkt_cnt)

        self.cleanup_filter(iface)

        # Miss test - miss on port number
        match = 'ip flower ip_proto udp dst_port 2000'
        action = 'mirred egress redirect dev %s' % iface
        self.install_filter(iface, match, action)

        pkt_cnt = 100
        exp_pkt_cnt = 0
        pkt = Ether(src="02:01:01:02:02:01",dst="02:12:23:34:45:56")/IP(src='10.0.0.10', dst='11.0.0.11')/UDP(dport=4000)/Raw('\x00'*64)
        self.test_filter(iface, ingress, pkt, pkt_cnt, exp_pkt_cnt)

        self.cleanup_filter(iface)

        # Miss test - miss on prototype
        match = 'ip flower ip_proto udp dst_port 4000'
        action = 'mirred egress redirect dev %s' % iface
        self.install_filter(iface, match, action)

        pkt_cnt = 100
        exp_pkt_cnt = 0
        pkt = Ether(src="02:01:01:02:02:01",dst="02:12:23:34:45:56")/IP(src='10.0.0.10', dst='11.0.0.11')/TCP(dport=4000)/Raw('\x00'*64)
        self.test_filter(iface, ingress, pkt, pkt_cnt, exp_pkt_cnt)

        self.cleanup_filter(iface)

class FlowerMatchVXLAN(FlowerBase):
    def netdev_execute(self):
        iface, ingress = self.configure_flower()
        M = self.dut
        A = self.src

        src_ip = self.src_addr[0].split('/')[0]
        dut_ip = self.dut_addr[0].split('/')[0]

        _, src_mac = A.cmd('cat /sys/class/net/%s/address | tr -d "\n"' % self.src_ifn[0])
        _, dut_mac = M.cmd('cat /sys/class/net/%s/address | tr -d "\n"' % self.dut_ifn[0])

        # Hit test - match all vxlan fields and decap
        match = 'ip flower enc_src_ip %s enc_dst_ip %s enc_dst_port 4789 enc_key_id 123' % (src_ip, dut_ip)
        action = 'mirred egress redirect dev %s' % iface
        self.install_filter(iface, match, action)
        pkt_cnt = 100
        exp_pkt_cnt = 100

        # VXLAN header with VNI 123
        vxlan_header = '\x08\x00\x00\x00\x00\x00\x7b\x00'
        enc_pkt = Ether(src="aa:bb:cc:dd:ee:ff",dst="01:02:03:04:05:06")/IP()/TCP()/Raw('\x00'*64)
        vxlan_header += str(enc_pkt)
        pkt = Ether(src=src_mac,dst=dut_mac)/IP(src=src_ip, dst=dut_ip)/UDP(sport=44534, dport=4789)/vxlan_header
        pkt_diff = len(Ether()) + len(IP()) + len(UDP()) + 8
        self.test_filter(iface, ingress, pkt, pkt_cnt, exp_pkt_cnt, -pkt_diff)

        self.cleanup_filter(iface)

        # Miss test - incorrect enc ip src
        match = 'ip flower enc_src_ip 1.1.1.1 enc_dst_ip %s enc_dst_port 4789 enc_key_id 123' % (dut_ip)
        action = 'mirred egress redirect dev %s' % iface
        self.install_filter(iface, match, action)

        pkt_cnt = 100
        exp_pkt_cnt = 0

        self.test_filter(iface, ingress, pkt, pkt_cnt, exp_pkt_cnt)

        self.cleanup_filter(iface)

        # Miss test - incorrect enc ip dst
        match = 'ip flower enc_src_ip %s enc_dst_ip 1.1.1.1 enc_dst_port 4789 enc_key_id 123' % (src_ip)
        action = 'mirred egress redirect dev %s' % iface
        self.install_filter(iface, match, action)

        pkt_cnt = 100
        exp_pkt_cnt = 0

        self.test_filter(iface, ingress, pkt, pkt_cnt, exp_pkt_cnt)

        self.cleanup_filter(iface)

        # Miss test - incorrect VNI
        match = 'ip flower enc_src_ip %s enc_dst_ip %s enc_dst_port 4789 enc_key_id 124' % (src_ip, dut_ip)
        action = 'mirred egress redirect dev %s' % iface
        self.install_filter(iface, match, action)

        pkt_cnt = 100
        exp_pkt_cnt = 0

        self.test_filter(iface, ingress, pkt, pkt_cnt, exp_pkt_cnt)

        self.cleanup_filter(iface)

class FlowerMatchMPLS(FlowerBase):
    def netdev_execute(self):
        iface, ingress = self.configure_flower()

        # Hit test
        match = 'mpls flower mpls_label 1111'
        action = 'mirred egress redirect dev %s' % iface
        self.install_filter(iface, match, action)

        pkt_cnt = 100
        exp_pkt_cnt = 100
        pkt = Ether(src="02:01:01:02:02:01",dst="02:12:23:34:45:56")/MPLS(label=1111)/Raw('\x00'*64)
        self.test_filter(iface, ingress, pkt, pkt_cnt, exp_pkt_cnt)

        self.cleanup_filter(iface)

        # Miss test
        match = 'mpls flower mpls_label 2222'
        action = 'mirred egress redirect dev %s' % iface
        self.install_filter(iface, match, action)

        pkt_cnt = 100
        exp_pkt_cnt = 0
        pkt = Ether(src="02:01:01:02:02:01",dst="02:12:23:34:45:56")/MPLS(label=1111)/Raw('\x00'*64)
        self.test_filter(iface, ingress, pkt, pkt_cnt, exp_pkt_cnt)

        self.cleanup_filter(iface)

class FlowerMatchTTL(FlowerBase):
    def netdev_execute(self):
        iface, ingress = self.configure_flower()

        # Hit test - IPv4
        match = 'ip flower ip_ttl 30'
        action = 'mirred egress redirect dev %s' % iface
        self.install_filter(iface, match, action)

        pkt_cnt = 100
        exp_pkt_cnt = 100
        pkt = Ether(src="02:01:01:02:02:01",dst="02:12:23:34:45:56")/IP(src='10.0.0.10', dst='11.0.0.11', ttl=30)/TCP()/Raw('\x00'*64)
        self.test_filter(iface, ingress, pkt, pkt_cnt, exp_pkt_cnt)

        self.cleanup_filter(iface)

        # Miss test -IP IPv4
        match = 'ip flower ip_ttl 20'
        action = 'mirred egress redirect dev %s' % iface
        self.install_filter(iface, match, action)

        pkt_cnt = 100
        exp_pkt_cnt = 0
        pkt = Ether(src="02:01:01:02:02:01",dst="02:12:23:34:45:56")/IP(src='10.0.0.10', dst='11.0.0.11', ttl=30)/TCP()/Raw('\x00'*64)
        self.test_filter(iface, ingress, pkt, pkt_cnt, exp_pkt_cnt)

        self.cleanup_filter(iface)

        # Hit test - IPv6
        match = 'ipv6 flower ip_ttl 15'
        action = 'mirred egress redirect dev %s' % iface
        self.install_filter(iface, match, action)

        pkt_cnt = 100
        exp_pkt_cnt = 100
        pkt = Ether(src="02:01:01:02:02:01",dst="02:12:23:34:45:56")/IPv6(src='10::10', dst='11::11', hlim=15)/TCP()/Raw('\x00'*64)
        self.test_filter(iface, ingress, pkt, pkt_cnt, exp_pkt_cnt)

        self.cleanup_filter(iface)

        # Miss test -IP IPv6
        match = 'ipv6 flower ip_ttl 5'
        action = 'mirred egress redirect dev %s' % iface
        self.install_filter(iface, match, action)

        pkt_cnt = 100
        exp_pkt_cnt = 0
        pkt = Ether(src="02:01:01:02:02:01",dst="02:12:23:34:45:56")/IPv6(src='10::10', dst='11::11',hlim=20)/TCP()/Raw('\x00'*64)
        self.test_filter(iface, ingress, pkt, pkt_cnt, exp_pkt_cnt)

        self.cleanup_filter(iface)

class FlowerMatchTOS(FlowerBase):
    def netdev_execute(self):
        iface, ingress = self.configure_flower()

        # Hit test - IPv4
        match = 'ip flower ip_tos 10'
        action = 'mirred egress redirect dev %s' % iface
        self.install_filter(iface, match, action)

        pkt_cnt = 100
        exp_pkt_cnt = 100
        pkt = Ether(src="02:01:01:02:02:01",dst="02:12:23:34:45:56")/IP(src='10.0.0.10', dst='11.0.0.11', tos=10)/TCP()/Raw('\x00'*64)
        self.test_filter(iface, ingress, pkt, pkt_cnt, exp_pkt_cnt)

        self.cleanup_filter(iface)

        # Miss test -IPv4
        match = 'ip flower ip_tos 15'
        action = 'mirred egress redirect dev %s' % iface
        self.install_filter(iface, match, action)

        pkt_cnt = 100
        exp_pkt_cnt = 0
        pkt = Ether(src="02:01:01:02:02:01",dst="02:12:23:34:45:56")/IP(src='10.0.0.10', dst='11.0.0.11', tos=30)/TCP()/Raw('\x00'*64)
        self.test_filter(iface, ingress, pkt, pkt_cnt, exp_pkt_cnt)

        self.cleanup_filter(iface)

        # Hit test - IPv6
        match = 'ipv6 flower ip_tos 30'
        action = 'mirred egress redirect dev %s' % iface
        self.install_filter(iface, match, action)

        pkt_cnt = 100
        exp_pkt_cnt = 100
        pkt = Ether(src="02:01:01:02:02:01",dst="02:12:23:34:45:56")/IPv6(src='10::10', dst='11::11', tc=30)/TCP()/Raw('\x00'*64)
        self.test_filter(iface, ingress, pkt, pkt_cnt, exp_pkt_cnt)

        self.cleanup_filter(iface)

        # Miss test -IP IPv6
        match = 'ipv6 flower ip_tos 20'
        action = 'mirred egress redirect dev %s' % iface
        self.install_filter(iface, match, action)

        pkt_cnt = 100
        exp_pkt_cnt = 0
        pkt = Ether(src="02:01:01:02:02:01",dst="02:12:23:34:45:56")/IPv6(src='10::10', dst='11::11', tc=10)/TCP()/Raw('\x00'*64)
        self.test_filter(iface, ingress, pkt, pkt_cnt, exp_pkt_cnt)

        self.cleanup_filter(iface)

class FlowerMatchWhitelist(FlowerBase):
    def netdev_execute(self):
        iface, _ = self.configure_flower()

        # Check that ARP tip match is installed in software only (not_in_hw)
        match = 'arp flower arp_tip 40.42.44.46'
        action = 'mirred egress redirect dev %s' % iface
        self.install_filter(iface, match, action, False)
        self.cleanup_filter(iface)

        # Check that ARP sip match is installed in software only (not_in_hw)
        match = 'arp flower arp_sip 40.42.44.46'
        action = 'mirred egress redirect dev %s' % iface
        self.install_filter(iface, match, action, False)
        self.cleanup_filter(iface)

        # Check that ARP op match is installed in software only (not_in_hw)
        match = 'arp flower arp_op reply'
        action = 'mirred egress redirect dev %s' % iface
        self.install_filter(iface, match, action, False)
        self.cleanup_filter(iface)

        # Check that ARP tha match is installed in software only (not_in_hw)
        match = 'arp flower arp_tha 02:01:21:12:22:11'
        action = 'mirred egress redirect dev %s' % iface
        self.install_filter(iface, match, action, False)
        self.cleanup_filter(iface)

        # Check that ARP sha match is installed in software only (not_in_hw)
        match = 'arp flower arp_sha 02:11:22:21:12:01'
        action = 'mirred egress redirect dev %s' % iface
        self.install_filter(iface, match, action, False)
        self.cleanup_filter(iface)

        # Check that Entunnel src ip match is installed in software only (not_in_hw)
        match = 'ip flower enc_src_ip 10.10.10.10'
        action = 'mirred egress redirect dev %s' % iface
        self.install_filter(iface, match, action, False)
        self.cleanup_filter(iface)

        # Check that Entunnel dst ip match is installed in software only (not_in_hw)
        match = 'ip flower enc_dst_ip 20.20.20.20'
        action = 'mirred egress redirect dev %s' % iface
        self.install_filter(iface, match, action, False)
        self.cleanup_filter(iface)

        # Check that Entunnel key id match is installed in software only (not_in_hw)
        match = 'ip flower enc_key_id 100'
        action = 'mirred egress redirect dev %s' % iface
        self.install_filter(iface, match, action, False)
        self.cleanup_filter(iface)

        # Check that icmp type match is installed in software only (not_in_hw)
        match = 'ip flower ip_proto icmp type 2'
        action = 'mirred egress redirect dev %s' % iface
        self.install_filter(iface, match, action, False)
        self.cleanup_filter(iface)

        # Check that icmp code match is installed in software only (not_in_hw)
        match = 'ip flower ip_proto icmp code 1'
        action = 'mirred egress redirect dev %s' % iface
        self.install_filter(iface, match, action, False)
        self.cleanup_filter(iface)

        # Check that tcp_flags match is installed in software only (not_in_hw)
        match = 'ip flower ip_proto tcp tcp_flags 2'
        action = 'mirred egress redirect dev %s' % iface
        self.install_filter(iface, match, action, False)
        self.cleanup_filter(iface)

class FlowerVxlanWhitelist(FlowerBase):
    def netdev_execute(self):
        iface, _ = self.configure_flower()
        M = self.dut

        # Check that vxlan without a specified destination IP is installed in software only (not_in_hw)
        match = 'ip flower enc_src_ip 10.0.0.2 enc_dst_port 5789'
        action = 'mirred egress redirect dev %s' % iface
        self.install_filter(iface, match, action, False)
        self.cleanup_filter(iface)

        # Check that vxlan with masked destination IP is installed in software only (not_in_hw)
        match = 'ip flower enc_src_ip 10.0.0.2 enc_dst_ip 10.0.0.1/24 enc_dst_port 4789'
        action = 'mirred egress redirect dev %s' % iface
        self.install_filter(iface, match, action, False)
        self.cleanup_filter(iface)

        # Check that vxlan without a specified destination port is installed in software only (not_in_hw)
        match = 'ip flower enc_src_ip 10.0.0.2 enc_dst_ip 10.0.0.1'
        action = 'mirred egress redirect dev %s' % iface
        self.install_filter(iface, match, action, False)
        self.cleanup_filter(iface)

        # Check that vxlan with destination port != 4789 is installed in software only (not_in_hw)
        match = 'ip flower enc_src_ip 10.0.0.2 enc_dst_ip 10.0.0.1 enc_dst_port 5789'
        action = 'mirred egress redirect dev %s' % iface
        self.install_filter(iface, match, action, False)
        self.cleanup_filter(iface)

        # Check that multiple vxlan tunnel output is installed in software only (not_in_hw)
        M.cmd('ip link add vxlan0 type vxlan id 123 dev %s dstport 4789' % self.dut_ifn[0])
        M.cmd('ip link add vxlan1 type vxlan id 125 dev %s dstport 4789' % self.dut_ifn[0])
        M.cmd('ifconfig vxlan0 up')
        M.cmd('ifconfig vxlan1 up')
        match = 'ip flower ip_proto tcp'
        action = 'tunnel_key set id 123 src_ip 10.0.0.1 dst_ip 10.0.0.2 dst_port 4789 action mirred egress mirror dev vxlan0 action mirred egress redirect dev vxlan1'
        self.install_filter(iface, match, action, False)
        self.cleanup_filter(iface)
        M.cmd('ip link delete vxlan0')
        M.cmd('ip link delete vxlan1')

class FlowerActionVXLAN(FlowerBase):
    def netdev_execute(self):
        iface, ingress = self.configure_flower()
        M = self.dut
        A = self.src

        src_ip = self.src_addr[0].split('/')[0]
        dut_ip = self.dut_addr[0].split('/')[0]

        _, src_mac = A.cmd('cat /sys/class/net/%s/address | tr -d "\n"' % self.src_ifn[0])
        _, dut_mac = M.cmd('cat /sys/class/net/%s/address | tr -d "\n"' % self.dut_ifn[0])

        ret,_ = M.cmd('ip link add vxlan0 type vxlan id 123 dev %s dstport 4789' % self.dut_ifn[0])
        if ret:
            raise NtiError('failed to add vxlan netdev on %s.' % self.dut_ifn[0])

        ret,_ = M.cmd('ifconfig vxlan0 up')
        if ret:
            raise NtiError('failed to up vxlan netdev on %s.' % self.dut_ifn[0])

        ret,_ = M.cmd('arp -i %s -s %s %s' % (self.dut_ifn[0], src_ip, src_mac))
        if ret:
            raise NtiError('failed to insert arp entry on  %s.' % self.dut_ifn[0])

        # Hit test - match all tcp packets and encap in vxlan
        match = 'ip flower skip_sw ip_proto tcp'
        action = 'tunnel_key set id 123 src_ip %s dst_ip %s dst_port 4789 action mirred egress redirect dev vxlan0' % (dut_ip, src_ip)
        self.install_filter(iface, match, action)

        pkt_cnt = 100
        exp_pkt_cnt = 99

        pkt = Ether(src="02:01:01:02:02:01",dst="02:12:23:34:45:56")/IP()/TCP()/Raw('\x00'*64)

        dump_file = os.path.join('/tmp/', 'dump.pcap')
        self.capture_packs(ingress, pkt, dump_file)
        pack_cap = rdpcap(dump_file)
        A.cmd("rm %s" % dump_file)
        pkt_diff = len(Ether()) + len(IP()) + len(UDP()) + 8
        self.pcap_check_bytes(exp_pkt_cnt, pack_cap, pkt, pkt_diff)

        exp_pkt = Ether(src=dut_mac,dst=src_mac)/IP(src=dut_ip, dst=src_ip)/UDP(sport=0, dport=4789)

        # create matchable strings from the expected packet (non tested fields may differ)
        vxlan_header = '0800000000007b00'
        mac_header = str(exp_pkt).encode("hex")[0:len(Ether())*2]
        ip_addresses = str(exp_pkt).encode("hex")[(len(Ether()) + 12)*2: (len(Ether()) + len(IP()))*2]
        ip_proto = str(exp_pkt).encode("hex")[(len(Ether()) + 9)*2: (len(Ether()) + 10)*2]
        dest_port = str(exp_pkt).encode("hex")[(len(Ether()) + len(IP()) + 2)*2: (len(Ether()) + len(IP()) + 4)*2]

        # check VXLAN header
        self.pcap_cmp_pkt_bytes(pack_cap, vxlan_header, len(Ether()) + len(IP()) + len(UDP()))
        # check tunnel ethernet header
        self.pcap_cmp_pkt_bytes(pack_cap, mac_header, 0)
        # check tunnel IP addresses
        self.pcap_cmp_pkt_bytes(pack_cap, ip_addresses, len(Ether()) + 12)
        # check tunnel IP proto
        self.pcap_cmp_pkt_bytes(pack_cap, ip_proto, len(Ether()) + 9)
        # check tunnel destination UDP port
        self.pcap_cmp_pkt_bytes(pack_cap, dest_port, len(Ether()) + len(IP()) + 2)
        # check encapsulated packet
        self.pcap_cmp_pkt_bytes(pack_cap, str(pkt).encode("hex"), len(Ether()) + len(IP()) + len(UDP()) + 8)

        self.cleanup_filter(iface)

        ret,_ = M.cmd('ip link delete vxlan0')

class FlowerActionSetEth(FlowerBase):
    def netdev_execute(self):
        iface, ingress = self.configure_flower()

        # Test Output Action
        match = 'ip flower'
        action = 'mirred egress redirect dev %s' % iface
        self.install_filter(iface, match, action)

        pkt = Ether(src="02:01:01:02:02:01",dst="02:12:23:34:45:56")/IP(src='10.0.0.10', dst='11.0.0.11')/TCP()/Raw('\x00'*64)
        exp_pkt = Ether(src="02:01:01:02:02:01",dst="02:12:23:34:45:56")/IP(src='10.0.0.10', dst='11.0.0.11')/TCP()/Raw('\x00'*64)
        self.test_packet(ingress, pkt, exp_pkt)

        self.cleanup_filter(iface)

        # Test Set SRC and DST Ethernet
        match = 'ip flower'
        action = 'pedit ex munge eth src set 14:24:34:44:45:46 munge eth dst set 11:22:33:44:55:66 pipe mirred egress redirect dev %s' % iface
        self.install_filter(iface, match, action)

        dump_fil='ip'
        pkt = Ether(src="02:01:01:02:02:01",dst="02:12:23:34:45:56")/IP(src='10.0.0.10', dst='11.0.0.11')/TCP()/Raw('\x00'*64)
        exp_pkt = Ether(src="14:24:34:44:45:46",dst="11:22:33:44:55:66")/IP(src='10.0.0.10', dst='11.0.0.11')/TCP()/Raw('\x00'*64)
        self.test_packet(ingress, pkt, exp_pkt, dump_fil)

        self.cleanup_filter(iface)

        # Test Set DST Ethernet
        match = 'ip flower'
        action = 'pedit ex munge eth dst set 14:24:34:44:45:46 pipe mirred egress redirect dev %s' % iface
        self.install_filter(iface, match, action)

        dump_fil='ip'
        pkt = Ether(src="02:01:01:02:02:01",dst="02:12:23:34:45:56")/IP(src='10.0.0.10', dst='11.0.0.11')/TCP()/Raw('\x00'*64)
        exp_pkt = Ether(src="02:01:01:02:02:01",dst="14:24:34:44:45:46")/IP(src='10.0.0.10', dst='11.0.0.11')/TCP()/Raw('\x00'*64)
        self.test_packet(ingress, pkt, exp_pkt, dump_fil)

        self.cleanup_filter(iface)

        # Test Set SRC Ethernet
        match = 'ip flower'
        action = 'pedit ex munge eth src set 11:22:33:44:55:66 pipe mirred egress redirect dev %s' % iface
        self.install_filter(iface, match, action)

        dump_fil='ip'
        pkt = Ether(src="02:01:01:02:02:01",dst="02:12:23:34:45:56")/IP(src='10.0.0.10', dst='11.0.0.11')/TCP()/Raw('\x00'*64)
        exp_pkt = Ether(src="11:22:33:44:55:66",dst="02:12:23:34:45:56")/IP(src='10.0.0.10', dst='11.0.0.11')/TCP()/Raw('\x00'*64)
        self.test_packet(ingress, pkt, exp_pkt, dump_fil)

        self.cleanup_filter(iface)

class FlowerActionSetIPv4(FlowerBase):
    def netdev_execute(self):
        iface, ingress = self.configure_flower()

        # Test Output Action
        match = 'ip flower'
        action = 'mirred egress redirect dev %s' % iface
        self.install_filter(iface, match, action)

        pkt = Ether(src="02:01:01:02:02:01",dst="02:12:23:34:45:56")/IP(src='10.0.0.10', dst='11.0.0.11')/TCP()/Raw('\x00'*64)
        exp_pkt = Ether(src="02:01:01:02:02:01",dst="02:12:23:34:45:56")/IP(src='10.0.0.10', dst='11.0.0.11')/TCP()/Raw('\x00'*64)
        self.test_packet(ingress, pkt, exp_pkt)

        self.cleanup_filter(iface)

        # Test Set SRC and DST IPv4
        match = 'ip flower'
        action = 'pedit ex munge ip src set 20.30.40.50 munge ip dst set 120.130.140.150 pipe mirred egress redirect dev %s' % iface
        self.install_filter(iface, match, action)

        dump_fil='ip'
        pkt = Ether(src="02:01:01:02:02:01",dst="02:12:23:34:45:56")/IP(src='10.0.0.10', dst='11.0.0.11')/TCP()/Raw('\x00'*64)
        exp_pkt = Ether(src="02:01:01:02:02:01",dst="02:12:23:34:45:56")/IP(src='20.30.40.50', dst='120.130.140.150')/TCP()/Raw('\x00'*64)
        self.test_packet(ingress, pkt, exp_pkt, dump_fil)

        self.cleanup_filter(iface)

        # Test Set DST IPv4
        match = 'ip flower'
        action = 'pedit ex munge ip dst set 22.33.44.55 pipe mirred egress redirect dev %s' % iface
        self.install_filter(iface, match, action)

        dump_fil='ip'
        pkt = Ether(src="02:01:01:02:02:01",dst="02:12:23:34:45:56")/IP(src='10.0.0.10', dst='11.0.0.11')/TCP()/Raw('\x00'*64)
        exp_pkt = Ether(src="02:01:01:02:02:01",dst="02:12:23:34:45:56")/IP(src='10.0.0.10', dst='22.33.44.55')/TCP()/Raw('\x00'*64)
        self.test_packet(ingress, pkt, exp_pkt, dump_fil)

        self.cleanup_filter(iface)

        # Test Set SRC IPv4
        match = 'ip flower'
        action = 'pedit ex munge ip src set 22.33.44.55 pipe mirred egress redirect dev %s' % iface
        self.install_filter(iface, match, action)

        dump_fil='ip'
        pkt = Ether(src="02:01:01:02:02:01",dst="02:12:23:34:45:56")/IP(src='10.0.0.10', dst='11.0.0.11')/TCP()/Raw('\x00'*64)
        exp_pkt = Ether(src="02:01:01:02:02:01",dst="02:12:23:34:45:56")/IP(src='22.33.44.55', dst='11.0.0.11')/TCP()/Raw('\x00'*64)
        self.test_packet(ingress, pkt, exp_pkt, dump_fil)

        self.cleanup_filter(iface)
