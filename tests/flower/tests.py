#
# Copyright (C) 2017,  Netronome Systems, Inc.  All rights reserved.
#
"""
Flower test group for the NFP Linux drivers.
"""

from netro.testinfra.nti_exceptions import NtiError
from netro.testinfra.system import cmd_log
from netro.tests.tcpdump import TCPDump
from netro.tests.tcpreplay import TCPReplay
from ..common_test import CommonNetdevTest, NtiSkip
from ..drv_grp import NFPKmodGrp
from time import sleep
import os
import re

#pylint cannot find TCP, UDP, IP, IPv6, Dot1Q in scapy for some reason
#pylint: disable=no-name-in-module
from scapy.all import Raw, Ether, rdpcap, wrpcap, TCP, UDP, IP, IPv6, Dot1Q, fragment, fragment6, IPv6ExtHdrFragment
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
             ('flower_match_tcp_flags', FlowerMatchTCPFlag, "Checks flower tcp flags match capabilities"),
             ('flower_match_udp', FlowerMatchUDP, "Checks basic flower udp match capabilities"),
             ('flower_match_mpls', FlowerMatchMPLS, "Checks basic flower mpls match capabilities"),
             ('flower_match_ttl', FlowerMatchTTL, "Checks basic flower ttl match capabilities"),
             ('flower_match_tos', FlowerMatchTOS, "Checks basic flower tos match capabilities"),
             ('flower_match_frag_ipv4', FlowerMatchFragIPv4, "Checks basic flower fragmentation for IPv4 match capabilities"),
             ('flower_match_frag_ipv6', FlowerMatchFragIPv6, "Checks basic flower fragmentation for IPv6 match capabilities"),
             ('flower_match_vxlan', FlowerMatchVXLAN, "Checks basic flower vxlan match capabilities"),
             ('flower_match_geneve', FlowerMatchGeneve, "Checks basic flower Geneve match capabilities"),
             ('flower_match_block', FlowerMatchBlock, "Checks basic flower block match capabilities"),
             ('flower_modify_mtu', FlowerModifyMTU, "Checks the setting of a mac repr MTU"),
             ('flower_match_whitelist', FlowerMatchWhitelist, "Checks basic flower match whitelisting"),
             ('flower_vxlan_whitelist', FlowerVxlanWhitelist, "Checks that unsupported vxlan rules are not offloaded"),
             ('flower_csum_whitelist', FlowerCsumWhitelist, "Checks that unsupported checksum rules are not offloaded"),
             ('flower_action_encap_vxlan', FlowerActionVXLAN, "Checks basic flower vxlan encapsulation action capabilities"),
             ('flower_action_encap_geneve', FlowerActionGENEVE, "Checks basic flower geneve encapsulation action capabilities"),
             ('flower_action_set_ether', FlowerActionSetEth, "Checks basic flower set ethernet action capabilities"),
             ('flower_action_set_ipv4', FlowerActionSetIPv4, "Checks basic flower set IPv4 action capabilities"),
             ('flower_action_set_ipv6', FlowerActionSetIPv6, "Checks basic flower set IPv6 action capabilities"),
             ('flower_action_set_udp', FlowerActionSetUDP, "Checks basic flower set UDP action capabilities"),
             ('flower_action_set_tcp', FlowerActionSetTCP, "Checks basic flower set TCP action capabilities"),
             ('flower_vlan_repr', FlowerVlanRepr, "Checks that unsupported vxlan rules are not offloaded"),
             ('flower_repr_linkstate', FlowerReprLinkstate, "Checks that repr link state is handled correctly"),
             ('flower_bond_egress', FlowerActionBondEgress, "Checks egressing to a linux bond"),
        )

        for t in T:
            self._tests[t[0]] = t[1](src, dut, self, t[0], t[2])

class FlowerBase(CommonNetdevTest):
    def configure_vlan_flower(self):
        M = self.dut
        iface = self.dut_ifn[0]
        ret, _ = self.dut.cmd('cat /sys/class/net/%s/phys_port_name' % (iface), fail=False)
        if ret:
            raise NtiError('interface %s is not a valid port' % iface)

        vlan_iface = '%s.100' % (iface)
        self.dut.cmd('ip link add link %s name %s type vlan id 100' % (iface, vlan_iface), fail=False)
        self.dut.cmd('ip link set dev %s up' % (vlan_iface), fail=False)

        M.cmd('tc qdisc del dev %s handle ffff: ingress' % vlan_iface, fail=False)
        M.cmd('tc qdisc add dev %s handle ffff: ingress' % vlan_iface)

        ingress = vlan_iface
        iface = vlan_iface
        M.refresh()
        return iface, ingress

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

    def add_egress_qdisc(self, iface):
        M = self.dut
        M.cmd('tc qdisc del dev %s handle ffff: ingress' % iface, fail=False)
        M.cmd('tc qdisc add dev %s handle ffff: ingress' % iface)
        M.refresh()

    def check_prereq(self, check, description):
        M = self.dut
        res, _ = M.cmd(check, fail=False)
        if res == 1:
            raise NtiSkip('DUT does not support feature: %s' % description)

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

        self.send_packs(interface, ingress, pkt, send_cnt)

        exp_bytes = (len(pkt) + len(Ether()) + pkt_len_diff) * exp_cnt
        lo_exp_cnt = exp_cnt - 10
        lo_exp_exp_bytes = (len(pkt) + len(Ether()) + pkt_len_diff) * (exp_cnt - 10)
        stats = M.netifs[interface].stats(get_tc_ing=True)
        if int(stats.tc_ing['tc_49152_pkts']) < lo_exp_cnt or int(stats.tc_ing['tc_49152_pkts']) > exp_cnt:
            raise NtiError('Counter missmatch. Expected: %s, Got: %s' % (exp_cnt, stats.tc_ing['tc_49152_pkts']))
        if int(stats.tc_ing['tc_49152_bytes']) < lo_exp_exp_bytes or int(stats.tc_ing['tc_49152_bytes']) > exp_bytes:
            raise NtiError('Counter missmatch. Expected: %s, Got: %s' % (exp_bytes, stats.tc_ing['tc_49152_bytes']))

    def test_packet(self, iface, ingress, send_pkt, exp_pkt, dump_filter=''):
        M = self.dut
        A = self.src
        dump_local = os.path.join('/tmp/', 'pcap-dump-%s' % (self.name))
        self.capture_packs(iface, ingress, send_pkt, dump_local, dump_filter)
        test_pkt = rdpcap(dump_local)
        cmd_log("rm %s" % dump_local)
        if str(exp_pkt) != str(test_pkt[0]):
            print "Expected:"
            exp_pkt.show()
            print "Got:"
            test_pkt[0].show()
            raise NtiError('Packet missmatch')

    def send_packs(self, iface, ingress, pkt, loop=100):
        M = self.dut
        A = self.src

        pcap_local = os.path.join(self.group.tmpdir, 'pcap_%s_input' % (self.name))
        pcap_src = os.path.join(self.src.tmpdir, 'pcap_%s_src' % (self.name))
        wrpcap(pcap_local, pkt)
        A.mv_to(pcap_local, pcap_src)

        #Ensure both ports are live before sending/receiving traffic
        M.link_wait(iface, state=True)
        A.link_wait(ingress, state=True)

        self.tcpreplay = TCPReplay(A, ingress, pcap_src, loop, 100)
        self.tcpreplay.run()
        A.cmd("rm %s" % pcap_src)

    def capture_packs(self, iface, ingress, send_pkt, pack_dump, dump_filter='',
                      snaplen=8192, wait=2):
        A = self.src
        dump_src = os.path.join(self.src.tmpdir, 'dump_%s_src' % (self.name))

        # Grab packets on egress interface - Assume packets are being mirrored
        stderr = os.path.join(A.tmpdir, 'tcpdump_err.txt')
        self.tcpdump = TCPDump(A, ingress, dump_src, resolve=False,
                               direction='in', stderrfn=stderr,
                               filter_expr=dump_filter, snaplen=snaplen)
        self.tcpdump.start(wait)
        self.send_packs(iface, ingress, send_pkt)
        self.tcpdump.stop(wait)
        A.mv_from(dump_src, pack_dump)

    def capture_packs_multiple_ifaces(self, iface, sending_port, ingress_list, send_pkt, pack_dump_list, dump_filter='', loop=100):
        A = self.src
        assert len(ingress_list) == len(pack_dump_list)

        dump = 0
        for ing in ingress_list:
            dump_src = os.path.join(self.group.tmpdir, 'dump_%s_src' % (dump))
            A.cmd("tcpdump -U -i %s -w %s -Q in %s " % (ing, dump_src, dump_filter), background=True)
            dump += 1

        sleep(5)
        self.send_packs(iface, sending_port, send_pkt, loop)
        sleep(5)
        A.cmd("killall -KILL tcpdump")
        dump = 0
        for ing in ingress_list:
            dump_src = os.path.join(self.group.tmpdir, 'dump_%s_src' % (dump))
            A.mv_from(dump_src, pack_dump_list[dump])
            dump += 1

    def pcap_check_bytes(self, exp_cnt, cap_packs, pkt, pkt_len_diff=0):
        if len(cap_packs) != exp_cnt:
            raise NtiError('Pcap count missmatch. Expected: %s, Got: %s' % (exp_cnt, len(cap_packs)))
        exp_bytes = (len(pkt) + len(Ether()) + pkt_len_diff)*exp_cnt
        total_bytes = 0
        for p in cap_packs:
            total_bytes += len(p) + len(Ether())
        if total_bytes != exp_bytes:
            raise NtiError('Pcap byte missmatch. Expected: %s, Got: %s' % (exp_bytes, total_bytes))

    def pcap_check_count_multiple_ifaces(self, exp_cnt, cap_packs, spread=True):
        pkt_total = 0
        different_ports = False
        for cap in cap_packs:
            pkt_total += len(cap)
            # If packets are not spread among ports, running count will always be 0 or expected total
            if pkt_total != 0 and pkt_total != exp_cnt:
                if spread:
                    different_ports = True
                else:
                    raise NtiError('Packets received on more than one port')

        if spread and not different_ports:
            raise NtiError('Packets not spread over different ports')
        if pkt_total != exp_cnt:
            raise NtiError('Pcap count missmatch. Expected: %s, Got: %s' % (exp_cnt, pkt_total))

    def pcap_cmp_pkt_bytes(self, pack_cap, exp_field, offset, fail=False):
        # offset is in bytes but packet treated as hex string so double offset
        offset *= 2
        for p in pack_cap:
            if str(p).encode("hex")[offset:offset+len(exp_field)] != exp_field:
                if not fail:
                    raise NtiError('Bad byte match for %s at offset %s  - %s' % (exp_field, offset, str(p).encode("hex")[offset:offset+len(exp_field)]))
            else:
                if fail:
                    raise NtiError('Bytes match unexpected for %s at offset %s  - %s' % (exp_field, offset, str(p).encode("hex")[offset:offset+len(exp_field)]))

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

class FlowerMatchTCPFlag(FlowerBase):
    def test(self, flags, offload):
        iface, ingress = self.configure_flower()

        match = 'ip flower ip_proto tcp tcp_flags ' + hex(flags)
        action = 'mirred egress redirect dev %s' % iface
        self.install_filter(iface, match, action, offload)

        if offload:
            pkt_cnt = 100
            exp_pkt_cnt = 100
            pkt = Ether(src="02:01:01:02:02:01",dst="02:12:23:34:45:56")/IP(src='10.0.0.10', dst='11.0.0.11')/TCP(flags=flags)/Raw('\x00'*64)
            self.test_filter(iface, ingress, pkt, pkt_cnt, exp_pkt_cnt)

    def netdev_execute(self):
        offload = [1, 2, 3, 4, 5, 6, 7, 9, 10, 12, 33, 34, 36]
        non_offload = [8, 16, 17, 22, 32, 64, 128]

        for flags in offload:
            self.test(flags, True)

        for flags in non_offload:
            self.test(flags, False)

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

        M.cmd('ip link add vxlan0 type vxlan dstport 4789 dev %s external' % self.dut_ifn[0])
        M.cmd('ifconfig vxlan0 up')

        self.add_egress_qdisc('vxlan0')

        # Hit test - match all vxlan fields and decap
        match = 'ip flower enc_src_ip %s enc_dst_ip %s enc_dst_port 4789 enc_key_id 123' % (src_ip, dut_ip)
        action = 'mirred egress redirect dev %s' % iface
        self.install_filter('vxlan0', match, action)
        pkt_cnt = 100
        exp_pkt_cnt = 100

        # VXLAN header with VNI 123
        vxlan_header = '\x08\x00\x00\x00\x00\x00\x7b\x00'
        enc_pkt = Ether(src="aa:bb:cc:dd:ee:ff",dst="01:02:03:04:05:06")/IP()/TCP()/Raw('\x00'*64)
        vxlan_header += str(enc_pkt)
        pkt = Ether(src=src_mac,dst=dut_mac)/IP(src=src_ip, dst=dut_ip)/UDP(sport=44534, dport=4789)/vxlan_header
        pkt_diff = len(Ether()) + len(IP()) + len(UDP()) + 8
        self.test_filter('vxlan0', ingress, pkt, pkt_cnt, exp_pkt_cnt, -pkt_diff)

        self.cleanup_filter('vxlan0')

        # Miss test - incorrect enc ip src
        match = 'ip flower enc_src_ip 1.1.1.1 enc_dst_ip %s enc_dst_port 4789 enc_key_id 123' % (dut_ip)
        action = 'mirred egress redirect dev %s' % iface
        self.install_filter('vxlan0', match, action)

        pkt_cnt = 100
        exp_pkt_cnt = 0

        self.test_filter('vxlan0', ingress, pkt, pkt_cnt, exp_pkt_cnt)

        self.cleanup_filter('vxlan0')

        # Miss test - incorrect enc ip dst
        match = 'ip flower enc_src_ip %s enc_dst_ip 1.1.1.1 enc_dst_port 4789 enc_key_id 123' % (src_ip)
        action = 'mirred egress redirect dev %s' % iface
        self.install_filter('vxlan0', match, action)

        pkt_cnt = 100
        exp_pkt_cnt = 0

        self.test_filter('vxlan0', ingress, pkt, pkt_cnt, exp_pkt_cnt)

        self.cleanup_filter('vxlan0')

        # Miss test - incorrect VNI
        match = 'ip flower enc_src_ip %s enc_dst_ip %s enc_dst_port 4789 enc_key_id 124' % (src_ip, dut_ip)
        action = 'mirred egress redirect dev %s' % iface
        self.install_filter('vxlan0', match, action)

        pkt_cnt = 100
        exp_pkt_cnt = 0

        self.test_filter('vxlan0', ingress, pkt, pkt_cnt, exp_pkt_cnt)

        self.cleanup_filter('vxlan0')

    def cleanup(self):
        self.dut.cmd('ip link del vxlan0', fail=False)
        return super(FlowerMatchVXLAN, self).cleanup()

class FlowerMatchGeneve(FlowerBase):
    def netdev_execute(self):
        iface, ingress = self.configure_flower()
        M = self.dut
        A = self.src

        src_ip = self.src_addr[0].split('/')[0]
        dut_ip = self.dut_addr[0].split('/')[0]

        _, src_mac = A.cmd('cat /sys/class/net/%s/address | tr -d "\n"' % self.src_ifn[0])
        _, dut_mac = M.cmd('cat /sys/class/net/%s/address | tr -d "\n"' % self.dut_ifn[0])

        M.cmd('ip link add gene0 type geneve dstport 6081 external')
        M.cmd('ifconfig gene0 up')

        self.add_egress_qdisc('gene0')

        # Hit test - match all geneve fields and decap
        match = 'ip flower enc_src_ip %s enc_dst_ip %s enc_dst_port 6081 enc_key_id 123' % (src_ip, dut_ip)
        action = 'mirred egress redirect dev %s' % iface
        self.install_filter('gene0', match, action)
        pkt_cnt = 100
        exp_pkt_cnt = 100

        # Geneve header with VNI 123
        geneve_header = '\x00\x00\x65\x58\x00\x00\x7b\x00'
        enc_pkt = Ether(src="aa:bb:cc:dd:ee:ff",dst="01:02:03:04:05:06")/IP()/TCP()/Raw('\x00'*64)
        geneve_header += str(enc_pkt)
        pkt = Ether(src=src_mac,dst=dut_mac)/IP(src=src_ip, dst=dut_ip)/UDP(sport=44534, dport=6081)/geneve_header
        pkt_diff = len(Ether()) + len(IP()) + len(UDP()) + 8
        self.test_filter('gene0', ingress, pkt, pkt_cnt, exp_pkt_cnt, -pkt_diff)

        self.cleanup_filter('gene0')

        # Miss test - incorrect enc ip src
        match = 'ip flower enc_src_ip 1.1.1.1 enc_dst_ip %s enc_dst_port 6081 enc_key_id 123' % (dut_ip)
        action = 'mirred egress redirect dev %s' % iface
        self.install_filter('gene0', match, action)

        pkt_cnt = 100
        exp_pkt_cnt = 0

        self.test_filter('gene0', ingress, pkt, pkt_cnt, exp_pkt_cnt)

        self.cleanup_filter('gene0')

        # Miss test - incorrect enc ip dst
        match = 'ip flower enc_src_ip %s enc_dst_ip 1.1.1.1 enc_dst_port 6081 enc_key_id 123' % (src_ip)
        action = 'mirred egress redirect dev %s' % iface
        self.install_filter('gene0', match, action)

        pkt_cnt = 100
        exp_pkt_cnt = 0

        self.test_filter('gene0', ingress, pkt, pkt_cnt, exp_pkt_cnt)

        self.cleanup_filter('gene0')

        # Miss test - incorrect VNI
        match = 'ip flower enc_src_ip %s enc_dst_ip %s enc_dst_port 6081 enc_key_id 124' % (src_ip, dut_ip)
        action = 'mirred egress redirect dev %s' % iface
        self.install_filter('gene0', match, action)

        pkt_cnt = 100
        exp_pkt_cnt = 0

        self.test_filter('gene0', ingress, pkt, pkt_cnt, exp_pkt_cnt)

        self.cleanup_filter('gene0')

    def cleanup(self):
        self.dut.cmd('ip link del gene0', fail=False)
        return super(FlowerMatchGeneve, self).cleanup()

class FlowerMatchBlock(FlowerBase):
    def netdev_execute(self):
        if len(self.dut_ifn) < 2 or len(self.src_ifn) < 2:
            raise NtiError('At least 2 ports are required to test blocks')

        M = self.dut
        A = self.src
        iface = self.dut_ifn[0]
        iface2 = self.dut_ifn[1]

        ingress = self.src_ifn[0]
        ingress2 = self.src_ifn[1]

        # Add 2 interfaces to a block
        M.cmd('tc qdisc del dev %s ingress_block 22 ingress' % iface, fail=False)
        M.cmd('tc qdisc del dev %s ingress_block 22 ingress' % iface2, fail=False)
        M.cmd('tc qdisc add dev %s ingress_block 22 ingress' % iface)
        M.cmd('tc qdisc add dev %s ingress_block 22 ingress' % iface2)

        # Add filter to block
        M.cmd('tc filter add block 22 protocol ip parent ffff: flower skip_sw ip_proto tcp action drop')

        pkt_cnt = 100
        exp_pkt_cnt = 100
        pkt = Ether(src="02:01:01:02:02:01",dst="02:12:23:34:45:56")/IP()/TCP()/Raw('\x00'*64)
        self.test_filter(iface, ingress, pkt, pkt_cnt, exp_pkt_cnt)

        pkt_cnt = 100
        exp_pkt_cnt = 200
        pkt = Ether(src="02:01:01:02:02:01",dst="02:12:23:34:45:56")/IP()/TCP()/Raw('\x00'*64)
        self.test_filter(iface2, ingress2, pkt, pkt_cnt, exp_pkt_cnt)

        # Clean up the filter
        M.cmd('tc filter del block 22 protocol ip parent ffff: prio 49152')
        M.cmd('tc qdisc del dev %s ingress_block 22 ingress' % iface, fail=False)
        M.cmd('tc qdisc del dev %s ingress_block 22 ingress' % iface2, fail=False)

class FlowerMatchMPLS(FlowerBase):
    def netdev_execute(self):
        self.check_prereq('tc filter add flower help 2>&1 | grep mpls', 'MPLS Flower classification')
        iface, ingress = self.configure_flower()

        # Hit test
        match = '0x8847 flower'
        action = 'mirred egress redirect dev %s' % iface
        self.install_filter(iface, match, action)

        pkt_cnt = 100
        exp_pkt_cnt = 100
        pkt = Ether(src="02:01:01:02:02:01",dst="02:12:23:34:45:56")/MPLS(label=3333)/Raw('\x00'*64)
        self.test_filter(iface, ingress, pkt, pkt_cnt, exp_pkt_cnt)

        self.cleanup_filter(iface)

        # Miss test
        match = '0x8847 flower'
        action = 'mirred egress redirect dev %s' % iface
        self.install_filter(iface, match, action)

        pkt_cnt = 100
        exp_pkt_cnt = 0
        pkt = Ether(src="02:01:01:02:02:01",dst="02:12:23:34:45:56")/IP()/TCP()/Raw('\x00'*64)
        self.test_filter(iface, ingress, pkt, pkt_cnt, exp_pkt_cnt)

        self.cleanup_filter(iface)

        # Hit test
        match = '0x8847 flower mpls_label 1111'
        action = 'mirred egress redirect dev %s' % iface
        self.install_filter(iface, match, action)

        pkt_cnt = 100
        exp_pkt_cnt = 100
        pkt = Ether(src="02:01:01:02:02:01",dst="02:12:23:34:45:56")/MPLS(label=1111)/Raw('\x00'*64)
        self.test_filter(iface, ingress, pkt, pkt_cnt, exp_pkt_cnt)

        self.cleanup_filter(iface)

        # Miss test
        match = '0x8847 flower mpls_label 2222'
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

class FlowerMatchFrag(FlowerBase):
    def install_test(self, flag, iface):
        match = self.ip_ver + ' flower ip_flags ' + flag
        action = 'mirred egress redirect dev %s' % iface
        self.install_filter(iface, match, action)

    def frag_filter(self, flags, iface, ingress):
        pkt = self.pkt
        frag_pkt = self.frag_pkt
        pkt_cnt = 100
        exp_pkt_cnt = 100

        if flags == 'nofrag':
            self.test_filter(iface, ingress, frag_pkt[0], pkt_cnt, 0)
            self.test_filter(iface, ingress, pkt, pkt_cnt, exp_pkt_cnt)
        if flags == 'frag':
            self.test_filter(iface, ingress, pkt, pkt_cnt, 0)
            self.test_filter(iface, ingress, frag_pkt[0], pkt_cnt, exp_pkt_cnt)
        if flags == 'nofirstfrag':
            self.test_filter(iface, ingress, frag_pkt[0], pkt_cnt, 0)
            self.test_filter(iface, ingress, frag_pkt[1], pkt_cnt, exp_pkt_cnt)
        if flags == 'firstfrag':
            self.test_filter(iface, ingress, frag_pkt[1], pkt_cnt, 0)
            self.test_filter(iface, ingress, frag_pkt[0], pkt_cnt, exp_pkt_cnt)

    def frag_test(self):
        iface, ingress = self.configure_flower()
        frag = ['nofrag', 'frag', 'firstfrag', 'nofirstfrag']

        for flags in frag:
            self.install_test(flags, iface)
            self.frag_filter(flags, iface, ingress)
            self.cleanup_filter(iface)

    def netdev_execute(self):
        self.frag_test()

class FlowerMatchFragIPv4(FlowerMatchFrag):
    ip_ver = 'ip'
    pkt = Ether(src="02:01:01:02:02:01",dst="02:12:23:34:45:56")/\
          IP()/TCP()/Raw('\x00'*1024)
    frag_pkt = fragment(Ether(src="02:01:01:02:02:01",dst="02:12:23:34:45:56")/
                        IP()/TCP()/Raw('\x00'*1024), 128)

class FlowerMatchFragIPv6(FlowerMatchFrag):
    ip_ver = 'ipv6'
    pkt = Ether(src="02:01:01:02:02:01",dst="02:12:23:34:45:56")/\
          IPv6()/TCP()/Raw('\x00'*1024)
    frag_pkt = fragment6(Ether(src="02:01:01:02:02:01",dst="02:12:23:34:45:56")/
                         IPv6()/IPv6ExtHdrFragment()/TCP()/Raw('\x00'*1024), 128)

class FlowerModifyMTU(FlowerBase):
    def netdev_execute(self):
        iface, ingress = self.configure_flower()
        M = self.dut
        A = self.src

        # Test for high MTU set - 9420 should be max
        ret = M.ip_link_set_mtu(iface, 9421, fail=False)
        if not ret:
            raise NtiError('invalid MTU of 9421 accepted on %s' %iface)

        # Test for high MTU set - 68 should be min
        ret = M.ip_link_set_mtu(iface, 67, fail=False)
        if not ret:
            raise NtiError('invalid MTU of 67 accepted on %s' %iface)

        # ensure the sending interface can handle jumbo frames
        ret = A.ip_link_set_mtu(ingress, 9421)

        # Hit test
        match = 'ip flower'
        action = 'mirred egress redirect dev %s' % iface
        self.install_filter(iface, match, action)

        pkt_cnt = 100
        exp_pkt_cnt = 0
        # Length 14 + 20 + 20 + 9366 = 9420
        pkt = Ether()/IP()/TCP()/Raw('\x00'*9366)

        dump_file = os.path.join('/tmp/', 'dump.pcap')
        self.capture_packs(iface, ingress, pkt, dump_file, snaplen=None)
        pack_cap = rdpcap(dump_file)
        cmd_log("rm %s" % dump_file)
        self.pcap_check_bytes(exp_pkt_cnt, pack_cap, pkt, 0)

        self.cleanup_filter(iface)

        # Set mtu to 9420 and check it passes
        ret = M.ip_link_set_mtu(iface, 9420)

        self.install_filter(iface, match, action)
        pkt_cnt = 100
        exp_pkt_cnt = 100
        dump_file = os.path.join('/tmp/', 'dump.pcap')
        self.capture_packs(iface, ingress, pkt, dump_file, snaplen=None)
        pack_cap = rdpcap(dump_file)
        cmd_log("rm %s" % dump_file)
        self.pcap_check_bytes(exp_pkt_cnt, pack_cap, pkt, 0)

        self.cleanup_filter(iface)

        # Mark MTU below packet size and check it fails
        ret = M.ip_link_set_mtu(iface, 9000)

        self.install_filter(iface, match, action)
        pkt_cnt = 100
        exp_pkt_cnt = 0
        dump_file = os.path.join('/tmp/', 'dump.pcap')
        self.capture_packs(iface, ingress, pkt, dump_file, snaplen=None)
        pack_cap = rdpcap(dump_file)
        cmd_log("rm %s" % dump_file)
        self.pcap_check_bytes(exp_pkt_cnt, pack_cap, pkt, 0)

        self.cleanup_filter(iface)

    def cleanup(self):
        self.src.ip_link_set_mtu(self.src_ifn[0], 1500)
        self.dut.ip_link_set_mtu(self.dut_ifn[0], 1500)
        return super(FlowerModifyMTU, self).cleanup()

class FlowerMatchWhitelist(FlowerBase):
    def netdev_execute(self):
        iface, _ = self.configure_flower()
        M = self.dut

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

        # Check match offloaded to non repr is rejected even with repr  egress dev
        M.cmd('ip link add dummy1 type dummy')
        M.cmd('ifconfig dummy1 up')

        self.add_egress_qdisc('dummy1')
        match = 'ip flower dst_mac 02:12:23:34:45:56'
        action = 'mirred egress redirect dev %s' % iface
        self.install_filter('dummy1', match, action, False)
        self.cleanup_filter('dummy1')

    def cleanup(self):
        self.dut.cmd('ip link del dummy1', fail=False)
        self.dut.cmd('rmmod dummy', fail=False)
        return super(FlowerMatchWhitelist, self).cleanup()

class FlowerVxlanWhitelist(FlowerBase):
    def netdev_execute(self):
        iface, _ = self.configure_flower()
        M = self.dut

        src_ip = self.src_addr[0].split('/')[0]
        dut_ip = self.dut_addr[0].split('/')[0]

        M.cmd('ip link add vxlan0 type vxlan dstport 4789 dev %s external' % self.dut_ifn[0])
        M.cmd('ifconfig vxlan0 up')

        self.add_egress_qdisc('vxlan0')

        # Check that vxlan without a specified destination IP is installed in software only (not_in_hw)
        match = 'ip flower enc_src_ip 10.0.0.2 enc_dst_port 5789'
        action = 'mirred egress redirect dev %s' % iface
        self.install_filter('vxlan0', match, action, False)
        self.cleanup_filter('vxlan0')

        # Check that vxlan with masked destination IP is installed in software only (not_in_hw)
        match = 'ip flower enc_src_ip 10.0.0.2 enc_dst_ip 10.0.0.1/24 enc_dst_port 4789'
        action = 'mirred egress redirect dev %s' % iface
        self.install_filter('vxlan0', match, action, False)
        self.cleanup_filter('vxlan0')

        # Check that vxlan without a specified destination port is installed in software only (not_in_hw)
        match = 'ip flower enc_src_ip 10.0.0.2 enc_dst_ip 10.0.0.1'
        action = 'mirred egress redirect dev %s' % iface
        self.install_filter('vxlan0', match, action, False)
        self.cleanup_filter('vxlan0')

        # Check that vxlan with destination port != 4789 is installed in software only (not_in_hw)
        match = 'ip flower enc_src_ip 10.0.0.2 enc_dst_ip 10.0.0.1 enc_dst_port 5789'
        action = 'mirred egress redirect dev %s' % iface
        self.install_filter('vxlan0', match, action, False)
        self.cleanup_filter('vxlan0')

        # Check that a vxlan tunnel match rule cannot be offloaded to a repr netdev
        match = 'ip flower enc_src_ip %s enc_dst_ip %s enc_dst_port 4789 enc_key_id 123' % (src_ip, dut_ip)
        action = 'mirred egress redirect dev vxlan0'
        self.install_filter(iface, match, action, False)
        self.cleanup_filter(iface)

        # Check that multiple vxlan tunnel output is installed in software only (not_in_hw)
        M.cmd('ip link add vxlan1 type vxlan id 0 dstport 4790')
        M.cmd('ifconfig vxlan1 up')
        M.cmd('ip link add vxlan2 type vxlan id 0 dstport 4791')
        M.cmd('ifconfig vxlan2 up')
        match = 'ip flower ip_proto tcp'
        action = 'tunnel_key set id 123 src_ip 10.0.0.1 dst_ip 10.0.0.2 dst_port 4789 action mirred egress mirror dev vxlan1 action mirred egress redirect dev vxlan2'
        self.install_filter('vxlan0', match, action, False)
        self.cleanup_filter('vxlan0')

    def cleanup(self):
        self.dut.cmd('ip link delete vxlan0', fail=False)
        self.dut.cmd('ip link delete vxlan1', fail=False)
        self.dut.cmd('ip link delete vxlan2', fail=False)
        return super(FlowerVxlanWhitelist, self).cleanup()

class FlowerCsumWhitelist(FlowerBase):
    def netdev_execute(self):
        iface, _ = self.configure_flower()

        # Check that set ipv4 without csum update is installed in software only (not_in_hw)
        match = 'ip flower'
        action = 'pedit ex munge ip src set 20.30.40.50 munge ip dst set 120.130.140.150 pipe mirred egress redirect dev %s' % iface
        self.install_filter(iface, match, action, False)
        self.cleanup_filter(iface)

        # Check that set ipv6 without csum update is installed in software only (not_in_hw)
        match = 'ipv6 flower'
        action = 'pedit ex munge ip6 src set 1234:2345:3456:4567:5678:6789:7890:8901 munge ' +\
                 'ip6 dst set 1000:2000:3000:4000:5000:6000:7000:8000 pipe mirred egress redirect dev %s' % iface
        self.install_filter(iface, match, action, False)
        self.cleanup_filter(iface)

        # Check that set tcp without csum update is installed in software only (not_in_hw)
        match = 'ip flower ip_proto tcp'
        action = 'pedit ex munge tcp dport set 2000 pipe mirred egress redirect dev %s' % iface
        self.install_filter(iface, match, action, False)
        self.cleanup_filter(iface)

        # Check that set udp without csum update is installed in software only (not_in_hw)
        match = 'ip flower ip_proto udp'
        action = 'pedit ex munge udp dport set 4000 pipe mirred egress redirect dev %s' % iface
        self.install_filter(iface, match, action, False)
        self.cleanup_filter(iface)

        # Check that set tcp with a udp csum update is installed in software only (not_in_hw)
        match = 'ip flower ip_proto tcp'
        action = 'pedit ex munge tcp dport set 2000 pipe csum udp pipe mirred egress redirect dev %s' % iface
        self.install_filter(iface, match, action, False)
        self.cleanup_filter(iface)

        # Check that set udp with a tcp csum update is installed in software only (not_in_hw)
        match = 'ip flower ip_proto udp'
        action = 'pedit ex munge udp dport set 4000 pipe csum tcp pipe mirred egress redirect dev %s' % iface
        self.install_filter(iface, match, action, False)
        self.cleanup_filter(iface)

        # Check that set tcp with a tcp csum update without a tcp is installed in software only (not_in_hw)
        match = 'ip flower'
        action = 'pedit ex munge tcp dport set 1500 pipe csum tcp pipe mirred egress redirect dev %s' % iface
        self.install_filter(iface, match, action, False)
        self.cleanup_filter(iface)

class FlowerActionVXLAN(FlowerBase):
    def netdev_execute(self):
        iface, ingress = self.configure_flower()
        M = self.dut
        A = self.src

        src_ip = self.src_addr[0].split('/')[0]
        dut_ip = self.dut_addr[0].split('/')[0]

        _, src_mac = A.cmd('cat /sys/class/net/%s/address | tr -d "\n"' % self.src_ifn[0])
        _, dut_mac = M.cmd('cat /sys/class/net/%s/address | tr -d "\n"' % self.dut_ifn[0])

        # the destination port is defined by the tc rule - confirmed in both skip_sw and skip_hw
        M.cmd('ip link add name vxlan0 type vxlan dstport 0 external')
        M.cmd('ifconfig vxlan0 up')

        M.cmd('arp -i %s -s %s %s' % (self.dut_ifn[0], src_ip, src_mac))

        # Hit test - match all tcp packets and encap in vxlan
        match = 'ip flower skip_sw ip_proto tcp'
        action = 'tunnel_key set id 123 src_ip %s dst_ip %s dst_port 4789 action mirred egress redirect dev vxlan0' % (dut_ip, src_ip)
        self.install_filter(iface, match, action)

        pkt_cnt = 100
        exp_pkt_cnt = 99

        pkt = Ether(src="02:01:01:02:02:01",dst="02:12:23:34:45:56")/IP()/TCP()/Raw('\x00'*64)

        dump_file = os.path.join('/tmp/', 'dump.pcap')
        self.capture_packs(iface, ingress, pkt, dump_file)
        pack_cap = rdpcap(dump_file)
        cmd_log("rm %s" % dump_file)
        pkt_diff = len(Ether()) + len(IP()) + len(UDP()) + 8
        self.pcap_check_bytes(exp_pkt_cnt, pack_cap, pkt, pkt_diff)

        exp_pkt = Ether(src=dut_mac,dst=src_mac)/IP(src=dut_ip, dst=src_ip)/UDP(sport=0, dport=4789)

        # create matchable strings from the expected packet (non tested fields may differ)
        vxlan_header = '0800000000007b00'
        mac_header = str(exp_pkt).encode("hex")[0:len(Ether())*2]
        ip_addresses = str(exp_pkt).encode("hex")[(len(Ether()) + 12)*2: (len(Ether()) + len(IP()))*2]
        ip_proto = str(exp_pkt).encode("hex")[(len(Ether()) + 9)*2: (len(Ether()) + 10)*2]
        dest_port = str(exp_pkt).encode("hex")[(len(Ether()) + len(IP()) + 2)*2: (len(Ether()) + len(IP()) + 4)*2]
        no_ttl = '00'

        # copy a captured packet and get scapy to calculate its checksum
        first = pack_cap[0].copy()
        del(first[UDP].chksum)
        udp_csum = str(first).encode("hex")[(len(Ether()) + len(IP()) + 6)*2: (len(Ether()) + len(IP()) + 8)*2]

        # check VXLAN header
        self.pcap_cmp_pkt_bytes(pack_cap, vxlan_header, len(Ether()) + len(IP()) + len(UDP()))
        # check tunnel ethernet header
        self.pcap_cmp_pkt_bytes(pack_cap, mac_header, 0)
        # check tunnel IP addresses
        self.pcap_cmp_pkt_bytes(pack_cap, ip_addresses, len(Ether()) + 12)
        # check tunnel TTL is non zero
        self.pcap_cmp_pkt_bytes(pack_cap, no_ttl, len(Ether()) + 8, fail=True)
        # check tunnel IP proto
        self.pcap_cmp_pkt_bytes(pack_cap, ip_proto, len(Ether()) + 9)
        # check tunnel destination UDP port
        self.pcap_cmp_pkt_bytes(pack_cap, dest_port, len(Ether()) + len(IP()) + 2)
        # check udp checksum
        self.pcap_cmp_pkt_bytes(pack_cap, udp_csum, len(Ether()) + len(IP()) + 6)
        # check encapsulated packet
        self.pcap_cmp_pkt_bytes(pack_cap, str(pkt).encode("hex"), len(Ether()) + len(IP()) + len(UDP()) + 8)

        self.cleanup_filter(iface)

        # modify action to uncheck the udp checksum flag
        action = 'tunnel_key set id 123 src_ip %s dst_ip %s dst_port 4789 nocsum action mirred egress redirect dev vxlan0' % (dut_ip, src_ip)
        self.install_filter(iface, match, action)
        self.capture_packs(iface, ingress, pkt, dump_file)
        pack_cap = rdpcap(dump_file)

        no_csum = '0000'
        # verify checksum is 0
        self.pcap_cmp_pkt_bytes(pack_cap, no_csum, len(Ether()) + len(IP()) + 6)

        self.cleanup_filter(iface)

    def cleanup(self):
        src_ip = self.src_addr[0].split('/')[0]
        self.dut.cmd('arp -i %s -d %s' % (self.dut_ifn[0], src_ip), fail=False)
        self.dut.cmd('ip link delete vxlan0', fail=False)
        return super(FlowerActionVXLAN, self).cleanup()

class FlowerActionGENEVE(FlowerBase):
    def netdev_execute(self):
        iface, ingress = self.configure_flower()
        M = self.dut
        A = self.src

        src_ip = self.src_addr[0].split('/')[0]
        dut_ip = self.dut_addr[0].split('/')[0]

        _, src_mac = A.cmd('cat /sys/class/net/%s/address | tr -d "\n"' % self.src_ifn[0])
        _, dut_mac = M.cmd('cat /sys/class/net/%s/address | tr -d "\n"' % self.dut_ifn[0])

        # the destination port is defined by the tc rule - confirmed in both skip_sw and skip_hw
        M.cmd('ip link add name gene0 type geneve dstport 0 external')
        M.cmd('ifconfig gene0 up')

        M.cmd('arp -i %s -s %s %s' % (self.dut_ifn[0], src_ip, src_mac))

        # Hit test - match all tcp packets and encap in geneve
        match = 'ip flower skip_sw ip_proto tcp'
        action = 'tunnel_key set id 123 src_ip %s dst_ip %s dst_port 6081 action mirred egress redirect dev gene0' % (dut_ip, src_ip)
        self.install_filter(iface, match, action)

        pkt_cnt = 100
        exp_pkt_cnt = 99

        pkt = Ether(src="02:01:01:02:02:01",dst="02:12:23:34:45:56")/IP()/TCP()/Raw('\x00'*64)

        dump_file = os.path.join('/tmp/', 'dump.pcap')
        self.capture_packs(iface, ingress, pkt, dump_file)
        pack_cap = rdpcap(dump_file)
        cmd_log("rm %s" % dump_file)
        pkt_diff = len(Ether()) + len(IP()) + len(UDP()) + 8
        self.pcap_check_bytes(exp_pkt_cnt, pack_cap, pkt, pkt_diff)

        exp_pkt = Ether(src=dut_mac,dst=src_mac)/IP(src=dut_ip, dst=src_ip)/UDP(sport=0, dport=6081)

        # create matchable strings from the expected packet (non tested fields may differ)
        geneve_header = '0000655800007b00'
        mac_header = str(exp_pkt).encode("hex")[0:len(Ether())*2]
        ip_addresses = str(exp_pkt).encode("hex")[(len(Ether()) + 12)*2: (len(Ether()) + len(IP()))*2]
        ip_proto = str(exp_pkt).encode("hex")[(len(Ether()) + 9)*2: (len(Ether()) + 10)*2]
        dest_port = str(exp_pkt).encode("hex")[(len(Ether()) + len(IP()) + 2)*2: (len(Ether()) + len(IP()) + 4)*2]

        # check GENEVE header
        self.pcap_cmp_pkt_bytes(pack_cap, geneve_header, len(Ether()) + len(IP()) + len(UDP()))
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

    def cleanup(self):
        src_ip = self.src_addr[0].split('/')[0]
        self.dut.cmd('arp -i %s -d %s' % (self.dut_ifn[0], src_ip), fail=False)
        self.dut.cmd('ip link delete gene0', fail=False)
        return super(FlowerActionGENEVE, self).cleanup()

class FlowerActionSetEth(FlowerBase):
    def netdev_execute(self):
        iface, ingress = self.configure_flower()

        # Test Output Action
        match = 'ip flower'
        action = 'mirred egress redirect dev %s' % iface
        self.install_filter(iface, match, action)

        pkt = Ether(src="02:01:01:02:02:01",dst="02:12:23:34:45:56")/IP(src='10.0.0.10', dst='11.0.0.11')/TCP()/Raw('\x00'*64)
        exp_pkt = Ether(src="02:01:01:02:02:01",dst="02:12:23:34:45:56")/IP(src='10.0.0.10', dst='11.0.0.11')/TCP()/Raw('\x00'*64)
        self.test_packet(iface, ingress, pkt, exp_pkt)

        self.cleanup_filter(iface)

        # Test Set SRC and DST Ethernet
        match = 'ip flower'
        action = 'pedit ex munge eth src set 14:24:34:44:45:46 munge eth dst set 11:22:33:44:55:66 pipe mirred egress redirect dev %s' % iface
        self.install_filter(iface, match, action)

        dump_fil='ip'
        pkt = Ether(src="02:01:01:02:02:01",dst="02:12:23:34:45:56")/IP(src='10.0.0.10', dst='11.0.0.11')/TCP()/Raw('\x00'*64)
        exp_pkt = Ether(src="14:24:34:44:45:46",dst="11:22:33:44:55:66")/IP(src='10.0.0.10', dst='11.0.0.11')/TCP()/Raw('\x00'*64)
        self.test_packet(iface, ingress, pkt, exp_pkt, dump_fil)

        self.cleanup_filter(iface)

        # Test Set DST Ethernet
        match = 'ip flower'
        action = 'pedit ex munge eth dst set 14:24:34:44:45:46 pipe mirred egress redirect dev %s' % iface
        self.install_filter(iface, match, action)

        dump_fil='ip'
        pkt = Ether(src="02:01:01:02:02:01",dst="02:12:23:34:45:56")/IP(src='10.0.0.10', dst='11.0.0.11')/TCP()/Raw('\x00'*64)
        exp_pkt = Ether(src="02:01:01:02:02:01",dst="14:24:34:44:45:46")/IP(src='10.0.0.10', dst='11.0.0.11')/TCP()/Raw('\x00'*64)
        self.test_packet(iface, ingress, pkt, exp_pkt, dump_fil)

        self.cleanup_filter(iface)

        # Test Set SRC Ethernet
        match = 'ip flower'
        action = 'pedit ex munge eth src set 11:22:33:44:55:66 pipe mirred egress redirect dev %s' % iface
        self.install_filter(iface, match, action)

        dump_fil='ip'
        pkt = Ether(src="02:01:01:02:02:01",dst="02:12:23:34:45:56")/IP(src='10.0.0.10', dst='11.0.0.11')/TCP()/Raw('\x00'*64)
        exp_pkt = Ether(src="11:22:33:44:55:66",dst="02:12:23:34:45:56")/IP(src='10.0.0.10', dst='11.0.0.11')/TCP()/Raw('\x00'*64)
        self.test_packet(iface, ingress, pkt, exp_pkt, dump_fil)

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
        self.test_packet(iface, ingress, pkt, exp_pkt)

        self.cleanup_filter(iface)

        # Test Set SRC and DST IPv4
        match = 'ip flower ip_proto tcp'
        action = 'pedit ex munge ip src set 20.30.40.50 munge ip dst set 120.130.140.150 pipe csum ip and tcp pipe mirred egress redirect dev %s' % iface
        self.install_filter(iface, match, action)

        dump_fil='ip'
        pkt = Ether(src="02:01:01:02:02:01",dst="02:12:23:34:45:56")/IP(src='10.0.0.10', dst='11.0.0.11')/TCP()/Raw('\x00'*64)
        exp_pkt = Ether(src="02:01:01:02:02:01",dst="02:12:23:34:45:56")/IP(src='20.30.40.50', dst='120.130.140.150')/TCP()/Raw('\x00'*64)
        self.test_packet(iface, ingress, pkt, exp_pkt, dump_fil)

        self.cleanup_filter(iface)

        # Test Set DST IPv4
        match = 'ip flower ip_proto tcp'
        action = 'pedit ex munge ip dst set 22.33.44.55 pipe csum ip and tcp pipe mirred egress redirect dev %s' % iface
        self.install_filter(iface, match, action)

        dump_fil='ip'
        pkt = Ether(src="02:01:01:02:02:01",dst="02:12:23:34:45:56")/IP(src='10.0.0.10', dst='11.0.0.11')/TCP()/Raw('\x00'*64)
        exp_pkt = Ether(src="02:01:01:02:02:01",dst="02:12:23:34:45:56")/IP(src='10.0.0.10', dst='22.33.44.55')/TCP()/Raw('\x00'*64)
        self.test_packet(iface, ingress, pkt, exp_pkt, dump_fil)

        self.cleanup_filter(iface)

        # Test Set SRC IPv4
        match = 'ip flower ip_proto tcp'
        action = 'pedit ex munge ip src set 22.33.44.55 pipe csum ip and tcp pipe mirred egress redirect dev %s' % iface
        self.install_filter(iface, match, action)

        dump_fil='ip'
        pkt = Ether(src="02:01:01:02:02:01",dst="02:12:23:34:45:56")/IP(src='10.0.0.10', dst='11.0.0.11')/TCP()/Raw('\x00'*64)
        exp_pkt = Ether(src="02:01:01:02:02:01",dst="02:12:23:34:45:56")/IP(src='22.33.44.55', dst='11.0.0.11')/TCP()/Raw('\x00'*64)
        self.test_packet(iface, ingress, pkt, exp_pkt, dump_fil)

        self.cleanup_filter(iface)

class FlowerActionSetIPv6(FlowerBase):
    def netdev_execute(self):
        iface, ingress = self.configure_flower()

        # Test Output Action
        match = 'ip flower'
        action = 'mirred egress redirect dev %s' % iface
        self.install_filter(iface, match, action)

        pkt = Ether(src="02:01:01:02:02:01",dst="02:12:23:34:45:56")/IP(src='10.0.0.10', dst='11.0.0.11')/TCP()/Raw('\x00'*64)
        exp_pkt = Ether(src="02:01:01:02:02:01",dst="02:12:23:34:45:56")/IP(src='10.0.0.10', dst='11.0.0.11')/TCP()/Raw('\x00'*64)
        self.test_packet(iface, ingress, pkt, exp_pkt)

        self.cleanup_filter(iface)

        # Test Set SRC and DST IPv6
        match = 'ipv6 flower ip_proto tcp'
        action = 'pedit ex munge ip6 src set 1234:2345:3456:4567:5678:6789:7890:8901 munge ' +\
                 'ip6 dst set 1000:2000:3000:4000:5000:6000:7000:8000 pipe csum tcp pipe mirred egress redirect dev %s' % iface
        self.install_filter(iface, match, action)

        dump_fil='ip6'
        pkt = Ether(src="02:01:01:02:02:01",dst="02:12:23:34:45:56")/IPv6(src='11::11', dst='10::10')/TCP()/Raw('\x00'*64)
        exp_pkt = Ether(src="02:01:01:02:02:01",dst="02:12:23:34:45:56")/IPv6(src='1234:2345:3456:4567:5678:6789:7890:8901',
                        dst='1000:2000:3000:4000:5000:6000:7000:8000')/TCP()/Raw('\x00'*64)
        self.test_packet(iface, ingress, pkt, exp_pkt, dump_fil)

        self.cleanup_filter(iface)

        # Test Set DST IPv6
        match = 'ipv6 flower ip_proto tcp'
        action = 'pedit ex munge ip6 dst set 1234:2345:3456:4567:5678:6789:7890:8901 pipe csum tcp pipe mirred egress redirect dev %s' % iface
        self.install_filter(iface, match, action)

        dump_fil='ip6'
        pkt = Ether(src="02:01:01:02:02:01",dst="02:12:23:34:45:56")/IPv6(src='11::11', dst='10::10')/TCP()/Raw('\x00'*64)
        exp_pkt = Ether(src="02:01:01:02:02:01",dst="02:12:23:34:45:56")/IPv6(src='11::11',
                        dst='1234:2345:3456:4567:5678:6789:7890:8901')/TCP()/Raw('\x00'*64)
        self.test_packet(iface, ingress, pkt, exp_pkt, dump_fil)

        self.cleanup_filter(iface)

        # Test Set SRC IPv6
        match = 'ipv6 flower ip_proto tcp'
        action = 'pedit ex munge ip6 src set 1234:2345:3456:4567:5678:6789:7890:8901 pipe csum tcp pipe mirred egress redirect dev %s' % iface
        self.install_filter(iface, match, action)

        dump_fil='ip6'
        pkt = Ether(src="02:01:01:02:02:01",dst="02:12:23:34:45:56")/IPv6(src='11::11', dst='10::10')/TCP()/Raw('\x00'*64)
        exp_pkt = Ether(src="02:01:01:02:02:01",dst="02:12:23:34:45:56")/IPv6(src='1234:2345:3456:4567:5678:6789:7890:8901',
                        dst='10::10')/TCP()/Raw('\x00'*64)
        self.test_packet(iface, ingress, pkt, exp_pkt, dump_fil)

        self.cleanup_filter(iface)

class FlowerActionSetUDP(FlowerBase):
    def netdev_execute(self):
        iface, ingress = self.configure_flower()

        # Test Output Action
        match = 'ip flower'
        action = 'mirred egress redirect dev %s' % iface
        self.install_filter(iface, match, action)

        pkt = Ether(src="02:01:01:02:02:01",dst="02:12:23:34:45:56")/IP(src='10.0.0.10', dst='11.0.0.11')/TCP()/Raw('\x00'*64)
        exp_pkt = Ether(src="02:01:01:02:02:01",dst="02:12:23:34:45:56")/IP(src='10.0.0.10', dst='11.0.0.11')/TCP()/Raw('\x00'*64)
        self.test_packet(iface, ingress, pkt, exp_pkt)

        self.cleanup_filter(iface)

        # Test Set SRC and DST UDP
        match = 'ip flower ip_proto udp'
        action = 'pedit ex munge udp sport set 4282 munge udp dport set 8242 pipe csum udp pipe mirred egress redirect dev %s' % iface
        self.install_filter(iface, match, action)

        dump_fil=''
        pkt = Ether(src="02:01:01:02:02:01",dst="02:12:23:34:45:56")/IP(src='10.0.0.10', dst='11.0.0.11')/UDP(sport=1000,dport=2000)/Raw('\x00'*64)
        exp_pkt = Ether(src="02:01:01:02:02:01",dst="02:12:23:34:45:56")/IP(src='10.0.0.10', dst='11.0.0.11')/UDP(sport=4282,dport=8242)/Raw('\x00'*64)
        self.test_packet(iface, ingress, pkt, exp_pkt, dump_fil)

        self.cleanup_filter(iface)

        # Test Set DST UDP
        match = 'ip flower ip_proto udp'
        action = 'pedit ex munge udp dport set 2000 pipe csum udp pipe mirred egress redirect dev %s' % iface
        self.install_filter(iface, match, action)

        dump_fil=''
        pkt = Ether(src="02:01:01:02:02:01",dst="02:12:23:34:45:56")/IP(src='10.0.0.10', dst='11.0.0.11')/UDP(sport=2222,dport=4444)/Raw('\x00'*64)
        exp_pkt = Ether(src="02:01:01:02:02:01",dst="02:12:23:34:45:56")/IP(src='10.0.0.10', dst='11.0.0.11')/UDP(sport=2222,dport=2000)/Raw('\x00'*64)
        self.test_packet(iface, ingress, pkt, exp_pkt, dump_fil)

        self.cleanup_filter(iface)

        # Test Set SRC UDP
        match = 'ip flower ip_proto udp'
        action = 'pedit ex munge udp sport set 4000 pipe csum udp pipe mirred egress redirect dev %s' % iface
        self.install_filter(iface, match, action)

        dump_fil=''
        pkt = Ether(src="02:01:01:02:02:01",dst="02:12:23:34:45:56")/IP(src='10.0.0.10', dst='11.0.0.11')/UDP(sport=2222,dport=4444)/Raw('\x00'*64)
        exp_pkt = Ether(src="02:01:01:02:02:01",dst="02:12:23:34:45:56")/IP(src='10.0.0.10', dst='11.0.0.11')/UDP(sport=4000,dport=4444)/Raw('\x00'*64)
        self.test_packet(iface, ingress, pkt, exp_pkt, dump_fil)

        self.cleanup_filter(iface)

class FlowerActionSetTCP(FlowerBase):
    def netdev_execute(self):
        iface, ingress = self.configure_flower()

        # Test Output Action
        match = 'ip flower'
        action = 'mirred egress redirect dev %s' % iface
        self.install_filter(iface, match, action)

        pkt = Ether(src="02:01:01:02:02:01",dst="02:12:23:34:45:56")/IP(src='10.0.0.10', dst='11.0.0.11')/TCP()/Raw('\x00'*64)
        exp_pkt = Ether(src="02:01:01:02:02:01",dst="02:12:23:34:45:56")/IP(src='10.0.0.10', dst='11.0.0.11')/TCP()/Raw('\x00'*64)
        self.test_packet(iface, ingress, pkt, exp_pkt)

        self.cleanup_filter(iface)

        # Test Set SRC and DST TCP
        match = 'ip flower ip_proto tcp'
        action = 'pedit ex munge tcp sport set 4282 munge tcp dport set 8242 pipe csum tcp pipe mirred egress redirect dev %s' % iface
        self.install_filter(iface, match, action)

        dump_fil=''
        pkt = Ether(src="02:01:01:02:02:01",dst="02:12:23:34:45:56")/IP(src='10.0.0.10', dst='11.0.0.11')/TCP(sport=1000,dport=2000)/Raw('\x00'*64)
        exp_pkt = Ether(src="02:01:01:02:02:01",dst="02:12:23:34:45:56")/IP(src='10.0.0.10', dst='11.0.0.11')/TCP(sport=4282,dport=8242)/Raw('\x00'*64)
        self.test_packet(iface, ingress, pkt, exp_pkt, dump_fil)

        self.cleanup_filter(iface)

        # Test Set DST TCP
        match = 'ip flower ip_proto tcp'
        action = 'pedit ex munge tcp dport set 2000 pipe csum tcp pipe mirred egress redirect dev %s' % iface
        self.install_filter(iface, match, action)

        dump_fil=''
        pkt = Ether(src="02:01:01:02:02:01",dst="02:12:23:34:45:56")/IP(src='10.0.0.10', dst='11.0.0.11')/TCP(sport=2222,dport=4444)/Raw('\x00'*64)
        exp_pkt = Ether(src="02:01:01:02:02:01",dst="02:12:23:34:45:56")/IP(src='10.0.0.10', dst='11.0.0.11')/TCP(sport=2222,dport=2000)/Raw('\x00'*64)
        self.test_packet(iface, ingress, pkt, exp_pkt, dump_fil)

        self.cleanup_filter(iface)

        # Test Set SRC UDP
        match = 'ip flower ip_proto tcp'
        action = 'pedit ex munge tcp sport set 4000 pipe csum tcp pipe mirred egress redirect dev %s' % iface
        self.install_filter(iface, match, action)

        dump_fil=''
        pkt = Ether(src="02:01:01:02:02:01",dst="02:12:23:34:45:56")/IP(src='10.0.0.10', dst='11.0.0.11')/TCP(sport=2222,dport=4444)/Raw('\x00'*64)
        exp_pkt = Ether(src="02:01:01:02:02:01",dst="02:12:23:34:45:56")/IP(src='10.0.0.10', dst='11.0.0.11')/TCP(sport=4000,dport=4444)/Raw('\x00'*64)
        self.test_packet(iface, ingress, pkt, exp_pkt, dump_fil)

        self.cleanup_filter(iface)

class FlowerVlanRepr(FlowerBase):
    def netdev_execute(self):
        iface, _ = self.configure_vlan_flower()

        # Check that redirects to upper netdevs is installed in software only (not_in_hw)
        match = 'ip flower'
        action = 'mirred egress redirect dev %s' % iface
        self.install_filter(iface, match, action, False)
        self.cleanup_filter(iface)

class FlowerReprLinkstate(CommonNetdevTest):
    def dmesg_check(self):
        _, out = self.dut.cmd('dmesg -c | grep %s' % (self.group.pci_dbdf))
        failures = re.search('ctrl msg for unknown port', out)
        if failures:
            raise NtiError("Failure detected: %s" % failures.group(0))

    def is_repr(self, ifc):
        _, out = self.dut.cmd('ethtool -i %s' % (ifc))

        driver = re.search('driver: (\w+)', out)
        if not driver:
            raise NtiError("Can't determine which driver is used - ethtool output invalid")

        return driver.groups()[0] == "nfp"

    def netdev_execute(self):
        self.dut.cmd('dmesg -c')
        new_ifcs = self.spawn_vf_netdev()
        if (len(new_ifcs) != 2):
            raise NtiError("Only expected to find 2 new interfaces, found %i instead" % len(new_ifcs))

        # Assume the ordering then check it
        vf = new_ifcs[0]
        repr = new_ifcs[1]
        if not self.is_repr(repr) and self.is_repr(vf):
            vf = new_ifcs[1]
            repr = new_ifcs[0]

        # Final sanity check
        if not self.is_repr(repr) or self.is_repr(vf):
            raise NtiError("The interfaces %s and %s could not be identified as repr and VF" % (repr, vf))

        self.dmesg_check()

        self.dut.link_wait(repr, state=False)
        self.dut.link_wait(vf, state=False)

        self.dut.cmd('ip link set %s up' % (repr))
        self.dut.link_wait(repr, state=False)
        self.dut.link_wait(vf, state=False)

        self.dut.cmd('ip link set %s down' % (repr))
        self.dut.cmd('ip link set %s up' % (vf))
        self.dut.link_wait(repr, state=False)
        self.dut.link_wait(vf, state=False)

        self.dut.cmd('ip link set %s up' % (repr))
        self.dut.link_wait(repr, state=True)
        self.dut.link_wait(vf, state=True)

        self.dut.reset_mods()
        self.dmesg_check()

class FlowerActionBondEgress(FlowerBase):
    def netdev_execute(self):
        iface, ingress = self.configure_flower()
        M = self.dut
        A = self.src

        # Reload bonding module if required
        M.cmd('modprobe -r bonding || :', fail=False)
        M.cmd('modprobe bonding mode=balance-xor miimon=100 xmit_hash_policy=layer3+4', fail=False)

        # Ensure bond0 exists
        M.cmd('ip link add name bond0 type bond', fail=False)

        # Enslave port to bond0
        M.cmd('ip link set dev bond0 down')
        M.cmd('ip link set dev %s down' % iface)
        self.dut.link_wait(iface, state=False)
        M.cmd('ip link set dev %s master bond0'  % iface)
        M.cmd('ip link set dev bond0 up')
        M.cmd('ip link set dev %s up' % iface)
        self.dut.link_wait(iface, state=True)

        # Install filter outputting to bond0
        match = 'ip flower'
        action = 'mirred egress redirect dev bond0'
        self.install_filter(iface, match, action)

        pkt = Ether(src="02:01:01:02:02:01",dst="02:12:23:34:45:56")/IP(src='10.0.0.10', dst='11.0.0.11')/TCP()/Raw('\x00'*64)
        self.test_packet(iface, ingress, pkt, pkt)

        if len(self.dut_ifn) < 2 or len(self.src_ifn) < 2:
            print 'Not enough interfaces in config file -  skipping some bond tests\n'
            self.cleanup_filter(iface)
            M.cmd('ip link set %s nomaster' % iface)
            M.cmd('modprobe -r bonding || :', fail=False)
            return

        iface2 = self.dut_ifn[1]
        ingress2 = self.src_ifn[1]

        # Enslave second port to bond0
        M.cmd('ip link set dev bond0 down')
        M.cmd('ip link set dev %s down' % iface2)
        self.dut.link_wait(iface2, state=False)
        M.cmd('ip link set dev %s master bond0'  % iface2)
        M.cmd('ip link set dev bond0 up')
        M.cmd('ip link set dev %s up' % iface2)
        self.dut.link_wait(iface2, state=True)

        dump_file = os.path.join(self.group.tmpdir, 'dump.pcap')
        dump_file2 = os.path.join(self.group.tmpdir, 'dump2.pcap')

        # Generate packets with incrementing IP addresses so they hash differently
        pkts = []
        for i in range (100):
                src_ip = "10.0.0.%s" % i
                pkts.append(Ether(src="02:01:01:02:02:01",dst="02:12:23:34:45:56")/IP(src=src_ip, dst='11.0.0.11')/TCP()/Raw('\x00'*64))

        self.capture_packs_multiple_ifaces(iface, ingress, [ingress, ingress2], pkts, [dump_file, dump_file2], loop=1)

        pack_cap = rdpcap(dump_file)
        pack_cap2 = rdpcap(dump_file2)

        self.pcap_check_count_multiple_ifaces(100, [pack_cap, pack_cap2], spread=True)

        # Test active/backup mode
        M.cmd('ip link set dev bond0 down')
        M.cmd('ip link set dev %s down' % iface)
        self.dut.link_wait(iface, state=False)
        M.cmd('ip link set dev %s down' % iface2)
        self.dut.link_wait(iface2, state=False)
        M.cmd('ip link set %s nomaster' % iface)
        M.cmd('ip link set %s nomaster' % iface2)
        ret=M.cmd('echo 1 >/sys/class/net/bond0/bonding/mode', fail=False)
        M.cmd('ip link set dev %s master bond0'  % iface)
        M.cmd('ip link set dev %s master bond0'  % iface2)
        M.cmd('ip link set dev bond0 up')
        M.cmd('ip link set dev %s up' % iface)
        self.dut.link_wait(iface, state=True)
        M.cmd('ip link set dev %s up' % iface2)
        self.dut.link_wait(iface2, state=True)

        self.capture_packs_multiple_ifaces(iface, ingress, [ingress, ingress2], pkts, [dump_file, dump_file2], loop=1)

        pack_cap = rdpcap(dump_file)
        pack_cap2 = rdpcap(dump_file2)

        self.pcap_check_count_multiple_ifaces(100, [pack_cap, pack_cap2], spread=False)

        self.cleanup_filter(iface)
        M.cmd('ip link set %s nomaster' % iface)
        M.cmd('ip link set %s nomaster' % iface2)
        M.cmd('modprobe -r bonding || :', fail=False)

        # Run a test on Team
        M.cmd('modprobe -r team_mode_loadbalance || :', fail=False)
        M.cmd('modprobe -r team || :', fail=False)
        M.cmd('modprobe team', fail=False)

        # Create team team0 and set to loadbalance
        M.cmd('ip link del dev team0', fail=False)
        M.cmd('ip link add name team0 type team')
        M.cmd('teamnl team0 setoption mode loadbalance')

        # Enslave ports to team0
        M.cmd('ip link set dev team0 down')
        M.cmd('ip link set dev %s down' % iface)
        self.dut.link_wait(iface, state=False)
        M.cmd('ip link set dev %s down' % iface2)
        self.dut.link_wait(iface2, state=False)
        M.cmd('ip link set dev %s master team0'  % iface)
        M.cmd('ip link set dev %s master team0'  % iface2)
        M.cmd('ip link set dev team0 up')
        M.cmd('ip link set dev %s up' % iface)
        self.dut.link_wait(iface, state=True)
        M.cmd('ip link set dev %s up' % iface2)
        self.dut.link_wait(iface2, state=True)

        action = 'mirred egress redirect dev team0'
        self.install_filter(iface, match, action)

        self.capture_packs_multiple_ifaces(iface, ingress, [ingress, ingress2], pkts, [dump_file, dump_file2], loop=1)

        pack_cap = rdpcap(dump_file)
        pack_cap2 = rdpcap(dump_file2)

        self.pcap_check_count_multiple_ifaces(100, [pack_cap, pack_cap2], spread=True)

        cmd_log("rm %s" % dump_file)
        cmd_log("rm %s" % dump_file2)

        self.cleanup_filter(iface)

    def cleanup(self):
        self.dut.cmd('ip link set %s nomaster' % self.dut_ifn[0], fail=False)
        if len(self.dut_ifn) > 1:
            self.dut.cmd('ip link set %s nomaster' % self.dut_ifn[1], fail=False)
        self.dut.cmd('modprobe -r bonding || :', fail=False)
        self.dut.cmd('ip link del dev team0', fail=False)
        self.dut.cmd('modprobe -r team_mode_loadbalance || :', fail=False)
        self.dut.cmd('modprobe -r team || :', fail=False)
        return super(FlowerActionBondEgress, self).cleanup()
