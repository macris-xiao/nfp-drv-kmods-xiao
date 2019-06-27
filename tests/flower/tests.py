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
from ..common_test import CommonTest, NtiSkip, NrtResult
from ..drv_grp import NFPKmodAppGrp
from struct import unpack, pack
from time import sleep
from copy import copy
import os, pprint
import ipaddress
import re

#pylint cannot find TCP, UDP, IP, IPv6, Dot1Q in scapy for some reason
#pylint: disable=no-name-in-module
from scapy.all import Raw, Ether, rdpcap, wrpcap, TCP, UDP, IP, IPv6, Dot1Q, fragment, fragment6, IPv6ExtHdrFragment, GRE
#You need latest scapy to import from contrib
from scapy.contrib.mpls import MPLS

###########################################################################
# Flower Unit Tests
###########################################################################

class NFPKmodFlower(NFPKmodAppGrp):
    """Flower tests for the NFP Linux drivers"""

    summary = "Basic flower tests of NFP Linux driver."

    def _init(self):
        self.pp = pprint.PrettyPrinter()
        NFPKmodAppGrp._init(self)

    def populate_tests(self):
        dut = (self.dut, self.addr_x, self.eth_x, self.addr_v6_x)
        src = (self.host_a, self.addr_a, self.eth_a, self.addr_v6_a)

        T = (('flower_match_mac', FlowerMatchMAC, "Checks basic flower mac match capabilities"),
             ('flower_match_vlan_id', FlowerMatchVLANID, "Checks basic flower vlan id match capabilities"),
             ('flower_match_vlan_pcp', FlowerMatchVLANPCP, "Checks basic flower vlan pcp match capabilities"),
             ('flower_match_vlan', FlowerMatchVLAN, "Checks basic flower vlan match capabilities"),
             ('flower_match_vlan_cfi', FlowerMatchVLANCFI, "Checks basic flower vlan with CFI set match capabilities"),
             ('flower_match_ipv4', FlowerMatchIPv4, "Checks basic flower ipv4 match capabilities"),
             ('flower_match_ipv6', FlowerMatchIPv6, "Checks basic flower ipv6 match capabilities"),
             ('flower_match_tcp', FlowerMatchTCP, "Checks basic flower tcp match capabilities"),
             ('flower_match_ipv4_tcp_flags', FlowerMatchIPv4TCPFlag, "Checks flower ipv4 tcp flags match capabilities"),
             ('flower_match_ipv6_tcp_flags', FlowerMatchIPv6TCPFlag, "Checks flower ipv6 tcp flags match capabilities"),
             ('flower_match_udp', FlowerMatchUDP, "Checks basic flower udp match capabilities"),
             ('flower_match_mpls', FlowerMatchMPLS, "Checks basic flower mpls match capabilities"),
             ('flower_match_ttl', FlowerMatchTTL, "Checks basic flower ttl match capabilities"),
             ('flower_match_tos', FlowerMatchTOS, "Checks basic flower tos match capabilities"),
             ('flower_match_frag_ipv4', FlowerMatchFragIPv4, "Checks basic flower fragmentation for IPv4 match capabilities"),
             ('flower_match_frag_ipv6', FlowerMatchFragIPv6, "Checks basic flower fragmentation for IPv6 match capabilities"),
             ('flower_match_gre', FlowerMatchGRE, "Checks basic flower gre match capabilities"),
             ('flower_match_vxlan', FlowerMatchVXLAN, "Checks basic flower vxlan match capabilities"),
             ('flower_match_geneve', FlowerMatchGeneve, "Checks basic flower Geneve match capabilities"),
             ('flower_match_geneve_opt', FlowerMatchGeneveOpt, "Checks flower Geneve option match capabilities"),
             ('flower_match_geneve_multi_opt', FlowerMatchGeneveMultiOpt, "Checks flower Genevei with multiple options match capabilities"),
             ('flower_match_block', FlowerMatchBlock, "Checks basic flower block match capabilities"),
             ('flower_match_tunnel_to_shared_mac', FlowerMatchTunnelToSharedMAC, "Checks tunnel decap when MACs are shared across ports"),
             ('flower_modify_mtu', FlowerModifyMTU, "Checks the setting of a mac repr MTU"),
             ('flower_match_whitelist', FlowerMatchWhitelist, "Checks basic flower match whitelisting"),
             ('flower_vxlan_whitelist', FlowerVxlanWhitelist, "Checks that unsupported vxlan rules are not offloaded"),
             ('flower_csum_whitelist', FlowerCsumWhitelist, "Checks that unsupported checksum rules are not offloaded"),
             ('flower_action_push_vlan', FlowerActionPushVLAN, "Checks basic flower push vlan action capabilities"),
             ('flower_action_pop_vlan', FlowerActionPopVLAN, "Checks basic flower pop vlan action capabilities"),
             ('flower_action_encap_vxlan', FlowerActionVXLAN, "Checks basic flower vxlan encapsulation action capabilities"),
             ('flower_action_encap_vxlan_merge', FlowerActionMergeVXLAN, "Checks basic flower vxlan encapsulation action when IP is on internal port (via merge)"),
             ('flower_action_encap_geneve', FlowerActionGENEVE, "Checks basic flower geneve encapsulation action capabilities"),
             ('flower_action_encap_geneve_opt', FlowerActionGENEVEOpt, "Checks flower geneve encap opt action capabilities"),
             ('flower_action_encap_geneve_multi_opt', FlowerActionGENEVEMultiOpt, "Checks flower geneve encap opt action capabilities"),
             ('flower_action_set_ether', FlowerActionSetEth, "Checks basic flower set ethernet action capabilities"),
             ('flower_action_set_ipv4', FlowerActionSetIPv4, "Checks basic flower set IPv4 action capabilities"),
             ('flower_action_set_ipv4_ttl_tos', FlowerActionSetIPv4TTLTOS, "Checks basic flower set IPv4 TTL/TOS action capabilities"),
             ('flower_action_set_ipv6', FlowerActionSetIPv6, "Checks basic flower set IPv6 action capabilities"),
             ('flower_action_set_ipv6_hl_fl', FlowerActionSetIPv6HopLimitFlowLabel, "Checks basic flower set Hop Limit and Flow Label IPv6 action capabilities"),
             ('flower_action_set_udp', FlowerActionSetUDP, "Checks basic flower set UDP action capabilities"),
             ('flower_action_set_tcp', FlowerActionSetTCP, "Checks basic flower set TCP action capabilities"),
             ('flower_action_set_multi', FlowerActionSetMulti, "Checks multiple flower set action capabilities"),
             ('flower_vlan_repr', FlowerVlanRepr, "Checks that unsupported vxlan rules are not offloaded"),
             ('flower_repr_linkstate', FlowerReprLinkstate, "Checks that repr link state is handled correctly"),
             ('flower_bond_egress', FlowerActionBondEgress, "Checks egressing to a linux bond"),
             ('flower_ingress_rate_limit', FlowerActionIngressRateLimit, "Checks ingress rate limiting capabilities"),
             ('flower_max_entries', FlowerMaxEntries, "Checks that maximum entries can be installed"),
        )

        for t in T:
            self._tests[t[0]] = t[1](src, dut, self, t[0], t[2])

class FlowerBase(CommonTest):
    def __init__(self, *args, **kwargs):
        super(FlowerBase, self).__init__(*args, **kwargs)

        self.ipv4_mc_mac = []
        self.ipv6_mc_mac = []
        #01-00-5E-00-00-00 through 01-00-5E-00-00-FF for IPv4 Multicast
        #33-33-00-00-00-00 through 33-33-FF-00-00-FF for IPv6 Multicast
        for end_octet in range(0, 255):
            self.ipv4_mc_mac.append('01:00:5E:00:00:%02X' % end_octet)
            self.ipv6_mc_mac.append('33:33:FF:00:00:%02X' % end_octet)

    def check_src_flower_fw(self, ingress):
        ethtool_fields = self.src.ethtool_drvinfo(ingress)
        if 'nfp' not in ethtool_fields['driver'] or \
           'flower' not in ethtool_fields['firmware-version']:
            return False

        if not ingress[:-1].endswith('np') or not ingress.startswith('en'):
            raise NtiSkip('Cannot determine PF interface name')

        return True

    def configure_vlan_flower(self, vlan_id):
        M = self.dut
        iface = self.dut_ifn[0]
        ret, _ = self.dut.cmd('cat /sys/class/net/%s/phys_port_name' % (iface), fail=False)
        if ret:
            raise NtiError('interface %s is not a valid port' % iface)

        vlan_iface = '%s.%s' % (iface, vlan_id)
        # The length of the interface name will increase, we need to be
        # sure it does not increase beyond IFNAMSIZ.
        if len(vlan_iface) > 15:
            raise NtiSkip('Creating %s as a vlan interface exceeds IFNAMSIZ' % vlan_iface)

        self.dut.cmd('ip link add link %s name %s type vlan id %s' % (iface, vlan_iface, vlan_id), fail=False)
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
        if self.check_src_flower_fw(ingress):
            pf_ifname = ingress[:-3]
            self.src.cmd('ip link set dev %s up' % (pf_ifname), fail=False)

        M.refresh()
        return iface, ingress

    def cleanup_flower(self, iface):
        M = self.dut
        M.cmd('tc qdisc del dev %s handle ffff: ingress' % iface, fail=False)
        M.refresh()

    def add_egress_qdisc(self, iface):
        M = self.dut
        M.cmd('tc qdisc del dev %s handle ffff: ingress' % iface, fail=False)
        M.cmd('tc qdisc add dev %s handle ffff: ingress' % iface)
        M.refresh()

    def check_prereq(self, check, description, on_src=False):
        if on_src:
            res, _ = self.src.cmd(check, fail=False)
        else:
            res, _ = self.dut.cmd(check, fail=False)

        if res == 1:
            if on_src:
                raise NtiSkip('SRC does not support feature: %s' % description)
            else:
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

    def test_filter(self, interface, ingress, pkt, exp_pkt, exp_cnt,
                    pkt_len_diff=0, fltr='', new_port=0):
        pcap_src = self.prep_pcap_simple_to_list(pkt)

        if exp_pkt != None:
            exp_pkt = str(exp_pkt)

        self.test_with_traffic(pcap_src, exp_pkt,
                               (self.src, ingress, self.src),
                               port=new_port, filter_overwrite=fltr)

        exp_bytes = (len(pkt) + len(Ether()) + pkt_len_diff) * exp_cnt
        lo_exp_cnt = exp_cnt - 10
        lo_exp_exp_bytes = (len(pkt) + len(Ether()) + pkt_len_diff) * (exp_cnt - 10)
        stats = self.dut.netifs[interface].stats(get_tc_ing=True)
        if int(stats.tc_ing['tc_49152_pkts']) < lo_exp_cnt or int(stats.tc_ing['tc_49152_pkts']) > exp_cnt:
            raise NtiError('Counter missmatch. Expected: %s, Got: %s' % (exp_cnt, stats.tc_ing['tc_49152_pkts']))
        if int(stats.tc_ing['tc_49152_bytes']) < lo_exp_exp_bytes or int(stats.tc_ing['tc_49152_bytes']) > exp_bytes:
            raise NtiError('Counter missmatch. Expected: %s, Got: %s' % (exp_bytes, stats.tc_ing['tc_49152_bytes']))

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

    def capture_packs_multiple_ifaces(self, iface, sending_port, ingress_list,
                                      send_pkt, pack_dump_list, dump_filter='',
                                      loop=100, snaplen=8192, wait=2):
        active_tcpdumps = []
        A = self.src
        assert len(ingress_list) == len(pack_dump_list)

        dump = 0
        for ing in ingress_list:
            dump_src = os.path.join(self.src.tmpdir, 'dump_%s_src' % (dump))
            stderr = os.path.join(A.tmpdir, 'tcpdump_%s_err.txt' % ing)
            dump_inst = TCPDump(A, ing, dump_src, resolve=False,
                                direction='in', stderrfn=stderr,
                                filter_expr=dump_filter, snaplen=snaplen)
            dump_inst.start(wait)
            active_tcpdumps.append(dump_inst)
            dump += 1

        sleep(5)
        self.send_packs(iface, sending_port, send_pkt, loop)
        sleep(5)
        # It would be preferred to traverse the list of tcpdumps,
        # but the stop function calls killall, so we only need 1.
        # Hopefully in the future we will be able to kill only the
        # selected tcpdump.
        dump_inst.stop(wait)
        dump = 0
        for ing in ingress_list:
            dump_src = os.path.join(self.src.tmpdir, 'dump_%s_src' % (dump))
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
    def execute(self):
        iface, ingress = self.configure_flower()

        # Hit test
        match = 'ip flower dst_mac %s' % self.ipv4_mc_mac[0]
        action = 'mirred egress redirect dev %s' % iface
        self.install_filter(iface, match, action)

        pkt = Ether(src=self.group.hwaddr_x[0],dst=self.ipv4_mc_mac[0])/\
              IP()/TCP()/Raw('\x00'*64)
        self.test_filter(iface, ingress, pkt, pkt, 100)

        self.cleanup_filter(iface)

        # Miss test
        match = 'ip flower dst_mac 02:42:42:42:42:42'
        action = 'mirred egress redirect dev %s' % iface
        self.install_filter(iface, match, action)

        pkt = Ether(src=self.group.hwaddr_x[0],dst=self.ipv4_mc_mac[0])/\
              IP()/TCP()/Raw('\x00'*64)
        self.test_filter(iface, ingress, pkt, None, 0)

        self.cleanup_filter(iface)

    def cleanup(self):
        self.cleanup_flower(self.dut_ifn[0])
        return super(FlowerMatchMAC, self).cleanup()

class FlowerMatchVLAN(FlowerBase):
    def execute(self):
        iface, ingress = self.configure_flower()

        # Hit test
        match = '802.1Q flower vlan_id 100 vlan_prio 6'
        action = 'mirred egress redirect dev %s' % iface
        self.install_filter(iface, match, action)

        pkt = Ether(src=self.group.hwaddr_x[0],dst=self.ipv4_mc_mac[0])/\
              Dot1Q(vlan=100, prio=6)/IP()/TCP()/Raw('\x00'*64)
        self.test_filter(iface, ingress, pkt, pkt, 100)

        self.cleanup_filter(iface)

        # Miss test
        match = '802.1Q flower vlan_id 400 vlan_prio 0'
        action = 'mirred egress redirect dev %s' % iface
        self.install_filter(iface, match, action)

        pkt = Ether(src=self.group.hwaddr_x[0],dst=self.ipv4_mc_mac[0])/\
              Dot1Q(vlan=100, prio=0)/IP()/TCP()/Raw('\x00'*64)
        self.test_filter(iface, ingress, pkt, None, 0)

        self.cleanup_filter(iface)

        # Hit test
        match = '802.1Q flower vlan_id 0'
        action = 'mirred egress redirect dev %s' % iface
        self.install_filter(iface, match, action)

        pkt = Ether(src=self.group.hwaddr_x[0],dst=self.ipv4_mc_mac[0])/\
              Dot1Q(vlan=0)/IP()/TCP()/Raw('\x00'*64)
        self.test_filter(iface, ingress, pkt, pkt, 100)

        self.cleanup_filter(iface)

        # Miss test
        match = '802.1Q flower vlan_id 0'
        action = 'mirred egress redirect dev %s' % iface
        self.install_filter(iface, match, action)

        pkt = Ether(src=self.group.hwaddr_x[0],dst=self.ipv4_mc_mac[0])/\
              Dot1Q(vlan=100)/IP()/TCP()/Raw('\x00'*64)
        self.test_filter(iface, ingress, pkt, None, 0)

        self.cleanup_filter(iface)

    def cleanup(self):
        self.cleanup_flower(self.dut_ifn[0])
        return super(FlowerMatchVLAN, self).cleanup()

class FlowerMatchVLANCFI(FlowerBase):
    def execute(self):
        iface, ingress = self.configure_flower()

        # Hit test
        match = '802.1Q flower vlan_id 100 vlan_prio 6'
        action = 'mirred egress redirect dev %s' % iface
        self.install_filter(iface, match, action)

        #In Scapy id is the 12th -bit (i.e. the DEI/CFI bit)
        pkt = Ether(src=self.group.hwaddr_x[0],dst=self.ipv4_mc_mac[0])/\
              Dot1Q(vlan=100, prio=6, id=1)/IP()/TCP()/Raw('\x00'*64)
        self.test_filter(iface, ingress, pkt, pkt, 100)

        self.cleanup_filter(iface)

        # Miss test
        match = '802.1Q flower vlan_id 400 vlan_prio 0'
        action = 'mirred egress redirect dev %s' % iface
        self.install_filter(iface, match, action)

        pkt = Ether(src=self.group.hwaddr_x[0],dst=self.ipv4_mc_mac[0])/\
              Dot1Q(vlan=100, prio=0, id=1)/IP()/TCP()/Raw('\x00'*64)
        self.test_filter(iface, ingress, pkt, None, 0)

        self.cleanup_filter(iface)

        # Hit test
        match = '802.1Q flower vlan_id 0'
        action = 'mirred egress redirect dev %s' % iface
        self.install_filter(iface, match, action)

        pkt = Ether(src=self.group.hwaddr_x[0],dst=self.ipv4_mc_mac[0])/\
              Dot1Q(vlan=0, id=1)/IP()/TCP()/Raw('\x00'*64)
        self.test_filter(iface, ingress, pkt, pkt, 100)

        self.cleanup_filter(iface)

        # Miss test
        match = '802.1Q flower vlan_id 0'
        action = 'mirred egress redirect dev %s' % iface
        self.install_filter(iface, match, action)

        pkt = Ether(src=self.group.hwaddr_x[0],dst=self.ipv4_mc_mac[0])/\
              Dot1Q(vlan=100, id=1)/IP()/TCP()/Raw('\x00'*64)
        self.test_filter(iface, ingress, pkt, None, 0)

        self.cleanup_filter(iface)

    def cleanup(self):
        self.cleanup_flower(self.dut_ifn[0])
        return super(FlowerMatchVLANCFI, self).cleanup()

class FlowerMatchVLANID(FlowerBase):
    def execute(self):
        iface, ingress = self.configure_flower()

        # Hit test
        match = '802.1Q flower vlan_id 600'
        action = 'mirred egress redirect dev %s' % iface
        self.install_filter(iface, match, action)

        pkt = Ether(src=self.group.hwaddr_x[0],dst=self.ipv4_mc_mac[0])/\
              Dot1Q(vlan=600)/IP()/TCP()/Raw('\x00'*64)
        self.test_filter(iface, ingress, pkt, pkt, 100)

        self.cleanup_filter(iface)

        # Miss test
        match = '802.1Q flower vlan_id 1200'
        action = 'mirred egress redirect dev %s' % iface
        self.install_filter(iface, match, action)

        pkt = Ether(src=self.group.hwaddr_x[0],dst=self.ipv4_mc_mac[0])/\
              Dot1Q(vlan=600)/IP()/TCP()/Raw('\x00'*64)
        self.test_filter(iface, ingress, pkt, None, 0)

        self.cleanup_filter(iface)

    def cleanup(self):
        self.cleanup_flower(self.dut_ifn[0])
        return super(FlowerMatchVLANID, self).cleanup()

class FlowerMatchVLANPCP(FlowerBase):
    def execute(self):
        iface, ingress = self.configure_flower()

        # Hit test
        match = '802.1Q flower vlan_prio 3'
        action = 'mirred egress redirect dev %s' % iface
        self.install_filter(iface, match, action)

        pkt = Ether(src=self.group.hwaddr_x[0],dst=self.ipv4_mc_mac[0])/\
              Dot1Q(vlan=200, prio=3)/IP()/TCP()/Raw('\x00'*64)
        self.test_filter(iface, ingress, pkt, pkt, 100)

        self.cleanup_filter(iface)

        # Miss test
        match = '802.1Q flower vlan_prio 2'
        action = 'mirred egress redirect dev %s' % iface
        self.install_filter(iface, match, action)

        pkt = Ether(src=self.group.hwaddr_x[0],dst=self.ipv4_mc_mac[0])/\
              Dot1Q(vlan=200, prio=3)/IP()/TCP()/Raw('\x00'*64)
        self.test_filter(iface, ingress, pkt, None, 0)

        self.cleanup_filter(iface)

    def cleanup(self):
        self.cleanup_flower(self.dut_ifn[0])
        return super(FlowerMatchVLANPCP, self).cleanup()

class FlowerMatchIPv4(FlowerBase):
    def execute(self):
        iface, ingress = self.configure_flower()

        # Hit test
        match = 'ip flower dst_ip 11.0.0.11'
        action = 'mirred egress redirect dev %s' % iface
        self.install_filter(iface, match, action)

        pkt = Ether(src=self.group.hwaddr_x[0],dst=self.ipv4_mc_mac[0])/\
              IP(src='10.0.0.10', dst='11.0.0.11')/TCP()/Raw('\x00'*64)
        self.test_filter(iface, ingress, pkt, pkt, 100)

        self.cleanup_filter(iface)

        # Miss test
        match = 'ip flower dst_ip 22.0.0.22'
        action = 'mirred egress redirect dev %s' % iface
        self.install_filter(iface, match, action)

        pkt = Ether(src=self.group.hwaddr_x[0],dst=self.ipv4_mc_mac[0])/\
              IP(src='10.0.0.10', dst='11.0.0.11')/TCP()/Raw('\x00'*64)
        self.test_filter(iface, ingress, pkt, None, 0)

        self.cleanup_filter(iface)

    def cleanup(self):
        self.cleanup_flower(self.dut_ifn[0])
        return super(FlowerMatchIPv4, self).cleanup()

class FlowerMatchIPv6(FlowerBase):
    def execute(self):
        iface, ingress = self.configure_flower()
        new_filter = '"not arp and' \
                     ' not udp port 5353 and' \
                     ' not ether host 01:80:c2:00:00:0e and' \
                     ' not ether host ff:ff:ff:ff:ff:ff"'

        # Hit test
        match = 'ipv6 flower dst_ip 11::11'
        action = 'mirred egress redirect dev %s' % iface
        self.install_filter(iface, match, action)

        pkt = Ether(src=self.group.hwaddr_x[0],dst=self.ipv6_mc_mac[0])/\
              IPv6(src='10::10', dst='11::11')/TCP()/Raw('\x00'*64)
        self.test_filter(iface, ingress, pkt, pkt, 100, fltr=new_filter)

        self.cleanup_filter(iface)

        # Miss test
        match = 'ipv6 flower dst_ip 22::22'
        action = 'mirred egress redirect dev %s' % iface
        self.install_filter(iface, match, action)

        pkt = Ether(src=self.group.hwaddr_x[0],dst=self.ipv6_mc_mac[0])/\
              IPv6(src='10::10', dst='11::11')/TCP()/Raw('\x00'*64)
        self.test_filter(iface, ingress, pkt, None, 0, fltr=new_filter)

        self.cleanup_filter(iface)

    def cleanup(self):
        self.cleanup_flower(self.dut_ifn[0])
        return super(FlowerMatchIPv6, self).cleanup()

class FlowerMatchTCP(FlowerBase):
    def execute(self):
        iface, ingress = self.configure_flower()

        # Hit test
        match = 'ip flower ip_proto tcp dst_port 2000'
        action = 'mirred egress redirect dev %s' % iface
        self.install_filter(iface, match, action)

        pkt = Ether(src=self.group.hwaddr_x[0],dst=self.ipv4_mc_mac[0])/\
              IP(src='10.0.0.10', dst='11.0.0.11')/\
              TCP(dport=2000)/Raw('\x00'*64)
        self.test_filter(iface, ingress, pkt, pkt, 100)

        self.cleanup_filter(iface)

        # Miss test - miss on port number
        match = 'ip flower ip_proto tcp dst_port 4000'
        action = 'mirred egress redirect dev %s' % iface
        self.install_filter(iface, match, action)

        pkt = Ether(src=self.group.hwaddr_x[0],dst=self.ipv4_mc_mac[0])/\
              IP(src='10.0.0.10', dst='11.0.0.11')/\
              TCP(dport=2000)/Raw('\x00'*64)
        self.test_filter(iface, ingress, pkt, None, 0)

        self.cleanup_filter(iface)

        # Miss test - miss on prototype
        match = 'ip flower ip_proto tcp dst_port 2000'
        action = 'mirred egress redirect dev %s' % iface
        self.install_filter(iface, match, action)

        pkt = Ether(src=self.group.hwaddr_x[0],dst=self.ipv4_mc_mac[0])/\
              IP(src='10.0.0.10', dst='11.0.0.11')/\
              UDP(dport=2000)/Raw('\x00'*64)
        self.test_filter(iface, ingress, pkt, None, 0)

        self.cleanup_filter(iface)

    def cleanup(self):
        self.cleanup_flower(self.dut_ifn[0])
        return super(FlowerMatchTCP, self).cleanup()

class FlowerMatchIPv4TCPFlag(FlowerBase):
    def test(self, flags, offload):
        iface, ingress = self.configure_flower()

        match = 'ip flower ip_proto tcp tcp_flags ' + hex(flags)
        action = 'mirred egress redirect dev %s' % iface
        self.install_filter(iface, match, action, offload)

        if offload:
            pkt = Ether(src=self.group.hwaddr_x[0],dst=self.ipv4_mc_mac[0])/\
                  IP(src='10.0.0.10', dst='11.0.0.11')/\
                  TCP(flags=flags)/Raw('\x00'*64)
            self.test_filter(iface, ingress, pkt, pkt, 100)

        self.cleanup_filter(iface)

    def execute(self):
        offload = [1, 2, 3, 4, 5, 6, 7, 9, 10, 12, 33, 34, 36]
        non_offload = [8, 16, 17, 22, 32, 64, 128]

        for flags in offload:
            self.test(flags, True)

        for flags in non_offload:
            self.test(flags, False)

    def cleanup(self):
        self.cleanup_flower(self.dut_ifn[0])
        return super(FlowerMatchIPv4TCPFlag, self).cleanup()

class FlowerMatchIPv6TCPFlag(FlowerBase):
    def test(self, flags, offload):
        iface, ingress = self.configure_flower()
        new_filter = '"not arp and' \
                     ' not udp port 5353 and' \
                     ' not ether host 01:80:c2:00:00:0e and' \
                     ' not ether host ff:ff:ff:ff:ff:ff"'

        match = 'ipv6 flower ip_proto tcp tcp_flags ' + hex(flags)
        action = 'mirred egress redirect dev %s' % iface
        self.install_filter(iface, match, action, offload)

        if offload:
            pkt = Ether(src=self.group.hwaddr_x[0],dst=self.ipv6_mc_mac[0])/\
                  IPv6(src='10::10', dst='11::11')/\
                  TCP(flags=flags)/Raw('\x00'*64)
            self.test_filter(iface, ingress, pkt, pkt, 100, fltr=new_filter)

        self.cleanup_filter(iface)

    def execute(self):
        offload = [1, 2, 3, 4, 5, 6, 7, 9, 10, 12, 33, 34, 36]
        non_offload = [8, 16, 17, 22, 32, 64, 128]

        for flags in offload:
            self.test(flags, True)

        for flags in non_offload:
            self.test(flags, False)

    def cleanup(self):
        self.cleanup_flower(self.dut_ifn[0])
        return super(FlowerMatchIPv6TCPFlag, self).cleanup()

class FlowerMatchUDP(FlowerBase):
    def execute(self):
        iface, ingress = self.configure_flower()

        # Hit test
        match = 'ip flower ip_proto udp dst_port 4000'
        action = 'mirred egress redirect dev %s' % iface
        self.install_filter(iface, match, action)

        pkt = Ether(src=self.group.hwaddr_x[0],dst=self.ipv4_mc_mac[0])/\
              IP(src='10.0.0.10', dst='11.0.0.11')/\
              UDP(dport=4000)/Raw('\x00'*64)
        self.test_filter(iface, ingress, pkt, pkt, 100)

        self.cleanup_filter(iface)

        # Miss test - miss on port number
        match = 'ip flower ip_proto udp dst_port 2000'
        action = 'mirred egress redirect dev %s' % iface
        self.install_filter(iface, match, action)

        pkt = Ether(src=self.group.hwaddr_x[0],dst=self.ipv4_mc_mac[0])/\
              IP(src='10.0.0.10', dst='11.0.0.11')/\
              UDP(dport=4000)/Raw('\x00'*64)
        self.test_filter(iface, ingress, pkt, None, 0)

        self.cleanup_filter(iface)

        # Miss test - miss on prototype
        match = 'ip flower ip_proto udp dst_port 4000'
        action = 'mirred egress redirect dev %s' % iface
        self.install_filter(iface, match, action)

        pkt = Ether(src=self.group.hwaddr_x[0],dst=self.ipv4_mc_mac[0])/\
              IP(src='10.0.0.10', dst='11.0.0.11')/\
              TCP(dport=4000)/Raw('\x00'*64)
        self.test_filter(iface, ingress, pkt, None, 0)

        self.cleanup_filter(iface)

    def cleanup(self):
        self.cleanup_flower(self.dut_ifn[0])
        return super(FlowerMatchUDP, self).cleanup()

class FlowerMatchGRE(FlowerBase):
    def execute(self):
        iface, ingress = self.configure_flower()
        M = self.dut
        A = self.src

        src_ip = self.src_addr[0].split('/')[0]
        dut_ip = self.dut_addr[0].split('/')[0]

        _, src_mac = A.cmd('cat /sys/class/net/%s/address | tr -d "\n"' % self.src_ifn[0])
        _, dut_mac = M.cmd('cat /sys/class/net/%s/address | tr -d "\n"' % self.dut_ifn[0])

        M.cmd('ip link del dev gre1', fail=False)
        M.cmd('ip link add gre1 type gretap remote %s local %s dev %s external' % (src_ip, dut_ip, self.dut_ifn[0]))
        M.cmd('ifconfig gre1 up')

        self.add_egress_qdisc('gre1')

        # Hit test - match all vxlan fields and decap
        match = 'ip flower enc_src_ip %s enc_dst_ip %s enc_key_id 321' % (src_ip, dut_ip)
        action = 'mirred egress redirect dev %s' % iface
        self.install_filter('gre1', match, action)

        ## Packet based on genve fields
        enc_pkt = Ether(src=self.group.hwaddr_x[0],dst=self.ipv4_mc_mac[0])/\
                  IP()/TCP()/Raw('\x00'*64)
        pkt = Ether(src=src_mac,dst=dut_mac)/\
              IP(src=src_ip, dst=dut_ip, tos=30, ttl=99, proto=47)/\
              GRE(proto=0x6558, key_present=1, key=321)/enc_pkt
        pkt_diff = len(Ether()) + len(IP()) + 8
        self.test_filter('gre1', ingress, pkt, enc_pkt, 100, -pkt_diff)

        self.cleanup_filter('gre1')

        # Miss test - incorrect enc ip src
        match = 'ip flower enc_src_ip 1.1.1.1 enc_dst_ip %s enc_key_id 321' % (dut_ip)
        action = 'mirred egress redirect dev %s' % iface
        self.install_filter('gre1', match, action)

        self.test_filter('gre1', ingress, pkt, None, 0)

        self.cleanup_filter('gre1')

        # Miss test - incorrect enc ip dst
        match = 'ip flower enc_src_ip %s enc_dst_ip 1.1.1.1 enc_key_id 321' % (src_ip)
        action = 'mirred egress redirect dev %s' % iface
        self.install_filter('gre1', match, action)

        self.test_filter('gre1', ingress, pkt, None, 0)

        self.cleanup_filter('gre1')

        # Miss test - incorrect tunnel key
        match = 'ip flower enc_src_ip %s enc_dst_ip %s enc_key_id 322' % (src_ip, dut_ip)
        action = 'mirred egress redirect dev %s' % iface
        self.install_filter('gre1', match, action)

        self.test_filter('gre1', ingress, pkt, None, 0)

        self.cleanup_filter('gre1')

        # Tunnel ToS and TTL matching are added in kernel 4.19
        if self.dut.kernel_ver_ge(4, 19):
            # Match on correct tunnel ToS and TTL
            match = 'ip flower enc_src_ip %s enc_dst_ip %s enc_tos 30 enc_ttl 99' % (src_ip, dut_ip)
            action = 'mirred egress redirect dev %s' % iface
            self.install_filter('gre1', match, action)

            self.test_filter('gre1', ingress, pkt, enc_pkt, 100, -pkt_diff)
            self.cleanup_filter('gre1')

            # Miss test - incorrect ToS
            match = 'ip flower enc_src_ip %s enc_dst_ip %s enc_tos 50 enc_ttl 99' % (src_ip, dut_ip)
            action = 'mirred egress redirect dev %s' % iface
            self.install_filter('gre1', match, action)

            self.test_filter('gre1', ingress, pkt, None, 0)
            self.cleanup_filter('gre1')

            # Miss test - incorrect TTL
            match = 'ip flower enc_src_ip %s enc_dst_ip %s enc_tos 30 enc_ttl 100' % (src_ip, dut_ip)
            action = 'mirred egress redirect dev %s' % iface
            self.install_filter('gre1', match, action)

            self.test_filter('gre1', ingress, pkt, None, 0)
            self.cleanup_filter('gre1')

    def cleanup(self):
        self.cleanup_flower('gre1')
        self.dut.cmd('ip link del gre1', fail=False)
        return super(FlowerMatchGRE, self).cleanup()

class FlowerMatchVXLAN(FlowerBase):
    def execute(self):
        iface, ingress = self.configure_flower()
        M = self.dut
        A = self.src

        src_ip = self.src_addr[0].split('/')[0]
        dut_ip = self.dut_addr[0].split('/')[0]

        _, src_mac = A.cmd('cat /sys/class/net/%s/address | tr -d "\n"' % self.src_ifn[0])
        _, dut_mac = M.cmd('cat /sys/class/net/%s/address | tr -d "\n"' % self.dut_ifn[0])

        M.cmd('ip link delete vxlan0', fail=False)
        M.cmd('ip link add vxlan0 type vxlan dstport 4789 dev %s external' % self.dut_ifn[0])
        M.cmd('ifconfig vxlan0 up')

        self.add_egress_qdisc('vxlan0')

        # Hit test - match all vxlan fields and decap
        match = 'ip flower enc_src_ip %s enc_dst_ip %s enc_dst_port 4789 enc_key_id 123' % (src_ip, dut_ip)
        action = 'mirred egress redirect dev %s' % iface
        self.install_filter('vxlan0', match, action)

        # VXLAN header with VNI 123, ToS 30, and TTL  99
        vxlan_header = '\x08\x00\x00\x00\x00\x00\x7b\x00'
        enc_pkt = Ether(src=self.group.hwaddr_x[0],dst=self.ipv4_mc_mac[0])/\
                  IP()/TCP()/Raw('\x00'*64)
        vxlan_header += str(enc_pkt)
        pkt = Ether(src=src_mac,dst=dut_mac)/\
              IP(src=src_ip, dst=dut_ip, tos=30, ttl=99)/\
              UDP(sport=44534, dport=4789)/vxlan_header
        pkt_diff = len(Ether()) + len(IP()) + len(UDP()) + 8
        self.test_filter('vxlan0', ingress, pkt, enc_pkt, 100, -pkt_diff)

        self.cleanup_filter('vxlan0')

        # Miss test - incorrect enc ip src
        match = 'ip flower enc_src_ip 1.1.1.1 enc_dst_ip %s enc_dst_port 4789 enc_key_id 123' % (dut_ip)
        action = 'mirred egress redirect dev %s' % iface
        self.install_filter('vxlan0', match, action)

        self.test_filter('vxlan0', ingress, pkt, None, 0)

        self.cleanup_filter('vxlan0')

        # Miss test - incorrect enc ip dst
        match = 'ip flower enc_src_ip %s enc_dst_ip 1.1.1.1 enc_dst_port 4789 enc_key_id 123' % (src_ip)
        action = 'mirred egress redirect dev %s' % iface
        self.install_filter('vxlan0', match, action)

        self.test_filter('vxlan0', ingress, pkt, None, 0)

        self.cleanup_filter('vxlan0')

        # Miss test - incorrect VNI
        match = 'ip flower enc_src_ip %s enc_dst_ip %s enc_dst_port 4789 enc_key_id 124' % (src_ip, dut_ip)
        action = 'mirred egress redirect dev %s' % iface
        self.install_filter('vxlan0', match, action)

        self.test_filter('vxlan0', ingress, pkt, None, 0)

        self.cleanup_filter('vxlan0')

        # Tunnel ToS and TTL matching are added in kernel 4.19
        if self.dut.kernel_ver_ge(4, 19):
            # Match on correct tunnel ToS and TTL
            match = 'ip flower enc_src_ip %s enc_dst_ip %s enc_dst_port 4789 enc_tos 30 enc_ttl 99' % (src_ip, dut_ip)
            action = 'mirred egress redirect dev %s' % iface
            self.install_filter('vxlan0', match, action)

            self.test_filter('vxlan0', ingress, pkt, enc_pkt, 100, -pkt_diff)
            self.cleanup_filter('vxlan0')

            # Miss test - incorrect ToS
            match = 'ip flower enc_src_ip %s enc_dst_ip %s enc_dst_port 4789 enc_tos 50 enc_ttl 99' % (src_ip, dut_ip)
            action = 'mirred egress redirect dev %s' % iface
            self.install_filter('vxlan0', match, action)

            self.test_filter('vxlan0', ingress, pkt, None, 0)
            self.cleanup_filter('vxlan0')

            # Miss test - incorrect TTL
            match = 'ip flower enc_src_ip %s enc_dst_ip %s enc_dst_port 4789 enc_tos 30 enc_ttl 100' % (src_ip, dut_ip)
            action = 'mirred egress redirect dev %s' % iface
            self.install_filter('vxlan0', match, action)

            self.test_filter('vxlan0', ingress, pkt, None, 0)
            self.cleanup_filter('vxlan0')

    def cleanup(self):
        self.cleanup_flower('vxlan0')
        self.dut.cmd('ip link del vxlan0', fail=False)
        return super(FlowerMatchVXLAN, self).cleanup()

class FlowerMatchGeneve(FlowerBase):
    def execute(self):
        iface, ingress = self.configure_flower()
        M = self.dut
        A = self.src

        src_ip = self.src_addr[0].split('/')[0]
        dut_ip = self.dut_addr[0].split('/')[0]

        _, src_mac = A.cmd('cat /sys/class/net/%s/address | tr -d "\n"' % self.src_ifn[0])
        _, dut_mac = M.cmd('cat /sys/class/net/%s/address | tr -d "\n"' % self.dut_ifn[0])

        M.cmd('ip link delete gene0', fail=False)
        M.cmd('ip link add gene0 type geneve dstport 6081 external')
        M.cmd('ifconfig gene0 up')

        self.add_egress_qdisc('gene0')

        # Hit test - match all geneve fields and decap
        match = 'ip flower enc_src_ip %s enc_dst_ip %s enc_dst_port 6081 enc_key_id 123' % (src_ip, dut_ip)
        action = 'mirred egress redirect dev %s' % iface
        self.install_filter('gene0', match, action)

        # Geneve header with VNI 123
        geneve_header = '\x00\x00\x65\x58\x00\x00\x7b\x00'
        enc_pkt = Ether(src=self.group.hwaddr_x[0],dst=self.ipv4_mc_mac[0])/\
                  IP()/TCP()/Raw('\x00'*64)
        geneve_header += str(enc_pkt)
        pkt = Ether(src=src_mac,dst=dut_mac)/IP(src=src_ip, dst=dut_ip)/UDP(sport=44534, dport=6081)/geneve_header
        pkt_diff = len(Ether()) + len(IP()) + len(UDP()) + 8
        self.test_filter('gene0', ingress, pkt, enc_pkt, 100, -pkt_diff)

        self.cleanup_filter('gene0')

        # Miss test - incorrect enc ip src
        match = 'ip flower enc_src_ip 1.1.1.1 enc_dst_ip %s enc_dst_port 6081 enc_key_id 123' % (dut_ip)
        action = 'mirred egress redirect dev %s' % iface
        self.install_filter('gene0', match, action)
        self.test_filter('gene0', ingress, pkt, None, 0)

        self.cleanup_filter('gene0')

        # Miss test - incorrect enc ip dst
        match = 'ip flower enc_src_ip %s enc_dst_ip 1.1.1.1 enc_dst_port 6081 enc_key_id 123' % (src_ip)
        action = 'mirred egress redirect dev %s' % iface
        self.install_filter('gene0', match, action)
        self.test_filter('gene0', ingress, pkt, None, 0)

        self.cleanup_filter('gene0')

        # Miss test - incorrect VNI
        match = 'ip flower enc_src_ip %s enc_dst_ip %s enc_dst_port 6081 enc_key_id 124' % (src_ip, dut_ip)
        action = 'mirred egress redirect dev %s' % iface
        self.install_filter('gene0', match, action)
        self.test_filter('gene0', ingress, pkt, None, 0)

        self.cleanup_filter('gene0')

    def cleanup(self):
        self.cleanup_flower('gene0')
        self.dut.cmd('ip link del gene0', fail=False)
        return super(FlowerMatchGeneve, self).cleanup()

class FlowerMatchGeneveOpt(FlowerBase):
    def hit_geneve_opt(self, iface, ingress, dut_ip, src_ip, dut_mac, src_mac, geneve_opt):
        tun_id = unpack('>hh', '\x00' + geneve_opt['vni_field'])[1]
        ver_opt_len = unpack('>h', '\x00' + geneve_opt['ver_opt_len'])[0]
        opt_class = unpack('>h', geneve_opt['opt_class'])[0]
        opt_type = unpack('>h', '\x00' + geneve_opt['opt_type'])[0]
        opt_len = str(len(geneve_opt['opt_data'])/4)
        opt_data = unpack('>' + opt_len + 'i', geneve_opt['opt_data'])
        tmp = ''
        for data in opt_data:
            tmp += hex(data)[2:]
        opt_data = tmp

        match = 'ip flower enc_src_ip %s enc_dst_ip %s enc_dst_port ' \
                '6081 enc_key_id %s geneve_opts %s:%s:%s' % \
                (src_ip, dut_ip, tun_id, hex(opt_class)[2:],
                hex(opt_type)[2:], opt_data)
        action = 'mirred egress redirect dev %s' % iface
        self.install_filter('gene0', match, action)

        geneve_opt_hd = geneve_opt['opt_class'] + geneve_opt['opt_type'] + \
                        geneve_opt['opt_len'] + geneve_opt['opt_data']
        geneve_header = geneve_opt['ver_opt_len'] + '\x00' + geneve_opt['protocol_type'] + \
                        geneve_opt['vni_field'] + '\x00' + geneve_opt_hd
        enc_pkt = Ether(src=self.group.hwaddr_x[0],dst=self.ipv4_mc_mac[0])/\
                  IP()/TCP()/Raw('\x00'*64)
        geneve_header += str(enc_pkt)
        pkt = Ether(src=src_mac,dst=dut_mac)/IP(src=src_ip, dst=dut_ip)/UDP(sport=44534, dport=6081)/geneve_header
        pkt_diff = len(Ether()) + len(IP()) + len(UDP()) + 8 + ver_opt_len * 4
        self.test_filter('gene0', ingress, pkt, enc_pkt, 100, -pkt_diff)

        self.cleanup_filter('gene0')

    def miss_geneve_opt(self, iface, ingress, dut_ip, src_ip, dut_mac, src_mac, geneve_opt):
        tun_id = unpack('>hh', '\x00' + geneve_opt['vni_field'])[1]
        opt_class = unpack('>h', geneve_opt['opt_class'])[0]
        opt_type = unpack('>h', '\x00' + geneve_opt['opt_type'])[0]
        opt_len = str(len(geneve_opt['opt_data'])/4)
        opt_data = 'ffffffff' * int(opt_len)

        match = 'ip flower enc_src_ip %s enc_dst_ip %s enc_dst_port ' \
                '6081 enc_key_id %s geneve_opts %s:%s:%s' % \
                (src_ip, dut_ip, tun_id, hex(opt_class)[2:],
                hex(opt_type)[2:], opt_data)
        action = 'mirred egress redirect dev %s' % iface
        self.install_filter('gene0', match, action)

        geneve_opt_hd = geneve_opt['opt_class'] + geneve_opt['opt_type'] + \
                        geneve_opt['opt_len'] + geneve_opt['opt_data']
        geneve_header = geneve_opt['ver_opt_len'] + '\x00' + geneve_opt['protocol_type'] + \
                        geneve_opt['vni_field'] + '\x00' + geneve_opt_hd
        enc_pkt = Ether(src=self.group.hwaddr_x[0],dst=self.ipv4_mc_mac[0])/\
                  IP()/TCP()/Raw('\x00'*64)
        geneve_header += str(enc_pkt)
        pkt = Ether(src=src_mac,dst=dut_mac)/IP(src=src_ip, dst=dut_ip)/UDP(sport=44534, dport=6081)/geneve_header
        self.test_filter('gene0', ingress, pkt, None, 0)

        self.cleanup_filter('gene0')

    def execute(self):
        iface, ingress = self.configure_flower()
        M = self.dut
        A = self.src

        src_ip = self.src_addr[0].split('/')[0]
        dut_ip = self.dut_addr[0].split('/')[0]

        _, src_mac = A.cmd('cat /sys/class/net/%s/address | tr -d "\n"' % self.src_ifn[0])
        _, dut_mac = M.cmd('cat /sys/class/net/%s/address | tr -d "\n"' % self.dut_ifn[0])

        M.cmd('ip link delete gene0', fail=False)
        M.cmd('ip link add gene0 type geneve dstport 6081 external')
        M.cmd('ifconfig gene0 up')

        self.add_egress_qdisc('gene0')

        geneve_opt = {'ver_opt_len': '\x02',
                      'protocol_type': '\x65\x58',
                      'vni_field' : '\x00\x00\x7b',
                      'opt_class' : '\x01\x02',
                      'opt_type' : '\x80',
                      'opt_len' : '\x01',
                      'opt_data' : '\x11\x22\x33\x44'}
        self.hit_geneve_opt(iface, ingress, dut_ip, src_ip, dut_mac, src_mac, geneve_opt)
        self.miss_geneve_opt(iface, ingress, dut_ip, src_ip, dut_mac, src_mac, geneve_opt)

        geneve_opt = {'ver_opt_len': '\x03',
                      'protocol_type': '\x65\x58',
                      'vni_field' : '\x00\x00\xEA',
                      'opt_class' : '\x04\x08',
                      'opt_type' : '\x12',
                      'opt_len' : '\x02',
                      'opt_data' : '\61\x62\x63\x64\x21\x22\x23\x24'}
        self.hit_geneve_opt(iface, ingress, dut_ip, src_ip, dut_mac, src_mac, geneve_opt)
        self.miss_geneve_opt(iface, ingress, dut_ip, src_ip, dut_mac, src_mac, geneve_opt)

        geneve_opt = {'ver_opt_len': '\x04',
                      'protocol_type': '\x65\x58',
                      'vni_field' : '\x00\x02\x37',
                      'opt_class' : '\x03\x06',
                      'opt_type' : '\x77',
                      'opt_len' : '\x03',
                      'opt_data' : '\x36\x27\x87\x42\x31\x32\x33\x44\x41\x42\x43\x44'}
        self.hit_geneve_opt(iface, ingress, dut_ip, src_ip, dut_mac, src_mac, geneve_opt)
        self.miss_geneve_opt(iface, ingress, dut_ip, src_ip, dut_mac, src_mac, geneve_opt)

    def cleanup(self):
        self.cleanup_flower('gene0')
        self.dut.cmd('ip link del gene0', fail=False)
        return super(FlowerMatchGeneveOpt, self).cleanup()

class FlowerMatchGeneveMultiOpt(FlowerBase):
    def geneve_opt_to_str(self, geneve_opt):
        ver_opt_len = unpack('>h', '\x00' + geneve_opt['ver_opt_len'])[0]
        opt_class = unpack('>h', geneve_opt['opt_class'])[0]
        opt_type = unpack('>h', '\x00' + geneve_opt['opt_type'])[0]
        opt_len = str(len(geneve_opt['opt_data'])/4)
        opt_data = unpack('>' + opt_len + 'i', geneve_opt['opt_data'])
        tmp = ''
        for data in opt_data:
            tmp += hex(data)[2:]
        opt_data = tmp

        return ('%s:%s:%s' % (hex(opt_class)[2:], hex(opt_type)[2:], opt_data))

    def hit_geneve_opt(self, iface, ingress, dut_ip, src_ip, dut_mac, src_mac, geneve_opt1, geneve_opt2):
        tun_id = unpack('>hh', '\x00' + geneve_opt1['vni_field'])[1]
        ver_opt_len1 = unpack('>h', '\x00' + geneve_opt1['ver_opt_len'])[0]
        ver_opt_len2 = unpack('>h', '\x00' + geneve_opt2['ver_opt_len'])[0]
        geneve1 = self.geneve_opt_to_str(geneve_opt1)
        geneve2 = self.geneve_opt_to_str(geneve_opt2)

        match = 'ip flower enc_src_ip %s enc_dst_ip %s enc_dst_port ' \
                '6081 enc_key_id %s geneve_opts %s,%s' % \
                (src_ip, dut_ip, tun_id, geneve1, geneve2)
        action = 'mirred egress redirect dev %s' % iface
        self.install_filter('gene0', match, action)

        opt_size = ver_opt_len1 + ver_opt_len2
        geneve_opt_hd = geneve_opt1['opt_class'] + geneve_opt1['opt_type'] + \
                        geneve_opt1['opt_len'] + geneve_opt1['opt_data']
        geneve_opt_hd += geneve_opt2['opt_class'] + geneve_opt2['opt_type'] + \
                        geneve_opt2['opt_len'] + geneve_opt2['opt_data']
        geneve_header = pack('h', opt_size) + geneve_opt1['protocol_type'] + \
                        geneve_opt1['vni_field'] + '\x00' + geneve_opt_hd
        enc_pkt = Ether(src=self.group.hwaddr_x[0],dst=self.ipv4_mc_mac[0])/\
                  IP()/TCP()/Raw('\x00'*64)
        geneve_header += str(enc_pkt)
        pkt = Ether(src=src_mac,dst=dut_mac)/IP(src=src_ip, dst=dut_ip)/UDP(sport=44534, dport=6081)/geneve_header
        pkt_diff = len(Ether()) + len(IP()) + len(UDP()) + 8 + opt_size * 4
        self.test_filter('gene0', ingress, pkt, enc_pkt, 100, -pkt_diff)

        self.cleanup_filter('gene0')

    def miss_geneve_opt(self, iface, ingress, dut_ip, src_ip, dut_mac, src_mac, geneve_opt1, geneve_opt2):
        tun_id = unpack('>hh', '\x00' + geneve_opt1['vni_field'])[1]
        ver_opt_len1 = unpack('>h', '\x00' + geneve_opt1['ver_opt_len'])[0]
        ver_opt_len2 = unpack('>h', '\x00' + geneve_opt2['ver_opt_len'])[0]
        miss_geneve_opt = copy(geneve_opt1)
        opt_class = unpack('>h', geneve_opt1['opt_class'])[0]
        miss_geneve_opt['opt_class'] = pack('>h',opt_class*2)
        geneve1 = self.geneve_opt_to_str(miss_geneve_opt)
        geneve2 = self.geneve_opt_to_str(geneve_opt2)

        match = 'ip flower enc_src_ip %s enc_dst_ip %s enc_dst_port ' \
                '6081 enc_key_id %s geneve_opts %s,%s' % \
                (src_ip, dut_ip, tun_id, geneve1, geneve2)
        action = 'mirred egress redirect dev %s' % iface
        self.install_filter('gene0', match, action)

        opt_size = ver_opt_len1 + ver_opt_len2
        geneve_opt_hd = geneve_opt1['opt_class'] + geneve_opt1['opt_type'] + \
                        geneve_opt1['opt_len'] + geneve_opt1['opt_data']
        geneve_opt_hd += geneve_opt2['opt_class'] + geneve_opt2['opt_type'] + \
                        geneve_opt2['opt_len'] + geneve_opt2['opt_data']
        geneve_header = pack('h', opt_size) + geneve_opt1['protocol_type'] + \
                        geneve_opt1['vni_field'] + '\x00' + geneve_opt_hd
        enc_pkt = Ether(src=self.group.hwaddr_x[0],dst=self.ipv4_mc_mac[0])/\
                  IP()/TCP()/Raw('\x00'*64)
        geneve_header += str(enc_pkt)
        pkt = Ether(src=src_mac,dst=dut_mac)/IP(src=src_ip, dst=dut_ip)/UDP(sport=44534, dport=6081)/geneve_header
        self.test_filter('gene0', ingress, pkt, None, 0)

        self.cleanup_filter('gene0')

    def execute(self):
        iface, ingress = self.configure_flower()
        M = self.dut
        A = self.src

        src_ip = self.src_addr[0].split('/')[0]
        dut_ip = self.dut_addr[0].split('/')[0]

        _, src_mac = A.cmd('cat /sys/class/net/%s/address | tr -d "\n"' % self.src_ifn[0])
        _, dut_mac = M.cmd('cat /sys/class/net/%s/address | tr -d "\n"' % self.dut_ifn[0])

        M.cmd('ip link delete gene0', fail=False)
        M.cmd('ip link add gene0 type geneve dstport 6081 external')
        M.cmd('ifconfig gene0 up')

        self.add_egress_qdisc('gene0')

        geneve_opt1 = {'ver_opt_len': '\x02',
                       'protocol_type': '\x65\x58',
                       'vni_field' : '\x00\x00\x7b',
                       'opt_class' : '\x01\x02',
                       'opt_type' : '\x80',
                       'opt_len' : '\x01',
                       'opt_data' : '\x11\x22\x33\x44'}

        geneve_opt2 = {'ver_opt_len': '\x02',
                       'protocol_type': '\x65\x58',
                       'vni_field' : '\x00\x00\x7b',
                       'opt_class' : '\x21\x42',
                       'opt_type' : '\x33',
                       'opt_len' : '\x01',
                       'opt_data' : '\x21\x32\x43\x54'}
        self.hit_geneve_opt(iface, ingress, dut_ip, src_ip, dut_mac, src_mac, geneve_opt1, geneve_opt2)
        self.miss_geneve_opt(iface, ingress, dut_ip, src_ip, dut_mac, src_mac, geneve_opt1, geneve_opt2)

        geneve_opt1 = {'ver_opt_len': '\x02',
                       'protocol_type': '\x65\x58',
                       'vni_field' : '\x00\x00\x7b',
                       'opt_class' : '\x31\x72',
                       'opt_type' : '\x80',
                       'opt_len' : '\x01',
                       'opt_data' : '\x11\x02\x04\x08'}

        geneve_opt2 = {'ver_opt_len': '\x03',
                       'protocol_type': '\x65\x58',
                       'vni_field' : '\x00\x00\xEA',
                       'opt_class' : '\x14\x09',
                       'opt_type' : '\x44',
                       'opt_len' : '\x02',
                       'opt_data' : '\x11\x11\x12\x13\x15\x18\x19\x15'}
        self.hit_geneve_opt(iface, ingress, dut_ip, src_ip, dut_mac, src_mac, geneve_opt1, geneve_opt2)
        self.miss_geneve_opt(iface, ingress, dut_ip, src_ip, dut_mac, src_mac, geneve_opt1, geneve_opt2)

        geneve_opt1 = {'ver_opt_len': '\x03',
                       'protocol_type': '\x65\x58',
                       'vni_field' : '\x00\x00\xEA',
                       'opt_class' : '\x13\x78',
                       'opt_type' : '\x62',
                       'opt_len' : '\x02',
                       'opt_data' : '\x22\x37\x59\x90\x11\x11\x21\x31'}

        geneve_opt2 = {'ver_opt_len': '\x03',
                       'protocol_type': '\x65\x58',
                       'vni_field' : '\x00\x00\xEA',
                       'opt_class' : '\x04\x08',
                       'opt_type' : '\x12',
                       'opt_len' : '\x02',
                       'opt_data' : '\x61\x62\x63\x64\x21\x22\x23\x24'}
        self.hit_geneve_opt(iface, ingress, dut_ip, src_ip, dut_mac, src_mac, geneve_opt1, geneve_opt2)
        self.miss_geneve_opt(iface, ingress, dut_ip, src_ip, dut_mac, src_mac, geneve_opt1, geneve_opt2)

    def cleanup(self):
        self.cleanup_flower('gene0')
        self.dut.cmd('ip link del gene0', fail=False)
        return super(FlowerMatchGeneveMultiOpt, self).cleanup()

class FlowerMaxEntries(FlowerBase):
    """ Test tries to install 500K entries. We do this using TCs batch
        command. The alternative of calling 'tc filter add' 500K times
        is not feasible as this takes too long. Creating the batch file
        on the orchestrator and copying it over is also not feasible as
        this file can become very large.
    """
    def execute(self):
        setup_local = os.path.join(self.group.tmpdir, 'generate_entries.py')
        setup_dut = os.path.join(self.dut.tmpdir, 'generate_entries.py')
        entry_filename = os.path.join(self.dut.tmpdir, 'rules.flows')
        iface, ingress = self.configure_flower()
        max_entry_cnt = 480000

        with open(setup_local, "w") as entry_file:
            entry_file.write('import ipaddress\n')
            entry_file.write('cnt = 0\n')
            entry_file.write('with open(\'%s\', "w") as entry_file:\n' % entry_filename)
            entry_file.write('\tfor ip in ipaddress.IPv4Network(u\'22.0.0.0/255.248.0.0\'):\n')
            entry_file.write('\t\tcnt += 1\n')
            entry_file.write('\t\tiface = \'%s\'\n' % iface)
            entry_file.write('\t\tmatch = \'ip prio 1 flower skip_sw dst_ip %s\' % ip\n')
            entry_file.write('\t\taction = \'drop\'\n')
            entry_file.write('\t\tcmd = \'filter add dev %s parent ffff: protocol %s action %s\\n\' % (iface, match, action)\n')
            entry_file.write('\t\tentry_file.write(cmd)\n')
            entry_file.write('\t\tif (cnt == %s):\n' % max_entry_cnt)
            entry_file.write('\t\t\tbreak\n')

        M = self.dut
        M.mv_to(setup_local, setup_dut)
        M.cmd('python %s' % setup_dut)
        M.cmd('tc -b %s' % entry_filename)

        self.cleanup_filter(iface)

    def cleanup(self):
        self.cleanup_flower(self.dut_ifn[0])
        return super(FlowerMaxEntries, self).cleanup()

class FlowerMatchTunnelToSharedMAC(FlowerBase):
    def prepare(self):
        if len(self.dut_ifn) < 2 or len(self.src_ifn) < 2:
            return NrtResult(name=self.name, testtype=self.__class__.__name__,
                             passed=None, comment='2 ports required for test')

    def execute(self):
        M = self.dut
        A = self.src

        src_ip = self.src_addr[0].split('/')[0]
        dut_ip = self.dut_addr[0].split('/')[0]

        _, src_mac = A.cmd('cat /sys/class/net/%s/address | tr -d "\n"' % self.src_ifn[0])
        _, dut_mac1 = M.cmd('cat /sys/class/net/%s/address | tr -d "\n"' % self.dut_ifn[0])
        _, dut_mac2 = M.cmd('cat /sys/class/net/%s/address | tr -d "\n"' % self.dut_ifn[1])

        # Set the 2nd interface to the same MAC address as the first
        M.cmd('ip link set dev %s down' % self.dut_ifn[1])
        M.cmd('ip link set %s address %s' % (self.dut_ifn[1], dut_mac1))
        M.cmd('ip link set dev %s up' % self.dut_ifn[1])

        M.cmd('ip link add name vxlan0 type vxlan dstport 0 external')
        M.cmd('ifconfig vxlan0 up')

        self.add_egress_qdisc('vxlan0')

        # Hit test - match all vxlan fields and decap
        match = 'ip flower enc_src_ip %s enc_dst_ip %s enc_dst_port 4789 enc_key_id 123' % (src_ip, dut_ip)
        action = 'mirred egress redirect dev %s' % self.dut_ifn[0]
        self.install_filter('vxlan0', match, action)

        # VXLAN header with VNI 123, ToS 30, and TTL  99
        vxlan_header = '\x08\x00\x00\x00\x00\x00\x7b\x00'
        enc_pkt = Ether(src=self.group.hwaddr_x[0],dst=self.ipv4_mc_mac[0])/\
                  IP()/TCP()/Raw('\x00'*64)
        vxlan_header += str(enc_pkt)
        pkt = Ether(src=src_mac,dst=dut_mac1)/IP(src=src_ip, dst=dut_ip, tos=30, ttl=99)/UDP(sport=44534, dport=4789)/vxlan_header
        pkt_diff = len(Ether()) + len(IP()) + len(UDP()) + 8

        # Tunnel packets should match on both ports
        self.test_filter('vxlan0', self.src_ifn[0], pkt, enc_pkt, 100,
                         -pkt_diff)
        sleep(2)
        self.test_filter('vxlan0', self.src_ifn[0], pkt, enc_pkt, 200,
                         -pkt_diff, new_port=1)

        # Reset the 2nd interface to its original MAC
        M.cmd('ip link set dev %s down' % self.dut_ifn[1])
        M.cmd('ip link set %s address %s' % (self.dut_ifn[1], dut_mac2))
        M.cmd('ip link set dev %s up' % self.dut_ifn[1])

        # Counts should now only increment when ingressing one interface
        self.test_filter('vxlan0', self.src_ifn[0], pkt, enc_pkt, 300,
                         -pkt_diff)
        sleep(2)
        self.test_filter('vxlan0', self.src_ifn[0], pkt, None, 300, -pkt_diff,
                         new_port=1)

        self.cleanup_filter('vxlan0')

    def cleanup(self):
        self.cleanup_flower('vxlan0')
        self.dut.cmd('ip link del vxlan0', fail=False)
        return super(FlowerMatchTunnelToSharedMAC, self).cleanup()

class FlowerMatchBlock(FlowerBase):
    def prepare(self):
        if len(self.dut_ifn) < 2 or len(self.src_ifn) < 2:
            return NrtResult(name=self.name, testtype=self.__class__.__name__,
                             passed=None, comment='2 ports required for test')

    def execute(self):
        M = self.dut
        A = self.src
        iface = self.dut_ifn[0]

        # Blocks are only supported from kernel 4.18
        if not self.dut.kernel_ver_ge(4, 18):
            ret = M.cmd('tc qdisc add dev %s ingress_block 22 ingress' % iface, fail=False)
            if not ret:
                raise NtiError('TC block was not rejected on a kernel lower than 4.18')
            return

        iface2 = self.dut_ifn[1]
        ingress = self.src_ifn[0]
        ingress2 = self.src_ifn[1]

        # Add 2 interfaces to a block
        M.cmd('tc qdisc del dev %s ingress_block 22 ingress' % iface, fail=False)
        M.cmd('tc qdisc del dev %s ingress_block 22 ingress' % iface2, fail=False)
        M.cmd('tc qdisc add dev %s ingress_block 22 ingress' % iface)
        M.cmd('tc qdisc add dev %s ingress_block 22 ingress' % iface2)

        # Add filter to block
        M.cmd('tc filter add block 22 protocol ip parent ffff: flower skip_sw \
               ip_proto tcp action mirred egress redirect dev %s' % iface)

        pkt = Ether(src=self.group.hwaddr_x[0],dst=self.ipv4_mc_mac[0])/\
              IP()/TCP()/Raw('\x00'*64)
        self.test_filter(iface, ingress, pkt, pkt, 100)

        pkt = Ether(src=self.group.hwaddr_x[0],dst=self.ipv4_mc_mac[0])/\
              IP()/TCP()/Raw('\x00'*64)
        self.test_filter(iface2, ingress, pkt, pkt, 200, new_port=1)

    def cleanup(self):
        self.dut.cmd('tc filter del block 22 protocol ip parent ffff: prio 49152', fail=False)
        self.dut.cmd('tc qdisc del dev %s ingress_block 22 ingress' % self.dut_ifn[0], fail=False)
        if len(self.dut_ifn) > 1:
            self.dut.cmd('tc qdisc del dev %s ingress_block 22 ingress' % self.dut_ifn[1], fail=False)
        return super(FlowerMatchBlock, self).cleanup()

class FlowerMatchMPLS(FlowerBase):
    def execute(self):
        self.check_prereq('tc filter add flower help 2>&1 | grep mpls', 'MPLS Flower classification')
        iface, ingress = self.configure_flower()

        # Hit test
        match = '0x8847 flower'
        action = 'mirred egress redirect dev %s' % iface
        self.install_filter(iface, match, action)

        pkt = Ether(src=self.group.hwaddr_x[0],dst=self.ipv4_mc_mac[0])/\
              MPLS(label=3333)/Raw('\x00'*64)
        self.test_filter(iface, ingress, pkt, pkt, 100)

        self.cleanup_filter(iface)

        # Miss test
        match = '0x8847 flower'
        action = 'mirred egress redirect dev %s' % iface
        self.install_filter(iface, match, action)

        pkt = Ether(src=self.group.hwaddr_x[0],dst=self.ipv4_mc_mac[0])/\
              IP()/TCP()/Raw('\x00'*64)
        self.test_filter(iface, ingress, pkt, None, 0)

        self.cleanup_filter(iface)

        # Hit test
        match = '0x8847 flower mpls_label 1111'
        action = 'mirred egress redirect dev %s' % iface
        self.install_filter(iface, match, action)

        pkt = Ether(src=self.group.hwaddr_x[0],dst=self.ipv4_mc_mac[0])/\
              MPLS(label=1111)/Raw('\x00'*64)
        self.test_filter(iface, ingress, pkt, pkt, 100)

        self.cleanup_filter(iface)

        # Miss test
        match = '0x8847 flower mpls_label 2222'
        action = 'mirred egress redirect dev %s' % iface
        self.install_filter(iface, match, action)

        pkt = Ether(src=self.group.hwaddr_x[0],dst=self.ipv4_mc_mac[0])/\
              MPLS(label=1111)/Raw('\x00'*64)
        self.test_filter(iface, ingress, pkt, None, 0)

        self.cleanup_filter(iface)

    def cleanup(self):
        self.cleanup_flower(self.dut_ifn[0])
        return super(FlowerMatchMPLS, self).cleanup()

class FlowerMatchTTL(FlowerBase):
    def execute(self):
        iface, ingress = self.configure_flower()

        # Hit test - IPv4
        match = 'ip flower ip_ttl 30'
        action = 'mirred egress redirect dev %s' % iface
        self.install_filter(iface, match, action)

        pkt = Ether(src=self.group.hwaddr_x[0],dst=self.ipv4_mc_mac[0])/\
              IP(src='10.0.0.10', dst='11.0.0.11', ttl=30)/TCP()/Raw('\x00'*64)
        self.test_filter(iface, ingress, pkt, pkt, 100)

        self.cleanup_filter(iface)

        # Miss test -IP IPv4
        match = 'ip flower ip_ttl 20'
        action = 'mirred egress redirect dev %s' % iface
        self.install_filter(iface, match, action)

        pkt = Ether(src=self.group.hwaddr_x[0],dst=self.ipv4_mc_mac[0])/\
              IP(src='10.0.0.10', dst='11.0.0.11', ttl=30)/TCP()/Raw('\x00'*64)
        self.test_filter(iface, ingress, pkt, None, 0)

        self.cleanup_filter(iface)

        # Hit test - IPv6
        new_filter = '"not arp and' \
                     ' not udp port 5353 and' \
                     ' not ether host 01:80:c2:00:00:0e and' \
                     ' not ether host ff:ff:ff:ff:ff:ff"'

        match = 'ipv6 flower ip_ttl 15'
        action = 'mirred egress redirect dev %s' % iface
        self.install_filter(iface, match, action)

        pkt = Ether(src=self.group.hwaddr_x[0],dst=self.ipv6_mc_mac[0])/\
              IPv6(src='10::10', dst='11::11', hlim=15)/TCP()/Raw('\x00'*64)
        self.test_filter(iface, ingress, pkt, pkt, 100, fltr=new_filter)

        self.cleanup_filter(iface)

        # Miss test -IP IPv6
        match = 'ipv6 flower ip_ttl 5'
        action = 'mirred egress redirect dev %s' % iface
        self.install_filter(iface, match, action)

        pkt = Ether(src=self.group.hwaddr_x[0],dst=self.ipv6_mc_mac[0])/\
              IPv6(src='10::10', dst='11::11',hlim=20)/TCP()/Raw('\x00'*64)
        self.test_filter(iface, ingress, pkt, None, 0, fltr=new_filter)

        self.cleanup_filter(iface)

    def cleanup(self):
        self.cleanup_flower(self.dut_ifn[0])
        return super(FlowerMatchTTL, self).cleanup()

class FlowerMatchTOS(FlowerBase):
    def execute(self):
        iface, ingress = self.configure_flower()

        # Hit test - IPv4
        match = 'ip flower ip_tos 10'
        action = 'mirred egress redirect dev %s' % iface
        self.install_filter(iface, match, action)

        pkt = Ether(src=self.group.hwaddr_x[0],dst=self.ipv4_mc_mac[0])/\
              IP(src='10.0.0.10', dst='11.0.0.11', tos=10)/TCP()/Raw('\x00'*64)
        self.test_filter(iface, ingress, pkt, pkt, 100)

        self.cleanup_filter(iface)

        # Miss test -IPv4
        match = 'ip flower ip_tos 15'
        action = 'mirred egress redirect dev %s' % iface
        self.install_filter(iface, match, action)

        pkt = Ether(src=self.group.hwaddr_x[0],dst=self.ipv4_mc_mac[0])/\
              IP(src='10.0.0.10', dst='11.0.0.11', tos=30)/TCP()/Raw('\x00'*64)
        self.test_filter(iface, ingress, pkt, None, 0)

        self.cleanup_filter(iface)

        # Hit test - IPv6
        new_filter = '"not arp and' \
                     ' not udp port 5353 and' \
                     ' not ether host 01:80:c2:00:00:0e and' \
                     ' not ether host ff:ff:ff:ff:ff:ff"'

        match = 'ipv6 flower ip_tos 30'
        action = 'mirred egress redirect dev %s' % iface
        self.install_filter(iface, match, action)

        pkt = Ether(src=self.group.hwaddr_x[0],dst=self.ipv6_mc_mac[0])/\
              IPv6(src='10::10', dst='11::11', tc=30)/TCP()/Raw('\x00'*64)
        self.test_filter(iface, ingress, pkt, pkt, 100, fltr=new_filter)

        self.cleanup_filter(iface)

        # Miss test -IP IPv6
        match = 'ipv6 flower ip_tos 20'
        action = 'mirred egress redirect dev %s' % iface
        self.install_filter(iface, match, action)

        pkt = Ether(src=self.group.hwaddr_x[0],dst=self.ipv6_mc_mac[0])/\
              IPv6(src='10::10', dst='11::11', tc=10)/TCP()/Raw('\x00'*64)
        self.test_filter(iface, ingress, pkt, None, 0, fltr=new_filter)

        self.cleanup_filter(iface)

    def cleanup(self):
        self.cleanup_flower(self.dut_ifn[0])
        return super(FlowerMatchTOS, self).cleanup()

class FlowerMatchFrag(FlowerBase):
    def install_test(self, flag, iface):
        match = self.ip_ver + ' flower ip_flags ' + flag
        action = 'mirred egress redirect dev %s' % iface
        self.install_filter(iface, match, action)

    def frag_filter(self, flags, iface, ingress):
        pkt = self.pkt
        frag_pkt = self.frag_pkt
        new_filter = self.new_filter

        if flags == 'nofrag':
            self.test_filter(iface, ingress, frag_pkt[0], None, 0,
                             fltr=new_filter)
            self.test_filter(iface, ingress, pkt, pkt, 100, fltr=new_filter)
        if flags == 'frag':
            self.test_filter(iface, ingress, pkt, None, 0, fltr=new_filter)
            self.test_filter(iface, ingress, frag_pkt[0], frag_pkt[0], 100,
                             fltr=new_filter)
        if flags == 'nofirstfrag':
            self.test_filter(iface, ingress, frag_pkt[0], None, 0,
                             fltr=new_filter)
            self.test_filter(iface, ingress, frag_pkt[1], frag_pkt[1], 100,
                             fltr=new_filter)
        if flags == 'firstfrag':
            self.test_filter(iface, ingress, frag_pkt[1], None, 0,
                             fltr=new_filter)
            self.test_filter(iface, ingress, frag_pkt[0], frag_pkt[0], 100,
                             fltr=new_filter)

    def frag_test(self):
        iface, ingress = self.configure_flower()
        frag = ['nofrag', 'frag', 'firstfrag', 'nofirstfrag']

        for flags in frag:
            self.install_test(flags, iface)
            self.frag_filter(flags, iface, ingress)
            self.cleanup_filter(iface)

    def execute(self):
        self.frag_test()

    def cleanup(self):
        self.cleanup_flower(self.dut_ifn[0])
        return super(FlowerMatchFrag, self).cleanup()

class FlowerMatchFragIPv4(FlowerMatchFrag):
    def __init__(self, *args, **kwargs):
        super(FlowerMatchFragIPv4, self).__init__(*args, **kwargs)
        self.ip_ver = 'ip'
        self.pkt = Ether(src=self.ipv4_mc_mac[0],dst=self.ipv4_mc_mac[1])/\
                   IP()/TCP()/Raw('\x00'*1024)
        self.frag_pkt = fragment(Ether(src=self.ipv4_mc_mac[0],
                                       dst=self.ipv4_mc_mac[1])/
                                 IP()/TCP()/Raw('\x00'*1024), 128)
        self.new_filter = ''

class FlowerMatchFragIPv6(FlowerMatchFrag):
    def __init__(self, *args, **kwargs):
        super(FlowerMatchFragIPv6, self).__init__(*args, **kwargs)
        self.ip_ver = 'ipv6'
        self.pkt = Ether(src=self.ipv6_mc_mac[0],dst=self.ipv6_mc_mac[1])/\
                   IPv6()/TCP()/Raw('\x00'*1024)
        self.frag_pkt = fragment6(Ether(src=self.ipv6_mc_mac[0],
                                        dst=self.ipv6_mc_mac[1])/
                                  IPv6()/IPv6ExtHdrFragment()/TCP()/\
                                  Raw('\x00'*1024), 128)
        self.new_filter = '"not arp and' \
                          ' not udp port 5353 and' \
                          ' not ether host 01:80:c2:00:00:0e and' \
                          ' not ether host ff:ff:ff:ff:ff:ff"'

class FlowerModifyMTU(FlowerBase):
    def set_sending_source_mtu(self, ingress, mtu):
        ret = self.src.ip_link_set_mtu(ingress, mtu, fail=False)
        if ret[0]:
            raise NtiSkip('Cannot set max mtu(%s) on %s' % (mtu, ingress))

        # If the source/endpoint system is using flower FW we need to take
        # extra care with setting MTUs. For flower FW it is advised to set
        # the MTU for the PF interface to the largest value supported by the
        # firmware, to avoid fallback packets from being unnecessarily dropped
        # due to being larger than the MTU of the PF.
        if self.check_src_flower_fw(ingress):
            pf_ifname = ingress[:-3]
            ret = self.src.ip_link_set_mtu(pf_ifname, mtu, fail=False)
            if ret[0]:
                raise NtiSkip('Cannot set max mtu(%s) on %s' % (mtu, pf_ifname))

    def execute(self):
        iface, ingress = self.configure_flower()
        M = self.dut

        # Test for high MTU set - 9420 should be max
        ret = M.ip_link_set_mtu(iface, 9421, fail=False)
        if not ret:
            raise NtiError('invalid MTU of 9421 accepted on %s' %iface)

        # Test for high MTU set - 68 should be min
        ret = M.ip_link_set_mtu(iface, 67, fail=False)
        if not ret:
            raise NtiError('invalid MTU of 67 accepted on %s' %iface)

        # ensure the sending interface can handle jumbo frames
        self.set_sending_source_mtu(ingress, 9216)

        # Hit test
        match = 'ip flower'
        action = 'mirred egress redirect dev %s' % iface
        self.install_filter(iface, match, action)

        # Length 14 + 20 + 20 + 9162 = 9216
        pkt = Ether(src=self.group.hwaddr_x[0],dst=self.ipv4_mc_mac[0])/\
              IP()/TCP()/Raw('\x00'*9162)
        pcap_src = self.prep_pcap_simple_to_list(pkt)
        self.test_with_traffic(pcap_src, None,
                               (self.src, self.src_ifn[0], self.src),
                               snaplen=9420)

        self.cleanup_filter(iface)

        # Set mtu to 9420 and check it passes
        ret = M.ip_link_set_mtu(iface, 9420)

        self.install_filter(iface, match, action)
        self.test_with_traffic(pcap_src, str(pkt),
                               (self.src, self.src_ifn[0], self.src),
                               snaplen=9420)

        self.cleanup_filter(iface)

        # Mark MTU below packet size and check it fails
        ret = M.ip_link_set_mtu(iface, 9000)

        self.install_filter(iface, match, action)
        self.test_with_traffic(pcap_src, None,
                               (self.src, self.src_ifn[0], self.src),
                               snaplen=9420)

        self.cleanup_filter(iface)

    def cleanup(self):
        self.cleanup_flower(self.dut_ifn[0])
        self.set_sending_source_mtu(self.src_ifn[0], 1500)
        self.src.ip_link_set_mtu(self.src_ifn[0], 1500)
        self.dut.ip_link_set_mtu(self.dut_ifn[0], 1500)
        return super(FlowerModifyMTU, self).cleanup()

class FlowerMatchWhitelist(FlowerBase):
    def execute(self):
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
        self.cleanup_flower(self.dut_ifn[0])
        self.dut.cmd('ip link del dummy1', fail=False)
        self.dut.cmd('rmmod dummy', fail=False)
        return super(FlowerMatchWhitelist, self).cleanup()

class FlowerVxlanWhitelist(FlowerBase):
    def execute(self):
        iface, _ = self.configure_flower()
        M = self.dut

        src_ip = self.src_addr[0].split('/')[0]
        dut_ip = self.dut_addr[0].split('/')[0]
        src_ip6 = self.src_addr_v6[0].split('/')[0]
        dut_ip6 = self.dut_addr_v6[0].split('/')[0]

        M.cmd('ip link delete vxlan0', fail=False)
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

        # Check that vxlan with ipv6 header is installed in software only (not_in_hw)
        match = 'ip flower enc_src_ip %s enc_dst_ip %s enc_dst_port 4789 enc_key_id 123' % (src_ip6, dut_ip6)
        action = 'mirred egress redirect dev %s' % iface
        self.install_filter('vxlan0', match, action, False)
        self.cleanup_filter('vxlan0')

        # Check that multiple vxlan tunnel output is installed in software only (not_in_hw)
        M.cmd('ip link delete vxlan1', fail=False)
        M.cmd('ip link add vxlan1 type vxlan id 0 dstport 4790')
        M.cmd('ifconfig vxlan1 up')
        M.cmd('ip link delete vxlan2', fail=False)
        M.cmd('ip link add vxlan2 type vxlan id 0 dstport 4791')
        M.cmd('ifconfig vxlan2 up')
        match = 'ip flower ip_proto tcp'
        action = 'tunnel_key set id 123 src_ip 10.0.0.1 dst_ip 10.0.0.2 dst_port 4789 action mirred egress mirror dev vxlan1 action mirred egress redirect dev vxlan2'
        self.install_filter('vxlan0', match, action, False)
        self.cleanup_filter('vxlan0')

        # Check that a vxlan tunnel output with ipv6 src/dest is installed in software only (not_in_hw)
        match = 'ip flower ip_proto tcp'
        action = 'tunnel_key set id 123 src_ip %s dst_ip %s dst_port 4789 nocsum action mirred egress redirect dev vxlan0' % (dut_ip6, src_ip6)
        self.install_filter(iface, match, action, False)
        self.cleanup_filter(iface)

    def cleanup(self):
        self.cleanup_flower('vxlan0')
        self.dut.cmd('ip link delete vxlan0', fail=False)
        self.dut.cmd('ip link delete vxlan1', fail=False)
        self.dut.cmd('ip link delete vxlan2', fail=False)
        return super(FlowerVxlanWhitelist, self).cleanup()

class FlowerCsumWhitelist(FlowerBase):
    def execute(self):
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

    def cleanup(self):
        self.cleanup_flower(self.dut_ifn[0])
        return super(FlowerCsumWhitelist, self).cleanup()

class FlowerActionPushVLAN(FlowerBase):
    def execute(self):
        iface, ingress = self.configure_flower()

        # Test Output Action
        match = 'ip flower'
        action = 'mirred egress redirect dev %s' % iface
        self.install_filter(iface, match, action)

        pkt = Ether(src=self.group.hwaddr_x[0],dst=self.ipv4_mc_mac[0])/\
              IP(src='10.0.0.10', dst='11.0.0.11')/TCP()/Raw('\x00'*64)
        exp_pkt = Ether(src=self.group.hwaddr_x[0],dst=self.ipv4_mc_mac[0])/\
                  IP(src='10.0.0.10', dst='11.0.0.11')/TCP()/Raw('\x00'*64)
        self.test_filter(iface, ingress, pkt, exp_pkt, 100)

        self.cleanup_filter(iface)

        # Test Push VLAN id and priority
        match = 'ip flower'
        action = 'vlan push id 1464 priority 3 '\
                 'pipe mirred egress redirect dev %s' % iface
        self.install_filter(iface, match, action)

        pkt = Ether(src=self.group.hwaddr_x[0],dst=self.ipv4_mc_mac[0])/\
              IP(src='10.0.0.10', dst='11.0.0.11')/\
              TCP()/Raw('\x00'*64)
        exp_pkt = Ether(src=self.group.hwaddr_x[0],dst=self.ipv4_mc_mac[0])/\
                  Dot1Q(vlan=1464, prio=3)/\
                  IP(src='10.0.0.10', dst='11.0.0.11')/\
                  TCP()/Raw('\x00'*64)
        self.test_filter(iface, ingress, pkt, exp_pkt, 100)

        self.cleanup_filter(iface)

        # Test Push VLAN id
        match = 'ip flower'
        action = 'vlan push id 2928 ' \
                 'pipe mirred egress redirect dev %s' % iface
        self.install_filter(iface, match, action)

        pkt = Ether(src=self.group.hwaddr_x[0],dst=self.ipv4_mc_mac[0])/\
              IP(src='10.0.0.10', dst='11.0.0.11')/\
              TCP()/Raw('\x00'*64)
        exp_pkt = Ether(src=self.group.hwaddr_x[0],dst=self.ipv4_mc_mac[0])/\
                  Dot1Q(vlan=2928)/\
                  IP(src='10.0.0.10', dst='11.0.0.11')/\
                  TCP()/Raw('\x00'*64)
        self.test_filter(iface, ingress, pkt, exp_pkt, 100)

        self.cleanup_filter(iface)

        # Test Push VLAN priority
        match = 'ip flower'
        action = 'vlan push id 0 priority 1 ' \
                 'pipe mirred egress redirect dev %s' % iface
        self.install_filter(iface, match, action)

        pkt = Ether(src=self.group.hwaddr_x[0],dst=self.ipv4_mc_mac[0])/\
              IP(src='10.0.0.10', dst='11.0.0.11')/\
              TCP()/Raw('\x00'*64)
        exp_pkt = Ether(src=self.group.hwaddr_x[0],dst=self.ipv4_mc_mac[0])/\
                  Dot1Q(vlan=0, prio=1)/\
                  IP(src='10.0.0.10', dst='11.0.0.11')/\
                  TCP()/Raw('\x00'*64)
        self.test_filter(iface, ingress, pkt, exp_pkt, 100)

        self.cleanup_filter(iface)

        # Test Push VLAN 0 id and priority
        match = 'ip flower'
        action = 'vlan push id 0 priority 0 ' \
                 'pipe mirred egress redirect dev %s' % iface
        self.install_filter(iface, match, action)

        pkt = Ether(src=self.group.hwaddr_x[0],dst=self.ipv4_mc_mac[0])/\
              IP(src='10.0.0.10', dst='11.0.0.11')/\
              TCP()/Raw('\x00'*64)
        exp_pkt = Ether(src=self.group.hwaddr_x[0],dst=self.ipv4_mc_mac[0])/\
                  Dot1Q(vlan=0, prio=0)/\
                  IP(src='10.0.0.10', dst='11.0.0.11')/\
                  TCP()/Raw('\x00'*64)
        self.test_filter(iface, ingress, pkt, exp_pkt, 100)

        self.cleanup_filter(iface)

    def cleanup(self):
        self.cleanup_flower(self.dut_ifn[0])
        return super(FlowerActionPushVLAN, self).cleanup()

class FlowerActionPopVLAN(FlowerBase):
    def execute(self):
        iface, ingress = self.configure_flower()

        # Test Output Action
        match = 'ip flower'
        action = 'mirred egress redirect dev %s' % iface
        self.install_filter(iface, match, action)

        pkt = Ether(src=self.group.hwaddr_x[0],dst=self.ipv4_mc_mac[0])/\
              IP(src='10.0.0.10', dst='11.0.0.11')/TCP()/Raw('\x00'*64)
        exp_pkt = Ether(src=self.group.hwaddr_x[0],dst=self.ipv4_mc_mac[0])/\
                  IP(src='10.0.0.10', dst='11.0.0.11')/TCP()/Raw('\x00'*64)
        self.test_filter(iface, ingress, pkt, exp_pkt, 100)

        self.cleanup_filter(iface)

        # Test Pop vlan
        match = '802.1Q flower'
        action = 'vlan pop pipe mirred egress redirect dev %s' % iface
        self.install_filter(iface, match, action)

        pkt = Ether(src=self.group.hwaddr_x[0],dst=self.ipv4_mc_mac[0])/\
              Dot1Q(vlan=3132, prio=1)/\
              IP(src='10.0.0.10', dst='11.0.0.11')/\
              TCP()/Raw('\x00'*64)
        exp_pkt = Ether(src=self.group.hwaddr_x[0],dst=self.ipv4_mc_mac[0])/\
                  IP(src='10.0.0.10', dst='11.0.0.11')/\
                  TCP()/Raw('\x00'*64)
        self.test_filter(iface, ingress, pkt, exp_pkt, 100)

        self.cleanup_filter(iface)

        # Test Pop vlan
        match = '802.1Q flower'
        action = 'vlan pop pipe mirred egress redirect dev %s' % iface
        self.install_filter(iface, match, action)

        pkt = Ether(src=self.group.hwaddr_x[0],dst=self.ipv4_mc_mac[0])/\
              Dot1Q(vlan=1102)/\
              IP(src='10.0.0.10', dst='11.0.0.11')/\
              TCP()/Raw('\x00'*64)
        exp_pkt = Ether(src=self.group.hwaddr_x[0],dst=self.ipv4_mc_mac[0])/\
                  IP(src='10.0.0.10', dst='11.0.0.11')/\
                  TCP()/Raw('\x00'*64)
        self.test_filter(iface, ingress, pkt, exp_pkt, 100)

        self.cleanup_filter(iface)

        # Test Pop vlan with DEI/CFI set
        #In Scapy id is the 12th -bit (i.e. the DEI/CFI bit)
        match = '802.1Q flower'
        action = 'vlan pop pipe mirred egress redirect dev %s' % iface
        self.install_filter(iface, match, action)

        pkt = Ether(src=self.group.hwaddr_x[0],dst=self.ipv4_mc_mac[0])/\
              Dot1Q(vlan=423, id=1)/\
              IP(src='10.0.0.10', dst='11.0.0.11')/\
              TCP()/Raw('\x00'*64)
        exp_pkt = Ether(src=self.group.hwaddr_x[0],dst=self.ipv4_mc_mac[0])/\
                  IP(src='10.0.0.10', dst='11.0.0.11')/\
                  TCP()/Raw('\x00'*64)
        self.test_filter(iface, ingress, pkt, exp_pkt, 100)

        self.cleanup_filter(iface)

    def cleanup(self):
        self.cleanup_flower(self.dut_ifn[0])
        return super(FlowerActionPopVLAN, self).cleanup()

class FlowerActionVXLAN(FlowerBase):
    def execute(self):
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
        if self.dut.kernel_ver_ge(4, 19):
            action = 'tunnel_key set id 123 src_ip %s dst_ip %s dst_port 4789 tos 30 ttl 99 action mirred egress redirect dev vxlan0' % (dut_ip, src_ip)
            self.install_filter(iface, match, action)
        else:
            action = 'tunnel_key set id 123 src_ip %s dst_ip %s dst_port 4789 action mirred egress redirect dev vxlan0' % (dut_ip, src_ip)
            self.install_filter(iface, match, action)

        exp_pkt_cnt = 100
        pkt = Ether(src=self.group.hwaddr_x[0],dst=self.ipv4_mc_mac[0])/\
              IP()/TCP()/Raw('\x00'*64)

        sleep(2)
        self.send_packs(iface, ingress, pkt)
        sleep(2)

        dump_file = os.path.join('/tmp/', 'dump.pcap')
        self.capture_packs(iface, ingress, pkt, dump_file, 'udp dst port 4789')
        pack_cap = rdpcap(dump_file)
        cmd_log("rm %s" % dump_file)
        pkt_diff = len(Ether()) + len(IP()) + len(UDP()) + 8
        self.pcap_check_bytes(exp_pkt_cnt, pack_cap, pkt, pkt_diff)

        exp_pkt = Ether(src=dut_mac,dst=src_mac)/\
                  IP(src=dut_ip, dst=src_ip, ttl=99, tos=30)/\
                  UDP(sport=0, dport=4789)

        # create matchable strings from the expected packet (non tested fields may differ)
        vxlan_header = '0800000000007b00'
        mac_header = str(exp_pkt).encode("hex")[0:len(Ether())*2]
        ip_addresses = str(exp_pkt).encode("hex")[(len(Ether()) + 12)*2: (len(Ether()) + len(IP()))*2]
        ip_proto = str(exp_pkt).encode("hex")[(len(Ether()) + 9)*2: (len(Ether()) + 10)*2]
        dest_port = str(exp_pkt).encode("hex")[(len(Ether()) + len(IP()) + 2)*2: (len(Ether()) + len(IP()) + 4)*2]
        no_ttl = '00'
        ttl = str(exp_pkt).encode("hex")[(len(Ether()) + 8)*2: (len(Ether()) + 9)*2]
        tos = str(exp_pkt).encode("hex")[(len(Ether()) + 1)*2: (len(Ether()) + 2)*2]

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

        # Setting of tunnel ToS and TTL are added in kernel 4.19
        if self.dut.kernel_ver_ge(4, 19):
            # check tunnel TTL
            self.pcap_cmp_pkt_bytes(pack_cap, ttl, len(Ether()) + 8)
            # check tunnel ToS
            self.pcap_cmp_pkt_bytes(pack_cap, tos, len(Ether()) + 1)

        self.cleanup_filter(iface)

        # modify action to uncheck the udp checksum flag
        action = 'tunnel_key set id 123 src_ip %s dst_ip %s dst_port 4789 nocsum action mirred egress redirect dev vxlan0' % (dut_ip, src_ip)
        self.install_filter(iface, match, action)
        self.capture_packs(iface, ingress, pkt, dump_file, 'udp dst port 4789')
        pack_cap = rdpcap(dump_file)

        no_csum = '0000'
        # verify checksum is 0
        self.pcap_cmp_pkt_bytes(pack_cap, no_csum, len(Ether()) + len(IP()) + 6)

        self.cleanup_filter(iface)

    def cleanup(self):
        self.cleanup_flower(self.dut_ifn[0])
        src_ip = self.src_addr[0].split('/')[0]
        self.dut.cmd('arp -i %s -d %s' % (self.dut_ifn[0], src_ip), fail=False)
        self.dut.cmd('ip link delete vxlan0', fail=False)
        return super(FlowerActionVXLAN, self).cleanup()

class FlowerActionMergeVXLAN(FlowerBase):
    def execute(self):
        iface, ingress = self.configure_flower()
        M = self.dut
        A = self.src

        src_ip = self.src_addr[0].split('/')[0]
        dut_ip = self.dut_addr[0].split('/')[0]

        _, src_mac = A.cmd('cat /sys/class/net/%s/address | tr -d "\n"' % self.src_ifn[0])

        # install an internal port - if we cannot then skip test
        M.cmd('modprobe -r openvswitch', fail=False)
        ret, _ = M.cmd('modprobe openvswitch', fail=False)
        if ret:
            raise NtiSkip('Open vSwitch kernel modules required to run test')
        ret, _ = M.cmd('ovs-dpctl add-dp int-port', fail=False)
        if ret:
            raise NtiSkip('ovs-dpctl app is required to run test')

        # remove the IP from the dut port and add it to the internal port
        M.cmd('ip addr del %s dev %s' % (self.dut_addr[0], self.dut_ifn[0]))
        M.cmd('ip addr add %s dev int-port' % self.dut_addr[0])
        M.cmd('ip link set dev int-port up')

        M.cmd('ip link add name vxlan0 type vxlan dstport 0 external')
        M.cmd('ifconfig vxlan0 up')

        M.cmd('arp -i int-port -s %s %s' % (src_ip, src_mac))

        # install filter to match all tcp packets and encap in vxlan
        match = 'ip flower skip_sw ip_proto tcp'
        action = 'tunnel_key set id 123 src_ip %s dst_ip %s dst_port 4789 action mirred egress redirect dev vxlan0' % (dut_ip, src_ip)
        self.install_filter(iface, match, action)

        # install filter to match on internal port and egress
        # uses an egress hook so need new qdisc and egress parent id in filter
        M.cmd('tc qdisc add dev int-port handle ffff: clsact')
        M.cmd('tc filter add dev int-port protocol ip parent ffff:fff3 flower ip_proto udp action mirred egress redirect dev %s' % iface)

        # tunnel EP is now on the internal port so packets should use its mac
        _, int_mac = M.cmd('cat /sys/class/net/int-port/address | tr -d "\n"')

        exp_pkt_cnt = 100
        pkt = Ether(src=self.group.hwaddr_x[0],dst=self.ipv4_mc_mac[0])/\
              IP()/TCP()/Raw('\x00'*64)

        sleep(2)
        self.send_packs(iface, ingress, pkt)
        sleep(2)

        dump_file = os.path.join('/tmp/', 'dump.pcap')
        self.capture_packs(iface, ingress, pkt, dump_file, 'udp dst port 4789')
        pack_cap = rdpcap(dump_file)
        cmd_log("rm %s" % dump_file)
        pkt_diff = len(Ether()) + len(IP()) + len(UDP()) + 8
        self.pcap_check_bytes(exp_pkt_cnt, pack_cap, pkt, pkt_diff)

        exp_pkt = Ether(src=int_mac,dst=src_mac)/\
                  IP(src=dut_ip, dst=src_ip)/\
                  UDP(sport=0, dport=4789)

        # create matchable strings from the expected packet (non tested fields may differ)
        vxlan_header = '0800000000007b00'
        mac_header = str(exp_pkt).encode("hex")[0:len(Ether())*2]
        ip_addresses = str(exp_pkt).encode("hex")[(len(Ether()) + 12)*2: (len(Ether()) + len(IP()))*2]
        ip_proto = str(exp_pkt).encode("hex")[(len(Ether()) + 9)*2: (len(Ether()) + 10)*2]
        dest_port = str(exp_pkt).encode("hex")[(len(Ether()) + len(IP()) + 2)*2: (len(Ether()) + len(IP()) + 4)*2]
        no_ttl = '00'
        ttl = str(exp_pkt).encode("hex")[(len(Ether()) + 8)*2: (len(Ether()) + 9)*2]
        tos = str(exp_pkt).encode("hex")[(len(Ether()) + 1)*2: (len(Ether()) + 2)*2]

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

    def cleanup(self):
        self.cleanup_flower(self.dut_ifn[0])
        src_ip = self.src_addr[0].split('/')[0]
        self.dut.cmd('arp -i %s -d %s' % (self.dut_ifn[0], src_ip), fail=False)
        self.dut.cmd('ip link delete vxlan0', fail=False)
        self.dut.cmd('ovs-dpctl del-dp int-port', fail=False)
        self.dut.cmd('modprobe -r openvswitch', fail=False)
        self.dut.cmd('ip addr add %s dev %s' % (self.dut_addr[0], self.dut_ifn[0]), fail=False)
        return super(FlowerActionMergeVXLAN, self).cleanup()

class FlowerActionGENEVE(FlowerBase):
    def execute(self):
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

        exp_pkt_cnt = 100
        pkt = Ether(src=self.group.hwaddr_x[0],dst=self.ipv4_mc_mac[0])/\
              IP()/TCP()/Raw('\x00'*64)

        sleep(2)
        self.send_packs(iface, ingress, pkt)
        sleep(2)

        dump_file = os.path.join('/tmp/', 'dump.pcap')
        self.capture_packs(iface, ingress, pkt, dump_file, 'udp dst port 6081')
        pack_cap = rdpcap(dump_file)
        cmd_log("rm %s" % dump_file)
        pkt_diff = len(Ether()) + len(IP()) + len(UDP()) + 8
        self.pcap_check_bytes(exp_pkt_cnt, pack_cap, pkt, pkt_diff)

        exp_pkt = Ether(src=dut_mac,dst=src_mac)/IP(src=dut_ip, dst=src_ip)/\
                  UDP(sport=0, dport=6081)

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
        self.cleanup_flower(self.dut_ifn[0])
        src_ip = self.src_addr[0].split('/')[0]
        self.dut.cmd('arp -i %s -d %s' % (self.dut_ifn[0], src_ip), fail=False)
        self.dut.cmd('ip link delete gene0', fail=False)
        return super(FlowerActionGENEVE, self).cleanup()

class FlowerActionGENEVEOpt(FlowerBase):
    def install_geneve_opt(self, iface, ingress, dut_ip, src_ip, dut_mac, src_mac, geneve_opt):
        match = 'ip flower skip_sw ip_proto tcp'
        action = 'tunnel_key set id %s src_ip %s dst_ip %s dst_port 6081' \
                 ' geneve_opts %s:%s:%s action mirred egress redirect dev ' \
                 'gene0' % (int(geneve_opt['vni_field'], 16), dut_ip, src_ip, \
                 geneve_opt['opt_class'], geneve_opt['opt_type'], geneve_opt['opt_data'])
        self.install_filter(iface, match, action)

        exp_pkt_cnt = 100
        pkt = Ether(src=self.group.hwaddr_x[0],dst=self.ipv4_mc_mac[0])/\
              IP(src='10.0.0.10', dst='11.0.0.11')/TCP()/Raw('\x00'*64)

        sleep(2)
        self.send_packs(iface, ingress, pkt)
        sleep(2)

        dump_file = os.path.join('/tmp/', 'dump.pcap')
        self.capture_packs(iface, ingress, pkt, dump_file, 'udp dst port 6081')
        pack_cap = rdpcap(dump_file)
        cmd_log("rm %s" % dump_file)
        pkt_diff = len(Ether()) + len(IP()) + len(UDP()) + 8 + int(geneve_opt['ver_opt_len'], 16) * 4
        self.pcap_check_bytes(exp_pkt_cnt, pack_cap, pkt, pkt_diff)

        exp_pkt = Ether(src=dut_mac,dst=src_mac)/IP(src=dut_ip, dst=src_ip)/\
                  UDP(sport=0, dport=6081)

        # create matchable strings from the expected packet (non tested fields may differ)
        geneve_opt_hd = geneve_opt['opt_class'] + geneve_opt['opt_type'] + \
                        geneve_opt['opt_len'] + geneve_opt['opt_data']
        geneve_header = geneve_opt['ver_opt_len'] + '00' + geneve_opt['protocol_type'] + \
                        geneve_opt['vni_field'] + '00' + geneve_opt_hd
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
        self.pcap_cmp_pkt_bytes(pack_cap, str(pkt).encode("hex"), len(Ether()) + len(IP()) + len(UDP()) + 8 + int(geneve_opt['ver_opt_len'], 16) * 4)

        self.cleanup_filter(iface)

    def execute(self):
        self.check_prereq('tc action add tunnel_key help 2>&1 | grep geneve_opts', 'Geneve Option action')
        iface, ingress = self.configure_flower()
        M = self.dut
        A = self.src

        src_ip = self.src_addr[0].split('/')[0]
        dut_ip = self.dut_addr[0].split('/')[0]

        _, src_mac = A.cmd('cat /sys/class/net/%s/address | tr -d "\n"' % self.src_ifn[0])
        _, dut_mac = M.cmd('cat /sys/class/net/%s/address | tr -d "\n"' % self.dut_ifn[0])

        # the destination port is defined by the tc rule - confirmed in both skip_sw and skip_hw
        M.cmd('ip link add name gene0 type geneve dstport 0 external')
        M.cmd('ifconfig gene0 down')
        M.cmd('ifconfig gene0 up')
        M.cmd('arp -i %s -s %s %s' % (self.dut_ifn[0], src_ip, src_mac))

        # Hit test - match all tcp packets and encap in geneve
        geneve_opt = {'ver_opt_len': '02',
                      'protocol_type': '6558',
                      'vni_field' : '00007b',
                      'opt_class' : '0102',
                      'opt_type' : '80',
                      'opt_len' : '01',
                      'opt_data' : '11223344'}
        self.install_geneve_opt(iface, ingress, dut_ip, src_ip, dut_mac, src_mac, geneve_opt)

        geneve_opt = {'ver_opt_len': '03',
                      'protocol_type': '6558',
                      'vni_field' : '0000f6',
                      'opt_class' : '1234',
                      'opt_type' : '88',
                      'opt_len' : '02',
                      'opt_data' : 'a1a2a3a4b1b2b3b4'}
        self.install_geneve_opt(iface, ingress, dut_ip, src_ip, dut_mac, src_mac, geneve_opt)

        geneve_opt = {'ver_opt_len': '04',
                      'protocol_type': '6558',
                      'vni_field' : '00007b',
                      'opt_class' : '0406',
                      'opt_type' : '80',
                      'opt_len' : '03',
                      'opt_data' : '11223344a1a2a3a4b1b2b3b4'}
        self.install_geneve_opt(iface, ingress, dut_ip, src_ip, dut_mac, src_mac, geneve_opt)

        geneve_opt = {'ver_opt_len': '05',
                      'protocol_type': '6558',
                      'vni_field' : '0000f6',
                      'opt_class' : '5678',
                      'opt_type' : 'aa',
                      'opt_len' : '04',
                      'opt_data' : 'a1a2a3a4b1b2b3b41122334455667788'}
        self.install_geneve_opt(iface, ingress, dut_ip, src_ip, dut_mac, src_mac, geneve_opt)

    def cleanup(self):
        self.cleanup_flower(self.dut_ifn[0])
        src_ip = self.src_addr[0].split('/')[0]
        self.dut.cmd('arp -i %s -d %s' % (self.dut_ifn[0], src_ip), fail=False)
        self.dut.cmd('ip link delete gene0', fail=False)
        return super(FlowerActionGENEVEOpt, self).cleanup()

class FlowerActionGENEVEMultiOpt(FlowerBase):
    def install_geneve_opt(self, iface, ingress, dut_ip, src_ip, dut_mac, src_mac, geneve_opt1, geneve_opt2):
        match = 'ip flower skip_sw ip_proto tcp'
        action = 'tunnel_key set id %s src_ip %s dst_ip %s dst_port 6081' \
                ' geneve_opts %s:%s:%s,%s:%s:%s action mirred egress redirect' \
                ' dev gene0' % (int(geneve_opt1['vni_field'], 16), dut_ip, src_ip, \
                 geneve_opt1['opt_class'], geneve_opt1['opt_type'], geneve_opt1['opt_data'],
                 geneve_opt2['opt_class'], geneve_opt2['opt_type'], geneve_opt2['opt_data'])
        self.install_filter(iface, match, action)

        exp_pkt_cnt = 100
        pkt = Ether(src=self.group.hwaddr_x[0],dst=self.ipv4_mc_mac[0])/\
              IP(src='10.0.0.10', dst='11.0.0.11')/TCP()/Raw('\x00'*64)

        sleep(2)
        self.send_packs(iface, ingress, pkt)
        sleep(2)

        dump_file = os.path.join('/tmp/', 'dump.pcap')
        self.capture_packs(iface, ingress, pkt, dump_file, 'udp dst port 6081')
        pack_cap = rdpcap(dump_file)
        cmd_log("rm %s" % dump_file)
        opt_size = int(geneve_opt1['ver_opt_len'], 16) + int(geneve_opt2['ver_opt_len'], 16)
        pkt_diff = len(Ether()) + len(IP()) + len(UDP()) + 8 + opt_size * 4
        self.pcap_check_bytes(exp_pkt_cnt, pack_cap, pkt, pkt_diff)

        exp_pkt = Ether(src=dut_mac,dst=src_mac)/IP(src=dut_ip, dst=src_ip)/\
                  UDP(sport=0, dport=6081)

        # create matchable strings from the expected packet (non tested fields may differ)
        geneve_opt_hd = geneve_opt1['opt_class'] + geneve_opt1['opt_type'] + \
                        geneve_opt1['opt_len'] + geneve_opt1['opt_data']
        geneve_opt_hd += geneve_opt2['opt_class'] + geneve_opt2['opt_type'] + \
                         geneve_opt2['opt_len'] + geneve_opt2['opt_data']
        geneve_header = '{:02d}'.format(opt_size) + '00' + geneve_opt1['protocol_type'] + \
                        geneve_opt1['vni_field'] + '00' + geneve_opt_hd
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
        self.pcap_cmp_pkt_bytes(pack_cap, str(pkt).encode("hex"), len(Ether()) + len(IP()) + len(UDP()) + 8 + opt_size * 4)

        self.cleanup_filter(iface)

    def execute(self):
        self.check_prereq('tc action add tunnel_key help 2>&1 | grep geneve_opts', 'Geneve Option action')
        iface, ingress = self.configure_flower()
        M = self.dut
        A = self.src

        src_ip = self.src_addr[0].split('/')[0]
        dut_ip = self.dut_addr[0].split('/')[0]

        _, src_mac = A.cmd('cat /sys/class/net/%s/address | tr -d "\n"' % self.src_ifn[0])
        _, dut_mac = M.cmd('cat /sys/class/net/%s/address | tr -d "\n"' % self.dut_ifn[0])

        # the destination port is defined by the tc rule - confirmed in both skip_sw and skip_hw
        M.cmd('ip link add name gene0 type geneve dstport 0 external')
        M.cmd('ifconfig gene0 down')
        M.cmd('ifconfig gene0 up')
        M.cmd('arp -i %s -s %s %s' % (self.dut_ifn[0], src_ip, src_mac))

        # Hit test - match all tcp packets and encap in geneve with 2 options
        # Total push action length = 24 Bytes
        geneve_opt1 = {'ver_opt_len': '02',
                       'protocol_type': '6558',
                       'vni_field' : '00007b',
                       'opt_class' : '0102',
                       'opt_type' : '80',
                       'opt_len' : '01',
                       'opt_data' : '11223344'}

        geneve_opt2 = {'ver_opt_len': '02',
                       'protocol_type': '6558',
                       'vni_field' : '0000f6',
                       'opt_class' : '1234',
                       'opt_type' : '88',
                       'opt_len' : '01',
                       'opt_data' : 'a1a2a3a4'}
        self.install_geneve_opt(iface, ingress, dut_ip, src_ip, dut_mac, src_mac, geneve_opt1, geneve_opt2)

        # Hit test - match all tcp packets and encap in geneve with 2 options
        # Total push action length = 32 Bytes
        geneve_opt1 = {'ver_opt_len': '03',
                       'protocol_type': '6558',
                       'vni_field' : '00007b',
                       'opt_class' : '0204',
                       'opt_type' : '77',
                       'opt_len' : '02',
                       'opt_data' : '1122334455667788'}

        geneve_opt2 = {'ver_opt_len': '03',
                       'protocol_type': '6558',
                       'vni_field' : '0000f6',
                       'opt_class' : '5678',
                       'opt_type' : 'ee',
                       'opt_len' : '02',
                       'opt_data' : 'a1a2a3a4b1b2b3b4'}
        self.install_geneve_opt(iface, ingress, dut_ip, src_ip, dut_mac, src_mac, geneve_opt1, geneve_opt2)

    def cleanup(self):
        self.cleanup_flower(self.dut_ifn[0])
        src_ip = self.src_addr[0].split('/')[0]
        self.dut.cmd('arp -i %s -d %s' % (self.dut_ifn[0], src_ip), fail=False)
        self.dut.cmd('ip link delete gene0', fail=False)
        return super(FlowerActionGENEVEMultiOpt, self).cleanup()

class FlowerActionSetEth(FlowerBase):
    def execute(self):
        iface, ingress = self.configure_flower()

        #Mac addrs selection used for testing changing MAC addrs
        dst_addr_a = self.group.hwaddr_a[0][:6] +"01:02:02:01"
        dst_addr_b = self.group.hwaddr_a[0][:6] +"12:34:56:78"
        src_addr_a = self.group.hwaddr_x[0][:6] +"20:19:18:17"
        src_addr_b = self.group.hwaddr_x[0][:6] +"40:50:60:70"

        # Test Output Action
        match = 'ip flower'
        action = 'mirred egress redirect dev %s' % iface
        self.install_filter(iface, match, action)

        pkt = Ether(src=self.group.hwaddr_x[0],dst=self.ipv4_mc_mac[0])/\
              IP(src='10.0.0.10', dst='11.0.0.11')/TCP()/Raw('\x00'*64)
        exp_pkt = Ether(src=self.group.hwaddr_x[0],dst=self.ipv4_mc_mac[0])/\
                  IP(src='10.0.0.10', dst='11.0.0.11')/TCP()/Raw('\x00'*64)
        self.test_filter(iface, ingress, pkt, exp_pkt, 100)

        self.cleanup_filter(iface)

        # Test Set SRC and DST Ethernet
        match = 'ip flower'
        action = 'pedit ex munge eth src set %s munge eth dst set %s ' \
                 'pipe mirred egress redirect dev %s' % (src_addr_a,
                                                         dst_addr_a, iface)
        self.install_filter(iface, match, action)

        pkt = Ether(src=self.group.hwaddr_x[0],dst=self.ipv4_mc_mac[0])/\
              IP(src='10.0.0.10', dst='11.0.0.11')/TCP()/Raw('\x00'*64)
        exp_pkt = Ether(src=src_addr_a,dst=dst_addr_a)/\
                  IP(src='10.0.0.10', dst='11.0.0.11')/TCP()/Raw('\x00'*64)
        self.test_filter(iface, ingress, pkt, exp_pkt, 100)

        self.cleanup_filter(iface)

        # Test Set DST Ethernet
        match = 'ip flower'
        action = 'pedit ex munge eth dst set %s ' \
                 'pipe mirred egress redirect dev %s' % (dst_addr_b, iface)
        self.install_filter(iface, match, action)

        pkt = Ether(src=self.group.hwaddr_x[0],dst=self.ipv4_mc_mac[0])/\
              IP(src='10.0.0.10', dst='11.0.0.11')/TCP()/Raw('\x00'*64)
        exp_pkt = Ether(src=self.group.hwaddr_x[0],dst=dst_addr_b)/\
                  IP(src='10.0.0.10', dst='11.0.0.11')/TCP()/Raw('\x00'*64)
        self.test_filter(iface, ingress, pkt, exp_pkt, 100)

        self.cleanup_filter(iface)

        # Test Set SRC Ethernet
        match = 'ip flower'
        action = 'pedit ex munge eth src set %s ' \
                 'pipe mirred egress redirect dev %s' % (src_addr_b, iface)
        self.install_filter(iface, match, action)

        pkt = Ether(src=self.group.hwaddr_x[0],dst=self.ipv4_mc_mac[0])/\
              IP(src='10.0.0.10', dst='11.0.0.11')/TCP()/Raw('\x00'*64)
        exp_pkt = Ether(src=src_addr_b,dst=self.ipv4_mc_mac[0])/\
                  IP(src='10.0.0.10', dst='11.0.0.11')/TCP()/Raw('\x00'*64)
        self.test_filter(iface, ingress, pkt, exp_pkt, 100)

        self.cleanup_filter(iface)

    def cleanup(self):
        self.cleanup_flower(self.dut_ifn[0])
        return super(FlowerActionSetEth, self).cleanup()

class FlowerActionSetIPv4TTLTOS(FlowerBase):
    def execute(self):
        iface, ingress = self.configure_flower()

        # Test Output Action
        match = 'ip flower'
        action = 'mirred egress redirect dev %s' % iface
        self.install_filter(iface, match, action)

        pkt = Ether(src=self.group.hwaddr_x[0],dst=self.ipv4_mc_mac[0])/\
              IP(src='10.0.0.10', dst='11.0.0.11')/TCP()/Raw('\x00'*64)
        exp_pkt = Ether(src=self.group.hwaddr_x[0],dst=self.ipv4_mc_mac[0])/\
                  IP(src='10.0.0.10', dst='11.0.0.11')/TCP()/Raw('\x00'*64)
        self.test_filter(iface, ingress, pkt, exp_pkt, 100)

        self.cleanup_filter(iface)

        # Test Set TTL and TOS IPv4
        match = 'ip flower ip_proto tcp'
        action = 'pedit ex munge ip ttl set 40 munge ip tos set 20 pipe csum ip and tcp pipe mirred egress redirect dev %s' % iface
        self.install_filter(iface, match, action)

        pkt = Ether(src=self.group.hwaddr_x[0],dst=self.ipv4_mc_mac[0])/\
              IP(src='10.0.0.10', dst='11.0.0.11', ttl=64, tos=50)/\
              TCP()/Raw('\x00'*64)
        exp_pkt = Ether(src=self.group.hwaddr_x[0],dst=self.ipv4_mc_mac[0])/\
                  IP(src='10.0.0.10', dst='11.0.0.11', ttl=40, tos=20)/\
                  TCP()/Raw('\x00'*64)
        self.test_filter(iface, ingress, pkt, exp_pkt, 100)

        self.cleanup_filter(iface)

        # Test Set TTL IPv4
        match = 'ip flower ip_proto tcp'
        action = 'pedit ex munge ip ttl set 30 pipe csum ip and tcp pipe mirred egress redirect dev %s' % iface
        self.install_filter(iface, match, action)

        pkt = Ether(src=self.group.hwaddr_x[0],dst=self.ipv4_mc_mac[0])/\
              IP(src='10.0.0.10', dst='11.0.0.11', ttl=64, tos=50)/\
              TCP()/Raw('\x00'*64)
        exp_pkt = Ether(src=self.group.hwaddr_x[0],dst=self.ipv4_mc_mac[0])/\
                  IP(src='10.0.0.10', dst='11.0.0.11', ttl=30, tos=50)/\
                  TCP()/Raw('\x00'*64)
        self.test_filter(iface, ingress, pkt, exp_pkt, 100)

        self.cleanup_filter(iface)

        # Test Set TOS IPv4
        match = 'ip flower ip_proto tcp'
        action = 'pedit ex munge ip tos set 10 pipe csum ip and tcp pipe mirred egress redirect dev %s' % iface
        self.install_filter(iface, match, action)

        pkt = Ether(src=self.group.hwaddr_x[0],dst=self.ipv4_mc_mac[0])/\
              IP(src='10.0.0.10', dst='11.0.0.11', ttl=64, tos=50)/\
              TCP()/Raw('\x00'*64)
        exp_pkt = Ether(src=self.group.hwaddr_x[0],dst=self.ipv4_mc_mac[0])/\
                IP(src='10.0.0.10', dst='11.0.0.11', ttl=64, tos=10)/\
                TCP()/Raw('\x00'*64)
        self.test_filter(iface, ingress, pkt, exp_pkt, 100)

        self.cleanup_filter(iface)

    def cleanup(self):
        self.cleanup_flower(self.dut_ifn[0])
        return super(FlowerActionSetIPv4TTLTOS, self).cleanup()

class FlowerActionSetIPv4(FlowerBase):
    def execute(self):
        iface, ingress = self.configure_flower()

        # Test Output Action
        match = 'ip flower'
        action = 'mirred egress redirect dev %s' % iface
        self.install_filter(iface, match, action)

        pkt = Ether(src=self.group.hwaddr_x[0],dst=self.ipv4_mc_mac[0])/\
              IP(src='10.0.0.10', dst='11.0.0.11')/TCP()/Raw('\x00'*64)
        exp_pkt = Ether(src=self.group.hwaddr_x[0],dst=self.ipv4_mc_mac[0])/\
                  IP(src='10.0.0.10', dst='11.0.0.11')/TCP()/Raw('\x00'*64)
        self.test_filter(iface, ingress, pkt, exp_pkt, 100)

        self.cleanup_filter(iface)

        # Test Set SRC and DST IPv4
        match = 'ip flower ip_proto tcp'
        action = 'pedit ex munge ip src set 20.30.40.50 munge ip dst set 120.130.140.150 pipe csum ip and tcp pipe mirred egress redirect dev %s' % iface
        self.install_filter(iface, match, action)

        pkt = Ether(src=self.group.hwaddr_x[0],dst=self.ipv4_mc_mac[0])/\
              IP(src='10.0.0.10', dst='11.0.0.11')/TCP()/Raw('\x00'*64)
        exp_pkt = Ether(src=self.group.hwaddr_x[0],dst=self.ipv4_mc_mac[0])/\
                  IP(src='20.30.40.50', dst='120.130.140.150')/\
                  TCP()/Raw('\x00'*64)
        self.test_filter(iface, ingress, pkt, exp_pkt, 100)

        self.cleanup_filter(iface)

        # Test Set DST IPv4
        match = 'ip flower ip_proto tcp'
        action = 'pedit ex munge ip dst set 22.33.44.55 pipe csum ip and tcp pipe mirred egress redirect dev %s' % iface
        self.install_filter(iface, match, action)

        pkt = Ether(src=self.group.hwaddr_x[0],dst=self.ipv4_mc_mac[0])/\
              IP(src='10.0.0.10', dst='11.0.0.11')/TCP()/Raw('\x00'*64)
        exp_pkt = Ether(src=self.group.hwaddr_x[0],dst=self.ipv4_mc_mac[0])/\
                  IP(src='10.0.0.10', dst='22.33.44.55')/TCP()/Raw('\x00'*64)
        self.test_filter(iface, ingress, pkt, exp_pkt, 100)

        self.cleanup_filter(iface)

        # Test Set SRC IPv4
        match = 'ip flower ip_proto tcp'
        action = 'pedit ex munge ip src set 22.33.44.55 pipe csum ip and tcp pipe mirred egress redirect dev %s' % iface
        self.install_filter(iface, match, action)

        pkt = Ether(src=self.group.hwaddr_x[0],dst=self.ipv4_mc_mac[0])/\
              IP(src='10.0.0.10', dst='11.0.0.11')/TCP()/Raw('\x00'*64)
        exp_pkt = Ether(src=self.group.hwaddr_x[0],dst=self.ipv4_mc_mac[0])/\
                  IP(src='22.33.44.55', dst='11.0.0.11')/TCP()/Raw('\x00'*64)
        self.test_filter(iface, ingress, pkt, exp_pkt, 100)

        self.cleanup_filter(iface)

        # Test Set multiple IPv4 DST with partial masks
        match = 'ip flower ip_proto tcp'
        action = 'pedit ex munge ip dst set 88.88.88.88 retain 65280 munge ' +\
                 'ip dst set 77.77.77.77 retain 16711680 pipe ' +\
                 'csum ip and tcp pipe mirred egress redirect dev %s' % iface
        self.install_filter(iface, match, action)

        pkt = Ether(src=self.group.hwaddr_x[0],dst=self.ipv4_mc_mac[0])/\
              IP(src='10.0.0.10', dst='11.0.0.11')/TCP()/Raw('\x00'*64)
        exp_pkt = Ether(src=self.group.hwaddr_x[0],dst=self.ipv4_mc_mac[0])/\
                  IP(src='10.0.0.10', dst='11.77.88.11')/TCP()/Raw('\x00'*64)
        self.test_filter(iface, ingress, pkt, exp_pkt, 100)

        self.cleanup_filter(iface)

        # Test Set multiple IPv4 SRC with partial masks
        match = 'ip flower ip_proto tcp'
        action = 'pedit ex munge ip src set 22.33.44.55 retain 65535 munge ' +\
                 'ip src set 66.77.88.99 retain 4294901760 pipe ' +\
                 'csum ip and tcp pipe mirred egress redirect dev %s' % iface
        self.install_filter(iface, match, action)

        pkt = Ether(src=self.group.hwaddr_x[0],dst=self.ipv4_mc_mac[0])/\
              IP(src='10.0.0.10', dst='11.0.0.11')/TCP()/Raw('\x00'*64)
        exp_pkt = Ether(src=self.group.hwaddr_x[0],dst=self.ipv4_mc_mac[0])/\
                  IP(src='66.77.44.55', dst='11.0.0.11')/TCP()/Raw('\x00'*64)
        self.test_filter(iface, ingress, pkt, exp_pkt, 100)

        self.cleanup_filter(iface)

    def cleanup(self):
        self.cleanup_flower(self.dut_ifn[0])
        return super(FlowerActionSetIPv4, self).cleanup()

class FlowerActionSetIPv6HopLimitFlowLabel(FlowerBase):
    def execute(self):
        iface, ingress = self.configure_flower()
        new_filter = '"not arp and' \
                     ' not udp port 5353 and' \
                     ' not ether host 01:80:c2:00:00:0e and' \
                     ' not ether host ff:ff:ff:ff:ff:ff"'

        # Test Output Action
        match = 'ip flower'
        action = 'mirred egress redirect dev %s' % iface
        self.install_filter(iface, match, action)

        pkt = Ether(src=self.group.hwaddr_x[0],dst=self.ipv4_mc_mac[0])/\
              IP(src='10.0.0.10', dst='11.0.0.11')/TCP()/Raw('\x00'*64)
        exp_pkt = Ether(src=self.group.hwaddr_x[0],dst=self.ipv4_mc_mac[0])/\
                  IP(src='10.0.0.10', dst='11.0.0.11')/TCP()/Raw('\x00'*64)
        self.test_filter(iface, ingress, pkt, exp_pkt, 100, fltr=new_filter)

        self.cleanup_filter(iface)

        # Test Set Hop Limit and Flow Label IPv6
        match = 'ipv6 flower ip_proto tcp'
        action = 'pedit ex munge ip6 hoplimit set 50 munge ip6 flow_lbl set 333 pipe ' +\
                 'csum tcp pipe mirred egress redirect dev %s' % iface
        self.install_filter(iface, match, action)

        pkt = Ether(src=self.group.hwaddr_x[0],dst=self.ipv6_mc_mac[0])/\
              IPv6(hlim=34, fl=1111)/TCP()/Raw('\x00'*64)
        exp_pkt = Ether(src=self.group.hwaddr_x[0],dst=self.ipv6_mc_mac[0])/\
                  IPv6(hlim=50, fl=333)/TCP()/Raw('\x00'*64)
        self.test_filter(iface, ingress, pkt, exp_pkt, 100, fltr=new_filter)

        self.cleanup_filter(iface)

        # Test Set Hop Limit IPv6
        match = 'ipv6 flower ip_proto tcp'
        action = 'pedit ex munge ip6 hoplimit set 20 pipe ' +\
                 'csum tcp pipe mirred egress redirect dev %s' % iface
        self.install_filter(iface, match, action)

        pkt = Ether(src=self.group.hwaddr_x[0],dst=self.ipv6_mc_mac[0])/\
              IPv6(hlim=34, fl=1111)/TCP()/Raw('\x00'*64)
        exp_pkt = Ether(src=self.group.hwaddr_x[0],dst=self.ipv6_mc_mac[0])/\
                  IPv6(hlim=20, fl=1111)/TCP()/Raw('\x00'*64)
        self.test_filter(iface, ingress, pkt, exp_pkt, 100, fltr=new_filter)

        self.cleanup_filter(iface)

        # Test Set Flow Label IPv6
        match = 'ipv6 flower ip_proto tcp'
        action = 'pedit ex munge ip6 flow_lbl set 242 pipe ' +\
                 'csum tcp pipe mirred egress redirect dev %s' % iface
        self.install_filter(iface, match, action)

        pkt = Ether(src=self.group.hwaddr_x[0],dst=self.ipv6_mc_mac[0])/\
              IPv6(hlim=34, fl=1111)/TCP()/Raw('\x00'*64)
        exp_pkt = Ether(src=self.group.hwaddr_x[0],dst=self.ipv6_mc_mac[0])/\
                  IPv6(hlim=34, fl=242)/TCP()/Raw('\x00'*64)
        self.test_filter(iface, ingress, pkt, exp_pkt, 100, fltr=new_filter)

        self.cleanup_filter(iface)

    def cleanup(self):
        self.cleanup_flower(self.dut_ifn[0])
        return super(FlowerActionSetIPv6HopLimitFlowLabel, self).cleanup()

class FlowerActionSetIPv6(FlowerBase):
    def execute(self):
        iface, ingress = self.configure_flower()
        new_filter = '"not arp and' \
                     ' not udp port 5353 and' \
                     ' not ether host 01:80:c2:00:00:0e and' \
                     ' not ether host ff:ff:ff:ff:ff:ff"'

        # Test Output Action
        match = 'ip flower'
        action = 'mirred egress redirect dev %s' % iface
        self.install_filter(iface, match, action)

        pkt = Ether(src=self.group.hwaddr_x[0],dst=self.ipv4_mc_mac[0])/\
              IP(src='10.0.0.10', dst='11.0.0.11')/TCP()/Raw('\x00'*64)
        exp_pkt = Ether(src=self.group.hwaddr_x[0],dst=self.ipv4_mc_mac[0])/\
                  IP(src='10.0.0.10', dst='11.0.0.11')/TCP()/Raw('\x00'*64)
        self.test_filter(iface, ingress, pkt, exp_pkt, 100, fltr=new_filter)

        self.cleanup_filter(iface)

        # Test Set SRC and DST IPv6
        match = 'ipv6 flower ip_proto tcp'
        action = 'pedit ex munge ip6 src set 1234:2345:3456:4567:5678:6789:7890:8901 munge ' +\
                 'ip6 dst set 1000:2000:3000:4000:5000:6000:7000:8000 pipe csum tcp pipe mirred egress redirect dev %s' % iface
        self.install_filter(iface, match, action)

        pkt = Ether(src=self.group.hwaddr_x[0],dst=self.ipv6_mc_mac[0])/\
              IPv6(src='11::11', dst='10::10')/TCP()/Raw('\x00'*64)
        exp_pkt = Ether(src=self.group.hwaddr_x[0],dst=self.ipv6_mc_mac[0])/\
                  IPv6(src='1234:2345:3456:4567:5678:6789:7890:8901',
                       dst='1000:2000:3000:4000:5000:6000:7000:8000')/\
                  TCP()/Raw('\x00'*64)
        self.test_filter(iface, ingress, pkt, exp_pkt, 100, fltr=new_filter)

        self.cleanup_filter(iface)

        # Test Set DST IPv6
        match = 'ipv6 flower ip_proto tcp'
        action = 'pedit ex munge ip6 dst set 1234:2345:3456:4567:5678:6789:7890:8901 pipe csum tcp pipe mirred egress redirect dev %s' % iface
        self.install_filter(iface, match, action)

        exp_pkt = Ether(src=self.group.hwaddr_x[0],dst=self.ipv6_mc_mac[0])/\
                  IPv6(src='11::11',
                       dst='1234:2345:3456:4567:5678:6789:7890:8901')/\
                  TCP()/Raw('\x00'*64)
        self.test_filter(iface, ingress, pkt, exp_pkt, 100, fltr=new_filter)

        self.cleanup_filter(iface)

        # Test Set SRC IPv6
        match = 'ipv6 flower ip_proto tcp'
        action = 'pedit ex munge ip6 src set 1234:2345:3456:4567:5678:6789:7890:8901 pipe csum tcp pipe mirred egress redirect dev %s' % iface
        self.install_filter(iface, match, action)

        pkt = Ether(src=self.group.hwaddr_x[0],dst=self.ipv6_mc_mac[0])/\
              IPv6(src='11::11', dst='10::10')/TCP()/Raw('\x00'*64)
        exp_pkt = Ether(src=self.group.hwaddr_x[0],dst=self.ipv6_mc_mac[0])/\
                  IPv6(src='1234:2345:3456:4567:5678:6789:7890:8901',
                       dst='10::10')/TCP()/Raw('\x00'*64)
        self.test_filter(iface, ingress, pkt, exp_pkt, 100, fltr=new_filter)

        self.cleanup_filter(iface)

    def cleanup(self):
        self.cleanup_flower(self.dut_ifn[0])
        return super(FlowerActionSetIPv6, self).cleanup()

class FlowerActionSetUDP(FlowerBase):
    def execute(self):
        iface, ingress = self.configure_flower()

        # Test Output Action
        match = 'ip flower'
        action = 'mirred egress redirect dev %s' % iface
        self.install_filter(iface, match, action)

        pkt = Ether(src=self.group.hwaddr_x[0],dst=self.ipv4_mc_mac[0])/\
              IP(src='10.0.0.10', dst='11.0.0.11')/TCP()/Raw('\x00'*64)
        exp_pkt = Ether(src=self.group.hwaddr_x[0],dst=self.ipv4_mc_mac[0])/\
                  IP(src='10.0.0.10', dst='11.0.0.11')/TCP()/Raw('\x00'*64)
        self.test_filter(iface, ingress, pkt, exp_pkt, 100)

        self.cleanup_filter(iface)

        # Test Set SRC and DST UDP
        match = 'ip flower ip_proto udp'
        action = 'pedit ex munge udp sport set 4282 munge udp dport set 8242 pipe csum udp pipe mirred egress redirect dev %s' % iface
        self.install_filter(iface, match, action)

        pkt = Ether(src=self.group.hwaddr_x[0],dst=self.ipv4_mc_mac[0])/\
              IP(src='10.0.0.10', dst='11.0.0.11')/UDP(sport=1000,dport=2000)/\
              Raw('\x00'*64)
        exp_pkt = Ether(src=self.group.hwaddr_x[0],dst=self.ipv4_mc_mac[0])/\
                  IP(src='10.0.0.10', dst='11.0.0.11')/\
                  UDP(sport=4282,dport=8242)/Raw('\x00'*64)
        self.test_filter(iface, ingress, pkt, exp_pkt, 100)

        self.cleanup_filter(iface)

        # Test Set DST UDP
        match = 'ip flower ip_proto udp'
        action = 'pedit ex munge udp dport set 2000 pipe csum udp pipe mirred egress redirect dev %s' % iface
        self.install_filter(iface, match, action)

        pkt = Ether(src=self.group.hwaddr_x[0],dst=self.ipv4_mc_mac[0])/\
              IP(src='10.0.0.10', dst='11.0.0.11')/\
              UDP(sport=2222,dport=4444)/Raw('\x00'*64)
        exp_pkt = Ether(src=self.group.hwaddr_x[0],dst=self.ipv4_mc_mac[0])/\
                  IP(src='10.0.0.10', dst='11.0.0.11')/\
                  UDP(sport=2222,dport=2000)/Raw('\x00'*64)
        self.test_filter(iface, ingress, pkt, exp_pkt, 100)

        self.cleanup_filter(iface)

        # Test Set SRC UDP
        match = 'ip flower ip_proto udp'
        action = 'pedit ex munge udp sport set 4000 pipe csum udp pipe mirred egress redirect dev %s' % iface
        self.install_filter(iface, match, action)

        pkt = Ether(src=self.group.hwaddr_x[0],dst=self.ipv4_mc_mac[0])/\
              IP(src='10.0.0.10', dst='11.0.0.11')/\
              UDP(sport=2222,dport=4444)/Raw('\x00'*64)
        exp_pkt = Ether(src=self.group.hwaddr_x[0],dst=self.ipv4_mc_mac[0])/\
                  IP(src='10.0.0.10', dst='11.0.0.11')/\
                  UDP(sport=4000,dport=4444)/Raw('\x00'*64)
        self.test_filter(iface, ingress, pkt, exp_pkt, 100)

        self.cleanup_filter(iface)

        # Test Set DST UDP with multi masks
        match = 'ip flower ip_proto udp'
        action = 'pedit ex munge udp dport set 5555 retain 240 munge '+\
                 'udp dport set 7777 retain 3840 pipe '+\
                 'csum udp pipe mirred egress redirect dev %s' % iface
        self.install_filter(iface, match, action)

        pkt = Ether(src=self.group.hwaddr_x[0],dst=self.ipv4_mc_mac[0])/\
              IP(src='10.0.0.10', dst='11.0.0.11')/\
              UDP(sport=2222,dport=4444)/Raw('\x00'*64)
        exp_pkt = Ether(src=self.group.hwaddr_x[0],dst=self.ipv4_mc_mac[0])/\
                  IP(src='10.0.0.10', dst='11.0.0.11')/\
                  UDP(sport=2222,dport=7868)/Raw('\x00'*64)
        self.test_filter(iface, ingress, pkt, exp_pkt, 100)

        self.cleanup_filter(iface)

        # Test Set SRC UDP with multi masks
        match = 'ip flower ip_proto udp'
        action = 'pedit ex munge udp sport set 1111 retain 255 munge '+\
                 'udp sport set 3333 retain 65280 pipe '+\
                 'csum udp pipe mirred egress redirect dev %s' % iface
        self.install_filter(iface, match, action)

        pkt = Ether(src=self.group.hwaddr_x[0],dst=self.ipv4_mc_mac[0])/\
              IP(src='10.0.0.10', dst='11.0.0.11')/\
              UDP(sport=2222,dport=4444)/Raw('\x00'*64)
        exp_pkt = Ether(src=self.group.hwaddr_x[0],dst=self.ipv4_mc_mac[0])/\
                  IP(src='10.0.0.10', dst='11.0.0.11')/\
                  UDP(sport=3415,dport=4444)/Raw('\x00'*64)
        self.test_filter(iface, ingress, pkt, exp_pkt, 100)

        self.cleanup_filter(iface)

    def cleanup(self):
        self.cleanup_flower(self.dut_ifn[0])
        return super(FlowerActionSetUDP, self).cleanup()

class FlowerActionSetTCP(FlowerBase):
    def execute(self):
        iface, ingress = self.configure_flower()

        # Test Output Action
        match = 'ip flower'
        action = 'mirred egress redirect dev %s' % iface
        self.install_filter(iface, match, action)

        pkt = Ether(src=self.group.hwaddr_x[0],dst=self.ipv4_mc_mac[0])/\
              IP(src='10.0.0.10', dst='11.0.0.11')/TCP()/Raw('\x00'*64)
        exp_pkt = Ether(src=self.group.hwaddr_x[0],dst=self.ipv4_mc_mac[0])/\
                  IP(src='10.0.0.10', dst='11.0.0.11')/TCP()/Raw('\x00'*64)
        self.test_filter(iface, ingress, pkt, exp_pkt, 100)

        self.cleanup_filter(iface)

        # Test Set SRC and DST TCP
        match = 'ip flower ip_proto tcp'
        action = 'pedit ex munge tcp sport set 4282 munge tcp dport set 8242 pipe csum tcp pipe mirred egress redirect dev %s' % iface
        self.install_filter(iface, match, action)

        pkt = Ether(src=self.group.hwaddr_x[0],dst=self.ipv4_mc_mac[0])/\
              IP(src='10.0.0.10', dst='11.0.0.11')/\
              TCP(sport=1000,dport=2000)/Raw('\x00'*64)
        exp_pkt = Ether(src=self.group.hwaddr_x[0],dst=self.ipv4_mc_mac[0])/\
                  IP(src='10.0.0.10', dst='11.0.0.11')/\
                  TCP(sport=4282,dport=8242)/Raw('\x00'*64)
        self.test_filter(iface, ingress, pkt, exp_pkt, 100)

        self.cleanup_filter(iface)

        # Test Set DST TCP
        match = 'ip flower ip_proto tcp'
        action = 'pedit ex munge tcp dport set 2000 pipe csum tcp pipe mirred egress redirect dev %s' % iface
        self.install_filter(iface, match, action)

        pkt = Ether(src=self.group.hwaddr_x[0],dst=self.ipv4_mc_mac[0])/\
              IP(src='10.0.0.10', dst='11.0.0.11')/\
              TCP(sport=2222,dport=4444)/Raw('\x00'*64)
        exp_pkt = Ether(src=self.group.hwaddr_x[0],dst=self.ipv4_mc_mac[0])/\
                  IP(src='10.0.0.10', dst='11.0.0.11')/\
                  TCP(sport=2222,dport=2000)/Raw('\x00'*64)
        self.test_filter(iface, ingress, pkt, exp_pkt, 100)

        self.cleanup_filter(iface)

        # Test Set SRC UDP
        match = 'ip flower ip_proto tcp'
        action = 'pedit ex munge tcp sport set 4000 pipe csum tcp pipe mirred egress redirect dev %s' % iface
        self.install_filter(iface, match, action)

        pkt = Ether(src=self.group.hwaddr_x[0],dst=self.ipv4_mc_mac[0])/\
              IP(src='10.0.0.10', dst='11.0.0.11')/\
              TCP(sport=2222,dport=4444)/Raw('\x00'*64)
        exp_pkt = Ether(src=self.group.hwaddr_x[0],dst=self.ipv4_mc_mac[0])/\
                  IP(src='10.0.0.10', dst='11.0.0.11')/\
                  TCP(sport=4000,dport=4444)/Raw('\x00'*64)
        self.test_filter(iface, ingress, pkt, exp_pkt, 100)

        self.cleanup_filter(iface)

        # Test Set DST TCP with multi masks
        match = 'ip flower ip_proto tcp'
        action = 'pedit ex munge tcp dport set 6666 retain 15 munge '+\
                 'tcp dport set 9999 retain 61440 pipe '+\
                 'csum tcp pipe mirred egress redirect dev %s' % iface
        self.install_filter(iface, match, action)

        pkt = Ether(src=self.group.hwaddr_x[0],dst=self.ipv4_mc_mac[0])/\
              IP(src='10.0.0.10', dst='11.0.0.11')/\
              TCP(sport=2222,dport=4444)/Raw('\x00'*64)
        exp_pkt = Ether(src=self.group.hwaddr_x[0],dst=self.ipv4_mc_mac[0])/\
                  IP(src='10.0.0.10', dst='11.0.0.11')/\
                  TCP(sport=2222,dport=8538)/Raw('\x00'*64)
        self.test_filter(iface, ingress, pkt, exp_pkt, 100)

        self.cleanup_filter(iface)

        # Test Set SRC TCP with multi masks
        match = 'ip flower ip_proto tcp'
        action = 'pedit ex munge tcp sport set 1111 retain 3840 munge '+\
                 'tcp sport set 3333 retain 240 pipe '+\
                 'csum tcp pipe mirred egress redirect dev %s' % iface
        self.install_filter(iface, match, action)

        pkt = Ether(src=self.group.hwaddr_x[0],dst=self.ipv4_mc_mac[0])/\
              IP(src='10.0.0.10', dst='11.0.0.11')/\
              TCP(sport=2222,dport=4444)/Raw('\x00'*64)
        exp_pkt = Ether(src=self.group.hwaddr_x[0],dst=self.ipv4_mc_mac[0])/\
                  IP(src='10.0.0.10', dst='11.0.0.11')/\
                  TCP(sport=1038,dport=4444)/Raw('\x00'*64)
        self.test_filter(iface, ingress, pkt, exp_pkt, 100)

        self.cleanup_filter(iface)

    def cleanup(self):
        self.cleanup_flower(self.dut_ifn[0])
        return super(FlowerActionSetTCP, self).cleanup()

class FlowerActionSetMulti(FlowerBase):
    def execute(self):
        iface, ingress = self.configure_flower()
        new_filter = '"not arp and' \
                     ' not udp port 5353 and' \
                     ' not ether host 01:80:c2:00:00:0e and' \
                     ' not ether host ff:ff:ff:ff:ff:ff"'

        #Mac addrs selection used for testing changing MAC addrs
        dst_addr_a = self.group.hwaddr_a[0][:6] +"01:02:02:01"
        dst_addr_b = self.group.hwaddr_a[0][:6] +"12:34:56:78"
        src_addr_a = self.group.hwaddr_x[0][:6] +"20:19:18:17"
        src_addr_b = self.group.hwaddr_x[0][:6] +"40:50:60:70"

        # Test Output Action
        match = 'ip flower'
        action = 'mirred egress redirect dev %s' % iface
        self.install_filter(iface, match, action)

        pkt = Ether(src=self.group.hwaddr_x[0],dst=self.ipv4_mc_mac[0])/\
              IP(src='10.0.0.10', dst='11.0.0.11')/TCP()/Raw('\x00'*64)
        exp_pkt = Ether(src=self.group.hwaddr_x[0],dst=self.ipv4_mc_mac[0])/\
                  IP(src='10.0.0.10', dst='11.0.0.11')/TCP()/Raw('\x00'*64)
        self.test_filter(iface, ingress, pkt, exp_pkt, 100)

        self.cleanup_filter(iface)

        # Test Set SRC ETH, SRC IP and SRC TCP
        match = 'ip flower ip_proto tcp'
        action = 'pedit ex munge eth src set %s munge ' \
                 'ip src set 66.77.88.99 munge ' \
                 'tcp sport set 4282 pipe ' \
                 'csum ip and tcp pipe ' \
                 'mirred egress redirect dev %s' % (src_addr_a, iface)
        self.install_filter(iface, match, action)

        pkt = Ether(src=self.group.hwaddr_x[0],dst=self.ipv4_mc_mac[0])/\
              IP(src='10.0.0.10', dst='11.0.0.11')/\
              TCP(sport=1000,dport=2000)/Raw('\x00'*64)
        exp_pkt = Ether(src=src_addr_a,dst=self.ipv4_mc_mac[0])/\
                  IP(src='66.77.88.99', dst='11.0.0.11')/\
                  TCP(sport=4282,dport=2000)/Raw('\x00'*64)
        self.test_filter(iface, ingress, pkt, exp_pkt, 100)

        self.cleanup_filter(iface)

        # Test Set DST ETH, DST IP and DST TCP
        match = 'ip flower ip_proto tcp'
        action = 'pedit ex munge eth dst set %s munge ' \
                 'ip dst set 99.88.77.66 munge ' \
                 'tcp dport set 8242 pipe ' \
                 'csum ip and tcp pipe ' \
                 'mirred egress redirect dev %s' % (dst_addr_a, iface)
        self.install_filter(iface, match, action)

        pkt = Ether(src=self.group.hwaddr_x[0],dst=self.ipv4_mc_mac[0])/\
              IP(src='10.0.0.10', dst='11.0.0.11')/\
              TCP(sport=1000,dport=2000)/Raw('\x00'*64)
        exp_pkt = Ether(src=self.group.hwaddr_x[0],dst=dst_addr_a)/\
                  IP(src='10.0.0.10', dst='99.88.77.66')/\
                  TCP(sport=1000,dport=8242)/Raw('\x00'*64)
        self.test_filter(iface, ingress, pkt, exp_pkt, 100)

        self.cleanup_filter(iface)

        # Test Set SRC ETH, SRC IPv6 and SRC TCP
        match = 'ipv6 flower ip_proto tcp'
        action = 'pedit ex munge eth src set %s munge ' \
                 'ip6 src set 1000:2000:3000:4000:5000:6000:7000:8000 munge ' \
                 'tcp sport set 4282 pipe ' \
                 'csum tcp pipe ' \
                 'mirred egress redirect dev %s' % (src_addr_b, iface)
        self.install_filter(iface, match, action)

        pkt = Ether(src=self.group.hwaddr_x[0],dst=self.ipv6_mc_mac[0])/\
              IPv6(src='11::11', dst='10::10')/\
              TCP(sport=1000,dport=2000)/Raw('\x00'*64)
        exp_pkt = Ether(src=src_addr_b,dst=self.ipv6_mc_mac[0])/\
                  IPv6(src='1000:2000:3000:4000:5000:6000:7000:8000',
                       dst='10::10')/\
                  TCP(sport=4282,dport=2000)/Raw('\x00'*64)
        self.test_filter(iface, ingress, pkt, exp_pkt, 100, fltr=new_filter)

        self.cleanup_filter(iface)

        # Test Set DST ETH, DST IPv6 and DST TCP
        match = 'ipv6 flower ip_proto tcp'
        action = 'pedit ex munge eth dst set %s munge ' \
                 'ip6 dst set 1000:2000:3000:4000:5000:6000:7000:8000 munge ' \
                 'tcp dport set 4282 pipe ' \
                 'csum tcp pipe ' \
                 'mirred egress redirect dev %s' % (dst_addr_b, iface)
        self.install_filter(iface, match, action)

        pkt = Ether(src=self.group.hwaddr_x[0],dst=self.ipv6_mc_mac[0])/\
              IPv6(src='11::11', dst='10::10')/\
              TCP(sport=1000,dport=2000)/Raw('\x00'*64)
        exp_pkt = Ether(src=self.group.hwaddr_x[0],dst=dst_addr_b)/\
                  IPv6(src='11::11',
                       dst='1000:2000:3000:4000:5000:6000:7000:8000')/\
                  TCP(sport=1000,dport=4282)/Raw('\x00'*64)
        self.test_filter(iface, ingress, pkt, exp_pkt, 100, fltr=new_filter)

        self.cleanup_filter(iface)

    def cleanup(self):
        self.cleanup_flower(self.dut_ifn[0])
        return super(FlowerActionSetMulti, self).cleanup()

class FlowerVlanRepr(FlowerBase):
    def execute(self):
        iface, _ = self.configure_vlan_flower(50)

        # Check that redirects to upper netdevs is installed in software only (not_in_hw)
        match = 'ip flower'
        action = 'mirred egress redirect dev %s' % iface
        self.install_filter(iface, match, action, False)
        self.cleanup_filter(iface)

        iface, _ = self.configure_vlan_flower(100)

        # Check that redirects to upper netdevs is installed in software only (not_in_hw)
        match = 'ip flower'
        action = 'mirred egress redirect dev %s' % iface
        self.install_filter(iface, match, action, False)
        self.cleanup_filter(iface)

    def cleanup(self):
        vlan_iface = '%s.%s' % (self.dut_ifn[0], 50)
        self.cleanup_flower(vlan_iface)
        vlan_iface = '%s.%s' % (self.dut_ifn[0], 100)
        self.cleanup_flower(vlan_iface)
        return super(FlowerVlanRepr, self).cleanup()

class FlowerReprLinkstate(CommonTest):
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

    def execute(self):
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
        self.netdev_prep()
        self.dmesg_check()

class FlowerActionBondEgress(FlowerBase):
    def execute(self):
        self.check_prereq('teamnl --help 2>&1 | grep setoption', 'OPT_NAME OPT_VALUE')
        iface, ingress = self.configure_flower()
        M = self.dut
        A = self.src

        new_filter = '"not arp and' \
                     ' not ip6 and' \
                     ' not udp port 5353 and' \
                     ' not ether host 01:80:c2:00:00:0e and' \
                     ' not ether host ff:ff:ff:ff:ff:ff"'

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

        pkt = Ether(src=self.group.hwaddr_x[0],dst=self.ipv4_mc_mac[0])/\
              IP(src='10.0.0.10', dst='11.0.0.11')/TCP()/Raw('\x00'*64)
        self.test_filter(iface, ingress, pkt, pkt, 100)

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
                pkts.append(Ether(src=self.group.hwaddr_x[0],
                                  dst=self.ipv4_mc_mac[0])/
                            IP(src=src_ip, dst='11.0.0.11')/
                            TCP()/Raw('\x00'*64))

        self.capture_packs_multiple_ifaces(iface, ingress, [ingress, ingress2],
                                           pkts, [dump_file, dump_file2],
                                           dump_filter=new_filter, loop=1)

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

        self.capture_packs_multiple_ifaces(iface, ingress, [ingress, ingress2],
                                           pkts, [dump_file, dump_file2],
                                           dump_filter=new_filter, loop=1)

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

        self.capture_packs_multiple_ifaces(iface, ingress, [ingress, ingress2],
                                           pkts, [dump_file, dump_file2],
                                           dump_filter=new_filter, loop=1)

        pack_cap = rdpcap(dump_file)
        pack_cap2 = rdpcap(dump_file2)

        self.pcap_check_count_multiple_ifaces(100, [pack_cap, pack_cap2], spread=True)

        cmd_log("rm %s" % dump_file)
        cmd_log("rm %s" % dump_file2)

        self.cleanup_filter(iface)

    def cleanup(self):
        self.cleanup_flower(self.dut_ifn[0])
        self.dut.cmd('ip link set %s nomaster' % self.dut_ifn[0], fail=False)
        if len(self.dut_ifn) > 1:
            self.dut.cmd('ip link set %s nomaster' % self.dut_ifn[1], fail=False)
        self.dut.cmd('modprobe -r bonding || :', fail=False)
        self.dut.cmd('ip link del dev team0', fail=False)
        self.dut.cmd('modprobe -r team_mode_loadbalance || :', fail=False)
        self.dut.cmd('modprobe -r team || :', fail=False)
        return super(FlowerActionBondEgress, self).cleanup()

class FlowerActionIngressRateLimit(FlowerBase):
    def execute(self):
        self.check_prereq("netserver -h 2>&1 | grep Usage:",
                          'netserver missing', on_src=True)
        self.check_prereq("netperf -h 2>&1 | grep Usage:", 'netperf missing')

        netperf_ip_1 = '20.0.0.10'
        netperf_ip_2 = '20.0.0.20'
        vf1, self.vf_repr1 = self.spawn_vf_netdev()
        vf2, self.vf_repr2 = self.spawn_vf_netdev()

        iface = self.dut_ifn[0]
        if not iface[:-1].endswith('np') or not iface.startswith('en'):
            raise NtiSkip('Cannot determine PF interface name')

        pf_ifname = iface[:-3]
        self.dut.cmd('ip link set dev %s up' % (pf_ifname), fail=False)

        self.dut.cmd('ip link set dev %s up' % self.vf_repr1)
        self.dut.cmd('tc qdisc del dev %s handle ffff: ingress' % self.vf_repr1, fail=False)
        self.dut.cmd('tc qdisc add dev %s handle ffff: ingress' % self.vf_repr1)

        self.dut.cmd('ip link set dev %s up' % self.vf_repr2)
        self.dut.cmd('tc qdisc del dev %s handle ffff: ingress' % self.vf_repr2, fail=False)
        self.dut.cmd('tc qdisc add dev %s handle ffff: ingress' % self.vf_repr2)

        # Configure rate limiter 1 - 1 mbps
        match = 'all prio 1 matchall'
        action = 'police rate 1000000 burst 275000 conform-exceed drop/continue'
        self.install_filter(self.vf_repr1, match, action)

        # Configure rate limiter 2 - 10 mbps
        match = 'all prio 1 matchall'
        action = 'police rate 10000000 burst 2200000 conform-exceed drop/continue'
        self.install_filter(self.vf_repr2, match, action)

        # Configure Output Action
        match = 'ip prio 2 flower'
        action = 'mirred egress redirect dev %s' % self.vf_repr2
        self.install_filter(self.vf_repr1, match, action)

        match = 'ip prio 2 flower'
        action = 'mirred egress redirect dev %s' % self.vf_repr1
        self.install_filter(self.vf_repr2, match, action)

        match = 'all prio 3 flower'
        action = 'mirred egress redirect dev %s' % self.vf_repr2
        self.install_filter(self.vf_repr1, match, action, False)

        match = 'all prio 3 flower'
        action = 'mirred egress redirect dev %s' % self.vf_repr1
        self.install_filter(self.vf_repr2, match, action, False)

        # Create namespaces
        self.dut.cmd('ip netns add ns1')
        self.dut.cmd('ip link set %s netns ns1' % vf1)
        self.dut.cmd('ip netns add ns2')
        self.dut.cmd('ip link set %s netns ns2' % vf2)

        # Prepare namespace for netperf
        self.dut.cmd('ip netns exec ns1 ip addr add %s/24 dev %s' % (netperf_ip_1, vf1))
        self.dut.cmd('ip netns exec ns1 ip link set dev %s up' % vf1)
        self.dut.cmd('ip netns exec ns2 ip addr add %s/24 dev %s' % (netperf_ip_2, vf2))
        self.dut.cmd('ip netns exec ns2 ip link set dev %s up' % vf2)

        # Start netperf - 1 mbps
        self.dut.cmd('ip netns exec ns2 netserver')
        ret, out = self.dut.cmd('ip netns exec ns1 netperf -H %s -l 60' % netperf_ip_2)
        rate_line = out.split('\n')[-2].strip()
        rate = float(rate_line.split()[-1])
        if rate > 1.15:
            raise NtiError("Rate equals more than 15%% the expected rate: %.2f" % rate)
        elif rate < 0.85:
            raise NtiError("Rate equals less than 15%% the expected rate: %.2f" % rate)

        # Check stats - vf1 - 1 mbps
        stats = self.dut.netifs[self.vf_repr1].stats(get_tc_ing=True)
        ret, out = self.dut.cmd('ip netns exec ns1 cat /proc/net/dev | grep %s' % vf1)
        # Packet stats
        matchall_pkt_stats = stats.tc_ing['tc_1_pkts']
        actual_sent_pkt = float(out.split()[10])
        point_1_stats = actual_sent_pkt * 0.01
        abs_diff_stats = abs(matchall_pkt_stats - actual_sent_pkt)
        if abs_diff_stats > point_1_stats:
            raise NtiError("Packet stats differ by more than 1%%: %.2f" % abs_diff_stats)
        # Bytes stats
        matchall_bytes_stats = stats.tc_ing['tc_1_bytes']
        actual_sent_bytes = float(out.split()[9]) + (len(Ether()) * actual_sent_pkt)
        point_1_stats = actual_sent_bytes * 0.01
        abs_diff_stats = abs(matchall_bytes_stats - actual_sent_bytes)
        if abs_diff_stats > point_1_stats:
            raise NtiError("Byte stats differ by more than 1%%: %.2f" % abs_diff_stats)

        # Start netperf - 10 mbps
        self.dut.cmd('ip netns exec ns1 netserver')
        ret, out = self.dut.cmd('ip netns exec ns2 netperf -H %s -l 60' % netperf_ip_1)
        rate_line = out.split('\n')[-2].strip()
        rate = float(rate_line.split()[-1])
        if rate > 11.5:
            raise NtiError("Rate equals more than 15%% the expected rate: %.2f" % rate)
        elif rate < 8.5:
            raise NtiError("Rate equals less than 15%% the expected rate: %.2f" % rate)

        # Check stats - vf2 - 10 mbps
        stats = self.dut.netifs[self.vf_repr2].stats(get_tc_ing=True)
        ret, out = self.dut.cmd('ip netns exec ns2 cat /proc/net/dev | grep %s' % vf2)
        # Packet stats
        matchall_pkt_stats = stats.tc_ing['tc_1_pkts']
        actual_sent_pkt = float(out.split()[10])
        point_1_stats = actual_sent_pkt * 0.01
        abs_diff_stats = abs(-matchall_pkt_stats + actual_sent_pkt)
        if abs_diff_stats > point_1_stats:
            raise NtiError("Stats differ by more than 1%%: %.2f" % abs_diff_stats)
        # Bytes stats
        matchall_bytes_stats = stats.tc_ing['tc_1_bytes']
        actual_sent_bytes = float(out.split()[9]) + (len(Ether()) * actual_sent_pkt)
        point_1_stats = actual_sent_bytes * 0.01
        abs_diff_stats = abs(matchall_bytes_stats - actual_sent_bytes)
        if abs_diff_stats > point_1_stats:
            raise NtiError("Byte stats differ by more than 1%%: %.2f" % abs_diff_stats)

        self.cleanup_filter(self.vf_repr1)
        self.cleanup_filter(self.vf_repr2)

    def cleanup(self):
        self.dut.cmd('ip netns del ns1', fail=False)
        self.dut.cmd('ip netns del ns2', fail=False)
        self.dut.cmd('echo 0 > /sys/bus/pci/devices/%s/sriov_numvfs' %
                     self.group.pci_dbdf)
        return super(FlowerActionIngressRateLimit, self).cleanup()
