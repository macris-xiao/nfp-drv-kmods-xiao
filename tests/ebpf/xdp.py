#
# Copyright (C) 2017,  Netronome Systems, Inc.  All rights reserved.
#
"""
XDP tests.
"""

import os
import netro.testinfra
from netro.testinfra.test import *
from netro.tests.tcpdump import TCPDump
from scapy.all import TCP, UDP, IP, Ether, rdpcap, wrpcap, IPv6, ICMP, Raw
from ..common_test import *
from ..drv_grp import NFPKmodGrp

###############################################################################
# Base classes
###############################################################################

class XDPTest(CommonTest):
    def xdp_start(self, prog):
        return self.dut.cmd('ip -force link set dev %s xdp obj %s sec ".text"' %
                            (self.dut_ifn[0],
                             os.path.join(self.dut.xdp_samples_dir, prog)))

    def xdp_stop(self):
        return self.dut.cmd('ip -force link set dev %s xdp off' %
                            (self.dut_ifn[0]))

    def tcpdump_cmd(self, capture_system, ifname, cmd_system, cmd):
        pcap_res = os.path.join(self.group.tmpdir, 'pcap_res')

        # Start TCPdump
        dump = os.path.join(capture_system.tmpdir, 'dump')
        stderr = os.path.join(capture_system.tmpdir, 'tcpdump_err.txt')
        filter_expr = '"not arp and' \
                      ' not ip6 and' \
                      ' not ether host 01:80:c2:00:00:0e"'
        self.tcpdump = TCPDump(capture_system, ifname, dump, resolve=False,
                               direction='in', stderrfn=stderr,
                               filter_expr=filter_expr)

        self.tcpdump.start()

        # Run command
        cmd_system.cmd(cmd)

        self.tcpdump.stop()

        # Dump the packets to logs for debug
        capture_system.cmd('tcpdump -r ' + dump)

        # Check the result
        capture_system.cp_from(dump, pcap_res)

        return rdpcap(pcap_res)

    def cleanup(self):
        self.xdp_stop()

class XDPadjBase(XDPTest):
    def get_src_pkt(self):
        pass

    def get_exp_pkt(self):
        pass

    def get_prog_name(self):
        pass

    def get_tcpdump_params(self):
        pass

    def execute(self):
        # Prepare packet
        pkt = self.get_src_pkt()

        pcap_local = os.path.join(self.group.tmpdir, 'pcap')
        pcap_src = os.path.join(self.src.tmpdir, 'pcap')

        wrpcap(pcap_local, Ether(pkt))
        self.src.mv_to(pcap_local, pcap_src)

        # Make sure there is connectivity
        self.ping(0)
        # Install XDP prog
        self.xdp_start(self.get_prog_name())

        cmd = "tcpreplay --intf1=%s --pps=100 --loop=100 -K %s " % \
              (self.src_ifn[0], pcap_src)

        tp = self.get_tcpdump_params()
        result_pkts = self.tcpdump_cmd(tp[0], tp[1], tp[2], cmd)

        # Compute expected packet
        exp_pkt = self.get_exp_pkt()

        exp_num = 100
        if exp_pkt is None:
            exp_num = 0

        if len(result_pkts) != exp_num:
            raise NtiError('Captured %d packets, expected %d' %
                           (len(result_pkts), exp_num))

        for p in result_pkts:
            if str(p) != exp_pkt:
                self.log('Bad packet', str(p) + "\n\n" + exp_pkt)
                raise NtiError("Packet doesn't match")

    def std_pkt(self, size=96):
        pkt = ''
        for b in self.group.hwaddr_x.split(':'):
            pkt += chr(int('0x' + b, 16))
        for b in self.group.hwaddr_a.split(':'):
            pkt += chr(int('0x' + b, 16))
        pkt += '\x12\x22'

        pkt += '\xaa'
        pkt += '\xf1' * (size - 16)
        pkt += '\x55'

        return pkt

class XDPtxBase(XDPadjBase):
    def get_tcpdump_params(self):
        return (self.src, self.src_ifn[0], self.src)

class XDPpassBase(XDPadjBase):
    def get_tcpdump_params(self):
        return (self.dut, self.dut_ifn[0], self.src)

# XXX: Note tunnel tests are hard-coding inner IPs.  This is slightly bad
#      but otherwise dealing with generating the XDP programs and correct
#      IP hdr checksum for Encap would be such a pain...
class XDPtunBase(XDPTest):
    def prepare(self):
        self.tun_name = 'ipip1'
        self.tun_ip_sub = '10.9.1.'

###############################################################################
# Simple tests
###############################################################################

class XDPpass(XDPTest):
    def execute(self):
        self.xdp_start('pass.o')

        self.ping(0)
        self.tcpping(0)
        self.ping6(0)

class XDPdrop(XDPTest):
    def execute(self):
        self.ping(0)
        self.tcpping(0)
        self.ping6(0)

        self.xdp_start('drop.o')

        self.ping(0, fail=False)
        self.tcpping(0, fail=False)
        self.ping6(0, fail=False)

###############################################################################
# TX tests
###############################################################################

class XDPtx(XDPtxBase):
    def get_src_pkt(self):
        return self.std_pkt()

    def get_exp_pkt(self):
        pkt = ''
        for b in self.group.hwaddr_a.split(':'):
            pkt += chr(int('0x' + b, 16))
        for b in self.group.hwaddr_x.split(':'):
            pkt += chr(int('0x' + b, 16))
        pkt += '\x12\x34'

        pkt += '\xaa'
        pkt += '\xf1' * 80
        pkt += '\x55'

        return pkt

    def get_prog_name(self):
        return 'tx.o'

class XDPtrunc2B(XDPtxBase):
    def get_src_pkt(self):
        return self.std_pkt()

    def get_exp_pkt(self):
        pkt = self.get_src_pkt()
        pkt = pkt[6:12] + pkt[0:6] + '\x12\x34' + pkt[16:]

        return pkt

    def get_prog_name(self):
        return 'adjust_head_trunc.o'

class XDPtruncTo14B(XDPtxBase):
    def get_src_pkt(self):
        return self.std_pkt()

    def get_exp_pkt(self):
        pkt = self.get_src_pkt()
        pkt = pkt[6:12] + pkt[0:6] + '\x12\x34' + '\x00' * 46

        return pkt

    def get_prog_name(self):
        return 'adjust_head_trunc_to_14.o'

class XDPprepMAC(XDPtxBase):
    def get_src_pkt(self):
        return self.std_pkt()

    def get_exp_pkt(self):
        pkt = self.get_src_pkt()
        pkt = pkt[6:12] + pkt[0:6] + '\x12\x34' + pkt

        return pkt

    def get_prog_name(self):
        return 'adjust_head_prep_mac.o'

class XDPprep256B(XDPtxBase):
    def get_src_pkt(self):
        return self.std_pkt()

    def get_exp_pkt(self):
        pkt = self.get_src_pkt()
        pkt = pkt[6:12] + pkt[0:6] + '\x12\x34' + '\x00' * 242 + pkt

        return pkt

    def get_prog_name(self):
        return 'adjust_head_prep_256.o'

class XDPprep256Bmtu(XDPtxBase):
    def get_src_pkt(self):
        return self.std_pkt(size=(self.group.mtu_x + 14 - 256))

    def get_exp_pkt(self):
        pkt = self.get_src_pkt()
        pkt = pkt[6:12] + pkt[0:6] + '\x12\x34' + '\x00' * 242 + pkt

        return pkt

    def get_prog_name(self):
        return 'adjust_head_prep_256.o'

class XDPfailShort(XDPtxBase):
    def get_src_pkt(self):
        return self.std_pkt()

    def get_exp_pkt(self):
        return None

    def get_prog_name(self):
        return 'adjust_head_fail_short.o'

class XDPfailLong(XDPtxBase):
    def get_src_pkt(self):
        return self.std_pkt()

    def get_exp_pkt(self):
        return None

    def get_prog_name(self):
        return 'adjust_head_fail_long.o'

class XDPfailOversized(XDPtxBase):
    def get_src_pkt(self):
        return self.std_pkt(size=(self.group.mtu_x + 14))

    def get_exp_pkt(self):
        return None

    def get_prog_name(self):
        return 'adjust_head_prep_256.o'

###############################################################################
# xdp_adjust_head() + PASS
###############################################################################

class XDPpassAdjZero(XDPpassBase):
    def get_src_pkt(self):
        return self.std_pkt()

    def get_exp_pkt(self):
        return self.get_src_pkt()

    def get_prog_name(self):
        return 'adjust_head_0.o'

class XDPpassAdjTwice(XDPpassBase):
    def get_src_pkt(self):
        return self.std_pkt()

    def get_exp_pkt(self):
        return self.get_src_pkt()

    def get_prog_name(self):
        return 'adjust_head_twice.o'

class XDPpassAdjUndersized(XDPpassBase):
    def get_src_pkt(self):
        return self.std_pkt(size=(64 + 14))

    def get_exp_pkt(self):
        pkt = self.get_src_pkt()
        return pkt[:12] + '\x12\x34'

    def get_prog_name(self):
        return 'adjust_head_trunc_pass.o'

class XDPpassOversized(XDPpassBase):
    def get_src_pkt(self):
        return self.std_pkt(size=(self.group.mtu_x + 14))

    def get_exp_pkt(self):
        pkt = self.get_src_pkt()
        return pkt[:12] + '\x12\x34' + '\x00' * 242 + pkt

    def get_prog_name(self):
        return 'adjust_head_prep_256_pass.o'

class XDPadjHeadDecIpIp(XDPtunBase):
    def execute(self):
        self.src.cmd('ip link replace %s type ipip local %s remote %s dev %s' %
                     (self.tun_name, self.src_addr[0][:-3],
                      self.dut_addr[0][:-3], self.src_ifn[0]))
        self.src.cmd('ifconfig %s %s2/24 up' %
                     (self.tun_name, self.tun_ip_sub))

        self.dut.cmd('ip link del dev %s' % (self.tun_name), fail=False)
        self.dut.cmd('ip addr replace %s1/24 dev %s' %
                     (self.tun_ip_sub, self.dut_ifn[0]))
        self.dut.cmd('ip neig replace %s2 dev %s lladdr %s' %
                     (self.tun_ip_sub, self.dut_ifn[0], self.group.hwaddr_a))

        self.xdp_start('adjust_head_dec_ip.o')

        # Check normal communication
        self.ping(0)
        self.tcpping(0)
        self.ping6(0)

        cmd = 'ping %s1 -c5 -i0.05 -W2 -I %s' % (self.tun_ip_sub, self.tun_name)
        cmd += '; hping3 -c 5 %s1 -a 10.9.1.2 -I %s' % \
               (self.tun_ip_sub, self.tun_name)
        cmd += ' || true'
        result_pkts = self.tcpdump_cmd(self.src, self.src_ifn[0], self.src, cmd)

        cnt_icmp = 0
        cnt_tcp = 0
        for p in result_pkts:
            if p.haslayer(ICMP):
                if p[ICMP].type == 0:
                    cnt_icmp += 1
            if p.haslayer(TCP):
                cnt_tcp += 1

        if cnt_icmp != 5:
            raise NtiError('Got ICMP responses: %d, expected 5' % (cnt_icmp))
        if cnt_tcp != 5:
            raise NtiError('Got TCP responses: %d, expected 5' % (cnt_tcp))

    def cleanup(self):
        self.xdp_stop()
        self.dut.cmd('ip addr del %s1/24 dev %s' %
                     (self.tun_ip_sub, self.dut_ifn[0]), fail=False)
        self.dut.cmd('ip neig del %s2 dev %s' %
                     (self.tun_ip_sub, self.dut_ifn[0]), fail=False)

        self.src.cmd('ip link del dev %s' % (self.tun_name), fail=False)

class XDPadjHeadEncIpIp(XDPtunBase):
    def execute(self):
        self.dut.cmd('ip link replace %s type ipip local %s remote %s dev %s' %
                     (self.tun_name, self.dut_addr[0][:-3],
                      self.src_addr[0][:-3], self.dut_ifn[0]))
        self.dut.cmd('ifconfig %s %s1/24 up' %
                     (self.tun_name, self.tun_ip_sub))

        self.src.cmd('ip link del dev %s' % (self.tun_name), fail=False)
        self.src.cmd('ip addr replace %s2/24 dev %s' %
                     (self.tun_ip_sub, self.src_ifn[0]))
        self.src.cmd('ip neig replace %s1 dev %s lladdr %s' %
                     (self.tun_ip_sub, self.src_ifn[0], self.group.hwaddr_x))

        self.xdp_start('adjust_head_prep_ip.o')

        cmd = 'ping %s1 -c5 -i0.05 -W2 -I %s' % \
              (self.tun_ip_sub, self.src_ifn[0])
        cmd += '; hping3 -c 5 %s1 -a 10.9.1.2 -I %s' % \
               (self.tun_ip_sub, self.tun_name)
        cmd += ' || true'
        result_pkts = self.tcpdump_cmd(self.src, self.src_ifn[0], self.src, cmd)

        cnt_icmp = 0
        cnt_tcp = 0
        for p in result_pkts:
            if p.haslayer(ICMP):
                if p[ICMP].type == 0:
                    cnt_icmp += 1
            if p.haslayer(TCP):
                cnt_tcp += 1

        if cnt_icmp != 5:
            raise NtiError('Got ICMP responses: %d, expected 5' % (cnt_icmp))
        if cnt_tcp != 5:
            raise NtiError('Got TCP responses: %d, expected 5' % (cnt_tcp))

    def cleanup(self):
        self.xdp_stop()
        self.src.cmd('ip addr del %s1/24 dev %s' %
                     (self.tun_ip_sub, self.src_ifn[0]), fail=False)
        self.src.cmd('ip neig del %s2 dev %s' %
                     (self.tun_ip_sub, self.src_ifn[0]), fail=False)

        self.dut.cmd('ip link del dev %s' % (self.tun_name), fail=False)
