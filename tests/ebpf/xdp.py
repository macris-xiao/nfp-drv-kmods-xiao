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
from ..drv_system import NfpNfdCtrl

###############################################################################
# Helpers
###############################################################################

def xdp_test_name_to_prog(test):
    # Skip the "tests.XXX.xdp_" in name
    last_dot = test.name.rfind('.')
    return test.name[last_dot + 5:] + '.o'

def xdp_skip_if_adj_head(test, prog_name):
    if test.group.xdp_mode() == "offload" and \
       prog_name.find("adjust") != -1:
        test.log("SKIP", "Skip because this test uses adjust_head")
        return NrtResult(name=test.name, testtype=test.__class__.__name__,
                         passed=None, comment="no adj head support")

###############################################################################
# Base classes
###############################################################################

class XDPTest(CommonTest):
    def cleanup(self):
        self.xdp_reset()

class XDPLoadTest(XDPTest):
    def execute(self):
        self.xdp_start(xdp_test_name_to_prog(self), mode=self.group.xdp_mode())

class XDPpassAllNoOffload(XDPTest):
    def execute(self):
        mode = self.group.xdp_mode()
        should_fail = mode == "offload"
        prog = xdp_test_name_to_prog(self)

        self.xdp_start(prog, mode=mode, should_fail=should_fail)
        return 0

class XDPadjBase(CommonPktCompareTest):
    def prepare(self):
        return xdp_skip_if_adj_head(self, self.get_prog_name())

    def install_filter(self):
        self.xdp_start(self.get_prog_name(), mode=self.group.xdp_mode())
        return 0

    def cleanup(self):
        self.xdp_reset()

class XDPtxBase(XDPadjBase):
    def prepare(self):
        return xdp_skip_if_adj_head(self, self.get_prog_name())

    def get_tcpdump_params(self):
        return (self.src, self.src_ifn[0], self.src)

class XDPpassBase(XDPadjBase):
    def get_tcpdump_params(self):
        return (self.dut, self.dut_ifn[0], self.src)

class XDPpassAll(XDPpassBase):
    def get_src_pkt(self):
        return self.std_pkt()

    def get_exp_pkt(self):
        return self.std_pkt()

    def get_prog_name(self):
        return xdp_test_name_to_prog(self)

# XXX: Note tunnel tests are hard-coding inner IPs.  This is slightly bad
#      but otherwise dealing with generating the XDP programs and correct
#      IP hdr checksum for Encap would be such a pain...
class XDPtunBase(XDPTest):
    def prepare(self):
        self.tun_name = 'ipip1'
        self.tun_ip_sub = self.group.tun_net

        return xdp_skip_if_adj_head(self, "adjust")

###############################################################################
# Simple tests
###############################################################################

class XDPStackLoadTest(XDPTest):
    def execute(self):
        mode = self.group.xdp_mode()
        stack_size = self.dut.nfd_reg_read_le32(self.dut_ifn[0],
                                                NfpNfdCtrl.BPF_STACK_SZ)
        stack_size &= 0xff
        stack_size *= 64

        fail = mode == "offload" and stack_size < 512
        self.log("Stack size",
                 "\tstack: %d\n\ttest needs: %d\n\tshould fail: %d\n" %
                 (stack_size, 512, fail))

        self.xdp_start(xdp_test_name_to_prog(self), mode=mode, should_fail=fail)

class XDPpass(XDPTest):
    def execute(self):
        self.xdp_start('pass.o', mode=self.group.xdp_mode())

        self.ping(0)
        self.tcpping(0)
        self.ping6(0)

class XDPdrop(XDPTest):
    def execute(self):
        self.ping(0)
        self.tcpping(0)
        self.ping6(0)

        self.xdp_start('drop.o', mode=self.group.xdp_mode())

        self.ping(0, should_fail=True)
        self.tcpping(0, should_fail=True)
        self.ping6(0, should_fail=True)

class XDPmultiPort(XDPTest):
    def execute(self):
        n_ports = len(self.dut_ifn)

        if n_ports < 2:
            raise NtiSkip("single port card")

        for p in range(0, n_ports):
            self.xdp_start('drop.o', port=p, mode=self.group.xdp_mode())

        for p in range(0, n_ports):
            self.xdp_start('pass.o', port=p, mode=self.group.xdp_mode())

            self.ping(port=p)
            self.tcpping(port=p)
            self.ping6(port=p)

            self.ping(port=int(not p), should_fail=True)
            self.tcpping(port=int(not p), should_fail=True)
            self.ping6(port=int(not p), should_fail=True)

            self.xdp_start('drop.o', port=p, mode=self.group.xdp_mode())

class XDPcmp(XDPTest):
    def execute(self):
        self.xdp_start('compares.o', mode=self.group.xdp_mode())

        self.ping(0)
        self.tcpping(0)
        self.ping6(0)

class XDPpassDPArd(XDPpassBase):
    def get_src_pkt(self):
        pkt = ''
        for b in self.group.hwaddr_x[0].split(':'):
            pkt += chr(int('0x' + b, 16))
        for b in self.group.hwaddr_a[0].split(':'):
            pkt += chr(int('0x' + b, 16))
        pkt += '\x12\x23\x00\x00'

        pkt += '\xaa' * 16
        pkt += '\x01\x02\x03\x04\x05\x06\x07\x08'
        pkt += '\xbb' * 32

        return pkt

    def get_exp_pkt(self):
        return self.get_src_pkt()

    def get_prog_name(self):
        return 'dpa_read.o'

class XDPpassDPAwr(XDPpassBase):
    def get_exp_pkt(self):
        pkt = self.get_src_pkt()
        implant = '\xee\xbb\xdd\xdd\xff\xff\xff\xff'
        pkt = pkt[:32] + implant + '\xbb' + implant + pkt[49:]
        return pkt

    def get_exp_pkt(self):
        return self.get_src_pkt()

    def get_prog_name(self):
        return 'dpa_write.o'

###############################################################################
# TX tests
###############################################################################

class XDPtx(XDPtxBase):
    def get_src_pkt(self):
        return self.std_pkt()

    def get_exp_pkt(self):
        pkt = ''
        for b in self.group.hwaddr_a[0].split(':'):
            pkt += chr(int('0x' + b, 16))
        for b in self.group.hwaddr_x[0].split(':'):
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
        return self.std_pkt(size=(self.group.mtu_x[0] + 14 - 256))

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

class XDPfailMaybeLong(XDPtxBase):
    def get_bar_rx_offset(self):
        return self.dut.nfd_reg_read_le32(self.dut_ifn[0], NfpNfdCtrl.RX_OFFSET)

    def execute(self):
        if self.get_bar_rx_offset() == 0:
            raise NtiSkip("This test doesn't work with dynamic headroom")
        XDPtxBase.execute(self)

    def get_src_pkt(self):
        return self.std_pkt()

    def get_exp_pkt(self):
        return None

    def get_prog_name(self):
        return 'adjust_head_mfail_long.o'

class XDPfailLong(XDPtxBase):
    def get_src_pkt(self):
        return self.std_pkt()

    def get_exp_pkt(self):
        return None

    def get_prog_name(self):
        return 'adjust_head_fail_long.o'

class XDPfailOversized(XDPtxBase):
    def get_src_pkt(self):
        return self.std_pkt(size=(self.group.mtu_x[0] + 14))

    def get_exp_pkt(self):
        return None

    def get_prog_name(self):
        return 'adjust_head_prep_256.o'

class XDPneg(XDPtxBase):
    def get_src_pkt(self):
        pkt = ''
        for b in self.group.hwaddr_x[0].split(':'):
            pkt += chr(int('0x' + b, 16))
        for b in self.group.hwaddr_a[0].split(':'):
            pkt += chr(int('0x' + b, 16))
        pkt += '\x12\x22'

        pkt += "".join([chr(i) for i in range(80)])

        return pkt

    def get_exp_pkt(self):
        pkt = self.get_src_pkt()
        pkt = pkt[6:12] + pkt[0:6] + '\x12\x22\xee\xdd' + '\xff' * 2 + \
              '\x00' * 4 + '\xf8\xf6\xf5\xf4\xf3\xf2\xf1\xf0' + pkt[30:]
        return pkt

    def get_prog_name(self):
        return 'neg.o'

class XDPjumpAtLast(XDPtx):
    def get_prog_name(self):
        return 'jump_at_last.o'

###############################################################################
# packet mod + PASS
###############################################################################

class XDPshifts(XDPpassBase):
    def get_src_pkt(self):
        return self.std_pkt()

    def get_exp_pkt(self):
        pkt = self.get_src_pkt()
        M = (1 << 64) - 1

        return pkt[0:16] + \
                 struct.pack('<Q', 0x1122334455667788 << 32 & M) + \
                 struct.pack('<Q', 0x1122334455667788 >> 32 & M) + \
                 struct.pack('<Q', 0x1122334455667788 >>  7 & M) + \
                 struct.pack('<Q', 0x1122334455667788 <<  7 & M) + \
                 struct.pack('<Q', 0x1122334455667788 << 45 & M) + \
               pkt[56:]

    def get_prog_name(self):
        return 'shifts.o'

class XDPswap(XDPpassBase):
    def get_src_pkt(self):
        std_mac_hdr = self.std_pkt()
        pkt = std_mac_hdr[0:14]

        pkt += "".join([chr(i) for i in range(80)])

        return pkt

    def get_exp_pkt(self):
        pkt = self.get_src_pkt()

        pkt = pkt[0:14] + \
              ''.join(reversed(pkt[14:16])) + \
              ''.join(reversed(pkt[16:20])) + \
              ''.join(reversed(pkt[20:28])) + \
              ''.join(reversed(pkt[28:30])) + '\x00' * 6 + \
              ''.join(reversed(pkt[36:40])) + '\x00' * 4 + \
              pkt[44:]

        return pkt

    def get_prog_name(self):
        return 'swap.o'

class XDPOPTmemcpy(XDPtxBase):
    def get_src_pkt(self):
        pkt = ''
        for b in self.group.hwaddr_x[0].split(':'):
            pkt += chr(int('0x' + b, 16))
        for b in self.group.hwaddr_a[0].split(':'):
            pkt += chr(int('0x' + b, 16))
        pkt += '\x12\x22'

        pkt += "".join([chr(i) for i in range(80)])

        return pkt

class XDPASMmemcpy1(XDPOPTmemcpy):
    def get_exp_pkt(self):
        pkt = self.get_src_pkt()
        pkt = pkt[6:12] + pkt[0:6] + '\x12\x34' + \
              pkt[84] + pkt[48:47+37] + pkt[51:]
        return pkt

    def get_prog_name(self):
        return 'opt_memcpy_1.o'

class XDPASMmemcpy2(XDPOPTmemcpy):
    def get_exp_pkt(self):
        pkt = self.get_src_pkt()
        pkt = pkt[6:12] + pkt[0:6] + '\x12\x34' + \
              pkt[14:39] + pkt[38:79] + pkt[80:94]
        return pkt

    def get_prog_name(self):
        return 'opt_memcpy_2.o'

class XDPASMmemcpy3(XDPOPTmemcpy):
    def get_exp_pkt(self):
        pkt = self.get_src_pkt()
        pkt = pkt[6:12] + pkt[0:6] + '\x12\x34' + \
              pkt[14:39] + pkt[72:80] + pkt[47:]
        return pkt

    def get_prog_name(self):
        return 'opt_memcpy_3.o'

class XDPASMmemcpy4(XDPOPTmemcpy):
    def get_exp_pkt(self):
        pkt = self.get_src_pkt()
        pkt = pkt[6:12] + pkt[0:6] + '\x12\x34' + \
              pkt[14:19] + pkt[37:37+16] + pkt[37+17] * 2 + pkt[37:]
        return pkt

    def get_prog_name(self):
        return 'opt_memcpy_4.o'

class XDPASMmemcpy5(XDPOPTmemcpy):
    def get_exp_pkt(self):
        pkt = self.get_src_pkt()
        pkt = pkt[6:12] + pkt[0:6] + '\x12\x34' + \
              pkt[14:16] + pkt[20:20+36] + pkt[20+44:20+48] * 3 + pkt[64:]
        return pkt

    def get_prog_name(self):
        return 'opt_memcpy_5.o'

class XDPASMmemcpy6(XDPOPTmemcpy):
    def get_exp_pkt(self):
        pkt = self.get_src_pkt()
        pkt = pkt[6:12] + pkt[0:6] + '\x12\x34' + \
              pkt[14:16] + pkt[24:24+24] + pkt[56:56+16] + pkt[56:]
        return pkt

    def get_prog_name(self):
        return 'opt_memcpy_6.o'

class XDPASMmemcpy7(XDPOPTmemcpy):
    def get_exp_pkt(self):
        pkt = self.get_src_pkt()
        pkt = pkt[6:12] + pkt[0:6] + '\x12\x34' + \
              pkt[14:16] + pkt[20:20+36]+ pkt[52:]
        return pkt

    def get_prog_name(self):
        return 'opt_memcpy_7.o'

class XDPASMmemcpy8(XDPOPTmemcpy):
    def get_exp_pkt(self):
        pkt = self.get_src_pkt()
        pkt = pkt[6:12] + pkt[0:6] + '\x12\x34' + \
              pkt[14:52] + pkt[64:68] * 3 + pkt[64:]
        return pkt

    def get_prog_name(self):
        return 'opt_memcpy_8.o'

class XDPASMmemcpy9(XDPOPTmemcpy):
    def get_exp_pkt(self):
        pkt = self.get_src_pkt()
        pkt = pkt[6:12] + pkt[0:6] + '\x12\x34' + \
              pkt[17:20] + pkt[17:65] + pkt[64:79] + pkt[80:]
        return pkt

    def get_prog_name(self):
        return 'opt_memcpy_9.o'

    def get_prog_src_file(self):
        return 'opt_memcpy_9.S'

class XDPCmembuiltins(XDPOPTmemcpy):
    def get_exp_pkt(self):
        pkt = self.get_src_pkt()
        pkt = pkt[6:12] + pkt[0:6] + '\x12\x34' + \
              pkt[22:30] + pkt[24:40] + pkt[38:40] + pkt[44:76] + pkt[72:]
        return pkt

    def get_prog_name(self):
        return 'opt_mem_builtins.o'

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
        return self.std_pkt(size=(self.group.mtu_x[0] + 14))

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
                     (self.tun_ip_sub, self.dut_ifn[0], self.group.hwaddr_a[0]))

        self.xdp_start('adjust_head_dec_ip.o', mode=self.group.xdp_mode())

        # Check normal communication
        self.ping(0)
        self.tcpping(0)
        self.ping6(0)

        cmd = 'ping %s1 -c5 -i0.05 -W2 -I %s' % (self.tun_ip_sub, self.tun_name)
        cmd += '; hping3 -c 5 %s1 -a %s2 -I %s' % \
               (self.tun_ip_sub, self.tun_ip_sub, self.tun_name)
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
        self.xdp_stop(mode=self.group.xdp_mode())
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
                     (self.tun_ip_sub, self.src_ifn[0], self.group.hwaddr_x[0]))

        self.xdp_start('adjust_head_prep_ip.o', mode=self.group.xdp_mode())

        cmd = 'ping %s1 -c5 -i0.05 -W2 -I %s' % \
              (self.tun_ip_sub, self.src_ifn[0])
        cmd += '; hping3 -c 5 %s1 -a %s2 -I %s' % \
               (self.tun_ip_sub, self.tun_ip_sub, self.tun_name)
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
        self.xdp_stop(mode=self.group.xdp_mode())
        self.src.cmd('ip addr del %s1/24 dev %s' %
                     (self.tun_ip_sub, self.src_ifn[0]), fail=False)
        self.src.cmd('ip neig del %s2 dev %s' %
                     (self.tun_ip_sub, self.src_ifn[0]), fail=False)

        self.dut.cmd('ip link del dev %s' % (self.tun_name), fail=False)
