#
# Copyright (C) 2017,  Netronome Systems, Inc.  All rights reserved.
#
"""
BPF test group for the NFP Linux drivers.
"""

import os
import time
import netro.testinfra
from netro.testinfra.nti_exceptions import NtiGeneralError
from netro.testinfra.system import _parse_ifconfig
from netro.testinfra.test import *
from ..common_test import *
from ..drv_grp import NFPKmodGrp
from ..ebpf_test import *
from xdp import *

###########################################################################
# Group
###########################################################################

class NFPKmodBPF(NFPKmodGrp):
    """BPF tests for the NFP Linux drivers"""

    summary = "BPF tests used for NFP Linux driver."

    def __init__(self, name, cfg=None, quick=False, dut_object=None,
                 dut=None, nfp=None, nfpkmods=None, mefw=None):

        NFPKmodGrp.__init__(self, name=name, cfg=cfg, quick=quick,
                            dut_object=dut_object)

    def xdp_mode(self):
        return "offload"

    def tc_mode(self):
        return "skip_sw"

    def populate_tests(self):
        dut = (self.dut, self.addr_x, self.eth_x, self.addr_v6_x)
        src = (self.host_a, self.addr_a, self.eth_a, self.addr_v6_a)

        XDP = (('xdp_pass', XDPpass, 'XDP pass test'),
               ('xdp_drop', XDPdrop, 'XDP drop test'),
               ('xdp_multi_port', XDPmultiPort, 'XDP on multi port cards'),
               ('xdp_pass_adj_head', XDPpassAdjZero,
                'XDP adjust head by zero pass test'),
               ('xdp_pass_adj_head_twice', XDPpassAdjTwice,
                'XDP adjust head to initial position pass test'),
               ('xdp_pass_adj_head_undersize', XDPpassAdjUndersized,
                'XDP adjust head to leave 14B test'),
               ('xdp_pass_adj_head_oversize', XDPpassOversized,
                'XDP pass oversized packet test'),
               ('xdp_pass_ipip_dec', XDPadjHeadDecIpIp,
                'Decapsulate IPIP with XDP'),
               ('xdp_pass_ipip_enc', XDPadjHeadEncIpIp,
                'Encapsulate IPIP with XDP'),
               ('xdp_tx', XDPtx, 'XDP tx test'),
               ('xdp_tx_adj_head_trunc', XDPtrunc2B,
                'XDP adjust head trunc 2B test'),
               ('xdp_tx_adj_head_trunc_to_hdr', XDPtruncTo14B,
                'XDP adjust head trunc to MAC header test'),
               ('xdp_tx_adj_head_prep', XDPprepMAC,
                'XDP adjust head prep MAC header test'),
               ('xdp_tx_adj_head_prep_max', XDPprep256B,
                'XDP adjust head prep 256B header test'),
               ('xdp_tx_adj_head_prep_short', XDPfailShort,
                'XDP adjust head prep fail test (short)'),
               ('xdp_tx_adj_head_prep_long', XDPfailMaybeLong,
                'XDP adjust head prep fail test (long)'),
               ('xdp_tx_adj_head_prep_very_long', XDPfailLong,
                'XDP adjust head prep fail test (very long)'),
               ('xdp_tx_adj_head_prep_max_mtu', XDPprep256Bmtu,
                'XDP adjust head prep 256B to make an MTU-sized packet test'),
               ('xdp_tx_adj_head_prep_max_oversize', XDPfailOversized,
                'XDP adjust head prep 256B on MTU-sized packet test'),
               ('xdp_shifts', XDPshifts, 'XDP test of shift operations'),
               ('xdp_cmp', XDPcmp, "Test compare instructions"),
               ('xdp_swap', XDPswap, 'Perform byte swaps'),
               ('xdp_dpa_rd', XDPpassDPArd, 'XDP direct packet access test'),
               ('xdp_dpa_wr', XDPpassDPAwr,
                'XDP direct packet access write test'),
               ('xdp_stack_huge', XDPStackLoadTest,
                'test we refuse to offload huge stackes (512B)'),
               ('xdp_stack_wr64', XDPLoadTest, 'write 64 bytes to the stack'),
               ('xdp_stack_wr128', XDPLoadTest, 'write 128 bytes to the stack'),
               ('xdp_stack_aligned', XDPpassAll,
                'aligned accesses to the stack'),
               ('xdp_stack_aligned_split', XDPpassAll,
                'make sure stack accesses are note aliased'),

               ('xdp_stack_read_unaligned_low8', XDPpassAll,
                'test unaligned 8B reads of the first 32B of the stack'),
               ('xdp_stack_read_unaligned_low4', XDPpassAll,
                'test unaligned 4B reads of the first 32B of the stack'),
               ('xdp_stack_read_unaligned_low2', XDPpassAll,
                'test unaligned 2B reads of the first 32B of the stack'),
               ('xdp_stack_read_unaligned_low1', XDPpassAll,
                'test unaligned 1B reads of the first 32B of the stack'),
               ('xdp_stack_read_unaligned_mid8', XDPpassAll,
                'test unaligned 8B reads of the 32B - 64B region of the stack'),
               ('xdp_stack_read_unaligned_mid4', XDPpassAll,
                'test unaligned 4B reads of the 32B - 64B region of the stack'),
               ('xdp_stack_read_unaligned_mid2', XDPpassAll,
                'test unaligned 2B reads of the 32B - 64B region of the stack'),
               ('xdp_stack_read_unaligned_mid1', XDPpassAll,
                'test unaligned 1B reads of the 32B - 64B region of the stack'),
               ('xdp_stack_read_unaligned_hig8', XDPpassAll,
                'test unaligned 8B reads of the stack region above 64B'),
               ('xdp_stack_read_unaligned_hig4', XDPpassAll,
                'test unaligned 4B reads of the stack region above 64B'),
               ('xdp_stack_read_unaligned_hig2', XDPpassAll,
                'test unaligned 2B reads of the stack region above 64B'),
               ('xdp_stack_read_unaligned_hig1', XDPpassAll,
                'test unaligned 1B reads of the stack region above 64B'),
               ('xdp_stack_read_unaligned_hig8_cross32', XDPpassAll,
                'test unaligned 8B reads of the stack region above 64B and crossing 32B boundary'),
               ('xdp_stack_read_unknown', XDPpassAll,
                'test reads via modified (non-constant) reg'),
               ('xdp_stack_read_unknown_bad_align', XDPpassAllNoOffload,
                'test reads via modified (non-constant) reg'),

               ('xdp_stack_write_unaligned_low8', XDPpassAll,
                'test unaligned 8B write of the first 32B of the stack'),
               ('xdp_stack_write_unaligned_low4', XDPpassAll,
                'test unaligned 4B write of the first 32B of the stack'),
               ('xdp_stack_write_unaligned_low2', XDPpassAll,
                'test unaligned 2B write of the first 32B of the stack'),
               ('xdp_stack_write_unaligned_low1', XDPpassAll,
                'test unaligned 1B write of the first 32B of the stack'),
               ('xdp_stack_write_unaligned_mid8', XDPpassAll,
                'test unaligned 8B write in the 32-64B range of the stack'),
               ('xdp_stack_write_unaligned_mid4', XDPpassAll,
                'test unaligned 4B write in the 32-64B range of the stack'),
               ('xdp_stack_write_unaligned_mid2', XDPpassAll,
                'test unaligned 2B write in the 32-64B range of the stack'),
               ('xdp_stack_write_unaligned_mid1', XDPpassAll,
                'test unaligned 1B write in the 32-64B range of the stack'),
               ('xdp_stack_write_unaligned_hig8', XDPpassAll,
                'test unaligned 8B write past the first 64B of the stack'),
               ('xdp_stack_write_unaligned_hig4', XDPpassAll,
                'test unaligned 4B write past the first 64B of the stack'),
               ('xdp_stack_write_unaligned_hig2', XDPpassAll,
                'test unaligned 2B write past the first 64B of the stack'),
               ('xdp_stack_write_unaligned_hig1', XDPpassAll,
                'test unaligned 1B write past the first 64B of the stack'),

               ('xdp_stack_write_unaligned_hig8_cross32', XDPpassAll,
                'test unaligned 8B write of the stack region above 64B and crossing 32B boundary'),
               ('xdp_stack_write_unknown', XDPpassAll,
                'test writes via modified (non-constant) reg'),
               ('xdp_stack_write_unknown_bad_align', XDPpassAllNoOffload,
                'test writes via modified (non-constant) reg'),

               ('xdp_mov64', XDPpassAll,
                'test optimization of repetitive mov64'),
               ('xdp_neg', XDPneg, 'BPF_NEG (ALU and ALU64)'),
               ('xdp_jump_at_last', XDPjumpAtLast, 'The last instruction is jump'),
               ('xdp_tx_memcpy_1', XDPASMmemcpy1,
                'Opt memory copy (len > 32 && len <= 40 && !4 aligned)'),
               ('xdp_tx_memcpy_2', XDPASMmemcpy2,
                'Opt memory copy (len > 40 && !4 aligned)'),
               ('xdp_tx_memcpy_3', XDPASMmemcpy3,
                'Opt memory copy (len < 8)'),
               ('xdp_tx_memcpy_4', XDPASMmemcpy4,
                'Opt memory copy (len <= 32 && !4 aligned)'),
        )

        for t in XDP:
            self._tests[t[0]] = t[1](src, dut, group=self, name=t[0],
                                     summary=t[2])

        TCs = (
            ('tc_dpa_rd', eBPFdpaRD, "DPA read with TC"),
        )

        for t in TCs:
            self._tests[t[0]] = t[1](src, dut, group=self, name=t[0],
                                     summary=t[2])

        if self.xdp_mode() == "drv":
            return

        T = (('bpf_capa', eBPFcapa, "eBPF capability test"),
             ('bpf_refcnt', eBPFrefcnt, "eBPF refcount test"),
             ('bpf_mtu_check', eBPFmtu, 'Check high MTU fails'),
             ('tc_pass', eBPFpass, "eBPF pass all filter"),
             ('tc_drop', eBPFdrop, "eBPF drop all filter"),
             ('tc_len', eBPFskbLen, "eBPF skb->len test"),
             ('tc_tcp58', eBPFtcp58, "eBPF filter on TCP port 58"),
             ('tc_gen_flags', eBPFflags, 'iproute/cls_bpf flag reporting'),
             ('tc_offload_disabled', eBPFtc_off,
              'Check if loading fails if ethtool disabled TC offloads'),
             ('tc_two_prog', eBPFtwo_prog, 'Check 2 progs fail'),
             ('bpf_ld_mask_combine', eBPFld_mask_combine,
              'eBPF ld/mask insn pair combination'),
             ('bpf_ld_shift_combine', eBPFld_shift_combine,
              'eBPF ld/shift insn pair combination'),
        )

        for t in T:
            self._tests[t[0]] = t[1](src, dut, group=self, name=t[0],
                                     summary=t[2])

        self._tests['bpf_fallback'] = \
            eBPFtest(src, dut, obj_name='store.o', mode="",
                     group=self, name='bpf_fallback',
                     summary='Check SW fallback')

        # Direct action tests
        DA = (('tc_da_DROP', 'da_2_drop.o', 1),
              ('tc_da_STOL', 'da_4_nuke.o', None),
              ('tc_da_QUE', 'da_5_nuke.o', None),
              ('tc_da_UNSP', 'da_-1_unspec.o', 0),
              ('tc_da_unkn', 'da_8_unspec.o', 0),
              ('tc_da_n_unkn', 'da_n_unspec.o', 0),
              ('tc_da_abort', 'da_abort.o', 0),
        )

        for t in DA:
            self._tests[t[0]] = eBPFda(src, dut, t[1], stat=t[2], group=self,
                                       name=t[0],
                                       summary='Direct act test with %s' % \
                                       (t[1]))

        TF = (('tc_da_and_act', 'da_2_drop.o', 'da', 'action drop'),
              ('tc_legacy_act', 'da_2_drop.o', '', 'action drop'),
        )

        for t in TF:
            self._tests[t[0]] = eBPFtest(src, dut, obj_name=t[1], tc_flags=t[2],
                                         act=t[3], should_fail=True,
                                         group=self, name=t[0],
                                         summary='Fail with %s %s' % \
                                         (t[1], t[2]))

        DAF = (('tc_da_OK', 'da_0_pass.o'),
               ('tc_da_RECL', 'da_1_pass.o'),
               ('tc_da_PIPE', 'da_3_unspec.o'),
               ('tc_da_REP', 'da_6_unspec.o'),
               ('tc_da_REDIR', 'da_7_redir.o'),
               ('tc_store', 'store.o'),
               ('tc_maps', 'maps.o'),
               ('tc_mark', 'mark.o'),
               ('tc_bad_ptr', 'validate_ptr_type.o'),
        )

        for t in DAF:
            self._tests[t[0]] = \
                eBPFtest(src, dut, t[1], should_fail=True, group=self,
                         name=t[0],
                         summary='Direct action %s fail test' % (t[0]))

    def _init(self):
        NFPKmodGrp._init(self)

        M = self.dut

        M.drv_load_netdev_conserving(fwname=None, nth=False)

        # Disable DAD
        cmd = ''
        for ifc in self.eth_x:
            cmd += 'sysctl -w net.ipv6.conf.%s.accept_dad=0;' % (ifc)
            cmd += 'sysctl -w net.ipv6.conf.%s.dad_transmits=0;' % (ifc)
        M.cmd(cmd)

        # Init DUT
        for p in range(0, len(self.eth_x)):
            M.cmd('ethtool -G %s rx 512 tx 512' % (self.eth_x[p]))
            M.cmd('ifconfig %s %s promisc up' % (self.eth_x[p], self.addr_x[p]))
            M.cmd('ip addr add %s dev %s' % (self.addr_v6_x[p], self.eth_x[p]))

        # Make sure NTI knows the NFP interface exists
        M.refresh()

        # stash hwaddrs for traffic generation
        self.hwaddr_x = []
        self.mtu_x = []
        self.promisc_x = []
        self.hwaddr_a = []
        self.mtu_a = []
        self.promisc_a = []
        for p in range(0, len(self.eth_x)):
            _, out = self.dut.cmd("ifconfig %s" % self.eth_x[p])
            ifcfg = _parse_ifconfig(out)
            self.hwaddr_x.append(ifcfg["hwaddr"])
            self.mtu_x.append(ifcfg["mtu"])
            self.promisc_x.append(out.find("PROMISC") != -1)

            _, out = self.host_a.cmd("ifconfig %s" % self.eth_a[p])
            ifcfg = _parse_ifconfig(out)
            self.hwaddr_a.append(ifcfg["hwaddr"])
            self.mtu_a.append(ifcfg["mtu"])
            self.promisc_a.append(out.find("PROMISC") != -1)

            # add static arp entries to speed up drop tests
            self.host_a.cmd('ip neigh add %s lladdr %s dev %s' %
                            (self.addr_x[p][:-3], self.hwaddr_x[p],
                             self.eth_a[p]), fail=False)
            self.host_a.cmd('ip neigh add %s lladdr %s dev %s' %
                            (self.addr_v6_x[p][:-3], self.hwaddr_x[p],
                             self.eth_a[p]), fail=False)

            # Make sure MTUs match just in case
            if self.mtu_a[p] != self.mtu_x[p]:
                raise NtiError("Device MTUs don't match %s vs %s" %
                               (self.mtu_a[p], self.mtu_x[p]))

        M.copy_bpf_samples()

        for i in range(0, len(self.eth_x)):
            self.dut.link_wait(self.eth_x[i])
        return

    def _fini(self):
        self.dut.cmd('rm -rf /lib/firmware/netronome')
        self.dut.reset_mods()

        NFPKmodGrp._fini(self)
        return

class NFPKmodXDPdrv(NFPKmodBPF):
    def xdp_mode(self):
        return "drv"

    def tc_mode(self):
        return "skip_hw"

###########################################################################
# Tests
###########################################################################

class eBPFcapa(CommonTest):
    def execute(self):
        """
        Check eBPF offload capability
        """
        passed = True
        comment = ''

        _, out = self.src.cmd('dmesg | tail -50 | grep "nfp.*BPF"',
                              fail=False)
        if not out:
            return NrtResult(name=self.name, testtype=self.__class__.__name__,
                             passed=False, comment="No BPF capa in dmesg")

        _, out = self.src.cmd('ethtool -k %s | grep "hw-tc-offload: [a-z]*$"' %
                              (self.src_ifn), fail=False)
        if not out:
            return NrtResult(name=self.name, testtype=self.__class__.__name__,
                             passed=False,
                             comment="ethtool does not report TC offload")

        return NrtResult(name=self.name, testtype=self.__class__.__name__,
                         passed=passed, comment=comment)

class eBPFrefcnt(eBPFtest):
    def __init__(self, src, dut, group=None, name="", summary=None):
        eBPFtest.__init__(self, src, dut,
                          group=group, name=name, summary=summary)

        # NTI list tests
        if self.dut is None:
            return

        if self.has_bpf_objects():
            raise NtiError('eBPF objects exist before test start')

    def has_bpf_objects(self):
        _, maps = self.dut.cmd('bpftool map | wc -l')
        _, progs = self.dut.cmd('bpftool progs | wc -l')

        return maps.strip() != '0' or progs.strip() != '0'

    def check_xdp(self, obj, mode):
        self.xdp_start(obj, mode=mode)
        self.xdp_stop(mode=mode)
        if self.has_bpf_objects():
            raise NtiError('eBPF objects after XDP%s with %s' % (mode, obj))

    def test_xdp(self):
        self.check_xdp("pass.o", mode="drv")
        self.check_xdp("map_ro_hash.o", mode="drv")

        self.check_xdp("pass.o", mode="offload")
        # TODO: add when map offload lands
        #self.check_xdp("map_ro_hash.o", mode="offload")

    def execute(self):
        # The TC offload will be loaded by the eBPFtest base class
        eBPFtest.cleanup(self)
        if self.has_bpf_objects():
            raise NtiError('eBPF objects after TC offload')

        self.test_xdp()

        # Check two ports at the same time
        if len(self.dut_ifn) < 2:
            return

        self.xdp_start("pass.o", port=1, mode="drv")
        self.test_xdp()
        self.xdp_stop(port=1, mode="drv")

        # Check with offload on one port
        self.xdp_start("pass.o", port=1, mode="offload")
        self.test_xdp()
        self.xdp_stop(port=1, mode="offload")

    def cleanup(self):
        self.xdp_reset()

class eBPFpass(eBPFtest):
    def __init__(self, src, dut, group=None, name="", summary=None):
        eBPFtest.__init__(self, src, dut,
                          group=group, name=name, summary=summary)

    def execute(self):
        self.ping(port=0)
        self.ping6(port=0)
        self.tcpping(port=0)

        counts = (30, 300, 3200, 10000)
        self.validate_cntrs(rx_t=counts, pass_all=True)

class eBPFdrop(eBPFtest):
    def __init__(self, src, dut, group=None, name="", summary=None):
        eBPFtest.__init__(self, src, dut, obj_name="drop.o",
                          group=group, name=name, summary=summary)

    def execute(self):
        self.ping(port=0, should_fail=True)
        self.ping6(port=0, should_fail=True)
        self.tcpping(port=0, should_fail=True)

        counts = (30, 300, 3200, 10000)
        self.validate_cntrs(rx_t=counts, app1_all=True)

class eBPFskbLen(eBPFtest):
    def __init__(self, src, dut, group=None, name="", summary=None):
        eBPFtest.__init__(self, src, dut, obj_name="len.o",
                          group=group, name=name, summary=summary)

    def execute(self):
        self.ping(port=0)
        self.ping6(port=0)
        self.tcpping(port=0)

        counts = (30, 300, 3200, 10000)
        self.validate_cntrs(rx_t=counts, pass_all=True)

        self.ping(port=0, size=1193, should_fail=True)
        self.ping(port=0, size=1200, should_fail=True)

        counts = (20, 300, 24850, 50000)
        self.validate_cntrs(rx_t=counts, exact_filter=True)

class eBPFtcp58(eBPFtest):
    def __init__(self, src, dut, group=None, name="", summary=None):
        eBPFtest.__init__(self, src, dut, obj_name="tcp58.o",
                          group=group, name=name, summary=summary)

    def execute(self):
        self.ping(port=0)
        self.ping6(port=0)
        self.tcpping(port=0, sport=58, dport=100)

        counts = (30, 300, 3200, 10000)
        self.validate_cntrs(rx_t=counts, pass_all=True)

        self.tcpping(port=0, sport=100, dport=58, should_fail=True)

        counts = (10, 16, 1080, 1800)
        self.validate_cntrs(rx_t=counts, exact_filter=True)

class eBPFda(eBPFtest):
    def __init__(self, src, dut, obj_name, stat,
                 group=None, name="", summary=None):
        eBPFtest.__init__(self, src, dut, obj_name=obj_name,
                          group=group, name=name, summary=summary)
        self.stat = stat

    def execute(self):
        do_fail = self.stat == None or self.stat == 1

        self.ping(port=0, should_fail=do_fail)
        self.ping6(port=0, should_fail=do_fail)
        self.tcpping(port=0, should_fail=do_fail)

        counts = (30, 300, 3200, 10000)
        self.validate_cntrs(rx_t=counts, pass_all=self.stat == 0,
                            app1_all=self.stat == 1, app2_all=self.stat == 2,
                            app3_all=self.stat == 3)

class eBPFflags(eBPFtest):
    def __init__(self, src, dut, group=None, name="", summary=None):
        eBPFtest.__init__(self, src, dut, mode="",
                          group=group, name=name, summary=summary)

    def execute(self):
        # The default one in this class should have no skip flags
        _, out = self.dut.cmd('tc filter show dev %s ingress' %
                              (self.dut_ifn[0]))
        if out.find('skip_') != -1:
            raise NtiGeneralError("skip_* flag set when it shouldn't be")

        # Check out skip_sw and skip_hw
        for opts in (("skip_sw", 0),
                     ("skip_hw", None)):
            self.dut.cmd('tc filter del dev %s ingress protocol all pref 49152 bpf' %
                         (self.dut_ifn[0]))

            flag=opts[0]
            ret = self.tc_bpf_load(obj=self.obj_name, flags=flag, da=True)
            if ret:
                return NrtResult(name=self.name,
                                 testtype=self.__class__.__name__,
                                 passed=False,
                                 comment="Unable to load filter with %s" % \
                                 (flag))

            _, out = self.dut.cmd('tc filter show dev %s ingress' %
                                  (self.dut_ifn[0]))
            if out.find(flag) == -1:
                raise NtiGeneralError("%s flag not set when it should be" %
                                   (flag))


class eBPFtc_off(eBPFtest):
    def __init__(self, src, dut, group=None, name="", summary=None):
        eBPFtest.__init__(self, src, dut, mode="skip_hw",
                          group=group, name=name, summary=summary)

    def execute(self):
        self.dut.cmd('ethtool -K %s hw-tc-offload off' % (self.dut_ifn[0]))

        ret = self.tc_bpf_load(obj=self.obj_name, skip_sw=True, da=True)
        if ret == 0:
            raise NtiGeneralError("loaded hw-only filter with tc offloads disabled")

class eBPFtwo_prog(eBPFtest):
    def __init__(self, src, dut, group=None, name="", summary=None):
        eBPFtest.__init__(self, src, dut,
                          group=group, name=name, summary=summary)

    def execute(self):
        ret = self.tc_bpf_load(obj=self.obj_name, skip_sw=True, da=True)
        if ret == 0:
            raise NtiGeneralError("loaded more than one filter")

class eBPFmtu(eBPFtest):
    def __init__(self, src, dut, group=None, name="", summary=None):
        eBPFtest.__init__(self, src, dut, mode="skip_hw",
                          group=group, name=name, summary=summary)

    def execute(self):
        self.dut.cmd('ifconfig %s mtu 3000' % (self.dut_ifn[0]))
        ret = self.tc_bpf_load(obj=self.obj_name, skip_sw=True, da=True)
        self.dut.cmd('ifconfig %s mtu 1500' % (self.dut_ifn[0]))

        if ret == 0:
            raise NtiGeneralError("loaded hw-only filter with large MTU")

#########################################################################
# Data passing/comparing tests
#########################################################################

class eBPFdataTest(CommonPktCompareTest):
    def get_tcpdump_params(self):
        return (self.dut, self.dut_ifn[0], self.src)

    def install_filter(self):
        self.dut.cmd('ethtool -K %s hw-tc-offload on' % (self.dut_ifn[0]))
        self.dut.cmd('tc qdisc add dev %s ingress' % (self.dut_ifn[0]))

        flags = self.group.tc_mode() + " da"

        return self.tc_bpf_load(obj=self.get_prog_name(), flags=flags)

    def cleanup(self):
        self.dut.cmd('tc qdisc del dev %s ingress' % self.dut_ifn[0])

class eBPFdpaRD(eBPFdataTest):
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

# Instruction combine tests are reusing eBPFdrop test infrastructure.
class eBPFld_mask_combine(eBPFdrop):
    def __init__(self, src, dut, group=None, name="", summary=None):
        eBPFtest.__init__(self, src, dut, obj_name="ld_mask_combine.o",
                          group=group, name=name, summary=summary)

class eBPFld_shift_combine(eBPFtest):
    def __init__(self, src, dut, group=None, name="", summary=None):
        eBPFtest.__init__(self, src, dut, obj_name="ld_shift_combine.o",
                          group=group, name=name, summary=summary)
