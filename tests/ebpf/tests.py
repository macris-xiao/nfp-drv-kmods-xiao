#
# Copyright (C) 2017,  Netronome Systems, Inc.  All rights reserved.
#
"""
BPF test group for the NFP Linux drivers.
"""

import os, pprint
import time
import netro.testinfra
from netro.testinfra.nti_exceptions import NtiGeneralError
from netro.testinfra.test import *
from ..common_test import *
from ..drv_grp import NFPKmodAppGrp
from ..ebpf_test import *
from xdp import *
from maps import *

class BPF_TLV:
    FUNC		= 1
    ADJUST_HEAD		= 2
    MAPS		= 3

###########################################################################
# Group
###########################################################################

class NFPKmodBPF(NFPKmodAppGrp):
    """BPF tests for the NFP Linux drivers"""

    summary = "BPF tests used for NFP Linux driver."

    def parse_bpf_caps(self):
        self.dut.bpf_caps = {
            "funcs" :  {
            },
            "adjust_head" : {
                "present"		: False,
                "flags"			: 0,
                "off_min"		: 0,
                "off_max"		: 0,
                "guaranteed_sub"	: 0,
                "guaranteed_add"	: 0,
            },
            "maps" : {
                "present"		: False,
                "types"			: 0,
                "max_maps"		: 0,
                "max_elems"		: 0,
                "max_key_sz"		: 0,
                "max_val_sz"		: 0,
                "max_elem_sz"		: 0,
            },
        }

        value = self._tests["xdp_pass"].read_sym_nffw("_abi_bpf_capabilities")
        if value is None:
            return

        while len(value) > 8:
            tlv_type = struct.unpack("<I", value[0:4])[0]
            tlv_len  = struct.unpack("<I", value[4:8])[0]
            value = value[8:]

            if tlv_type == BPF_TLV.FUNC:
                cap = self.dut.bpf_caps["funcs"]

                func_id = struct.unpack("<I", value[0:4])[0]
                func_addr = struct.unpack("<I", value[4:8])[0]
                cap[func_id] = func_addr

            elif tlv_type == BPF_TLV.ADJUST_HEAD:
                cap = self.dut.bpf_caps["adjust_head"]

                cap["present"]	= True
                cap["flags"]	= struct.unpack("<I", value[0:4])[0]
                cap["off_min"]	= struct.unpack("<I", value[4:8])[0]
                cap["off_max"]	= struct.unpack("<I", value[8:12])[0]
                cap["guaranteed_sub"] = struct.unpack("<I", value[12:16])[0]
                cap["guaranteed_add"] = struct.unpack("<I", value[16:20])[0]

            elif tlv_type == BPF_TLV.MAPS:
                cap = self.dut.bpf_caps["maps"]

                cap["present"]	= True
                cap["types"]	= struct.unpack("<I", value[0:4])[0]
                cap["max_maps"]	= struct.unpack("<I", value[4:8])[0]
                cap["max_elems"]	= struct.unpack("<I", value[8:12])[0]
                cap["max_key_sz"]	= struct.unpack("<I", value[12:16])[0]
                cap["max_val_sz"]	= struct.unpack("<I", value[16:20])[0]
                cap["max_elem_sz"]	= struct.unpack("<I", value[20:24])[0]

            else:
                LOG_sec("Unknown TLV")
                LOG("type: %d len: %d" % (tlv_type, tlv_len))
                LOG_endsec()

            value = value[tlv_len:]

        pp = pprint.PrettyPrinter()

        LOG_sec("BPF capability TLVs parsed")
        LOG(pp.pformat(self.dut.bpf_caps))
        LOG_endsec()

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
               ('xdp_pass_adj_offload_far', XDPpassOffloadFar,
                'XDP adjust head almost too far for offload'),
               ('xdp_pass_adj_offload_close', XDPpassOffloadClose,
                'XDP adjust head almost too close for offload'),
               ('xdp_pass_adj_offload_far2', XDPpassOffloadFar2,
                'XDP adjust head almost too far for offload (adj twice)'),
               ('xdp_pass_adj_offload_close2', XDPpassOffloadClose2,
                'XDP adjust head almost too close for offload (adj twice)'),
               ('xdp_fail_adj_offload_far', XDPfailOffloadFar,
                'XDP adjust head too far for offload'),
               ('xdp_fail_adj_offload_close', XDPfailOffloadClose,
                'XDP adjust head too close for offload'),
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
               ('xdp_tx_adj_head_prep_twice_short', XDPfailTwiceShort,
                'XDP adjust head prep -256B two times'),
               ('xdp_tx_adj_head_prep_twice_long', XDPfailTwiceLong,
                'XDP adjust head prep 256B two times'),
               ('xdp_tx_adj_head_prep_twice_65k', XDPfailOversized,
                'XDP adjust head prep 65kB two times'),
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
                'make sure stack accesses are not aliased'),
               ('xdp_stack_roundup', XDPpassAll,
                'test stack of size not aligned to 4B'),

               ('xdp_stack_read_low8', XDPpassAll,
                'test 8B reads of the first 32B of the stack'),
               ('xdp_stack_read_low4', XDPpassAll,
                'test 4B reads of the first 32B of the stack'),
               ('xdp_stack_read_low2', XDPpassAll,
                'test 2B reads of the first 32B of the stack'),
               ('xdp_stack_read_low1', XDPpassAll,
                'test 1B reads of the first 32B of the stack'),
               ('xdp_stack_read_mid8', XDPpassAll,
                'test 8B reads of the 32B - 64B region of the stack'),
               ('xdp_stack_read_mid4', XDPpassAll,
                'test 4B reads of the 32B - 64B region of the stack'),
               ('xdp_stack_read_mid2', XDPpassAll,
                'test 2B reads of the 32B - 64B region of the stack'),
               ('xdp_stack_read_mid1', XDPpassAll,
                'test 1B reads of the 32B - 64B region of the stack'),
               ('xdp_stack_read_hig8', XDPpassAll,
                'test 8B reads of the stack region above 64B'),
               ('xdp_stack_read_hig4', XDPpassAll,
                'test 4B reads of the stack region above 64B'),
               ('xdp_stack_read_hig2', XDPpassAll,
                'test 2B reads of the stack region above 64B'),
               ('xdp_stack_read_hig1', XDPpassAll,
                'test 1B reads of the stack region above 64B'),
               ('xdp_stack_read_hig8_cross32', XDPpassAll,
                'test 8B reads of the stack region above 64B and crossing 32B boundary'),
               ('xdp_stack_read_unknown', XDPpassAll,
                'test reads via modified (constant) reg'),
               ('xdp_stack_read_unknown_bad_align', XDPLoadFailTest,
                'test reads via modified (non-constant) reg'),
               ('xdp_stack_read_unaligned', XDPLoadFailTest,
                'test unaligned reads (kernel should reject)'),

               ('xdp_stack_write_low8', XDPpassAll,
                'test 8B write of the first 32B of the stack'),
               ('xdp_stack_write_low4', XDPpassAll,
                'test 4B write of the first 32B of the stack'),
               ('xdp_stack_write_low2', XDPpassAll,
                'test 2B write of the first 32B of the stack'),
               ('xdp_stack_write_low1', XDPpassAll,
                'test 1B write of the first 32B of the stack'),
               ('xdp_stack_write_mid8', XDPpassAll,
                'test 8B write in the 32-64B range of the stack'),
               ('xdp_stack_write_mid4', XDPpassAll,
                'test 4B write in the 32-64B range of the stack'),
               ('xdp_stack_write_mid2', XDPpassAll,
                'test 2B write in the 32-64B range of the stack'),
               ('xdp_stack_write_mid1', XDPpassAll,
                'test 1B write in the 32-64B range of the stack'),
               ('xdp_stack_write_hig8', XDPpassAll,
                'test 8B write past the first 64B of the stack'),
               ('xdp_stack_write_hig4', XDPpassAll,
                'test 4B write past the first 64B of the stack'),
               ('xdp_stack_write_hig2', XDPpassAll,
                'test 2B write past the first 64B of the stack'),
               ('xdp_stack_write_hig1', XDPpassAll,
                'test 1B write past the first 64B of the stack'),

               ('xdp_stack_write_hig8_cross32', XDPpassAll,
                'test 8B write of the stack region above 64B and crossing 32B boundary'),
               ('xdp_stack_write_unknown', XDPpassAll,
                'test writes via modified (constant) reg'),
               ('xdp_stack_write_unknown_bad_align', XDPLoadFailTest,
                'test writes via modified (non-constant) reg'),
               ('xdp_stack_write_unaligned', XDPLoadFailTest,
                'test unaligned writes (kernel should reject)'),

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
               ('xdp_tx_memcpy_5', XDPASMmemcpy5,
                'Opt memory copy (multiple seq, with invalid)'),
               ('xdp_tx_memcpy_6', XDPASMmemcpy6,
                'Opt memory copy (multiple seq, all valid)'),
               ('xdp_tx_memcpy_7', XDPASMmemcpy7,
                'Opt memory copy (jump into middle of sequence)'),
               ('xdp_tx_memcpy_8', XDPASMmemcpy8,
                'Opt memory copy (cross memory access )'),
               ('xdp_tx_memcpy_9', XDPASMmemcpy9,
                'Opt memory copy (unusal cases)'),
               ('xdp_tx_mem_builtins', XDPCmembuiltins,
                'Memory operation builtins tests'),
               ('array_init', XDParrayInitialise, 'Check array is initialised to 0'),
               ('map_limits', XDPmapLimits, 'Check limits on map parameters'),
               ('map_stress', XDPmapStress,
                'Multi-threaded stress test of maps'),
               ('map_htab', XDPhtabCtrl, 'Test basic ctrl path of hash maps'),
               ('map_dp_htab', XDPhtabLookup,
                'Test basic data path lookups for hash maps'),
               ('map_dp_htab_twice', XDPhtabLookupTwice,
                'Test two data path lookups for (two separate) hash maps'),
               ('map_array', XDParrayCtrl, 'Test basic ctrl path of arrays'),
               ('map_dp_array', XDParrayLookup,
                'Test basic data path lookups for arrays'),
               ('map_dp_array_twice', XDParrayLookupTwice,
                'Test two data path lookups for (two separate) arrays'),
               ('xdp_imm_relo', XDPimmRelo,
                'Immediate relocation (return address)'),
               ('xdp_imm_relo2', XDPimmRelo2,
                'Immediate relocation (return address)'),
               ('xdp_oversize', XDPLoadNoOffloadTest,
                'Load program too large for the code store'),
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
             ('tc_hw_ethtool_feature', eBPFtc_feature,
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
        NFPKmodAppGrp._init(self)

        self.dut.copy_bpf_samples()
        self.parse_bpf_caps()
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

        self.n_start = self.bpf_obj_cnt()

        if self.has_bpf_objects():
            raise NtiError('eBPF objects exist before test start')

    def bpf_obj_cnt(self):
        _, prog = self.dut.bpftool_prog_list()
        _, maps = self.dut.bpftool_map_list()

        return len(prog) + len(maps)

    def has_bpf_objects(self):
        return self.bpf_obj_cnt() != self.n_start

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

class eBPFtc_feature(eBPFtest):
    def __init__(self, src, dut, group=None, name="", summary=None):
        eBPFtest.__init__(self, src, dut, mode="skip_hw",
                          group=group, name=name, summary=summary)

    def execute(self):
        self.dut.cmd('ethtool -K %s hw-tc-offload off' % (self.dut_ifn[0]))

        ret = self.tc_bpf_load(obj=self.obj_name, skip_sw=True, da=True)
        if ret == 0:
            raise NtiError("loaded hw-only filter with tc offloads disabled")

        self.dut.cmd('ethtool -K %s hw-tc-offload on' % (self.dut_ifn[0]))
        ret = self.tc_bpf_load(obj=self.obj_name, skip_sw=True, da=True)
        if ret != 0:
            raise NtiError("Couldn't load hw-only filter with tc offloads on")

        ret, _ = self.dut.cmd('ethtool -K %s hw-tc-offload off' %
                              (self.dut_ifn[0]),
                              fail=False)
        if ret == 0:
            raise NtiError("Disabled TC offloads with filter loaded")

        # Clean the existing filter
        cmd  = 'tc qdisc del dev %s ingress; ' % (self.dut_ifn[0])
        cmd += 'tc qdisc add dev %s ingress; ' % (self.dut_ifn[0])
        self.dut.cmd(cmd)
        # Now we should be able to disable
        self.dut.cmd('ethtool -K %s hw-tc-offload off' % (self.dut_ifn[0]))
        # XDP should load without ethtool flag...
        self.xdp_start('pass.o', mode="offload")
        self.xdp_stop(mode="offload")
        # .. or with it
        self.dut.cmd('ethtool -K %s hw-tc-offload on' % (self.dut_ifn[0]))
        self.xdp_start('pass.o', mode="offload")
        # And we should be able to disable the flag with XDP on
        self.dut.cmd('ethtool -K %s hw-tc-offload off' % (self.dut_ifn[0]))

    def cleanup(self):
        self.xdp_stop(mode="offload")
        eBPFtest.cleanup(self)

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

        ret = self.tc_bpf_load(obj=self.obj_name, skip_sw=True, da=True)
        ret, _ = self.dut.cmd('ifconfig %s mtu 3000' % (self.dut_ifn[0]),
                              fail=False)
        if ret ==  0:
            raise NtiError("Set large MTU when BPF loaded!")

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

class eBPFld_shift_combine(eBPFdrop):
    def __init__(self, src, dut, group=None, name="", summary=None):
        eBPFtest.__init__(self, src, dut, obj_name="ld_shift_combine.o",
                          group=group, name=name, summary=summary)
