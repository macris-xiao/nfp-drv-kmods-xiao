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

    def populate_tests(self):
        dut = (self.dut, self.addr_x, self.eth_x, self.addr_v6_x)
        src = (self.host_a, self.addr_a, self.eth_a, self.addr_v6_a)

        T = (('bpf_capa', eBPFcapa, "eBPF capability test"),
             ('bpf_pass', eBPFpass, "eBPF pass all filter"),
             ('bpf_drop', eBPFdrop, "eBPF drop all filter"),
             ('bpf_mark', eBPFmark, "eBPF mark all filter"),
             ('bpf_abort', eBPFabort, "eBPF abort all filter"),
             ('bpf_redirect', eBPFredir, "eBPF redirect all filter"),
             ('bpf_4ctx', eBPFmark, "eBPF ME 4 context mode test"),
             ('bpf_tcp58', eBPFmark, "eBPF filter on TCP port 58"),
             ('bpf_jeq_jgt', eBPFjeq_jgt, "eBPF JEQ JGT branch test"),
             ('bpf_jneq', eBPFjneq, "eBPF JNE branch test"),
             ('bpf_tc_gen_flags', eBPFflags, 'iproute/cls_bpf flag reporting'),
             ('bpf_tc_offload_disabled', eBPFtc_off,
              'Check if loading fails if ethtool disabled TC offloads'),
             ('bpf_two_prog', eBPFtwo_prog, 'Check 2 progs fail'),
             ('bpf_mtu_check', eBPFmtu, 'Check high MTU fails'),
             ('bpf_harden', eBPFharden, 'Check hardening makes fail'),
        )

        for t in T:
            self._tests[t[0]] = t[1](src, dut, group=self, name=t[0],
                                     summary=t[2])

        TS = (('bpf_fallback', 'store.o', '', 'Check SW fallback'),
        )

        for t in TS:
            self._tests[t[0]] = eBPFtest(src, dut, obj_name=t[1], tc_flags=t[2],
                                         group=self, name=t[0], summary=t[3])

        # Direct action tests
        DA = (('bpf_da_DROP', 'da_2_drop.o', 1),
              ('bpf_da_STOL', 'da_4_nuke.o', None),
              ('bpf_da_QUE', 'da_5_nuke.o', None),
              ('bpf_da_UNSP', 'da_-1_unspec.o', 0),
              ('bpf_da_unkn', 'da_8_unspec.o', 0),
              ('bpf_da_n_unkn', 'da_n_unspec.o', 0),
              ('bpf_da_abort', 'da_abort.o', 0),
        )

        for t in DA:
            self._tests[t[0]] = eBPFda(src, dut, t[1], stat=t[2], group=self,
                                       name=t[0],
                                       summary='Direct act test with %s' % \
                                       (t[1]))

        # Test if cls_bpf offload works by default
        DFL = (('bpf_cls_pass_dfl', eBPFpass,
                'Check if TC pass gets offloaded'),
               ('bpf_cls_mark_dfl', eBPFmark,
                'Check if TC mark gets offloaded'),
        )

        for t in DFL:
            self._tests[t[0]] = t[1](src, dut, tc_flags="",
                                     group=self, name=t[0], summary=t[2])

        TF = (('bpf_da_and_act', 'pass.o', 'da skip_sw'),
              ('bpf_bad_ptr', 'validate_ptr_type.o', 'skip_sw'),
              ('bpf_store', 'store.o', 'skip_sw'),
              ('bpf_maps', 'maps.o', 'skip_sw'),
        )

        for t in TF:
            self._tests[t[0]] = eBPFtest(src, dut, obj_name=t[1],
                                         tc_flags=t[2], should_fail=True,
                                         group=self, name=t[0],
                                         summary='Fail with %s %s' % \
                                         (t[1], t[2]))

        DAF = (('OK', 'da_0_pass.o'),
             ('RECL', 'da_1_pass.o'),
             ('PIPE', 'da_3_unspec.o'),
             ('REP', 'da_6_unspec.o'),
             ('REDIR', 'da_7_redir.o'),
        )

        for t in DAF:
            tn = 'bpf_da_' + t[0]
            self._tests[tn] = \
                eBPFtest(src, dut, t[1], tc_flags="da skip_sw", act="",
                         should_fail=True, group=self, name=tn,
                         summary='Direct action %s fail test' % (t[0]))

        XDP = (('xdp_pass', XDPpass, 'XDP pass test'),
               ('xdp_drop', XDPdrop, 'XDP drop test'),
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
        )

        for t in XDP:
            self._tests[t[0]] = t[1](src, dut, group=self, name=t[0],
                                     summary=t[2])

    def driver_load(self):
        M = self.dut

        if not self.upstream_drv:
            # Try to see if FW is already loaded
            M.insmod(netdev=True, userspace=True)
            ret, _ = M.cmd_rtsym('_pf0_net_bar0', fail=False)
            if ret == 0:
                return

            M.rmmod()

        # If not use kernel loader
        M.cmd('mkdir -p /lib/firmware/netronome')
        M.cp_to(self.netdevfw, '/lib/firmware/netronome/%s' % M.get_fw_name())

        if self.upstream_drv:
            M.cmd('modprobe nfp')
        else:
            M.insmod(netdev=True, userspace=True)


    def _init(self):
        NFPKmodGrp._init(self)

        self.driver_load()

        M = self.dut

        # Disable DAD
        cmd = ''
        for ifc in self.eth_x:
            cmd += 'sysctl -w net.ipv6.conf.%s.accept_dad=0;' % (ifc)
            cmd += 'sysctl -w net.ipv6.conf.%s.dad_transmits=0;' % (ifc)
        M.cmd(cmd)

        # Init DUT
        M.cmd('ethtool -G %s rx 512 tx 512' % (self.eth_x[0]))
        M.cmd('ifconfig %s %s promisc up' % (self.eth_x[0], self.addr_x[0]))
        M.cmd('ip addr add %s dev %s' % (self.addr_v6_x[0], self.eth_x[0]))

        # Make sure NTI knows the NFP interface exists
        M.refresh()

        # stash hwaddrs for traffic generation
        _, out = self.dut.cmd("ifconfig %s" % self.eth_x[0])
        ifcfg = _parse_ifconfig(out)
        self.hwaddr_x = ifcfg["hwaddr"]
        self.mtu_x = ifcfg["mtu"]
        self.promisc_x = out.find("PROMISC") != -1

        _, out = self.host_a.cmd("ifconfig %s" % self.eth_a[0])
        ifcfg = _parse_ifconfig(out)
        self.hwaddr_a = ifcfg["hwaddr"]
        self.mtu_a = ifcfg["mtu"]
        self.promisc_a = out.find("PROMISC") != -1

        # add static arp entries to speed up drop tests
        self.host_a.cmd('ip neigh add %s lladdr %s dev %s' %
                        (self.addr_x[0][:-3], self.hwaddr_x, self.eth_a[0]),
                        fail=False)
        self.host_a.cmd('ip neigh add %s lladdr %s dev %s' %
                        (self.addr_v6_x[0][:-3], self.hwaddr_x, self.eth_a[0]),
                        fail=False)

        M.copy_bpf_samples()

        # Make sure MTUs match just in case
        if self.mtu_a != self.mtu_x:
            raise NtiError("Device MTUs don't match %s vs %s" % (self.mtu_a,
                                                                 self.mtu_x))

        # SRC needs a tmp dir too
        if hasattr(self.host_a, 'tmpdir'):
            raise NtiGeneralError('SRC already has tmp dir')
        self.host_a.tmpdir = self.host_a.make_temp_dir()

        return

    def _fini(self):
        self.dut.cmd('rm -rf /lib/firmware/netronome')
        self.dut.reset_mods()

        self.host_a.cmd('rm -rf %s' % self.host_a.tmpdir)

        NFPKmodGrp._fini(self)
        return

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

class eBPFpass(eBPFtest):
    def __init__(self, src, dut, tc_flags="skip_sw", group=None, name="",
                 summary=None):
        eBPFtest.__init__(self, src, dut, obj_name="pass.o",
                          tc_flags=tc_flags, group=group, name=name,
                          summary=summary)

    def execute(self):
        self.ping(port=0)
        self.ping6(port=0)
        self.tcpping(port=0)

        counts = (30, 38, 3200, 3700)
        self.validate_cntrs(rx_t=counts, pass_all=True)

class eBPFdrop(eBPFtest):
    def __init__(self, src, dut, group=None, name="", summary=None):
        eBPFtest.__init__(self, src, dut, obj_name="drop.o",
                          group=group, name=name, summary=summary)

    def execute(self):
        self.ping(port=0, fail=False)
        self.ping6(port=0, fail=False)
        self.tcpping(port=0, fail=False)

        counts = (30, 38, 3200, 3700)
        self.validate_cntrs(rx_t=counts, app1_all=True)

class eBPFmark(eBPFtest):
    def __init__(self, src, dut, tc_flags="skip_sw", group=None, name="",
                 summary=None):
        eBPFtest.__init__(self, src, dut, obj_name="mark.o",
                          tc_flags=tc_flags, group=group, name=name,
                          summary=summary)

    def execute(self):
        self.ping(port=0)
        self.ping6(port=0)
        self.tcpping(port=0)

        counts = (30, 38, 3200, 3700)
        self.validate_cntrs(rx_t=counts, pass_all=True, mark_all=True)

class eBPF4ctx(eBPFtest):
    def __init__(self, src, dut, tc_flags="skip_sw", group=None, name="",
                 summary=None):
        eBPFtest.__init__(self, src, dut, obj_name="4ctx.o",
                          tc_flags=tc_flags, group=group, name=name,
                          summary=summary)

    def execute(self):
        self.ping(port=0)
        self.ping6(port=0)
        self.tcpping(port=0)

        counts = (30, 38, 3200, 3700)
        self.validate_cntrs(rx_t=counts, pass_all=True)

        self.ping(port=0, size=200, pattern="00", fail=False)
        self.ping(port=0, size=200, pattern="11", fail=False)
        self.ping(port=0, size=200, pattern="77", fail=False)

        counts = (30, 36, 7200, 7500)
        self.validate_cntrs(rx_t=counts, app1_all=True)

        self.ping(port=0, size=200, pattern="22")
        self.ping(port=0, size=200, pattern="55")
        self.ping(port=0, size=200, pattern="66")

        counts = (30, 36, 7200, 7500)
        self.validate_cntrs(rx_t=counts, pass_all=True)

        _, out = self.dut.cmd_reg('mecsr:i34.me9.CtxEnables')
        if out.find('InUseContexts=0x1') == -1:
            raise NtiGeneralError('InUseContexts not set to 0x1')
        if out.find('CtxEnables.CtxEnables=0x55') == -1:
            raise NtiGeneralError('CtxEnables not set to 0x55')

class eBPFtcp58(eBPFtest):
    def __init__(self, src, dut, group=None, name="", summary=None):
        eBPFtest.__init__(self, src, dut, obj_name="tcp58.o",
                          group=group, name=name, summary=summary)

    def execute(self):
        self.ping(port=0)
        self.ping6(port=0)
        self.tcpping(port=0, sport=58, dport=100)

        counts = (30, 38, 3200, 3700)
        self.validate_cntrs(rx_t=counts, pass_all=True)

        self.tcpping(port=0, sport=100, dport=58)

        counts = (10, 12, 1040, 1200)
        self.validate_cntrs(rx_t=counts, exact_filter=True)

class eBPFjeq_jgt(eBPFtest):
    def __init__(self, src, dut, group=None, name="", summary=None):
        eBPFtest.__init__(self, src, dut, obj_name="jeq_jgt.o",
                          group=group, name=name, summary=summary)

    def execute(self):
        self.ping(port=0, pattern="aa")
        self.ping(port=0, size=100)
        self.ping(port=0, size=100, pattern="a0")
        self.ping(port=0, size=100, pattern="af")

        counts = (40, 48, 5200, 5700)
        self.validate_cntrs(rx_t=counts, pass_all=True)

        self.ping(port=0, size=100, pattern="aa", fail=False)
        self.ping(port=0, size=100, pattern="bb", fail=False)
        self.ping(port=0, size=100, pattern="cc", fail=False)

        counts = (30, 34, 4260, 4400)
        self.validate_cntrs(rx_t=counts, exact_filter=True)

class eBPFjneq(eBPFtest):
    def __init__(self, src, dut, group=None, name="", summary=None):
        eBPFtest.__init__(self, src, dut, obj_name="jneq.o",
                          group=group, name=name, summary=summary)

    def execute(self):
        self.ping(port=0)
        self.ping(port=0, pattern="aa")
        self.ping(port=0, size=100, pattern="aa")

        counts = (30, 38, 3300, 3600)
        self.validate_cntrs(rx_t=counts, pass_all=True)

        self.ping(port=0, size=100, fail=False)
        self.ping(port=0, size=100, pattern="bb", fail=False)
        self.ping(port=0, size=100, pattern="cc", fail=False)

        counts = (30, 38, 4260, 4600)
        self.validate_cntrs(rx_t=counts, exact_filter=True)

class eBPFabort(eBPFtest):
    def __init__(self, src, dut, tc_flags="skip_sw", group=None, name="",
                 summary=None):
        eBPFtest.__init__(self, src, dut, obj_name="abort.o",
                          tc_flags=tc_flags, group=group, name=name,
                          summary=summary)

    def execute(self):
        # Too short to hit filters or marking
        self.ping(port=0)
        self.ping6(port=0)
        self.tcpping(port=0)

        counts = (30, 38, 3200, 3700)
        self.validate_cntrs(rx_t=counts, pass_all=True)

        # Just about too short but would hit the filter
        self.ping(port=0, size=162, pattern="aa")

        counts = (10, 13, 2000, 2200)
        self.validate_cntrs(rx_t=counts, pass_all=True)

        # Will hit the mark but too short for second filter
        self.ping(port=0, size=500)

        counts = (10, 13, 5400, 5600)
        self.validate_cntrs(rx_t=counts, pass_all=True, mark_all=True)

        # Will hit the filter
        self.ping(port=0, size=163, pattern="aa", fail=False)
        self.ping(port=0, size=1100, pattern="aa", fail=False)

        counts = (20, 23, 13470, 14000)
        self.validate_cntrs(rx_t=counts, exact_filter=True)

class eBPFredir(eBPFtest):
    def __init__(self, src, dut, tc_flags="skip_sw", group=None, name="",
                 summary=None):
        if src[0]: # for ticmd list
            act = "action mirred egress redirect dev " + dut[2][0]
        else:
            act = ""
        eBPFtest.__init__(self, src, dut, obj_name="drop.o",
                          tc_flags=tc_flags, act=act, group=group, name=name,
                          summary=summary)

    def execute(self):
        if not self.group.promisc_x:
            self.dut.cmd('ip link set dev %s promisc on' % (self.dut_ifn[0]))
        if not self.group.promisc_a:
            self.src.cmd('ip link set dev %s promisc on' % (self.src_ifn[0]))

        self.src.cp_to(os.path.join(self.group.samples_trafgen, 'redir.txf'),
                       self.group.tmpdir)

        old_src_stats = self.src.netifs[self.src_ifn[0]].stats()

        self.src.cmd('trafgen  --conf %s  -o %s -n 10' %
                     (os.path.join(self.group.tmpdir, 'redir.txf'),
                      self.src_ifn[0]))

        time.sleep(0.2)
        new_src_stats = self.src.netifs[self.src_ifn[0]].stats()

        counts = (10, 12, 900, 1050)
        self.validate_cntrs(rx_t=counts, app1_all=True)

        if not self.group.promisc_x:
            self.dut.cmd('ip link set dev %s promisc off' % (self.dut_ifn[0]))
        if not self.group.promisc_a:
            self.src.cmd('ip link set dev %s promisc off' % (self.src_ifn[0]))

        # Note: this assumes Fortville, sorry :(
        end_stats = new_src_stats - old_src_stats
        if not end_stats.ethtool['port.rx_size_127'] in range(counts[0],
                                                              counts[1]):
            raise NtiGeneralError("src rx packets (%d vs %d,%d)" % \
                               (end_stats.ethtool['port.rx_size_127'],
                                counts[0], counts[1]))
        if not end_stats.ethtool['port.rx_bytes'] in range(counts[2],
                                                           counts[3]):
            raise NtiGeneralError("src rx bytes (%d vs %d,%d)" % \
                               (end_stats.ethtool['port.rx_bytes'],
                                counts[0], counts[1]))

class eBPFda(eBPFtest):
    def __init__(self, src, dut, obj_name, stat, tc_flags="da skip_sw",
                 group=None, name="", summary=None):
        eBPFtest.__init__(self, src, dut, obj_name=obj_name,
                          tc_flags=tc_flags, act="", group=group, name=name,
                          summary=summary)
        self.stat = stat


    def execute(self):
        do_fail = self.stat == 2 or self.stat == 4 or self.stat == 5

        self.ping(port=0, fail=do_fail)
        self.ping6(port=0, fail=do_fail)
        self.tcpping(port=0, fail=do_fail)

        counts = (30, 38, 3200, 3700)
        self.validate_cntrs(rx_t=counts, pass_all=self.stat == 0,
                            app1_all=self.stat == 1, app2_all=self.stat == 2,
                            app3_all=self.stat == 3)

class eBPFflags(eBPFtest):
    def __init__(self, src, dut, group=None, name="", summary=None):
        eBPFtest.__init__(self, src, dut, obj_name="pass.o", tc_flags="",
                          group=group, name=name, summary=summary)

    def execute(self):
        # The default one in this class should have no skip flags
        _, out = self.dut.cmd('tc filter show dev %s ingress' % (self.dut_ifn[0]))
        if out.find('skip_') != -1:
            raise NtiGeneralError("skip_* flag set when it shouldn't be")

        # Check out skip_sw and skip_hw
        for flag in ("skip_sw", "skip_hw"):
            self.dut.cmd('tc filter del dev %s ingress protocol all pref 49151 bpf' %
                         (self.dut_ifn[0]))

            ret = self.tc_bpf_load(flags=flag)
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
        eBPFtest.__init__(self, src, dut, obj_name="pass.o",
                          tc_flags="skip_hw", group=group, name=name,
                          summary=summary)

    def execute(self):
        self.dut.cmd('ethtool -K %s hw-tc-offload off' % (self.dut_ifn[0]))

        ret = self.tc_bpf_load(flags="skip_sw")
        if ret == 0:
            raise NtiGeneralError("loaded hw-only filter with tc offloads disabled")

class eBPFtwo_prog(eBPFtest):
    def __init__(self, src, dut, group=None, name="", summary=None):
        eBPFtest.__init__(self, src, dut, obj_name="pass.o",
                          tc_flags="skip_sw", group=group, name=name,
                          summary=summary)

    def execute(self):
        ret = self.tc_bpf_load(flags="skip_sw")
        if ret == 0:
            raise NtiGeneralError("loaded more than one filter")

class eBPFmtu(eBPFtest):
    def __init__(self, src, dut, group=None, name="", summary=None):
        eBPFtest.__init__(self, src, dut, obj_name="pass.o",
                          tc_flags="skip_hw", group=group, name=name,
                          summary=summary)

    def execute(self):
        self.dut.cmd('ifconfig %s mtu 3000' % (self.dut_ifn[0]))
        ret = self.tc_bpf_load(flags="skip_sw")
        self.dut.cmd('ifconfig %s mtu 1500' % (self.dut_ifn[0]))

        if ret == 0:
            raise NtiGeneralError("loaded hw-only filter with large MTU")

class eBPFharden(eBPFtest):
    def __init__(self, src, dut, group=None, name="", summary=None):
        eBPFtest.__init__(self, src, dut, obj_name="pass.o",
                          tc_flags="skip_sw", group=group, name=name,
                          summary=summary)

    def execute(self):
        self.dut.cmd('sysctl net.core.bpf_jit_enable=1; sysctl net.core.bpf_jit_harden=2')
        ret = self.tc_bpf_load(flags="skip_sw")
        self.dut.cmd('sysctl net.core.bpf_jit_enable=0; sysctl net.core.bpf_jit_harden=0')
        if ret == 0:
            raise NtiGeneralError("loaded filter with hardening")
