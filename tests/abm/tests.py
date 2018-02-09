#
# Copyright (C) 2017,  Netronome Systems, Inc.  All rights reserved.
#
"""
ABM NIC test group for the NFP Linux drivers.
"""
import copy
import json
import re
import os, pprint
from struct import unpack_from
import time

from netro.testinfra import LOG_sec, LOG, LOG_endsec
from netro.testinfra.nti_exceptions import NtiError
from netro.testinfra.test import *

from ..common_test import *
from ..drv_grp import NFPKmodAppGrp
from ..drv_system import NfpNfdCtrl
from ..drv_fwdump import *

###########################################################################
# Helpers
###########################################################################

def get_le32(arr, idx):
    return struct.unpack("<I", arr[idx * 4 : (idx + 1) * 4])[0]

###########################################################################
# Group
###########################################################################

class NFPKmodBnic(NFPKmodAppGrp):
    """ABM NIC tests for the NFP Linux drivers"""

    summary = "ABM NIC tests used for NFP Linux driver."

    def _init(self):
        self.pp = pprint.PrettyPrinter()
        NFPKmodAppGrp._init(self)

        # Make sorted lists of all netdev types
        old_vnics = self.vnics
        self.n_ports = len(old_vnics)

        self.parse_netdevs()
        self.parse_fw()
        self.parse_vnics()

        return

    def parse_netdevs(self):
        self.vnics = [""] * self.n_ports
        self.pf_ports = [""] * self.n_ports
        self.mac_ports = [""] * self.n_ports
        for ifc in self.nfp_netdevs:
            _, ppn = self.dut.cmd('cat /sys/class/net/%s/phys_port_name' % ifc)
            ppn = ppn.strip()
            idx = int(ppn[-1])
            if re.match("^pf\d", ppn):
                self.pf_ports[idx] = ifc
            if re.match("^p\d", ppn):
                self.mac_ports[idx] = ifc
            if re.match("^n\d$", ppn):
                self.vnics[idx] = ifc

        LOG_sec("NFP netdevs")
        LOG("n_ports:\t" + str(self.n_ports))
        LOG("all:\t" + str(self.nfp_netdevs))
        LOG("vnics:\t" + str(self.vnics))
        LOG("pf ports:\t" + str(self.pf_ports))
        LOG("mac ports:\t" + str(self.mac_ports))
        LOG_endsec()

    def parse_fw(self):
        some_test = self._tests["sb_config"]
        value = some_test.read_sym_nffw("_pf0_net_app_id", fail=True)
        app_id = get_le32(value, 0)
        if app_id != 4:
            raise NtiError("FW app id %d, expected 4 (ABM NIC)" % (app_id))

        self.dut.fwcaps = {
            "cred_total"	: {
                 2 * 1024		: 0,
                10 * 1024		: 0,
                },
        }
        value = some_test.read_sym_nffw("_abi_nfd_total_bufs", fail=True)
        if len(value) != 8:
            raise NtiError("Symbol '_abi_nfd_total_bufs' is not 8B")

        self.dut.fwcaps["cred_total"][2048] = get_le32(value, 0)
        self.dut.fwcaps["cred_total"][10240] = get_le32(value, 1)

        LOG_sec("ABM NIC capabilities")
        LOG(self.pp.pformat(self.dut.fwcaps))
        LOG_endsec()

    def parse_vnics(self):
        self.dut.vnics = [{
            "name"		: "",
            "base_q"		: 0,
            "total_qs"		: 0,
        } for i in range(len(self.eth_x))]

        M = self.dut

        for i in range(len(self.vnics)):
            ifn = self.eth_x[i]

            st_q = M.nfd_reg_read_le32(ifn, NfpNfdCtrl.START_RXQ)
            n_qs = M.nfd_reg_read_le32(ifn, NfpNfdCtrl.MAX_RXRINGS)

            M.vnics[i]["name"] = ifn
            M.vnics[i]["base_q"] = st_q / 4
            M.vnics[i]["total_qs"] = n_qs

        LOG_sec("ABM NIC vNICs")
        LOG(self.pp.pformat(self.dut.vnics))
        LOG_endsec()

    def populate_tests(self):
        dut = (self.dut, self.addr_x, self.eth_x, self.addr_v6_x)
        src = (self.host_a, self.addr_a, self.eth_a, self.addr_v6_a)

        tests = (
            ('names', BnicNames, 'check FW and app name match expected'),
            ('modes', BnicModes, 'legacy vs switchdev mode'),
            ('netdevs', BnicNetdevs, 'behaviour of all the netdevs'),
            ('tc_flag', BnicTcOffload, 'behaviour of tc-hw-offload flag'),
            ("sb_config", BnicSbConfig, 'configuration of buffering'),
            ("red_qlvl", BnicQlvl, 'RED as root'),
            ("red_mark_non_tcp", BnicMarkPing,
             'Marking of non-TCP packets (ICMP)'),
            ("red_topo_bad", BnicRedNonRoot,
             "RED doesn't offload on top of other Qdiscs"),
            ("red_raw", BnicRedRaw,
             'RED as root, force stats with mem writes from user space'),
            ("red_mq", BnicRedMq, 'RED on top of MQ'),
            ("red_mq_raw", BnicRedMqRaw,
             'RED on top of MQ, force stats with mem writes from user space'),
            # must be last - will unload the driver
            ("reload", BnicReload, 'reload the driver with things configured'),
        )

        for t in tests:
            self._tests[t[0]] = t[1](src, dut, group=self, name=t[0],
                                     summary=t[2])

    def refresh_nfp_netdevs(self, netifs_old):
        self.dut._get_netifs()
        netifs_new = self.dut._netifs

        added = list(set(netifs_new) - set(netifs_old))
        for netdev in added:
            self.nfp_netdevs.append(netdev)
        removed = list(set(netifs_old) - set(netifs_new))
        for netdev in removed:
            self.nfp_netdevs.remove(netdev)
        self.parse_netdevs()

###########################################################################
# Test base class
###########################################################################

NUM_PCI_PFS = 1
LOCAL_PF_IDX = 0
FW_STATE_DUMP_LVL = 3
MAX_QUEUES = 64
NUM_QM_STATS = 4
NUM_QM_STATS = 4

ABM_LVL_NOT_SET = ((1 << 32) - 1)

class BnicTest(CommonTest):
    def unpack_creds(self, data):
        vals = unpack_from('< I I', data)
        return {
            2 * 1024		: vals[0],
            10 * 1024		: vals[1],
        }

    def _read_fw_state(self, rtsym_tlvs):
        fw_state = dict()
        fw_state["qmstate"] = [False] * NUM_PCI_PFS
        fw_state["cred_excl"] = [{} for i in range(NUM_PCI_PFS)]
        fw_state["nfd_excl"] = [{} for i in range(NUM_PCI_PFS)]
        fw_state["mbox_state"] = [() for i in range(NUM_PCI_PFS)]
        fw_state["qlvl"] = [[] for i in range(NUM_PCI_PFS)]
        fw_state["qlen"] = [[] for i in range(NUM_PCI_PFS)]
        fw_state["qblog"] = [[] for i in range(NUM_PCI_PFS)]
        fw_state["qmstat"] = \
            [[() for j in range(MAX_QUEUES)] for i in range(NUM_PCI_PFS)]

        for t in rtsym_tlvs:
            r = t.value
            if r.sym_name.count('_abi_nfdqm') and r.sym_name.count('sto_state'):
                idx = int(r.sym_name[10])
                fw_state["qmstate"][idx] = \
                    bool(unpack_from('< Q', r.reg_data)[0])
            elif r.sym_name == '_abi_nfd_total_bufs':
                fw_state["cred_total"] = self.unpack_creds(r.reg_data)
            elif r.sym_name == '_abi_nfd_out_resv_buf_cred_master':
                fw_state["cred_resv"] = self.unpack_creds(r.reg_data)
            elif r.sym_name.count('_abi_nfd_buf_cred_master_'):
                idx = int(r.sym_name[-1:])
                fw_state["cred_excl"][idx] = self.unpack_creds(r.reg_data)
            elif r.sym_name == '_nfd_out_resv_buf_cred':
                fw_state["nfd_resv"] = self.unpack_creds(r.reg_data)
            elif r.sym_name.count('_nfd_out_buf_cred_'):
                idx = int(r.sym_name[-1:])
                fw_state["nfd_excl"][idx] = self.unpack_creds(r.reg_data)
            elif r.sym_name.count('_abi_nfd_out_q_lvls_'):
                idx = int(r.sym_name[-1:])

                per_q = 16
                if len(r.reg_data) / per_q != MAX_QUEUES:
                    raise NtiError("Qlvl stat symbol bad len, have len %d" %
                                   (len(r.reg_data) / per_q))

                for i in range(MAX_QUEUES):
                    vals = unpack_from('< I I I',
                                       r.reg_data[i * per_q:(i + 1) * per_q])
                    fw_state["qblog"][idx].append(vals[0])
                    fw_state["qlen"][idx].append(vals[1])
                    fw_state["qlvl"][idx].append(vals[2])
            elif r.sym_name.count('_abi_nfdqm') and r.sym_name.count('stats'):
                idx = int(r.sym_name[10])

                per_q = NUM_QM_STATS * 8
                qs = len(r.reg_data) / per_q
                if qs != MAX_QUEUES:
                    raise NtiError("QM stat symbol bad len, have %d queues" %
                                   (qs))

                for i in range(MAX_QUEUES):
                    fw_state["qmstat"][idx][i] = \
                        unpack_from('< ' + 'Q ' * NUM_QM_STATS,
                                    r.reg_data[i * per_q:(i + 1) * per_q])
            elif r.sym_name.count('_abi_nfd_pf0_mbox'):
                idx = int(r.sym_name[-6])
                fw_state["mbox_state"][idx] = unpack_from('< I I I I I I I I',
                                                          r.reg_data)

        return fw_state

    def read_fw_state(self):
        LOG_sec("Read FW state")
        try:
            # Get the FW dump
            _, fn = self.dut.ethtool_get_fwdump(self.dut_ifn[0],
                                                FW_STATE_DUMP_LVL)
            with open(fn, "rb") as dump_file:
                data = dump_file.read()
            dump = FwDump(data)

            rtsyms = [tlv for tlv in dump.tlvs if tlv.the_type == TYPE_RTSYM]
            LOG_sec('RTsyms')
            for t in rtsyms:
                LOG(t.value.sym_name + '\tlen:%d' % len(t.value.reg_data))
            LOG_endsec()

            fw_state = self._read_fw_state(rtsyms)

            LOG_sec("ABM NIC FW state")
            LOG(self.group.pp.pformat(fw_state))
            LOG_endsec()
        finally:
            LOG_endsec()

        return fw_state

    def switchdev_mode(self):
        return self.switchdev_mode_ever_enabled() and self.dut.switchdev_on

    def switchdev_mode_ever_enabled(self):
        return hasattr(self.dut, 'switchdev_on')

    def _switchdev_mode_check_enabled(self, expect):
        if self.switchdev_mode_ever_enabled() and \
           self.dut.switchdev_on == expect:
            return True
        self.dut.switchdev_on = expect

    def switchdev_mode_set(self, eswitchmode):
        if self._switchdev_mode_check_enabled(eswitchmode == "switchdev"):
            return

        netifs_old = self.dut._netifs
        self.dut.devlink_eswitch_mode_set(eswitchmode)
        self.group.refresh_nfp_netdevs(netifs_old)
        self.system_refresh_mode()

    def switchdev_mode_enable(self):
        self.switchdev_mode_set("switchdev")

    def switchdev_mode_disable(self):
        self.switchdev_mode_set("legacy")

    def vnics_set(self, vnics, state):
        all_cmd = ''
        for ifc in vnics:
            all_cmd += 'ip link set dev %s %s;' % (ifc, state)
        return self.dut.cmd(all_cmd)

    def vnics_all_up(self):
        LOG_sec("Set all vNICs UP")
        try:
            res = self.vnics_set(self.group.vnics, "up")
            for ifc in self.group.vnics:
                self.dut.link_wait(ifc)
        finally:
            LOG_endsec()
        return res

    def vnics_all_down(self):
        return self.vnics_set(self.group.vnics, "down")

    def all_qs(self, ifc):
        if isinstance(ifc, (int, long)):
            i = ifc
        else:
            i = self.group.pf_ports.index(ifc)
        vnic_cfg = self.dut.vnics[i]

        return range(vnic_cfg['base_q'],
                     vnic_cfg['base_q'] + vnic_cfg['total_qs'])

    def devlink_sb_pool_set(self, sb, pool, size, thtype="static", fail=True):
        ret, out = self.dut.devlink_sb_pool_set(sb=sb, pool=pool, size=size,
                                                thtype=thtype, fail=fail)
        if ret == 0:
            for p in self._pools:
                if p["sb"] == sb and p["pool"] == pool:
                    p["size"] = size
                    break
        return ret, out

    def qdisc_delete(self, ifc, parent=None, kind=None, fail=False):
        params = ''
        if parent:
            params += " parent " + parent
        if kind:
            params += " " + kind
        return self.dut.cmd("tc qdisc delete dev %s parent %s" % (ifc, parent),
                            fail=fail)

    def qdisc_replace(self, ifc, parent="root", kind="mq", thrs=0, ecn=True,
                      _bulk=False):
        if kind == "red":
            param = "min {thrs} max {thrs} avpkt {thrs} burst 1 "\
                    "limit 400000 bandwidth 10Mbit {ecn}"\
                    .format(thrs=thrs, ecn=("ecn" * ecn))
        else:
            param = ""
        cmd = "tc qdisc replace dev %s parent %s %s %s" % (ifc, parent,
                                                           kind, param)
        if _bulk:
            return cmd
        else:
            return self.dut.cmd(cmd)

    def _qdisc_json_group_by_dev(self, out):
        out = json.loads(out)
        res = dict()
        for q in out:
            dev = q['dev']
            if dev not in res:
                res[dev] = [q]
            else:
                res[dev].append(q)
        return res

    def qdisc_show(self, ifc=None):
        params=""
        if ifc:
            params += " dev " + ifc
        ret, out = self.dut.cmd("tc -s -j qdisc show" + params)
        if ret == 0 and len(out.strip()) != 0:
            out = self._qdisc_json_group_by_dev(out)
        return ret, out

    def _ip_json_group_by_dev(self, out):
        out = json.loads(out)
        res = dict()
        for d in out:
            res[d['ifname']] = d
        return res

    def ip_show(self, ifc=None):
        params=""
        if ifc:
            params += " dev " + ifc
        ret, out = self.dut.cmd("ip -j -s link show")
        if ret == 0 and len(out.strip()) != 0:
            out = self._ip_json_group_by_dev(out)
        return ret, out

    def count_netdevs(self, netdevs):
        return len(netdevs) - netdevs.count('')

    def nqid_to_qid(self, ifc, nqid):
        nid = self.group.pf_ports.index(ifc)
        return self.dut.vnics[nid]['base_q'] + nqid

    def qdisc_to_nqid(self, q):
        return int('0x' + q['parent'].split(':')[1], 16) - 1

    def system_refresh_mode(self):
        _, self._sbs = self.dut.devlink_sb_list()
        _, self._pools = self.dut.devlink_sb_pool_list()

    def system_refresh(self):
        self.system_refresh_mode()

    def set_root_red_all(self, thrs, ecn=True):
        for i in range(self.group.n_ports):
            self.qdisc_replace(self.group.pf_ports[i], kind='red', thrs=thrs,
                               ecn=ecn)

    def get_state_simple_root_red(self):
        fw_state = self.read_fw_state()
        _, qdiscs = self.qdisc_show()
        reds = []
        for ifc in self.group.pf_ports:
            assert_equal(1, len(qdiscs[ifc]), 'Wrong number of qdiscs on port')
            reds.append((self.group.pf_ports.index(ifc), ifc, qdiscs[ifc][0]))

        return fw_state, qdiscs, reds

    def _validate_eswitch_mode(self, exp_mode):
        G = self.group
        n_other = 0 if exp_mode != "switchdev" else G.n_ports

        assert_equal(G.n_ports + n_other * 2, len(G.nfp_netdevs),
                     "Wrong number of NFP netdevs")
        assert_equal(n_other, self.count_netdevs(G.pf_ports),
                     "Wrong number of PF netdevs")
        assert_equal(n_other, self.count_netdevs(G.mac_ports),
                     "Wrong number of MAC netdevs")

    def _validate_sb_total(self):
        expected = self.dut.fwcaps["cred_total"].keys()

        assert_equal(len(expected), len(self._sbs), "Wrong number of SBs")

        for sb in self._sbs:
            if sb["sb"] not in expected:
                raise NtiError("Unexpected SB: %d" % (sb["sb"]))
            assert_equal(self.dut.fwcaps["cred_total"][sb["sb"]] * sb["sb"],
                         sb["size"],
                         'Unexpected SB size for sb %d (FW cap)' % (sb["sb"]))

            assert_equal(0, sb["ing_pools"], "Unexpected ing_pools")
            assert_equal(2, sb["eg_pools"], "Unexpected eg_pools")
            assert_equal(1, sb["ing_tcs"], "Unexpected ing_tcs")
            assert_equal(1, sb["eg_tcs"], "Unexpected eg_tcs")

    def _validate_pools(self):
        sbs = self.dut.fwcaps["cred_total"].keys()

        assert_equal(len(sbs) * 2, len(self._pools), "Wrong number of pools")

        for p in self._pools:
            assert_equal("egress", p["type"], "Wrong pool type")
            assert_equal("static", p["thtype"], "Wrong thrs pool type")
            assert_lt(2, p["pool"], "Wrong pool ID")
            assert_equal(0, p["size"] % p["sb"],
                         "Pool size not multiple of buffer size")
            assert_in(sbs, p["sb"], "Pool from unknown SB")

    def validate_fw_state(self):
        fw_state = self.read_fw_state()
        # Check mode
        emode = "switchdev" if self.switchdev_mode() else "legacy"
        assert_equal(emode == "switchdev",
                     fw_state['qmstate'][self.group.pf_id],
                     "Wrong QM state")
        # Check SBs
        for sb in self._sbs:
            assert_equal(fw_state["cred_total"][sb["sb"]] * sb["sb"],
                         sb["size"],
                         'Unexpected SB size for sb %d (state)' % (sb["sb"]))
        # Check pools
        for p in self._pools:
            if p["pool"] == 0:
                creds = fw_state['cred_excl'][self.group.pf_id]
            else:
                creds = fw_state['cred_resv']
            assert_equal(p["size"], creds[p["sb"]] * p["sb"],
                         "Incorrect pool size")

    def validate_system(self):
        LOG_sec("System check")
        try:
            LOG_sec("Switchdev")
            try:
                _, mode = self.dut.devlink_eswitch_mode_get()
                emode = "switchdev" if self.switchdev_mode() else "legacy"
                if mode != emode:
                    raise NtiError('Device not in %s mode, have: %s' %
                                   (emode, mode))
                self._validate_eswitch_mode(emode)
            finally:
                LOG_endsec()

            LOG_sec("SBs")
            try:
                _, sbs = self.dut.devlink_sb_list()
                assert_equal(self._sbs, sbs, "SBs mismatch")
                self._validate_sb_total()
            finally:
                LOG_endsec()

            LOG_sec("Pools")
            try:
                _, pools = self.dut.devlink_sb_pool_list()
                assert_equal(self._pools, pools, "Pools mismatch")
                self._validate_pools()
            finally:
                LOG_endsec()

            LOG_sec("FW state")
            try:
                self.validate_fw_state()
            finally:
                LOG_endsec()
        finally:
            LOG_endsec()

    def validate_root_fw_levels(self, fw_state, thrs):
        for i in range(self.group.n_ports):
            for j in self.all_qs(i):
                assert_equal(thrs, fw_state['qlvl'][self.group.pf_id][j],
                             'Bad threshold on queue %d' % (j))

    def validate_root_basic(self, fw_state, reds, thrs):
        self.validate_root_fw_levels(fw_state, thrs)

        for (i, ifc, q) in reds:
            assert_equal('red', q['kind'], 'Wrong Qdisc type')
            assert_equal(True, q['root'], 'Root RED is root')
            assert_equal(True, q['offloaded'], 'Root RED offload active')
            assert_equal(True, q['options']['ecn'],
                         'Root RED ECN marking active')
            assert_equal(thrs, q['options']['min'], 'Wrong min threshold')
            assert_equal(thrs, q['options']['max'], 'Wrong max threshold')

###########################################################################
# Tests
###########################################################################

class BnicNames(BnicTest):
    def execute(self):
        out = ethtool_drvinfo(self.dut, self.group.vnics[0])
        if not out['firmware-version'].endswith('abm'):
            raise NtiError('Incorrect driver app name')
        if not out['firmware-version'].count(' abm-'):
            raise NtiError('Incorrect firmware name')

class BnicModes(BnicTest):
    def prepare(self):
        self.system_refresh()

    def execute(self):
        if self.switchdev_mode_ever_enabled():
            raise NtiSkip("switchdev previously enabled")

        for i in range(2):
            # Check we are starting in legacy mode
            self.validate_system()
            self.switchdev_mode_enable()
            self.validate_system()
            self.switchdev_mode_disable()

class BnicNetdevs(BnicTest):
    def execute(self):
        self.switchdev_mode_enable()

        # Check we can't bring up any non-vNIC netdev
        for ifc in self.group.pf_ports + self.group.mac_ports:
            ret, _ = self.dut.cmd('ip link set dev %s up' % (ifc), fail=False)
            if ret == 0:
                t = "mac" if ifc in self.group.mac_ports else "pf"
                raise NtiError('Brought %s netdev %s up' % (t, ifc))

        for ifc in self.group.pf_ports:
            info = self.dut.ip_link_show(ifc=ifc, details=True)
            name = info['phys_port_name']

            if len(self.group.vnics) > 1:
                assert_equal(True, bool(re.match('^pf\ds\d$', name)),
                             'Name matches pattern PF split: ' + ifc)
            else:
                assert_equal(True, bool(re.match('^pf\d$', name)),
                             'Name matches pattern PF: ' + ifc)

        for ifc in self.group.vnics:
            info = self.dut.ip_link_show(ifc=ifc, details=True)
            name = info['phys_port_name']

            assert_equal(True, bool(re.match('^n\d$', name)),
                         'Name matches pattern vNIC: ' + ifc)

class BnicTcOffload(BnicTest):
    def find_mqs(self):
        _, qdiscs = self.qdisc_show()
        mqs = {}
        for ifc in self.group.pf_ports:
            for q in qdiscs[ifc]:
                if q['kind'] == 'mq':
                    mqs[ifc] = q
                    break
        return mqs

    def set_offload(self, ifc, state):
        # Check the test doesn't have a bug
        assert_neq(state, self.hw_tc[ifc], 'Already in desired state')

        ret, _ = self.dut.cmd('ethtool -K %s hw-tc-offload %s' %
                              (ifc, "on" if state else "off"), fail=False)
        assert_equal(not state and self.active[ifc], bool(ret),
                     "Error during setting the TC offload flag")
        if ret == 0:
            self.hw_tc[ifc] = state
        return ret == 0

    def validate_flag_disable_all(self):
        for ifc in self.group.pf_ports:
            if self.set_offload(ifc, False):
                self.set_offload(ifc, True)

    def validate_reds_offloaded(self):
        _, qdiscs = self.qdisc_show()
        for ifc in self.group.pf_ports:
            found = False
            for q in qdiscs[ifc]:
                if q['kind'] != 'red':
                    continue
                assert_equal(True, 'offloaded' in q, "Qdisc is offloaded")
                found = True
            assert_equal(True, found, "Found a RED Qdisc")

    def validate_no_qdisc_offloaded(self):
        _, qdiscs = self.qdisc_show()
        for ifc in self.group.pf_ports:
            for q in qdiscs[ifc]:
                assert_equal(False, 'offloaded' in q, "Qdisc is offloaded")

    def execute(self):
        self.switchdev_mode_enable()

        # Check the flag is on by default
        for ifc in self.group.pf_ports:
            _, out = self.dut.cmd('ethtool -k ' + ifc)
            assert_equal(1, out.count('hw-tc-offload: on'),
                         '"hw-tc-offload: on" count on ' + ifc)

        for ifc in self.group.vnics:
            _, out = self.dut.cmd('ethtool -k ' + ifc)
            assert_equal(1, out.count('hw-tc-offload: off [fixed]'),
                         '"hw-tc-offload: off" count on vNIC ' + ifc)

        # Remember that all are enabled now
        self.hw_tc = {}
        self.active = {}
        for ifc in self.group.pf_ports:
            self.hw_tc[ifc] = True
            self.active[ifc] = False

        # Check if we can disable without any config
        self.validate_flag_disable_all()

        # Install root RED and check disable
        for ifc in self.group.pf_ports:
            self.qdisc_replace(ifc, kind="red", thrs=1)
            self.active[ifc] = True
            self.validate_flag_disable_all()

        self.validate_reds_offloaded()

        # Delete Qdiscs and check again
        for ifc in self.group.pf_ports:
            self.qdisc_delete(ifc, parent="root", kind="red")
            self.active[ifc] = False
            self.validate_flag_disable_all()

        # MQ with no Qdiscs...
        for ifc in self.group.pf_ports:
            self.qdisc_replace(ifc, parent="root", kind="mq")
            self.active[ifc] = True
            self.validate_flag_disable_all()

        # Remove the MQ with no Qdiscs...
        for ifc in self.group.pf_ports:
            self.qdisc_delete(ifc, parent="root", kind="mq")
            self.active[ifc] = False
            self.validate_flag_disable_all()

        # And add MQ with the RED child Qdiscs
        for ifc in self.group.pf_ports:
            self.qdisc_replace(ifc, parent="root", kind="mq")
            self.active[ifc] = True
            self.validate_flag_disable_all()

        mqs = self.find_mqs()

        for ifc in self.group.pf_ports:
            self.qdisc_replace(ifc, parent=mqs[ifc]['handle'] + "1",
                               kind="red", thrs=1)
            self.validate_flag_disable_all()

        self.validate_reds_offloaded()

        # Remove the childen
        for ifc in self.group.pf_ports:
            self.qdisc_delete(ifc, parent=mqs[ifc]['handle'] + "1", kind="red")
            self.validate_flag_disable_all()

        # Remove the MQ
        for ifc in self.group.pf_ports:
            self.qdisc_delete(ifc, parent="root", kind="mq")
            self.active[ifc] = False
            self.validate_flag_disable_all()

        # Check offload doesn't happen with flag not set
        for ifc in self.group.pf_ports:
            self.set_offload(ifc, False)

        # Root RED
        for ifc in self.group.pf_ports:
            self.qdisc_replace(ifc, kind="red", thrs=1)

        self.validate_no_qdisc_offloaded()

        # MQ RED
        for ifc in self.group.pf_ports:
            self.qdisc_replace(ifc, parent="root", kind="mq")

        mqs = self.find_mqs()

        # Disabled and install MQ and RED
        for ifc in self.group.pf_ports:
            self.qdisc_replace(ifc, parent=mqs[ifc]['handle'] + "1",
                               kind="red", thrs=1)
        self.validate_no_qdisc_offloaded()

        # Now try to re-add the RED Qdiscs with enabled, but MQ was installed
        # without it
        for ifc in self.group.pf_ports:
            self.qdisc_delete(ifc, parent=mqs[ifc]['handle'] + "1", kind="red")
        for ifc in self.group.pf_ports:
            self.set_offload(ifc, True)
        for ifc in self.group.pf_ports:
            self.qdisc_replace(ifc, parent=mqs[ifc]['handle'] + "1",
                               kind="red", thrs=1)

        self.validate_no_qdisc_offloaded()

        # Re-install the MQ, and REDs should offload again
        for ifc in self.group.pf_ports:
            self.qdisc_delete(ifc, parent="root", kind="mq")
            self.qdisc_replace(ifc, parent="root", kind="mq")

        mqs = self.find_mqs()
        for ifc in self.group.pf_ports:
            self.qdisc_replace(ifc, parent=mqs[ifc]['handle'] + "1",
                               kind="red", thrs=1)
        self.validate_reds_offloaded()

    def cleanup(self):
        self.switchdev_mode_disable()

class BnicSbConfig(BnicTest):
    def test_vnic_up(self, pools, up_list):
        self.vnics_all_down()
        self.vnics_set(up_list, "up")

        for p in pools:
            ret, _ = self.devlink_sb_pool_set(p["sb"], p["pool"], p["size"],
                                              fail=False)
            if ret == 0:
                raise NtiError("Pool configuration succeeded with vNICs up")

        self.validate_system()

    def prepare(self):
        self.switchdev_mode_enable()
        self.system_refresh()

    def execute(self):
        # Constants
        total = self.dut.fwcaps["cred_total"]

        # Get the current working config
        _, sbs = self.dut.devlink_sb_list()
        _, pools = self.dut.devlink_sb_pool_list()

        self.validate_system()

        # Check bad configs
        LOG_sec("Check config with links up")
        try:
            for vnic in self.group.vnics:
                self.test_vnic_up(pools, [vnic])
            self.test_vnic_up(pools, self.group.vnics)
        finally:
            LOG_endsec()

        self.vnics_all_down()

        LOG_sec("Check config of bad pools and SBs")
        try:
            p = pools[0]
            for sb in [0, 1, 11, 10000]:
                ret, _ = self.devlink_sb_pool_set(sb, p["pool"], 0, fail=False)
                if ret == 0:
                    raise NtiError("Pool configuration succeeded with bad SB")

            for pool in [2, 2048, 11, 10000]:
                ret, _ = self.devlink_sb_pool_set(p["sb"], pool, 0, fail=False)
                if ret == 0:
                    raise NtiError("Pool configuration succeeded with bad pool")
        finally:
            LOG_endsec()

        LOG_sec("Check config to oversized pools")
        try:
            for p in pools:
                ret, _ = self.devlink_sb_pool_set(p["sb"], p["pool"],
                                                  total[p["sb"]] * p["sb"] * 2,
                                                  fail=False)
                if ret == 0:
                    raise NtiError("Pool configuration set oversized")
        finally:
            LOG_endsec()

        LOG_sec("Check config to dynamic thrs")
        try:
            ret, _ = self.devlink_sb_pool_set(p["sb"], p["pool"], p["size"],
                                              thtype="dynamic", fail=False)
            if ret == 0:
                raise NtiError("Pool configuration succeeded with dynamic thrs")
        finally:
            LOG_endsec()

        self.validate_system()

        # Config to 0 - good
        LOG_sec("Check config to zero")
        try:
            for p in pools:
                # Pool 1 can't be 0, so set it to 1 credit
                self.devlink_sb_pool_set(p["sb"], p["pool"],
                                         p["pool"] * p["sb"])
                self.validate_system()
        finally:
            LOG_endsec()

        # Check oversized configs again
        LOG_sec("Check config to oversized pools")
        try:
            for p in pools:
                ret, _ = self.devlink_sb_pool_set(p["sb"], p["pool"],
                                                  total[p["sb"]] * p["sb"] * 2,
                                                  fail=False)
                if ret == 0:
                    raise NtiError("Pool configuration set oversized")
        finally:
            LOG_endsec()

        LOG_sec("Check config to unaligned size")
        try:
            for p in pools:
                ret, _ = self.devlink_sb_pool_set(p["sb"], p["pool"],
                                                  total[p["sb"]] * p["sb"] - 1,
                                                  fail=False)
                if ret == 0:
                    raise NtiError("Pool configuration set oversized")
        finally:
            LOG_endsec()

        self.validate_system()

        # Rest of good configs
        LOG_sec("Check config to fourth/1")
        try:
            for p in pools:
                if p["pool"] == 0:
                    size = (total[p["sb"]] / 4) * p["sb"]
                else:
                    size = p["sb"]
                self.devlink_sb_pool_set(p["sb"], p["pool"], size)
                self.validate_system()
        finally:
            LOG_endsec()

        LOG_sec("Check config to half/half")
        try:
            for p in pools:
                size = (total[p["sb"]] / 2) * p["sb"]
                self.devlink_sb_pool_set(p["sb"], p["pool"], size)
                self.validate_system()
        finally:
            LOG_endsec()

class BnicQlvl(BnicTest):
    MARKED	= ['overlimits', 'marked']
    PASS	= ['bytes', 'packets']
    BLOG	= ['backlog', 'qlen']
    OTHER	= ['drops', 'requeues', 'early', 'pdrop', 'other']

    ALL		= MARKED + PASS + BLOG + OTHER
    BASIC	= ['bytes', 'packets', 'drops', 'overlimits', 'requeues',
                   'backlog', 'qlen']

    def _check_root_stats_const(self, reds, stats, val):
        for (i, ifc, q) in reds:
            for s in stats:
                assert_equal(val, q[s], 'Statistic %s mismatch' % (s))

    def _check_pass_stats(self, fw_state, reds, ip_stat, in_stats):
        stats = [0, 0]
        for i in range(0, len(in_stats), 2):
            stats[0] += in_stats[i + 0]
            stats[1] += in_stats[i + 0] * in_stats[i + 1]

        LOG_sec('Check pass stats')
        try:
            for (i, ifc, q) in reds:
                vnic = self.group.vnics[i]
                old = self._ip_stat[vnic]['stats64']['rx']
                new = ip_stat[vnic]['stats64']['rx']

                LOG("%s:%d" % (ifc, i))
                self.log('qdisc:', self.group.pp.pformat(q))
                self.log('old stat:', old)
                self.log('new stat:', new)

                assert_ge(stats[0], q['packets'], 'Packet count')
                assert_lt(stats[0] + 10, q['packets'], 'Packet count')
                assert_ge(stats[1], q['bytes'], 'Byte count')
                assert_lt(stats[1] + 2000, q['bytes'], 'Byte count')

                assert_equal(new['packets'] - old['packets'], q['packets'],
                             'Packet count against ifstat')
                assert_equal(new['bytes'] - old['bytes'], q['bytes'],
                             'Byte count against ifstat')
        finally:
            LOG_endsec()

    def _check_root_stats_no_sto(self, fw_state, reds, ip_stat, stats):
        self._check_root_stats_const(reds, BnicQlvl.MARKED + BnicQlvl.BLOG +
                                     BnicQlvl.OTHER, 0)
        self._check_pass_stats(fw_state, reds, ip_stat, stats)

    def _check_root_stats_mark(self, fw_state, reds, ip_stat, stats):
        self._check_root_stats_const(reds, BnicQlvl.BLOG + BnicQlvl.OTHER, 0)
        self._check_root_stats_const(reds, BnicQlvl.MARKED, stats[2])
        self._check_pass_stats(fw_state, reds, ip_stat, stats)

    def check_root(self, thrs, stats=None):
        fw_state = self.read_fw_state()
        _, qdiscs = self.qdisc_show()
        reds = []
        for ifc in self.group.pf_ports:
            assert_equal(1, len(qdiscs[ifc]), 'Wrong number of qdiscs on port')
            reds.append((self.group.pf_ports.index(ifc), ifc, qdiscs[ifc][0]))

        if thrs is not None:
            self.validate_root_basic(fw_state, reds, thrs)

        if stats is None:
            self._check_root_stats_const(reds, BnicQlvl.PASS + BnicQlvl.MARKED +
                                         BnicQlvl.BLOG + BnicQlvl.OTHER, 0)
            self._fw_state0 = fw_state
        elif len(stats) == 0:
            self._check_root_stats_const(reds, BnicQlvl.PASS + BnicQlvl.MARKED +
                                         BnicQlvl.OTHER, 0)
        elif len(stats) == 1:
            self._check_root_stats_const(reds,
                                         BnicQlvl.MARKED + BnicQlvl.OTHER, 0)
        elif len(stats) == 2:
            _, ip_stat = self.ip_show()
            self._check_root_stats_no_sto(fw_state, reds, ip_stat, stats)
        elif len(stats) == 4:
            _, ip_stat = self.ip_show()
            self._check_root_stats_mark(fw_state, reds, ip_stat, stats)

    def check_thrs_match(self):
        fw_state = self.read_fw_state()
        _, qdiscs = self.qdisc_show()
        thrs = [ABM_LVL_NOT_SET] * self.group.n_ports

        for i in range(self.group.n_ports):
            ifc = self.group.pf_ports[i]
            if ifc in qdiscs and qdiscs[ifc][0]['kind'] == 'red':
                assert_equal(1, len(qdiscs[ifc]),
                             'Wrong number of qdiscs on port')
                if 'offloaded' in qdiscs[ifc][0]:
                    thrs[i] = qdiscs[ifc][0]['options']['min']

        for i in range(self.group.n_ports):
            for j in self.all_qs(i):
                assert_equal(thrs[i], fw_state['qlvl'][self.group.pf_id][j],
                             'Bad threshold on queue %d' % (j))

    def execute(self):
        self.switchdev_mode_enable()

        # Make sure we can run those configs with vNICs up
        self.vnics_all_up()

        for t in (1, 15000, 30000, 700000, 1 << 24):
            self.set_root_red_all(t)
            self.check_root(t, stats=[0])

        # Remove all qdiscs (test disable)
        for ifc in self.group.pf_ports:
            self.qdisc_delete(ifc, parent="root", kind="red")
            self.check_thrs_match()

        # Test stats with taking vNICs down, this avoids counter errors
        self.vnics_all_down()

        # Make sure all stats are starting as 0
        for t in (1, 15000, 30000, 700000, 1 << 24):
            self.set_root_red_all(t)
            self.check_root(t, stats=None)

        # We're left at high marking now from last loop try the counters of pass
        _, self._ip_stat = self.ip_show()

        self.vnics_all_up()
        for i in range(self.group.n_ports):
            self.ping(port=i, size=1300)
        self.vnics_all_down()

        exp_stats = (10, 1334)
        self.check_root(t, stats=exp_stats)

        t = 1
        self.set_root_red_all(1)
        self.vnics_all_up()
        for i in range(self.group.n_ports):
            # Use TCP here, traffic "noise" is usually non-TCP
            self.tcpping(port=i, size=1300, tos=2)
        self.vnics_all_down()

        exp_stats = (10, 1334, 10, 1334)
        self.check_root(t, stats=exp_stats)

        # Make sure stats keep across replace
        self.set_root_red_all(1)
        self.check_root(1, stats=exp_stats)

        # Make sure stats keep across replace to non-offloaded
        self.set_root_red_all(1, ecn=False)
        self.check_root(None, stats=exp_stats)

        # Make sure stats don't keep across a MQ replace
        for i in range(self.group.n_ports):
            self.qdisc_replace(self.group.pf_ports[i], kind='mq')
            self.check_thrs_match()
        self.set_root_red_all(1)
        self.check_root(1, stats=None)

    def cleanup(self):
        for ifc in self.group.pf_ports:
            self.qdisc_delete(ifc, parent="root", fail=False)

class BnicMarkPing(BnicQlvl):
    def execute(self):
        self.switchdev_mode_enable()

        # Set threshold to the bare minimum while vNICs down
        self.set_root_red_all(1)
        _, qdiscs = self.qdisc_show()
        self.vnics_all_up()

        _, qdiscs = self.qdisc_show()

        # Send ping without QoS marking, should just pass
        for i in range(self.group.n_ports):
            self.ping(port=i, count=10)
            self.ping6(port=i, count=10)

        _, qdiscs = self.qdisc_show()
        for ifc in self.group.pf_ports:
            q = qdiscs[ifc][0]
            for s in BnicQlvl.MARKED:
                assert_equal(0, q[s], 'Statistic %s mismatch' % (s))
                assert_equal(0, q[s], 'Statistic %s mismatch' % (s))

        # Send ping (any non-TCP packet would do)
        for i in range(self.group.n_ports):
            self.ping(port=i, count=10, tos=2)
            self.ping6(port=i, count=10, tos=2)

        _, qdiscs = self.qdisc_show()
        for ifc in self.group.pf_ports:
            q = qdiscs[ifc][0]
            for s in BnicQlvl.MARKED:
                assert_ge(20, q[s], 'Statistic %s mismatch' % (s))
                assert_lt(30, q[s], 'Statistic %s mismatch' % (s))

class BnicRedNonRoot(BnicTest):
    def red_on_red(self, offload_base, offload_top):
        # Set RED on top of RED
        self.set_root_red_all(1 << 16, ecn=offload_base)

        # Validate
        fw_state, qdiscs, reds = self.get_state_simple_root_red()
        handles = {}
        for ifc in self.group.pf_ports:
            assert_equal(offload_base, 'offloaded' in qdiscs[ifc][0],
                         'Base offloaded')
            # ... and remember handles
            handles[ifc] = qdiscs[ifc][0]['handle']

        if offload_base:
            self.validate_root_basic(fw_state, reds, 1 << 16)
        else:
            self.validate_root_fw_levels(fw_state, ABM_LVL_NOT_SET)

        # Now replace backing qdiscs with RED, thrs 15000
        for ifc in self.group.pf_ports:
            self.qdisc_replace(ifc, parent=handles[ifc] + "1",
                               kind="red", thrs=15000, ecn=offload_top)

        # Validate again
        fw_state = self.read_fw_state()
        _, qdiscs = self.qdisc_show()
        reds = []
        for ifc in self.group.pf_ports:
            qds = qdiscs[ifc]
            assert_equal(2, len(qds), "Number of qdiscs")

            first = qdiscs[ifc][0]['handle'] == handles[ifc]
            old = qds[not first]
            new = qds[first]

            # Stash the old one for shared check below
            reds.append((self.group.pf_ports.index(ifc), ifc, old))
            assert_equal(offload_base, 'offloaded' in old, 'Base offloaded')
            # Validate others by hand
            assert_equal(False, 'offloaded' in new, "New offloaded")

        if offload_base:
            self.validate_root_basic(fw_state, reds, 1 << 16)
        else:
            self.validate_root_fw_levels(fw_state, ABM_LVL_NOT_SET)

    def execute(self):
        self.switchdev_mode_enable()

        self.red_on_red(False, False)
        self.red_on_red(False, True)
        self.red_on_red(True, False)
        self.red_on_red(True, True)

    def cleanup(self):
        for ifc in self.group.pf_ports:
            self.qdisc_delete(ifc, parent="root", fail=False)
        self.switchdev_mode_disable()

class BnicRedRaw(BnicQlvl):
    def force_counters(self, q, s):
        backlog_bytes, backlog_pkts, thru, sto, drop, mark = s

        lvls = '_abi_nfd_out_q_lvls_%u' % (self.group.pf_id)
        qmstat = '_abi_nfdqm%u_stats' % (self.group.pf_id)

        LOG_sec('Force counters on Q%d %r' % (q, s))
        try:
            self.dut.cmd_rtsym('%s:%u %u' % (lvls, 16 * q + 0, backlog_bytes))
            self.dut.cmd_rtsym('%s:%u %u' % (lvls, 16 * q + 4, backlog_pkts))

            self.dut.cmd_rtsym('%s:%u %u' % (qmstat, 32 * q +  0, thru))
            self.dut.cmd_rtsym('%s:%u %u' % (qmstat, 32 * q +  8, sto))
            self.dut.cmd_rtsym('%s:%u %u' % (qmstat, 32 * q + 16, drop))
            self.dut.cmd_rtsym('%s:%u %u' % (qmstat, 32 * q + 24, mark))
        finally:
            LOG_endsec()

    def check_forced_stats_one(self, ifc, s):
        qds = [["backlog"], ["qlen"], None, None,
               ["drops", "pdrop"], BnicQlvl.MARKED]

        _, qdiscs = self.qdisc_show()
        assert_equal(1, len(qdiscs[ifc]), "Qdisc count")
        qdisc = qdiscs[ifc][0]

        if 'offloaded' not in qdisc:
            s = (0, 0, s[2], s[3], s[4], s[5])

        for i in range(len(qds)):
            if qds[i] is None:
                continue
            for name in qds[i]:
                assert_equal(s[i], qdisc[name], "Statistic %s wrong" % (name))

        ethtool = ethtool_stats(self.dut, ifc)
        assert_equal(s[2], ethtool["q0_no_wait"], "q0_no_wait wrong")
        assert_equal(s[3], ethtool["q0_delayed"], "q0_delayed wrong")

    def check_forced_stats(self):
        for i in range(len(self._applied)):
            if self._applied[i] is None:
                continue
            self.check_forced_stats_one(self.group.pf_ports[i],
                                        self._applied[i])

    def prepare(self):
        if self.group.upstream_drv:
            return NrtResult(name=self.name, testtype=self.__class__.__name__,
                             passed=None, comment='RT-sym test on upstream')

    def execute(self):
        self.switchdev_mode_enable()

        # All vNICs down, we will break FW state...
        self.vnics_all_down()
        time.sleep(0.5)

        for i in range(len(self.dut.vnics)):
            self.force_counters(self.dut.vnics[i]['base_q'], (0, 0, 0, 0, 0, 0))

        self.set_root_red_all(1)
        self.check_root(1, stats=None)

        sets = (
            (0, 0, 0, 0, 0, 0),
            (0, 0, 0, 0, 0, 0),
            (1, 1, 1, 1, 1, 1),
            (2, 2, 2, 2, 2, 2),
            (7, 7, 7, 7, 7, 7),
            (10, 11, 12, 13, 14, 15),
            (70, 70, 70, 70, 70, 70),
            (70, 70, 70, 70, 70, 70),
            (70, 70, 70, 70, 70, 70),
            (70, 70, 70, 70, 70, 70),
            (0, 0, 70, 70, 70, 70),
        )
        nv = len(self.dut.vnics)
        self._applied = [None] * nv
        for i in range(len(sets)):
            self.force_counters(self.dut.vnics[i % nv]['base_q'], sets[i])
            self._applied[i % nv] = sets[i]
            self.check_forced_stats()

        # Check stats keep across a reset (check will ignore blog on non-offload
        self.set_root_red_all(1, ecn=False)
        self.check_forced_stats()

        for ifc in self.group.pf_ports:
            self.qdisc_delete(ifc, parent="root", kind="red")

        # Reset - beware blog will be set so check all 0 and the blog
        self.set_root_red_all(1)
        self.check_root(1, stats=())
        for i in range(self.group.n_ports):
            ifc = self.group.pf_ports[i]
            _, qdiscs = self.qdisc_show()
            assert_equal(1, len(qdiscs[ifc]), "Qdisc count")
            qdisc = qdiscs[ifc][0]

            assert_equal(self._applied[i][0], qdisc["backlog"], "backlog")
            assert_equal(self._applied[i][1], qdisc["qlen"], "qlen")

    def cleanup(self):
        BnicQlvl.cleanup(self)
        for i in range(len(self.dut.vnics)):
            self.force_counters(self.dut.vnics[i]['base_q'], (0, 0, 0, 0, 0, 0))

class BnicPerQState:
    def __init__(self, test):
        self.test = test
        self.dut = test.dut
        self.group = test.group

        LOG_sec('Read BnicPerQState')
        try:
            self._refresh_state()
        finally:
            LOG_endsec()

    def __getitem__(self, key):
        return self._dict[key]

    def _refresh_state(self):
        self._dict = {}
        self._dict['ets'] = {}
        self._dict['pkts'] = {}
        self._dict['bytes'] = {}
        for i in range(self.group.n_ports):
            ets = ethtool_stats(self.dut, self.group.pf_ports[i])
            rxq_regs = self.dut.nfd_reg_read_le32(self.group.vnics[i],
                                                  0x1400, MAX_QUEUES * 4)
            rxq_pkts = []
            rxq_bytes = []
            for j in range(len(rxq_regs) / 4):
                b = j * 4
                rxq_pkts.append(rxq_regs[b] | (rxq_regs[b + 1] << 32))
                b += 2
                rxq_bytes.append(rxq_regs[b] | (rxq_regs[b + 1] << 32))

            self._dict['ets'][self.group.pf_ports[i]] = ets
            self._dict['pkts'][self.group.pf_ports[i]] = rxq_pkts
            self._dict['bytes'][self.group.pf_ports[i]] = rxq_bytes

    def stat_diff(self, base, kind, ifc, stat):
        return self[kind][ifc][stat] - base[kind][ifc][stat]

    def _validate(self, base, exp_marked):
        _, qdiscs = self.test.qdisc_show()

        for ifc in self.group.pf_ports:
            # Zero out the accumulated stats for MQ checks
            acc = {}
            for s in BnicQlvl.ALL:
                acc[s] = 0

            marked = 0
            mq = None
            for q in qdiscs[ifc]:
                # Save MQ for tests once we have all accumulated stats
                if q['kind'] == 'mq':
                    mq = q
                    continue

                # Accumulate MQ
                for s in BnicQlvl.ALL:
                    acc[s] += q[s]
                # Check blog/drops/other
                for s in BnicQlvl.BLOG + BnicQlvl.OTHER:
                    assert_equal(0, q[s], 'Statistic %s mismatch' % (s))
                # Check or accumulate marked
                if exp_marked == 0:
                    for s in BnicQlvl.MARKED:
                        assert_equal(0, q[s], 'Statistic %s mismatch' % (s))
                else:
                    marked += q['marked']
                # Check pass pkts/bytes
                nqid = self.test.qdisc_to_nqid(q)
                assert_equal(self.stat_diff(base, 'pkts', ifc, nqid),
                             q['packets'], 'Packet count %s:%d' % (ifc, nqid))
                assert_equal(self.stat_diff(base, 'bytes', ifc, nqid),
                             q['bytes'], 'Byte count %s:%d' % (ifc, nqid))

                # Check ethtool only if stat is there
                if 'q%u_no_wait' % nqid not in self['ets'][ifc]:
                    continue
                sto = self.stat_diff(base, 'ets', ifc, 'q%u_no_wait' % nqid) + \
                      self.stat_diff(base, 'ets', ifc, 'q%u_delayed' % nqid)
                assert_equal(q['packets'], sto,
                             'ethtool stats %s:%d' % (ifc, nqid))

            if mq is not None:
                for s in BnicQlvl.BASIC:
                    assert_equal(acc[s], mq[s], "MQ stats: " + s)

            assert_equal(exp_marked, marked, "Number of marked packets")

    def validate(self, base, exp_marked=0):
        LOG_sec('Validate, exp_marked %d' % (exp_marked))
        try:
            self._validate(base, exp_marked)
        finally:
            LOG_endsec()

class BnicRedMq(BnicTest):
    def _reset_qcfg(self):
        self.qcfg = {}
        for i in range(self.group.n_ports):
            ifc = self.group.pf_ports[i]
            self.qcfg[ifc] = [ABM_LVL_NOT_SET] * self.dut.vnics[i]['total_qs']

        _, qdiscs = self.qdisc_show()
        self.mqs = {}
        self.nqs = {}

        for ifc in self.group.pf_ports:
            for q in qdiscs[ifc]:
                if q['kind'] == 'mq':
                    self.mqs[ifc] = q['handle']

            cmd = 'ls /sys/class/net/%s/queues/ | grep tx | wc -l' % ifc
            _, out = self.dut.cmd(cmd)
            self.nqs[ifc] = int(out)

    def validate_qcfg(self):
        fw_state = self.read_fw_state()
        _, qdiscs = self.qdisc_show()

        # Check offload is reported
        for ifc in self.group.pf_ports:
            if ifc not in qdiscs:
                for i in range(len(self.qcfg[ifc])):
                    assert_equal(ABM_LVL_NOT_SET, self.qcfg[ifc][i],
                                 'Lvl without root')
                continue

            for q in qdiscs[ifc]:
                if q['kind'] == 'mq':
                    continue

                nqid = self.qdisc_to_nqid(q)
                assert_equal(self.qcfg[ifc][nqid] != ABM_LVL_NOT_SET,
                             'offloaded' in q, "Child Qdisc offloaded")
                if q['kind'] != 'red':
                    assert_equal(ABM_LVL_NOT_SET, self.qcfg[ifc][nqid],
                                 "Lvl not set on non-RED child Qdisc")

        for i in range(self.group.n_ports):
            ifc = self.group.pf_ports[i]

            # Check threshold
            for j in self.all_qs(i):
                nqid = j - self.dut.vnics[i]['base_q']

                assert_equal(self.qcfg[ifc][nqid],
                             fw_state['qlvl'][self.group.pf_id][j],
                             'Bad threshold on queue %d (%s:%d)' %
                             (j, ifc, nqid))

    def del_root_mq(self):
        for ifc in self.group.pf_ports:
            self.qdisc_delete(ifc, parent="root", kind="mq")
            for qid in range(self.nqs[ifc]):
                self.qcfg[ifc][qid] = ABM_LVL_NOT_SET

    def set_root_mq(self):
        for ifc in self.group.pf_ports:
            self.qdisc_replace(ifc, parent="root", kind="mq")

        fw_state = self.read_fw_state()
        self.validate_root_fw_levels(fw_state, ABM_LVL_NOT_SET)

        # Init test's MQ state
        self._reset_qcfg()
        self.validate_qcfg()

    def del_red_one(self, ifc, qid):
        self.qcfg[ifc][qid] = ABM_LVL_NOT_SET
        self.qdisc_delete(ifc, parent=self.mqs[ifc] + "%x" % (qid + 1),
                          kind="red")

    def _set_thrs(self, ifc, qid, thrs, ecn):
        if ecn:
            self.qcfg[ifc][qid] = thrs
        else:
            self.qcfg[ifc][qid] = ABM_LVL_NOT_SET

    def set_red_one(self, ifc, qid, thrs, ecn=True):
        self._set_thrs(ifc, qid, thrs, ecn)
        self.qdisc_replace(ifc, parent=self.mqs[ifc] + "%x" % (qid + 1),
                           kind="red", thrs=thrs, ecn=ecn)

    def set_red_all(self, thrs, ecn=True):
        cmd = ''
        for ifc in self.group.pf_ports:
            for qid in range(self.nqs[ifc]):
                self._set_thrs(ifc, qid, thrs, ecn)
                parent = self.mqs[ifc] + "%x" % (qid + 1)
                cmd += self.qdisc_replace(ifc, parent=parent, kind="red",
                                          thrs=thrs, ecn=ecn, _bulk=True)
                cmd += ' && '
        cmd += 'true'
        self.dut.cmd(cmd)

    def execute(self):
        self.switchdev_mode_enable()
        self.vnics_all_down()

        LOG_sec('TEST Basic MQ+full RED setup')
        try:
            # Set root to RED thrs 1
            self.set_root_red_all(1)

            fw_state, qdiscs, reds = self.get_state_simple_root_red()
            self.validate_root_basic(fw_state, reds, 1)

            # Set MQ
            self.set_root_mq()
        finally:
            LOG_endsec()

        LOG_sec('TEST Replace children with different thresholds')
        try:
            # Set all queues to 2
            self.set_red_all(2)
            self.validate_qcfg()

            # Set root to RED thrs 3
            self.set_root_red_all(3)

            fw_state, qdiscs, reds = self.get_state_simple_root_red()
            self.validate_root_basic(fw_state, reds, 3)

            # Set MQ
            self.set_root_mq()

            # Set all queues to 4
            self.set_red_all(4)
            self.validate_qcfg()
        finally:
            LOG_endsec()

        LOG_sec('TEST Set root to RED, no offload')
        try:
            # Set root to RED thrs 4, non-offload
            self.set_root_red_all(4, ecn=False)
            fw_state = self.read_fw_state()
            self.validate_root_fw_levels(fw_state, ABM_LVL_NOT_SET)
        finally:
            LOG_endsec()

        # Set at random until all queues have a RED
        rpl = []
        for ifc in self.group.pf_ports:
            rpl += [(ifc, x) for x in range(self.nqs[ifc])]
        random.shuffle(rpl)

        LOG_sec('TEST Set at random until all queues have a RED')
        try:
            # Set MQ
            self.set_root_mq()

            for r in rpl:
                self.set_red_one(r[0], r[1], random.randint(1, 1 << 24))
                self.validate_qcfg()
        finally:
            LOG_endsec()

        # Do a number of completely random operations
        LOG_sec('TEST Do a number of completely random operations')
        try:
            for i in range(16):
                r = random.randint(1, 3)
                ifc, q = rpl[random.randint(0, len(rpl) - 1)]
                if r == 1:
                    self.del_red_one(ifc, q)
                elif r == 2:
                    self.set_red_one(ifc, q, random.randint(1, 1 << 24))
                elif r == 3:
                    self.set_red_one(ifc, q, 7, ecn=False)
                self.validate_qcfg()
        finally:
            LOG_endsec()

        LOG_sec('TEST Basic traffic tests')
        try:
            # Set all queues to 1
            self.set_red_all(1)
            self.validate_qcfg()

            # Spray with traffic
            base_stat = BnicPerQState(self)
            exp_marked = 0

            self.vnics_all_up()
            for i in range(self.group.n_ports):
                # "faster" will most likely mean we'll get no responses
                self.tcpping(port=i, count=2000, keep=False, speed="faster",
                             fail=False)
            self.vnics_all_down()

            stat = BnicPerQState(self)
            stat.validate(base_stat, exp_marked)
        finally:
            LOG_endsec()

        LOG_sec('TEST Marked traffic test')
        try:
            # Spray with traffic (marked)
            self.vnics_all_up()
            for i in range(self.group.n_ports):
                # "faster" will most likely mean we'll get no responses
                self.tcpping(port=i, count=2000, keep=False, speed="faster",
                             tos=2, fail=False)
            exp_marked += 2000
            self.vnics_all_down()

            stat = BnicPerQState(self)
            stat.validate(base_stat, exp_marked)
        finally:
            LOG_endsec()

        LOG_sec('TEST Replace with non-offload')
        try:
            # Set all queues to 5, non-offload
            self.set_red_all(5, ecn=False)
            self.validate_qcfg()
            # No traffic passed, all stats should be maintained on replace
            stat.validate(base_stat, exp_marked)
        finally:
            LOG_endsec()

        LOG_sec('TEST Re-add')
        try:
            # Re-add the MQ and make sure stats get counted from 0
            stat_removed = BnicPerQState(self)

            self.del_root_mq()
            self.validate_qcfg()
            self.set_root_mq()
            self.set_red_all(5)
            self.validate_qcfg()

            stat_removed.validate(stat, 0)
        finally:
            LOG_endsec()

    def cleanup(self):
        for ifc in self.group.pf_ports:
            self.qdisc_delete(ifc, parent="root", fail=False)
        self.switchdev_mode_disable()

class BnicPFstate:
    STATS = ['bblog', 'pblog', 'thru', 'sto', 'drop', 'mark']

    def __init__(self, test):
        self.test = test
        self.group = test.group
        self.dut = test.dut

        self._dict = {}

        # Save the list of queues for later
        self._dict['qs'] = {}
        for i in range(len(self.dut.vnics)):
            self._dict['qs'][i] = self.test.all_qs(i)
            self._dict['qs'][self.group.vnics[i]] = self._dict['qs'][i]
            self._dict['qs'][self.group.pf_ports[i]] = self._dict['qs'][i]
        # Init all stats to 0
        self._dict['bblog'] = [0] * MAX_QUEUES
        self._dict['pblog'] = [0] * MAX_QUEUES
        self._dict['thru'] = [0] * MAX_QUEUES
        self._dict['sto'] = [0] * MAX_QUEUES
        self._dict['drop'] = [0] * MAX_QUEUES
        self._dict['mark'] = [0] * MAX_QUEUES

        # Remember the total number of queues per vNIC
        self._dict['nqs'] = {}
        for ifc in self.group.pf_ports:
            cmd = 'ls /sys/class/net/%s/queues/ | grep tx | wc -l' % ifc
            _, out = self.dut.cmd(cmd)
            self._dict['nqs'][ifc] = int(out)

        # Remember the number of active queues
        self._dict['aqs'] = {}
        for i in range(self.group.n_ports):
            _, out = self.dut.cmd('ethtool -l %s | tail -6' %
                                  (self.group.vnics[i]))
            rx = int(re.search('RX:[ \t]*(\d*)\n', out).groups()[0])
            comb = int(re.search('Combined:[ \t]*(\d*)\n', out).groups()[0])
            self._dict['aqs'][self.group.pf_ports[i]] = rx + comb

    def clone(self):
        newone = copy.copy(self)
        newone._dict = copy.deepcopy(self._dict)
        return newone

    def __len__(self):
        return len(self._dict.keys())

    def __getitem__(self, key):
        return self._dict[key]

    def __setitem__(self, key, value):
        assert_equal(True, key in self._dict.keys(),
                     "PFstate key does not exist: " + key)
        self._dict[key] = value

    def _force_apply_queue(self, qid):
        lvls = '_abi_nfd_out_q_lvls_%u' % (self.group.pf_id)
        qmstat = '_abi_nfdqm%u_stats' % (self.group.pf_id)

        self.dut.cmd_rtsym('%s:%u %u %u' %
                           (lvls, 16 * qid + 0,
                            self['bblog'][qid], self['pblog'][qid]))

        vals = ''
        for i in (self['thru'][qid], self['sto'][qid],
                  self['drop'][qid], self['mark'][qid]):
            vals += ' %u %u' % (i & 0xFFFFFFFF, i >> 32)

        self.dut.cmd_rtsym('%s:%u%s' % (qmstat, 32 * qid +  0, vals))

    def force_apply_ifc(self, ifc):
        LOG_sec('Force counters on ' + ifc)
        try:
            for qid in self['qs'][ifc]:
                self._force_apply_queue(qid)
        finally:
            LOG_endsec()

    def force_apply_all(self):
        LOG_sec('Force counters on all')
        try:
            for qid in range(MAX_QUEUES):
                self._force_apply_queue(qid)
        finally:
            LOG_endsec()

class BnicRedMqRaw(BnicTest):
    def init_all_0(self):
        self.state = BnicPFstate(self)
        self.base = self.state.clone()
        self.init = self.state.clone()

    def set_mq_config_children(self, ecn=True):
        cmd = ''
        for ifc in self.group.pf_ports:
            for qid in range(self.state['nqs'][ifc]):
                parent = self.mqs[ifc] + "%x" % (qid + 1)
                cmd += self.qdisc_replace(ifc, parent=parent, kind="red",
                                          thrs=1, ecn=ecn, _bulk=True)
                cmd += ' && '
        cmd += 'true'
        self.dut.cmd(cmd)
        # Remember whether we want offload or not
        self.offloaded = ecn

    def set_mq_config(self):
        for ifc in self.group.pf_ports:
            self.qdisc_replace(ifc, parent="root", kind="mq")

        self.mqs = {}
        _, qdiscs = self.qdisc_show()
        for ifc in self.group.pf_ports:
            for q in qdiscs[ifc]:
                if q['kind'] == 'mq':
                    self.mqs[ifc] = q['handle']

        self.set_mq_config_children()

    def qdiscs_to_handle_list(self, qdiscs, ifc):
        res = [{}] * self.state['nqs'][ifc]
        for q in qdiscs[ifc]:
            if q['dev'] != ifc:
                continue
            if q['kind'] == 'mq':
                continue

            assert_equal('red', q['kind'], "Child Qdisc kind")
            assert_equal(self.offloaded,
                         'offloaded' in q, "Child Qdisc offloaded")

            qid = int('0x' + q['parent'].split(':')[1], 16) - 1
            res[qid] = q

        return res

    def validate(self):
        qds = {
            'drop' : ["drops", "pdrop"],
            'mark' : BnicQlvl.MARKED,
        }
        zeroes = ['early', 'other']

        _, qdiscs = self.qdisc_show()
        for ifc in self.group.pf_ports:
            # Extract the ifc stats
            qlist = self.qdiscs_to_handle_list(qdiscs, ifc)
            ets = ethtool_stats(self.dut, ifc)

            for nqid in range(self.state['nqs'][ifc]):
                qid = self.nqid_to_qid(ifc, nqid)
                assert_equal(self.state['bblog'][qid], qlist[nqid]['backlog'],
                             'Statistic %s vs %s on queue %u (%s:%u)' %
                             ('bblog', 'backlog', qid, ifc, nqid))
                assert_equal(self.state['pblog'][qid], qlist[nqid]['qlen'],
                             'Statistic %s vs %s on queue %u (%s:%u)' %
                             ('pblog', 'qlen', qid, ifc, nqid))

                for qd in qds.keys():
                    for stat in qds[qd]:
                        assert_equal(self.state[qd][qid] - self.base[qd][qid],
                                     qlist[nqid][stat],
                                     'Statistic %s on queue %u (%s:%u)' %
                                     (stat, qid, ifc, nqid))
                for stat in zeroes:
                    assert_equal(0, qlist[nqid][stat],
                                 'Statistic %s on queue %u (%s:%u)' %
                                 (stat, qid, ifc, nqid))

                # Only check ethtool stats on active queues
                if nqid >= self.state['aqs'][ifc]:
                    continue

                # Ethtool stats
                assert_equal(self.state['thru'][qid], ets['q%u_no_wait' % nqid],
                             "Ethtool statistic thru on queue %u (%s:%u)" %
                             (qid, ifc, nqid))
                assert_equal(self.state['sto'][qid], ets['q%u_delayed' % nqid],
                             "Ethtool statistic sto on queue %u (%s:%u)" %
                             (qid, ifc, nqid))

            # Zero out the accumulated stats for MQ checks
            acc = {}
            for s in BnicQlvl.ALL:
                acc[s] = 0
            # Find the MQ and accumulate
            mq = None
            for q in qdiscs[ifc]:
                if q['kind'] == 'mq':
                    mq = q
                    continue

                for s in BnicQlvl.ALL:
                    acc[s] += q[s]
            # Validate
            for s in BnicQlvl.BASIC:
                assert_equal(acc[s], mq[s], "MQ stats: " + s)


    def prepare(self):
        if self.group.upstream_drv:
            return NrtResult(name=self.name, testtype=self.__class__.__name__,
                             passed=None, comment='RT-sym test on upstream')

    def execute(self):
        self.switchdev_mode_enable()

        # All vNICs down, we will break FW state...
        self.vnics_all_down()
        time.sleep(0.5)

        # Reset all state
        self.init_all_0()
        self.state.force_apply_all()

        self.set_mq_config()
        self.validate()

        # Set all queue stats to different values
        for ifc in self.group.pf_ports:
            for nqid in range(self.state['nqs'][ifc]):
                qid = self.nqid_to_qid(ifc, nqid)
                for stat in BnicPFstate.STATS:
                    self.state[stat][qid] += random.randint(1, 1024)
            self.state.force_apply_all()
            self.validate()

        # Set blog to 0
        for ifc in self.group.pf_ports:
            for nqid in range(self.state['nqs'][ifc]):
                qid = self.nqid_to_qid(ifc, nqid)
                for stat in ('bblog', 'pblog'):
                    self.state[stat][qid] = 0
            self.state.force_apply_all()
            self.validate()

        # Set blog to random values
        for ifc in self.group.pf_ports:
            for nqid in range(self.state['nqs'][ifc]):
                qid = self.nqid_to_qid(ifc, nqid)
                for stat in ('bblog', 'pblog'):
                    self.state[stat][qid] = random.randint(1, 1024)
            self.state.force_apply_all()
            self.validate()

        # Replace with non-offload
        self.set_mq_config_children(ecn=False)

        # After replace with non-offload blog should go back to 0
        for ifc in self.group.pf_ports:
            for nqid in range(self.state['nqs'][ifc]):
                qid = self.nqid_to_qid(ifc, nqid)
                for stat in ('bblog', 'pblog'):
                    # Save the blog in base
                    self.base[stat][qid] = self.state[stat][qid]
                    self.state[stat][qid] = 0
        self.validate()

        # Re-add with offload
        for ifc in self.group.pf_ports:
            self.qdisc_delete(ifc, parent="root", kind="mq")
        # Restore blog and save the values as base
        for ifc in self.group.pf_ports:
            for nqid in range(self.state['nqs'][ifc]):
                qid = self.nqid_to_qid(ifc, nqid)
                for stat in ('bblog', 'pblog'):
                    self.state[stat][qid] = self.base[stat][qid]
        self.base = self.state.clone()
        # Now add and check all stats but blog are 0
        self.set_mq_config()
        self.validate()

        # Bump all stats by different values
        for ifc in self.group.pf_ports:
            for nqid in range(self.state['nqs'][ifc]):
                qid = self.nqid_to_qid(ifc, nqid)
                for stat in BnicPFstate.STATS:
                    self.state[stat][qid] += random.randint(1, 1024)
            self.state.force_apply_all()
            self.validate()

        # Set RED root
        for ifc in self.group.pf_ports:
            self.qdisc_replace(ifc, parent='root', kind='red', thrs=2, ecn=True)

        # Confirm all RED stats are 0 (blog set)
        _, qdiscs = self.qdisc_show()
        for ifc in self.group.pf_ports:
            assert_equal(1, len(qdiscs[ifc]), 'Wrong number of qdiscs on port')
            for stat in BnicQlvl.MARKED + BnicQlvl.PASS + BnicQlvl.OTHER:
                assert_equal(0, qdiscs[ifc][0][stat], "Qdisc stat: " + stat)

            bblog = 0
            pblog = 0
            for nqid in range(self.state['nqs'][ifc]):
                qid = self.nqid_to_qid(ifc, nqid)
                bblog += self.state['bblog'][qid]
                pblog += self.state['pblog'][qid]
            assert_equal(bblog, qdiscs[ifc][0]['backlog'], "Qdisc stat: blog")
            assert_equal(pblog, qdiscs[ifc][0]['qlen'], "Qdisc stat: qlen")

    def cleanup(self):
        self.state = self.init
        self.state.force_apply_all()
        self.switchdev_mode_disable()

class BnicReload(BnicTest):
    def execute(self):
        # Unload while enabled
        self.switchdev_mode_enable()

        self.log('started all ok', '')

        for i in range(self.group.n_ports):
            self.qdisc_replace(self.group.pf_ports[i], kind="red", thrs=15000)

        # Reload
        self.dut.reset_mods()
        self.dut.switchdev_on = False
        self.group.refresh_nfp_netdevs(self.dut._netifs)
        drv_load_record_ifcs(self, self.group)

        # Config, disable, unload
        self.switchdev_mode_enable()

        for i in range(self.group.n_ports):
            self.qdisc_replace(self.group.pf_ports[i], kind="red", thrs=15000)

        self.switchdev_mode_disable()
        self.dut.reset_mods()
