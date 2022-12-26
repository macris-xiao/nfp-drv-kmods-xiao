#
# Copyright (C) 2017,  Netronome Systems, Inc.  All rights reserved.
#
"""
ABM NIC test group for the NFP Linux drivers.
"""
import copy
import json
import math
import re
import os, pprint
from struct import unpack_from
import time

from netro.testinfra import LOG_sec, LOG, LOG_endsec
from netro.testinfra.nti_exceptions import NtiError
from netro.testinfra.test import *

from ..common_test import *
from ..drv_grp import NFPKmodAppGrp
from ..drv_fwdump import *
from ..nfd import NfdBarOff

###########################################################################
# Helpers
###########################################################################

def get_le32(arr, idx):
    return struct.unpack("<I", arr[idx * 4 : (idx + 1) * 4])[0]

def qdisc_str(q):
    return "ifc: '%s' k:'%s' p:'%s' h:'%s'" % \
        (q["dev"],
         q["kind"],
         q["parent"] if "parent" in q else "--",
         q["handle"])

def qdisc_offloaded(q, offloaded):
    assert_eq(offloaded, 'offloaded' in q and q['offloaded'],
              "Qdisc %s offloaded" % (qdisc_str(q)))

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
            "num_prio"		: 1,
            "num_bands"		: 1,
            "act_mask"		: 1 << ACT_MARK_DROP,
        }
        value = some_test.read_sym_nffw("_abi_nfd_total_bufs", fail=True)
        if len(value) != 8:
            raise NtiError("Symbol '_abi_nfd_total_bufs' is not 8B")

        self.dut.fwcaps["cred_total"][2048] = get_le32(value, 0)
        self.dut.fwcaps["cred_total"][10240] = get_le32(value, 1)

        value = some_test.read_sym_nffw("_abi_pci_dscp_num_prio_0", fail=False)
        if value is not None:
            assert_eq(8, len(value), "num_prio sym len")
            self.dut.fwcaps["num_prio"] = get_le32(value, 0)

        value = some_test.read_sym_nffw("_abi_pci_dscp_num_band_0", fail=False)
        if value is not None:
            assert_eq(8, len(value), "num_bands sym len")
            self.dut.fwcaps["num_bands"] = get_le32(value, 0)

        value = some_test.read_sym_nffw("_abi_nfd_out_q_actions_0", fail=False)
        if value is not None:
            assert_eq(8, len(value), "act_mask sym len")
            self.dut.fwcaps["act_mask"] = get_le32(value, 0)

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

            st_q = M.nfd_reg_read_le32(ifn, NfdBarOff.START_RXQ)
            n_qs = M.nfd_reg_read_le32(ifn, NfdBarOff.MAX_RXRINGS)

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
            ("red_mark_non_tcp", BnicMarkPing,
             'Marking of non-TCP packets (ICMP)'),
            ("red_topo_bad", BnicRedNonRoot,
             "RED doesn't offload on top of other Qdiscs"),
            ("red_mq", BnicRedMq, 'RED on top of MQ'),
            ("red_mq_raw", BnicRedMqRaw,
             'RED on top of MQ, force stats with mem writes from user space'),
            ("gred_mq", BnicGRed, 'Offloaded GRED on top of MQ'),
            ("gred_mq_bad", BnicGRedBad, 'Non-offloaded GRED on top of MQ'),
            ("gred_mq_raw", BnicGRedRaw,
             'GRED on top of MQ, force stats with mem writes from user space'),
            ("eg_u32", BnicU32eg, "Manipulating u32 filters vs qdisc offload"),
            ("cls_u32", BnicU32, "Manipulating u32 filters"),
            ("act", BnicAct, "Drop vs mark action"),
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

ACT_MARK_DROP = 0
ACT_DROP = 2

ABM_LVL_NOT_SET = ((1 << 31) - 1)

class BnicTest(CommonTest):
    def unpack_creds(self, data):
        vals = unpack_from('< I I', data)
        return {
            2 * 1024		: vals[0],
            10 * 1024		: vals[1],
        }

    def _empty_config_dict(self):
        fw_state = dict()
        fw_state["qlvl"] = [[] for i in range(NUM_PCI_PFS)]
        fw_state["qact"] = [[] for i in range(NUM_PCI_PFS)]
        fw_state["qlen"] = [[] for i in range(NUM_PCI_PFS)]
        fw_state["qblog"] = [[] for i in range(NUM_PCI_PFS)]
        fw_state["qmstat"] = \
            [[() for j in range(MAX_QUEUES)] for i in range(NUM_PCI_PFS)]

        return fw_state

    def _read_fw_state(self, rtsym_tlvs):
        fw_state = self._empty_config_dict()
        fw_state["qmstate"] = [False] * NUM_PCI_PFS
        fw_state["cred_excl"] = [{} for i in range(NUM_PCI_PFS)]
        fw_state["nfd_excl"] = [{} for i in range(NUM_PCI_PFS)]
        fw_state["mbox_state"] = [() for i in range(NUM_PCI_PFS)]
        fw_state["priomap"] = [[] for i in range(NUM_PCI_PFS)]

        band_range = range(self.dut.fwcaps["num_bands"])

        fw_state["prio"] = [
            self._empty_config_dict() for i in band_range
        ]

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
                idx = int(r.sym_name[20])

                per_q = 16

                if r.sym_name.count('per_band'):
                    tgts = fw_state["prio"]
                else:
                    tgts = (fw_state,)

                if len(r.reg_data) / per_q / len(tgts) != MAX_QUEUES:
                    raise NtiError("Qlvl stat symbol bad len, have len %d" %
                                   (len(r.reg_data) / per_q))

                for t in range(len(tgts)):
                    for i in range(MAX_QUEUES):
                        start = (t * MAX_QUEUES + i) * per_q
                        end = (t * MAX_QUEUES + i + 1) * per_q

                        vals = unpack_from('< I I I I', r.reg_data[start:end])

                        tgts[t]["qblog"][idx].append(vals[0])
                        tgts[t]["qlen"][idx].append(vals[1])
                        tgts[t]["qlvl"][idx].append(vals[2])
                        tgts[t]["qact"][idx].append(vals[3])
            elif r.sym_name.count('_abi_nfdqm') and r.sym_name.count('stats'):
                idx = int(r.sym_name[10])

                per_q = NUM_QM_STATS * 8
                qs = len(r.reg_data) / per_q

                if r.sym_name.count('per_band'):
                    tgts = fw_state["prio"]
                else:
                    tgts = (fw_state,)

                if qs / len(tgts) != MAX_QUEUES:
                    raise NtiError("QM stat symbol '%s' bad len, queues: %d / %d != %d" %
                                   (r.sym_name, qs, len(tgts), MAX_QUEUES))

                for t in range(len(tgts)):
                    for i in range(MAX_QUEUES):
                        start = (t * MAX_QUEUES + i) * per_q
                        end = (t * MAX_QUEUES + i + 1) * per_q
                        tgts[t]["qmstat"][idx][i] = \
                            unpack_from('< ' + 'Q ' * NUM_QM_STATS,
                                        r.reg_data[start:end])

            elif r.sym_name.count('_abi_nfd_pf0_mbox'):
                idx = int(r.sym_name[-6])
                fw_state["mbox_state"][idx] = unpack_from('< I I I I I I I I',
                                                          r.reg_data)

            elif r.sym_name.count('_abi_dscp_prio2band'):
                # Symbol is 2 D array with # PCIe rows
                per_pf = len(r.reg_data) / NUM_PCI_PFS
                for i in range(NUM_PCI_PFS):
                    fw_state["priomap"][i] = \
                        unpack_from('>' + ' I' * (per_pf / 4),
                                    r.reg_data[i * per_pf:(i + 1) * per_pf])

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
        if eswitchmode == "switchdev":
            self.dut.cmd("udevadm settle")
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

    def encode_prio(self, p):
        bits = int(math.log(self.dut.fwcaps["num_prio"] - 1, 2)) + 1
        return p << (8 - bits)

    def u32_add(self, ifc, proto="ip", side="egress", prio=None,
                v=None, mask=None, flags="skip_sw", band=None, fail=True,
                _bulk=False):
        # Defaults
        if mask is None:
            bits = int(math.log(self.dut.fwcaps["num_prio"] - 1, 2)) + 1
            mask = ((1 << bits) - 1) << (8 - bits)

        # Build command
        cmd = 'tc filter add dev %s %s' % (ifc, side)
        if prio is not None:
            cmd += ' prio %d' % (prio)
        if proto is not None:
            cmd += ' protocol %s' % (proto)
        cmd += ' u32 match'
        if proto == "ipv6":
            cmd += ' ip6 priority'
        elif proto == "ip":
            cmd += ' ip tos'
        if v is not None:
            cmd += ' 0x%x' % (v)
        if mask is not None:
            cmd += ' 0x%x' % (mask)
        if flags is not None:
            cmd += ' %s' % (flags)
        if band is not None:
            cmd += ' flowid :%d' % (band)

        if _bulk:
            return cmd
        return self.dut.cmd(cmd, fail=fail)

    def u32_remove(self, ifc, proto="ip", side="egress", prio=None, fail=True):
        cmd = 'tc filter delete dev %s %s' % (ifc, side)
        if prio is not None:
            cmd += ' prio %d' % (prio)
        if proto is not None:
            cmd += ' protocol %s' % (proto)
        cmd += ' u32'
        return self.dut.cmd(cmd, fail=fail)

    def qdisc_delete(self, ifc, parent=None, kind=None, fail=False):
        params = ""
        if ifc:
            params += " dev " + ifc
        if parent:
            params += " parent " + parent
        if kind:
            params += " " + kind
        return self.dut.cmd("tc qdisc delete" + params, fail=fail)

    def qdisc_replace(self, ifc, parent="root", handle=None, kind="mq", thrs=0,
                      ecn=True, harddrop=False, bands=None, default=None,
                      vq=None, grio=False, _bulk=False):
        param = ""
        if parent is not None:
            param += "parent " + parent
        if handle is not None:
            param += " handle %s:" % handle

        if kind == "red":
            param += " red min {thrs} max {thrs} avpkt {thrs} burst 1 "\
                    "limit 400000 bandwidth 10Mbit {ecn} {harddrop}"\
                    .format(thrs=thrs, ecn=("ecn" * ecn),
                            harddrop=("harddrop" * harddrop))
        elif kind == "gred":
            param += " gred"
            if bands is not None:
                param += " setup vqs %d" % (bands)
                if default is not None:
                    param += " default %d" % (default)
                if harddrop:
                    param += " harddrop"
                if grio:
                    param += " grio"
            else:
                param += " vq %d" % (vq)
                param += " min {thrs} max {thrs} avpkt {thrs} burst 1 "\
                    .format(thrs=thrs)
                param += " limit 400000 bandwidth 10Mbit"
            if ecn:
                param += " ecn"
        else:
            param += " " + kind

        cmd = "tc qdisc replace dev %s %s" % (ifc, param)
        if _bulk:
            return cmd
        else:
            return self.dut.cmd(cmd)

    def build_gred(self, ifc, parent="root", handle=None, bands=4, default=0,
                   thrs=[0,0,0,0], ecn=True, parent_flags=True, _bulk=False):
        if handle is None:
            if _bulk:
                raise NtiError('No handle and _bulk in GRED build')
            _, qh = self.qdisc_by_handle(ifc)
            for h in range(4096, 0, -1):
                handle = hex(h)[2:]
                if handle not in qh[ifc]:
                    break

        cmd = ''
        cmd += self.qdisc_replace(ifc, parent=parent, handle=handle,
                                  kind="gred",
                                  bands=bands, default=default,
                                  ecn=(ecn and parent_flags),
                                  _bulk=True)
        cmd += ' && '
        for i in range(bands):
            cmd += self.qdisc_replace(ifc, parent=parent, handle=handle,
                                      kind="gred", vq=i, thrs=thrs[i],
                                      ecn=ecn, _bulk=True)
            cmd += ' && '
        cmd += 'true'
        if _bulk:
            return cmd
        else:
            return self.dut.cmd(cmd)

    def build_mq_gred(self, thrs=[1000, 2000, 3000, 4000], parent_flags=True):
        cmd = ''
        for i in range(self.group.n_ports):
            ifc = self.group.pf_ports[i]
            cmd += self.qdisc_replace(ifc, parent="root", handle="1000",
                                      kind="mq", _bulk=True)
            cmd += ' && '
            for qid in range(self.dut.vnics[i]['total_qs']):
                cmd += self.build_gred(ifc, parent="1000:%x" % (qid + 1),
                                       handle=hex(4095 - qid)[2:],
                                       bands=self.dut.fwcaps["num_bands"],
                                       default=0, thrs=thrs,
                                       parent_flags=parent_flags,
                                       _bulk=True)
                cmd += ' && '
        cmd += 'true'
        self.dut.cmd(cmd)

    def _qdisc_json_group_by_dev(self, out):
        res = dict()
        for q in out:
            dev = q['dev']
            if dev not in res:
                res[dev] = [q]
            else:
                res[dev].append(q)
        return res

    def _qdisc_json_group_by_dev_handle(self, out):
        res = dict()
        for q in out:
            dev = q['dev']
            if dev not in res:
                res[dev] = {}
            res[dev][q['handle']] = q
        return res

    def _qdisc_show(self, ifc=None):
        params = ""
        if ifc:
            params += " dev " + ifc
        ret, out = self.dut.cmd("tc -s -j qdisc show" + params)
        if ret == 0 and len(out.strip()) != 0:
            out = json.loads(out)
        else:
            out = dict()
        return ret, out

    def qdisc_show(self, ifc=None):
        ret, out = self._qdisc_show(ifc)
        out = self._qdisc_json_group_by_dev(out)
        return ret, out

    def qdisc_by_handle(self, ifc=None):
        ret, out = self._qdisc_show(ifc)
        out = self._qdisc_json_group_by_dev_handle(out)
        return ret, out

    def _ip_json_group_by_dev(self, out):
        out = json.loads(out)
        res = dict()
        for d in out:
            res[d['ifname']] = d
        return res

    def ip_show(self, ifc=None):
        params = ""
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

    def set_root_red_all(self, thrs, harddrop=False):
        for i in range(self.group.n_ports):
            self.qdisc_replace(self.group.pf_ports[i], kind='red', thrs=thrs,
                               harddrop=harddrop)

    def build_mq_red(self, thrs, ecn=True):
        cmd = ''
        for i in range(self.group.n_ports):
            ifc = self.group.pf_ports[i]
            cmd += self.qdisc_replace(ifc, parent="root", handle="1000",
                                      kind="mq", _bulk=True)
            cmd += ' && '
            for qid in range(self.dut.vnics[i]['total_qs']):
                cmd += self.qdisc_replace(ifc, parent="1000:%x" % (qid + 1),
                                          kind="red", thrs=thrs, ecn=ecn,
                                          _bulk=True)
                cmd += ' && '
        cmd += 'true'
        self.dut.cmd(cmd)

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
            assert_in(p["sb"], sbs, "Pool from unknown SB")

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
        out = self.dut.ethtool_drvinfo(self.group.vnics[0])
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
            ret, _ = self.dut.ip_link_set_up(ifc, fail=False)
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

        self.validate_no_qdisc_offloaded()

        # Delete Qdiscs and check again
        for ifc in self.group.pf_ports:
            self.qdisc_delete(ifc, parent="root")
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
            self.qdisc_delete(ifc, parent=mqs[ifc]['handle'] + "1")
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
            self.qdisc_delete(ifc, parent=mqs[ifc]['handle'] + "1")
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

    GRED_ALL	= ['prob_drop', 'forced_drop', 'prob_mark', 'forced_mark',
                   'pdrop', 'backlog', 'qave', 'packets', 'bytes']

class BnicMarkPing(BnicQlvl):
    def execute(self):
        self.switchdev_mode_enable()

        # Set threshold to the bare minimum while vNICs down, we want ARPs and
        # other tiny packets to get through but not the pings
        self.build_mq_red(128)
        _, qdiscs = self.qdisc_show()
        self.vnics_all_up()

        _, qdiscs = self.qdisc_show()

        # Send ping without QoS marking, should just pass
        for i in range(self.group.n_ports):
            self.ping(port=i, count=10, size=200, should_fail=True)
            self.ping6(port=i, count=10, size=200, should_fail=True)

        _, qdiscs = self.qdisc_show()
        for ifc in self.group.pf_ports:
            acc = {
                'packets'	: 0,
                'bytes'	: 0,
                'drops'	: 0,
                'pdrop'	: 0,
            }
            for q in qdiscs[ifc]:
                if q['kind'] != "red":
                    continue
                for s in BnicQlvl.MARKED:
                    assert_equal(0, q[s], 'Statistic %s mismatch' % (s))
                for s in acc.keys():
                    acc[s] += q[s]
            for s in ('drops', 'pdrop'):
                assert_ge(20, acc[s], 'Statistic %s mismatch' % (s))
            assert_lt(10, acc['packets'], 'Statistic packets mismatch')
            assert_lt(3000, acc['bytes'], 'Statistic bytes mismatch')

        # Send ping (any non-TCP packet would do)
        for i in range(self.group.n_ports):
            self.ping(port=i, count=10, size=200, tos=2)
            self.ping6(port=i, count=10, size=200, tos=2)

        _, qdiscs = self.qdisc_show()
        for ifc in self.group.pf_ports:
            accu = {}
            for s in BnicQlvl.MARKED:
                accu[s] = 0
            for q in qdiscs[ifc]:
                if q['kind'] != "red":
                    continue
                for s in BnicQlvl.MARKED:
                    accu[s] += q[s]
            for s in BnicQlvl.MARKED:
                assert_ge(20, accu[s], 'Statistic %s mismatch' % (s))
                assert_lt(30, accu[s], 'Statistic %s mismatch' % (s))

    def cleanup(self):
        for ifc in self.group.pf_ports:
            self.qdisc_delete(ifc, parent="root", fail=False)
        return super(BnicMarkPing, self).cleanup()

class BnicRedNonRoot(BnicTest):
    def red_simple_check(self, offload_base):
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

        return handles

    def red_on_red(self, offload_base, offload_top):
        # Set RED on top of RED
        self.set_root_red_all(1 << 16, harddrop=not offload_base)

        handles = self.red_simple_check(offload_base)

        # Now replace backing qdiscs with RED, thrs 15000
        for ifc in self.group.pf_ports:
            self.qdisc_replace(ifc, parent=handles[ifc] + "1",
                               kind="red", thrs=15000, ecn=offload_top)

        # Validate again, neither should offload
        fw_state = self.read_fw_state()
        _, qdiscs = self.qdisc_show()
        for ifc in self.group.pf_ports:
            qds = qdiscs[ifc]
            assert_equal(2, len(qds), "Number of qdiscs")

            assert_equal(False, 'offloaded' in qds[0], 'Qdisc 0 offloaded')
            assert_equal(False, 'offloaded' in qds[1], "Qdisc 1 offloaded")

        self.validate_root_fw_levels(fw_state, ABM_LVL_NOT_SET)

        # We can't easily replace with limit 0 because iproute2 won't let us,
        # only test replace with limit set
        for ifc in self.group.pf_ports:
            self.qdisc_replace(ifc, parent="root", kind="red", thrs=(1 << 16),
                               ecn=offload_base)

        self.red_simple_check(offload_base)

    def execute(self):
        self.switchdev_mode_enable()

        self.red_on_red(False, False)
        self.red_on_red(False, True)

        # Build a simple MQ + RED
        self.build_mq_red(1)

        # Now put a RED on first RED
        firsts = {}

        _, qdiscs = self.qdisc_show()
        for ifc in self.group.pf_ports:
            for q in qdiscs[ifc]:
                if 'parent' in q and q['parent'] == '1000:1':
                    firsts[ifc] = q['handle']
                    self.qdisc_replace(ifc, parent=q['handle'] + '1',
                                       kind="red", thrs=(1 << 16), ecn=True)
                    break

        # Check both first RED and its child get unoffloaded
        _, qdiscs = self.qdisc_show()
        for ifc in self.group.pf_ports:
            for q in qdiscs[ifc]:
                offload = q['kind'] == 'mq' or \
                          (q['kind'] == 'red' and q['parent'][:4] == "1000"
                           and q['parent'] != "1000:1")
                assert_eq(offload, 'offloaded' in q and q['offloaded'],
                          "Qdisc %s offloaded" % qdisc_str(q))

        # Now replace that RED on first with GRED
        for ifc in self.group.pf_ports:
            self.build_gred(ifc, parent=firsts[ifc] + "1", handle="999",
                            bands=4, default=0, thrs=[1, 2, 3, 4])

        # Check both first RED and GRED are not offloaded
        _, qdiscs = self.qdisc_show()
        for ifc in self.group.pf_ports:
            for q in qdiscs[ifc]:
                offload = q['kind'] == 'mq' or \
                          (q['kind'] == 'red' and q['parent'] != "1000:1")
                assert_eq(offload, 'offloaded' in q and q['offloaded'],
                          "Qdisc %s offloaded" % qdisc_str(q))

    def cleanup(self):
        for ifc in self.group.pf_ports:
            self.qdisc_delete(ifc, parent="root", fail=False)
        self.switchdev_mode_disable()

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
            ets = self.dut.ethtool_stats(self.group.pf_ports[i])
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

    def _validate(self, base, exp_marked, exp_dropped):
        _, qdiscs = self.test.qdisc_show()

        for ifc in self.group.pf_ports:
            # Zero out the accumulated stats for MQ checks
            acc = {}
            for s in BnicQlvl.ALL:
                acc[s] = 0

            dropped = 0
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
                    if s.count('drop'):
                        dropped += q[s]
                    else:
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
            assert_equal(exp_dropped, dropped, "Number of dropped packets")

    def validate(self, base, exp_marked=0, exp_dropped=0):
        LOG_sec('Validate, exp_marked %d exp_dropped %d' %
                (exp_marked, exp_dropped))
        try:
            self._validate(base, exp_marked, exp_dropped)
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
        self.qdisc_delete(ifc, parent=self.mqs[ifc] + "%x" % (qid + 1))

    def _set_thrs(self, ifc, qid, thrs, harddrop):
        if harddrop:
            self.qcfg[ifc][qid] = ABM_LVL_NOT_SET
        else:
            self.qcfg[ifc][qid] = thrs

    def set_red_one(self, ifc, qid, thrs, harddrop=False):
        self._set_thrs(ifc, qid, thrs, harddrop)
        self.qdisc_replace(ifc, parent=self.mqs[ifc] + "%x" % (qid + 1),
                           kind="red", thrs=thrs, harddrop=harddrop)

    def set_red_all(self, thrs=0, thrs_func=None, harddrop=False):
        cmd = ''
        for i in range(self.group.n_ports):
            ifc = self.group.pf_ports[i]
            for qid in range(self.nqs[ifc]):
                if thrs_func:
                    thrs = thrs_func(i + 1, qid)
                self._set_thrs(ifc, qid, thrs, harddrop)
                parent = self.mqs[ifc] + "%x" % (qid + 1)
                cmd += self.qdisc_replace(ifc, parent=parent, kind="red",
                                          thrs=thrs, harddrop=harddrop,
                                          _bulk=True)
                cmd += ' && '
        cmd += 'true'
        self.dut.cmd(cmd)

    def execute(self):
        self.switchdev_mode_enable()
        self.vnics_all_down()

        LOG_sec('TEST Basic MQ+full RED thresholds')
        try:
            # Set MQ
            self.set_root_mq()

            # Set all queues to 1
            self.set_red_all(1)
            self.validate_qcfg()

            # Set all queues to 2
            self.set_red_all(2)
            self.validate_qcfg()

            # Set all queues to variable
            self.set_red_all(thrs_func=(lambda x, y: x * 1000 + y))
            self.validate_qcfg()
        finally:
            LOG_endsec()

        LOG_sec('TEST Set root to RED, no offload')
        try:
            # Set root to RED thrs 4, non-offload
            self.set_root_red_all(4, harddrop=True)
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
                    self.set_red_one(ifc, q, 7, harddrop=True)
                self.validate_qcfg()
        finally:
            LOG_endsec()

        LOG_sec('TEST Basic traffic tests')
        try:
            # Set all queues to 1
            self.set_red_all(90)
            self.validate_qcfg()

            # Spray with traffic
            base_stat = BnicPerQState(self)
            exp_marked = 0
            exp_dropped = 4000

            self.vnics_all_up()
            for i in range(self.group.n_ports):
                # "faster" will most likely mean we'll get no responses
                self.tcpping(port=i, count=2000, keep=False, speed="faster",
                             fail=False)
            self.vnics_all_down()

            stat = BnicPerQState(self)
            stat.validate(base_stat, exp_marked, exp_dropped)
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
            stat.validate(base_stat, exp_marked, exp_dropped)
        finally:
            LOG_endsec()

        LOG_sec('TEST Replace with non-offload')
        try:
            # Set all queues to 5, non-offload
            self.set_red_all(5, harddrop=True)
            self.validate_qcfg()
            # No traffic passed, all stats should be maintained on replace
            stat.validate(base_stat, exp_marked, exp_dropped)
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

            stat_removed.validate(stat, 0, 0)
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

    def set_mq_config_children(self, harddrop=False):
        cmd = ''
        for ifc in self.group.pf_ports:
            for qid in range(self.state['nqs'][ifc]):
                parent = self.mqs[ifc] + "%x" % (qid + 1)
                cmd += self.qdisc_replace(ifc, parent=parent, kind="red",
                                          thrs=1, harddrop=harddrop, _bulk=True)
                cmd += ' && '
        cmd += 'true'
        self.dut.cmd(cmd)
        # Remember whether we want offload or not
        self.offloaded = not harddrop

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

            qid = self.qdisc_to_nqid(q)
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
            ets = self.dut.ethtool_stats(ifc)

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

        # Since per-band stats were added we have to wipe the ethtool counters
        LOG_sec("Wipe ethtool stats from other bands")
        try:
            for band in range(1, self.dut.fwcaps["num_bands"]):
                qmstat = '_abi_nfdqm%u_stats_per_band' % (self.group.pf_id)
                base = band * NfdBarOff.MAX_RXRINGS

                for qid in range(NfdBarOff.MAX_RXRINGS):
                    self.dut.cmd_rtsym('%s:%u 0 0 0 0' %
                                       (qmstat, (base + qid) * 32))
        finally:
            LOG_endsec()

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
        self.set_mq_config_children(harddrop=True)

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
            self.qdisc_delete(ifc, parent="root")
        self.build_mq_red(thrs=2)

        # Confirm all RED stats are 0 (blog set)
        _, qdiscs = self.qdisc_show()
        for ifc in self.group.pf_ports:
            for q in qdiscs[ifc]:
                for stat in BnicQlvl.MARKED + BnicQlvl.PASS + BnicQlvl.OTHER:
                    if stat not in BnicQlvl.BASIC and q['kind'] == "mq":
                        continue
                    assert_eq(0, q[stat], "Qdisc %s stat: %s" %
                              (qdisc_str(q), stat))

                if q['kind'] == "mq":
                    continue

                nqid = self.qdisc_to_nqid(q)
                qid = self.nqid_to_qid(ifc, nqid)

                assert_equal(self.state['bblog'][qid],
                             q['backlog'], "Qdisc %s stat: blog" % qdisc_str(q))
                assert_equal(self.state['pblog'][qid],
                             q['qlen'], "Qdisc %s stat: qlen" % qdisc_str(q))

    def cleanup(self):
        if not hasattr(self, 'init'):
            return
        self.state = self.init
        self.state.force_apply_all()
        self.switchdev_mode_disable()

class BnicReload(BnicTest):
    def build_mq_red_gred_mix(self):
        cmd = ''
        for i in range(self.group.n_ports):
            ifc = self.group.pf_ports[i]
            cmd += self.qdisc_replace(ifc, parent="root", handle="1000",
                                      kind="mq", _bulk=True)
            cmd += ' && '
            for qid in range(2):
                cmd += self.qdisc_replace(ifc, parent="1000:%x" % (qid + 1),
                                          kind="red", thrs=1111 * (qid + 1),
                                          _bulk=True)
                cmd += ' && '
            for qid in range(2, 4):
                cmd += self.build_gred(ifc, parent="1000:%x" % (qid + 1),
                                       handle=hex(2000 + qid)[2:],
                                       bands=4, default=0,
                                       thrs=[1000, 2000, 3000, 4000],
                                       _bulk=True)
                cmd += ' && '
        cmd += 'true'
        self.dut.cmd(cmd)

    def execute(self):
        # Unload while enabled
        self.switchdev_mode_enable()

        self.build_mq_red_gred_mix()

        # Reload
        self.dut.reset_mods()
        self.dut.switchdev_on = False
        self.group.refresh_nfp_netdevs(self.dut._netifs)
        drv_load_record_ifcs(self.group, self.group)

        # Config, disable, unload
        self.switchdev_mode_enable()

        self.build_mq_red_gred_mix()

        self.switchdev_mode_disable()
        self.dut.reset_mods()

###########################################################################
# GRED tests
###########################################################################
class BnicGRedBad(BnicTest):
    def check_offload(self, pred):
        _, qdiscs = self.qdisc_show()
        for i in range(self.group.n_ports):
            ifc = self.group.pf_ports[i]
            assert_eq(self.dut.vnics[i]['total_qs'] + 1, len(qdiscs[ifc]),
                      "Num Qdiscs")
            for q in qdiscs[ifc]:
                qdisc_offloaded(q, pred(q))

    def fix_main(self, bands):
        cmd = ''
        for i in range(self.group.n_ports):
            ifc = self.group.pf_ports[i]
            for qid in range(self.dut.vnics[i]['total_qs']):
                cmd += self.qdisc_replace(ifc, parent="1000:%x" % (qid + 1),
                                          handle=hex(4095 - qid)[2:],
                                          kind="gred", bands=bands,
                                          default=0, _bulk=True)
                cmd += ' && '
        cmd += 'true'
        self.dut.cmd(cmd)

    def execute(self):
        self.switchdev_mode_enable()

        bands = self.dut.fwcaps["num_bands"]

        # Install MQ and base GRED on all ports
        cmd = ''
        for i in range(self.group.n_ports):
            ifc = self.group.pf_ports[i]
            # MQ
            cmd += self.qdisc_replace(ifc, parent="root", handle="1000",
                                      kind="mq", _bulk=True)
            cmd += ' && '
            # GREDs
            for qid in range(self.dut.vnics[i]['total_qs']):
                cmd += self.qdisc_replace(ifc, parent="1000:%x" % (qid + 1),
                                          handle=hex(4095 - qid)[2:],
                                          kind="gred", bands=bands, default=0,
                                          _bulk=True)
                cmd += ' && '
        cmd += 'true'
        self.dut.cmd(cmd)

        # Check only MQ is offloaded now
        self.check_offload((lambda q: q['kind'] == "mq"))

        # Set up bands
        cmd = ''
        for i in range(self.group.n_ports):
            ifc = self.group.pf_ports[i]
            # GREDs
            for qid in range(self.dut.vnics[i]['total_qs']):
                for i in range(bands):
                    cmd += self.qdisc_replace(ifc, parent="1000:%x" % (qid + 1),
                                              handle=hex(4095 - qid)[2:],
                                              kind="gred", vq=i,
                                              thrs=(qid + 1) * 10000 + i * 100,
                                              _bulk=True)
                    cmd += ' && '
        cmd += 'true'
        self.dut.cmd(cmd)

        # Check all are offloaded now
        self.check_offload((lambda q: True))

        # Resize the bands
        cmd = ''
        for i in range(self.group.n_ports):
            ifc = self.group.pf_ports[i]
            for qid in range(self.dut.vnics[i]['total_qs']):
                cmd += self.qdisc_replace(ifc, parent="1000:%x" % (qid + 1),
                                          handle=hex(4095 - qid)[2:],
                                          kind="gred", bands=(bands + 1),
                                          default=0, _bulk=True)
                cmd += ' && '
        cmd += 'true'
        self.dut.cmd(cmd)

        self.check_offload((lambda q: q['kind'] == "mq"))
        self.fix_main(bands)
        self.check_offload((lambda q: True))

        # Change the default
        cmd = ''
        for i in range(self.group.n_ports):
            ifc = self.group.pf_ports[i]
            for qid in range(self.dut.vnics[i]['total_qs']):
                cmd += self.qdisc_replace(ifc, parent="1000:%x" % (qid + 1),
                                          handle=hex(4095 - qid)[2:],
                                          kind="gred", bands=bands,
                                          default=1, _bulk=True)
                cmd += ' && '
        cmd += 'true'
        self.dut.cmd(cmd)

        self.check_offload((lambda q: q['kind'] == "mq"))
        self.fix_main(bands)
        self.check_offload((lambda q: True))

        # Disable ECN
        cmd = ''
        for i in range(self.group.n_ports):
            ifc = self.group.pf_ports[i]
            for qid in range(self.dut.vnics[i]['total_qs']):
                cmd += self.qdisc_replace(ifc, parent="1000:%x" % (qid + 1),
                                          handle=hex(4095 - qid)[2:],
                                          kind="gred", bands=bands,
                                          default=0, ecn=False, _bulk=True)
                cmd += ' && '
        cmd += 'true'
        self.dut.cmd(cmd)

        self.check_offload(lambda q:
                           q['kind'] == "mq" or
                           bool(self.dut.fwcaps["act_mask"] & (1 << ACT_DROP)))
        self.fix_main(bands)
        self.check_offload((lambda q: True))

        # Enable harddrop
        cmd = ''
        for i in range(self.group.n_ports):
            ifc = self.group.pf_ports[i]
            for qid in range(self.dut.vnics[i]['total_qs']):
                cmd += self.qdisc_replace(ifc, parent="1000:%x" % (qid + 1),
                                          handle=hex(4095 - qid)[2:],
                                          kind="gred", bands=bands,
                                          default=0, harddrop=True, _bulk=True)
                cmd += ' && '
        cmd += 'true'
        self.dut.cmd(cmd)

        self.check_offload((lambda q: q['kind'] == "mq"))
        self.fix_main(bands)
        self.check_offload((lambda q: True))

        # GRIO
        cmd = ''
        for i in range(self.group.n_ports):
            ifc = self.group.pf_ports[i]
            for qid in range(self.dut.vnics[i]['total_qs']):
                cmd += self.qdisc_replace(ifc, parent="1000:%x" % (qid + 1),
                                          handle=hex(4095 - qid)[2:],
                                          kind="gred", bands=bands,
                                          default=0, grio=True, _bulk=True)
                cmd += ' && '
        cmd += 'true'
        self.dut.cmd(cmd)

        self.check_offload((lambda q: q['kind'] == "mq"))
        self.fix_main(bands)
        self.check_offload((lambda q: True))

        # Enable harddrop only on one
        for ifc in self.group.pf_ports:
            qid = 0
            self.qdisc_replace(ifc, parent="1000:%x" % (qid + 1),
                               handle=hex(4095 - qid)[2:],
                               kind="gred", bands=bands, default=0,
                               harddrop=True)

        self.check_offload((lambda q: q['handle'] != hex(4095)[2:] + ':'))

        for ifc in self.group.pf_ports:
            qid = 0
            self.qdisc_replace(ifc, parent="1000:%x" % (qid + 1),
                               handle=hex(4095 - qid)[2:],
                               kind="gred", bands=bands, default=0, ecn=True)

        self.check_offload((lambda q: True))

        # Now onto breaking the virtual queues
        cmd = ''
        for i in range(self.group.n_ports):
            ifc = self.group.pf_ports[i]
            # GREDs
            for qid in range(self.dut.vnics[i]['total_qs']):
                cmd += "tc qdisc replace dev {ifc} "\
                    "parent {parent} handle {handle}: gred vq {vq} "\
                    "min {thrs} max 10000 avpkt 5000 burst 1 "\
                    "limit 400000 bandwidth 10Mbit ecn"\
                    .format(ifc=ifc, parent="1000:%x" % (qid + 1),
                            handle=hex(4095 - qid)[2:], vq=0, thrs=5000)
                cmd += ' && '
        cmd += 'true'
        self.dut.cmd(cmd)

        self.check_offload((lambda q: q['kind'] == "mq"))

    def cleanup(self):
        self.switchdev_mode_disable()
        return super(BnicGRedBad, self).cleanup()

class BnicGRed(BnicTest):
    def check_offload(self, pred):
        _, qdiscs = self.qdisc_show()
        for i in range(self.group.n_ports):
            ifc = self.group.pf_ports[i]
            assert_eq(self.dut.vnics[i]['total_qs'] + 1, len(qdiscs[ifc]),
                      "Num Qdiscs")
            for q in qdiscs[ifc]:
                qdisc_offloaded(q, pred(q))

    def execute(self):
        self.switchdev_mode_enable()

        self.build_mq_gred(thrs=[1, 2, 3, 4])

        # Check tresholds get set correctly
        fw_state = self.read_fw_state()

        for i in range(self.group.n_ports):
            for q in self.all_qs(i):
                for b in range(self.dut.fwcaps["num_bands"]):
                    assert_eq(b + 1,
                              fw_state["prio"][b]['qlvl'][self.group.pf_id][q],
                              "Threshold on band %d queue %d" % (b, q))

        # Change marking on GRED 0 and last
        cmd = ''
        for i in range(self.group.n_ports):
            ifc = self.group.pf_ports[i]
            for qid in (0, self.dut.vnics[i]['total_qs'] - 1):
                cmd += self.build_gred(ifc, parent="1000:%x" % (qid + 1),
                                       handle=hex(4095 - qid)[2:],
                                       bands=self.dut.fwcaps["num_bands"],
                                       default=0, thrs=[qid + 4, qid + 5,
                                                        qid + 6, qid + 7],
                                       _bulk=True)
                cmd += ' && '
        cmd += 'true'
        self.dut.cmd(cmd)

        # Check tresholds get set correctly
        fw_state = self.read_fw_state()

        for i in range(self.group.n_ports):
            for q in self.all_qs(i):
                for b in range(self.dut.fwcaps["num_bands"]):
                    lvl = b + 1
                    if q == self.dut.vnics[i]['base_q'] or \
                       q == self.dut.vnics[i]['base_q'] + \
                            self.dut.vnics[i]['total_qs'] - 1:
                        lvl = 4 + b + q - self.dut.vnics[i]['base_q']
                    assert_eq(lvl,
                              fw_state["prio"][b]['qlvl'][self.group.pf_id][q],
                              "Threshold on band %d queue %d" % (b, q))

        # Now stats
        self.vnics_all_up()
        for i in range(self.group.n_ports):
            # "faster" will most likely mean we'll get no responses
            self.tcpping(port=i, count=2000, keep=False, speed="faster",
                         tos=2, fail=False)
        self.vnics_all_down()

        _, qdiscs = self.qdisc_show()
        qh = {}
        # Should all get marked
        for ifc in self.group.pf_ports:
            qh[ifc] = {}
            marked = 0
            total_pkts = 0
            total_bytes = 0
            mq = None
            for q in qdiscs[ifc]:
                qh[ifc][q['handle']] = q
                if q['kind'] == 'mq':
                    mq = q
                if q['kind'] != 'gred':
                    continue
                pkts = 0
                q['vqa'] = [None] * self.dut.fwcaps["num_bands"]
                for vq in q["options"]["vqs"]:
                    q['vqa'][vq["vq"]] = vq
                    for s in ('prob_drop', 'forced_drop', 'other',
                              'prob_mark', 'backlog', 'qave'):
                        assert_eq(0, vq[s],
                                  qdisc_str(q) + "stat '%s' vq %d" %
                                  (s, vq["vq"]))

                    for s in ('forced_mark', 'pdrop'):
                        if vq["vq"] != 0:
                            assert_eq(0, vq[s],
                                      qdisc_str(q) + "stat '%s' vq %d" %
                                      (s, vq["vq"]))
                        else:
                            marked += vq[s]

                    assert_approx(vq['forced_mark'], 6, vq['packets'],
                                  qdisc_str(q) + "packets vq %d" % (vq["vq"]))
                    assert_ge(vq['packets'] * 60, vq['bytes'],
                              qdisc_str(q) + "bytes vq %d" % (vq["vq"]))
                    pkts += vq['packets']
                    total_bytes += vq['bytes']
                assert_eq(pkts, q['packets'], qdisc_str(q) + "packets")
                assert_ge(q['packets'] * 60, q['bytes'],
                          qdisc_str(q) + "bytes")
                total_pkts += pkts
            assert_range(2000, 2030, marked, "total marked count")
            assert_eq(mq["packets"], total_pkts, "total packet count")
            assert_eq(mq["bytes"], total_bytes, "total byte count")

        # Make sure stats don't change on a down interface
        _, qdiscs = self.qdisc_show()
        for ifc in self.group.pf_ports:
            for q in qdiscs[ifc]:
                for s in BnicQlvl.BASIC:
                    assert_eq(qh[ifc][q['handle']][s], q[s],
                              qdisc_str(q) + "stat: '%s'" % (s))
                if q['kind'] != 'gred':
                    continue
                for vq in q["options"]["vqs"]:
                    for s in ('prob_drop', 'forced_drop', 'other', 'pdrop',
                              'prob_mark', 'forced_mark', 'backlog', 'qave'):
                        assert_eq(qh[ifc][q['handle']]['vqa'][vq['vq']][s],
                                  vq[s], qdisc_str(q) + "stat: '%s' vq: %d" %
                                  (s, vq['vq']))

        # Stats don't change on unoffload
        cmd = ''
        for i in range(self.group.n_ports):
            ifc = self.group.pf_ports[i]
            # GREDs
            for qid in range(self.dut.vnics[i]['total_qs']):
                cmd += "tc qdisc replace dev {ifc} "\
                    "parent {parent} handle {handle}: gred vq {vq} "\
                    "min {thrs} max 10000 avpkt 5000 burst 1 "\
                    "limit 400000 bandwidth 10Mbit ecn"\
                    .format(ifc=ifc, parent="1000:%x" % (qid + 1),
                            handle=hex(4095 - qid)[2:], vq=0, thrs=5000)
                cmd += ' && '
        cmd += 'true'
        self.dut.cmd(cmd)

        _, qdiscs = self.qdisc_show()
        for ifc in self.group.pf_ports:
            for q in qdiscs[ifc]:
                for s in BnicQlvl.BASIC:
                    assert_eq(qh[ifc][q['handle']][s], q[s],
                              qdisc_str(q) + "stat: '%s'" % (s))
                if q['kind'] != 'gred':
                    continue
                for vq in q["options"]["vqs"]:
                    for s in ('prob_drop', 'forced_drop', 'other', 'pdrop',
                              'prob_mark', 'forced_mark', 'backlog', 'qave'):
                        assert_eq(qh[ifc][q['handle']]['vqa'][vq['vq']][s],
                                  vq[s], qdisc_str(q) + "stat: '%s' vq: %d" %
                                  (s, vq['vq']))

        # Send to particular band
        self.build_mq_gred(thrs=[1, 2, 3, 4])

        for ifc in self.group.pf_ports:
            self.qdisc_replace(ifc, parent=None, kind="clsact")
            self.u32_add(ifc, prio=100, proto="ip",
                         v=self.encode_prio(1), band=1)

        self.vnics_all_up()
        for i in range(self.group.n_ports):
            self.tcpping(port=i, count=1500, keep=False, speed="faster",
                         tos=self.encode_prio(1) | 2, fail=False)
        self.vnics_all_down()

        # Check stats for that band
        _, qdiscs = self.qdisc_show()
        for ifc in self.group.pf_ports:
            marked = [0] * self.dut.fwcaps["num_bands"]
            total_pkts = 0
            total_bytes = 0
            mq = None
            for q in qdiscs[ifc]:
                qh[ifc][q['handle']] = q
                if q['kind'] == 'mq':
                    mq = q
                if q['kind'] != 'gred':
                    continue
                pkts = 0
                for vq in q["options"]["vqs"]:
                    for s in ('prob_drop', 'forced_drop', 'other',
                              'prob_mark', 'backlog', 'qave'):
                        assert_eq(0, vq[s],
                                  qdisc_str(q) + "stat '%s' vq %d" %
                                  (s, vq["vq"]))

                    for s in ('forced_mark', 'pdrop'):
                            marked[vq['vq']] += vq[s]

                    assert_approx(vq['forced_mark'], 6, vq['packets'],
                                  qdisc_str(q) + "packets vq %d" % (vq["vq"]))
                    assert_ge(vq['packets'] * 60, vq['bytes'],
                              qdisc_str(q) + "bytes vq %d" % (vq["vq"]))
                    pkts += vq['packets']
                    total_bytes += vq['bytes']
                assert_eq(pkts, q['packets'], qdisc_str(q) + "packets")
                assert_ge(q['packets'] * 60, q['bytes'],
                          qdisc_str(q) + "bytes")
                total_pkts += pkts
            exp_marked = [2000, 1500, 0, 0]
            for i in range(len(marked)):
                if exp_marked[i]:
                    assert_range(exp_marked[i], exp_marked[i] + 50, marked[i],
                                 "total marked count vq %d" % (i))
                else:
                    assert_eq(0, marked[i], "total marked count vq %d" % (i))
            assert_eq(mq["packets"], total_pkts, "total packet count")
            assert_eq(mq["bytes"], total_bytes, "total byte count")

    def cleanup(self):
        self.switchdev_mode_disable()
        return super(BnicGRed, self).cleanup()

class BnicGRedRaw(BnicTest):
    def rtsym_get(self, sym, off):
        _, out = self.dut.cmd_rtsym('%s:%u' % (sym, off))
        return int(out.split()[1], 16)

    def rtsym_set(self, sym, off, val):
        self.dut.cmd_rtsym('%s:%u %u' % (sym, off, val))

    def rtsym_add(self, sym, off, add):
        val = self.rtsym_get(sym, off)
        val += add
        self.rtsym_set(sym, off, val)

    def _check_q(self, q, s, val):
        assert_eq(val, q[s], qdisc_str(q) + "stat: '%s'" % (s))

    def _check_vq(self, q, vq, s, val):
        assert_eq(val, vq[s],
                  qdisc_str(q) + "stat '%s' vq %d" % (s, vq["vq"]))

    def _check_zero_q(self, q, s):
        self._check_q(q, s, 0)

    def _check_zero_vq(self, q, vq, s):
        self._check_vq(q, vq, s, 0)

    def _check_basic_zero(self, q):
        for s in BnicQlvl.BASIC:
            self._check_zero_q(q, s)

    def _check_gred_zero(self, q, vq):
        for s in BnicQlvl.GRED_ALL:
            self._check_zero_vq(q, vq, s)

    def check_all_stats(self, offloaded=True, accu=False, backlog=False):
        _, qdiscs = self.qdisc_show()
        for ifc in self.group.pf_ports:
            for q in qdiscs[ifc]:
                qdisc_offloaded(q, offloaded or q['kind'] != 'gred' or
                                q['parent'] != '1000:1')

                if q['kind'] == 'gred' and q['parent'] != '1000:1':
                    self._check_basic_zero(q)
                else:
                    self._check_zero_q(q, 'requeues')
                    if accu:
                        self._check_q(q, 'packets', 64)
                        self._check_q(q, 'bytes', 68)
                        self._check_q(q, 'drops', 80)
                        self._check_q(q, 'overlimits', 84)
                    else:
                        self._check_zero_q(q, 'packets')
                        self._check_zero_q(q, 'bytes')
                        self._check_zero_q(q, 'drops')
                        self._check_zero_q(q, 'overlimits')

                    if backlog:
                        self._check_q(q, 'backlog', 88)
                        self._check_q(q, 'qlen', 92)
                    else:
                        self._check_zero_q(q, 'backlog')
                        self._check_zero_q(q, 'qlen')

                if q['kind'] != 'gred':
                    continue

                for vq in q["options"]["vqs"]:
                    if q['parent'] != '1000:1':
                        self._check_gred_zero(q, vq)
                    else:
                        for s in ['prob_drop', 'forced_drop', 'prob_mark',
                                  'qave']:
                            self._check_zero_vq(q, vq, s)
                        if accu:
                            self._check_vq(q, vq, 'packets', vq["vq"] * 10 + 1)
                            self._check_vq(q, vq, 'bytes', vq["vq"] * 10 + 2)
                            self._check_vq(q, vq, 'pdrop', vq["vq"] * 10 + 5)
                            self._check_vq(q, vq, 'forced_mark',
                                           vq["vq"] * 10 + 6)
                        else:
                            self._check_zero_vq(q, vq, 'packets')
                            self._check_zero_vq(q, vq, 'bytes')
                            self._check_zero_vq(q, vq, 'pdrop')
                            self._check_zero_vq(q, vq, 'forced_mark')

                        if backlog:
                            self._check_vq(q, vq, 'backlog', vq["vq"] * 10 + 7)
                        else:
                            self._check_zero_q(q, 'backlog')

    def prepare(self):
        if self.group.upstream_drv:
            return NrtResult(name=self.name, testtype=self.__class__.__name__,
                             passed=None, comment='RT-sym test on upstream')

    def execute(self):
        self.switchdev_mode_enable()

        self.vnics_all_down()

        # Build GRED hierarchy on all vNICs
        self.build_mq_gred()

        # Check all stats are zero twice - to make sure stats are stable
        self.check_all_stats()
        self.check_all_stats()

        # For stats on GRED 0 add something to all counters
        for i in range(self.group.n_ports):
            for b in range(self.dut.fwcaps["num_bands"]):
                q = self.dut.vnics[i]['base_q'] + b * NfdBarOff.MAX_RXRINGS

                self.rtsym_add("_abi_nfd_rxq_stats%u_per_band" %
                               (self.group.pf_id), q * 16, b * 10 + 1)
                self.rtsym_add("_abi_nfd_rxq_stats%u_per_band" %
                               (self.group.pf_id), q * 16 + 8, b * 10 + 2)

                self.rtsym_add("_abi_nfdqm%u_stats_per_band" %
                               (self.group.pf_id), q * 32, b * 10 + 3)
                self.rtsym_add("_abi_nfdqm%u_stats_per_band" %
                               (self.group.pf_id), q * 32 + 8, b * 10 + 4)
                self.rtsym_add("_abi_nfdqm%u_stats_per_band" %
                               (self.group.pf_id), q * 32 + 16, b * 10 + 5)
                self.rtsym_add("_abi_nfdqm%u_stats_per_band" %
                               (self.group.pf_id), q * 32 + 24, b * 10 + 6)

                self.rtsym_add("_abi_nfd_out_q_lvls_%u_per_band" %
                               (self.group.pf_id), q * 16, b * 10 + 7)
                self.rtsym_add("_abi_nfd_out_q_lvls_%u_per_band" %
                               (self.group.pf_id), q * 16 + 4, b * 10 + 8)

        # Check the modified counters twice
        self.check_all_stats(True, True, True)
        self.check_all_stats(True, True, True)

        # Unoffload - stats should stay almost the same (save for backlog)
        cmd = ''
        for i in range(self.group.n_ports):
            ifc = self.group.pf_ports[i]
            cmd += "tc qdisc replace dev {ifc} "\
                "parent {parent} handle {handle}: gred vq {vq} "\
                "min {thrs} max 10000 avpkt 5000 burst 1 "\
                "limit 400000 bandwidth 10Mbit ecn"\
                .format(ifc=ifc, parent="1000:%x" % (1),
                        handle=hex(4095)[2:], vq=0, thrs=5000)
            cmd += ' && '
        cmd += 'true'
        self.dut.cmd(cmd)

        # Recheck
        self.check_all_stats(False, True, False)
        self.check_all_stats(False, True, False)

        # Fix the offload and make sure stats return
        cmd = ''
        for i in range(self.group.n_ports):
            ifc = self.group.pf_ports[i]
            cmd += "tc qdisc replace dev {ifc} "\
                "parent {parent} handle {handle}: gred vq {vq} "\
                "min 5000 max 5000 avpkt 5000 burst 1 "\
                "limit 400000 bandwidth 10Mbit ecn"\
                .format(ifc=ifc, parent="1000:%x" % (1),
                        handle=hex(4095)[2:], vq=0, thrs=5000)
            cmd += ' && '
        cmd += 'true'
        self.dut.cmd(cmd)

        # Recheck
        self.check_all_stats(True, True, True)
        self.check_all_stats(True, True, True)

        # Remove / rebuild the structure
        for ifc in self.group.pf_ports:
            self.qdisc_delete(ifc, parent="root", kind="mq")
        self.build_mq_gred()

        # Check all accumulative stats are 0
        self.check_all_stats(True, False, True)
        self.check_all_stats(True, False, True)

        # Check the ethtool stat
        for ifc in self.group.pf_ports:
            stats = self.dut.ethtool_stats(ifc)

            sto = 0
            non_sto = 0
            for b in range(self.dut.fwcaps["num_bands"]):
                q = self.dut.vnics[i]['base_q'] + b * NfdBarOff.MAX_RXRINGS

                non_sto += self.rtsym_get("_abi_nfdqm%u_stats_per_band" %
                                          (self.group.pf_id), q * 32)
                sto += self.rtsym_get("_abi_nfdqm%u_stats_per_band" %
                                      (self.group.pf_id), q * 32 + 8)

            assert_eq(non_sto, stats['q0_no_wait'], "Ethtool stat 'q0_no_wait'")
            assert_eq(sto, stats['q0_delayed'], "Ethtool stat 'q0_delayed'")

    def cleanup(self):
        self.switchdev_mode_disable()

        for i in range(self.group.n_ports):
            for b in range(self.dut.fwcaps["num_bands"]):
                q = self.dut.vnics[i]['base_q'] + b * NfdBarOff.MAX_RXRINGS

                self.rtsym_set("_abi_nfd_out_q_lvls_%u_per_band" %
                               (self.group.pf_id), q * 16, 0)
                self.rtsym_set("_abi_nfd_out_q_lvls_%u_per_band" %
                               (self.group.pf_id), q * 16 + 4, 0)

        return super(BnicGRedRaw, self).cleanup()

###########################################################################
# u32 tests
###########################################################################
class BnicU32eg(BnicTest):
    def check_offload(self, cls, pred):
        _, qdiscs = self.qdisc_show()
        for i in range(self.group.n_ports):
            ifc = self.group.pf_ports[i]
            assert_eq(self.dut.vnics[i]['total_qs'] + 1 + int(cls),
                      len(qdiscs[ifc]), "Num Qdiscs")
            for q in qdiscs[ifc]:
                qdisc_offloaded(q, pred(q))

    def execute(self):
        self.switchdev_mode_enable()

        # Install egress Qdisc
        for ifc in self.group.pf_ports:
            self.qdisc_replace(ifc, parent=None, kind="clsact")
        # Add some rules
        for ifc in self.group.pf_ports:
            self.u32_add(ifc, prio=100, proto="ip", v=0x80, band=0)
        # Create RED
        self.build_mq_red(1)
        # RED should not offload now
        self.check_offload(True, (lambda q: q['kind'] == "mq"))

        # Remove the rules
        for ifc in self.group.pf_ports:
            self.u32_remove(ifc, prio=100, proto="ip")
        # RED should offload now
        self.check_offload(True, (lambda q: q['kind'] != "clsact"))

        # Re-add again, this time Qdisc is already there
        for ifc in self.group.pf_ports:
            self.u32_add(ifc, prio=100, proto="ip", v=0x80, band=0)
        # RED should have gotten unoffload again
        self.check_offload(True, (lambda q: q['kind'] == "mq"))

        # Remove egress Qdisc
        for ifc in self.group.pf_ports:
            self.qdisc_delete(ifc, parent=None, kind="clsact")
        # RED should offload now
        self.check_offload(False, (lambda q: True))

        # Add only the egress Qdisc
        for ifc in self.group.pf_ports:
            self.qdisc_replace(ifc, parent=None, kind="clsact")
        # Still offloaded
        self.check_offload(True, (lambda q: q['kind'] != "clsact"))
        # Add some rules
        for ifc in self.group.pf_ports:
            self.u32_add(ifc, prio=100, proto="ip", v=0x80, band=0)
        # Now not offloaded
        self.check_offload(True, (lambda q: q['kind'] == "mq"))

        # Nuke the filters with the Qdisc
        for ifc in self.group.pf_ports:
            self.qdisc_delete(ifc, parent=None, kind="clsact")
        # Should offload now
        self.check_offload(False, (lambda q: True))

        # Now onto GRED
        self.build_mq_gred()
        # GRED should offload nicely
        self.check_offload(False, (lambda q: True))

        # Add the egress Qdisc
        for ifc in self.group.pf_ports:
            self.qdisc_replace(ifc, parent=None, kind="clsact")
        # Still offloaded
        self.check_offload(True, (lambda q: q['kind'] != "clsact"))
        # Add some rules
        for ifc in self.group.pf_ports:
            self.u32_add(ifc, prio=100, proto="ip", v=0x80, band=0)
        # Still offloaded
        self.check_offload(True, (lambda q: q['kind'] != "clsact"))
        # Nuke the filters with the Qdisc
        for ifc in self.group.pf_ports:
            self.qdisc_delete(ifc, parent=None, kind="clsact")
        # And still offloaded
        self.check_offload(False, (lambda q: q['kind'] != "clsact"))

    def cleanup(self):
        self.switchdev_mode_disable()
        return super(BnicU32eg, self).cleanup()

class BnicU32(BnicTest):
    def test_one_map(self, ifc, gen):
        bits = int(math.log(self.dut.fwcaps["num_bands"] - 1, 2)) + 1

        # Set the prios to the values from gen
        cmd = ''
        for p in range(self.dut.fwcaps["num_prio"]):
            band = gen(p)
            cmd += self.u32_add(ifc, prio=100, proto="ip",
                                v=self.encode_prio(p), band=band, _bulk=True)
            cmd += ' && '
            cmd += self.u32_add(ifc, prio=101, proto="ipv6",
                                v=self.encode_prio(p), band=band, _bulk=True)
            cmd += ' && '
        self.dut.cmd(cmd + 'true')

        # Read FW state
        fw_state = self.read_fw_state()
        # Manually compute the prio map
        pm = []
        for p in range(self.dut.fwcaps["num_prio"]):
            band = gen(p)
            if p * bits / 32 == len(pm):
                pm.append(0)
            pm[p * bits / 32] |= band << (p * bits % 32)

        for i in range(len(pm)):
            assert_eq(pm[i], fw_state["priomap"][self.group.pf_id][i],
                      "priomap word %d" % (i))

    def execute(self):
        self.switchdev_mode_enable()

        # Install egress Qdisc
        for ifc in self.group.pf_ports:
            self.qdisc_replace(ifc, parent=None, kind="clsact")
        # File all prios to band 1
        for ifc in self.group.pf_ports:
            self.test_one_map(ifc, (lambda p: 1))

        # File all prios to band mod
        for ifc in self.group.pf_ports:
            self.qdisc_delete(ifc, parent=None, kind="clsact")
        for ifc in self.group.pf_ports:
            self.qdisc_replace(ifc, parent=None, kind="clsact")

        for ifc in self.group.pf_ports:
            self.test_one_map(ifc, (lambda p: p % 4))

        # Check we can duplicate a good filter
        for ifc in self.group.pf_ports:
            self.qdisc_delete(ifc, parent=None, kind="clsact")
        for ifc in self.group.pf_ports:
            self.qdisc_replace(ifc, parent=None, kind="clsact")

        self.u32_add(ifc, prio=100, proto="ip", v=self.encode_prio(0), band=1)
        self.u32_add(ifc, prio=100, proto="ip", v=self.encode_prio(0), band=1)

        # But we can't duplicate a bad one
        ret, _ = self.u32_add(ifc, prio=100, proto="ip",
                              v=self.encode_prio(0), band=2, fail=False)
        assert_neq(ret, 0, "Add bad v4 filter status")
        # Neither can we on the other proto
        ret, _ = self.u32_add(ifc, prio=100, proto="ipv6",
                              v=self.encode_prio(0), band=2, fail=False)
        assert_neq(ret, 0, "Add bad v6 filter status")

        # But we can't add conflicting mask
        ret, _ = self.u32_add(ifc, prio=100, proto="ip",
                              v=self.encode_prio(0), mask=0x80, band=2,
                              fail=False)

        # We can add good covering mask
        self.u32_add(ifc, prio=100, proto="ip",
                     v=self.encode_prio(0), mask=0x80, band=1)

    def cleanup(self):
        self.switchdev_mode_disable()
        return super(BnicU32, self).cleanup()

###########################################################################
# Action setting tests
###########################################################################
class BnicAct(BnicTest):
    def check_offload(self, pred):
        _, qdiscs = self.qdisc_show()
        for i in range(self.group.n_ports):
            ifc = self.group.pf_ports[i]
            assert_eq(self.dut.vnics[i]['total_qs'] + 1, len(qdiscs[ifc]),
                      "Num Qdiscs")
            for q in qdiscs[ifc]:
                qdisc_offloaded(q, pred(q))

    def check_act(self, pred):
        fw_state = self.read_fw_state()
        for i in range(self.group.n_ports):
            for band in range(self.dut.fwcaps["num_bands"]):
                for qid in self.all_qs(i):
                    act = fw_state['prio'][band]['qact'][self.group.pf_id][qid]
                    assert_eq(pred(qid, band), act,
                              "Queue Action for band: %d queue: %d" %
                              (band, qid))

    def execute(self):
        self.switchdev_mode_enable()

        # Build normal GRED with all the ECNs
        self.build_mq_gred(parent_flags=False)

        # Check all are offloaded
        self.check_offload((lambda x: True))

        # Check actions are all set to ACT_MARK_DROP
        self.check_act((lambda q, band: ACT_MARK_DROP))

        if self.dut.fwcaps["num_bands"] > 1:
            vqs = (0, self.dut.fwcaps["num_bands"] - 1)
        else:
            vqs = (0)

        for vq in vqs:
            # Now disable the ECN
            cmd = ''
            for i in range(self.group.n_ports):
                ifc = self.group.pf_ports[i]
                for qid in range(self.dut.vnics[i]['total_qs']):
                    cmd += self.qdisc_replace(ifc, parent="1000:%x" % (qid + 1),
                                              handle=hex(4095 - qid)[2:],
                                              kind="gred", vq=vq, thrs=5000,
                                              ecn=False, _bulk=True)
                    cmd += ' && '
            cmd += 'true'
            self.dut.cmd(cmd)

            # If DROP action is not support there is no offload
            if self.dut.fwcaps["act_mask"] & (1 << ACT_DROP) == 0:
                self.check_offload((lambda x: q['kind'] == "mq"))
            else:
                self.check_offload((lambda x: True))
                self.check_act((lambda q, band:
                                ACT_DROP if band == vq else ACT_MARK_DROP))

            # Go back to the ECN on that band
            cmd = ''
            for i in range(self.group.n_ports):
                ifc = self.group.pf_ports[i]
                for qid in range(self.dut.vnics[i]['total_qs']):
                    cmd += self.qdisc_replace(ifc, parent="1000:%x" % (qid + 1),
                                              handle=hex(4095 - qid)[2:],
                                              kind="gred", vq=vq, thrs=5000,
                                              _bulk=True)
                    cmd += ' && '
            cmd += 'true'
            self.dut.cmd(cmd)

            # And check the act is back to MARK/DROP
            self.check_act((lambda q, band: ACT_MARK_DROP))

    def cleanup(self):
        self.switchdev_mode_disable()
        return super(BnicAct, self).cleanup()
