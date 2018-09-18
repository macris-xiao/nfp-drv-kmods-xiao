#
# Copyright (C) 2018,  Netronome Systems, Inc.  All rights reserved.
#
"""
ABM NIC test group for the NFP Linux drivers.
"""

from ..drv_grp import NFPKmodAppGrp
from drv_info import DrvInfoEthtool
from mac_stats import MacStatsEthtool
from netconsole import NetconsoleTest
from phys_port_name import PhysPortName
from stats_ethtool import StatsEthtool

class NFPKmodNetdev(NFPKmodAppGrp):
    """Basic FW-independent NIC tests for the NFP Linux drivers"""

    summary = "FW-independent NIC tests used for NFP Linux driver."

    def _init(self):
        super(NFPKmodNetdev, self)._init()

        self.dut.defaults = {}
        for vnic in self.dut.vnics:
            self.dut.defaults[vnic] = {}

        for vnic in self.dut.vnics:
            self.dut.defaults[vnic]["link"] = self.dut.ip_link_stats(vnic)
            self.dut.defaults[vnic]["chan"] = \
                self.dut.ethtool_channels_get(vnic)["current"]
            self.dut.defaults[vnic]["ring"] = \
                self.dut.ethtool_rings_get(vnic)["current"]

    def populate_tests(self):
        dut = (self.dut, self.addr_x, self.eth_x, self.addr_v6_x)
        src = (self.host_a, self.addr_a, self.eth_a, self.addr_v6_a)

        tests = (
            ('bsp_version', BspVerTest, "Test NSP BSP Version function"),
            ('bsp_diag', BSPDiag, "Test the basic BSP diagnostics"),
            ('sensors', SensorsTest, "Test Hwmon sensors functionality"),
            ('phys_port_name', PhysPortName, "Test port naming"),
            ('ethtool_drvinfo', DrvInfoEthtool, "Ethtool -i test"),
            ('ethtool_get_speed', LinkSpeedEthtool, "Ethtool get settings"),
            ('ethtool_stats', StatsEthtool, "Ethtool stats"),
            ('ethtool_mac_stats', MacStatsEthtool, "Ethtool MAC stats"),
            ('devlink_port_show', DevlinkPortsShow,
             "Check basic devlink port output"),
            ('netconsole', NetconsoleTest, 'Test netconsole over the NFP'),
            ('mtu_flbufsz_check', MtuFlbufCheck,
             "Check if driver sets correct fl_bufsz and mtu"),
            ('huge_ring', HugeRings, "Check allocation of huge rings"),
        )

        for t in tests:
            self._tests[t[0]] = t[1](src, dut, group=self, name=t[0],
                                     summary=t[2])

###########################################################################
# Test classes
###########################################################################

import os
import re
from netro.testinfra.nti_exceptions import NtiError
from netro.testinfra.system import cmd_log
from ..common_test import CommonTest, NtiSkip, assert_eq, assert_ge
from ..drv_system import NfpNfdCtrl

class BspVerTest(CommonTest):
    def execute(self):
        self.nsp_min(16)

        cmd  = 'dmesg | tac | sed -n "1,/nfp: NFP PCIe Driver/p"'
        cmd += ' | grep "nfp 0000:%s"' % (self.group.pci_id)
        cmd += ' | grep -o "BSP: .*" | cut -c 6- | tr -d "\n"'
        _, ver = self.dut.cmd(cmd)
        comp = ver.split('.')
        if len(comp) != 3:
            raise NtiError('bad bsp version format: %s %d' % (ver, len(comp)))
        for i in range(3):
            if len(comp[i]) != 6:
                raise NtiError('bad bsp version format: %s' % ver)
            if False == all(c in '0123456789abcdefABCDEF' for c in comp[i]):
                raise NtiError('bad bsp version format (char): %s' % ver)

class BSPDiag(CommonTest):
    def execute(self):
        regx_sp = re.compile('[^ ]* (\d*\.\d*).*', re.M | re.S)
        for ifc in self.dut.nfp_netdevs:
            info = self.dut.ethtool_drvinfo(ifc)

            ver_m = regx_sp.match(info['firmware-version'])
            if not ver_m:
                raise NtiError("Ethtool does not report NSP ABI")

            if not self.group.upstream_drv:
                ver = ver_m.groups()[0]
                _, cmd_ver = self.dut.cmd_nsp('-v')
                cmd_ver = cmd_ver.split('\n')[0]

                if cmd_ver != ver:
                    raise NtiError("NSP ABI version does not match ethtool:'%s' user space:'%s'" % (ver, cmd_ver))

            _, out = self.dut.cmd('ethtool -w %s' % (ifc))
            if out.find('flag: 0, version: 1, length: 8192') == -1:
                raise NtiError("ethtool dump report unexpected")

            # Just to exercise the code path
            _, out = self.dut.cmd('ethtool -w %s data /dev/null' % (ifc))

class SensorsTest(CommonTest):
    def get_attr(self, array, attr):
        for s in array :
            if attr in s :
                return s
        raise NtiError('didn\'t find attr: %s', attr)

    def execute(self):
        self.nsp_min(15)

        ret, out = self.dut.cmd('sensors -u nfp-pci-%s%s' %
                                (self.group.pci_id[0:2],
                                 self.group.pci_id[3:5]))
        if ret != 0:
            raise NtiError('sensors not found')
        lines = out.splitlines()

        temp = float(self.get_attr(lines, "temp1_input").split(':')[1])
        high = float(self.get_attr(lines, "temp1_max").split(':')[1])
        crit = float(self.get_attr(lines, "temp1_crit").split(':')[1])

        if int(high) != 95:
                raise NtiError('invalid high temp val')
        if int(crit) != 105:
                raise NtiError('invalid crit temp val')
        if int(temp) < 15 or int(temp) > 80:
                raise NtiError('invalid temp')

        power = float(self.get_attr(lines, "power1_input").split(':')[1])
        power_lim = float(self.get_attr(lines, "power1_max").split(':')[1])

        if int(power) < 5 or int(power) > 25 :
                raise NtiError('invalid power limit')
        if int(power_lim) != 25:
                raise NtiError('invalid power val')

class LinkSpeedEthtool(CommonTest):
    def execute(self):
        if self.group.upstream_drv:
            raise NtiSkip('BSP tools upstream')

        _, phy = self.dut.cmd_phymod('-E | grep "^eth"')
        phy = phy.strip().split('\n')

        self.ifc_skip_if_not_all_up()

        if len(phy) != len(self.dut_ifn):
            raise NtiError("Bad number of items userspace:%d interfaces:%d" %
                           (len(phy), len(self.dut_ifn)))

        for i in range(0, len(phy)):
            p = re.match('eth(\d*): NBI[^(]*\((\d)\)\t"([^"]*)" ([^ ]*) (\d*)G',
                         phy[i]).groups()

            phymod = int(p[4]) * 1000
            ethtool = self.dut.ethtool_get_speed(self.dut_ifn[i])

            if phymod != ethtool:
                raise NtiError("On port %d phymod reports:%d ethtool:%d" %
                               (i, phymod, ethtool))

class MtuFlbufCheck(CommonTest):
    def get_vnic_reg(self, offset):
        return self.dut.nfd_reg_read_le32(self.dut.vnics[0], offset)

    def get_bar_rx_offset(self):
        return self.get_vnic_reg(NfpNfdCtrl.RX_OFFSET)

    def get_bar_mtu(self):
        return self.get_vnic_reg(NfpNfdCtrl.MTU)

    def get_bar_flbufsz(self):
        return self.get_vnic_reg(NfpNfdCtrl.FLBUFSZ)

    def check(self, has_xdp):
        check_mtus = [1500, 1024, 2049, 2047, 2048 - 32, 2048 - 64]

        for mtu in check_mtus:
            self.dut.ip_link_set_mtu(self.dut.vnics[0], mtu)
            bmtu = self.get_bar_mtu()
            bflbufsz = self.get_bar_flbufsz()
            rxoffset = self.get_bar_rx_offset()

            if has_xdp:
                xdp_off = 256 - rxoffset
            else:
                xdp_off = 0

            fl_bufsz = xdp_off + rxoffset + 14 + 8 + mtu
            if rxoffset == 0:
                fl_bufsz += 64

            fl_bufsz = (fl_bufsz + 63) & ~63
            fl_bufsz -= xdp_off

            self.log("vals", [mtu, bmtu, rxoffset, bflbufsz, fl_bufsz])

            if mtu != bmtu:
                raise NtiError("MTU doesn't match BAR (was:%d expect:%d)" %
                               (mtu, bmtu))
            if fl_bufsz != bflbufsz:
                raise NtiError("FL_BUFSZ doesn't match BAR (was:%d expect:%d)" %
                               (fl_bufsz, bflbufsz))

    def execute(self):
        self.check(False)

        if self.kernel_min(4, 8):
            return
        ret, _ = cmd_log('ls %s' % (os.path.join(self.group.samples_xdp,
                                                 'pass.o')),
                         fail=False)
        if ret != 0:
            raise NtiSkip('XDP samples not found')

        self.dut.copy_bpf_samples()

        self.dut.cmd('ethtool -L %s rx 0 tx 0 combined 1' % (self.dut.vnics[0]))
        self.xdp_start('pass.o')

        self.check(True)

        self.xdp_stop()

    def cleanup(self):
        vnic = self.dut.vnics[0]
        self.dut.ip_link_set_mtu(vnic, 1500)
        self.dut.ethtool_channels_set(vnic, self.dut.defaults[vnic]["chan"])

        return super(MtuFlbufCheck, self).cleanup()

class DevlinkPortsShow(CommonTest):
    def execute(self):
        if self.group.upstream_drv:
            raise NtiSkip('BSP tools upstream')
        if self.kernel_min(4, 6):
            raise NtiSkip("Devlink needs kernel 4.6 or newer")

        dev = "pci/%s" % (self.group.pci_dbdf)

        _, phy = self.dut.cmd_phymod('-E | grep "^eth"')
        ports = [l.split() for l in phy.split('\n') if l != ""]

        _, dl = self.dut.cmd('devlink port show | grep %s' % (dev))
        dl_ports = [l.split() for l in dl.split('\n') if l != ""]

        if len(ports) != len(dl_ports):
            raise NtiError("Unexpected port count bsp:%d vs devlink:%d" %
                           (len(ports), len(dl_ports)))

        for p in ports:
            # Decode phymod output
            ethX  = p[0]
            label = p[2]
            mac   = p[3]

            port = re.match("eth(\d*):", ethX).group(1)

            labels = re.match('"(\d*)\.(\d*)"', label).groups()
            main_port = labels[0]
            subport   = labels[1]

            lane = re.match("NBI\d*.(\d*).*", p[1]).groups()[0]

            # Get netdev and verify it has right MAC addr
            cmd = 'devlink port show %s/%s' % (dev, lane)
            _, dl_port = self.dut.cmd(cmd)

            netdev = re.match(".*netdev (\w*).*", dl_port).group(1)
            self.dut.cmd('ip link show dev %s | grep %s' % (netdev, mac))

            # Check split group
            if dl_port.find('split') != -1:
                split = re.match(".*split_group (\w*).*", dl_port).group(1)
                if split != main_port:
                    raise NtiError("Split group %s, should be %s" %
                                   (split, main_port))
            elif subport != "0":
                raise NtiError("Split group not reported for non-0th subport")

class HugeRings(CommonTest):
    def execute(self):
        self.port = 0
        self.rings_changed = False

        if len(self.dut.nfp_netdevs) != len(self.dut.vnics):
            raise NtiSkip('switchdev firmware')

        rings = self.dut.ethtool_rings_get(self.dut.vnics[0])

        ret, _ = self.dut.ethtool_rings_set(self.dut.vnics[0], rings["max"],
                                            fail=False)
        self.rings_changed = ret == 0
        if ret:
            _, dmesg = self.dut.cmd('dmesg | tail -200')
            assert_eq(0, dmesg.count("Call Trace:"), "stack dumps in the logs")
            assert_ge(1, dmesg.count("consider lowering descriptor count"),
                      "our info/warning in the logs")
        else:
            pkt_cnt = max(rings["max"]["rx"], rings["max"]["tx"]) + 128
            self.src.ping(addr=self.dut_addr[self.port][:-3],
                          ifc=self.src_ifn[self.port],
                          count=pkt_cnt, flood=True)

    def cleanup(self):
        if self.rings_changed:
            defaults = self.dut.defaults[self.dut.vnics[self.port]]["ring"]
            self.dut.ethtool_rings_set(self.dut.vnics[self.port], defaults)

        return super(HugeRings, self).cleanup()
