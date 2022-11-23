#
# Copyright (C) 2017,  Netronome Systems, Inc.  All rights reserved.
#
"""
Unit test group for the NFP Linux driver tests which require a driver reload.
"""

import os
import re
import random
import netro.testinfra
from netro.testinfra.test import *
from ..drv_grp import NFPKmodGrp
from fw_load import KernelLoadTest
import time
from netro.testinfra.nti_exceptions import NtiGeneralError
from netro.testinfra.nrt_result import NrtResult
from netro.testinfra.system import cmd_log
from ..common_test import CommonNetdevTest, NtiSkip
from ..common_test import AMDA_10G_CARDS, AMDA_25G_CARDS, AMDA_40G_CARDS, \
    AMDA_100G_CARDS
from ..drv_system import DrvSystem

###########################################################################
# Unit Tests
###########################################################################


class NFPKmodReload(NFPKmodGrp):
    """Unit tests for the NFP Linux drivers"""

    summary = "Unit tests used for NFP Linux driver."

    def __init__(self, name, cfg=None, quick=False, dut_object=None,
                 dut=None, nfp=None, nfpkmods=None, mefw=None):

        NFPKmodGrp.__init__(self, name=name, cfg=cfg, quick=quick,
                            dut_object=dut_object)

    def populate_tests(self):
        dut = (self.dut, self.addr_x, self.eth_x, self.addr_v6_x)
        src = (self.host_a, self.addr_a, self.eth_a, self.addr_v6_a)

        T = (('set_speed', SpeedSet, "Flip speed and reload driver"),
             ('port_split', DevlinkSplit,
              "Split/unsplit port and reload driver in between"),
             ('kernel_fw_load', KernelLoadTest, "Test kernel firmware loader"),
             )

        for t in T:
            self._tests[t[0]] = t[1](src, dut, self, t[0], t[2])


class SpeedSet(CommonNetdevTest):
    def port_index_obtain(self):
        self.port2idx = []
        _, nsp = self.dut.cmd_nsp(' -E | grep NBI')
        self.nsp = nsp.strip().split('\n')
        for i in range(0, len(self.nsp)):
            p = re.match('eth(.*): NBI', self.nsp[i]).groups()
            self.port2idx += [int(p[0])]

    def reload_fw_to_2x10G(self, ifc_list):
        self.dut.cmd('mkdir -p /lib/firmware/netronome')
        partno = self.dut.get_part_no()
        nffw_file = "nic_" + partno + "_2x10.nffw"
        self.netdevfw_2x10G = os.path.dirname(self.group.netdevfw)
        self.netdevfw_2x10G = self.netdevfw_2x10G + "/" + nffw_file
        # netdevfw_2x10G: Path to 2x10 fw example:
        # /root/firmware/agilio-nic-firmware-22.07-1/nfdk/nic_AMDA0144-0002_2x10.nffw

        self.dut.cp_to(self.netdevfw_2x10G, '/lib/firmware/netronome/')
        self.dut.nffw_unload()
        self.dut.reset_mods()
        self.dut.insmod(netdev=True, userspace=True)
        for ifc in ifc_list:
            self.dut.ip_link_set_up(ifc)

    def set_src_speed(self, speed, ifc_list):
        for ifc in ifc_list:
            self.src.ip_link_set_down(ifc)
            self.src.cmd('ethtool -s %s speed %d' % (ifc, speed))
        # Reload the driver on the EP (src) using modprobe as self.src
        # is of type LinuxSystem and rmmod helper function self.src.rmmod()
        # doesn't exist for LinuxSystem
        self.src.cmd('rmmod nfp && modprobe nfp')
        for ifc in ifc_list:
            self.src.ip_link_set_up(ifc)

        self.src.cmd('ip addr add dev %s %s' % (self.src_ifn[0],
                     self.src_addr[0]))
        self.src.cmd('ip addr add dev %s %s' % (self.src_ifn[0],
                     self.src_addr_v6[0]))
        self.src.cmd('ip addr add dev %s %s' % (self.src_ifn[1],
                     self.src_addr[1]))
        self.src.cmd('ip addr add dev %s %s' % (self.src_ifn[1],
                     self.src_addr_v6[1]))

    def check_fails(self, ifc, all_speeds, skip_speeds=[]):
        for speed in all_speeds:
            if speed in skip_speeds:
                continue

            ret, out = self.dut.ethtool_set_speed(ifc, speed, fail=False)

            correct_fail_output1 = out[1].find('link settings update failed')
            correct_fail_output2 = out[1].find('Cannot set new settings')

            # if neither failing outputs are seen, it must mean that the speed
            # was set
            if correct_fail_output1 == -1 and correct_fail_output2 == -1:
                raise NtiError('Set %s speed to %d did not fail' %
                               (ifc, speed))

    def check_fails_all(self, all_speeds, skip_speeds=[]):
        for ifc in self.dut_ifn:
            self.check_fails(ifc, all_speeds, skip_speeds)

    def netdev_execute(self):
        # Make sure remote host using nfp
        for ifc in self.src_ifn:
            _, src_drv_info = self.src.cmd('ethtool -i %s | grep driver' % ifc)
            if src_drv_info.split()[1] != 'nfp':
                raise NtiSkip("EP expect: nfp, actual: %s"
                              % src_drv_info.split()[1])

        all_speeds = (0, 1, 1237, 10000, 25000, 40000)

        if self.dut.get_nsp_ver(self.dut_ifn[0]) < 15:
            self.check_fails_all(all_speeds)
            return

        # Get AMDAXXXX number
        AMDA_no = self.dut.get_amda_only()

        str_def_speed = None

        # Get the default speed depending on card type
        if AMDA_no in AMDA_10G_CARDS:
            default_speed = 10000
            str_def_speed = "10G"
        elif AMDA_no in AMDA_25G_CARDS:
            default_speed = 25000
            str_def_speed = "25G"

        # Note that 40G and 100G cards cannot change their speed setting, but
        # can be split into ports with slower speeds. See port_split test. 40G
        # and 100G cards are still checked in this test if it fails where
        # expected.
        supported_speeds = {
            "10G": (10000, 1000),
            "25G": (25000, 10000),
        }

        self.ifc_skip_if_not_all_up()

        # All cards not in supported_speeds can't do ethtool speed setting
        if str_def_speed not in supported_speeds:
            for ifc in self.dut_ifn:
                cur_speed = self.dut.ethtool_get_speed(ifc)
                self.check_fails(ifc, all_speeds, [cur_speed])
            return

        # Make sure all ports have the same speed (simplify things)
        cur_speed = self.dut.ethtool_get_speed(self.dut_ifn[0])
        for ifc in self.dut_ifn[1:]:
            if cur_speed != self.dut.ethtool_get_speed(ifc):
                raise NtiError("Ports don't all have the same speed")
        speeds = supported_speeds[str_def_speed]
        if cur_speed not in speeds:
            raise NtiError("Speed %d is not on the supported list" % cur_speed)

        for i in range(len(self.dut_ifn)):
            self.port_index_obtain()
            at_speed = self.dut.nfp_phymod_get_speed(self.port2idx[i])
            if at_speed != cur_speed:
                raise NtiError("Phymod and ethtool speed mismatch (%d vs %d)" %
                               (at_speed, cur_speed))

        # Rotate the list until the current speed is at the beginning
        while speeds[0] != cur_speed:
            speeds = speeds[1:] + speeds[:1]

        # Reconfig until back to initial
        speeds = speeds[1:] + speeds[:1]
        while True:
            for ifc in self.dut_ifn:
                self.check_fails(ifc, all_speeds, speeds)

            # We need to configure in correct order.  Assume that
            # @supported_speeds has the "default" mode first, we need to
            # try to keep the last port in default mode when mixed config
            ifc_list = self.dut_ifn
            src_ifc_list = self.src_ifn
            if speeds[0] == supported_speeds[str_def_speed][0]:
                ifc_list = list(reversed(ifc_list))
                src_ifc_list = list(reversed(src_ifc_list))

            for ifc in ifc_list:
                ret, out = self.dut.ethtool_set_speed(ifc, speeds[0])
                if out[1].find('link settings update failed') != -1:
                    raise NtiError('Failed to set %s speed to %d' %
                                   (ifc, speeds[0]))

                # Make sure port disappears
                time.sleep(3)  # Refresh of eth table may take some time
                ret, _ = self.dut.cmd('ip link show %s' % (ifc), fail=False)
                if ret == 0:
                    raise NtiError("Netdev didn't disappear")

            if speeds[0] == supported_speeds[str_def_speed][0]:
                self.reload_driver()
            else:
                self.reload_fw_to_2x10G(ifc_list)

            self.set_src_speed(speeds[0], src_ifc_list)

            time.sleep(3)
            self.ifc_skip_if_not_all_up()

            for i in range(len(self.dut_ifn)):
                ifc = self.dut_ifn[i]
                self.port_index_obtain()
                at_speed = self.dut.nfp_phymod_get_speed(self.port2idx[i])
                if at_speed != speeds[0]:
                    raise NtiError('Phymod speed not %d after reload on %s' %
                                   (speeds[0], ifc))

                at_speed = self.dut.ethtool_get_speed(ifc)
                if at_speed != speeds[0]:
                    raise NtiError('Speed not %d after reload on %s' %
                                   (speeds[0], ifc))

            # Check if we are back to where we started
            if speeds[0] == cur_speed:
                return
            speeds = speeds[1:] + speeds[:1]

    def cleanup(self):
        # Reset the speed with BSP media command.
        # nfp-media -C should output the default speed
        # eg. phy0=25G+ (default)

        _, out = self.dut.cmd_media('-C')  # /opt/netronome/bin/nfp-media
        if 'default' not in out:
            raise NtiError("Speed could not be reset to default with"
                           " nfp-media -C")
        return super(SpeedSet, self).cleanup()


###########################################################################
class DevlinkSplit(CommonNetdevTest):
    def check_fails_split(self, idx, bad_counts):
        for count in bad_counts:
            ret, _ = self.dut.devlink_split(idx, count, fail=False)
            if ret == 0:
                raise NtiError('Split %d to %d did not fail' % (idx, count))

    def check_fails_unsplit(self, idx):
        ret, _ = self.dut.devlink_unsplit(idx, fail=False)
        if ret == 0:
            raise NtiError('Unsplit %d did not fail' % (idx))

    def check_all_fails(self, idx, bad_counts):
        self.check_fails_split(idx, bad_counts)
        self.check_fails_unsplit(idx)

    def unsplit_check(self, card_info):
        cur_cnt = len(self.dut.phys_netdevs)
        bad_ports = range(cur_cnt, cur_cnt + 2)
        if card_info[0] > 1:
            bad_ports.append(0)  # fail because of order
        bad_ports.append(-1)

        if cur_cnt != card_info[0] * card_info[1]:
            raise NtiError('Netdev counts not %d' % (cur_cnt))

        for i in range(-1, cur_cnt + 2):
            self.check_fails_split(i, range(-1, 9))

        for i in bad_ports:
            self.check_fails_unsplit(i)

    def unsplit(self, card_info):
        for x in list(reversed(range(0, card_info[0]))):
            for i in [x * card_info[1]]:
                self.dut.devlink_unsplit(i)

        cur_cnt_remain = 0
        for ifc in self.dut_ifn:
            ret, _ = self.dut.cmd('ip link show %s' % ifc, fail=False)
            if ret == 0:
                cur_cnt_remain += 1

        if cur_cnt_remain:
            raise NtiError('Not all netdevs disappeared %d left'
                           % (cur_cnt_remain))

    def split_check(self, card_info):
        cur_cnt = len(self.dut.phys_netdevs)
        bad_ports = [x for x in range(1, (cur_cnt + 1) * card_info[1])
                     if x % card_info[1] != 0]
        if card_info[0] > 1:
            bad_ports.append(cur_cnt - 1)  # fail because of order
        bad_ports.append(-1)

        if cur_cnt != card_info[0]:
            raise NtiError('Netdev counts not %d' % (cur_cnt))

        for i in bad_ports:
            self.check_fails_split(i, range(-1, 9))

        for i in range(-1, cur_cnt + 2):
            self.check_fails_unsplit(i)

    def split(self, card_info):
        for i in [x * card_info[1] for x in range(0, card_info[0])]:
            self.dut.devlink_split(i, card_info[1])

        cur_cnt_remain = 0
        for ifc in self.dut_ifn:
            ret, _ = self.dut.cmd('ip link show %s' % ifc, fail=False)
            if ret == 0:
                cur_cnt_remain += 1

        if cur_cnt_remain:
            raise NtiError('Not all netdevs disappeared %d left'
                           % (cur_cnt_remain))

    def reload_driver(self, partno, card_info, split):
        if split:
            media = '_%dx%d' % (card_info[0] * card_info[1], card_info[2])
        else:
            media = '_%dx%d' % (card_info[0], card_info[1] * card_info[2])

        fwname = 'nic_' + partno + media + '.nffw'

        CommonNetdevTest.reload_driver(self, fwname)

    def netdev_execute(self):
        if not self.dut.netdevfw_dir:
            raise NtiSkip('This test requires "netdevfw_dir" in the config')

        # Check for old NSP
        if self.dut.get_nsp_ver(self.dut_ifn[0]) < 15:
            self.check_fails_all(all_speeds)
            return

        supported_splits = {
            "AMDA0081-0001": (1, 4, 10),
            "AMDA0097-0001": (2, 4, 10),
        }

        partno = self.dut.get_hwinfo('assembly.partno')
        cur_cnt = len(self.dut.phys_netdevs)

        # All cards not in supported_splits can't do splits
        if partno not in supported_splits:
            for i in range(-1, cur_cnt + 2):
                self.check_all_fails(i, range(-1, 9))
            return

        card_info = supported_splits[partno]
        n_ports = card_info[0]
        divisor = card_info[1]

        # Make sure all ports have the same count (simplify things)
        if cur_cnt != n_ports and cur_cnt % divisor != 0:
            raise NtiError("Ports don't all have the same split")

        if cur_cnt != n_ports:
            self.unsplit_check(card_info)
            self.unsplit(card_info)
            self.reload_driver(partno, card_info, False)

        self.split_check(card_info)
        self.split(card_info)
        self.reload_driver(partno, card_info, True)
        self.unsplit_check(card_info)

        if cur_cnt == n_ports:
            self.unsplit(card_info)
            self.reload_driver(partno, card_info, False)
            self.split_check(card_info)
