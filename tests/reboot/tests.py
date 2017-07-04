#
# Copyright (C) 2017,  Netronome Systems, Inc.  All rights reserved.
#
"""
Unit test group for the NFP Linux driver tests which require a reboot.
"""

import random
import netro.testinfra
from netro.testinfra.test import *
from ..drv_grp import NFPKmodGrp

###########################################################################
# Unit Tests
###########################################################################

class NFPKmodReboot(NFPKmodGrp):
    """Unit tests for the NFP Linux drivers"""

    summary = "Unit tests used for NFP Linux driver."

    def __init__(self, name, cfg=None, quick=False, dut_object=None,
                 dut=None, nfp=None, nfpkmods=None, mefw=None):

        NFPKmodGrp.__init__(self, name=name, cfg=cfg, quick=quick,
                            dut_object=dut_object)

    def populate_tests(self):
        dut = (self.dut, self.addr_x, self.eth_x, self.addr_v6_x)
        src = (self.host_a, self.addr_a, self.eth_a, self.addr_v6_a)

        T = (('set_speed', SpeedSet, "Flip speed and reboot machine"),
             ('port_split', DevlinkSplit,
              "Split/unspliet port and reboot in between"),
        )

        for t in T:
            self._tests[t[0]] = t[1](src, dut, self, t[0], t[2])


import time
from netro.testinfra.nti_exceptions import NtiGeneralError
from netro.testinfra.nrt_result import NrtResult
from netro.testinfra.system import cmd_log
from ..common_test import *
from ..drv_system import DrvSystem

class SpeedSet(CommonNetdevTest):
    def check_fails(self, ifc, all_speeds, skip_speeds=[]):
        for speed in all_speeds:
            if speed in skip_speeds:
                continue

            ret, out = self.dut.ethtool_set_speed(ifc, speed, fail=False)
            if out[1].find('not setting speed') == -1:
                raise NtiError('Set %s speed to %d did not fail' %
                               (ifc, speed))

    def check_fails_all(self, all_speeds, skip_speeds=[]):
        for ifc in self.dut_ifn:
            self.check_fails(ifc, all_speeds, skip_speeds)

    def netdev_execute(self):
        all_speeds = ( 0, 1, 1237, 10000, 25000, 40000 )

        # Check for old NSP
        if self.dut.get_nsp_ver(self.dut_ifn[0]) < 15:
            self.check_fails_all(all_speeds)
            return

        supported_speeds = {
            "AMDA0099-0001"	:	( 25000, 10000 ),
        }

        partno = self.dut.get_hwinfo('assembly.partno')

        self.ifc_skip_if_not_all_up()

        # All cards not in supported_speeds can't do ethtool speed setting
        if not partno in supported_speeds:
            for ifc in self.dut_ifn:
                cur_speed = self.dut.ethtool_get_speed(ifc)
                self.check_fails(ifc, all_speeds, [cur_speed])
            return

        # Make sure all ports have the same speed (simplify things)
        cur_speed = self.dut.ethtool_get_speed(self.dut_ifn[0])
        for ifc in self.dut_ifn[1:]:
            if cur_speed != self.dut.ethtool_get_speed(ifc):
                raise NtiError("Ports don't all have the same speed")

        speeds = supported_speeds[partno]
        if cur_speed not in speeds:
            raise NtiError("Speed %d is not on the supported list" % speed)

        for i in range(len(self.dut_ifn)):
            at_speed = self.dut.nfp_phymod_get_speed(i)
            if at_speed != cur_speed:
                raise NtiError("Phymod and ethtool speed mismatch (%d vs %d)" %
                               (at_speed, speed))

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
            if speeds[0] == supported_speeds[partno][0]:
                ifc_list = list(reversed(ifc_list))

            for ifc in ifc_list:
                ret, out = self.dut.ethtool_set_speed(ifc, speeds[0])
                if out[1].find('not setting speed') != -1:
                    raise NtiError('Failed to set %s speed to %d' %
                                   (ifc, speeds[0]))

                # Make sure port disappears
                time.sleep(3) # Refresh of eth table may take some time
                ret, _ = self.dut.cmd('ifconfig %s' % (ifc), fail=False)
                if ret == 0:
                    raise NtiError("Netdev didn't disappear")

            self.reboot()

            self.ifc_skip_if_not_all_up()

            for i in range(len(self.dut_ifn)):
                ifc = self.dut_ifn[i]

                at_speed = self.dut.nfp_phymod_get_speed(i)
                if at_speed != speeds[0]:
                    raise NtiError('Phymod speed not %d after reboot on %s' %
                                   (speeds[0], ifc))

                at_speed = self.dut.ethtool_get_speed(ifc)
                if at_speed != speeds[0]:
                    raise NtiError('Speed not %d after reboot on %s' %
                                   (speeds[0], ifc))

            # Check if we are back to where we started
            if speeds[0] == cur_speed:
                return
            speeds = speeds[1:] + speeds[:1]

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
        cur_cnt = self.dut.count_our_netdevs()
        bad_ports = range(cur_cnt, cur_cnt + 2)
        if card_info[0] > 1:
            bad_ports.append(0) # fail because of order
        bad_ports.append(-1)

        if cur_cnt != card_info[0] * card_info[1]:
            raise NtiError('Netdev counts not %d' % (cur_cnt))

        for i in range(-1, cur_cnt + 2):
            self.check_fails_split(i, range(-1, 9))

        for i in bad_ports:
            self.check_fails_unsplit(i)

    def unsplit(self, card_info):
        for i in list(reversed(range(0, card_info[0]))):
            # Pick the unsplit port at random.
            idxs = range(i * card_info[1], (i + 1) * card_info[1])
            self.dut.devlink_unsplit(random.choice(idxs))

        cur_cnt = self.dut.count_our_netdevs()
        if cur_cnt:
            raise NtiError('Not all netdevs disappeared %d left' % (cur_cnt))

    def split_check(self, card_info):
        cur_cnt = self.dut.count_our_netdevs()
        bad_ports = [x for x in range(1, (cur_cnt + 1) * card_info[1])
                        if x % card_info[1] != 0]
        if card_info[0] > 1:
            bad_ports.append(cur_cnt - 1) # fail because of order
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

        cur_cnt = self.dut.count_our_netdevs()
        if cur_cnt:
            raise NtiError('Not all netdevs disappeared %d left' % (cur_cnt))

    def reboot(self, partno, card_info, split):
        if split:
            media = '_%dx%d' % (card_info[0] * card_info[1], card_info[2])
        else:
            media = '_%dx%d' % (card_info[0], card_info[1] * card_info[2])

        fwname = 'nic_' + partno + media + '.nffw'

        CommonNetdevTest.reboot(self, fwname)

    def netdev_execute(self):
        if not self.dut.netdevfw_dir:
            raise NtiSkip('This test requires "netdevfw_dir" in the config')

        # Check for old NSP
        if self.dut.get_nsp_ver(self.dut_ifn[0]) < 15:
            self.check_fails_all(all_speeds)
            return

        supported_splits = {
            "AMDA0081-0001"	:	(1, 4, 10),
            "AMDA0097-0001"	:	(2, 4, 10),
        }

        partno = self.dut.get_hwinfo('assembly.partno')
        cur_cnt = self.dut.count_our_netdevs()

        # All cards not in supported_splits can't do splits
        if not partno in supported_splits:
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
            self.reboot(partno, card_info, False)

        self.split_check(card_info)
        self.split(card_info)
        self.reboot(partno, card_info, True)
        self.unsplit_check(card_info)

        if cur_cnt == n_ports:
            self.unsplit(card_info)
            self.reboot(partno, card_info, False)
            self.split_check(card_info)
