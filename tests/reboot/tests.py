#
# Copyright (C) 2017,  Netronome Systems, Inc.  All rights reserved.
#
"""
Unit test group for the NFP Linux driver tests which require a reboot.
"""

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
