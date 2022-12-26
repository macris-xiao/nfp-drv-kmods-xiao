#
# Copyright (C) 2016-2017,  Netronome Systems, Inc.  All rights reserved.
#
"""
Unit test group for the NFP Linux drivers.
"""

import os
import re
import time
from random import shuffle
from netro.testinfra.nti_exceptions import NtiGeneralError
from netro.testinfra.nrt_result import NrtResult
from netro.testinfra.system import cmd_log
from netro.testinfra.test import *
from ..reconfig_test import ReconfigTest
from ..drv_grp import NFPKmodGrp

###########################################################################
# Unit Tests
###########################################################################

class ChannelReconfig(ReconfigTest):
    """Test class for channel reconfiguration"""
    # Information applicable to all subclasses
    _gen_info = """
    Test ring reconfiguration via ethtool
    """

    def reconfig_execute(self):
        # Check if DebugFS has the right number of directories
        out = self.dut.dfs_nn_port_lines('ls', 'queue/rx/')
        if int(out) != self.orig['ring_max_rx']:
            raise NtiGeneralError("DebugFS wrong dir cnt:%s expect:%d" %
                                  (out, self.orig['ring_max_rx']))

        out = self.dut.dfs_nn_port_lines('ls', 'queue/rx/')
        if int(out) != self.orig['ring_max_tx']:
            raise NtiGeneralError("DebugFS wrong dir cnt:%s expect:%d" %
                                  (out, self.orig['ring_max_tx']))

        out = self.dut.dfs_nn_port_lines('ls', 'queue/rx/')
        if int(out) != self.orig['ring_max_rx']:
            raise NtiGeneralError("DebugFS wrong dir cnt:%s expect:%d" %
                                  (out, self.orig['ring_max_rx']))

        # Check configurations which should be refused
        bad = ((1, 1, 1), # both separate and combined - not supported
               (1, 1, 0), # both separate - not supported
               (1, 0, 0), # no tx queues
               (0, 0, 0), # no queues
               (0, 0, self.orig['ring_max_comb'] + 1),
               (self.orig['ring_max_rx'] - self.orig['ring_max_comb'] + 1,
                0,
                self.orig['ring_max_comb']),
               (0,
                self.orig['ring_max_tx'] - self.orig['ring_max_comb'] + 1,
                self.orig['ring_max_comb']))

        for t in bad:
            ret, _ = self.set_ring_config(t)
            if ret == 0:
                raise NtiGeneralError("Bad config rx %d tx %d comb %d accepted"
                                      % t)

        # Now check good ones
        good = ((1, 0, 1),
                (0, 1, 1),
                (0, 0, 1),
                (0, 0, self.orig['ring_max_comb']),
                (self.orig['ring_max_rx'] - self.orig['ring_max_comb'],
                 0,
                 self.orig['ring_max_comb']),
                (0,
                 self.orig['ring_max_tx'] - self.orig['ring_max_comb'],
                 self.orig['ring_max_comb']))

        # These only work if there is more than 1 vector
        good_ext = (
            (self.orig['ring_max_rx'] - self.orig['ring_max_comb'] + 1,
             0,
             self.orig['ring_max_comb'] - 1),
            (0,
             self.orig['ring_max_tx'] - self.orig['ring_max_comb'] + 1,
             self.orig['ring_max_comb'] - 1))

        if self.orig['ring_max_comb'] > 1:
            good = good + good_ext

        for t in good:
            ret, _ = self.set_ring_config(t)
            if ret != 0:
                raise NtiGeneralError("Good config rx %d tx %d comb %d rejected"
                                      % t)

            self.check_ring_config()

        # Check if things get updated if device is down
        down_up = ((0, 0, 1),
                   (0, 0, self.orig['ring_max_comb']),
                   (self.orig['ring_max_rx'] - self.orig['ring_max_comb'],
                    0,
                    self.orig['ring_max_comb']),
                   (0,
                    self.orig['ring_max_tx'] - self.orig['ring_max_comb'],
                    self.orig['ring_max_comb']))

        for t in down_up:
            self.dut.ip_link_set_down(self.dut_ifn[0])

            ret, _ = self.set_ring_config(t)
            if ret != 0:
                raise NtiGeneralError("Good config rx %d tx %d comb %d rejected"
                                      % t)

            self.dut.ip_link_set_up(self.dut_ifn[0])

            self.check_ring_config()

        # Now try some configurations with XDP
        if not self.has_xdp:
            return

        ret, _ = self.set_ring_config((0, 0, 1))
        self.refresh_ring_config()
        if ret != 0:
            raise NtiError("Trivial 0,0,1 config (for XDP) rejected")
        self.set_xdp_prog("pass")

        xdp_bad = bad
        if self.total_tx_rings < self.orig['ring_max_rx'] + self.orig['ring_max_tx']:
            xdp_bad = bad + ((self.orig['ring_max_rx'] - self.orig['ring_max_comb'],
                              self.orig['ring_max_tx'] - self.orig['ring_max_comb'],
                              self.orig['ring_max_comb']),)

        self.log('all', xdp_bad)
        for t in xdp_bad:
            self.log('try', t)
            ret, _ = self.set_ring_config(t)
            if ret == 0:
                raise NtiGeneralError("Bad config rx %d tx %d comb %d accepted"
                                      % t)

        for t in good:
            if self.total_tx_rings < t[0] + t[1] + t[2] * 2:
                continue
            ret, _ = self.set_ring_config(t)
            if ret != 0:
                raise NtiError("Good config rx %d tx %d comb %d rejected" % t)

            self.check_ring_config()

        self.set_xdp_prog()

        # Unloaded, check again
        for t in bad:
            ret, _ = self.set_ring_config(t)
            if ret == 0:
                raise NtiGeneralError("Bad config rx %d tx %d comb %d accepted"
                                      % t)

        for t in good:
            ret, _ = self.set_ring_config(t)
            if ret != 0:
                raise NtiGeneralError("Good config rx %d tx %d comb %d rejected"
                                      % t)

            self.check_ring_config()
