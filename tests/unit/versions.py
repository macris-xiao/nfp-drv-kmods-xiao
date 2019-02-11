#
# Copyright (C) 2019,  Netronome Systems, Inc.  All rights reserved.
#
"""
Unit test group for devlink info (versions) reporting.
"""

import os
from ..common_test import CommonNonUpstreamTest, assert_eq

class VersionsTest(CommonNonUpstreamTest):
    def netdev_execute(self):
        self.nsp_min(28)

        _, info = self.dut.devlink_get_info("pci/" + self.group.pci_dbdf)
        assert_eq(info["driver"], "nfp", "Driver name")

        # Serial
        assert_eq(info["serial_number"],
                  self.dut.get_hwinfo("assembly.vendor") +
                  self.dut.get_hwinfo("assembly.partno") +
                  self.dut.get_hwinfo("assembly.serial"),
                  "Board serial")

        # Fixed versions
        fixed = info["versions"]["fixed"]
        assert_eq(fixed["board.id"], self.dut.get_hwinfo("assembly.partno"),
                  "Board model")
        assert_eq(fixed["board.rev"], self.dut.get_hwinfo("assembly.revision"),
                  "Board revision")
        assert_eq(fixed["board.vendor"], self.dut.get_hwinfo("assembly.vendor"),
                  "Board vendor")
        assert_eq(fixed["board.model"], self.dut.get_hwinfo("assembly.model"),
                  "Board name")

        # Running
        matches = [("bsp.version", "fw.mgmt"),
                   ("cpld.version", "fw.cpld"),
                   ("app.version", "fw.app")]

        # Parse the nfp-nsp output
        _, vers = self.dut.cmd_nsp("-Q")
        nsp = { "running" : dict(), "stored" : dict() }
        for l in vers.split('\n'):
            vals = l.split(':\t')
            if len(vals) != 2:
                continue
            if vals[0][-7:] == "running":
                nsp["running"][vals[0][:-8]] = vals[1]
            elif vals[0][-7:] == "flashed":
                nsp["stored"][vals[0][:-8]] = vals[1]

        # Compare
        for m in matches:
            for k in ("running", "stored"):
                assert_eq(nsp[k][m[0]], info["versions"][k][m[1]],
                          "Checking NSP %s vs devlink %s (%s)" %
                          (m[0], m[1], k))

    def cleanup(self):
        self.dut.reset_mods()
        return super(VersionsTest, self).cleanup()
