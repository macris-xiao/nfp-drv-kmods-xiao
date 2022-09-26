#
# Copyright (C) 2022 Corigine, Inc. All rights reserved.
#
import re
from netro.testinfra.nti_exceptions import NtiError
from ..common_test import CommonTest


class TestEthtool(CommonTest):
    info = """
    Tests that the `ethtool --test` command functions as expected.
    This is done in four parts, for each interface:
    - The link state of the interface is changed and then compared to the
    output of `ethtool -t` to ensure that the driver is correctly reporting
    the state of the interface.
    - The running firmware is inspected and compared to the output of
    `ethtool -t` to confirm that the driver is correctly reporting
    information regarding the firmware in use.
    - The NSP version is detected and compared to the output of
    `ethtool -t` to confirm that the driver is correctly reporting
    information regarding the NSP
    - It is tested whether or not the register can be used to read
    device details and that this matches the output of `ethtool -t`

    If any of these four steps fails, for any interface, the test will fail.
    """
    def link_test(self, ifc):
        """
        Changes the link state and matches the output
        of ethtool -t.
        """
        M = self.dut

        # Turn port up and check link test output
        M.cmd('ip link set dev %s up' % ifc)

        M.link_wait(ifc)

        test_out = M.ethtool_get_test(ifc, fail=False)
        if test_out['Link'] == 1:
            raise NtiError("Link test failed! Expected a PASS but got a FAIL")

        # Check if the test result (PASS/FAIL) matches
        # the outcome of each test. In this case, we
        # expect the test result to be "PASS" and the
        # outcome count to be 0.
        test_result = test_out['result']
        overall_outcome = test_out['outcome']

        if test_result == "FAIL" or overall_outcome > 0:
            raise NtiError("Expected a PASS but received a FAIL")

        # Turn port down and check link test output
        overall_outcome = 0
        M.cmd('ip link set dev %s down' % ifc)

        test_out = M.ethtool_get_test(ifc, fail=False)
        if test_out['Link'] == 0:
            raise NtiError("Link test failed! Expected a FAIL but got a PASS")

        # Check if the test result (PASS/FAIL) matches
        # the outcome of each test. In this case, we
        # expect the test result to be "FAIL" and the
        # outcome count to be greater than 0.
        test_result = test_out['result']
        overall_outcome = test_out['outcome']

        if test_result == "PASS" or overall_outcome == 0:
            raise NtiError("Expected a FAIL but received a PASS")

        return 0

    def fw_test(self, ifc):
        """
        Test to see if the firmware is loaded and matches the output
        of ethtool -t.
        """
        M = self.dut

        _, loaded = M.nffw_status(fail=False)
        test_out = M.ethtool_get_test(ifc, fail=False)
        if loaded and (test_out['Firmware'] == 1):
            raise NtiError("Firmware is loaded but reported as not loaded!")
        elif not loaded and (test_out['Firmware'] == 0):
            raise NtiError("Firmware is not loaded but reported as loaded!")

        return 0

    def nsp_test(self, ifc):
        """
        Test to see if NSP is detected and matches the output
        of ethtool -t.
        """
        M = self.dut
        nsp_check = True
        bsp_check = True

        # get nsp version
        _, out = M.cmd_nsp("-v")
        sp_ver = out.split()[0]
        sp_ver = sp_ver.split(".")

        if len(sp_ver) != 2:
            nsp_check = False
        if sp_ver[0] != "0":
            nsp_check = False

        # get bsp version
        _, out = M.cmd_nsp("-r")
        ver = out.split()[0]

        # Check for old BSP version e.g. BSP version is
        # 010217.010217.010325, therefore out = 010325
        oldBSP = re.compile(r"[0-9]{6}")
        if ver == oldBSP or ver == "":
            bsp_check = False

        # check if test output is correct
        test_out = M.ethtool_get_test(ifc, fail=False)
        if nsp_check and bsp_check and (test_out['NSP'] == 1):
            raise NtiError("The NSP is detected but reported as not detected!")
        elif (not nsp_check or not bsp_check) and (test_out['NSP'] == 0):
            raise NtiError("NSP check returns %s and BSP check returns %s \
                            but reported as detected!"
                            % (nsp_check, bsp_check))

        return 0

    def reg_test(self, ifc):
        """
        Test to see if the register can read the device details
        and matches the output of ethtool -t.
        """
        M = self.dut

        register_cmd = "xpb:ArmIsldXpbMap.PluXpb.PluMisc.PluDeviceID"
        _, reg_out = M.cmd_reg(register_cmd, fail=False)
        test_out = M.ethtool_get_test(ifc, fail=False)
        if reg_out and (test_out['Register'] == 1):
            raise NtiError("Register is available but reported as \
                            not available")
        elif not reg_out and (test_out['Register'] == 0):
            raise NtiError("Register is not available but reported \
                            as available")

        return 0

    def execute(self):
        for ifc in self.dut.nfp_netdevs:
            self.link_test(ifc)
            self.fw_test(ifc)
            self.nsp_test(ifc)
            self.reg_test(ifc)

    def cleanup(self):
        # set the ports back up for tests that follow
        for ifc in self.dut.nfp_netdevs:
            self.dut.cmd('ip link set dev %s up' % ifc)
            self.dut.link_wait(ifc)
