#
# Copyright (C) 2018,  Netronome Systems, Inc.  All rights reserved.
#
import re
from netro.testinfra import LOG_sec, LOG, LOG_endsec
from netro.testinfra.nti_exceptions import NtiError
from ..common_test import CommonTest

class DrvInfoEthtool(CommonTest):
    def check_common(self, info):
        # Checking that ethtool correctly shows what features the driver
        # supports:
        # It is expected that info (ethtool -i output) will have features set
        # to "yes" and "no" according to what is expected of the driver to
        # support.
        yes = [ "supports-statistics", "supports-test",
                "supports-eeprom-access"]
        no = ["supports-priv-flags" ]

        for i in yes:
            if info[i] != "yes" and i == "supports-test":
                raise NtiError(i + ": " + info[i] + ", expected yes. Driver "
                               + "version is possibly too old. Ensure you have "
                               + "the latest driver installed, newer than July "
                               + "2022.")
            if info[i] != "yes" and i == "supports-eeprom-access":
                raise NtiError(i + ": " + info[i] + ", expected yes. Driver "
                               + "version is possibly too old. Ensure you have "
                               + "the latest driver installed, newer than"
                               + "August 2022.")
            elif info[i] != "yes":
                raise NtiError(i + ": " + info[i] + ", expected yes")
        for i in no:
            if info[i] != "no":
                raise NtiError(i + ": " + info[i] + ", expected no")

        if self.dut.kernel_ver_ge(4, 0) and info["expansion-rom-version"]:
            raise NtiError("Expansion Rom reported")
        if len(info["version"]) < 4:
            raise NtiError("Version not reported")

    def check_common_vnic(self, info):
        if info["supports-register-dump"] != "yes":
            raise NtiError("vNIC without register dump")
        if not info["firmware-version"].startswith("0.0.") and \
           not info["firmware-version"].startswith("1.0."):
            raise NtiError("Bad NFD version")

        self.check_common(info)

    def check_info_repr(self, info):
        LOG("\n\nChecking Representor Info\n")

        if info["driver"] != "nfp":
            raise NtiError("Driver not reported as nfp")
        if info["supports-register-dump"] != "no":
            raise NtiError("Representor with register dump")
        if info["bus-info"] != self.group.pci_dbdf:
            raise NtiError("Incorrect bus info")

        fw_ver = info["firmware-version"].strip().split(' ')
        if len(fw_ver) != 4:
            raise NtiError("FW version has %d items, expected 4" %
                           (len(fw_ver)))

        self.check_common(info)

    def check_info_vf(self, info):
        LOG("\n\nChecking VF Info\n")

        if info["driver"] != "nfp_netvf":
            raise NtiError("Driver not reported as nfp_netvf")
        if not info["bus-info"]:
            raise NtiError("VF without bus info")

        fw_ver = info["firmware-version"].strip().split(' ')
        if len(fw_ver) != 1:
            raise NtiError("FW version has %d items, expected 1" %
                           (len(fw_ver)))

        self.check_common_vnic(info)

    def check_info_pf(self, info):
        LOG("\n\nChecking PF Info\n")

        if info["driver"] != "nfp":
            raise NtiError("Driver not reported as nfp")
        if info["bus-info"] != self.group.pci_dbdf:
            raise NtiError("Incorrect bus info")

        fw_ver = info["firmware-version"].strip().split(' ')
        if len(fw_ver) != 4:
            raise NtiError("FW version has %d items, expected 4" %
                           (len(fw_ver)))

        self.check_common_vnic(info)

    def execute(self):
        new_ifcs = self.spawn_vf_netdev(1)

        for ifc in new_ifcs:
            info = self.dut.ethtool_drvinfo(ifc["name"])
            if info["driver"] == "nfp":
                self.check_info_repr(info)
            elif info["driver"] == "nfp_netvf":
                self.check_info_vf(info)
            else:
                raise NtiError("Driver not reported")

        for ifc in self.dut.nfp_netdevs:
            info = self.dut.ethtool_drvinfo(ifc)
            if info["firmware-version"][0] != "*":
                self.check_info_pf(info)
            else:
                self.check_info_repr(info)
