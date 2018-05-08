#
# Copyright (C) 2017,  Netronome Systems, Inc.  All rights reserved.
#
"""
Unit test group for the NFP Linux driver tests which require a driver reboot.
"""

import os.path
import random
import netro.testinfra
from netro.testinfra.test import *
from ..drv_grp import NFPKmodGrp

###########################################################################
# Unit Tests
###########################################################################

class NFPKmodReboot(NFPKmodGrp):
    """Unit tests for the NFP Linux drivers"""

    summary = "Unit tests used for NFP Linux driver, requiring DUT reboot."

    def __init__(self, name, cfg=None, quick=False, dut_object=None,
                 dut=None, nfp=None, nfpkmods=None, mefw=None):

        NFPKmodGrp.__init__(self, name=name, cfg=cfg, quick=quick,
                            dut_object=dut_object)

    def populate_tests(self):
        dut = (self.dut, self.addr_x, self.eth_x, self.addr_v6_x)
        src = (self.host_a, self.addr_a, self.eth_a, self.addr_v6_a)

        T = (('flash_arm', FlashArm, "Flash arm via ethtool and reboot host"),
        )

        for t in T:
            self._tests[t[0]] = t[1](src, dut, self, t[0], t[2])


import time
from netro.testinfra.nti_exceptions import NtiGeneralError
from netro.testinfra.nrt_result import NrtResult
from netro.testinfra.system import cmd_log
from ..common_test import *
from ..drv_system import DrvSystem

class FlashArm(CommonNetdevTest):
    def flash_test(self, fw_path, fw_name, version, version_idx):

        # Make some garbage binary file based on the actual flash image
        garbage_flash = "/tmp/flash-garbage.bin"
        self.dut.cmd("base64 %s/%s > %s" % (fw_path, fw_name, garbage_flash))

        for ifc in self.nfp_netdevs:
            ret, out = self.dut.cmd("ethtool -f %s ../../%s" %
                                  (ifc, garbage_flash), include_stderr=True,
                                  fail=False)
            if ret == 0:
                raise NtiError("Expected to fail flashing garbage image on interface %s" % \
                               ifc)
            if out[1] != "Flashing failed: Invalid argument\n":
                raise NtiError("Expected EINVAL failure trying to flash garbage file on interface %s. Got %s instead." %
                               (ifc, out))

            ret, out = self.dut.cmd("ethtool -f %s ../../%s/%s 1" %
                                    (ifc, fw_path, fw_name),
                                    include_stderr=True, fail=False)
            if ret == 0:
                raise NtiError("Expected to fail flashing region #1 on interface %s" % \
                               ifc)
            if out[1] != "Flashing failed: Operation not supported\n":
                raise NtiError("Expected EOPNOTSUPP failure trying to flash region #1 on interface %s. Got %s instead." %
                               (ifc, out))

        self.dut.cmd("ethtool -f %s ../../%s/%s" %
                     (self.dut_ifn[0], fw_path, fw_name))
        self.reboot()

        cmd  = 'dmesg | grep "nfp 0000:%s"' % (self.group.pci_id)
        cmd += ' | grep -o "BSP: .*" | cut -c 6- | tail -1 | tr -d "\n"'
        _, ver = self.dut.cmd(cmd)
        comp = ver.split('.')
        if len(comp) != 3:
            raise NtiError('Did not find the expected BSP version string: %s' % \
                           comp)
        if not version is None and not version_idx is None:
            LOG("checking actual version...")
            if comp[version_idx] != version:
                raise NtiError('Incorrect BSP version: %s != %s' % \
                               (comp[version_idx], version))

    def netdev_execute(self):
        self.nsp_min(21)
        fw_path = "/opt/netronome/flash/"
        _, contents = self.dut.cmd("find %s -maxdepth 1 -mindepth 1" % fw_path)

        # We can't determine the version from the actual binary files. So we use
        # the NSP binary file name to infer the version from. This is fine for
        # the NSP version verification, but doesn't help us for flash-one.
        # In that case, we just verify that we can actually flash and it there
        # are no ill effects.

        nsp_version_re = re.search("nfp-nspd-(0\w+).bin", contents)
        if not nsp_version_re:
            raise NtiError("Unable to read NSP version from filename")
        nsp_version = nsp_version_re.groups(1)[0]

        for fw in [["flash-nic.bin", nsp_version, 2],
                   ["flash-one.bin", None, None]]:

            fmatch = re.search(fw[0], contents)
            if not fmatch:
                raise NtiSkip("Test requires BSP package installed with access to the %s" % \
                              fw[0])

            self.flash_test(fw_path, fw[0], fw[1], fw[2])
