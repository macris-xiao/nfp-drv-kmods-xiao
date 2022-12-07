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
             ('kexec_traffic', KexecWithTraffic, "Run kexec with traffic flowing"),
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
    def flash_test(self, fw_path, fw_name, version):

        # Make some garbage binary file based on the actual flash image
        garbage_flash = "/lib/firmware/flash-garbage.bin"
        self.dut.cmd("base32 %s%s > %s" % (fw_path, fw_name, garbage_flash))
        self.dut.cmd("yes | cp %s%s /lib/firmware/" % (fw_path, fw_name))

        if not self.dut.kernel_ver_lt(5, 1):

            for ifc in self.nfp_netdevs:
                ret, out = self.dut.cmd("devlink dev flash pci/0000:%s file flash-garbage.bin" %
                                        (self.group.pci_id), include_stderr=True,
                                        fail=False)
                if ret == 0:
                    raise NtiError("Expected to fail flashing garbage image on interface %s" % \
                                    ifc)

                _, out = self.dut.cmd('dmesg | grep "nfp 0000:%s" | tail -5' % (self.group.pci_id))
                if "nfp_nsp: Result (error) code set: -8 (1) command: 11" not in out:
                    raise NtiError("Expected failure trying to flash garbage file on interface %s. Got %s instead." %
                                    (ifc, out))

                ret, out = self.dut.cmd("devlink dev flash pci/0000:%s file %s component 1" %
                                        (self.group.pci_id, fw_name),
                                        include_stderr=True, fail=False)

                if ret == 0:
                    raise NtiError("Expected to fail flashing region #1 on interface %s" % \
                                    ifc)

                if out[1] != "Error: component update is not supported by this device.\n":
                    raise NtiError("Expected EOPNOTSUPP failure trying to flash region #1 on interface %s. Got %s instead." %
                                    (ifc, out))

            self.dut.cmd("devlink dev flash pci/0000:%s file %s" %
                         (self.group.pci_id, fw_name))
            self.reboot()

        else:
            for ifc in self.nfp_netdevs:
                ret, out = self.dut.cmd("ethtool -f %s flash-garbage.bin" %
                                        (ifc), include_stderr=True,
                                        fail=False)
                if ret == 0:
                    raise NtiError("Expected to fail flashing garbage image on interface %s" % \
                                    ifc)
                if not re.match("Flashing failed", out[1]):
                    raise NtiError("Expected failure trying to flash garbage file on interface %s. Got %s instead." %
                                    (ifc, out))
                ret, out = self.dut.cmd("ethtool -f %s %s 1" %
                                        (ifc, fw_name),
                                        include_stderr=True, fail=False)
                _, flash_confirm = self.dut.cmd("dmesg --level=info | tail -n 1")

                if "Finished writing flash image" not in flash_confirm:
                    if ret == 0:
                        raise NtiError("Expected to fail flashing region #1 on interface %s" % \
                                        ifc)
                    if out[1] != "Flashing failed: Operation not supported\n":
                        raise NtiError("Expected EOPNOTSUPP failure trying to flash region #1 on interface %s. Got %s instead." %
                                        (ifc, out))

            self.dut.cmd("ethtool -f %s %s" %
                         (self.dut_ifn[0], fw_name))
            self.reboot()

        # Check that correct BSP for this test is used
        self.check_bsp_min(version)

    def netdev_execute(self):
        self.check_nsp_min(21)
        fw_path = "/opt/netronome/flash/"
        flash_images = []
        _, contents = self.dut.cmd("find %s -maxdepth 1 -mindepth 1" % fw_path)

        # We can't determine the version from the actual binary files. So we use
        # the NSP binary file name to infer the version from. This is fine for
        # the NSP version verification, but doesn't help us for flash-one.
        # In that case, we just verify that we can actually flash and it there
        # are no ill effects.

        # Default branch BSP uses flash-boot.bin instead of flash-nic/flash-one
        # images.
        nsp_version_re = re.findall("flash-boot-([\w|\d\.-]*)\.bin", contents)
        if nsp_version_re:
            if nsp_version_re[0] != 'raw':
                nsp_version = nsp_version_re[0]
            else:
                nsp_version = nsp_version_re[1]
            flash_images.append(["flash-boot.bin", nsp_version, 1])
        else:
            nsp_version_re = re.search("nfp-nspd-([\w|\d\.-]*)\bin", contents)
            if not nsp_version_re:
                raise NtiError("Unable to read NSP version from filename")
            nsp_version = nsp_version_re.groups(1)[0]
            flash_images.append(["flash-nic.bin", nsp_version, 2])
            flash_images.append(["flash-one.bin", None, None])

        for fw in flash_images:
            fmatch = re.search(fw[0], contents)
            if not fmatch:
                raise NtiSkip("Test requires BSP package installed with access to the %s" % \
                              fw[0])

            self.flash_test(fw_path, fw[0], fw[1])

class KexecWithTraffic(CommonNetdevTest):
    def prepare(self):
        return self.tool_required("kexec", "kexec-tools")

    def netdev_execute(self):
        self.dut.cmd('kexec -l /boot/vmlinuz-$(uname -r) --ramdisk='
                     '/boot/initramfs-$(uname -r).img --reuse-cmdline')

        time.sleep(5)

        if not self.group.upstream_drv:
            uptime = self.dut.get_nsp_uptime()

        # Ensure connectivity
        self.ping(0)

        # Flood with traffic while executing kexec
        pidfile = self.src.spawn_netperfs(self.group.addr_x[0][:-3])
        time.sleep(5)
        self.dut.bg_proc_start("kexec -xe", fail=False)

        time.sleep(5)
        self.ping(0, should_fail=True)

        # Many of the netperf's may have died already
        self.kill_pidfile(self.src, pidfile)

        self.dut.wait_online()
        self.reinit_test()

        # If we have CPP access, we can check the state of the NFP to determine
        # if this was a full reboot or only a kexec
        if not self.group.upstream_drv:
            self.dut.insmod(netdev=False, userspace=True)
            if self.dut.get_nsp_uptime() < uptime:
                raise NtiError("NFP state has been reset, failed kexec")
            self.dut.rmmod()

        self.netdev_prep()
        time.sleep(5)
        # Check we can still pass traffic after kexec
        self.ping(0)

    def cleanup(self):
        self.dut.bg_proc_stop_all()
        self.src.bg_proc_stop_all()

        super(KexecWithTraffic, self).cleanup()
