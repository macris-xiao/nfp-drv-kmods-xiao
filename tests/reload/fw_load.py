#
# Copyright (C) 2019,  Netronome Systems, Inc.  All rights reserved.
#

import os
import time
import netro.testinfra
from netro.testinfra.test import *
from netro.testinfra.nti_exceptions import NtiGeneralError
from ..common_test import CommonTest, NtiSkip


class KernelLoadTest(CommonTest):
    def load_test(self, expect_dummy, expect_reset):
        M = self.dut

        M.cmd('dmesg --read-clear')
        M.refresh()
        netifs_old = M._netifs
        M.insmod(netdev=None)
        time.sleep(1)
        M.refresh()
        netifs_new = M._netifs

        if len(netifs_new) - len(netifs_old) < len(self.dut_addr):
            raise NtiGeneralError('Expected %d interfaces created, got %d' %
                                  (len(self.dut_addr),
                                   len(netifs_new) - len(netifs_old)))

        new_ifcs = list(set(netifs_new) - set(netifs_old))

        not_present = filter(lambda x: x not in new_ifcs, self.dut_ifn)
        if len(not_present):
            raise NtiError("Interfaces not present after load: " +
                           str(not_present))

        # We don't have a clean way to assert whether a soft reset has taken
        # place, especially with our upstream driver, so scrape dmesg to
        # determine whether the event occurred
        _, msgs = M.cmd('dmesg --read-clear')
        reset = re.search('%s.*soft-?reset.*nfp' % self.group.pci_id, msgs,
                          re.IGNORECASE)
        if not reset and expect_reset:
            raise NtiError("Expected soft reset but didn't detect it")
        if reset and not expect_reset:
            raise NtiError("Unexpected soft reset detected")

        # The dummy NFD firmware does not have operational vNICs so skip the
        # interface tests
        info = self.dut.ethtool_drvinfo(self.dut_ifn[0])
        fw_name = info["firmware-version"].strip().split(' ')[2]
        if expect_dummy:
            if fw_name != 'TEST_FW_1234567':
                raise NtiError("Expected dummy firmware loaded")

            self.dut.reset_mods()
            return
        elif fw_name == 'TEST_FW_1234567':
            raise NtiError("Didn't expect dummy firmware to be loaded")

        for ifc in new_ifcs:
            # Ignore possible VF/PF representors and vNICs, but bring them up.
            # One of them may be our CPU port.
            if ifc not in self.dut_ifn:
                M.ip_link_set_up(ifc)
                continue

            i = self.dut_ifn.index(ifc)
            M.ip_link_set_up(ifc)
            M.cmd('ip addr add dev %s %s' % (ifc, self.dut_addr[i]))

        for ifc in self.dut_ifn:
            self.dut.link_wait(ifc)

        for ifc in self.dut_ifn:
            i = self.dut_ifn.index(ifc)
            self.ping(i)

        # See if after kernel load SR-IOV limit was set correctly
        max_vfs = self.read_scalar_nffw('nfd_vf_cfg_max_vfs')
        ret, _ = M.cmd('echo %d > /sys/bus/pci/devices/0000:%s/sriov_numvfs' %
                       (max_vfs + 1, self.group.pci_id), fail=False)
        if not ret:
            raise NtiGeneralError('SR-IOV VF limit not obeyed')

        M.reset_mods()

    def execute(self):
        M = self.dut

        if self.dut.get_pci_device_id() != '3800':
            self.spi_bus = 0
            fw_suffix = '_nfp-4xxx-b0'
        else:
            self.spi_bus = 1
            fw_suffix = '_nfp-38xxc'

        tests = [
            # HWinfo keys, expect dummy FW, expect explicit soft reset
            ('app_fw_from_flash=0 abi_drv_reset=0',   False,   True),
            ('app_fw_from_flash=1 abi_drv_reset=0',   True,    True),
            ('app_fw_from_flash=2 abi_drv_reset=0',   True,    True),
            ('app_fw_from_flash=0 abi_drv_reset=1',   False,   True),
            ('app_fw_from_flash=1 abi_drv_reset=1',   True,    True),
            ('app_fw_from_flash=2 abi_drv_reset=1',   True,    True),
            ('app_fw_from_flash=0 abi_drv_reset=2',   False,   False),
            ('app_fw_from_flash=1 abi_drv_reset=2',   True,    False),
            ('app_fw_from_flash=2 abi_drv_reset=2',   True,    False),
        ]

        M.cmd('mkdir -p /lib/firmware/netronome')
        M.cp_to(self.group.netdevfw,
                '/lib/firmware/netronome/%s' % M.get_fw_name_any())
        M.cp_to(os.path.join(self.group.mefw, 'dummy_nfd%s.nffw' % fw_suffix),
                self.dut.tmpdir)

        # Base case, executable on both upstream and oot drivers
        LOG_sec('Baseline FW load test')
        try:
            self.load_test(False, True)
        finally:
            LOG_endsec()

        # Need at least hwinfo string lookup and FW loaded commands
        if self.group.upstream_drv:
            raise NtiSkip('Cannot test more complex FW loading scenarios '
                          'upstream')

        M.insmod(netdev=False, userspace=True)
        self.check_nsp_min(26)

        _, phy = self.dut.cmd_phymod('-E | grep "^eth"')
        phy = phy.strip().split('\n')
        if len(phy) != 2:
            raise NtiSkip('Sample FW only supports 2 port cards')

        fw_path = os.path.join(self.dut.tmpdir, 'dummy_nfd%s.nffw' % fw_suffix)
        M.cmd_fis('-b %d delete nti.fw' % self.spi_bus, fail=False)
        M.cmd_fis('-b %d -b0 init' % self.spi_bus)
        M.cmd_fis('-b %d create -b %s nti.fw' % (self.spi_bus, fw_path))
        M.cmd_hwinfo('-u mefw.loadbus=%d appfw.part=nti.fw' % self.spi_bus)

        for arg in tests:
            LOG_sec('FW load with: %s' % arg[0])
            try:
                M.cmd_hwinfo('-u %s' % arg[0])

                M.reset_mods()
                self.load_test(arg[1], arg[2])

                M.insmod(netdev=False, userspace=True)
            finally:
                LOG_endsec()

    def cleanup(self):
        self.dut.cmd('rm -rf /lib/firmware/netronome')

        if not self.group.upstream_drv:
            self.dut.reset_mods()
            self.dut.insmod(netdev=False, userspace=True)
            self.dut.cmd_hwinfo('-u mefw.loadbus= appfw.part=')
            self.dut.cmd_hwinfo('-u app_fw_from_flash= abi_drv_reset=')
            self.dut.cmd_fis('-b %d delete nti.fw' % self.spi_bus, fail=False)

        for ifc in self.src_ifn:
            self.src.cmd('ip a flush %s ' % ifc)

        self.dut.reset_mods()
        return super(KernelLoadTest, self).cleanup()
