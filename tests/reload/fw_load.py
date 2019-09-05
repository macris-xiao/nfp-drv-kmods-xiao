#
# Copyright (C) 2019,  Netronome Systems, Inc.  All rights reserved.
#

import time
import netro.testinfra
from netro.testinfra.test import *
from netro.testinfra.nti_exceptions import NtiGeneralError
from ..common_test import CommonTest

class KernelLoadTest(CommonTest):
    def load_test(self, name):
        M = self.dut

        M.cp_to(self.group.netdevfw, '/lib/firmware/netronome/%s' % name)

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

        for ifc in new_ifcs:
            # Ignore possible VF/PF representors and vNICs, but bring them up.
            # One of them may be our CPU port.
            if ifc not in self.dut_ifn:
                self.dut.cmd('ifconfig %s up' % (ifc))
                continue

            i = self.dut_ifn.index(ifc)
            M.cmd('ifconfig %s %s up' % (ifc, self.dut_addr[i]))

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

        M.rmmod()
        M.cmd('rm /lib/firmware/netronome/%s' % (name))

    def execute(self):
        M = self.dut

        M.cmd('mkdir -p /lib/firmware/netronome')

        self.load_test(M.get_fw_name_any())

    def cleanup(self):
        self.dut.cmd('rm -rf /lib/firmware/netronome')
        self.dut.reset_mods()
