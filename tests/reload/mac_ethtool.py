#
# Copyright (C) 2022,  Corigine, Inc.  All rights reserved.
#
from netro.testinfra.nti_exceptions import NtiError
from ..common_test import CommonNetdevTest
import random
import os


class EthtoolMac(CommonNetdevTest):
    info = """
    Tests that the ethtool -E command functions as expected.
    The original mac address is stored, while a new mac
    address is generated. The new mac address is then set
    using the ethtool -E command. A cleanup sets
    it back to the original mac address.
    """
    original_dut_mac = {}
    new_dut_mac = {}

    def netdev_execute(self):
        """
        Record the original MAC address of the dst interface. Then generate
        a new MAC address that should be assigned to the PF.
        Check that the MAC address can be changed with ethtool -E.
        """
        M = self.dut

        # Get firmware name
        fwname = M.get_fw_name(load_drv=False)

        # Get magic number
        magic_num = self.get_magic_num()

        for ifc in self.dut_ifn:
            # Save the original mac addresses
            r, self.original_dut_mac[ifc] = M.cmd('cat \
                                                  /sys/class/net/%s/address'
                                                  % (ifc))
            self.original_dut_mac[ifc] = self.original_dut_mac[ifc].strip()

            # Generate new MAC addresses
            new_dut_mac = "02:00:00:%02x:%02x:%02x" % (random.randint(0, 255),
                                                       random.randint(0, 255),
                                                       random.randint(0, 255))
            self.new_dut_mac[ifc] = new_dut_mac

            # Test for incorrect inputs
            # Out of range offset
            offset = 9
            out, _ = M.ethtool_set_mac(ifc, magic_num, self.new_dut_mac[ifc],
                                       offset=offset, fail=False)
            if out == 0:
                raise NtiError("An out of range offset did not produce a FAIL")

            # Incorrect magic number
            incorrect_magic_num = "0x20"
            out, _ = M.ethtool_set_mac(ifc, incorrect_magic_num,
                                       self.new_dut_mac[ifc],
                                       fail=False)
            if out == 0:
                raise NtiError("An incorrect magic number did not \
                               produce a FAIL")

            # Test with correct inputs
            # Set the interface mac address to the new mac address
            M.ethtool_set_mac(ifc, magic_num, self.new_dut_mac[ifc])
            M.netifs[ifc].mac = self.new_dut_mac[ifc]

        self.reload_drv(fwname)

        # Second for loop to avoid reloading the driver multiple
        # times. The loop below checks if the mac address has
        # been set. A ping test can be added as a future check.
        for ifc in self.dut_ifn:
            # Check that the mac address on the interface is correct
            self.check_mac(ifc, self.new_dut_mac[ifc])

            # Check that the dst is pingable after MAC change
            # TODO: Add ip addresses and ping test

    def get_magic_num(self):
        # Returns the magic number in the form of:
        # 0x<device_id><vendor_id>
        ven_id = self.dut.get_vendor_id()
        device_id = self.dut.get_pci_device_id()

        magic_num = "0x" + device_id + ven_id

        return magic_num

    def check_mac(self, ifc, expected_mac):
        expected_mac = expected_mac.replace(':', '')
        # Execute at src/dst depending on string

        # Get the MAC address of src interface
        r, ethtool_mac = self.dut.cmd('ethtool -e %s offset 0 length 6 | '
                                      'awk -F ":\t\t" \'FNR == 3 '
                                      '{{print $2}}\'' % ifc)
        r, cat_show_mac = self.dut.cmd('cat /sys/class/net/%s/address' % ifc)

        # Clean cmd output
        ethtool_mac = ethtool_mac.strip()
        ethtool_mac = ethtool_mac.replace(' ', '')
        cat_show_mac = cat_show_mac.strip()
        cat_show_mac = cat_show_mac.replace(':', '')

        # Compare the MAC address with the expected MAC address
        if ethtool_mac != expected_mac:
            msg = 'Incorrect MAC address returned by "ethtool -e".'
            raise NtiError(msg)
        elif cat_show_mac != expected_mac:
            msg = 'Incorrect MAC address found in ' \
                  '"/sys/class/net/%s/address".' % ifc
            raise NtiError(msg)

    def reload_drv(self, fwname):
        # Get firmware path (tmpxxx/nic_AMDAxxx)
        fwpath = os.path.join(self.dut.tmpdir, fwname)

        # Reload driver
        self.dut.reset_mods()
        self.dut.insmod(netdev=False, userspace=True)

        # Reload firmware
        self.dut.nffw_unload()
        self.dut.nffw_load(fwpath)

        # Reload driver
        self.dut.rmmod()
        self.dut.insmod(netdev=True, userspace=True)

    def cleanup(self):
        """
        Execute the Ethtool_E_MAC cleanup
        """
        # Restore the original MAC addresses
        fwname = self.dut.get_fw_name(load_drv=False)

        # Check if any mac addresses were stored

        # Restore all mac addresses for all interfaces
        for ifc in self.original_dut_mac.keys():
            magic_num = self.get_magic_num()
            self.dut.ethtool_set_mac(ifc, magic_num,
                                     self.original_dut_mac[ifc])
            self.dut.netifs[ifc].mac = self.original_dut_mac[ifc]

        self.reload_drv(fwname)

        for ifc in self.original_dut_mac.keys():
            # Check that the mac addresses on the dst interface is correct
            self.check_mac(ifc, self.original_dut_mac[ifc])

        return super(EthtoolMac, self).cleanup()
