#
# Copyright (C) 2016,  Netronome Systems, Inc.  All rights reserved.
#
"""
Base for all driver test groups.
"""

import collections
import os
import re

import netro.testinfra
from netro.testinfra import LOG_sec, LOG_endsec
from netro.testinfra.nti_exceptions import *
from libs.nrt_system import NrtSystem
from libs.nrt_system import kill_bg_process
from drv_system import *


###############################################################################
# A group of unit tests
###############################################################################
class NFPKmodGrp(netro.testinfra.Group):
    """Simple unit tests group"""

    summary = "NFPKmodGrp tests"

    _info = """
    Run a barrage of simple unit tests against an NFP configured as
    Just-a-NIC. The tests are designed to test particular aspects of
    the driver.

    The test configuration looks like this:

                     DUT
                 ethX
                  ^
    Host A        |
      ethA <------+

    The kernel module can also be optionally copied from the controller to
    the DUT and loaded before tests are run. Also, the standard BSP kernel
    modules as well as the ME firmware image can optionally be copied
    and loaded prior to running any tests.

    """

    _config = collections.OrderedDict()
    _config["General"] = collections.OrderedDict([
        ('noclean', [False, "Don't clean the systems after a run (default "
                            "False). Useful for debugging test failures."])])
    _config["DUT"] = collections.OrderedDict([
        ("name", [True, "Host name of the DUT (can also be <user>@<host> or "
                        "IP address). Assumes root as default."]),
        ("addrX", [True, "IPv4 address/mask to be assigned to ethX"]),
        ("addr6X", [True, "IPv6 address/mask to be assigned to ethX"]),
        ("nfpkmod", [False, "Directory with kernel mods to load on DUT"]),
        ("nfp", [False, "NFP device number to use (default 0)"]),
        ("netdevfw", [True, "Path to netdev firmware"]),
        ("mefw", [True, "Path to firmware image directory"]),
    ])
    _config["HostA"] = collections.OrderedDict([
        ("name", [True, "Host name of the Host A (can also be <user>@<host> "
                        "or IP address). Assumes root as default."]),
        ("eth", [True, "Name of the interface on Host A"]),
        ("addrA", [True, "IPv4 address/mask to be assigned to Host A"]),
        ("addr6A", [True, "IPv4 address/mask to be assigned to Host A"]),
        ("reload", [False, "Attempt to reload the kmod for ethA "
                           "(default false)."])
    ])

    def __init__(self, name, cfg=None, quick=False, dut_object=None):
        """Initialise base NFPKmodGrp class

        @name:       A unique name for the group of tests
        @cfg:        A Config parser object (optional)
        @quick:      Omit some system info gathering to speed up running tests
        @dut_object: A DUT object used for pulling in endpoint/DUT data
                     (optional), only used when the PALAB is used
        """
        self.quick = quick
        self.dut_object = dut_object

        self.tmpdir = None
        self.cfg = cfg

        # Set up attributes initialised by the config file.
        # If no config was provided these will be None.
        self.noclean = False

        self.dut = None
        self.pci_id = None
        self.eth_x = None
        self.addr_x = None
        self.addr_v6_x = None
        self.intf_x = None
        self.nfp = 0
        self.nfpkmods = None
        self.netdevfw = None
        self.mefw = None

        self.host_a = None
        self.eth_a = None
        self.addr_a = None
        self.addr_v6_a = None
        self.intf_a = None
        self.reload_a = False

        # Call the parent's initializer.  It'll set up common attributes
        # and parses/validates the config file.
        netro.testinfra.Group.__init__(self, name, cfg=cfg,
                                       quick=quick, dut_object=dut_object)

        self.populate_tests()

    def clean_hosts(self):
        """ Clean host A.
        """
        # Clean attached hosts
        LOG_sec("Cleaning Host A: %s" % self.host_a.host)

        LOG_endsec()

        return

    def _init(self):
        """Initialise the systems for tests from this group
        called from the groups run() method.
        """

        if self.dut:
            _, out = self.dut.cmd("lspci -d '19ee:'")
            self.pci_id = out.split()[0]

            self.dut.cmd('lsmod | grep nfp_test_harness && rmmod nfp_test_harness', fail=False)
            self.dut.cmd('lsmod | grep nfp && rmmod nfp', fail=False)
            ret, _ = self.dut.cmd('ls /lib/firmware/netronome', fail=False)
            if ret == 0:
                raise NtiGeneralError('ERROR: driver tests require standard firmware directory to not be present!   Please remove the /lib/firmware/netronome/ directory!')

        return

    def _fini(self):
        """ Clean up the systems for tests from this group
        called from the groups run() method.
        """
        client_list = [self.dut, self.host_a]
        for client in client_list:
            kill_bg_process(client.host, "TCPKeepAlive")
            if hasattr(client, 'tmpdir') and not self.noclean:
                client.rm_dir(client.tmpdir)

        if self.dut:
            self.dut.cmd('rm -rf /lib/firmware/netronome')

        if self.dut and not self.noclean:
            self.dut.cmd('lsmod | grep nfp && rmmod nfp', fail=False)

        netro.testinfra.Group._fini(self)
        return

    def _parse_cfg(self):
        """
        Assign values to the members of NFPKmodGrp based on the cfg file.
        This method is used only when a cfg file is given in the command line
        Make sure the config is suitable for this project of tests
        """

        # The superclass implementation takes care of sanity checks
        netro.testinfra.Group._parse_cfg(self)

        self.dut_object = None

        # General
        if self.cfg.has_option("General", "noclean"):
            self.noclean = self.cfg.getboolean("General", "noclean")

        # DUT
        self.addr_x = self.cfg.get("DUT", "addrX")
        self.addr_v6_x = self.cfg.get("DUT", "addr6X")

        if self.cfg.has_option("DUT", "nfp"):
            self.nfp = self.cfg.getint("DUT", "nfp")
        if self.cfg.has_option("DUT", "nfpkmods"):
            self.nfpkmods = self.cfg.get("DUT", "nfpkmods")
            self.nfpkmod = os.path.join(self.nfpkmods, 'nfp.ko')
            self.nthkmod = os.path.join(self.nfpkmods, 'nfp_test_harness.ko')
        if self.cfg.has_option("DUT", "netdevfw"):
            self.netdevfw = self.cfg.get("DUT", "netdevfw")
        if self.cfg.has_option("DUT", "mefw"):
            self.mefw = self.cfg.get("DUT", "mefw")

        self.dut = DrvSystem(self.cfg.get("DUT", "name"), self,
                             quick=self.quick)

        # Host A
        self.host_a = NrtSystem(self.cfg.get("HostA", "name"), self.quick)
        self.eth_a = self.cfg.get("HostA", "eth")
        self.addr_a = self.cfg.get("HostA", "addrA")
        self.addr_v6_a = self.cfg.get("HostA", "addr6A")
        if self.cfg.has_option("HostA", "reload"):
            self.reload_a = self.cfg.getboolean("HostA", "reload")

        self.host_a.cmd('ifconfig %s %s' % (self.eth_a, self.addr_a))

        return
