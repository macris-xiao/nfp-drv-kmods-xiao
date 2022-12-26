#
# Copyright (C) 2016-2017,  Netronome Systems, Inc.  All rights reserved.
#
"""
Base for all driver test groups.
"""

import collections
import os
import re
import tempfile

import netro.testinfra
from netro.testinfra import LOG_sec, LOG_endsec
from netro.testinfra.nti_exceptions import *
from netro.testinfra.system import _parse_ip_addr_stats
from libs.nrt_system import NrtSystem
from libs.nrt_system import kill_bg_process
from drv_system import *
from common_test import drv_load_record_ifcs

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
                            "False). Useful for debugging test failures."]),
        ('force_fw_reload', [False, "Force firmware to be reloaded between"
                                    "tests."]),
        ('rm_fw_dir', [False, "Allow test code to remove the "
                              "/lib/firmware/netronome directory if present"]),
        ('installed_drv', [False, "Use upstream/installed driver"]),
        ('tun_net', [True, "Tunnel subnet to use. First 3 octets of an IPv4 "
                           "subnet to use on tunnels (e.g. '10.9.1.') incl "
                           "the trailing dot."])
    ])
    _config["DUT"] = collections.OrderedDict([
        ("name", [True, "Host name of the DUT (can also be <user>@<host> or "
                        "IP address). Assumes root as default."]),
        ("ethX", [True, "List of names of the interfaces on DUT"]),
        ("addrX", [True, "List of IPv4 address/mask to be assigned to ethX"]),
        ("addr6X", [True, "List of IPv6 address/mask to be assigned to ethX"]),
        ("nfpkmods", [False, "Directory with kernel mods to load on DUT"]),
        ("nfp", [False, "NFP device number to use (default 0)"]),
        ("netdevfw", [True, "Path to netdev firmware"]),
        ("netdevfw_nfd3", [False, "Specifies whether netdev fw is nfd3-based"]),
        ("netdevfw_dir", [False, "Path to netdev firmwares"]),
        ("samples", [True, "Path to directory with test samples"]),
        ("ebpf_perf_baseline", [False,
                                "Path to file with target eBPF performance"]),
        ("serial", [False, "Serial number for adapter selection "
                           "(default to nfp 0, takes precedence over @nfp)"]),
        ("bsppath", [False, "Path to the BSP installation "
                            "(default /opt/netronome/)"]),
    ])
    _config["HostA"] = collections.OrderedDict([
        ("name", [True, "Host name of the Host A (can also be <user>@<host> "
                        "or IP address). Assumes root as default."]),
        ("ethA", [True, "List of names of the interfaces on Host A"]),
        ("addrA", [True, "List of IPv4 address/mask to be assigned to HostA"]),
        ("addr6A", [True, "List of IPv6 address/mask to be assigned to HostA"]),
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

        # This is determined from the system state later on, defaulted for now
        self.upstream_drv = False

        # Set up attributes initialised by the config file.
        # If no config was provided these will be None.
        self.noclean = False
        self.force_fw_reload = False
        self.rm_fw_dir = False
        self.installed_drv = False
        self.tun_net = None

        self.dut = None
        self.pci_id = None
        self.eth_x = None
        self.addr_x = None
        self.addr_v6_x = None
        self.intf_x = None
        self.nfp = 0
        self.nfpkmods = None
        self.netdevfw = None
        self.netdevfw_nfd3 = False
        self.netdevfw_dir = None
        self.samples = None
        self.ebpf_baseline_file = None
        self.serial = None
        self.bsppath = '/opt/netronome'

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

        if not self.dut:
            return

        # Setup Host A IPs
        cmd = ''
        for i in range(len(self.eth_a)):
            cmd += 'ip link set dev %s down;' % (self.eth_a[i])
            cmd += 'ip addr flush dev %s;' % (self.eth_a[i])
            cmd += 'ip -6 addr flush dev %s;' % (self.eth_a[i])
            cmd += 'ip addr add dev %s %s;' % (self.eth_a[i], self.addr_a[i])
            cmd += 'ip addr add dev %s %s;' % (self.eth_a[i], self.addr_v6_a[i])
            cmd += 'ip link set dev %s up;' % (self.eth_a[i])
        self.host_a.cmd(cmd)

        cmd = ''
        # Enable verbose logging
        cmd += 'sysctl -w kernel.printk="7 6";'
        self.dut.cmd(cmd)
        # Don't reinit @cmd to run the common commands on both

        # Disable DAD on Host A
        for ifc in self.eth_a:
            cmd += 'sysctl -w net.ipv6.conf.%s.accept_dad=0;' % (ifc)
            cmd += 'sysctl -w net.ipv6.conf.%s.dad_transmits=0;' % (ifc)
        self.host_a.cmd(cmd)

        # Clean systems from "tun_net" IPs
        cmd = ''
        _, out = self.host_a.cmd('ip a | grep %s' % (self.tun_net), fail=False)
        for line in out.split('\n'):
            p = line.split()
            if len(p) < 5:
                continue
            cmd += 'ip a d %s dev %s;' % (p[1], p[4])
        # Clean the "tun_net" neigh entries
        _, out = self.host_a.cmd('ip ne show to %s0/24' % (self.tun_net))
        for line in out.split('\n'):
            p = line.split()
            if len(p) < 3:
                continue
            cmd += 'ip link set dev %s down;' % (p[2])
            cmd += 'ip link set dev %s up;' % (p[2])
        if cmd:
            self.host_a.cmd(cmd)

        self.dut.cmd('lsmod | grep nfp_test_harness && rmmod nfp_test_harness', fail=False)
        self.dut.cmd('lsmod | grep nfp && rmmod nfp', fail=False)
        ret, _ = self.dut.cmd('ls /lib/firmware/netronome', fail=False)
        if ret == 0:
            if self.rm_fw_dir:
                self.dut.cmd('rm -r /lib/firmware/netronome')
            else:
                raise NtiGeneralError('ERROR: driver tests require standard firmware directory to not be present!   Please remove the /lib/firmware/netronome/ directory!')

        _, out = self.dut.cmd("(lspci -D -d 19ee: && lspci -D -d 1da8:) | \
                              cut -d ' ' -f1")
        devices = out.split()

        # Resolve serial if given
        if self.serial:
            self.nfp = None
            cmd = '(lspci -d 19ee: -v && lspci -d 1da8: -v)'
            cmd += ' | sed -n "s/-/:/g;s/.*Serial Number \(.*\)/\\1/p"'
            _, out = self.dut.cmd(cmd)

            serials = out.split()

            i = -1
            self.pci_ids = []
            self.pci_dbdfs = []
            for s in serials:
                i += 1
                serial = s[:-6] # remove the interface part
                if serial != self.serial:
                    continue

                # Figure out IDs. We store the main PCIe device ID, but also
                # keep track of additional PCIe devices
                interface = int(s[19])
                if interface == 0:
                    self.pci_id = devices[i][5:]
                    self.pci_dbdf = devices[i]
                    self.pf_id = int(s[-4])

                # Store all PCIe interface IDs
                self.pci_ids.insert(interface, devices[i][5:])
                self.pci_dbdfs.insert(interface, devices[i])

            if self.pci_id is None:
                raise NtiGeneralError("Couldn't find device is SN: %s" %
                                      self.serial)

        self.tmpdir = tempfile.mkdtemp()

        if hasattr(self.host_a, 'tmpdir'):
            LOG('WARNING: SRC already has tmp dir, reusing it')
        else:
            self.host_a.tmpdir = self.host_a.make_temp_dir()

        LOG_sec("TMP directories:")
        LOG("Local:\t %s" % (self.tmpdir))
        LOG("HostA:\t %s" % (self.host_a.tmpdir))
        LOG("DUT:\t %s" % (self.dut.tmpdir))
        LOG_endsec()

        self.dut.reset_mods()
        return

    def _fini(self):
        """ Clean up the systems for tests from this group
        called from the groups run() method.
        """
        # Capture dmesg after tests finished
        if self.dut:
            self.dut.cmd("dmesg")

        LOG_sec("RM TMP directories")
        client_list = [self.dut, self.host_a]
        for client in client_list:
            kill_bg_process(client.host, "TCPKeepAlive")
            if hasattr(client, 'tmpdir') and not self.noclean:
                client.rm_dir(client.tmpdir)
        if hasattr(self, 'tmpdir') and not self.noclean:
            cmd_log("rm -rf %s" % (self.tmpdir))
        LOG_endsec()

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
        if self.cfg.has_option("General", "force_fw_reload"):
            self.force_fw_reload = self.cfg.getboolean("General", "force_fw_reload")
        if self.cfg.has_option("General", "rm_fw_dir"):
            self.rm_fw_dir = self.cfg.getboolean("General", "rm_fw_dir")
        if self.cfg.has_option("General", "installed_drv"):
            self.installed_drv = self.cfg.getboolean("General", "installed_drv")
        if self.cfg.has_option("General", "tun_net"):
            self.tun_net = self.cfg.get("General", "tun_net")

        # DUT
        self.eth_x = self.cfg.get("DUT", "ethX").split()
        self.addr_x = self.cfg.get("DUT", "addrX").split()
        self.addr_v6_x = self.cfg.get("DUT", "addr6X").split()

        if self.cfg.has_option("DUT", "nfp"):
            self.nfp = int(self.cfg.getint("DUT", "nfp"))
        if self.cfg.has_option("DUT", "nfpkmods"):
            self.nfpkmods = self.cfg.get("DUT", "nfpkmods")
            self.nfpkmod = os.path.join(self.nfpkmods, 'nfp.ko')
            self.nthkmod = os.path.join(self.nfpkmods, 'nfp_test_harness.ko')
        if self.cfg.has_option("DUT", "netdevfw"):
            self.netdevfw = self.cfg.get("DUT", "netdevfw")
        if self.cfg.has_option("DUT", "netdevfw_nfd3"):
            self.netdevfw_nfd3 = self.cfg.get("DUT", "netdevfw_nfd3")
        if self.cfg.has_option("DUT", "netdevfw_dir"):
            self.netdevfw_dir = self.cfg.get("DUT", "netdevfw_dir")
        if self.cfg.has_option("DUT", "samples"):
            self.samples = self.cfg.get("DUT", "samples")
            self.mefw = os.path.join(self.samples, 'mefw')
            self.samples_trafgen = os.path.join(self.samples, 'trafgen')
            self.samples_bpf = os.path.join(self.samples, 'bpf')
            self.samples_xdp = os.path.join(self.samples, 'xdp')
            self.samples_xdp_perf = os.path.join(self.samples,
                                                 'xdp_performance')
            self.samples_c = os.path.join(self.samples, 'c')
        if self.cfg.has_option("DUT", "ebpf_perf_baseline"):
            self.ebpf_baseline_file  = self.cfg.get("DUT", 'ebpf_perf_baseline')
        if self.cfg.has_option("DUT", "serial"):
            self.serial = self.cfg.get("DUT", "serial")
        if self.cfg.has_option("DUT", "bsppath"):
            self.bsppath = self.cfg.get("DUT", "bsppath")

        if not self.installed_drv and self.nfpkmods == None:
            raise NtiGeneralError('ERROR: kernel module not provided: nfpkmods=None or installed_drv=False')

        self.dut = DrvSystem(self.cfg.get("DUT", "name"), self,
                             quick=self.quick)

        # Host A
        self.host_a = LinuxSystem(self.cfg.get("HostA", "name"), self, self.quick)
        self.eth_a = self.cfg.get("HostA", "ethA").split()
        self.addr_a = self.cfg.get("HostA", "addrA").split()
        self.addr_v6_a = self.cfg.get("HostA", "addr6A").split()
        if self.cfg.has_option("HostA", "reload"):
            self.reload_a = self.cfg.getboolean("HostA", "reload")

        if len(self.eth_x) != len(self.eth_a) or \
           len(self.addr_x) != len(self.addr_a) or \
           len(self.addr_v6_x) != len(self.addr_v6_a) or \
           len(self.eth_x) != len(self.addr_x) or \
           len(self.eth_x) != len(self.addr_v6_x):
            raise NtiGeneralError('ERROR: Config has different number of addresses and interfaces')

        return

    def bpf_capable(self):
        if hasattr(self, 'is_bpf_capable'):
            return self.is_bpf_capable

        cmd = 'ethtool -k lo | grep hw-tc-offload'

        # Check if BPF files are available
        LOG_sec ("Check if BPF tools available")
        ret, _ = cmd_log(cmd, fail=False)
        LOG_endsec()

        self.is_bpf_capable = ret == 0

        return self.is_bpf_capable

    def xdp_capable(self):
        if hasattr(self, 'is_xdp_capable'):
            return self.is_xdp_capable

        cmd = 'ls tests/samples/xdp/*.o'
        cmd += '&& ip link help 2>&1 | grep xdp'

        # Check if XDP files are available
        LOG_sec ("Check if XDP available")
        ret, _ = cmd_log(cmd, fail=False)
        LOG_endsec()

        self.is_xdp_capable = ret == 0

        return self.is_xdp_capable

class NFPKmodAppGrp(NFPKmodGrp):
    """Base class for app netdev tests"""

    def __init__(self, name, cfg=None, quick=False, dut_object=None,
                 dut=None, nfp=None, nfpkmods=None, mefw=None):

        NFPKmodGrp.__init__(self, name=name, cfg=cfg, quick=quick,
                            dut_object=dut_object)

    def do_init(self):
        NFPKmodGrp._init(self)

        drv_load_record_ifcs(self, self, fwname=None)

        M = self.dut

        # Disable DAD
        cmd = ''
        for ifc in self.eth_x:
            cmd += 'sysctl -w net.ipv6.conf.{ifc}.accept_dad=0 '
            cmd += 'net.ipv6.conf.{ifc}.dad_transmits=0 '
            cmd += 'net.ipv6.conf.{ifc}.keep_addr_on_down=1 '
            cmd += '&& '
            cmd = cmd.format(ifc=ifc)

        # Init DUT
        for p in range(len(self.eth_x)):
            cmd += 'ip link set dev {ifc} promisc on up && '
            cmd += 'ip addr replace dev {ifc} {ipv4} && '
            cmd += 'ip addr replace dev {ifc} {ipv6} && '
            cmd = cmd.format(ifc=self.eth_x[p],
                             ipv4=self.addr_x[p], ipv6=self.addr_v6_x[p])
        cmd += 'true'
        M.cmd(cmd)

        # Make sure NTI knows the NFP interface exists
        M.refresh()

        # stash hwaddrs for traffic generation
        self.hwaddr_x = []
        self.mtu_x = []
        self.promisc_x = []
        self.hwaddr_a = []
        self.mtu_a = []
        self.promisc_a = []
        for p in range(0, len(self.eth_x)):
            _, out = self.dut.cmd("ip link show dev %s" % self.eth_x[p])
            ipdevinfo = _parse_ip_addr_stats(out)
            self.hwaddr_x.append(ipdevinfo["hwaddr"])
            self.mtu_x.append(ipdevinfo["mtu"])
            self.promisc_x.append(out.find("PROMISC") != -1)

            _, out = self.host_a.cmd("ip link show dev %s" % self.eth_a[p])
            ipdevinfo = _parse_ip_addr_stats(out)
            self.hwaddr_a.append(ipdevinfo["hwaddr"])
            self.mtu_a.append(ipdevinfo["mtu"])
            self.promisc_a.append(out.find("PROMISC") != -1)

            # add static arp entries to speed up drop tests
            self.host_a.cmd('ip neigh add %s lladdr %s dev %s' %
                            (self.addr_x[p][:-3], self.hwaddr_x[p],
                             self.eth_a[p]), fail=False)
            self.host_a.cmd('ip neigh add %s lladdr %s dev %s' %
                            (self.addr_v6_x[p][:-3], self.hwaddr_x[p],
                             self.eth_a[p]), fail=False)

            # Make sure MTUs match just in case
            if self.mtu_a[p] != self.mtu_x[p]:
                raise NtiError("Device MTUs don't match %s vs %s" %
                               (self.mtu_a[p], self.mtu_x[p]))

        for i in range(0, len(self.eth_x)):
            self.dut.link_wait(self.eth_x[i])
        return

    def _init(self):
        try:
            self.do_init()
        except:
            self._fini()
            raise

    def _fini(self):
        self.dut.cmd('rm -rf /lib/firmware/netronome')
        self.dut.reset_mods()

        NFPKmodGrp._fini(self)
        return
