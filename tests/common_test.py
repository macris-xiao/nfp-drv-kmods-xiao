##
## Copyright (C) 2016-2017,  Netronome Systems, Inc.  All rights reserved.
##

import binascii
import os
import struct
import time
import re

from elftools.elf.elffile import ELFFile
from elftools.elf.sections import SymbolTableSection
from scapy.all import TCP, UDP, IP, Ether, rdpcap, wrpcap, IPv6, ICMP, Raw

from netro.testinfra.nrt_result import NrtResult
from netro.testinfra.nti_exceptions import NtiError, NtiGeneralError
from netro.testinfra.test import Test
from netro.testinfra.system import _parse_ethtool
from netro.testinfra import LOG_init, LOG_sec, LOG, LOG_endsec, CMD
from netro.tests.tcpdump import TCPDump

###############################################################################
# Exception for throwing results
###############################################################################
class NtiSkip(Exception):
    """ Exception raised to skip tests.

    Attributes:
        msg  -- explanation of the reason test was skipeed
    """

    def __init__(self, msg):
        self.msg = msg

    def __str__(self):
        return repr(self.msg)

###############################################################################
# Helper functions
###############################################################################
def ethtool_drvinfo(host, ifc):
    _, out = host.cmd('ethtool -i %s' % (ifc))

    ret = {}

    lines = out.split('\n')
    for l in lines:
        vals = l.split(': ')
        ret[vals[0]] = ': '.join(vals[1:])

    return ret

def ethtool_stats(host, ifc):
    _, out = host.cmd('ethtool -S %s' % (ifc))

    return _parse_ethtool(out)

###############################################################################
# Test with cleanup
###############################################################################
class CommonTest(Test):
    """A generic test class. Tests are subclasses of this class and
    actual tests are instances of those sub classes.

    This class provides more structure than Test class, the prepare
    execute and cleanup stages are separate.  The execute stage is
    expected to throw exceptions when things fail.  Those exceptions
    will be propagated but cleanup stage will always follow.

    This class also contains the common initialization.
    """
    def __init__(self, src, dut, group=None, name="", summary=None):
        """
        @src:        A tuple of System and interface name from which to send
        @dut:        A tuple of System and interface name which should receive
        @group:      Test group this test belongs to
        @name:       Name for this test instance
        @summary:    Optional one line summary for the test
        """
        Test.__init__(self, group, name, summary)

        self.src = None
        self.src_ifn = None
        self.dut = None
        self.dut_ifn = None

        # src and dut maybe None if called without config file for list
        if not src[0]:
            return

        self.src = src[0]
        self.src_addr = src[1]
        self.src_ifn = src[2]
        self.src_addr_v6 = src[3]

        self.dut = dut[0]
        self.dut_addr = dut[1]
        self.dut_ifn = dut[2]
        self.dut_addr_v6 = dut[3]

        self.active_xdp = [None] * len(self.dut_ifn)
        return

    def prepare(self):
        """
        Prepare tests

        @return NrtResult on error
        """
        pass

    def execute(self):
        """
        Run the test, throw an exception if anything goes wrong
        """
        pass

    def cleanup(self):
        """
        Cleanup after tests
        """
        pass

    def run(self):
        res = self.prepare()
        if res:
            return res

        res = NrtResult(name=self.name, testtype=self.__class__.__name__,
                        passed=True)

        try:
            self.execute()
        except NtiSkip as err:
            res = NrtResult(name=self.name, testtype=self.__class__.__name__,
                            passed=None, comment=str(err))
        finally:
            self.cleanup()

        return res


    def log(self, text, thing):
        LOG_sec(text)
        if 'pp' in dir(thing):
            LOG(thing.pp())
        else:
            LOG(str(thing))
        LOG_endsec()

    def log_stat_diff(self, diff):
        self.log("Interface stats difference", diff)

    def kernel_min(self, major, minor):
        M = self.dut

        if M.kernel_maj < major or \
           (M.kernel_maj == major and M.kernel_min < minor):
            comment = "Kernel version %d.%d < %d.%d" % \
                (M.kernel_maj, M.kernel_min, major, minor)
            return NrtResult(name=self.name, testtype=self.__class__.__name__,
                             passed=None, comment=comment)

    def nsp_min(self, exp_ver):
        if self.group.upstream_drv:
            nsp_ver = self.dut.get_nsp_ver(ifc=self.dut_ifn[0])
        else:
            nsp_ver = self.dut.get_nsp_ver()
        if nsp_ver < exp_ver:
            raise NtiSkip("NSP version %d, test requires %d" %
                          (nsp_ver, exp_ver))

    def ifc_all_up(self):
        for i in range(0, len(self.dut_ifn)):
            self.dut.cmd('ethtool -G %s rx 512 tx 512' % (self.dut_ifn[i]),
                         fail=False)
            self.dut.cmd('ifconfig %s %s up' % (self.dut_ifn[i],
                                                self.dut_addr[i]))

    def ifc_all_down(self):
        for i in range(0, len(self.dut_ifn)):
            self.dut.cmd('ip link set %s down' % (self.dut_ifn[i]))

    def ifc_skip_if_not_all_up(self):
        for i in range(0, len(self.dut_ifn)):
            self.dut.link_wait(self.dut_ifn[i])

            _, out = self.dut.cmd('ethtool %s' % (self.dut_ifn[i]))
            if out.find('Link detected: yes') == -1:
                raise NtiSkip("Interface %s is not up" % (self.dut_ifn[i]))

    def tc_bpf_load(self, obj, flags="", act="",
                    skip_sw=False, skip_hw=False, da=False,
                    dev=None, port=None):
        for_dev = ""

        if dev and port:
            raise NtiError("Method can't have both port and dev specified")
        if dev is not None:
            for_dev = "dev " + dev
        if port is not None:
            for_dev = "dev " + self.dut_ifn[port]

        if skip_sw:
            flags += " skip_sw"
        if skip_hw:
            flags += " skip_hw"
        if da:
            flags += " da"

        obj_full = os.path.join(self.dut.bpf_samples_dir, obj)
        cmd = 'tc filter add dev %s parent ffff:  bpf obj %s %s %s %s' % \
              (self.dut_ifn[0], obj_full, for_dev, flags, act)

        ret, _ = self.dut.cmd(cmd, fail=False)
        return ret

    def xdp_start(self, prog, port=0, mode="", should_fail=False):
        prog_path = os.path.join(self.dut.xdp_samples_dir, prog)
        cmd = 'ip -force link set dev %s xdp%s obj %s sec ".text"' % \
              (self.dut_ifn[port], mode, prog_path)

        ret, out = self.dut.cmd(cmd, fail=False)
        if ret and should_fail == False:
            raise NtiError("Couldn't load XDP")
        if ret == 0 and should_fail == True:
            raise NtiError("XDP loaded and it shouldn't")
        if ret != 0:
            return ret, out

        # Record what we added so we can reset in case of error
        self.active_xdp[port] = mode

        return ret, out

    def xdp_stop(self, port=0, mode=""):
        self.active_xdp[port] = None

        return self.dut.cmd('ip -force link set dev %s xdp%s off' %
                            (self.dut_ifn[port], mode))

    def xdp_reset(self):
        for p in range(0, len(self.active_xdp)):
            if not self.active_xdp[p] is None:
                self.xdp_stop(port=p, mode=self.active_xdp[p])

    def ping(self, port, count=10, size=0, pattern="", ival="0.05",
             should_fail=False):
        opts = ""
        if size:
            opts = opts + "-s %d " % (size)
        if pattern:
            opts = opts + "-p %s " % (pattern)
        if ival:
            opts = opts + "-i %s " % (ival)

        ret, _ = self.src.cmd('ping -c %d -W2 %s -I %s %s' %
                              (count, opts, self.src_ifn[port],
                               self.dut_addr[port][:-3]), fail=False)
        if ret and should_fail == False:
            raise NtiGeneralError("Couldn't ping endpoint")
        if ret == 0 and should_fail == True:
            raise NtiGeneralError("Could ping endpoint")
        return ret

    def ping6(self, port, count=10, should_fail=False):
        ret, _ = self.src.cmd('ping6 -c %d -i0.1 -W5 -I %s %s' %
                              (count, self.src_ifn[port],
                               self.dut_addr_v6[port][:-3]), fail=False)
        if ret and should_fail == False:
            raise NtiGeneralError("Couldn't ping6 endpoint")
        if ret == 0 and should_fail == True:
            raise NtiGeneralError("Could ping6 endpoint")
        return ret

    def tcpping(self, port, count=10, sport=100, dport=58, should_fail=False):
        ret, _ = self.src.cmd('hping3 %s --fast -c %d -s %d -p %d -d 50 -k --syn' %
                              (self.dut_addr[port][:-3], count, sport, dport),
                              fail=False)
        if ret and should_fail == False:
            raise NtiGeneralError("Couldn't TCP ping endpoint")
        if ret == 0 and should_fail == True:
            raise NtiGeneralError("Could TCP ping endpoint")
        return ret

    def tcpdump_cmd(self, capture_system, ifname, cmd_system, cmd):
        pcap_res = os.path.join(self.group.tmpdir, 'pcap_res')

        # Start TCPdump
        dump = os.path.join(capture_system.tmpdir, 'dump')
        stderr = os.path.join(capture_system.tmpdir, 'tcpdump_err.txt')
        filter_expr = '"not arp and' \
                      ' not ip6 and' \
                      ' not ether host 01:80:c2:00:00:0e and' \
                      ' not ether host ff:ff:ff:ff:ff:ff"'
        self.tcpdump = TCPDump(capture_system, ifname, dump, resolve=False,
                               direction='in', stderrfn=stderr,
                               filter_expr=filter_expr)

        self.tcpdump.start()

        # Run command
        cmd_system.cmd(cmd)

        self.tcpdump.stop()

        # Dump the packets to logs for debug
        capture_system.cmd('tcpdump -xxvvv -r ' + dump)

        # Check the result
        capture_system.cp_from(dump, pcap_res)

        return rdpcap(pcap_res)

    def read_sym_nffw(self, name, nffw_path=None):
        if not nffw_path:
            nffw_path = self.group.netdevfw

        with open(nffw_path, 'rb') as f:
            elf = ELFFile(f)

            for section in elf.iter_sections():
                if not isinstance(section, SymbolTableSection):
                    continue

                sl = section.get_symbol_by_name(name)
                if not sl:
                    self.log('NFFW symbol lookup: ' + name, '\nnot found\n')
                    return None
                if len(sl) > 1:
                    raise NtiError('multiple symbols found for ' + name)

                symbol = sl[0]

                sec = elf.get_section(symbol['st_shndx'])

                LOG_sec('NFFW symbol lookup: ' + name)
                LOG('section idx:\t' + str(symbol['st_shndx']))
                LOG('size:\t\t' + str(symbol['st_size']))
                LOG('position:\t\t' + hex(symbol['st_value']))
                LOG('section start:\t' + hex(sec['sh_addr']))
                LOG('section len:\t' + hex(sec['sh_size']))
                LOG('section type:\t' + sec['sh_type'])

                # Most likely a BSS section
                if sec['sh_type'] == 'SHT_NOBITS':
                    LOG_endsec()
                    return bytearray(symbol['st_size'])

                start = symbol['st_value'] - sec['sh_addr']
                end = start + symbol['st_size']

                if end > sec['sh_size']:
                    LOG_endsec()
                    raise NtiError("Symbol %s extends past the end of section"
                                   % (name))

                value = sec.data()[start:end]

                LOG('symbol off:\t' + hex(start))
                LOG('symbol off end:\t' + hex(end))

                LOG('\nValue:\n')
                LOG(binascii.hexlify(value))

                LOG_endsec()

                return value

        raise NtiError('no symbol section in NFFW file ' + nffw_path)

    def read_scalar_nffw(self, name, nffw_path=None):
        raw = self.read_sym_nffw(name, nffw_path)
        value = struct.unpack("<Q", raw)[0]

        LOG_sec("NFFW scalar lookup: " + name + " = " + str(value))
        LOG_endsec()

        return value

class CommonDrvTest(CommonTest):
    def cleanup(self):
        self.dut.reset_mods()
        self.dut.reset_dirs()


class CommonNTHTest(CommonTest):
    def execute(self):
        if self.group.upstream_drv:
            raise NtiSkip("NTH test on upstream")

        M = self.dut

        M.insmod()
        M.insmod(module="nth")

        self.nth_execute()

    def nth_execute(self):
        pass

    def cleanup(self):
        self.dut.reset_mods()


class CommonNetdevTest(CommonTest):
    def spawn_vf_netdev(self):
        # Enable VFs if supported
        max_vfs = self.read_scalar_nffw('nfd_vf_cfg_max_vfs')
        if max_vfs > 0:
            self.dut.cmd('modprobe -r vfio_pci')
            ret, _ = self.dut.cmd('echo %d > /sys/bus/pci/devices/0000:%s/sriov_numvfs' %
                                  (1, self.group.pci_id))

        netifs_old = self.dut._netifs
        self.dut.cmd("udevadm settle")
        self.dut._get_netifs()

        return list(set(self.dut._netifs) - set(netifs_old))

    def netdev_prep(self, fwname=None):
        LOG_sec("NFP netdev test prep")
        # Load the driver and remember which interfaces got spawned
        self.dut._get_netifs()
        netifs_old = self.dut._netifs

        self.dut.drv_load_netdev_conserving(fwname)

        self.dut._get_netifs()
        netifs_new = self.dut._netifs

        # All netdevs
        self.nfp_netdevs = list(set(netifs_new) - set(netifs_old))

        # vNIC netdevs
        self.vnics = []
        for ifc in self.nfp_netdevs:
            info = ethtool_drvinfo(self.dut, ifc)
            if info["bus-info"] == self.group.pci_dbdf:
                self.vnics.append(ifc)

        for ifc in self.nfp_netdevs:
            self.dut.cmd('ifconfig %s up' % (ifc))
        self.ifc_all_up()

        LOG_endsec() # NFP netdev test prep

        LOG_sec("NFP netdevs")
        LOG("all: " + str(self.nfp_netdevs))
        LOG("vnics: " + str(self.vnics))
        LOG_endsec()

    def execute(self):
        self.netdev_prep()

        self.netdev_execute()

    def cleanup(self):
        LOG_sec("NFP netdev test cleanup")
        self.dut.reset_mods()
        self.dut.reset_dirs()
        LOG_endsec()

    def reboot(self, fwname=None):
        self.dut.reset_mods()
        self.dut.cmd('reboot')
        # Give it time to go down
        time.sleep(10)

        ret = -1
        wait = 400
        while ret != 0:
            ret, _ = self.src.cmd('ping -W 1 -c 1 %s' % (self.dut.host),
                                  fail=False)
            wait -= 1
            if wait == 0:
                raise NtiError('Waiting for reboot timed out')

        # Give it time to come up
        time.sleep(5)

        self.dut.__init__(self.dut.host, self.dut.grp)
        self.group._init()
        self.netdev_prep(fwname=fwname)

class CommonNonUpstreamTest(CommonNetdevTest):
    def execute(self):
        if self.group.upstream_drv:
            raise NtiSkip('BSP tools upstream')

        CommonNetdevTest.execute(self)

class CommonPktCompareTest(CommonTest):
    """
    Base class for sending packets, capturing them and comparing
    the modifications.
    """

    def install_filter(self):
        """
        This function is called before traffic is generated to install
        the filter.  Note that there is no uninstall, because you should
        uninstall in cleanup.
        """
        pass

    def get_src_pkt(self):
        pass

    def get_exp_pkt(self):
        pass

    def get_prog_name(self):
        """
        Returns install parameters
        """
        pass

    def get_tcpdump_params(self):
        pass

    def std_pkt(self, size=96):
        pkt = ''
        for b in self.group.hwaddr_x[0].split(':'):
            pkt += chr(int('0x' + b, 16))
        for b in self.group.hwaddr_a[0].split(':'):
            pkt += chr(int('0x' + b, 16))
        pkt += '\x12\x22'

        pkt += '\xaa'
        pkt += '\xf1' * (size - 16)
        pkt += '\x55'

        return pkt

    def execute(self):
        # Prepare packet
        pkt = self.get_src_pkt()

        pcap_local = os.path.join(self.group.tmpdir, 'pcap')
        pcap_src = os.path.join(self.src.tmpdir, 'pcap')

        wrpcap(pcap_local, Ether(pkt))
        self.src.mv_to(pcap_local, pcap_src)

        # Make sure there is connectivity
        self.ping(0)

        # Install prog
        ret = self.install_filter()
        if ret != 0:
            raise NtiError("Filter load failed")

        cmd = "tcpreplay --intf1=%s --pps=100 --loop=100 -K %s " % \
              (self.src_ifn[0], pcap_src)

        tp = self.get_tcpdump_params()
        result_pkts = self.tcpdump_cmd(tp[0], tp[1], tp[2], cmd)

        # Compute expected packet
        exp_pkt = self.get_exp_pkt()

        exp_num = 100
        if exp_pkt is None:
            exp_num = 0

        if len(result_pkts) < exp_num or len(result_pkts) > exp_num + 5:
            raise NtiError('Captured %d packets, expected %d' %
                           (len(result_pkts), exp_num))

        found = 0
        for p in result_pkts:
            if str(p) == exp_pkt:
                found += 1
            else:
                self.log('Bad packet',
                         ':'.join(x.encode('hex') for x in str(p))
                         + "\n\n" +
                         ':'.join(x.encode('hex') for x in exp_pkt))

        if found != exp_num:
            raise NtiError("Found %d packets, was looking for %d" %
                           (found, exp_num))
