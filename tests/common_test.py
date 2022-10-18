##
## Copyright (C) 2016-2017,  Netronome Systems, Inc.  All rights reserved.
##

import binascii
import json
import os
import struct
import time
import re

from elftools.elf.elffile import ELFFile
from elftools.elf.sections import SymbolTableSection
from scapy.all import Ether, rdpcap, wrpcap, Raw

from netro.testinfra.nrt_result import NrtResult
from netro.testinfra.nti_exceptions import NtiError, NtiGeneralError
from netro.testinfra.system import cmd_log
from netro.testinfra.test import Test
from netro.testinfra import LOG_init, LOG_sec, LOG, LOG_endsec, CMD
from netro.tests.tcpdump import TCPDump

###############################################################################
# Assorted Cards
###############################################################################

# List of AMDA numbers related to 25G cards
AMDA_25G_CARDS = ['AMDA0099', 'AMDA0161', 'AMDA0144', 'AMDA2000']

###############################################################################
# Assert-style helper functions
###############################################################################

def assert_equal(expected, actual, error_message):
    if expected != actual:
        raise NtiGeneralError("%s: expected '%r' but was '%r'" % (error_message,
                                                                  expected,
                                                                  actual))

def assert_eq(expected, actual, error_message):
    assert_equal(expected, actual, error_message)

def assert_neq(expected, actual, error_message):
    if expected == actual:
        raise NtiGeneralError("%s: value %r not allowed" % (error_message,
                                                            actual))

def assert_geq(threshold, actual, error_message):
    if threshold > actual:
        raise NtiGeneralError("%s: %r > %r" % (error_message, threshold,
                                               actual))

def assert_ge(threshold, actual, error_message):
    if actual < threshold:
        raise NtiGeneralError("%s: %r < %r" % (error_message, actual,
                                               threshold))

def assert_lt(threshold, actual, error_message):
    if actual >= threshold:
        raise NtiGeneralError("%s: %r >= %r" % (error_message, actual,
                                                threshold))

def assert_range(threshold_min, threshold_max, actual, error_message):
    assert_ge(threshold_min, actual, error_message)
    assert_lt(threshold_max, actual, error_message)

def assert_approx(expected, diff, actual, error_message):
    assert_range(expected - diff, expected + diff, actual, error_message)

def assert_in(expected, actual, error_message):
    if expected not in actual:
        raise NtiGeneralError("%s: %r, not in %r" % (error_message, actual,
                                                     expected))

def assert_nin(disallowed, actual, error_message):
    if disallowed in actual:
        raise NtiGeneralError("%s: %r, contains %r" % (error_message, actual,
                                                       disallowed))

###############################################################################
# Exception for throwing results
###############################################################################
class DrvTestResultException(Exception):
    """ Exception raised to skip/fail tests.

    Attributes:
        msg  -- explanation of the reason test was terminated
    """

    def __init__(self, msg):
        self.msg = msg

    def __str__(self):
        return repr(self.msg)

class NtiSkip(DrvTestResultException):
    pass

class NtiFail(DrvTestResultException):
    pass

###############################################################################
# Helper functions
###############################################################################


def bsp_string_to_num(version):
    """
    Converts BSP version to a new number and returns it
    """
    # Split digits at non-numerical characters,
    # e.g. 22.07-0 => ["22","07","0"]
    version = version.strip()
    version = re.split(r'\D+', version)

    # Check for if there is a version revision
    if len(version) == 3:
        revision = int(version[2])
    else:
        revision = 0

    # Create new number by shifting their bits.
    # This is used to compare BSP versions
    # but as a new encoded number.
    # 22.07-0 will be 1443584 as follows:
    # 0x160000 + 0x700 + 0x0 = 0x160700 => 1443584
    bsp_ver = (int(version[0]) << 16) + (int(version[1]) << 8) + revision

    return bsp_ver


def bsp_num_to_string(number):
    """
    Returns BSP version as follows: 22.07-0
    """
    # 22   07   0
    # |    |    |
    # maj  min  ref
    maj = (number >> 16) & 0xff
    min = (number >> 8) & 0xff
    ref = number & 0xff
    version = "%s.0%s-%s" % (maj, min, ref)

    return version

def drv_load_record_ifcs(obj, group, fwname=None):
    # Load the driver and remember which interfaces got spawned
    obj.dut._get_netifs()
    netifs_old = obj.dut._netifs

    obj.dut.drv_load_netdev_conserving(fwname)

    obj.dut._get_netifs()
    netifs_new = obj.dut._netifs

    # All netdevs
    obj.nfp_netdevs = list(set(netifs_new) - set(netifs_old))

    cmd = ''

    # vNIC netdevs
    obj.vnics = []
    for ifc in obj.nfp_netdevs:
        info = obj.dut.ethtool_drvinfo(ifc)
        if info["firmware-version"][0] != "*":
            obj.vnics.append(ifc)
            # Use less buffers to speed up things, especially on debug kernels
            cmd += 'ethtool -G %s rx 512 tx 512 && ' % (ifc)

    # Store repr netdevs, assuming all non-vnic NFP netdevs are representors.
    obj.reprs = list(set(obj.nfp_netdevs) - set(obj.vnics))

    # To enable tests to use a single reference, we store the physical port
    # netdevs. For representor type apps, these will be the representors, for
    # legacy apps these will be the vnics.
    obj.phys_netdevs = []
    if len(obj.reprs) != 0:
        # We need to jump through some hoops here to only include phys reprs in
        # this list. ip link actually provides this information quite easily,
        # but this has only recently been added so we can't assume its available
        # just yet.
        _, lookup = obj.dut.cmd('find -L /sys/class/net -maxdepth 2 ' +
                                '-name \'phys_port_name\' -exec cat {} \; ' +
                                '-exec echo -n "{} " \; ' +
                                '-exec cat {} \; 2>/dev/null | grep -E "^/"')
        for iface in obj.reprs:
            if re.search('%s/[^ ]+ p[0-9]' % iface, lookup):
                obj.phys_netdevs.append(iface)
    else:
        obj.phys_netdevs = obj.vnics

    cmd += 'true'
    obj.dut.cmd(cmd)

    # TODO: currently some tests expect the netdev lists on the group or test
    #       this is wrong!  New tests should use them on dut, and we can move
    #       this code into dut class once all are migrated.
    obj.dut.nfp_netdevs = obj.nfp_netdevs
    obj.dut.vnics = obj.vnics
    obj.dut.reprs = obj.reprs
    obj.dut.phys_netdevs = obj.phys_netdevs

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

        self.active_xdp = [{ ""		: None,
                             "generic"	: None,
                             "drv"	: None,
                             "offload"	: None }
                           for x in range(len(self.dut_ifn))]
        self.test_metrics = []
        self.test_comment = ""
        self.test_result = True
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

        try:
            self.execute()
            res = NrtResult(name=self.name, testtype=self.__class__.__name__,
                            passed=self.test_result, comment=self.test_comment,
                            res=self.test_metrics)
        except NtiSkip as err:
            res = NrtResult(name=self.name, testtype=self.__class__.__name__,
                            passed=None, comment=str(err))
        finally:
            LOG_sec("Test clean up")
            try:
                self.cleanup()
            finally:
                LOG_endsec()

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

    def reinit_test(self):
        self.dut.__init__(self.dut.host, self.dut.grp)
        self.group._init()

    def kernel_min(self, major, minor):
        if not self.dut.kernel_ver_ge(major, minor):
            comment = "Kernel version %s < %d.%d" % \
                (self.dut.kernel_ver(), major, minor)
            return NrtResult(name=self.name, testtype=self.__class__.__name__,
                             passed=None, comment=comment)

    def tool_required(self, bin, description):
        ret, _ = self.dut.cmd("which %s" % bin, fail=False)
        if ret != 0:
            comment = "Requires %s" % description
            return NrtResult(name=self.name, testtype=self.__class__.__name__,
                             passed=None, comment=comment)

    def check_bsp_min(self, exp_ver):
        """
        This function checks that the BSP version is not too old
        """
        # Obtain BSP version on the DUT
        nsp_flash_ver = self.dut.get_bsp_ver()

        # Convert BSP versions to a new number
        # for comparisons
        bsp_num = bsp_string_to_num(nsp_flash_ver)
        exp_bsp_num = bsp_string_to_num(exp_ver)

        if bsp_num < exp_bsp_num:
            raise NtiSkip("BSP version \"%s\" is outdated, the tests"
                          " requires \"%s\"" % (nsp_flash_ver, exp_ver))

    def check_nsp_min(self, exp_ver):
        """
        This function checks that the NSP API version is not too old
        """
        if self.group.upstream_drv:
            nsp_ver = self.dut.get_nsp_ver(ifc=self.dut_ifn[0])
        else:
            nsp_ver = self.dut.get_nsp_ver()
        if nsp_ver < exp_ver:
            raise NtiSkip("NSP API version \"0.%s\" is outdated, the test"
                          " requires \"0.%s\"" % (nsp_ver, exp_ver))

    def skip_not_ifc_phys(self):
        for ifc in self.dut_ifn:
            ret, name = self.dut.cmd("cat /sys/class/net/%s/phys_port_name" %
                                     (ifc), fail=False)
            if ret or not re.search('p\d+(s\d+)*$', name):
                raise NtiSkip('Interface %s is not a physical ifc' % ifc)

    def kill_pidfile(self, host, pidfile, sig="-SIGTERM", max_retry=10,
                     retry_period=1, max_fail=0):
        """
        Note: the default -SIGTERM signal is used to terminate a process.
        """
        cmd = ''' # kill_pidfile
        fail=0

        PID=$(cat {pid}) &&
        echo $PID &&
        rm {pid} ||
        exit 1

        for p in $PID; do
            kill {sig} $p || ((fail++))
        done

        for p in $PID; do
            i=0
            while [[ -d /proc/$p || $i -lt {max_retry} ]]; do
                let i++; sleep {retry_period};
            done
            if [i == 10]; then
                kill SIGKILL $p || ((fail++))
            fi
            i=0
            while [[ -d /proc/$p || $i -lt {max_retry} ]]; do
                let i++; sleep {retry_period};
            done
            if [i == 10]; then
                exit 1
            fi
        done

        if [ $fail -gt {max_fail} ]; then
            exit 1
        fi
        '''

        return host.cmd(cmd.format(pid=pidfile, sig=sig, max_retry=max_retry,
                        retry_period=retry_period, max_fail=max_fail))

    def nfp_ifc_is_vnic(self, ethtool_info):
        return ethtool_info["firmware-version"][0] == "0" or \
               ethtool_info["firmware-version"][0] == "1" # NFD version

    def nfp_ifc_is_repr(self, ethtool_info):
        return ethtool_info["firmware-version"][0] == "*"

    def ifc_all_up(self):
        for i in range(0, len(self.dut_ifn)):
            self.dut.cmd(
                'ip addr replace %s dev %s && ip link set dev %s up' %
                        (self.dut_addr[i], self.dut_ifn[i], self.dut_ifn[i]))

    def ifc_all_down(self):
        for i in range(0, len(self.dut_ifn)):
            self.dut.cmd('ip link set %s down' % (self.dut_ifn[i]))

    def ifc_skip_if_not_all_up(self):
        for i in range(0, len(self.dut_ifn)):
            self.dut.link_wait(self.dut_ifn[i])

            _, out = self.dut.cmd('ethtool %s' % (self.dut_ifn[i]))
            if out.find('Link detected: yes') == -1:
                raise NtiSkip("Interface %s is not up" % (self.dut_ifn[i]))

    def tc_bpf_load(self, obj, flags="", act="", verifier_log="", extack="",
                    needle_noextack="", skip_sw=False, skip_hw=False,
                    da=False):
        if skip_sw:
            flags += " skip_sw"
        if skip_hw:
            flags += " skip_hw"
        if da:
            flags += " da"

        obj_full = os.path.join(self.dut.bpf_samples_dir, obj)
        cmd = 'tc filter add dev %s parent ffff:  bpf obj %s %s %s' % \
              (self.dut_ifn[0], obj_full, flags, act)

        ret, (_, err) = self.dut.cmd(cmd, fail=False, include_stderr=True)
        if verifier_log:
            self.check_verifier_log_nfp(err, verifier_log)
        if extack:
            self.check_extack(err, extack)
        if needle_noextack:
            self.check_no_extack(err, needle_noextack)
        return ret

    def xdp_start(self, prog, port=0, ifc=None, mode="", force=True, progdir="",
                  should_fail=False, verifier_log="", extack="",
                  needle_noextack=""):
        if ifc is None:
            ifc = self.dut_ifn[port]
        else:
            port = None
        if progdir == "":
                progdir = self.dut.xdp_samples_dir

        prog_path = os.path.join(progdir, prog)
        cmd = 'ip %s link set dev %s xdp%s obj %s sec ".text"' % \
              ('-force' * force, ifc, mode, prog_path)

        ret, (out, err) = self.dut.cmd(cmd, fail=False, include_stderr=True)
        if ret and should_fail == False:
            raise NtiError("Couldn't load XDP")
        if ret == 0 and should_fail == True:
            raise NtiError("XDP loaded and it shouldn't")
        if verifier_log:
            self.check_verifier_log_nfp(err, verifier_log)
        if extack:
            self.check_extack(err, extack)
        if needle_noextack:
            self.check_no_extack(err, needle_noextack)
        if ret != 0:
            return ret, out

        # Record what we added so we can reset in case of error
        if port is not None:
            self.active_xdp[port][mode] = prog_path

        return ret, out

    def xdp_stop(self, port=0, ifc=None, mode=""):
        if ifc is None:
            ifc = self.dut_ifn[port]
        else:
            port = None

        if port is not None:
            self.active_xdp[port][mode] = None

        return self.dut.cmd('ip -force link set dev %s xdp%s off' %
                            (ifc, mode))

    def xdp_reset(self):
        for p in range(len(self.active_xdp)):
            for m in self.active_xdp[p].keys():
                if self.active_xdp[p][m] is not None:
                    self.xdp_stop(port=p, mode=m)

    def check_extack(self, output, reference):
        lines = output.split("\n")
        comp = len(lines) >= 2 and lines[0] == reference
        if not comp:
            raise NtiError("Missing or incorrect netlink extack message")

    def check_no_extack(self, output, needle):
        if output.count(needle) or output.count("Warning:"):
            raise NtiError("Found '%s' in command output, leaky extack?" % (needle))

    def check_verifier_log(self, output, reference):
        lines = output.split("\n")
        for l in reversed(lines):
            if l == reference:
                return
        raise NtiError("Missing or incorrect message in verifier log")

    def check_verifier_log_nfp(self, output, reference):
        self.check_verifier_log(output, "[nfp] " + reference)

    def ping(self, port, count=10, size=None, pattern="", ival="0.05",
             tos=None, should_fail=False):
        return self.src.ping(addr=self.dut_addr[port][:-3],
                             ifc=self.src_ifn[port],
                             count=count, size=size, pattern=pattern,
                             ival=ival, tos=tos, should_fail=should_fail)

    def ping6(self, port, count=10, size=None, pattern="", ival="0.05",
              tos=None, should_fail=False):
        return self.src.ping6(addr=self.dut_addr_v6[port][:-3],
                              ifc=self.src_ifn[port],
                              count=count, size=size, pattern=pattern,
                              ival=ival, tos=tos, should_fail=should_fail)

    def hping3_cmd(self, port, count=10, sport=100, dport=58, size=50, tos=None,
                   ip_id=None, ttl=None, seq=None, ack=None, win=None,
                   keep=True, speed="fast", opts=""):
        if keep:
            opts += "-k "
        if tos is not None:
            opts += "-o %x " % (tos)
        if ip_id is not None:
            opts += "--id %d " % ip_id
        if ttl is not None:
            opts += "--ttl %d " % ttl
        if seq is not None:
            opts += "--setseq %d " % seq
        if ack is not None:
            opts += "--setack %d " % ack
        if win is not None:
            opts += "--win %d " % win
        if count is not None:
            opts += "-c %d " % count
        opts += "--{speed} ".format(speed=speed)

        cmd  = 'hping3 {addr} -s {sport} -p {dport} -d {size} {opts}'
        cmd = cmd.format(addr=self.dut_addr[port][:-3], cnt=count, sport=sport,
                         dport=dport, size=size, opts=opts)
        return cmd

    def tcpping(self, port, count=10, sport=100, dport=58, size=50, tos=None,
                ip_id=None, ttl=None, seq=None, ack=None, win=None, keep=True,
                speed="fast", fail=False, should_fail=False, timeout = None):
        opts = "--syn "
        cmd = ""
        if timeout is not None:
            cmd += "timeout %d " % timeout
        cmd += self.hping3_cmd(port=port, count=count, sport=sport, dport=dport,
                              size=size, tos=tos, ip_id=ip_id, ttl=ttl, seq=seq,
                              ack=ack, win=win, keep=keep, speed=speed,
                              opts=opts)
        ret, out = self.src.cmd(cmd, fail=False)
        if fail == False:
            return ret, out
        if ret and should_fail == False:
            raise NtiGeneralError("Couldn't TCP ping endpoint")
        if ret == 0 and should_fail == True:
            raise NtiGeneralError("Could TCP ping endpoint")
        return ret

    def prep_pcap(self, pkt):
        pcap_local = os.path.join(self.group.tmpdir, 'pcap')
        pcap_src = os.path.join(self.src.tmpdir, 'pcap')

        if not isinstance(pkt, list):
            pkt = Ether(pkt) * 100
        elif len(pkt) != 100:
            raise NtiError('Internal error - 100 pkts expected on the list')

        wrpcap(pcap_local, pkt)
        self.src.mv_to(pcap_local, pcap_src)

        return pcap_src

    def prep_pcap_simple_to_list(self, pkt):
        pkts = []
        for i in range(100):
            pkts.append(pkt)
        return self.prep_pcap(pkts)

    def prep_pcap_simple_seq(self, pkt):
        pkts = []
        for i in range(100):
            pkt = pkt[:14] + chr(i) + '\x00\x00\x00' + pkt[18:]
            pkts.append(Ether(pkt))
        return self.prep_pcap(pkts)

    def tcpdump_cmd(self, capture_system, ifname, cmd_system, cmd,
                    snaplen=8192, filter_overwrite=None):
        pcap_res = os.path.join(self.group.tmpdir, 'pcap_res')

        # Start TCPdump
        dump = os.path.join(capture_system.tmpdir, 'dump')
        stderr = os.path.join(capture_system.tmpdir, 'tcpdump_err.txt')
        filter_expr = '"not arp and' \
                      ' not ip6 and' \
                      ' not udp port 5353 and' \
                      ' not ether host 01:80:c2:00:00:0e and' \
                      ' not ether host ff:ff:ff:ff:ff:ff"'

        if filter_overwrite is not None:
            filter_expr = filter_overwrite

        self.tcpdump = TCPDump(capture_system, ifname, dump, resolve=False,
                               direction='in', stderrfn=stderr,
                               filter_expr=filter_expr, snaplen=snaplen)

        self.tcpdump.start(wait=3)

        # Run command
        cmd_system.cmd(cmd)

        self.tcpdump.stop(wait=3)

        # Dump the packets to logs for debug
        capture_system.cmd('tcpdump -xxvvv -r ' + dump)

        # Check the result
        capture_system.cp_from(dump, pcap_res)

        return rdpcap(pcap_res)

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

    def test_with_traffic(self, pcap_src, exp_pkt, tcpdump_params, port=0,
                          snaplen=8192, filter_overwrite=None):
        cmd = "tcpreplay --intf1=%s --pps=100 %s " % \
              (self.src_ifn[port], pcap_src)

        tp = tcpdump_params
        result_pkts = self.tcpdump_cmd(tp[0], tp[1], tp[2], cmd, snaplen,
                                       filter_overwrite)

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

        LOG_sec("Capture test OK exp: %d got: %d/%d" % (exp_num, found,
                                                        len(result_pkts)))
        LOG_endsec()

    def bpftool_map_perf_capture_validate(self, events, event_data,
                                          exp_num=100):
        LOG_sec('Events from: ' + events)
        cmd_log('cat ' + events)
        LOG_endsec()

        events = json.load(open(events))
        exp_data = [ord(c) for c in event_data]

        found = 0

        assert_ge(exp_num, len(events), 'Number of events')
        LOG_sec('Looking for samples')
        try:
            for e in events:
                assert_equal(9, e["type"], 'Event type')
                if exp_data == e["data"][:len(event_data)] and \
                   len(exp_data) + 8 > len(e["data"]):
                    found += 1
                else:
                    self.log('Bad sample',
                             ':'.join("%02x" % x for x in e["data"])
                             + "\n\n" +
                             ':'.join("%02x" % x for x in exp_data))
        finally:
            LOG_endsec()

        assert_ge(exp_num, found, "Events found")

        LOG_sec("Events OK exp: %d got: %d/%d" % (exp_num, found, len(events)))
        LOG_endsec()

    def read_sym_nffw(self, name, nffw_path=None, fail=False):
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
                    if fail:
                        raise NtiError("NFFW can't find symbol '%s'" % (name))
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

    def spawn_vf_netdev(self):
        # Enable VFs if supported
        max_vfs = self.read_scalar_nffw('nfd_vf_cfg_max_vfs')
        ret, num = self.dut.cmd('cat /sys/bus/pci/devices/%s/sriov_numvfs' %
                                self.group.pci_dbdf)
        num_vfs = int(num) + 1
        if max_vfs > 0:
            if num_vfs != 1:
                self.dut.cmd('echo 0 > /sys/bus/pci/devices/%s/sriov_numvfs' %
                             self.group.pci_dbdf)
            if not self.dut.kernel_ver_ge(4, 12):
                self.dut.cmd('modprobe -r pci_stub')
            ret, _ = self.dut.cmd('echo %d > /sys/bus/pci/devices/%s/sriov_numvfs' %
                                  (num_vfs, self.group.pci_dbdf))

        netifs_old = self.dut._netifs
        self.dut.cmd("udevadm settle")
        self.dut._get_netifs()

        return list(set(self.dut._netifs) - set(netifs_old))

    def spawn_tc_vf_netdev(self, num):
        # Enable TC VFs if supported
        max_vfs = self.read_scalar_nffw('nfd_vf_cfg_max_vfs')
        num_vfs = int(num)
        if num_vfs > max_vfs:
             raise NtiError('num_vfs must less than max_vfs')
        if not self.dut.kernel_ver_ge(4, 12):
            self.dut.cmd('modprobe -r pci_stub')
        self.dut.cmd('echo %d > /sys/bus/pci/devices/%s/sriov_numvfs' %
                                  (num_vfs, self.group.pci_dbdf))
        pci_dbdf = self.group.pci_dbdf
        pci_dbdf_cut = re.findall("\d+", pci_dbdf)
        ret, out = self.dut.cmd('lspci | grep Eth | grep %s | grep %s' %
                                (self.dut.get_vf_id(), pci_dbdf_cut[1]))
        lines = out.split("\n")
        vfs = []
        vf_reps = []
        for line in lines:
            if line == '':
                continue
            vf_pci_bdf = line.split(" ")
            vf_pci = pci_dbdf_cut[0] +  ":" + vf_pci_bdf[0]
            ret, out = self.dut.cmd('ls /sys/bus/pci/devices/%s/net/' % vf_pci)
            vf = re.findall(".*", out)
            vfs.append(vf[0])
            vf_reps.append("")
        netifs_old = self.dut._netifs
        self.dut.cmd("udevadm settle")
        self.dut._get_netifs()
        vfs_and_reprs = set(self.dut._netifs) - set(netifs_old)
        vf_reps_tmp = set(vfs_and_reprs) - set(vfs)
        for vf_rep in vf_reps_tmp:
            _, out = self.dut.cmd('cat /sys/class/net/%s/phys_port_name' % vf_rep)
            m = re.findall("\d+", out)
            index = int(m[-1])
            vf_reps[index] = vf_rep
        return vfs, vf_reps

    def netdev_prep(self, fwname=None):
        LOG_sec("NFP netdev test prep")

        drv_load_record_ifcs(self, self.group, fwname=fwname)

        # Refresh the DUT interface list if its not populated.
        # This could happen when we reload the driver and interfaces changed
        if len(self.dut_ifn) == 0:
            self.dut_ifn = self.vnics
            self.dut_addr = [0] * len(self.vnics)
            self.dut_addr_v6 = [0] * len(self.vnics)

        for ifc in self.nfp_netdevs:
            self.dut.cmd('ip link set %s up' % (ifc))
        self.ifc_all_up()

        LOG_endsec() # NFP netdev test prep

        LOG_sec("NFP netdevs")
        LOG("all: " + str(self.nfp_netdevs))
        LOG("vnics: " + str(self.vnics))
        LOG("reprs: " + str(self.reprs))
        LOG("phys_netdevs: " + str(self.phys_netdevs))
        LOG_endsec()

    def check_prereq(self, check, description, on_src=False):
        if on_src:
            res, _ = self.src.cmd(check, fail=False)
        else:
            res, _ = self.dut.cmd(check, fail=False)

        if res == 1:
            if on_src:
                raise NtiSkip('SRC does not support feature:%s' % description)
            else:
                raise NtiSkip('DUT does not support feature:%s' % description)

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
        self.dut.cmd('reboot', fail=False)
        # Give it time to go down
        time.sleep(10)

        self.dut.wait_online()
        self.reinit_test()
        self.netdev_prep(fwname=fwname)

    def reload_driver(self, fwname=None):
        # Clear our IP address information.
        # If the test configuration changed, these no longer have any meaning.
        self.dut_addr = []
        self.dut_addr_v6 = []
        self.dut_ifn = []

        self.dut.nffw_unload()
        self.dut.reset_mods()
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

    def execute(self):
        pcap_src = self.prep_pcap(self.get_src_pkt())

        # Make sure there is connectivity
        self.ping(0)

        # Install prog
        ret = self.install_filter()
        if ret != 0:
            raise NtiError("Filter load failed")

        self.test_with_traffic(pcap_src, self.get_exp_pkt(),
                               self.get_tcpdump_params())
