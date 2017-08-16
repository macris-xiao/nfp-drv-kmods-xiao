##
## Copyright (C) 2016-2017,  Netronome Systems, Inc.  All rights reserved.
##

import binascii
import os
import struct
import time

from elftools.elf.elffile import ELFFile
from elftools.elf.sections import SymbolTableSection

from netro.testinfra.nrt_result import NrtResult
from netro.testinfra.nti_exceptions import NtiGeneralError
from netro.testinfra.test import Test
from netro.testinfra import LOG_init, LOG_sec, LOG, LOG_endsec, CMD

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

    def tc_bpf_load(self, obj=None, flags=None):
        if not obj:
            obj = self.obj_name
        if not flags:
            flags = self.tc_flags

        obj_full = os.path.join(self.dut.bpf_samples_dir, obj)
        cmd = 'tc filter add dev %s parent ffff:  bpf obj %s %s %s' % \
              (self.dut_ifn[0], obj_full, flags, self.act)

        ret, _ = self.dut.cmd(cmd, fail=False)
        return ret

    def xdp_start(self, prog):
        return self.dut.cmd('ip -force link set dev %s xdp obj %s sec ".text"' %
                            (self.dut_ifn[0],
                             os.path.join(self.dut.xdp_samples_dir, prog)))

    def xdp_stop(self):
        return self.dut.cmd('ip -force link set dev %s xdp off' %
                            (self.dut_ifn[0]))

    def ping(self, port, count=10, size=0, pattern="", fail=True):
        opts = ""
        if size:
            opts = opts + "-s %d " % (size)
        if pattern:
            opts = opts + "-p %s " % (pattern)

        ret, _ = self.src.cmd('ping -c %d -i0.05 -W2 %s -I %s %s' %
                              (count, opts, self.src_ifn[port],
                               self.dut_addr[port][:-3]), fail=False)
        if ret and fail:
            raise NtiGeneralError("Couldn't ping endpoint")
        if ret == 0 and not fail:
            raise NtiGeneralError("Could ping endpoint")


    def ping6(self, port, count=10, fail=True):
        ret, _ = self.src.cmd('ping6 -c %d -i0.1 -W5 -I %s %s' %
                              (count, self.src_ifn[port],
                               self.dut_addr_v6[port][:-3]), fail=False)
        if ret and fail:
            raise NtiGeneralError("Couldn't ping6 endpoint")
        if ret == 0 and not fail:
            raise NtiGeneralError("Could ping6 endpoint")


    def tcpping(self, port, count=10, sport=100, dport=58, fail=True):
        ret, _ = self.src.cmd('hping3 %s --fast -c %d -s %d -p %d -d 50 -k --syn' %
                              (self.dut_addr[port][:-3], count, sport, dport),
                              fail=False)
        if ret != 0 and fail:
            raise NtiGeneralError("Couldn't TCP ping endpoint")
        if ret == 0 and not fail:
            raise NtiGeneralError("Could TCP ping endpoint")

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

                start = symbol['st_value'] - sec['sh_addr']
                end = start + symbol['st_size']

                value = sec.data()[start:end]

                LOG_sec('NFFW symbol lookup: ' + name)
                LOG('section idx:\t' + str(symbol['st_shndx']))
                LOG('size:\t\t' + str(symbol['st_size']))
                LOG('position:\t\t' + hex(symbol['st_value']))
                LOG('section start:\t' + hex(sec['sh_addr']))
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

    # Load the driver, with non-upstream mode don't spawn netdev,
    # in upstream mode do, since it's the only way there.
    def drv_load_any(self):
        M = self.dut

        if not self.group.upstream_drv:
            M.insmod()
            return

        # Upstream mode
        # Copy the FW over
        if self.group.netdevfw:
            M.cmd('mkdir -p /lib/firmware/netronome')
            M.cp_to(self.group.netdevfw,
                    '/lib/firmware/netronome/%s' % (M.get_fw_name_serial()))
        else:
            M.cp_to(self.dut.netdevfw_dir, '/lib/firmware/netronome')

        M.rm_dir_on_clean('/lib/firmware/netronome')

        M.insmod(netdev=None)

    # Load the driver for netdev operation.
    def drv_load_netdev_conserving(self, fwname):
        # In upstream mode, just load the driver, there are no tricks
        # to pull off.
        if self.group.upstream_drv:
            self.drv_load_any()
            return

        # With non-upstream driver, load the module, see if FW is already there,
        # if it isn't load it manually so that the driver won't reset it.
        M = self.dut

        if not fwname:
            fwname = self.group.netdevfw
        else:
            fwname = os.path.join(self.dut.netdevfw_dir, fwname)

        M.insmod(netdev=True, userspace=True)
        ret, _ = M.cmd_rtsym('_pf0_net_bar0', fail=False)
        if ret != 0:
            M.nffw_unload()
            M.nffw_load('%s' % fwname)
            M.rmmod()
            M.insmod(netdev=True, userspace=True)

        M.insmod(module="nth")

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
    def netdev_prep(self, fwname=None):
        self.drv_load_netdev_conserving(fwname)
        self.ifc_all_up()

    def execute(self):
        self.netdev_prep()

        self.netdev_execute()

    def cleanup(self):
        self.dut.reset_mods()
        self.dut.reset_dirs()

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
