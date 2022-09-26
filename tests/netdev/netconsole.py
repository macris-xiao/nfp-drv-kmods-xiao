#
# Copyright (C) 2018,  Netronome Systems, Inc.  All rights reserved.
#

import os
import random
import string
import netro.testinfra
from netro.testinfra.test import *
from ..common_test import CommonTest, assert_equal

class NetconsoleTest(CommonTest):
    info = """
    Netconsole is a kernel module that logs kernel printk messages over UDP,
    the purpose of this test is to ensure that the driver is able to correctly
    log its activity using netconsole.

    The test will create a file in which to log the relevant information and
    then starts up netconsole with this file.

    Lines of data are then echoed, nstat is checked for packet losses and the netconsole
    process is stopped. More data is then echoed and then the contents of the file are
    logged. If the expected lines are then not present, the test will fail.
    """
    def prepare(self):
        self.port = 0
        self.netconsname = None
        self.nc_running = False

        return super(NetconsoleTest, self).prepare()

    def spawn_netcons(self, port=0):
        self.dut.cmd('modprobe netconsole')
        self._netconsname = ''.join(random.choice(string.ascii_uppercase +
                                                  string.digits) \
                                    for _ in range(8))
        self.netconsname = os.path.join('/sys/kernel/config/netconsole',
                                        self._netconsname)
        self.netconsport = random.randint(6000, 60000)

        cmd  = 'mkdir %s && ' % self.netconsname
        cmd += 'cd %s && ' % self.netconsname
        cmd += 'echo %s > remote_port && ' % self.netconsport
        cmd += 'echo %s > remote_ip && ' % self.group.addr_a[port][:-3]
        cmd += 'echo %s > dev_name && ' % self.dut_ifn[port]
        cmd += 'echo 1 > enabled'
        self.dut.cmd(cmd)

    def stop_netcons(self):
        self.dut.cmd('rmdir ' + self.netconsname, fail=False)
        self.netconsname = None

    def spawn_nc(self):
        self.netconsfile = os.path.join(self.src.tmpdir,
                                        'netcons_' + self._netconsname)
        self.netconspid = self.netconsfile + '.pid'

        # Copy the program over
        if not hasattr(self, 'src_udp_sink'):
            self.src_udp_sink = os.path.join(self.src.tmpdir,
                                             'udp_netcons_sink')
            self.src.cp_to(os.path.join(self.group.samples_c,
                                        'udp_netcons_sink'),
                           self.src_udp_sink)

        # Start listening
        self.src.cmd('{prog} {port} {outfile} & command ; echo $! > {pidfile}'
                     .format(prog=self.src_udp_sink, port=self.netconsport,
                             outfile=self.netconsfile, pidfile=self.netconspid))
        self.nc_running = True

    def stop_nc(self, wait_for_line=None):
        if wait_for_line:
            cmd = ''' # stop_nc
            t0=$(date +%s)
            while ! grep {line} {dump}; do
                if [ $(($(date +%s) - $t0)) -ge 30 ]; then
                    echo Timeout
                    break
                fi
            done
            '''

            self.src.cmd(cmd.format(line=wait_for_line, dump=self.netconsfile))
        self.nc_running = False
        self.kill_pidfile(self.src, self.netconspid)

        self.src.mv_from(self.netconsfile, self.group.tmpdir)
        return os.path.join(self.group.tmpdir,
                            os.path.basename(self.netconsfile))

    def test_with_data(self, n, fail=True):
        self.spawn_nc()

        cmd = ''
        for i in range(n):
            cmd += 'echo this_is_line_%d_ > /dev/kmsg && ' % i
        # Read nstat in case we loose packets to see if stack seen drops
        self.src.cmd('nstat')
        self.dut.cmd(cmd + 'true')

        self.src.cmd('nstat')
        data = self.stop_nc(wait_for_line='this_is_line_%d_' % (n - 1))
        self.src.cmd('nstat')
        with open(data, 'r') as myfile:
            data = myfile.read()

        # Log the contents
        self.log('File data - line hit count', data.count('this_is_line_'))
        self.log('File data', data)

        # Check all expected lines are present
        if fail:
            for i in range(n):
                assert_equal(1, data.count('this_is_line_%d_' % i), 'Line %d' % i)
        else:
            for i in range(n):
                if data.count('this_is_line_%d_' % i) != 1:
                    self.log("Fail log", "Line %d: expected '1' but was '%r'" % \
                             (i, data.count('this_is_line_%d_' % i)))
                    return 1
        return 0

    def netcons_prep(self):
        self.dut.skip_test_if_mode_switchdev()

        ## Enable pause frames and save old values (for NFP they're always on)
        self.src_pause = self.src.ethtool_pause_get(self.src_ifn[self.port])
        if self.src_pause:
            self.src.ethtool_pause_set(self.src_ifn[self.port],
                                       {"autoneg"	: self.src_pause["autoneg"],
                                        "rx"	: True,
                                        "tx"	: True })

        # Read ethtool stats in case we loose packets record start counters
        self.src.cmd('ethtool -S %s' % (self.src_ifn[self.port]))
        self.dut.cmd('ethtool -S %s' % (self.dut_ifn[self.port]))

        self.dut.link_wait(self.dut_ifn[self.port])

    def execute(self):
        self.netcons_prep()

        self.spawn_netcons()
        self.test_with_data(4)

    def cleanup(self):
        if self.nc_running:
            self.stop_nc()
        if self.netconsname:
            self.stop_netcons()
        # Read ethtool stats in case we loose packets to see if cards seen drops
        self.src.cmd('ethtool -S %s' % (self.src_ifn[self.port]))
        self.dut.cmd('ethtool -S %s' % (self.dut_ifn[self.port]))
        # Undo pause frame settings
        if hasattr(self, 'src_pause'):
            self.src.ethtool_pause_set(self.src_ifn[self.port], self.src_pause)
        return super(NetconsoleTest, self).cleanup()
