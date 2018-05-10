#
# Copyright (C) 2018,  Netronome Systems, Inc.  All rights reserved.
#

import netro.testinfra
from netro.testinfra.test import *
from ..common_test import *
from ..unit.netconsole import NetconsoleTest
import random
import string
import time

class NetconsoleRandTest(NetconsoleTest):
    def init_state(self):
        self.xdp = None
        self.n_rings = 8
        self.n_bufs = 512

    def prepare(self):
        self.init_state()
        self.netcons_noise_running = False
        self.src_netperf = None
        self.dut_netperf = None
        return super(NetconsoleRandTest, self).prepare()

    def spawn_background_netcons_noise(self):
        name = 'netcons_noise_' + self._netconsname + '.pid'
        self.netcons_noise_pid = os.path.join(self.dut.tmpdir, name)

        self.dut.cmd('while true; do echo noise_%s > /dev/kmsg ; done '
                     ' >/dev/null 2>/dev/null & command ; echo $! > %s' %
                     (self._netconsname, self.netcons_noise_pid))
        self.netcons_noise_running = True

    def stop_background_netcons_noise(self):
        self.netcons_noise_running = False
        self.kill_pidfile(self.dut, self.netcons_noise_pid)

    def spawn_netperfs(self, port=0):
        name = 'netperf_' + self._netconsname + '.pid'

        cmd = ''' # spawn_netperfs
        echo > {pidfile};
        for i in `seq {n}`; do
            netperf -H {host} -l 0 -t TCP_STREAM -- -m 400 -M 400 \
                >/dev/null 2>/dev/null & command;
            echo $! >> {pidfile}
            sleep 0.1 # otherwise some fail to connect and kill barfs
        done
        '''

        self.dut_netperf = os.path.join(self.dut.tmpdir, name)
        self.dut.cmd(cmd.format(n=16, host=self.group.addr_a[port][:-3],
                                pidfile=self.dut_netperf))

        self.src_netperf = os.path.join(self.src.tmpdir, name)
        self.src.cmd(cmd.format(n=16, host=self.group.addr_x[port][:-3],
                                pidfile=self.src_netperf))

    def stop_netperfs(self):
        if self.dut_netperf:
            f = self.dut_netperf
            self.dut_netperf = None
            # DUT netperfs may have already died because we call this after
            # taking link down or unloading the driver, so max_fail=num_started.
            self.kill_pidfile(self.dut, f, max_fail=16)
        if self.src_netperf:
            f = self.src_netperf
            self.src_netperf = None
            self.kill_pidfile(self.src, f, max_fail=2)

    def flip_xdp(self):
        if self.xdp == None:
            if self.has_bpf_offload:
                self.xdp = 'drv' if random.randint(0, 1) else 'offload'
            else:
                self.xdp = 'drv'
            prog = 'pass.o' if self.xdp == 'drv' else 'map_atomic32.o'
            self.xdp_start(prog, mode=self.xdp)
        else:
            self.xdp_stop(mode=self.xdp)
            self.xdp = None

    def flip_link(self):
        self.ifc_all_down()
        self.ifc_all_up()
        self.n_bufs = 512

        # DUT -> SRC sessions will die from the ifdown
        self.stop_netperfs()
        self.spawn_netperfs()

    def flip_rings(self, port=0):
        self.n_rings = 8 if self.n_rings == 4 else 4
        self.dut.cmd('ethtool -L %s combined %d rx 0 tx 0' %
                     (self.dut_ifn[port], self.n_rings))

    def flip_bufs(self, port=0):
        self.n_bufs = 1024 if self.n_bufs == 2048 else 2048
        self.dut.cmd('ethtool -G %s rx %d tx %d' %
                     (self.dut_ifn[port], self.n_bufs, self.n_bufs))

    def flip_driver(self):
        self.dut.reset_mods()

        self.stop_netperfs()
        self.stop_background_netcons_noise()
        self.stop_netcons()

        self.netdev_prep()
        self.init_state()

        self.dut.link_wait(self.dut_ifn[self.port])

        self.spawn_netcons()
        self.spawn_background_netcons_noise()
        self.spawn_netperfs()

    def netdev_execute(self):
        self.netcons_prep()

        self.has_bpf_offload = self.read_scalar_nffw('_pf0_net_app_id') == 2
        self.dut.copy_bpf_samples()

        self.src.cmd('netserver', fail=False)
        self.dut.cmd('netserver', fail=False)

        self.spawn_netcons()
        self.spawn_background_netcons_noise()
        self.spawn_netperfs()

        for tid in range(1000):
            c = random.randint(0, 50)

            LOG_sec('Test #%d => %d' % (tid, c))
            try:
                if c < 20:
                    self.flip_xdp()
                elif c < 30:
                    self.flip_link()
                elif c < 40:
                    self.flip_rings()
                elif c < 50:
                    self.flip_bufs()
                else:
                    self.flip_driver()

                time.sleep(0.5)
                self.test_with_data(100)
            finally:
                LOG_endsec()

    def cleanup(self):
        if self.netcons_noise_running:
            self.stop_background_netcons_noise()
        self.stop_netperfs()
        return super(NetconsoleRandTest, self).cleanup()
