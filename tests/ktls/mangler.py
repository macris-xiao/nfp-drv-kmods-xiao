#
# Copyright (C) 2019,  Netronome Systems, Inc.  All rights reserved.
#

import time, os

from netro.testinfra import LOG_sec, LOG, LOG_endsec
from netro.testinfra.nti_exceptions import NtiError

from .base import KTLSTestBase

class KTLSMangler(KTLSTestBase):
    def check_one_ipv(self, ifc_dut, ifc_src, v6):
        ipv = "IPv6 " if v6 else "IPv4 "

        n_bytes = 500000000
        n_threads = 12

        if v6:
            dut_addr = self.group.addr_v6_x[0][:-3]
            src_addr = self.group.addr_v6_a[0][:-3]
        else:
            dut_addr = self.group.addr_x[0][:-3]
            src_addr = self.group.addr_a[0][:-3]

        self.procs[self.dut], dut_port = \
            self.spawn_ktls_sink(self.dut, v6=v6, tag=ifc_dut)
        self.procs[self.src], src_port = \
            self.spawn_ktls_sink(self.src, v6=v6, tag=ifc_src)

        LOG_sec(ipv + "TLS 1.2 TX with offload")
        try:
            start = time.time()
            _, (out, err) = self.run_ktls_source(self.dut, server=src_addr,
                                                 port=src_port, length=n_bytes,
                                                 writesz=16000, n=n_threads,
                                                 v6=v6, timeout=15)
            end = time.time()
            # If TX is offloaded we should be all good
            if err:
                raise NtiError('KTLS offload run failed: %d ' % (err, ))
            if end - start >= 15:
                raise NtiError('KTLS offload run timed out')
            if out.count('\n') > 2:
                raise NtiError('KTLS offload many errors: ' + out + '\n')
        finally:
            LOG_endsec()

        LOG_sec(ipv + "TLS 1.2 TX without offload")
        try:
            _, (out, err) = self.run_ktls_source(self.dut, server=dut_addr,
                                                 port=dut_port, length=n_bytes,
                                                 writesz=16000, n=n_threads,
                                                 v6=v6, timeout=15)
            # If TX is not offloaded we should see a lot of errors
            if err:
                raise NtiError('KTLS non-offload run failed: %d ' % (err, ))
            if end - start >= 15:
                raise NtiError('KTLS non-offload run timed out')
            if out.count('\n') < n_threads * 3 / 4 or err:
                raise NtiError('KTLS non-offload few errors: ' + out + '\n')
        finally:
            LOG_endsec()

        self.kill_procs()

    def setup_tcf(self, host, ifc):
        host.copy_bpf_samples()
        prog = os.path.join(host.bpf_samples_dir, 'mangler.o')
        host.cmd('tc qdisc add dev %s clsact' % (ifc))
        self.tc_set[host] = True
        host.cmd('tc filter add dev %s egress prio 101 protocol all bpf obj %s' %
                 (ifc, prog))

    def prepare(self):
        self.tc_set = dict()
        self.tc_set[self.dut] = False
        self.tc_set[self.src] = False
        self.src_reenable = False

        return super(KTLSMangler, self).prepare()

    def execute(self):
        ifc_dut = self.dut_ifn[0]
        ifc_src = self.src_ifn[0]

        self.dut.copy_c_samples()
        self.src.copy_c_samples()

        self.setup_tcf(self.dut, ifc_dut)
        self.setup_tcf(self.src, ifc_src)

        # Make sure all are enabled, driver will set the FW bit
        # as connections come and go
        self.tls_enable_all_feats()

        # Disable offload on source if enabled, we want the stack to do encrypt
        features = self.src.ethtool_features_get(ifc_src)
        if 'tls-hw-tx-offload' in features and \
           features['tls-hw-tx-offload'][:2] == 'on':
            self.src_reenable = True
            self.src.cmd('ethtool -K %s tls-hw-tx-offload off' % (ifc_src))

        self.check_one_ipv(ifc_dut, ifc_src, v6=False)
        self.check_one_ipv(ifc_dut, ifc_src, v6=True)

    def cleanup(self):
        ifc_dut = self.dut_ifn[0]
        ifc_src = self.src_ifn[0]

        if self.src_reenable:
            self.src.cmd('ethtool -K %s tls-hw-tx-offload on' % (ifc_src))
        if self.tc_set[self.dut]:
            self.dut.cmd('tc qdisc delete dev %s clsact' % (ifc_dut))
        if self.tc_set[self.src]:
            self.src.cmd('tc qdisc delete dev %s clsact' % (ifc_src))

        return super(KTLSMangler, self).cleanup()
