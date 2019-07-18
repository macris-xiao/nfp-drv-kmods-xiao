#
# Copyright (C) 2019,  Netronome Systems, Inc.  All rights reserved.
#

import time

from netro.testinfra import LOG_sec, LOG, LOG_endsec
from netro.testinfra.nti_exceptions import NtiError

from ..common_test import assert_geq

from .base import KTLSTestBase

class KTLSTrafficTestBase(KTLSTestBase):
    def test_both_dir(self, ifc, v6, min_rx, min_tx, n_bytes, n_threads):
        if v6:
            dut_addr = self.group.addr_v6_x[0][:-3]
            src_addr = self.group.addr_v6_a[0][:-3]
        else:
            dut_addr = self.group.addr_x[0][:-3]
            src_addr = self.group.addr_a[0][:-3]

        # Spawn the sink
        LOG_sec("TX IPv%s" % ("6" if v6 else "4",))
        try:
            stats = self.dut.ethtool_stats(ifc)

            self.procs[self.src], port = \
                self.spawn_ktls_sink(self.src, v6=v6, tag=ifc)
            start = time.time()
            _, (out, err) = self.run_ktls_source(self.dut, server=src_addr,
                                                 port=port, length=n_bytes,
                                                 writesz=16000, n=n_threads,
                                                 v6=v6)
            end = time.time()
            # Kill sink
            self.kill_procs()

            if out or err:
                raise NtiError('KTLS source errors: ' + out + '\n' + err)

            Mbps = n_bytes * n_threads * 8 / (end - start) / 10 ** 6
            assert_geq(min_tx, Mbps, "Mbps")

            self.log('Result', 'time %.3f\nMbps %.2f' % (end - start, Mbps))

            self.test_comment += "%.2fMbps |" % (Mbps, )

            stats_diff = self.dut.ethtool_stats_diff(ifc, stats)
            assert_geq(min_tx, stats_diff['tx_tls_encrypted_packets'],
                       "Ethtool 'tx_tls_encrypted_packets'")
        finally:
            LOG_endsec()

        LOG_sec("RX IPv%s" % ("6" if v6 else "4",))
        try:
            stats = self.dut.ethtool_stats(ifc)

            self.procs[self.dut], port = \
                self.spawn_ktls_sink(self.dut, v6=v6, tag=ifc)
            start = time.time()
            _, (out, err) = self.run_ktls_source(self.src, server=dut_addr,
                                                 port=port, length=n_bytes,
                                                 writesz=16000, n=n_threads,
                                                 v6=v6)
            end = time.time()
            # Kill sink
            self.kill_procs()

            if out or err:
                raise NtiError('KTLS source errors: ' + out + '\n' + err)

            Mbps = n_bytes * n_threads * 8 / (end - start) / 10 ** 6
            assert_geq(min_rx, Mbps, "Mbps")

            self.log('Result', 'time %.3f\nMbps %.2f' % (end - start, Mbps))

            self.test_comment += "%.2fMbps|" % (Mbps, )

            stats_diff = self.dut.ethtool_stats_diff(ifc, stats)
            assert_geq(min_rx, stats_diff['rx_tls_decrypted_packets'],
                       "Ethtool 'rx_tls_decrypted_packets'")
        finally:
            LOG_endsec()

    def run_traffic_test(self, min_rx, min_tx, n_bytes=500000000, n_threads=12):
        ifc = self.group.eth_x[0]

        self.dut.copy_c_samples()
        self.src.copy_c_samples()

        # Make sure all are enabled
        self.tls_enable_all_feats()

        self.test_both_dir(ifc, True, min_rx, min_tx,
                           n_bytes=n_bytes, n_threads=n_threads)
        self.test_both_dir(ifc, False, min_rx, min_tx,
                           n_bytes=n_bytes, n_threads=n_threads)
