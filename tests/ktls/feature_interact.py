#
# Copyright (C) 2019,  Netronome Systems, Inc.  All rights reserved.
#

from netro.testinfra import LOG_sec, LOG, LOG_endsec

from ..common_test import NtiSkip, assert_geq

from .base import KTLSTestBase

class KTLSFeatureInteract(KTLSTestBase):
    def feat_set(self, ifc, state):
        if self.feat_state != state:
            self.dut.cmd("ethtool -K %s %s %s" % (ifc, self.feat_write, state))
        self.feat_state = state

    def check_one_ipv(self, ifc, v6):
        ipv = "IPv6 " if v6 else "IPv4 "

        addrs = self.group.addr_v6_x if v6 else self.group.addr_x
        daddr = addrs[0][:-3]
        addrs = self.group.addr_v6_a if v6 else self.group.addr_a
        saddr = addrs[0][:-3]

        # Start sinks
        self.procs[self.dut], dport = \
            self.spawn_ktls_sink(self.dut, v6=v6, tag=ifc)

        self.procs[self.src], sport = \
            self.spawn_ktls_sink(self.src, v6=v6, tag=ifc)
        # Remember stats
        stats = self.dut.ethtool_stats(ifc)

        LOG_sec("%s TLS 1.2 %s on" % (ipv, self.feat_read))
        try:
            self.feat_set(ifc, "on")
            self.run_ktls_source(self.src, server=daddr, port=dport,
                                 length=1000 * 1000, v6=v6, timeout=5)
            self.run_ktls_source(self.dut, server=saddr, port=sport,
                                 length=1000 * 1000, v6=v6, timeout=5)
        finally:
            LOG_endsec()

        LOG_sec("%s TLS 1.2 %s off" % (ipv, self.feat_read))
        try:
            self.feat_set(ifc, "off")
            self.run_ktls_source(self.src, server=daddr, port=dport,
                                 length=1000 * 1000, v6=v6, timeout=5)
            self.run_ktls_source(self.dut, server=saddr, port=sport,
                                 length=1000 * 1000, v6=v6, timeout=5)
        finally:
            LOG_endsec()

        # Make sure we actually used offload
        stats_diff = self.dut.ethtool_stats_diff(ifc, stats)
        assert_geq(50, stats_diff['rx_tls_decrypted_packets'],
                   "Ethtool 'rx_tls_decrypted_packets'")
        assert_geq(50, stats_diff['tx_tls_encrypted_packets'],
                   "Ethtool 'tx_tls_encrypted_packets'")

        self.kill_procs()

    def execute(self):
        self.init_feat_state = None

        ifc = self.group.eth_x[0]

        features = self.dut.ethtool_features_get(ifc)
        if features[self.feat_read] not in { 'on', 'off' }:
            raise NtiSkip("Fixed %s state '%s'" %
                          (self.feat_read, features[self.feat_read], ))
        self.init_feat_state = features[self.feat_read]
        self.feat_state = self.init_feat_state

        self.dut.copy_c_samples()
        self.src.copy_c_samples()

        self.tls_enable_all_feats()

        self.check_one_ipv(ifc, v6=False)
        self.check_one_ipv(ifc, v6=True)

    def cleanup(self):
        if self.init_feat_state:
            self.feat_set(self.group.eth_x[0], self.init_feat_state)

        return super(KTLSFeatureInteract, self).cleanup()

class KTLSFeatRxCsum(KTLSFeatureInteract):
    feat_read = "rx-checksumming"
    feat_write = "rx"

class KTLSFeatTxCsum(KTLSFeatureInteract):
    feat_read = "tx-checksumming"
    feat_write = "tx"

class KTLSFeatGro(KTLSFeatureInteract):
    feat_read = "generic-receive-offload"
    feat_write = "gro"

class KTLSFeatGso(KTLSFeatureInteract):
    feat_read = "generic-segmentation-offload"
    feat_write = "gso"

class KTLSFeatTso(KTLSFeatureInteract):
    feat_read = "tcp-segmentation-offload"
    feat_write = "tso"
