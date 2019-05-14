#
# Copyright (C) 2019,  Netronome Systems, Inc.  All rights reserved.
#

from netro.testinfra import LOG_sec, LOG, LOG_endsec

from ..common_test import CommonTest, assert_eq
from ..nfd import NfdTlvCap

from .base import KTLSTestBase

# Use CommonTest as the base, KTLSTestBase would skip the test if no caps
class KTLSEthtoolCaps(CommonTest):
    def execute(self):
        ifc = self.group.eth_x[0]

        features = self.dut.ethtool_features_get(ifc)
        for f in KTLSTestBase.feat_map.keys():
            bit = KTLSTestBase.feat_map[f]
            if bit == -1 or not self.dut.crypto_ops[bit]:
                assert_eq("off [fixed]", features[f], "Feature '%s'" % (f, ))
            else:
                assert_eq("on", features[f], "Feature '%s'" % (f, ))

class KTLSEthtoolEnable(KTLSTestBase):
    def get_crypto_cap(self, ifc):
        crypto_cap = self.dut.nfd_get_vnic_cap(ifc, NfdTlvCap.CRYPTO)
        LOG_sec("Crypto cap")
        LOG(self.group.pp.pformat(crypto_cap))
        LOG_endsec()
        return crypto_cap

    def spawn_procs(self, src, sink, tag, v6):
        if sink == self.dut:
            addrs = self.group.addr_v6_x if v6 else self.group.addr_x
        else:
            addrs = self.group.addr_v6_a if v6 else self.group.addr_a
        addr = addrs[0][:-3]

        self.procs[sink], port = self.spawn_ktls_sink(sink, v6=v6, tag=tag)
        self.procs[src] = self.spawn_ktls_source(src, server=addr,
                                                 port=port, length=10000,
                                                 writesz=100,
                                                 sleep_len=1000 * 1000,
                                                 sleep_ival=1, v6=v6, tag=tag)

    def ifc_check_crypto_enabled(self, cond, ifc):
        crypto_cap = self.get_crypto_cap(ifc)
        # 4 words of caps, 4 words of enabled, we only care about enabled here
        for i in range(4):
            for b in range(32):
                assert_eq(cond(i * 32 + b), bool(crypto_cap[i + 4] & (1 << b)),
                          "Op #%d enabled" % (i * 32 + b, ))

    def check_one_ipv(self, ifc, v6):
        ipv = "IPv6 " if v6 else "IPv4 "
        LOG_sec(ipv + "TLS 1.2 RX bit")
        try:
            self.spawn_procs(self.src, self.dut, ifc, v6=v6)
            self.ifc_check_crypto_enabled((lambda i: i == 1), ifc)
        finally:
            LOG_endsec()

        # Reverse direction
        LOG_sec(ipv + "TLS 1.2 TX bit")
        try:
            self.kill_procs()
            self.spawn_procs(self.dut, self.src, ifc, v6=v6)
            # Now we should have enabled TLS 1.2 TX bit
            self.ifc_check_crypto_enabled((lambda i: i == 0), ifc)
        finally:
            LOG_endsec()

        # Disable again
        LOG_sec(ipv + "TLS 1.2 disable")
        try:
            self.kill_procs()
            self.ifc_check_crypto_enabled((lambda i: False), ifc)
        finally:
            LOG_endsec()

        # Now we're going to disable offload while things still run
        LOG_sec(ipv + "TLS 1.2 RX bit + disable at runtime")
        try:
            self.spawn_procs(self.src, self.dut, ifc, v6=v6)

            feats = self.tls_set_all_feats(ifc, "off")
            if self._feat_init is None:
                self._feat_init = feats
            # While procs run things should still be enabled
            self.ifc_check_crypto_enabled((lambda i: i == 1), ifc)
            # But not after procs get killed
            self.kill_procs()
            self.ifc_check_crypto_enabled((lambda i: False), ifc)
        finally:
            LOG_endsec()

        # And offload shouldn't be re-enabled
        LOG_sec(ipv + "TLS 1.2 w/ disabled offload")
        try:
            self.spawn_procs(self.dut, self.src, ifc, v6=v6)
            self.ifc_check_crypto_enabled((lambda i: False), ifc)
        finally:
            LOG_endsec()

        # Even after feature change, program restart is needed
        LOG_sec(ipv + "TLS 1.2 TX bit + disable at runtime")
        try:
            self.tls_set_all_feats(ifc, "on")
            self.ifc_check_crypto_enabled((lambda i: False), ifc)
            self.kill_procs()
            self.spawn_procs(self.dut, self.src, ifc, v6=v6)
            self.ifc_check_crypto_enabled((lambda i: i == 0), ifc)
            self.tls_set_all_feats(ifc, "off")
            self.ifc_check_crypto_enabled((lambda i: i == 0), ifc)

            self.kill_procs()
            self.ifc_check_crypto_enabled((lambda i: False), ifc)
        finally:
            LOG_endsec()

        self.tls_set_all_feats(ifc, "on")

    def execute(self):
        ifc = self.group.eth_x[0]

        self.dut.copy_c_samples()
        self.src.copy_c_samples()

        # Make sure all are enabled, driver will set the FW bit
        # as connections come and go
        self.tls_enable_all_feats()

        # All disabled to begin with
        self.ifc_check_crypto_enabled((lambda i: False), ifc)

        self.check_one_ipv(ifc, v6=False)
        self.check_one_ipv(ifc, v6=True)
