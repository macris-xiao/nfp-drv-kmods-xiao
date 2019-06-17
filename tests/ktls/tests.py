#
# Copyright (C) 2019,  Netronome Systems, Inc.  All rights reserved.
#
"""
kTLS offload NIC test group for the NFP Linux drivers.
"""
import os, pprint

from netro.testinfra import LOG_sec, LOG, LOG_endsec

from ..drv_grp import NFPKmodAppGrp
from ..nfd import NfdTlvCap

from .conn_stress import KTLSConnStress
from .drops import KTLSDropsThroughput
from .ethtool_enable import KTLSEthtoolCaps, KTLSEthtoolEnable
from .feature_interact import KTLSFeatRxCsum, KTLSFeatTxCsum, KTLSFeatTso, \
    KTLSFeatGro, KTLSFeatGso
from .high_throughput import KTLSHighThroughput
from .mangler import KTLSMangler
from .mixed_throughput import KTLSMixedThroughput

class NFPKmodKTLS(NFPKmodAppGrp):
    """kTLS NIC tests for the NFP Linux drivers"""

    summary = "kTLS NIC tests used for NFP Linux driver."

    def _init(self):
        self.pp = pprint.PrettyPrinter()
        NFPKmodAppGrp._init(self)

        # Make sorted lists of all netdev types
        old_vnics = self.vnics
        self.n_ports = len(old_vnics)

        self.parse_fw()

        return

    def parse_fw(self):
        self._parse_fw()

        found = False
        LOG_sec("KTLS NIC capabilities")
        for i in range(len(self.dut.crypto_ops)):
            if self.dut.crypto_ops[i]:
                LOG("Crypto bit#%d" % (i, ))
                found = True
        if not found:
            LOG("Not crypto capable")
        LOG_endsec()

    def _parse_fw(self):
        self.dut.crypto_ops = [False] * 4 * 4 * 8

        crypto_cap = self.dut.nfd_get_vnic_cap(self.eth_x[0], NfdTlvCap.CRYPTO)
        if crypto_cap is None or len(crypto_cap) < 8:
            return

        # 4 words of caps, 4 words of enabled, we only care about caps here
        for i in range(4):
            for b in range(32):
                self.dut.crypto_ops[i * 32 + b] = bool(crypto_cap[i] & (1 << b))

    def populate_tests(self):
        dut = (self.dut, self.addr_x, self.eth_x, self.addr_v6_x)
        src = (self.host_a, self.addr_a, self.eth_a, self.addr_v6_a)

        tests = (
            ('ktls_ethtool_caps', KTLSEthtoolCaps, 'basic kTLS ethtool caps'),
            ('ktls_ethtool_ena', KTLSEthtoolEnable, 'kTLS ethtool enable'),
            ('ktls_conn_stress', KTLSConnStress,
             'kTLS connection stress - opening and closing lots of connections'),
            ('ktls_rxcsum', KTLSFeatRxCsum, 'interaction with RX csum offload'),
            ('ktls_txcsum', KTLSFeatTxCsum, 'interaction with TX csum offload'),
            ('ktls_gro', KTLSFeatGro, 'interaction with GRO'),
            ('ktls_gso', KTLSFeatGso, 'interaction with GSO'),
            ('ktls_tso', KTLSFeatTso, 'interaction with TSO'),
            ('ktls_traffic_bw', KTLSHighThroughput,
             'kTLS connection bandwidth'),
            ('ktls_traffic_drops', KTLSDropsThroughput,
             'kTLS connection bandwidth with drops'),
            ('ktls_traffic_mixed', KTLSMixedThroughput,
             'kTLS connection bandwidth with other TCP traffic'),
            ('ktls_mangle_pkts', KTLSMangler,
             'kTLS connection with packet corruption'),
        )

        for t in tests:
            self._tests[t[0]] = t[1](src, dut, group=self, name=t[0],
                                     summary=t[2])
