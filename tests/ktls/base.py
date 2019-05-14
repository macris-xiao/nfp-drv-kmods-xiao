#
# Copyright (C) 2019,  Netronome Systems, Inc.  All rights reserved.
#
import os
import random

from netro.testinfra.nrt_result import NrtResult

from ..common_test import CommonTest
from ..nfd import NfdCryptoCap

class KTLSTestBase(CommonTest):
    feat_map = {
        'tls-hw-tx-offload' : 0,
        'tls-hw-rx-offload' : 1,
        'tls-hw-record' : -1,
    }

    def kill_procs(self):
        for m in self.procs.keys():
            self.kill_pidfile(m, self.procs.pop(m), max_fail=4)

    def prepare(self):
        self.procs = dict()

        if self.dut.crypto_ops[NfdCryptoCap.TLS12_TX] and \
           self.dut.crypto_ops[NfdCryptoCap.TLS12_RX]:
            return
        return NrtResult(name=self.name, testtype=self.__class__.__name__,
                         passed=None, comment='FW lacks TLS 1.2 support')

    # TLS enable all helpers
    def tls_set_all_feats(self, ifc, want):
        features = self.dut.ethtool_features_get(ifc)

        cmd = ""
        for f in KTLSTestBase.feat_map.keys():
            bit = KTLSTestBase.feat_map[f]
            if bit == -1 or not self.dut.crypto_ops[bit]:
                continue

            if features[f] != want:
                cmd += 'ethtool -K %s %s %s && ' % (ifc, f, want)

        if cmd:
            self.dut.cmd(cmd + "true")
            return features
        else:
            return None

    def tls_enable_all_feats(self):
        self._feat_init = self.tls_set_all_feats(self.group.eth_x[0], "on")

    def _cleanup_tls_feats(self):
        if not hasattr(self, '_feat_init') or not self._feat_init:
            return

        ifc = self.group.eth_x[0]
        cmd = ''
        for f in KTLSTestBase.feat_map.keys():
            bit = KTLSTestBase.feat_map[f]
            if bit == -1 or not self.dut.crypto_ops[bit]:
                continue

            cmd += 'ethtool -K %s %s %s;' % (ifc, f, self._feat_init[f])
        self.dut.cmd(cmd + 'true')

    def cleanup(self):
        self.kill_procs()
        self._cleanup_tls_feats()

        return super(KTLSTestBase, self).cleanup()

    # Process spawning helpers
    def _spawn_sample_simple(self, host, prog, tag, opts):
        name = '{prog}_{tag}.pid'.format(prog=prog, tag=tag)
        pidfile = os.path.join(host.tmpdir, name)

        cmd = ''' # spawn_{prog}
        echo > {pidfile};
        {samples_dir}/{prog} {opts} >/dev/null 2>/dev/null & command;
        echo $! >> {pidfile}
        '''

        host.cmd(cmd.format(samples_dir=host.c_samples_dir,
                            prog=prog, opts=opts, pidfile=pidfile))
        return pidfile

    def spawn_ktls_sink(self, host, port=None, readsz=4000, tag="nti"):
        if port is None:
            port = random.randint(1024, 65535)
        opts = "-p {port} -r {readsz}".format(port=port, readsz=readsz)

        pidfile = self._spawn_sample_simple(host, "ktls_sink", tag, opts)

        return pidfile, port

    def spawn_ktls_source(self, host, server, port, length, writesz=4000,
                          sleep_len=0, sleep_ival=0, v6=False, tag="nti"):
        opts = "-s {server} -p {port} -l {length} -w {writesz}"
        opts = opts.format(server=server, port=port, length=length,
                           writesz=writesz)
        if sleep_len:
            opts += " -t %d" % (sleep_len, )
        if sleep_ival:
            opts += " -i %d" % (sleep_ival, )
        if v6:
            opts += " -6"

        return self._spawn_sample_simple(host, "ktls_source", tag, opts)
