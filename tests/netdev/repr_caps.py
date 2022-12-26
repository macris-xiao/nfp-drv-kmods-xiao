#
# Copyright (C) 2018,  Netronome Systems, Inc.  All rights reserved.
#

import os
import random
import string
import netro.testinfra
from netro.testinfra.test import *
from ..common_test import CommonTest, NtiSkip, NtiError, assert_eq
from ..nfd import NfdBarOff, NfdCap, NfdTlvCap

class ReprCaps(CommonTest):
    info = """
    The purpose of this test is to confirm that the driver is correctly
    reporting the capabilities of a vNIC.

    The test initially checks to see if representors are available, before
    getting the vNIC and representor features. The hw-tc-offload value is
    set to OFF and the features are checked, with the actual values being
    compared to the expected values. The hw-tc-offload value is then set to
    ON and the features are checked again. This is repeated for all device
    capabilities.

    If any actual values do not match the expected values, the test will fail.
    """
    f_dont_care = { 'tx-nocache-copy', 'tx-checksumming', 'scatter-gather',
                    'generic-receive-offload', 'udp-fragmentation-offload',
                    'tcp-segmentation-offload' }

    def check_feature(self, feat, f, cap, mask, dflt):
        if cap & mask:
            exp = dflt
        else:
            exp = 'off [fixed]'
        assert_eq(exp, feat[f], "Feature '%s'" % (f))

    def check_features(self, rep, cap, highdma='on', rxcsum='on', txcsum='on',
                       rxhash='on', rxvlan='on', txvlan='on', sg='on',
                       tso='on', tso_mangleid='off', tc='on'):
        feat = self.dut.ethtool_features_get(rep)

        for f in feat:
            if f in self.f_dont_care:
                pass
            elif f == 'highdma':
                assert_eq(highdma, feat[f], "Feature '%s'" % (f))
            elif f == 'hw-tc-offload':
                assert_eq(tc, feat[f], "Feature '%s'" % (f))
            elif f in { 'tx-tcp-segmentation', 'tx-tcp6-segmentation'}:
                self.check_feature(feat, f, cap, NfdCap.LSO | NfdCap.LSO2, tso)
            elif f == 'tx-tcp-mangleid-segmentation':
                self.check_feature(feat, f, cap, NfdCap.LSO | NfdCap.LSO2, tso_mangleid)
            elif f == 'rx-checksumming':
                self.check_feature(feat, f, cap, NfdCap.RXCSUM, rxcsum)
            elif f in { 'tx-checksum-ipv4', 'tx-checksum-ipv6' }:
                self.check_feature(feat, f, cap, NfdCap.TXCSUM, txcsum)
            elif f == 'rx-vlan-offload':
                self.check_feature(feat, f, cap, NfdCap.RXVLAN, rxvlan)
            elif f == 'tx-vlan-offload':
                self.check_feature(feat, f, cap, NfdCap.TXVLAN, txvlan)
            elif f == 'receive-hashing' :
                self.check_feature(feat, f, cap, NfdCap.RSS | NfdCap.RSS2,
                                   rxhash)
            elif f == 'tx-scatter-gather':
                self.check_feature(feat, f, cap, NfdCap.GATHER, sg)
            elif f == 'generic-segmentation-offload':
                if cap & NfdCap.GATHER and sg == 'on':
                    exp = 'on'
                else:
                    exp = 'off [requested on]'
                assert_eq(exp, feat[f], "Feature '%s'" % (f))
            elif f == 'tx-lockless':
                assert_eq('on [fixed]', feat[f], "Feature '%s'" % (f))
            elif f == 'rx-gro-list':
                assert_eq('off', feat[f], "Feature '%s'" % (f))
            elif f == 'rx-udp-gro-forwarding':
                assert_eq('off', feat[f], "Feature '%s'" % (f))
            else:
                assert_eq('off [fixed]', feat[f], "Feature '%s'" % (f))

    def prepare(self):
        self.vnic_feat = None
        self.repr_feat = None
        return super(ReprCaps, self).prepare()

    def execute(self):
        self.dut.devlink_eswitch_mode_set('switchdev', fail=False)
        if len(self.group.reprs) == 0:
            raise NtiSkip('no reprs')

        vnic = self.group.vnics[0]
        rep = self.group.reprs[0]

        self.vnic_feat = self.dut.ethtool_features_get(vnic)
        self.repr_feat = self.dut.ethtool_features_get(rep)

        cap = self.dut.nfd_get_vnic_cap(vnic, NfdTlvCap.REPR_CAP)
        self.log('Read caps', cap)
        if cap is None:
            cap = 0
        else:
            cap = cap[0]

        # Check initial config
        self.check_features(rep, cap)

        # We should control TC offloads freely
        self.dut.cmd('ethtool -K %s hw-tc-offload off' % (rep))
        self.check_features(rep, cap, tc='off')
        self.dut.cmd('ethtool -K %s hw-tc-offload on' % (rep))
        self.check_features(rep, cap)

        # Nothing to test if we don't have repr caps
        if cap == 0:
            return

        # Turn high DMA off
        self.dut.cmd('ethtool -K %s highdma off' % (vnic))
        self.check_features(rep, cap, highdma='off [requested on]')

        self.dut.cmd('ethtool -K %s highdma on' % (vnic))
        self.check_features(rep, cap)
        self.dut.cmd('ethtool -K %s highdma off' % (rep))
        self.check_features(rep, cap, highdma='off')
        self.dut.cmd('ethtool -K %s highdma on' % (rep))

        # Turn VLAN features off
        if cap & NfdCap.RXVLAN:
            self.dut.cmd('ethtool -K %s rxvlan off' % (vnic))
            self.check_features(rep, cap, rxvlan='off [requested on]')

            self.dut.cmd('ethtool -K %s rxvlan on' % (vnic))
            self.check_features(rep, cap)
            self.dut.cmd('ethtool -K %s rxvlan off' % (rep))
            self.check_features(rep, cap, rxvlan='off')
            self.dut.cmd('ethtool -K %s rxvlan on' % (rep))

        if cap & NfdCap.TXVLAN:
            self.dut.cmd('ethtool -K %s txvlan off' % (vnic))
            self.check_features(rep, cap, txvlan='off [requested on]')

            self.dut.cmd('ethtool -K %s txvlan on' % (vnic))
            self.check_features(rep, cap)
            self.dut.cmd('ethtool -K %s txvlan off' % (rep))
            self.check_features(rep, cap, txvlan='off')
            self.dut.cmd('ethtool -K %s txvlan on' % (rep))

        # Turn RX csum off
        if cap & NfdCap.RXCSUM:
            self.dut.cmd('ethtool -K %s rx off' % (vnic))
            self.check_features(rep, cap, rxcsum='off [requested on]')

            self.dut.cmd('ethtool -K %s rx on' % (vnic))
            self.check_features(rep, cap)
            self.dut.cmd('ethtool -K %s rx off' % (rep))
            self.check_features(rep, cap, rxcsum='off')
            self.dut.cmd('ethtool -K %s rx on' % (rep))

        # Turn TX csum off
        if cap & NfdCap.TXCSUM:
            self.dut.cmd('ethtool -K %s tx off' % (vnic))
            self.check_features(rep, cap, txcsum='off [requested on]',
                                tso='off [requested on]')
            self.dut.cmd('ethtool -K %s tx on' % (vnic))
            self.check_features(rep, cap, tso='on')
            self.dut.cmd('ethtool -K %s tx off' % (rep))
            self.check_features(rep, cap, txcsum='off',
                                tso='off [requested on]')
            self.dut.cmd('ethtool -K %s tx on' % (rep))

        # Turn HASH features off
        if cap & (NfdCap.RSS | NfdCap.RSS2):
            self.dut.cmd('ethtool -K %s rxhash off' % (vnic))
            self.check_features(rep, cap, rxhash='off [requested on]')

            self.dut.cmd('ethtool -K %s rxhash on' % (vnic))
            self.check_features(rep, cap)
            self.dut.cmd('ethtool -K %s rxhash off' % (rep))
            self.check_features(rep, cap, rxhash='off')
            self.dut.cmd('ethtool -K %s rxhash on' % (rep))

        # Turn scatter-gather off
        if cap & NfdCap.GATHER:
            self.dut.cmd('ethtool -K %s sg off' % (vnic))
            self.check_features(rep, cap, sg='off [requested on]',
                                tso='off [requested on]')
            self.dut.cmd('ethtool -K %s sg on' % (vnic))
            self.check_features(rep, cap)
            self.dut.cmd('ethtool -K %s sg off' % (rep))
            self.check_features(rep, cap, sg='off',
                                tso='off [requested on]')
            self.dut.cmd('ethtool -K %s sg on' % (rep))

        # Turn LSO on
        if cap & (NfdCap.LSO | NfdCap.LSO2):
            if cap & (NfdCap.GATHER | NfdCap.TXCSUM) != \
                      NfdCap.GATHER | NfdCap.TXCSUM:
                raise NtiError('FW supports LSO without SG and TXCSUM')

            self.dut.cmd('ethtool -K %s tso on' % (rep), fail=False)
            self.check_features(rep, cap, tso='on', tso_mangleid='off [requested on]')
            self.dut.cmd('ethtool -K %s tso on' % (vnic))
            self.check_features(rep, cap, tso='on', tso_mangleid='on')

            # Turn SG off
            self.dut.cmd('ethtool -K %s sg off' % (vnic))
            self.check_features(rep, cap, sg='off [requested on]',
                                tso='off [requested on]',
                                tso_mangleid='off [requested on]')
            self.dut.cmd('ethtool -K %s sg on' % (vnic))

            # Turn txcsum off
            self.dut.cmd('ethtool -K %s tx off' % (vnic))
            self.check_features(rep, cap, txcsum='off [requested on]',
                                tso='off [requested on]',
                                tso_mangleid='off [requested on]')
            self.dut.cmd('ethtool -K %s tx on' % (vnic))

            # Also try just turning off txcsum on repr
            self.dut.cmd('ethtool -K %s tx off' % (rep))
            self.check_features(rep, cap, txcsum='off',
                                tso='off [requested on]',
                                tso_mangleid='off [requested on]')
            self.dut.cmd('ethtool -K %s tx on' % (rep))

            self.dut.cmd('ethtool -K %s tso off' % (rep))
            self.check_features(rep, cap, tso='off')
            self.dut.cmd('ethtool -K %s tso off' % (vnic))
            self.check_features(rep, cap, tso='off')

    def restore_feat(self, ifc, feat):
        if feat is None:
            return

        cmd = 'ethtool -K ' + ifc
        cmd += ' highdma ' + 'on' if feat['highdma'] else 'off'
        cmd += ' rxvlan ' + 'on' if feat['rx-vlan-offload'] else 'off'
        cmd += ' txvlan ' + 'on' if feat['tx-vlan-offload'] else 'off'
        cmd += ' rxhash ' + 'on' if feat['receive-hashing'] else 'off'
        cmd += ' rx ' + 'on' if feat['rx-checksumming'] else 'off'
        cmd += ' tx ' + 'on' if feat['tx-checksumming'] else 'off'
        cmd += ' tso ' + 'on' if feat['tx-tcp-segmentation'] else 'off'
        self.dut.cmd(cmd, fail=False)

    def cleanup(self):
        if self.vnic_feat:
            self.restore_feat(self.group.vnics[0], self.vnic_feat)
        if self.repr_feat:
            self.restore_feat(self.group.reprs[0], self.repr_feat)

        return super(ReprCaps, self).cleanup()
