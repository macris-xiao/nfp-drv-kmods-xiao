#
# Copyright (C) 2018,  Netronome Systems, Inc.  All rights reserved.
#
import re
from netro.testinfra import LOG_sec, LOG, LOG_endsec
from netro.testinfra.nti_exceptions import NtiError
from ..common_test import CommonTest

class StatsEthtool(CommonTest):
    info = """
    The purpose of this test is to ensure that the command `ethtool -S`
    returns the correct statistics. Not necessarily that the statistics
    are correct, but that the statistics that the driver is supposed to
    support are present.

    This is done by running the ethtool command and then inspecting the
    number of statistics, of each known type, that are returned.

    If any stats are missing, the test will fail.
    """
    def check_sw_stats_present(self, keys, num_rings=1):
        if len(filter(lambda x: x.startswith('rvec_'), keys)) < 3 * num_rings:
            raise NtiError("rvec stats missing")
        if 'hw_rx_csum_ok' not in keys:
            raise NtiError("SW stats missing")

    def check_vnic_stats_present(self, keys):
        keys = filter(lambda x: x.startswith('dev_') or x.startswith('bpf_'),
                      keys)
        if len(keys) != 26:
            raise NtiError("Expected 26 vNIC stats, got %d" % (len(keys)))

    def check_vnic_queue_stats_present(self, keys, num_rings=1):
        if len(filter(lambda x: x.startswith('txq_'), keys)) < 2 * num_rings:
            raise NtiError("txq stats missing")
        if len(filter(lambda x: x.startswith('rxq_'), keys)) < 2 * num_rings:
            raise NtiError("rxq stats missing")

    def check_mac_stats_present(self, keys):
        keys = filter(lambda x: x.startswith('mac.'), keys)

        expected = 59 if self.mac_stats else 0

        if len(keys) != expected:
            raise NtiError("Expected %d MAC stats, got %d" %
                           (expected, len(keys)))

    def execute(self):
        for ifc in self.dut.nfp_netdevs:
            info = self.dut.ethtool_drvinfo(ifc)
            fw = info['firmware-version']
            vf_list = []
            # If this is sriov firmware then create a VF so those stats can be
            # included in the check as well
            if "sri" in fw:
                # create a vf
                vf_ifcs = self.spawn_vf_netdev(1)
                for vfs in vf_ifcs:
                    vf_list.append(vfs["name"])

        # Check if FW supports MAC stats
        self.mac_stats = self.read_sym_nffw('_mac_stats') is not None

        all_netdevs = vf_list + self.dut.nfp_netdevs
        names = {}
        stats = {}
        infos = {}
        for ifc in all_netdevs:
            _, out = self.dut.cmd('cat /sys/class/net/%s/phys_port_name || echo'
                                  % (ifc))
            names[ifc] = out.strip()

            infos[ifc] = self.dut.ethtool_drvinfo(ifc)
            stats[ifc] = self.dut.ethtool_stats(ifc)

        LOG_sec("Checking statistics")

        for ifc in all_netdevs:
            keys = stats[ifc].keys()

            # VF vNIC or PF vNIC (not a physical port vNIC)
            if names[ifc] == "" or re.match('^n\d*', names[ifc]):
                num_rings = self.dut.ethtool_channels_get(ifc)["max"]["rx"]

                self.check_sw_stats_present(keys, num_rings)
                self.check_vnic_stats_present(keys)
                self.check_vnic_queue_stats_present(keys, num_rings)

                LOG("Bare vNIC (PF representor/VF) OK: " + ifc)
                continue

            # PF/VF representor
            if re.match('^pf\d*', names[ifc]):
                self.check_vnic_stats_present(keys)

                if not all([x.startswith('dev_') or x.startswith('bpf_')
                            for x in keys]):
                    raise NtiError("VF representor has non-BAR stats")

                LOG("VF representor OK: " + ifc)
                continue

            # Physical port representor
            if self.nfp_ifc_is_repr(infos[ifc]) and \
               re.match('^p\d+', names[ifc]):
                self.check_mac_stats_present(keys)

                if not all([x.startswith('mac.') for x in keys]):
                    raise NtiError("MAC representor has non-MAC stats")

                LOG("Physical port representor OK: " + ifc)
                continue

            # Physical port vNIC
            if self.nfp_ifc_is_vnic(infos[ifc]) and \
               re.match('^p\d+', names[ifc]):
                num_rings = self.dut.ethtool_channels_get(ifc)["max"]["rx"]

                self.check_sw_stats_present(keys, num_rings)
                self.check_vnic_stats_present(keys)
                self.check_vnic_queue_stats_present(keys, num_rings)
                self.check_mac_stats_present(keys)

                LOG("Physical port vNIC OK: " + ifc)
                continue

            raise NtiError("Unknown netdev type: " + ifc)

        LOG_endsec()
