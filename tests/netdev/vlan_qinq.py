#
# Copyright (C) 2022,  Corigine, Inc.  All rights reserved.
#
from netro.testinfra.nti_exceptions import NtiError
from ..common_test import CommonTest, NtiSkip


class VlanQinq(CommonTest):
    info = """
    Test the VLAN and QinQ header offloading functionality.

    The test verifies that:
    1. The features, tx-vlan-offload, rx-vlan-offload and
       rx-vlan-stag-hw-parse, exist and can be enabled.
    2. The driver automatically disables certain features when conflicting
       features are requested.
    3. Virtual interfaces can be created using VLAN protocols.
    4. Virtual interfaces can be created using QinQ protocols.
    """

    features_of_interest = ['rx-vlan-offload',
                            'tx-vlan-offload',
                            'rx-vlan-stag-hw-parse']
                        #   'tx-vlan-stag-hw-insert'
                        # QinQ tx offloading is not supported yet
    # This maps feature names (as they are reported with `ethtool -k`) to
    # setting names (as they need to be specified with `ethtool -K`)
    feature_name_mapping = {'rx-vlan-offload': 'rxvlan',
                            'tx-vlan-offload': 'txvlan',
                            'rx-vlan-stag-hw-parse': 'rx-vlan-stag-hw-parse'}
                        #   'tx-vlan-stag-hw-insert': 'tx-vlan-stag-hw-insert'
                        # QinQ tx offloading is not supported yet
    old_feature_states = {}
    created_interfaces = []

    def check_features_exist(self, iface):
        current_features = self.dut.ethtool_features_get(iface)
        for f in self.features_of_interest:
            if f not in current_features:
                raise NtiError("Feature %s not found in feature list" % f)

    def save_interface_feature_states(self, iface):
        current_features = self.dut.ethtool_features_get(iface)
        snapshot = {}
        for f in self.features_of_interest:
            if f in current_features:
                snapshot[f] = current_features[f]
        self.old_feature_states[iface] = snapshot

    def set_features(self, iface, features_states):
        # Set
        for f, s in features_states.items():
            self.dut.cmd('ethtool -K %s %s %s' % (iface,
                         self.feature_name_mapping[f], s.split(' ')[0]))
        # Verify set correctly
        self.check_features(iface, features_states)

    def check_features(self, iface, features_states):
        current_features = self.dut.ethtool_features_get(iface)
        for f, s in features_states.items():
            if not current_features[f].startswith(s):
                raise NtiError("Feature %s could not be "
                               "set to %s" % (f, s))

    def create_virtual_interface(self, base_if, new_if, proto, tag):
        legal, error, _ = self.dut.is_legal_interface_name(new_if)
        if not legal:
            raise NtiSkip(error)
        # Create
        self.dut.cmd('ip link add link %s name %s type vlan protocol '
                     '%s id %s' % (base_if, new_if, proto, tag))
        # Add to clean-up list
        self.created_interfaces.append((base_if, new_if))
        # Verify
        _, out = self.dut.cmd('ip -d link show %s' % new_if)
        out = out.split(' ')
        if 'vlan' not in out:
            raise NtiError('Virtual interface query: Not a VLAN interface')
        try:
            proto_index = out.index('protocol')
            proto_value = out[proto_index + 1]
            if proto_value.lower() != proto.lower():
                raise NtiError('Virtual interface query: Expected protocol '
                               '"%s", got "%s"' % (proto, proto_value))
        except (ValueError, IndexError):
            raise NtiError('Virtual interface query: No protocol reported')
        try:
            tag_index = out.index('id')
            tag_value = out[tag_index + 1]
            if tag_value != tag:
                raise NtiError('Virtual interface query: Expected id "%s", '
                               'got "%s"' % (tag, tag_value))
        except (ValueError, IndexError):
            raise NtiError('Virtual interface query: No id reported')

    def execute(self):
        # Check the bsp version as a minimum
        self.check_bsp_min('22.08-0')
        self.ifc_all_down()

        chip_model_number = self.dut.get_pci_device_id()
        if (chip_model_number not in ['3800', '4000']):
            raise NtiSkip("Test only supported on Kestrel (NFP3800) and "
                          "Osprey (NFP4000) cards")

        for iface in self.dut_ifn:
            # Step 1: Check features
            # ----------------------
            self.check_features_exist(iface)
            self.save_interface_feature_states(iface)

            # Note: VLAN and QinQ offloading are mutually exclusive and need to
            # be tested independently.

            # Step 2: Test mutual exclusivity of features
            # -------------------------------------------
            self.set_features(iface, {'rx-vlan-offload': 'off',
                                      'tx-vlan-offload': 'off',
                                      'rx-vlan-stag-hw-parse': 'off'})
            # Turn VLAN on
            self.set_features(iface, {'rx-vlan-offload': 'on',
                                      'tx-vlan-offload': 'on'})
            # Turn QinQ on
            self.set_features(iface, {'rx-vlan-stag-hw-parse': 'on'})
            # Verify VLAN turned off
            self.check_features(iface, {'rx-vlan-offload': 'off',
                                        'tx-vlan-offload': 'on'})
            # Turn VLAN on
            self.set_features(iface, {'rx-vlan-offload': 'on',
                                      'tx-vlan-offload': 'on'})
            # Verify QinQ turned off
            self.check_features(iface, {'rx-vlan-stag-hw-parse': 'off'})

            # Step 3: Test VLAN features
            # --------------------------
            self.set_features(iface, {'rx-vlan-offload': 'on',
                                      'tx-vlan-offload': 'on',
                                      'rx-vlan-stag-hw-parse': 'off'})
            vlan_id = '1000'
            vlan_pr = '802.1ad'
            vlan_if = '%s.%s' % (iface, vlan_id)
            _, _, vlan_if = self.dut.is_legal_interface_name(vlan_if)
            self.create_virtual_interface(iface, vlan_if, vlan_pr, vlan_id)
            # TODO: Send traffic and verify offloading counters increment
            self.cleanup_interfaces()

            # Step 4: Test QinQ features
            # --------------------------
            self.set_features(iface, {'rx-vlan-offload': 'off',
                                      'tx-vlan-offload': 'off',
                                      'rx-vlan-stag-hw-parse': 'on'})
            qinq_id = '4000'
            qinq_pr = '802.1q'
            qinq_if = '%s.%s' % (iface, qinq_id)
            self.create_virtual_interface(iface, vlan_if, vlan_pr, vlan_id)
            _, _, qinq_if = self.dut.is_legal_interface_name(qinq_if)
            self.create_virtual_interface(vlan_if, qinq_if, qinq_pr, qinq_id)
            # TODO: Send traffic and verify offloading counters increment
            self.cleanup_interfaces()

    def cleanup_interfaces(self):
        for base_if, created_if in reversed(self.created_interfaces):
            self.dut.cmd('ip link del link %s name %s' % (base_if, created_if))
            self.created_interfaces.pop()

    def restore_all_feature_states(self):
        for iface, snapshot in self.old_feature_states.items():
            self.set_features(iface, snapshot)
        self.old_feature_states = {}

    def cleanup(self):
        # Delete all created interfaces
        self.cleanup_interfaces()
        # Reset features
        self.restore_all_feature_states()
        self.ifc_all_up()
