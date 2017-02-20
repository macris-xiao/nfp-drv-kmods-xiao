#
# Copyright (C) 2016-2017,  Netronome Systems, Inc.  All rights reserved.
#
"""
Randomized test group for the NFP Linux drivers.
"""

import math
import netro.testinfra
from ..reconfig_test import *
from ..drv_grp import NFPKmodGrp

###########################################################################
# Unit Tests
###########################################################################


class NFPKmodRand(NFPKmodGrp):
    """Randized tests for the NFP Linux drivers"""

    summary = "Randomized tests of NFP Linux driver."

    def __init__(self, name, cfg=None, quick=False, dut_object=None,
                 dut=None, nfp=None, nfpkmods=None, mefw=None):

        NFPKmodGrp.__init__(self, name=name, cfg=cfg, quick=quick,
                            dut_object=dut_object)

    def populate_tests(self):
        dut = (self.dut, self.addr_x, self.eth_x, self.addr_v6_x)
        src = (self.host_a, self.addr_a, self.eth_a, self.addr_v6_a)

        T = (
            ('reconfig', RandomReconfig, "Test reconfig"),
        )

        for t in T:
            self._tests[t[0]] = t[1](src, dut, self, t[0], t[2])


class NFPKmodRandErr(NFPKmodGrp):
    """Randized tests for the NFP Linux drivers with error injection"""

    summary = "Randomized tests of NFP Linux driver with error injection."

    def __init__(self, name, cfg=None, quick=False, dut_object=None,
                 dut=None, nfp=None, nfpkmods=None, mefw=None):

        NFPKmodGrp.__init__(self, name=name, cfg=cfg, quick=quick,
                            dut_object=dut_object)

    def populate_tests(self):
        dut = (self.dut, self.addr_x, self.eth_x, self.addr_v6_x)
        src = (self.host_a, self.addr_a, self.eth_a, self.addr_v6_a)

        T = (
            ('reconfig', RandomReconfig, "Test reconfig"),
        )

        for t in T:
            self._tests[t[0]] = t[1](src, dut, self, t[0], t[2],
                                     fail_policy=False)


class RandomReconfig(ReconfigTest):
    """Test class for random ethtool reconfiguration"""
    # Information applicable to all subclasses
    _gen_info = """
    Test random reconfiguration via ethtool
    """

    def do_one(self):
        val = random.randrange(0, 5 + self.has_xdp * 2 + (1 ^ self.fail_policy))
        val = val % (6 + self.has_xdp * 2)

        if val == 0:
            self.log('Run ifup', '')
            self.ifup()
            self.check_ring_config() # implies desc config
        elif val == 1:
            self.log('Run ifdown', '')
            self.ifdown()
        elif val == 2:
            rx = random.randrange(0, self.orig['ring_max_rx'])
            tx = random.randrange(0, self.orig['ring_max_tx'])
            comb = min(rx, tx)
            conf = (rx - comb, tx - comb, comb)
            self.log('Run set rings', str(conf))
            self.set_ring_config(conf)
            self.check_ring_config()
        elif val == 3:
            max_rx = int(math.log(self.orig['rxd_max'], 2))
            max_tx = int(math.log(self.orig['txd_max'], 2))
            rx = random.randrange(0, max_rx + 1 + 2)
            tx = random.randrange(0, max_tx + 1 + 2)

            # Limit the size to something reasonable, otherwise we will go OOM
            if rx > 14 and rx <= max_rx:
                rx = 14
            if tx > 14 and tx <= max_tx:
                tx = 14

            conf = (1 << rx, 1 << tx)
            self.log('Run set desc', str(conf))
            self.set_desc_config(conf)
            self.check_desc_config()
        elif val == 4:
            mtu = random.randrange(0, 8500)
            self.log('Run set mtu', str(mtu))
            self.set_mtu(mtu)
        elif val == 5:
            val = random.randrange(0, 3)
            if val == 0:
                self.log('Run reload', '')
                self.reload_mod()
                self.check_ring_config()
        elif val == 6:
            self.log('Run XDP pass', '')
            self.set_xdp_prog("pass")
            self.check_ring_config()
        elif val == 7:
            self.log('Run XDP --', '')
            self.set_xdp_prog()
            self.check_ring_config()

    def reconfig_execute(self):
        for n in range(0, 1500):
            self.do_one()
