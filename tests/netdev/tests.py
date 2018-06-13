#
# Copyright (C) 2018,  Netronome Systems, Inc.  All rights reserved.
#
"""
ABM NIC test group for the NFP Linux drivers.
"""

from ..drv_grp import NFPKmodAppGrp
from netconsole import NetconsoleTest

class NFPKmodNetdev(NFPKmodAppGrp):
    """Basic FW-independent NIC tests for the NFP Linux drivers"""

    summary = "FW-independent NIC tests used for NFP Linux driver."

    def populate_tests(self):
        dut = (self.dut, self.addr_x, self.eth_x, self.addr_v6_x)
        src = (self.host_a, self.addr_a, self.eth_a, self.addr_v6_a)

        tests = (
            ('netconsole', NetconsoleTest, 'Test netconsole over the NFP'),
        )

        for t in tests:
            self._tests[t[0]] = t[1](src, dut, group=self, name=t[0],
                                     summary=t[2])
