#
# Copyright (C) 2016,  Netronome Systems, Inc.  All rights reserved.
#
"""
Randomized test group for the NFP Linux drivers.
"""

import netro.testinfra

###########################################################################
# Unit Tests
###########################################################################


class NFPKmodRand(netro.testinfra.Group):
    """Randized tests for the NFP Linux drivers"""

    summary = "Randomized tests of NFP Linux driver."


class NFPKmodRandErr(NFPKmodRand):
    """Randized tests for the NFP Linux drivers with error injection"""

    summary = "Randomized tests of NFP Linux driver with error injection."
