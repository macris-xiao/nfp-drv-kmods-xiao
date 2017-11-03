#
# Copyright (C) 2016-2017,  Netronome Systems, Inc.  All rights reserved.
#

import netro.testinfra
from setup import NFPKmodSetup
from unit import NFPKmodUnit
from ebpf import NFPKmodBPF, NFPKmodXDPdrv
from rand import NFPKmodRand, NFPKmodRandErr
from reload import NFPKmodReload
from flower import NFPKmodFlower
from drv_grp import *

class Project(netro.testinfra.Project):
    """Tests for the NFP configured as Just-a-NIC with the physical
    ports represented as vNICs on the host."""

    summary = "Tests for the NFP configured as Just-a-NIC"

    _groups = { "setup" : NFPKmodSetup,
                "unit" :  NFPKmodUnit,
                "ebpf" :  NFPKmodBPF,
                "ebpfdrv" :  NFPKmodXDPdrv,
                "rand" :  NFPKmodRand,
                "rand_err" : NFPKmodRandErr,
                "reload" :   NFPKmodReload,
                "flower" :   NFPKmodFlower }