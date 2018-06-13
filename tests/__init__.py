#
# Copyright (C) 2016-2017,  Netronome Systems, Inc.  All rights reserved.
#

import netro.testinfra
from setup import NFPKmodSetup
from unit import NFPKmodUnit
from ebpf import NFPKmodBPF, NFPKmodXDPdrv
from ebpf_perf import NFPKmodBPFPerf, NFPKmodBPFPerfdrv
from abm import NFPKmodBnic
from netdev import NFPKmodNetdev
from rand import NFPKmodRand, NFPKmodRandErr
from reload import NFPKmodReload
from reboot import NFPKmodReboot
from flower import NFPKmodFlower
from drv_grp import *

class Project(netro.testinfra.Project):
    """Tests for the NFP configured as Just-a-NIC with the physical
    ports represented as vNICs on the host."""

    summary = "Tests for the NFP configured as Just-a-NIC"

    _groups = { "setup" : NFPKmodSetup,
                "unit" :  NFPKmodUnit,
                "netdev"	: NFPKmodNetdev,
                "ebpf" :  NFPKmodBPF,
                "ebpfdrv" :  NFPKmodXDPdrv,
                "ebpf_perf" :  NFPKmodBPFPerf,
                "ebpf_perf_drv" :  NFPKmodBPFPerfdrv,
                "abm" :     NFPKmodBnic,
                "rand" :  NFPKmodRand,
                "rand_err" : NFPKmodRandErr,
                "reload" :   NFPKmodReload,
                "reboot" :   NFPKmodReboot,
                "flower" :   NFPKmodFlower }
