#
# Copyright (C) 2018,  Netronome Systems, Inc.  All rights reserved.
#

class NfdBarOff:
    MTU			= 0x18
    FLBUFSZ		= 0x1c
    VERSION		= 0x30
    MAX_RXRINGS		= 0x40
    MAX_MTU		= 0x44
    START_RXQ		= 0x4c
    RX_OFFSET		= 0x50
    TLV_BASE		= 0x58
    BPF_STACK_SZ	= 0x88

class NfdCtrl:
    ENABLE		= (0x1 <<  0)
    PROMISC		= (0x1 <<  1)
    L2BC		= (0x1 <<  2)
    L2MC		= (0x1 <<  3)
    RXCSUM		= (0x1 <<  4)
    TXCSUM		= (0x1 <<  5)
    RXVLAN		= (0x1 <<  6)
    TXVLAN		= (0x1 <<  7)
    SCATTER		= (0x1 <<  8)
    GATHER		= (0x1 <<  9)
    LSO			= (0x1 << 10)
    CTAG_FILTER		= (0x1 << 11)
    CMSG_DATA		= (0x1 << 12)
    RINGCFG		= (0x1 << 16)
    RSS			= (0x1 << 17)
    IRQMOD		= (0x1 << 18)
    RINGPRIO		= (0x1 << 19)
    MSIXAUTO		= (0x1 << 20)
    TXRWB		= (0x1 << 21)
    VXLAN		= (0x1 << 24)
    NVGRE		= (0x1 << 25)
    BPF			= (0x1 << 27)
    LSO2		= (0x1 << 28)
    RSS2		= (0x1 << 29)
    CSUM_COMPLETE	= (0x1 << 30)
    LIVE_ADDR		= (0x1 << 31)

class NfdCap(NfdCtrl):
    pass

class NfdTlvCap:
    UNKNOWN	= 0
    END		= 2
    REPR_CAP	= 7
