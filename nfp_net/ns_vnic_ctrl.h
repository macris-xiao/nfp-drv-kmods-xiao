/*
 * Copyright 2014-2015 Netronome, Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 * vim:shiftwidth=8:noexpandtab
 *
 * @file kernel/ns_vnic_ctrl.h
 *
 * Netronome vNIC driver: Control BAR layout
 */
#ifndef _NS_VNIC_CTRL_H_
#define _NS_VNIC_CTRL_H_

/**
 * Configuration BAR size.
 *
 * The configuration BAR is 8K in size, but on the NFP6000, due to
 * THB-350, 32k needs to be reserved.
 */
#ifdef __NFP_IS_6000
#define NS_VNIC_CFG_BAR_SZ		(32 * 1024)
#else
#define NS_VNIC_CFG_BAR_SZ		(8 * 1024)
#endif

/**
 * Offset in Freelist buffer where packet starts on RX
 */
#define NS_VNIC_RX_OFFSET		32

/**
 * Hash type pre-pended when a RSS hash was computed
 */
#define NS_VNIC_RSS_NONE		0
#define NS_VNIC_RSS_IPV4		1
#define NS_VNIC_RSS_IPV6		2
#define NS_VNIC_RSS_IPV6_EX		3
#define NS_VNIC_RSS_IPV4_TCP		4
#define NS_VNIC_RSS_IPV6_TCP		5
#define NS_VNIC_RSS_IPV6_EX_TCP		6
#define NS_VNIC_RSS_IPV4_UDP		7
#define NS_VNIC_RSS_IPV6_UDP		8
#define NS_VNIC_RSS_IPV6_EX_UDP		9

/**
 * @NS_VNIC_TXR_MAX:         Maximum number of TX rings
 * @NS_VNIC_TXR_MASK:        Mask for TX rings
 * @NS_VNIC_RXR_MAX:         Maximum number of RX rings
 * @NS_VNIC_RXR_MASK:        Mask for RX rings
 */
#define NS_VNIC_TXR_MAX			64
#define NS_VNIC_TXR_MASK		(NS_VNIC_TXR_MAX - 1)
#define NS_VNIC_RXR_MAX			64
#define NS_VNIC_RXR_MASK		(NS_VNIC_RXR_MAX - 1)

/**
 * Read/Write config words
 * @NS_VNIC_CFG_CTRL:        Global control
 * @NS_VNIC_CFG_UPDATE:      Indicate which fields are updated
 * @NS_VNIC_CFG_TXRS_ENABLE: Bitmask of enabled TX rings
 * @NS_VNIC_CFG_RXRS_ENABLE: Bitmask of enabled RX rings
 * @NS_VNIC_CFG_MTU:         Set MTU size
 * @NS_VNIC_CFG_FLBUFSZ:     Set freelist buffer size (must be larger than MTU)
 * @NS_VNIC_CFG_EXN:         MSI-X table entry for exceptions
 * @NS_VNIC_CFG_LSC:         MSI-X table entry for link state changes
 * @NS_VNIC_CFG_MACADDR:     MAC address
 *
 * TODO:
 * - define Error details in UPDATE
 */
#define NS_VNIC_CFG_CTRL		0x0000
#define   NS_VNIC_CFG_CTRL_ENABLE	  (0x1 <<  0) /* Global enable */
#define   NS_VNIC_CFG_CTRL_PROMISC	  (0x1 <<  1) /* Enable Promisc mode */
#define   NS_VNIC_CFG_CTRL_L2BC		  (0x1 <<  2) /* Allow L2 Broadcast */
#define   NS_VNIC_CFG_CTRL_L2MC		  (0x1 <<  3) /* Allow L2 Multicast */
#define   NS_VNIC_CFG_CTRL_RXCSUM	  (0x1 <<  4) /* Enable RX Checksum */
#define   NS_VNIC_CFG_CTRL_TXCSUM	  (0x1 <<  5) /* Enable TX Checksum */
#define   NS_VNIC_CFG_CTRL_RXVLAN	  (0x1 <<  6) /* Enable VLAN strip */
#define   NS_VNIC_CFG_CTRL_TXVLAN	  (0x1 <<  7) /* Enable VLAN insert */
#define   NS_VNIC_CFG_CTRL_SCATTER	  (0x1 <<  8) /* Scatter DMA */
#define   NS_VNIC_CFG_CTRL_GATHER	  (0x1 <<  9) /* Gather DMA */
#define   NS_VNIC_CFG_CTRL_LSO		  (0x1 << 10) /* LSO/TSO */
#define   NS_VNIC_CFG_CTRL_RINGCFG	  (0x1 << 16) /* Ring runtime changes */
#define   NS_VNIC_CFG_CTRL_RSS		  (0x1 << 17) /* RSS */
#define   NS_VNIC_CFG_CTRL_IRQMOD	  (0x1 << 18) /* Interrupt moderation */
#define   NS_VNIC_CFG_CTRL_RINGPRIO	  (0x1 << 19) /* Ring priorities */
#define   NS_VNIC_CFG_CTRL_MSIXAUTO	  (0x1 << 20) /* MSI-X auto-masking */
#define   NS_VNIC_CFG_CTRL_TXRWB	  (0x1 << 21) /* Write-back of TX ring*/
#define   NS_VNIC_CFG_CTRL_L2SWITCH	  (0x1 << 22) /* L2 Switch */
#define   NS_VNIC_CFG_CTRL_L2SWITCH_LOCAL (0x1 << 23) /* Switch to local */
#define NS_VNIC_CFG_UPDATE		0x0004
#define   NS_VNIC_CFG_UPDATE_GEN	  (0x1 <<  0) /* General update */
#define   NS_VNIC_CFG_UPDATE_RING	  (0x1 <<  1) /* Ring config change */
#define   NS_VNIC_CFG_UPDATE_RSS	  (0x1 <<  2) /* RSS config change */
#define   NS_VNIC_CFG_UPDATE_TXRPRIO	  (0x1 <<  3) /* TX Ring prio change */
#define   NS_VNIC_CFG_UPDATE_RXRPRIO	  (0x1 <<  4) /* RX Ring prio change */
#define   NS_VNIC_CFG_UPDATE_MSIX	  (0x1 <<  5) /* MSI-X change */
#define   NS_VNIC_CFG_UPDATE_L2SWITCH	  (0x1 <<  6) /* Switch config change */
#define   NS_VNIC_CFG_UPDATE_ERR	  (0x1 << 31) /* A error occurred */
#define NS_VNIC_CFG_TXRS_ENABLE		0x0008
#define NS_VNIC_CFG_RXRS_ENABLE		0x0010
#define NS_VNIC_CFG_MTU			0x0018
#define NS_VNIC_CFG_FLBUFSZ		0x001c
#define NFP_NET_CFG_EXN			0x001f
#define NS_VNIC_CFG_LSC			0x0020
#define NS_VNIC_CFG_MACADDR		0x0024

/**
 * Read-only words:
 * @NS_VNIC_CFG_VERSION:     Firmware version number
 * @NS_VNIC_CFG_STS:         Status
 * @NS_VNIC_CFG_CAP:         Capabilities (same bits as @NS_VNIC_CFG_CTRL)
 * @NS_VNIC_MAX_TXRINGS:     Maximum number of TX rings
 * @NS_VNIC_MAX_RXRINGS:     Maximum number of RX rings
 * @NS_VNIC_MAX_MTU:         Maximum support MTU
 * @NS_VNIC_CFG_START_TXQ:   Start Queue Control Queue to use for TX (PF only)
 * @NS_VNIC_CFG_START_RXQ:   Start Queue Control Queue to use for RX (PF only)
 *
 * TODO:
 * - define more STS bits
 */
#define NS_VNIC_CFG_VERSION		0x0030
#define NS_VNIC_CFG_STS			0x0034
#define   NS_VNIC_CFG_STS_LINK		  (0x1 << 0) /* Link up or down */
#define NS_VNIC_CFG_CAP			0x0038
#define NS_VNIC_CFG_MAX_TXRINGS		0x003c
#define NS_VNIC_CFG_MAX_RXRINGS		0x0040
#define NS_VNIC_CFG_MAX_MTU		0x0044
#define NS_VNIC_CFG_START_TXQ		0x0048
#define NS_VNIC_CFG_START_RXQ		0x004c

/*
 * YDS-155 workaround for the NFP-3200
 * @NS_VNIC_CFG_SPARE_ADDR:  Host DMA address for ME code to use as it likes
 */
#define NS_VNIC_CFG_SPARE_ADDR		0x0060

/**
 * RSS configuration (only when NS_VNIC_CFG_CTRL_RSS is enabled)
 * @NS_VNIC_CFG_RSS_CFG:     RSS configuration word
 * @NS_VNIC_CFG_RSS_KEY:     RSS "secret" key
 * @NS_VNIC_CFG_RSS_ITBL:    RSS indirection table
 */
#define NS_VNIC_CFG_RSS_BASE		0x0100
#define NS_VNIC_CFG_RSS_CTRL		NS_VNIC_CFG_RSS_BASE
#define   NS_VNIC_CFG_RSS_MASK		  (0x7f)
#define   NS_VNIC_CFG_RSS_MASK_of(_x)	  ((_x) & 0x7f)
#define   NS_VNIC_CFG_RSS_IPV4		  (1 <<  8) /* RSS for IPv4 */
#define   NS_VNIC_CFG_RSS_IPV6		  (1 <<  9) /* RSS for IPv6 */
#define   NS_VNIC_CFG_RSS_IPV4_TCP	  (1 << 10) /* RSS for IPv4/TCP */
#define   NS_VNIC_CFG_RSS_IPV4_UDP	  (1 << 11) /* RSS for IPv4/UDP */
#define   NS_VNIC_CFG_RSS_IPV6_TCP	  (1 << 12) /* RSS for IPv6/TCP */
#define   NS_VNIC_CFG_RSS_IPV6_UDP	  (1 << 13) /* RSS for IPv6/UDP */
#define   NS_VNIC_CFG_RSS_TOEPLITZ	  (1 << 24) /* Use Toeplitz hash */
#define NS_VNIC_CFG_RSS_KEY		(NS_VNIC_CFG_RSS_BASE + 0x4)
#define NS_VNIC_CFG_RSS_KEY_SZ		0x28
#define NS_VNIC_CFG_RSS_ITBL		(NS_VNIC_CFG_RSS_BASE + 0x4 + \
					 NS_VNIC_CFG_RSS_KEY_SZ)
#define NS_VNIC_CFG_RSS_ITBL_SZ		0x80

/**
 * TX ring configuration
 * @NS_VNIC_CFG_TXR_BASE:    Base offset for TX ring configuration
 * @NS_VNIC_CFG_TXR_ADDR:    Offset of host address for TX ring _x
 * @NS_VNIC_CFG_TXR_WB_ADDR: Offset of host addr for TX ring _x ptr write back
 * @NS_VNIC_CFG_TXR_SZ:      Offset to configure size for ring _x
 * @NS_VNIC_CFG_TXR_VEC:     Offset to set MSI-X table entry for ring _x
 * @NS_VNIC_CFG_TXR_PRIO:    Offset to set per TX ring priorities for ring _x.
 */
#define NS_VNIC_CFG_TXR_BASE		0x0200
#define NS_VNIC_CFG_TXR_ADDR(_x)	(NS_VNIC_CFG_TXR_BASE + ((_x) * 0x8))
#define NS_VNIC_CFG_TXR_WB_ADDR(_x)	(NS_VNIC_CFG_TXR_BASE + 0x200 + \
					 ((_x) * 0x8))
#define NS_VNIC_CFG_TXR_SZ(_x)		(NS_VNIC_CFG_TXR_BASE + 0x400 + (_x))
#define NS_VNIC_CFG_TXR_VEC(_x)		(NS_VNIC_CFG_TXR_BASE + 0x440 + (_x))
#define NS_VNIC_CFG_TXR_PRIO(_x)	(NS_VNIC_CFG_TXR_BASE + 0x480 + (_x))

/**
 * RX ring configuration
 * @NS_VNIC_CFG_RXR_BASE:    Base offset for RX ring configuration
 * @NS_VNIC_CFG_RXR_ADDR:    Offset of host address for RX ring _x
 * @NS_VNIC_CFG_RXR_SZ:      Offset to configure size for ring _x
 * @NS_VNIC_CFG_RXR_VEC:     Offset to set MSI-X table entry for ring _x
 * @NS_VNIC_CFG_TXR_PRIO:    Offset to set per RX ring priorities for ring _x.
 */
#define NS_VNIC_CFG_RXR_BASE		0x0800
#define NS_VNIC_CFG_RXR_ADDR(_x)	(NS_VNIC_CFG_RXR_BASE + ((_x) * 0x8))
#define NS_VNIC_CFG_RXR_SZ(_x)		(NS_VNIC_CFG_RXR_BASE + 0x200 + (_x))
#define NS_VNIC_CFG_RXR_VEC(_x)		(NS_VNIC_CFG_RXR_BASE + 0x240 + (_x))
#define NS_VNIC_CFG_RXR_PRIO(_x)	(NS_VNIC_CFG_RXR_BASE + 0x280 + (_x))

/**
 * General device stats (all counters are 64bit)
 */
#define NS_VNIC_CFG_STATS_BASE		0x0b00

#define NS_VNIC_CFG_STATS_RX_DISCARDS   (NS_VNIC_CFG_STATS_BASE + 0x00)
#define NS_VNIC_CFG_STATS_RX_ERRORS     (NS_VNIC_CFG_STATS_BASE + 0x08)
#define NS_VNIC_CFG_STATS_RX_OCTETS     (NS_VNIC_CFG_STATS_BASE + 0x10)
#define NS_VNIC_CFG_STATS_RX_UC_OCTETS  (NS_VNIC_CFG_STATS_BASE + 0x18)
#define NS_VNIC_CFG_STATS_RX_MC_OCTETS  (NS_VNIC_CFG_STATS_BASE + 0x20)
#define NS_VNIC_CFG_STATS_RX_BC_OCTETS  (NS_VNIC_CFG_STATS_BASE + 0x28)
#define NS_VNIC_CFG_STATS_RX_FRAMES     (NS_VNIC_CFG_STATS_BASE + 0x30)
#define NS_VNIC_CFG_STATS_RX_MC_FRAMES  (NS_VNIC_CFG_STATS_BASE + 0x38)
#define NS_VNIC_CFG_STATS_RX_BC_FRAMES  (NS_VNIC_CFG_STATS_BASE + 0x40)

#define NS_VNIC_CFG_STATS_TX_DISCARDS   (NS_VNIC_CFG_STATS_BASE + 0x48)
#define NS_VNIC_CFG_STATS_TX_ERRORS     (NS_VNIC_CFG_STATS_BASE + 0x50)
#define NS_VNIC_CFG_STATS_TX_OCTETS     (NS_VNIC_CFG_STATS_BASE + 0x58)
#define NS_VNIC_CFG_STATS_TX_UC_OCTETS  (NS_VNIC_CFG_STATS_BASE + 0x60)
#define NS_VNIC_CFG_STATS_TX_MC_OCTETS  (NS_VNIC_CFG_STATS_BASE + 0x68)
#define NS_VNIC_CFG_STATS_TX_BC_OCTETS  (NS_VNIC_CFG_STATS_BASE + 0x70)
#define NS_VNIC_CFG_STATS_TX_FRAMES     (NS_VNIC_CFG_STATS_BASE + 0x78)
#define NS_VNIC_CFG_STATS_TX_MC_FRAMES  (NS_VNIC_CFG_STATS_BASE + 0x80)
#define NS_VNIC_CFG_STATS_TX_BC_FRAMES  (NS_VNIC_CFG_STATS_BASE + 0x88)

/**
 * Per ring stats (optional)
 * @NS_VNIC_CFG_TXR_STATS:   TX ring statistics (Packet and Byte count)
 * @NS_VNIC_CFG_RXR_STATS:   RX ring statistics (Packet and Byte count)
 */
#define NS_VNIC_CFG_TXR_STATS_BASE	0x1000
#define NS_VNIC_CFG_TXR_STATS(_x)	(NS_VNIC_CFG_TXR_STATS_BASE + \
					 ((_x) * 0x10))
#define NS_VNIC_CFG_RXR_STATS_BASE	0x1400
#define NS_VNIC_CFG_RXR_STATS(_x)	(NS_VNIC_CFG_RXR_STATS_BASE + \
					 ((_x) * 0x10))

#endif /* _NS_VNIC_CTRL_H_ */
/*
 * Local variables:
 * c-file-style: "Linux"
 * indent-tabs-mode: t
 * End:
 */
