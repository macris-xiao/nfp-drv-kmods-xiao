/*
 * Copyright (C) 2015, Netronome, Inc.
 * All right reserved.
 * Author: Jason McMullan <jason.mcmullan@netronome.com>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * This header file declares the nfp6000 MAC API functions relating to
 * the Ethernet core and the NBI gasket interface.
 *
 * The nfp6000 contains two MACs.  Access to a MAC is provided through
 * a struct nfp_nbi_dev device handle which is returned by the
 * nfp_nbi_open() function (See nfp_nbi.h).
 *
 * Each nfp6000 MAC contains two ethernet cores each capable of
 * supporting up to twelve 10GE ports.  Many of the functions in this
 * header file accept a "core" parameter specifying the Ethernet core
 * and a "port" parameter specifying the port on that core.
 *
 * When PCP is enabled the traffic on a port can be classified into a
 * maximum of eight channels.  The flow control mechanisms are based
 * on the capacity assigned to these channels. Many of the gasket
 * control functions accept a "chan" parameter specifying the channel.
 */

#ifndef __NFP_NBI_MAC_ETH_H__
#define __NFP_NBI_MAC_ETH_H__

#define NFP_NBI_MAC_DQDWRR_TO 1000	/* wait for dwrr register access */

#define NFP_NBI_MAC_CHAN_MAX            127
#define NFP_NBI_MAC_CHAN_PAUSE_WM_MAX  2047
#define NFP_NBI_MAC_PORT_HWM_MAX       2047
#define NFP_NBI_MAC_PORT_HWM_DELTA_MAX   31

#define NFP_NBI_MAC_ENET_OFF		0
#define NFP_NBI_MAC_ILK			1
#define NFP_NBI_MAC_ENET_10M		2
#define NFP_NBI_MAC_ENET_100M		3
#define NFP_NBI_MAC_ENET_1G		4
#define NFP_NBI_MAC_ENET_10G		5
#define NFP_NBI_MAC_ENET_40G		6
#define NFP_NBI_MAC_ENET_100G		7

#define NFP_NBI_MAC_SINGLE_LANE(l) ((l == NFP_NBI_MAC_ENET_10M)  || \
				(l == NFP_NBI_MAC_ENET_100M) || \
				(l == NFP_NBI_MAC_ENET_1G)   || \
				(l == NFP_NBI_MAC_ENET_10G))

#define NFP_NBI_MAC_ONEG_MODE(l) ((l == NFP_NBI_MAC_ENET_10M)  || \
			      (l == NFP_NBI_MAC_ENET_100M) || \
			      (l == NFP_NBI_MAC_ENET_1G))

int nfp_nbi_mac_eth_ifdown(struct nfp_nbi_dev *nbi, int core, int port);
int nfp_nbi_mac_eth_ifup(struct nfp_nbi_dev *nbi, int core, int port);
int nfp_nbi_mac_eth_read_linkstate(struct nfp_nbi_dev *nbi,
				   int core, int port, uint32_t * linkstate);
int nfp_nbi_mac_eth_write_mac_addr(struct nfp_nbi_dev *nbi,
				   int core, int port, uint64_t hwaddr);
int nfp_nbi_mac_eth_read_mac_addr(struct nfp_nbi_dev *nbi, int core,
				  int port, uint64_t * hwaddr);
int nfp_nbi_mac_eth_read_mode(struct nfp_nbi_dev *nbi, int core, int port);

#endif
