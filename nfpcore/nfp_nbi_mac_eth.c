/**
 * Copyright (C) 2013-2014 Netronome Systems, Inc.  All rights reserved.
 *
 * @file nfp_nbi_mac_eth.c
 * nfp6000 MAC API functions
 *
 * Functions mostly related to the MAC Ethernet
 * (Hydra) core and the MAC-NBI channel interface.
 */

#include <linux/kernel.h>
#include <linux/module.h>

#include "nfp.h"
#include "nfp_nbi.h"

#define NFP_MAC                                     0x3a0000
#define NFP_MAC_MacMuxCtrl                          0x0000000c
#define NFP_MAC_MacSerDesEn                         0x00000010
#define   NFP_MAC_MacSerDesEn_SerDesEnable(_x)      (((_x) & 0xffffff) << 0)
#define NFP_MAC_ETH(_x)	\
	(NFP_MAC + 0x40000 + ((_x) & 0x1) * 0x20000)
#define NFP_MAC_ETH_MacEthChPcsSeg_BaseRStatus1(_x) \
					(0x00004080 + (0x400 * ((_x) & 0xf)))
#define   NFP_MAC_ETH_MacEthChPcsSeg_BaseRStatus1_BlockLocked \
					(1 << 0)
#define   NFP_MAC_ETH_MacEthChPcsSeg_BaseRStatus1_RcvLinkStatus \
					(1 << 12)
#define NFP_MAC_ETH_MacEthChPcsSeg_Ctl1(_x)     \
					(0x00004000 + (0x400 * ((_x) & 0xf)))
#define   NFP_MAC_ETH_MacEthChPcsSeg_Ctl1_Loopback \
					(1 << 14)
#define   NFP_MAC_ETH_MacEthChPcsSeg_Ctl1_SpeedSel(_x) \
					(((_x) & 0xf) << 2)
#define   NFP_MAC_ETH_MacEthChPcsSeg_Ctl1_SpeedSelection13 \
					(1 << 13)
#define   NFP_MAC_ETH_MacEthChPcsSeg_Ctl1_SpeedSelection6 \
					(1 << 6)
#define NFP_MAC_ETH_MacEthChPcsSeg_Status1(_x)  \
					(0x00004004 + (0x400 * ((_x) & 0xf)))
#define   NFP_MAC_ETH_MacEthChPcsSeg_Status1_RcvLinkStatus \
					(1 << 2)
#define NFP_MAC_ETH_MacEthGlobal_EthActCtlSeg           0x00003000
#define   NFP_MAC_ETH_MacEthGlobal_EthActCtlSeg_EthActivateSegment(_x) \
					(((_x) & 0xfff) << 0)
#define NFP_MAC_ETH_MacEthSeg_EthCmdConfig(_x)          \
					(0x00000008 + (0x400 * ((_x) & 0xf)))
#define   NFP_MAC_ETH_MacEthSeg_EthCmdConfig_EthRxEna   \
					(1 << 1)
#define   NFP_MAC_ETH_MacEthSeg_EthCmdConfig_EthTxEna   \
					(1 << 0)
#define NFP_MAC_ETH_MacEthSeg_EthMacAddr0(_x)           \
					(0x0000000c + (0x400 * ((_x) & 0xf)))
#define   NFP_MAC_ETH_MacEthSeg_EthMacAddr0_EthMacAddr0(_x) \
					(((_x) & 0xffffffff) << 0)
#define NFP_MAC_ETH_MacEthSeg_EthMacAddr1(_x)           \
					(0x00000010 + (0x400 * ((_x) & 0xf)))
#define   NFP_MAC_ETH_MacEthSeg_EthMacAddr1_EthMacAddr1(_x) \
					(((_x) & 0xffff) << 0)
#define NFP_MAC_ETH_EthSgmiiIfMode(_x)        \
					(0x00000350 + (0x400 * ((_x) & 0xf)))
#define   NFP_MAC_ETH_EthSgmiiIfMode_EthSgmiiEna \
					(1 << 0)
#define   NFP_MAC_ETH_EthSgmiiIfMode_EthSgmiiPcsEnable \
					(1 << 5)
#define     NFP_MAC_ETH_EthSgmiiIfMode_Speed_100Mbps (1)
#define     NFP_MAC_ETH_EthSgmiiIfMode_Speed_10Mbps (0)
#define   NFP_MAC_ETH_EthSgmiiIfMode_Speed_of(_x) \
					(((_x) >> 2) & 0x3)
#define NFP_NBI_MAC_EthChPcsCtl1_Mode_Mask \
	(NFP_MAC_ETH_MacEthChPcsSeg_Ctl1_SpeedSelection13 | \
	 NFP_MAC_ETH_MacEthChPcsSeg_Ctl1_SpeedSelection6 | \
	 NFP_MAC_ETH_MacEthChPcsSeg_Ctl1_SpeedSel(0xf))
#define NFP_NBI_MAC_EthChPcsCtl1_Mode_10GE \
	(NFP_MAC_ETH_MacEthChPcsSeg_Ctl1_SpeedSelection13 | \
	 NFP_MAC_ETH_MacEthChPcsSeg_Ctl1_SpeedSelection6 | \
	 NFP_MAC_ETH_MacEthChPcsSeg_Ctl1_SpeedSel(0))
#define NFP_NBI_MAC_EthChPcsCtl1_Mode_10PASSTS \
	(NFP_MAC_ETH_MacEthChPcsSeg_Ctl1_SpeedSelection13 | \
	 NFP_MAC_ETH_MacEthChPcsSeg_Ctl1_SpeedSelection6 | \
	 NFP_MAC_ETH_MacEthChPcsSeg_Ctl1_SpeedSel(0x1))
#define NFP_NBI_MAC_EthChPcsCtl1_Mode_8023AV \
	(NFP_MAC_ETH_MacEthChPcsSeg_Ctl1_SpeedSelection13 | \
	 NFP_MAC_ETH_MacEthChPcsSeg_Ctl1_SpeedSelection6 | \
	 NFP_MAC_ETH_MacEthChPcsSeg_Ctl1_SpeedSel(0x2))
#define NFP_NBI_MAC_EthChPcsCtl1_Mode_40GE \
	(NFP_MAC_ETH_MacEthChPcsSeg_Ctl1_SpeedSelection13 | \
	 NFP_MAC_ETH_MacEthChPcsSeg_Ctl1_SpeedSelection6 | \
	 NFP_MAC_ETH_MacEthChPcsSeg_Ctl1_SpeedSel(0x3))
#define NFP_NBI_MAC_EthChPcsCtl1_Mode_100GE \
	(NFP_MAC_ETH_MacEthChPcsSeg_Ctl1_SpeedSelection13 | \
	 NFP_MAC_ETH_MacEthChPcsSeg_Ctl1_SpeedSelection6 | \
	 NFP_MAC_ETH_MacEthChPcsSeg_Ctl1_SpeedSel(0x4))
#define NFP_NBI_MAC_MacMuxCtrl_Error 0x1
#define NFP_NBI_MAC_EthActCtlSeg_Disabled 0x2
#define NFP_NBI_MAC_EthChPcsStatus1_RcvLinkStatus_Down 0x4
#define NFP_NBI_MAC_EthChPcsBaseRStatus1_RcvLinkStatus_Down 0x8
#define NFP_NBI_MAC_EthChPcsBaseRStatus1_BlockLocked_False 0x10
#define NFP_NBI_MAC_EthCmdConfig_EthTxEna_False 0x20
#define NFP_NBI_MAC_EthCmdConfig_EthRxEna_False 0x40
#define NFP_MAC_ILK_LkRxAlignStatus_False 0x80
#define NFP_MAC_ILK_LkRxStatusMessage_False 0x100

/**
 * nfp_nbi_mac_eth_ifdown() - Disable an Ethernet port.
 * @nbi:	NBI device handle
 * @core:	MAC ethernet core: [0-1]
 * @port:	MAC ethernet port: [0-11]
 *
 * This function disables Rx & Tx, initiates a PCS reset and
 * deactivates the specified port.
 *
 * Return: 0, or -ERRNO
 */
int nfp_nbi_mac_eth_ifdown(struct nfp_nbi_dev *nbi, int core, int port)
{
	uint64_t r;
	uint32_t d = 0;
	uint32_t m = 0;
	int mode = 0;

	if (!nbi)
		return -ENODEV;

	if ((core < 0) || (core > 1))
		return -EINVAL;

	if ((port < 0) || (port > 11))
		return -EINVAL;

	/* Disable the serdes lanes */
	mode = nfp_nbi_mac_eth_read_mode(nbi, core, port);
	if (mode < 0)
		return mode;
	switch (mode) {
	case (NFP_NBI_MAC_ENET_100G):
		m = 0x3ff << (core * 12);
		break;
	case (NFP_NBI_MAC_ENET_40G):
		m = (0xf << (port + core * 12));
		break;
	default:
		m = (0x1 << (port + core * 12));
		break;
	}
	r = NFP_MAC_MacSerDesEn;
	m = NFP_MAC_MacSerDesEn_SerDesEnable(m);
	d = 0;

	return nfp_nbi_mac_regw(nbi, NFP_MAC, r, m, d);
}
EXPORT_SYMBOL(nfp_nbi_mac_eth_ifdown);

/**
 * nfp_nbi_mac_eth_ifup() - Enable an Ethernet port.
 * @nbi:	NBI device handle
 * @core:	MAC ethernet core: [0-1]
 * @port:	MAC ethernet port: [0-11]
 *
 * This function enables Rx & Tx, and initiates a PCS reset and
 * activates the specified port. It assumes that the port speed and
 * all other configuration parameters for the port have been
 * initialized elsewhere.
 *
 * Return: 0, or -ERRNO
 */
int nfp_nbi_mac_eth_ifup(struct nfp_nbi_dev *nbi, int core, int port)
{
	int ret;
	uint64_t r;
	uint32_t d = 0;
	uint32_t m = 0;
	int mode = 0;

	if (!nbi)
		return -ENODEV;

	if ((core < 0) || (core > 1))
		return -EINVAL;

	if ((port < 0) || (port > 11))
		return -EINVAL;

	/* Activate the segment */
	r = NFP_MAC_ETH_MacEthGlobal_EthActCtlSeg;
	d = NFP_MAC_ETH_MacEthGlobal_EthActCtlSeg_EthActivateSegment(port);
	m = d;
	ret = nfp_nbi_mac_regw(nbi, NFP_MAC_ETH(core), r, m, d);
	if (ret < 0)
		return ret;

	/* Enable transmit & receive paths */
	r = NFP_MAC_ETH_MacEthSeg_EthCmdConfig(port);
	d = NFP_MAC_ETH_MacEthSeg_EthCmdConfig_EthRxEna |
	    NFP_MAC_ETH_MacEthSeg_EthCmdConfig_EthTxEna;
	m = d;
	ret = nfp_nbi_mac_regw(nbi, NFP_MAC_ETH(core), r, m, d);
	if (ret < 0)
		return ret;

	/* Enable the serdes lanes */
	mode = nfp_nbi_mac_eth_read_mode(nbi, core, port);
	if (mode < 0)
		return mode;
	switch (mode) {
	case (NFP_NBI_MAC_ENET_100G):
		m = 0x3ff << (core * 12);
		break;
	case (NFP_NBI_MAC_ENET_40G):
		m = (0xf << (port + core * 12));
		break;
	default:
		m = (0x1 << (port + core * 12));
		break;
	}
	r = NFP_MAC_MacSerDesEn;
	m = NFP_MAC_MacSerDesEn_SerDesEnable(m);
	d = m;

	return nfp_nbi_mac_regw(nbi, NFP_MAC, r, m, d);
}
EXPORT_SYMBOL(nfp_nbi_mac_eth_ifup);

/**
 * nfp_nbi_mac_eth_read_linkstate() - Check the link state of an Ethernet port
 * @nbi:	NBI device
 * @core:	MAC ethernet core: [0-1]
 * @port:	MAC ethernet port: [0-11]
 * @linkstate:	State detail
 *
 * This function returns 1 if the specified port has link up and block
 * lock.  It returns zero if the link is down.  If linkstate parameter
 * is not NULL this function will use it to return more detail for the
 * link down state.
 *
 * Return: 0 - link down, 1 - link up, or -ERRNO.
 */
int nfp_nbi_mac_eth_read_linkstate(struct nfp_nbi_dev *nbi, int core, int port,
				   uint32_t *linkstate)
{
	uint64_t r;
	uint32_t d = 0;
	uint32_t m = 0;
	uint32_t status = 0;
	int ret;

	if (!nbi)
		return -ENODEV;

	if ((core < 0) || (core > 1))
		return -EINVAL;

	if ((port < 0) || (port > 11))
		return -EINVAL;

	if (linkstate)
		*linkstate = 0;

	ret = nfp_nbi_mac_regr(nbi, NFP_MAC,
			       NFP_MAC_MacMuxCtrl, &d);
	if (ret < 0)
		return ret;

	m = 1 << ((core * 12) + port);
	if ((d & m) > 0)
		status |= NFP_NBI_MAC_MacMuxCtrl_Error;

	r = NFP_MAC_ETH_MacEthGlobal_EthActCtlSeg;
	ret = nfp_nbi_mac_regr(nbi, NFP_MAC_ETH(core), r, &d);
	if (ret < 0)
		return ret;

	if (!(d & (0x1 << port)))
		status |= NFP_NBI_MAC_EthActCtlSeg_Disabled;

	r = NFP_MAC_ETH_MacEthChPcsSeg_Status1(port);
	/* Double read to clear latch low on link down */
	ret = nfp_nbi_mac_regr(nbi, NFP_MAC_ETH(core), r, &d);
	if (ret < 0)
		return ret;

	ret = nfp_nbi_mac_regr(nbi, NFP_MAC_ETH(core), r, &d);
	if (ret < 0)
		return ret;

	if (!(d & NFP_MAC_ETH_MacEthChPcsSeg_Status1_RcvLinkStatus))
		status |= NFP_NBI_MAC_EthChPcsStatus1_RcvLinkStatus_Down;

	r = NFP_MAC_ETH_MacEthChPcsSeg_BaseRStatus1(port);
	ret = nfp_nbi_mac_regr(nbi, NFP_MAC_ETH(core), r, &d);
	if (ret < 0)
		return ret;

	if (!(d & NFP_MAC_ETH_MacEthChPcsSeg_BaseRStatus1_RcvLinkStatus))
		status |=
		    NFP_NBI_MAC_EthChPcsBaseRStatus1_RcvLinkStatus_Down;

	if (!(d & NFP_MAC_ETH_MacEthChPcsSeg_BaseRStatus1_BlockLocked))
		status |=
		    NFP_NBI_MAC_EthChPcsBaseRStatus1_BlockLocked_False;

	r = NFP_MAC_ETH_MacEthSeg_EthCmdConfig(port);
	ret = nfp_nbi_mac_regr(nbi, NFP_MAC_ETH(core), r, &d);
	if (ret < 0)
		return ret;

	if (!(d & NFP_MAC_ETH_MacEthSeg_EthCmdConfig_EthTxEna))
		status |= NFP_NBI_MAC_EthCmdConfig_EthTxEna_False;

	if (!(d & NFP_MAC_ETH_MacEthSeg_EthCmdConfig_EthRxEna))
		status |= NFP_NBI_MAC_EthCmdConfig_EthRxEna_False;

	if (linkstate)
		*linkstate = status;

	return (status) ? 0 : 1;
}
EXPORT_SYMBOL(nfp_nbi_mac_eth_read_linkstate);

/**
 * nfp_nbi_mac_eth_read_mode() - Return the mode for an Ethernet port.
 * @nbi:	NBI device
 * @core:	MAC ethernet core: [0-1]
 * @port:	MAC ethernet port: [0-11]
 *
 * This function returns the mode for the specified port.
 *
 * Returned valued will be one of:
 *    NFP_NBI_MAC_ENET_OFF:	Disabled
 *    NFP_NBI_MAC_ILK:		Interlaken mode
 *    NFP_NBI_MAC_ENET_10M:	10Mbps Ethernet
 *    NFP_NBI_MAC_ENET_100M:	100Mbps Ethernet
 *    NFP_NBI_MAC_ENET_1G:	1Gbps Ethernet
 *    NFP_NBI_MAC_ENET_10G:	10Gbps Ethernet
 *    NFP_NBI_MAC_ENET_40G:	40Gbps Ethernet
 *    NFP_NBI_MAC_ENET_100G:	100Gbps Ethernet
 *
 * Return: Port mode, or -ERRNO
 */
int nfp_nbi_mac_eth_read_mode(struct nfp_nbi_dev *nbi, int core, int port)
{
	int ret;
	uint64_t r;
	uint32_t d = 0;
	uint32_t m = 0;
	uint32_t mux = 0;
	int mode;
	int s;

	if (!nbi)
		return -ENODEV;

	if ((core < 0) || (core > 1))
		return -EINVAL;

	if ((port < 0) || (port > 11))
		return -EINVAL;

	/* Check the Serdes lane assignments */
	ret =
	    nfp_nbi_mac_regr(nbi, NFP_MAC, NFP_MAC_MacMuxCtrl,
			     &mux);
	if (ret < 0)
		return ret;

	m = 1 << ((core * 12) + port);
	if ((mux & m) > 0)
		return NFP_NBI_MAC_ILK;

	/* check port 0 for 100G 0x2050 */
	r = NFP_MAC_ETH_MacEthChPcsSeg_Ctl1(0);
	ret = nfp_nbi_mac_regr(nbi, NFP_MAC_ETH(core), r, &d);
	if (ret < 0)
		return ret;

	if ((d & NFP_NBI_MAC_EthChPcsCtl1_Mode_Mask) ==
	    NFP_NBI_MAC_EthChPcsCtl1_Mode_100GE) {
		/* port 0-9 = 100G - ports 10, 11 can be 10G */
		if (port < 10)
			return NFP_NBI_MAC_ENET_100G;
	}

	/* check ports 0,4,8 for 40G */
	s = port % 4;
	r = NFP_MAC_ETH_MacEthChPcsSeg_Ctl1(port - s);
	ret = nfp_nbi_mac_regr(nbi, NFP_MAC_ETH(core), r, &d);
	if (ret < 0)
		return ret;

	if ((d & NFP_NBI_MAC_EthChPcsCtl1_Mode_Mask) ==
	    NFP_NBI_MAC_EthChPcsCtl1_Mode_40GE)
		return NFP_NBI_MAC_ENET_40G;

	/* All that remains is 10G or less */
	r = NFP_MAC_ETH_MacEthChPcsSeg_Ctl1(port);
	ret = nfp_nbi_mac_regr(nbi, NFP_MAC_ETH(core), r, &d);
	if (ret < 0)
		return ret;

	switch (d & NFP_NBI_MAC_EthChPcsCtl1_Mode_Mask) {
	case (NFP_NBI_MAC_EthChPcsCtl1_Mode_10GE):
		/* check if < 10G AE */
		r = NFP_MAC_ETH_EthSgmiiIfMode(port);
		ret = nfp_nbi_mac_regr(nbi, NFP_MAC_ETH(core), r, &d);
		if (ret < 0)
			return ret;

		if (d & NFP_MAC_ETH_EthSgmiiIfMode_EthSgmiiPcsEnable) {
			if (d & NFP_MAC_ETH_EthSgmiiIfMode_EthSgmiiEna) {
				int s;

				s = NFP_MAC_ETH_EthSgmiiIfMode_Speed_of(d);
				/* SGMII */
				switch (s) {
				case (NFP_MAC_ETH_EthSgmiiIfMode_Speed_10Mbps):
					mode = NFP_NBI_MAC_ENET_10M;
					break;
				case (NFP_MAC_ETH_EthSgmiiIfMode_Speed_100Mbps):
					mode = NFP_NBI_MAC_ENET_100M;
					break;
				case (0x2):
					/* AE case */
					mode = NFP_NBI_MAC_ENET_1G;
					break;
				default:
					mode = -EINVAL;
					break;
				}
			} else {
				/* 100Base-X */
				mode = NFP_NBI_MAC_ENET_1G;
			}
			return mode;
		} else {
			return NFP_NBI_MAC_ENET_10G;
		}

		break;
	case (NFP_NBI_MAC_EthChPcsCtl1_Mode_8023AV):
		break;
	case (NFP_NBI_MAC_EthChPcsCtl1_Mode_10PASSTS):
		break;
	default:
		break;
	}

	return -EINVAL;
}
EXPORT_SYMBOL(nfp_nbi_mac_eth_read_mode);

/**
 * nfp_nbi_mac_eth_write_mac_addr() - Write the MAC address for a port
 * @nbi:	NBI device
 * @core:	MAC ethernet core: [0-1]
 * @port:	MAC ethernet port: [0-11]
 * @hwaddr:	MAC address (48-bits)
 *
 * Return: 0, or -ERRNO
 */
int nfp_nbi_mac_eth_write_mac_addr(struct nfp_nbi_dev *nbi, int core,
				   int port, uint64_t hwaddr)
{
	int ret;
	uint64_t r;
	uint32_t d = 0;
	uint32_t m = 0;

	if (!nbi)
		return -ENODEV;

	if ((core < 0) || (core > 1))
		return -EINVAL;

	if ((port < 0) || (port > 11))
		return -EINVAL;

	if ((hwaddr >> 48) > 0)
		return -EINVAL;

	r = NFP_MAC_ETH_MacEthSeg_EthMacAddr0(port);
	m = NFP_MAC_ETH_MacEthSeg_EthMacAddr0_EthMacAddr0(0xffffffffffff);
	d = NFP_MAC_ETH_MacEthSeg_EthMacAddr0_EthMacAddr0(hwaddr);

	ret = nfp_nbi_mac_regw(nbi, NFP_MAC_ETH(core), r, m, d);
	if (ret < 0)
		return ret;

	r = NFP_MAC_ETH_MacEthSeg_EthMacAddr1(port);
	m = NFP_MAC_ETH_MacEthSeg_EthMacAddr1_EthMacAddr1(0xffff);
	d = NFP_MAC_ETH_MacEthSeg_EthMacAddr1_EthMacAddr1(hwaddr >> 32);

	return nfp_nbi_mac_regw(nbi, NFP_MAC_ETH(core), r, m, d);
}
EXPORT_SYMBOL(nfp_nbi_mac_eth_write_mac_addr);

/**
 * nfp_nbi_mac_eth_read_mac_addr() - Read the MAC address for a port
 * @nbi:	NBI device
 * @core:	MAC ethernet core: [0-1]
 * @port:	MAC ethernet port: [0-11]
 * @hwaddr:	MAC address (48-bits)
 *
 * Return: 0, or -ERRNO
 */
int nfp_nbi_mac_eth_read_mac_addr(struct nfp_nbi_dev *nbi, int core,
				  int port, uint64_t *hwaddr)
{
	int ret;
	uint64_t r;
	uint32_t d = 0;
	uint32_t m = 0;

	if (!nbi)
		return -ENODEV;

	if ((core < 0) || (core > 1))
		return -EINVAL;

	if ((port < 0) || (port > 11))
		return -EINVAL;

	if (!hwaddr)
		return -EINVAL;

	r = NFP_MAC_ETH_MacEthSeg_EthMacAddr0(port);
	ret = nfp_nbi_mac_regr(nbi, NFP_MAC_ETH(core), r, &d);
	if (ret < 0)
		return ret;

	r = NFP_MAC_ETH_MacEthSeg_EthMacAddr1(port);
	ret = nfp_nbi_mac_regr(nbi, NFP_MAC_ETH(core), r, &m);
	if (ret < 0)
		return ret;

	*hwaddr = m;
	*hwaddr = (*hwaddr << 32) | d;
	return 0;
}
EXPORT_SYMBOL(nfp_nbi_mac_eth_read_mac_addr);
