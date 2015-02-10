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

#include "nfp.h"
#include "nfp_nbi.h"
#include "nfp_nbi_mac_eth.h"

#define NFP6000_LONGNAMES
#include "nfp6000/nfp_nbi_mac.h"

#define MACDBG(fmt,args...) do { if (0) pr_debug(fmt ,##args); } while (0)

#define NFP_NBI_MAC_NUM_PORTCHAN_REGS 8
static const int nfp_nbi_mac_ig_portchan_regs[] = {
	NFP_NBI_MACX_CSR_MacPort2to0ChanAssign,
	NFP_NBI_MACX_CSR_MacPort5to3ChanAssign,
	NFP_NBI_MACX_CSR_MacPort8to6ChanAssign,
	NFP_NBI_MACX_CSR_MacPort11to9ChanAssign,
	NFP_NBI_MACX_CSR_MacPort14to12ChanAssign,
	NFP_NBI_MACX_CSR_MacPort17to15ChanAssign,
	NFP_NBI_MACX_CSR_MacPort20to18ChanAssign,
	NFP_NBI_MACX_CSR_MacPort23to21ChanAssign
};

static const int nfp_nbi_mac_eg_portchan_regs[] = {
	NFP_NBI_MACX_CSR_MacEgPort2to0ChanAssign,
	NFP_NBI_MACX_CSR_MacEgPort5to3ChanAssign,
	NFP_NBI_MACX_CSR_MacEgPort8to6ChanAssign,
	NFP_NBI_MACX_CSR_MacEgPort11to9ChanAssign,
	NFP_NBI_MACX_CSR_MacEgPort14to12ChanAssign,
	NFP_NBI_MACX_CSR_MacEgPort17to15ChanAssign,
	NFP_NBI_MACX_CSR_MacEgPort20to18ChanAssign,
	NFP_NBI_MACX_CSR_MacEgPort23to21ChanAssign
};

/*
  void nfp_nbi_mac_addr(void); r =
  NFP_NBI_MACX_ETH_MacEthSeg_EthMacAddr0_EthMacAddr0(_x) */

int nfp_nbi_mac_eth_ifdown(struct nfp_nbi_dev *nbi, int core, int port)
{
	uint64_t r;
	uint32_t d = 0;
	uint32_t m = 0;
	int mode = 0;

	if (nbi == NULL) {
		return -ENODEV;
	}
	if ((core < 0) || (core > 1)) {
		return -EINVAL;
	}
	if ((port < 0) || (port > 11)) {
		return -EINVAL;
	}
	// Disable the serdes lanes
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
	r = NFP_NBI_MACX_CSR_MacSerDesEn;
	m = NFP_NBI_MACX_CSR_MacSerDesEn_SerDesEnable(m);
	d = 0;

	return nfp_nbi_mac_regw(nbi, NFP_NBI_MACX_CSR, r, m, d);
}

int nfp_nbi_mac_eth_ifup(struct nfp_nbi_dev *nbi, int core, int port)
{
	int ret;
	uint64_t r;
	uint32_t d = 0;
	uint32_t m = 0;
	int mode = 0;

	if (nbi == NULL) {
		return -ENODEV;
	}
	if ((core < 0) || (core > 1)) {
		return -EINVAL;
	}
	if ((port < 0) || (port > 11)) {
		return -EINVAL;
	}

	/* Activate the segment */
	r = NFP_NBI_MACX_ETH_MacEthGlobal_EthActCtlSeg;
	d = NFP_NBI_MACX_ETH_MacEthGlobal_EthActCtlSeg_EthActivateSegment(port);
	m = d;
	ret = nfp_nbi_mac_regw(nbi, NFP_NBI_MACX_ETH(core), r, m, d);
	if (ret < 0)
		return ret;

	/* Enable transmit & receive paths */
	r = NFP_NBI_MACX_ETH_MacEthSeg_EthCmdConfig(port);
	d = NFP_NBI_MACX_ETH_MacEthSeg_EthCmdConfig_EthRxEna |
	    NFP_NBI_MACX_ETH_MacEthSeg_EthCmdConfig_EthTxEna;
	m = d;
	ret = nfp_nbi_mac_regw(nbi, NFP_NBI_MACX_ETH(core), r, m, d);
	if (ret < 0)
		return ret;

	// Enable the serdes lanes
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
	r = NFP_NBI_MACX_CSR_MacSerDesEn;
	m = NFP_NBI_MACX_CSR_MacSerDesEn_SerDesEnable(m);
	d = m;

	return nfp_nbi_mac_regw(nbi, NFP_NBI_MACX_CSR, r, m, d);
}

int nfp_nbi_mac_eth_write_egress_dsa(struct nfp_nbi_dev *nbi, int core,
				     int port, int octets)
{
	uint64_t r;
	uint32_t d = 0;
	uint32_t m = 0;

	if (nbi == NULL) {
		return -ENODEV;
	}
	if ((core < 0) || (core > 1)) {
		return -EINVAL;
	}
	if ((port < 0) || (port > 11)) {
		return -EINVAL;
	}

	if ((octets != 0) && (octets != 4) && (octets != 8)) {
		return -EINVAL;
	}

	if ((port + core * 12) <= 15) {
		r = NFP_NBI_MACX_CSR_MacEgPrePendDsaCtl15to00;
	} else {
		r = NFP_NBI_MACX_CSR_MacEgPrePendDsaCtlLkand23to16;
	}

	switch (port + core * 12) {
	case 0:
		m = NFP_NBI_MACX_CSR_MacPrePendDsaCtl1_DsaTagModePort0(0xf);
		d = NFP_NBI_MACX_CSR_MacPrePendDsaCtl1_DsaTagModePort0(octets /
								       2);
		break;
	case 1:
		m = NFP_NBI_MACX_CSR_MacPrePendDsaCtl1_DsaTagModePort1(0xf);
		d = NFP_NBI_MACX_CSR_MacPrePendDsaCtl1_DsaTagModePort1(octets /
								       2);
		break;
	case 2:
		m = NFP_NBI_MACX_CSR_MacPrePendDsaCtl1_DsaTagModePort2(0xf);
		d = NFP_NBI_MACX_CSR_MacPrePendDsaCtl1_DsaTagModePort2(octets /
								       2);
		break;
	case 3:
		m = NFP_NBI_MACX_CSR_MacPrePendDsaCtl1_DsaTagModePort3(0xf);
		d = NFP_NBI_MACX_CSR_MacPrePendDsaCtl1_DsaTagModePort3(octets /
								       2);
		break;
	case 4:
		m = NFP_NBI_MACX_CSR_MacPrePendDsaCtl1_DsaTagModePort4(0xf);
		d = NFP_NBI_MACX_CSR_MacPrePendDsaCtl1_DsaTagModePort4(octets /
								       2);
		break;
	case 5:
		m = NFP_NBI_MACX_CSR_MacPrePendDsaCtl1_DsaTagModePort5(0xf);
		d = NFP_NBI_MACX_CSR_MacPrePendDsaCtl1_DsaTagModePort5(octets /
								       2);
		break;
	case 6:
		m = NFP_NBI_MACX_CSR_MacPrePendDsaCtl1_DsaTagModePort6(0xf);
		d = NFP_NBI_MACX_CSR_MacPrePendDsaCtl1_DsaTagModePort6(octets /
								       2);
		break;
	case 7:
		m = NFP_NBI_MACX_CSR_MacPrePendDsaCtl1_DsaTagModePort7(0xf);
		d = NFP_NBI_MACX_CSR_MacPrePendDsaCtl1_DsaTagModePort7(octets /
								       2);
		break;
	case 8:
		m = NFP_NBI_MACX_CSR_MacPrePendDsaCtl1_DsaTagModePort8(0xf);
		d = NFP_NBI_MACX_CSR_MacPrePendDsaCtl1_DsaTagModePort8(octets /
								       2);
		break;
	case 9:
		m = NFP_NBI_MACX_CSR_MacPrePendDsaCtl1_DsaTagModePort9(0xf);
		d = NFP_NBI_MACX_CSR_MacPrePendDsaCtl1_DsaTagModePort9(octets /
								       2);
		break;
	case 10:
		m = NFP_NBI_MACX_CSR_MacPrePendDsaCtl1_DsaTagModePort10(0xf);
		d = NFP_NBI_MACX_CSR_MacPrePendDsaCtl1_DsaTagModePort10(octets /
									2);
		break;
	case 11:
		m = NFP_NBI_MACX_CSR_MacPrePendDsaCtl1_DsaTagModePort11(0xf);
		d = NFP_NBI_MACX_CSR_MacPrePendDsaCtl1_DsaTagModePort11(octets /
									2);
		break;
	case 12:
		m = NFP_NBI_MACX_CSR_MacPrePendDsaCtl1_DsaTagModePort12(0xf);
		d = NFP_NBI_MACX_CSR_MacPrePendDsaCtl1_DsaTagModePort12(octets /
									2);
		break;
	case 13:
		m = NFP_NBI_MACX_CSR_MacPrePendDsaCtl1_DsaTagModePort13(0xf);
		d = NFP_NBI_MACX_CSR_MacPrePendDsaCtl1_DsaTagModePort13(octets /
									2);
		break;
	case 14:
		m = NFP_NBI_MACX_CSR_MacPrePendDsaCtl1_DsaTagModePort14(0xf);
		d = NFP_NBI_MACX_CSR_MacPrePendDsaCtl1_DsaTagModePort14(octets /
									2);
		break;
	case 15:
		m = NFP_NBI_MACX_CSR_MacPrePendDsaCtl1_DsaTagModePort15(0xf);
		d = NFP_NBI_MACX_CSR_MacPrePendDsaCtl1_DsaTagModePort15(octets /
									2);
		break;
	case 16:
		m = NFP_NBI_MACX_CSR_MacPrePendDsaCtl2_DsaTagModePort16(0xf);
		d = NFP_NBI_MACX_CSR_MacPrePendDsaCtl2_DsaTagModePort16(octets /
									2);
		break;
	case 17:
		m = NFP_NBI_MACX_CSR_MacPrePendDsaCtl2_DsaTagModePort17(0xf);
		d = NFP_NBI_MACX_CSR_MacPrePendDsaCtl2_DsaTagModePort17(octets /
									2);
		break;
	case 18:
		m = NFP_NBI_MACX_CSR_MacPrePendDsaCtl2_DsaTagModePort18(0xf);
		d = NFP_NBI_MACX_CSR_MacPrePendDsaCtl2_DsaTagModePort18(octets /
									2);
		break;
	case 19:
		m = NFP_NBI_MACX_CSR_MacPrePendDsaCtl2_DsaTagModePort19(0xf);
		d = NFP_NBI_MACX_CSR_MacPrePendDsaCtl2_DsaTagModePort19(octets /
									2);
		break;
	case 20:
		m = NFP_NBI_MACX_CSR_MacPrePendDsaCtl2_DsaTagModePort20(0xf);
		d = NFP_NBI_MACX_CSR_MacPrePendDsaCtl2_DsaTagModePort20(octets /
									2);
		break;
	case 21:
		m = NFP_NBI_MACX_CSR_MacPrePendDsaCtl2_DsaTagModePort21(0xf);
		d = NFP_NBI_MACX_CSR_MacPrePendDsaCtl2_DsaTagModePort21(octets /
									2);
		break;
	case 22:
		m = NFP_NBI_MACX_CSR_MacPrePendDsaCtl2_DsaTagModePort22(0xf);
		d = NFP_NBI_MACX_CSR_MacPrePendDsaCtl2_DsaTagModePort22(octets /
									2);
		break;
	case 23:
		m = NFP_NBI_MACX_CSR_MacPrePendDsaCtl2_DsaTagModePort23(0xf);
		d = NFP_NBI_MACX_CSR_MacPrePendDsaCtl2_DsaTagModePort23(octets /
									2);
		break;
	default:
		MACDBG("Invalid Port: %d\n", port);
		return -EINVAL;
		break;
	}

	return nfp_nbi_mac_regw(nbi, NFP_NBI_MACX_CSR, r, m, d);
}

int nfp_nbi_mac_write_egress_prepend_enable(struct nfp_nbi_dev *nbi, int chan,
					    int state)
{
	uint64_t r;
	//uint32_t d = 0;
	uint32_t m;

	if (nbi == NULL) {
		return -ENODEV;
	}
	if ((chan < 0) || (chan > NFP_NBI_MAC_CHAN_MAX)) {
		return -EINVAL;
	}
	if ((state < 0) || (state > 1)) {
		return -EINVAL;
	}

	switch (chan / 4) {
	case 0:
		r = NFP_NBI_MACX_CSR_EgCmdPrependEn0Lo;
		break;
	case 1:
		r = NFP_NBI_MACX_CSR_EgCmdPrependEn0Hi;
		break;
	case 2:
		r = NFP_NBI_MACX_CSR_EgCmdPrependEn1Lo;
		break;
	case 3:
		r = NFP_NBI_MACX_CSR_EgCmdPrependEn1Hi;
		break;
	default:
		return -EINVAL;
	}

	m = 1 << (chan % 4);
	return nfp_nbi_mac_regw(nbi, NFP_NBI_MACX_CSR, r, m, state);
}

int nfp_nbi_mac_eth_write_egress_skip(struct nfp_nbi_dev *nbi, int core,
				      int port, int octets)
{
	uint64_t r;
	uint32_t d = 0;
	uint32_t m = 0;

	if (nbi == NULL) {
		return -ENODEV;
	}
	if ((core < 0) || (core > 1)) {
		return -EINVAL;
	}
	if ((port < 0) || (port > 11)) {
		return -EINVAL;
	}

	if ((octets < 0) || (octets > 8)) {
		return -EINVAL;
	}

	switch ((port + core * 12) / 4) {
	case 0:
		r = NFP_NBI_MACX_CSR_MacPrePendCtl03to00;
		break;
	case 1:
		r = NFP_NBI_MACX_CSR_MacPrePendCtl07to04;
		break;
	case 2:
		r = NFP_NBI_MACX_CSR_MacPrePendCtl11to08;
		break;
	case 3:
		r = NFP_NBI_MACX_CSR_MacPrePendCtl15to12;
		break;
	case 4:
		r = NFP_NBI_MACX_CSR_MacPrePendCtl19to16;
		break;
	case 5:
		r = NFP_NBI_MACX_CSR_MacPrePendCtl23to20;
		break;
	default:
		return -EINVAL;
		break;
	}

	switch (port) {
	case 0:
		m = NFP_NBI_MACX_CSR_MacPrePendCtl1_EGSkipOctetsPort0(0xf);
		d = NFP_NBI_MACX_CSR_MacPrePendCtl1_EGSkipOctetsPort0(octets);
		break;
	case 1:
		m = NFP_NBI_MACX_CSR_MacPrePendCtl1_EGSkipOctetsPort1(0xf);
		d = NFP_NBI_MACX_CSR_MacPrePendCtl1_EGSkipOctetsPort1(octets);
		break;
	case 2:
		m = NFP_NBI_MACX_CSR_MacPrePendCtl1_EGSkipOctetsPort2(0xf);
		d = NFP_NBI_MACX_CSR_MacPrePendCtl1_EGSkipOctetsPort2(octets);
		break;
	case 3:
		m = NFP_NBI_MACX_CSR_MacPrePendCtl1_EGSkipOctetsPort3(0xf);
		d = NFP_NBI_MACX_CSR_MacPrePendCtl1_EGSkipOctetsPort3(octets);
		break;
	case 4:
		m = NFP_NBI_MACX_CSR_MacPrePendCtl2_EGSkipOctetsPort4(0xf);
		d = NFP_NBI_MACX_CSR_MacPrePendCtl2_EGSkipOctetsPort4(octets);
		break;
	case 5:
		m = NFP_NBI_MACX_CSR_MacPrePendCtl2_EGSkipOctetsPort5(0xf);
		d = NFP_NBI_MACX_CSR_MacPrePendCtl2_EGSkipOctetsPort5(octets);
		break;
	case 6:
		m = NFP_NBI_MACX_CSR_MacPrePendCtl2_EGSkipOctetsPort6(0xf);
		d = NFP_NBI_MACX_CSR_MacPrePendCtl2_EGSkipOctetsPort6(octets);
		break;
	case 7:
		m = NFP_NBI_MACX_CSR_MacPrePendCtl2_EGSkipOctetsPort7(0xf);
		d = NFP_NBI_MACX_CSR_MacPrePendCtl2_EGSkipOctetsPort7(octets);
		break;
	case 8:
		m = NFP_NBI_MACX_CSR_MacPrePendCtl3_EGSkipOctetsPort8(0xf);
		d = NFP_NBI_MACX_CSR_MacPrePendCtl3_EGSkipOctetsPort8(octets);
		break;
	case 9:
		m = NFP_NBI_MACX_CSR_MacPrePendCtl3_EGSkipOctetsPort9(0xf);
		d = NFP_NBI_MACX_CSR_MacPrePendCtl3_EGSkipOctetsPort9(octets);
		break;
	case 10:
		m = NFP_NBI_MACX_CSR_MacPrePendCtl3_EGSkipOctetsPort10(0xf);
		d = NFP_NBI_MACX_CSR_MacPrePendCtl3_EGSkipOctetsPort10(octets);
		break;
	case 11:
		m = NFP_NBI_MACX_CSR_MacPrePendCtl3_EGSkipOctetsPort11(0xf);
		d = NFP_NBI_MACX_CSR_MacPrePendCtl3_EGSkipOctetsPort11(octets);
		break;
	default:
		return -EINVAL;
		break;
	}

	//MACDBG("nfp_nbi_mac_eth_write_egress_skip: Port %d, octets: %d\n", port, octets);
	return nfp_nbi_mac_regw(nbi, NFP_NBI_MACX_CSR, r, m, d);
}

/* void nfp_nbi_mac_ethfifo_rxwm(void);
   void nfp_nbi_mac_ethfifo_txwm(void);
*/

int nfp_nbi_mac_eth_write_port_hwm(struct nfp_nbi_dev *nbi, int core, int port,
				   int hwm, int delta)
{
	uint64_t r;
	uint32_t d = 0;
	uint32_t m = 0;

	if (nbi == NULL) {
		return -ENODEV;
	}
	if ((core < 0) || (core > 1)) {
		return -EINVAL;
	}
	if ((port < 0) || (port > 11)) {
		return -EINVAL;
	}

	if ((hwm < 0) || (hwm > NFP_NBI_MAC_PORT_HWM_MAX)) {
		MACDBG
		    ("write_port_hwm: High watermark value out of range (0-%d):, %d.\n",
		     NFP_NBI_MAC_PORT_HWM_MAX, hwm);
		return -EINVAL;
	}

	if ((delta < 0) || (delta > NFP_NBI_MAC_PORT_HWM_DELTA_MAX)) {
		MACDBG
		    ("write_port_hwm: Drop delta value out of range (0-%d):, %d.\n",
		     NFP_NBI_MAC_PORT_HWM_DELTA_MAX, delta);
		return -EINVAL;
	}
	//register = MAC + "csr_porthwm%d" % ((seg + hyd * 12) / 2)
	r = NFP_NBI_MACX_CSR_MacPortHwm((port + core * 12) / 2);

	if ((port % 2) == 0) {
		m = NFP_NBI_MACX_CSR_MacPortHwm_PortHwm0(0x7ff) |
		    NFP_NBI_MACX_CSR_MacPortHwm_PortDropDelta0(0x1f);
		d = NFP_NBI_MACX_CSR_MacPortHwm_PortHwm0(hwm) |
		    NFP_NBI_MACX_CSR_MacPortHwm_PortDropDelta0(delta);
	} else {
		m = NFP_NBI_MACX_CSR_MacPortHwm_PortHwm1(0x7ff) |
		    NFP_NBI_MACX_CSR_MacPortHwm_PortDropDelta1(0x1f);
		d = NFP_NBI_MACX_CSR_MacPortHwm_PortHwm1(hwm) |
		    NFP_NBI_MACX_CSR_MacPortHwm_PortDropDelta1(delta);
	}

	return nfp_nbi_mac_regw(nbi, NFP_NBI_MACX_CSR, r, m, d);
}

//  void read_port_hwm(struct nfp_nbi_dev *nbi, int eth, int port);

/*
 *
 *   Enable/disable timestamp/parse-result prepend on ingress.
 *
 *  @param nbi NBI device
 *  @param core mac ethernet core: [0-1]
 *  @param port mac ethernet port: [0-11]
 *  @param feature disable = 0; parse-result = 1; timestamp = 2; both = 3.
 */
int nfp_nbi_mac_eth_write_ingress_prepend_enable(struct nfp_nbi_dev *nbi,
						 int core, int port,
						 int feature)
{
	uint64_t r;
	uint32_t d = 0;
	uint32_t m = 0;

	if (nbi == NULL) {
		return -ENODEV;
	}

	switch (feature) {
	case NFP_NBI_MACX_CSR_IgPrependEn_PrependEn0_No_Prepend:
	case NFP_NBI_MACX_CSR_IgPrependEn_PrependEn0_Prepend_CHK:
	case NFP_NBI_MACX_CSR_IgPrependEn_PrependEn0_Prepend_TS:
	case NFP_NBI_MACX_CSR_IgPrependEn_PrependEn0_Prepend_TS_CHK:
		break;
	default:
		return -EINVAL;
	}

	if (core == 0) {
		r = NFP_NBI_MACX_CSR_IgPortPrependEn0;
	} else if (core == 1) {
		r = NFP_NBI_MACX_CSR_IgPortPrependEn1;
	} else {
		return -EINVAL;
	}

	switch (port) {
	case 0:
		m = NFP_NBI_MACX_CSR_IgPrependEn_PrependEn0(0x3);
		d = NFP_NBI_MACX_CSR_IgPrependEn_PrependEn0(feature);
		break;
	case 1:
		m = NFP_NBI_MACX_CSR_IgPrependEn_PrependEn1(0x3);
		d = NFP_NBI_MACX_CSR_IgPrependEn_PrependEn1(feature);
		break;
	case 2:
		m = NFP_NBI_MACX_CSR_IgPrependEn_PrependEn2(0x3);
		d = NFP_NBI_MACX_CSR_IgPrependEn_PrependEn2(feature);
		break;
	case 3:
		m = NFP_NBI_MACX_CSR_IgPrependEn_PrependEn3(0x3);
		d = NFP_NBI_MACX_CSR_IgPrependEn_PrependEn3(feature);
		break;
	case 4:
		m = NFP_NBI_MACX_CSR_IgPrependEn_PrependEn4(0x3);
		d = NFP_NBI_MACX_CSR_IgPrependEn_PrependEn4(feature);
		break;
	case 5:
		m = NFP_NBI_MACX_CSR_IgPrependEn_PrependEn5(0x3);
		d = NFP_NBI_MACX_CSR_IgPrependEn_PrependEn5(feature);
		break;
	case 6:
		m = NFP_NBI_MACX_CSR_IgPrependEn_PrependEn6(0x3);
		d = NFP_NBI_MACX_CSR_IgPrependEn_PrependEn6(feature);
		break;
	case 7:
		m = NFP_NBI_MACX_CSR_IgPrependEn_PrependEn7(0x3);
		d = NFP_NBI_MACX_CSR_IgPrependEn_PrependEn7(feature);
		break;
	case 8:
		m = NFP_NBI_MACX_CSR_IgPrependEn_PrependEn8(0x3);
		d = NFP_NBI_MACX_CSR_IgPrependEn_PrependEn8(feature);
		break;
	case 9:
		m = NFP_NBI_MACX_CSR_IgPrependEn_PrependEn9(0x3);
		d = NFP_NBI_MACX_CSR_IgPrependEn_PrependEn9(feature);
		break;
	case 10:
		m = NFP_NBI_MACX_CSR_IgPrependEn_PrependEn10(0x3);
		d = NFP_NBI_MACX_CSR_IgPrependEn_PrependEn10(feature);
		break;
	case 11:
		m = NFP_NBI_MACX_CSR_IgPrependEn_PrependEn11(0x3);
		d = NFP_NBI_MACX_CSR_IgPrependEn_PrependEn11(feature);
		break;
	default:
		/* NFP_NBI_MACX_CSR_IGPREPENDEN_PREPEND_LK(_x) */
		//MACDBG("Invalid Port: %d\n", port);
		return -EINVAL;
		break;
	}

	return nfp_nbi_mac_regw(nbi, NFP_NBI_MACX_CSR, r, m, d);
}

/*
 *
 *   Read timestamp/parse-result prepend on ingress.
 *
 *  @param nbi NBI device
 *  @param core mac ethernet core: [0-1]
 *  @param port mac ethernet port: [0-11]
 *  @return  disable = 0; parse-result = 1; timestamp = 2; both = 3.
 *  @return  < 0 Error
 */
int nfp_nbi_mac_eth_read_ingress_prepend_state(struct nfp_nbi_dev *nbi,
					       int core, int port)
{
	uint64_t r;
	uint32_t d = 0;
	int ret;

	if (nbi == NULL) {
		return -ENODEV;
	}

	if (core == 0) {
		r = NFP_NBI_MACX_CSR_IgPortPrependEn0;
	} else if (core == 1) {
		r = NFP_NBI_MACX_CSR_IgPortPrependEn1;
	} else {
		return -EINVAL;
	}

	ret = nfp_nbi_mac_regr(nbi, NFP_NBI_MACX_CSR, r, &d);
	if (ret < 0)
		return ret;

	switch (port) {
	case 0:
		ret = NFP_NBI_MACX_CSR_IgPrependEn_PrependEn0_of(d);
		break;
	case 1:
		ret = NFP_NBI_MACX_CSR_IgPrependEn_PrependEn1_of(d);
		break;
	case 2:
		ret = NFP_NBI_MACX_CSR_IgPrependEn_PrependEn2_of(d);
		break;
	case 3:
		ret = NFP_NBI_MACX_CSR_IgPrependEn_PrependEn3_of(d);
		break;
	case 4:
		ret = NFP_NBI_MACX_CSR_IgPrependEn_PrependEn4_of(d);
		break;
	case 5:
		ret = NFP_NBI_MACX_CSR_IgPrependEn_PrependEn5_of(d);
		break;
	case 6:
		ret = NFP_NBI_MACX_CSR_IgPrependEn_PrependEn6_of(d);
		break;
	case 7:
		ret = NFP_NBI_MACX_CSR_IgPrependEn_PrependEn7_of(d);
		break;
	case 8:
		ret = NFP_NBI_MACX_CSR_IgPrependEn_PrependEn8_of(d);
		break;
	case 9:
		ret = NFP_NBI_MACX_CSR_IgPrependEn_PrependEn9_of(d);
		break;
	case 10:
		ret = NFP_NBI_MACX_CSR_IgPrependEn_PrependEn10_of(d);
		break;
	case 11:
		ret = NFP_NBI_MACX_CSR_IgPrependEn_PrependEn11_of(d);
		break;
	default:
		/* NFP_NBI_MACX_CSR_IGPREPENDEN_PREPEND_LK(_x) */
		//MACDBG("Invalid Port: %d\n", port);
		return -EINVAL;
		break;
	}

	return ret;
}

/*
 * Set the number of octets to skip on ingress packets.
 *  @param nbi NBI device
 *  @param core mac ethernet core: [0-1]
 *  @param port mac ethernet port: [0-11]
 *  @param octets Number of octets to skip [0-8]
 */
int nfp_nbi_mac_eth_write_ingress_skip(struct nfp_nbi_dev *nbi, int core,
				       int port, int octets)
{
	uint64_t r;
	uint32_t d = 0;
	uint32_t m = 0;

	if (nbi == NULL) {
		return -ENODEV;
	}
	if ((core < 0) || (core > 1)) {
		return -EINVAL;
	}
	if ((port < 0) || (port > 11)) {
		return -EINVAL;
	}

	if ((octets < 0) || (octets > 8)) {
		return -EINVAL;
	}

	switch ((port + core * 12) / 4) {
	case 0:
		r = NFP_NBI_MACX_CSR_MacPrePendCtl03to00;
		break;
	case 1:
		r = NFP_NBI_MACX_CSR_MacPrePendCtl07to04;
		break;
	case 2:
		r = NFP_NBI_MACX_CSR_MacPrePendCtl11to08;
		break;
	case 3:
		r = NFP_NBI_MACX_CSR_MacPrePendCtl15to12;
		break;
	case 4:
		r = NFP_NBI_MACX_CSR_MacPrePendCtl19to16;
		break;
	case 5:
		r = NFP_NBI_MACX_CSR_MacPrePendCtl23to20;
		break;
	default:
		//MACDBG("Invalid port\n");
		return -EINVAL;
		break;
	}

	switch (port) {
	case 0:
		m = NFP_NBI_MACX_CSR_MacPrePendCtl1_IGSkipOctetsPort0(0xf);
		d = NFP_NBI_MACX_CSR_MacPrePendCtl1_IGSkipOctetsPort0(octets);
		break;
	case 1:
		m = NFP_NBI_MACX_CSR_MacPrePendCtl1_IGSkipOctetsPort1(0xf);
		d = NFP_NBI_MACX_CSR_MacPrePendCtl1_IGSkipOctetsPort1(octets);
		break;
	case 2:
		m = NFP_NBI_MACX_CSR_MacPrePendCtl1_IGSkipOctetsPort2(0xf);
		d = NFP_NBI_MACX_CSR_MacPrePendCtl1_IGSkipOctetsPort2(octets);
		break;
	case 3:
		m = NFP_NBI_MACX_CSR_MacPrePendCtl1_IGSkipOctetsPort3(0xf);
		d = NFP_NBI_MACX_CSR_MacPrePendCtl1_IGSkipOctetsPort3(octets);
		break;
	case 4:
		m = NFP_NBI_MACX_CSR_MacPrePendCtl2_IGSkipOctetsPort4(0xf);
		d = NFP_NBI_MACX_CSR_MacPrePendCtl2_IGSkipOctetsPort4(octets);
		break;
	case 5:
		m = NFP_NBI_MACX_CSR_MacPrePendCtl2_IGSkipOctetsPort5(0xf);
		d = NFP_NBI_MACX_CSR_MacPrePendCtl2_IGSkipOctetsPort5(octets);
		break;
	case 6:
		m = NFP_NBI_MACX_CSR_MacPrePendCtl2_IGSkipOctetsPort6(0xf);
		d = NFP_NBI_MACX_CSR_MacPrePendCtl2_IGSkipOctetsPort6(octets);
		break;
	case 7:
		m = NFP_NBI_MACX_CSR_MacPrePendCtl2_IGSkipOctetsPort7(0xf);
		d = NFP_NBI_MACX_CSR_MacPrePendCtl2_IGSkipOctetsPort7(octets);
		break;
	case 8:
		m = NFP_NBI_MACX_CSR_MacPrePendCtl3_IGSkipOctetsPort8(0xf);
		d = NFP_NBI_MACX_CSR_MacPrePendCtl3_IGSkipOctetsPort8(octets);
		break;
	case 9:
		m = NFP_NBI_MACX_CSR_MacPrePendCtl3_IGSkipOctetsPort9(0xf);
		d = NFP_NBI_MACX_CSR_MacPrePendCtl3_IGSkipOctetsPort9(octets);
		break;
	case 10:
		m = NFP_NBI_MACX_CSR_MacPrePendCtl3_IGSkipOctetsPort10(0xf);
		d = NFP_NBI_MACX_CSR_MacPrePendCtl3_IGSkipOctetsPort10(octets);
		break;
	case 11:
		m = NFP_NBI_MACX_CSR_MacPrePendCtl3_IGSkipOctetsPort11(0xf);
		d = NFP_NBI_MACX_CSR_MacPrePendCtl3_IGSkipOctetsPort11(octets);
		break;
	default:
		//MACDBG("Invalid Port: %d\n", port);
		return -EINVAL;
		break;
	}

	//MACDBG("nfp_nbi_mac_eth_write_ingress_skip: Port %d, octets: %d\n", port, octets);
	return nfp_nbi_mac_regw(nbi, NFP_NBI_MACX_CSR, r, m, d);
}

// void nfp_nbi_mac_krneg(void);

int nfp_nbi_mac_eth_write_loopback_mode(struct nfp_nbi_dev *nbi, int core,
					int port, int mode)
{
	uint64_t r;
	uint32_t d = 0;
	uint32_t m = 0;

	if (nbi == NULL) {
		return -ENODEV;
	}
	if ((core < 0) || (core > 1)) {
		return -EINVAL;
	}
	if ((port < 0) || (port > 11)) {
		return -EINVAL;
	}
	//MACDBG("PCS Loopback: %d.\n", mode);

	// 10G Base-R: The PCS transmits the constant pattern of 0x00ff/0x00
	// 40G/100G Base-R: The PCS transmits the MAC transmit data unchanged
	r = NFP_NBI_MACX_ETH_MacEthChPcsSeg_EthChPcsCtl1(port);
	m = NFP_NBI_MACX_ETH_MacEthChPcsSeg_EthChPcsCtl1_EthPcsLoopback;
	if ((mode & NFP_NBI_MAC_LOOP_SYSPCS) > 0)
		d = NFP_NBI_MACX_ETH_MacEthChPcsSeg_EthChPcsCtl1_EthPcsLoopback;

	return nfp_nbi_mac_regw(nbi, NFP_NBI_MACX_ETH(core), r, m, d);
}

int nfp_nbi_mac_eth_read_loopback_mode(struct nfp_nbi_dev *nbi, int core,
				       int port)
{
	int ret;
	uint64_t r;
	uint32_t d = 0;
	int mode = 0;

	if (nbi == NULL) {
		return -ENODEV;
	}
	if ((core < 0) || (core > 1)) {
		return -EINVAL;
	}
	if ((port < 0) || (port > 11)) {
		return -EINVAL;
	}

	r = NFP_NBI_MACX_ETH_MacEthChPcsSeg_EthChPcsCtl1(port);
	ret = nfp_nbi_mac_regr(nbi, NFP_NBI_MACX_ETH(core), r, &d);
	if (ret < 0)
		return ret;

	if ((d & NFP_NBI_MACX_ETH_MacEthChPcsSeg_EthChPcsCtl1_EthPcsLoopback) >
	    0) {
		mode |= NFP_NBI_MAC_LOOP_SYSPCS;
	}
	//MACDBG("PCS Loopback: %d.\n", mode);
	return mode;
}

int nfp_nbi_mac_eth_write_mru(struct nfp_nbi_dev *nbi, int core, int port,
			      int framelen)
{
	uint64_t r;
	uint32_t d = 0;
	uint32_t m = 0;

	if (nbi == NULL) {
		return -ENODEV;
	}
	if ((core < 0) || (core > 1)) {
		return -EINVAL;
	}
	if ((port < 0) || (port > 11)) {
		return -EINVAL;
	}
	if ((framelen < 0) || (framelen > NFP_MAX_ETH_FRAME_LEN)) {
		return -EINVAL;
	}

	r = NFP_NBI_MACX_ETH_MacEthSeg_EthFrmLength(port);
	m = NFP_NBI_MACX_ETH_MacEthSeg_EthFrmLength_EthFrmLength(0xffff);
	d = NFP_NBI_MACX_ETH_MacEthSeg_EthFrmLength_EthFrmLength(framelen);

	return nfp_nbi_mac_regw(nbi, NFP_NBI_MACX_ETH(core), r, m, d);
}

int nfp_nbi_mac_eth_read_mru(struct nfp_nbi_dev *nbi, int core, int port)
{
	int ret;
	uint64_t r;
	uint32_t d = 0;

	if (nbi == NULL) {
		return -ENODEV;
	}
	if ((core < 0) || (core > 1)) {
		return -EINVAL;
	}
	if ((port < 0) || (port > 11)) {
		return -EINVAL;
	}

	r = NFP_NBI_MACX_ETH_MacEthSeg_EthFrmLength(port);

	ret = nfp_nbi_mac_regr(nbi, NFP_NBI_MACX_ETH(core), r, &d);
	if (ret < 0)
		return ret;

	return NFP_NBI_MACX_ETH_MacEthSeg_EthFrmLength_EthFrmLength_of(d);
}

int nfp_nbi_mac_eth_write_pause_quant(struct nfp_nbi_dev *nbi, int core,
				      int port, int pcpclass, int quant)
{
	uint64_t r;
	uint32_t d = 0;
	uint32_t m = 0;

	if (nbi == NULL) {
		return -ENODEV;
	}
	if ((core < 0) || (core > 1)) {
		return -EINVAL;
	}
	if ((port < 0) || (port > 11)) {
		return -EINVAL;
	}
	if ((pcpclass < 0) || (pcpclass > 7)) {
		return -EINVAL;
	}
	if ((quant < 0) || (quant > 0xffff)) {
		return -EINVAL;
	}

	switch (pcpclass) {
	case 0:
		r = NFP_NBI_MACX_ETH_MacEthSeg_EthPauseQuantaCL01(port);
		m = NFP_NBI_MACX_ETH_MacEthSeg_EthPauseQuantaCL01_EthPauseQuantaCL0(0xffff);
		d = NFP_NBI_MACX_ETH_MacEthSeg_EthPauseQuantaCL01_EthPauseQuantaCL0(quant);
		break;
	case 1:
		r = NFP_NBI_MACX_ETH_MacEthSeg_EthPauseQuantaCL01(port);
		m = NFP_NBI_MACX_ETH_MacEthSeg_EthPauseQuantaCL01_EthPauseQuantaCL1(0xffff);
		d = NFP_NBI_MACX_ETH_MacEthSeg_EthPauseQuantaCL01_EthPauseQuantaCL1(quant);
		break;
	case 2:
		r = NFP_NBI_MACX_ETH_MacEthSeg_EthPauseQuantaCL23(port);
		m = NFP_NBI_MACX_ETH_MacEthSeg_EthPauseQuantaCL23_EthPauseQuantaCL2(0xffff);
		d = NFP_NBI_MACX_ETH_MacEthSeg_EthPauseQuantaCL23_EthPauseQuantaCL2(quant);
		break;
	case 3:
		r = NFP_NBI_MACX_ETH_MacEthSeg_EthPauseQuantaCL23(port);
		m = NFP_NBI_MACX_ETH_MacEthSeg_EthPauseQuantaCL23_EthPauseQuantaCL3(0xffff);
		d = NFP_NBI_MACX_ETH_MacEthSeg_EthPauseQuantaCL23_EthPauseQuantaCL3(quant);
		break;
	case 4:
		r = NFP_NBI_MACX_ETH_MacEthSeg_EthPauseQuantaCL45(port);
		m = NFP_NBI_MACX_ETH_MacEthSeg_EthPauseQuantaCL45_EthPauseQuantaCL4(0xffff);
		d = NFP_NBI_MACX_ETH_MacEthSeg_EthPauseQuantaCL45_EthPauseQuantaCL4(quant);
		break;
	case 5:
		r = NFP_NBI_MACX_ETH_MacEthSeg_EthPauseQuantaCL45(port);
		m = NFP_NBI_MACX_ETH_MacEthSeg_EthPauseQuantaCL45_EthPauseQuantaCL5(0xffff);
		d = NFP_NBI_MACX_ETH_MacEthSeg_EthPauseQuantaCL45_EthPauseQuantaCL5(quant);
		break;
	case 6:
		r = NFP_NBI_MACX_ETH_MacEthSeg_EthPauseQuantaCL67(port);
		m = NFP_NBI_MACX_ETH_MacEthSeg_EthPauseQuantaCL67_EthPauseQuantaCL6(0xffff);
		d = NFP_NBI_MACX_ETH_MacEthSeg_EthPauseQuantaCL67_EthPauseQuantaCL6(quant);
		break;
	case 7:
		r = NFP_NBI_MACX_ETH_MacEthSeg_EthPauseQuantaCL67(port);
		m = NFP_NBI_MACX_ETH_MacEthSeg_EthPauseQuantaCL67_EthPauseQuantaCL7(0xffff);
		d = NFP_NBI_MACX_ETH_MacEthSeg_EthPauseQuantaCL67_EthPauseQuantaCL7(quant);
		break;
	default:
		MACDBG("nfp_nbi_mac_pause_quanta: Invalid class\n");
		return -EINVAL;
	}

	return nfp_nbi_mac_regw(nbi, NFP_NBI_MACX_ETH(core), r, m, d);
}

int nfp_nbi_mac_eth_write_pause_thresh(struct nfp_nbi_dev *nbi, int core,
				       int port, int pcpclass, int thresh)
{
	uint64_t r;
	uint32_t d = 0;
	uint32_t m = 0;

	if (nbi == NULL) {
		return -ENODEV;
	}
	if ((core < 0) || (core > 1)) {
		return -EINVAL;
	}
	if ((port < 0) || (port > 11)) {
		return -EINVAL;
	}
	if ((pcpclass < 0) || (pcpclass > 7)) {
		return -EINVAL;
	}
	if ((thresh < 0) || (thresh > 0xffffffff)) {
		return -EINVAL;
	}

	switch (pcpclass) {
	case 0:
		r = NFP_NBI_MACX_ETH_MacEthSeg_EthQuantaThreshCL01(port);
		m = NFP_NBI_MACX_ETH_MacEthSeg_EthQuantaThreshCL01_EthQuantaThreshCL0(0xffff);
		d = NFP_NBI_MACX_ETH_MacEthSeg_EthQuantaThreshCL01_EthQuantaThreshCL0(thresh);
		break;
	case 1:
		r = NFP_NBI_MACX_ETH_MacEthSeg_EthQuantaThreshCL01(port);
		m = NFP_NBI_MACX_ETH_MacEthSeg_EthQuantaThreshCL01_EthQuantaThreshCL1(0xffff);
		d = NFP_NBI_MACX_ETH_MacEthSeg_EthQuantaThreshCL01_EthQuantaThreshCL1(thresh);
		break;
	case 2:
		r = NFP_NBI_MACX_ETH_MacEthSeg_EthQuantaThreshCL23(port);
		m = NFP_NBI_MACX_ETH_MacEthSeg_EthQuantaThreshCL23_EthQuantaThreshCL2(0xffff);
		d = NFP_NBI_MACX_ETH_MacEthSeg_EthQuantaThreshCL23_EthQuantaThreshCL2(thresh);
		break;
	case 3:
		r = NFP_NBI_MACX_ETH_MacEthSeg_EthQuantaThreshCL23(port);
		m = NFP_NBI_MACX_ETH_MacEthSeg_EthQuantaThreshCL23_EthQuantaThreshCL3(0xffff);
		d = NFP_NBI_MACX_ETH_MacEthSeg_EthQuantaThreshCL23_EthQuantaThreshCL3(thresh);
		break;
	case 4:
		r = NFP_NBI_MACX_ETH_MacEthSeg_EthQuantaThreshCL45(port);
		m = NFP_NBI_MACX_ETH_MacEthSeg_EthQuantaThreshCL45_EthQuantaThreshCL4(0xffff);
		d = NFP_NBI_MACX_ETH_MacEthSeg_EthQuantaThreshCL45_EthQuantaThreshCL4(thresh);
		break;
	case 5:
		r = NFP_NBI_MACX_ETH_MacEthSeg_EthQuantaThreshCL45(port);
		m = NFP_NBI_MACX_ETH_MacEthSeg_EthQuantaThreshCL45_EthQuantaThreshCL5(0xffff);
		d = NFP_NBI_MACX_ETH_MacEthSeg_EthQuantaThreshCL45_EthQuantaThreshCL5(thresh);
		break;
	case 6:
		r = NFP_NBI_MACX_ETH_MacEthSeg_EthQuantaThreshCL67(port);
		m = NFP_NBI_MACX_ETH_MacEthSeg_EthQuantaThreshCL67_EthQuantaThreshCL6(0xffff);
		d = NFP_NBI_MACX_ETH_MacEthSeg_EthQuantaThreshCL67_EthQuantaThreshCL6(thresh);
		break;
	case 7:
		r = NFP_NBI_MACX_ETH_MacEthSeg_EthQuantaThreshCL67(port);
		m = NFP_NBI_MACX_ETH_MacEthSeg_EthQuantaThreshCL67_EthQuantaThreshCL7(0xffff);
		d = NFP_NBI_MACX_ETH_MacEthSeg_EthQuantaThreshCL67_EthQuantaThreshCL7(thresh);
		break;
	default:
		//MACDBG("nfp_nbi_mac_quanta_thresh: Invalid class\n");
		return -EINVAL;
	}

	return nfp_nbi_mac_regw(nbi, NFP_NBI_MACX_ETH(core), r, m, d);
}

int nfp_nbi_mac_read_chan_pausewm(struct nfp_nbi_dev *nbi, int chan)
{
	int ret;
	uint32_t d = 0;

	if (nbi == NULL) {
		return -ENODEV;
	}

	if ((chan < 0) || (chan > NFP_NBI_MAC_CHAN_MAX)) {
		//MACPRT("read_channel_pausewm: Channel out of range (0-%d):, %d.\n", NFP_NBI_MAC_CHAN_MAX, chan);
		return -EINVAL;
	}
	//MAC + "csr_pausewatermark%d" % (chan / 2)
	ret =
	    nfp_nbi_mac_regr(nbi, NFP_NBI_MACX_CSR,
			     NFP_NBI_MACX_CSR_PauseWaterMark(chan / 2), &d);
	if (ret < 0)
		return ret;

	if (chan % 2 == 0) {
		d = NFP_NBI_MACX_CSR_PauseWaterMark_PauseWaterMark0_of(d);
	} else {
		d = NFP_NBI_MACX_CSR_PauseWaterMark_PauseWaterMark1_of(d);
	}

	return d;
}

int nfp_nbi_mac_write_chan_pausewm(struct nfp_nbi_dev *nbi, int chan, int pwm)
{
	uint64_t r;
	uint32_t d = 0;
	uint32_t m = 0;

	if (nbi == NULL) {
		return -ENODEV;
	}

	if ((chan < 0) || (chan > NFP_NBI_MAC_CHAN_MAX)) {
		return -EINVAL;
	}

	if ((pwm < 0) || (pwm > NFP_NBI_MAC_CHAN_PAUSE_WM_MAX)) {
		return -EINVAL;
	}
	//MAC + "csr_pausewatermark%d" % (chan / 2)
	r = NFP_NBI_MACX_CSR_PauseWaterMark(chan / 2);

	if (chan % 2 == 0) {
		m = NFP_NBI_MACX_CSR_PauseWaterMark_PauseWaterMark0
		    (NFP_NBI_MAC_CHAN_PAUSE_WM_MAX);
		d = NFP_NBI_MACX_CSR_PauseWaterMark_PauseWaterMark0(pwm);
	} else {
		m = NFP_NBI_MACX_CSR_PauseWaterMark_PauseWaterMark1
		    (NFP_NBI_MAC_CHAN_PAUSE_WM_MAX);
		d = NFP_NBI_MACX_CSR_PauseWaterMark_PauseWaterMark1(pwm);
	}

	return nfp_nbi_mac_regw(nbi, NFP_NBI_MACX_CSR, r, m, d);
}

/*
  void read_pause_status(struct nfp_nbi_dev *nbi, int eth, int port);
*/

int nfp_nbi_mac_eth_read_pcpremap(struct nfp_nbi_dev *nbi, int core, int port,
				  struct nfp_nbi_mac_chanremap *chanremap)
{
	int ret;
	uint32_t d = 0;

	if (nbi == NULL) {
		return -ENODEV;
	}
	if ((core < 0) || (core > 1)) {
		return -EINVAL;
	}
	if ((port < 0) || (port > 11)) {
		return -EINVAL;
	}
	if (chanremap == NULL) {
		return -EINVAL;
	}

	ret =
	    nfp_nbi_mac_regr(nbi, NFP_NBI_MACX_CSR,
			     NFP_NBI_MACX_CSR_MacPcpReMap(port + 12 * core),
			     &d);
	if (ret < 0)
		return ret;

	chanremap->ch_class[0] = NFP_NBI_MACX_CSR_MacPcpReMap_PcpReMap0_of(d);
	chanremap->ch_class[1] = NFP_NBI_MACX_CSR_MacPcpReMap_PcpReMap1_of(d);
	chanremap->ch_class[2] = NFP_NBI_MACX_CSR_MacPcpReMap_PcpReMap2_of(d);
	chanremap->ch_class[3] = NFP_NBI_MACX_CSR_MacPcpReMap_PcpReMap3_of(d);
	chanremap->ch_class[4] = NFP_NBI_MACX_CSR_MacPcpReMap_PcpReMap4_of(d);
	chanremap->ch_class[5] = NFP_NBI_MACX_CSR_MacPcpReMap_PcpReMap5_of(d);
	chanremap->ch_class[6] = NFP_NBI_MACX_CSR_MacPcpReMap_PcpReMap6_of(d);
	chanremap->ch_class[7] = NFP_NBI_MACX_CSR_MacPcpReMap_PcpReMap7_of(d);
	chanremap->untagd = NFP_NBI_MACX_CSR_MacPcpReMap_UntaggedChan_of(d);

#if 0
	MACDBG("Channel remap %d.%d: 0x%x  %d,%d,%d,%d,%d,%d,%d,%d  %d\n",
	       core, port, d, chanremap->ch_class[0], chanremap->ch_class[1],
	       chanremap->ch_class[2], chanremap->ch_class[3],
	       chanremap->ch_class[4], chanremap->ch_class[5],
	       chanremap->ch_class[6], chanremap->ch_class[7],
	       chanremap->untagd);
#endif

	return 0;

}

int nfp_nbi_mac_eth_write_pcpremap(struct nfp_nbi_dev *nbi, int core, int port,
				   struct nfp_nbi_mac_chanremap *chanremap)
{
	//uint64_t r;
	uint32_t d = 0;
	uint32_t m = 0;

	if (nbi == NULL) {
		return -ENODEV;
	}
	if ((core < 0) || (core > 1)) {
		return -EINVAL;
	}
	if ((port < 0) || (port > 11)) {
		return -EINVAL;
	}
	if (chanremap == NULL) {
		return -EINVAL;
	}

	m = NFP_NBI_MACX_CSR_MacPcpReMap_PcpReMap0(7);
	m |= NFP_NBI_MACX_CSR_MacPcpReMap_PcpReMap1(7);
	m |= NFP_NBI_MACX_CSR_MacPcpReMap_PcpReMap2(7);
	m |= NFP_NBI_MACX_CSR_MacPcpReMap_PcpReMap3(7);
	m |= NFP_NBI_MACX_CSR_MacPcpReMap_PcpReMap4(7);
	m |= NFP_NBI_MACX_CSR_MacPcpReMap_PcpReMap5(7);
	m |= NFP_NBI_MACX_CSR_MacPcpReMap_PcpReMap6(7);
	m |= NFP_NBI_MACX_CSR_MacPcpReMap_PcpReMap7(7);
	m |= NFP_NBI_MACX_CSR_MacPcpReMap_UntaggedChan(0x3f);

	d = NFP_NBI_MACX_CSR_MacPcpReMap_PcpReMap0(chanremap->ch_class[0]);
	d |= NFP_NBI_MACX_CSR_MacPcpReMap_PcpReMap1(chanremap->ch_class[1]);
	d |= NFP_NBI_MACX_CSR_MacPcpReMap_PcpReMap2(chanremap->ch_class[2]);
	d |= NFP_NBI_MACX_CSR_MacPcpReMap_PcpReMap3(chanremap->ch_class[3]);
	d |= NFP_NBI_MACX_CSR_MacPcpReMap_PcpReMap4(chanremap->ch_class[4]);
	d |= NFP_NBI_MACX_CSR_MacPcpReMap_PcpReMap5(chanremap->ch_class[5]);
	d |= NFP_NBI_MACX_CSR_MacPcpReMap_PcpReMap6(chanremap->ch_class[6]);
	d |= NFP_NBI_MACX_CSR_MacPcpReMap_PcpReMap7(chanremap->ch_class[7]);
	d |= NFP_NBI_MACX_CSR_MacPcpReMap_UntaggedChan(chanremap->untagd);

#if 0
	MACDBG
	    ("Write channel remap %d.%d: 0x%x - %d,%d,%d,%d,%d,%d,%d,%d  %d\n\t\t\t\t\t%d,%d,%d,%d,%d,%d,%d,%d  %d\n",
	     core, port, d, chanremap->ch_class[0], chanremap->ch_class[1],
	     chanremap->ch_class[2], chanremap->ch_class[3],
	     chanremap->ch_class[4], chanremap->ch_class[5],
	     chanremap->ch_class[6], chanremap->ch_class[7], chanremap->untagd,
	     NFP_NBI_MACX_CSR_MacPcpReMap_PcpReMap0_of(d),
	     NFP_NBI_MACX_CSR_MacPcpReMap_PcpReMap1_of(d),
	     NFP_NBI_MACX_CSR_MacPcpReMap_PcpReMap2_of(d),
	     NFP_NBI_MACX_CSR_MacPcpReMap_PcpReMap3_of(d),
	     NFP_NBI_MACX_CSR_MacPcpReMap_PcpReMap4_of(d),
	     NFP_NBI_MACX_CSR_MacPcpReMap_PcpReMap5_of(d),
	     NFP_NBI_MACX_CSR_MacPcpReMap_PcpReMap6_of(d),
	     NFP_NBI_MACX_CSR_MacPcpReMap_PcpReMap7_of(d),
	     NFP_NBI_MACX_CSR_MacPcpReMap_UntaggedChan_of(d));
#endif

	return nfp_nbi_mac_regw(nbi, NFP_NBI_MACX_CSR,
				NFP_NBI_MACX_CSR_MacPcpReMap(port + 12 * core),
				m, d);
}

/*
  void nfp_nbi_mac_port_config(void);
  void set_speed(struct nfp_nbi_dev *nbi, int eth, int port, int speed);
*/

int nfp_nbi_mac_eth_write_portchan(struct nfp_nbi_dev *nbi, int core,
				   struct nfp_nbi_mac_portchan *ig,
				   struct nfp_nbi_mac_portchan *eg)
{
	int ret;
	uint64_t r;
	uint32_t d = 0;
	uint32_t m = 0;
	int i, j, p;

	if (nbi == NULL) {
		return -ENODEV;
	}
	if ((core < 0) || (core > 1)) {
		return -EINVAL;
	}
	if ((ig == NULL) && (eg == NULL)) {
		return -EINVAL;
	}

	m = NFP_NBI_MACX_CSR_MacPortChanAssign_PortBaseChan0(0x3f) |
	    NFP_NBI_MACX_CSR_MacPortChanAssign_PortNumOfChannels0(0xf) |
	    NFP_NBI_MACX_CSR_MacPortChanAssign_PortBaseChan1(0x3f) |
	    NFP_NBI_MACX_CSR_MacPortChanAssign_PortNumOfChannels1(0xf) |
	    NFP_NBI_MACX_CSR_MacPortChanAssign_PortBaseChan2(0x3f) |
	    NFP_NBI_MACX_CSR_MacPortChanAssign_PortNumOfChannels2(0xf);

	if (ig != NULL) {
		// Ingress
		//MACDBG("Ingress \n");
		p = 0;
		for (j = 0; j < NFP_NBI_MAC_NUM_PORTCHAN_REGS / 2; j++) {
			for (i = 0; i < 3; i++) {
				if ((ig[p + i].base < 0)
				    || (ig[p + i].base > 63)) {
					MACDBG
					    ("write_hydra_portchan: Port %d: Invalid base channel %d\n",
					     p + i, ig[p + i].base);
					return -EINVAL;
				}
				if ((ig[p + i].num < 0) || (ig[p + i].num > 8)) {
					MACDBG
					    ("write_hydra_portchan: Port %d: Invalid number of channels %d\n",
					     p + i, ig[p + i].num);
					return -EINVAL;
				}
			}
			d = NFP_NBI_MACX_CSR_MacPortChanAssign_PortBaseChan0(ig
									     [p
									      +
									      0].
									     base);
			d |= NFP_NBI_MACX_CSR_MacPortChanAssign_PortNumOfChannels0(ig[p + 0].num);

			d |= NFP_NBI_MACX_CSR_MacPortChanAssign_PortBaseChan1(ig
									      [p
									       +
									       1].
									      base);
			d |= NFP_NBI_MACX_CSR_MacPortChanAssign_PortNumOfChannels1(ig[p + 1].num);

			d |= NFP_NBI_MACX_CSR_MacPortChanAssign_PortBaseChan2(ig
									      [p
									       +
									       2].
									      base);
			d |= NFP_NBI_MACX_CSR_MacPortChanAssign_PortNumOfChannels2(ig[p + 2].num);
			r = nfp_nbi_mac_ig_portchan_regs[j +
							 (NFP_NBI_MAC_NUM_PORTCHAN_REGS
							  / 2) * core];
			ret = nfp_nbi_mac_regw(nbi, NFP_NBI_MACX_CSR, r, m, d);
			if (ret < 0)
				return ret;
			//MACDBG("Ingress 0x%x 0x%x\n", (unsigned)r, (unsigned)d);
			//MACDBG("ports %d-%d: %d - %d; %d - %d; %d - %d\n", p, p+2,
			//           ig[p].base, ig[p].num, ig[p+1].base, ig[p+1].num, ig[p+2].base, ig[p+2].num);
			p = p + 3;
		}
	}

	if (eg != NULL) {
		// Egress
		//MACDBG("Egress \n");
		p = 0;
		for (j = 0; j < NFP_NBI_MAC_NUM_PORTCHAN_REGS / 2; j++) {
			for (i = 0; i < 3; i++) {
				if ((eg[p + i].base < 0)
				    || (eg[p + i].base > 63)) {
					MACDBG
					    ("write_hydra_portchan: Port %d: Invalid base channel %d\n",
					     p + i, eg[p + i].base);
					return -EINVAL;
				}
				if ((eg[p + i].num < 0) || (eg[p + i].num > 8)) {
					MACDBG
					    ("write_hydra_portchan: Port %d: Invalid number of channels %d\n",
					     p + i, eg[p + i].num);
					return -EINVAL;
				}
			}
			d = NFP_NBI_MACX_CSR_MacPortChanAssign_PortBaseChan0(eg
									     [p
									      +
									      0].
									     base);
			d |= NFP_NBI_MACX_CSR_MacPortChanAssign_PortNumOfChannels0(eg[p + 0].num);

			d |= NFP_NBI_MACX_CSR_MacPortChanAssign_PortBaseChan1(eg
									      [p
									       +
									       1].
									      base);
			d |= NFP_NBI_MACX_CSR_MacPortChanAssign_PortNumOfChannels1(eg[p + 1].num);

			d |= NFP_NBI_MACX_CSR_MacPortChanAssign_PortBaseChan2(eg
									      [p
									       +
									       2].
									      base);
			d |= NFP_NBI_MACX_CSR_MacPortChanAssign_PortNumOfChannels2(eg[p + 2].num);
			r = nfp_nbi_mac_eg_portchan_regs[j +
							 (NFP_NBI_MAC_NUM_PORTCHAN_REGS
							  / 2) * core];
			ret = nfp_nbi_mac_regw(nbi, NFP_NBI_MACX_CSR, r, m, d);
			if (ret < 0)
				return ret;
			//MACDBG("Ingress 0x%x 0x%x\n", (unsigned)r, (unsigned)d);
			//MACDBG("ports %d-%d: %d - %d; %d - %d; %d - %d\n", p, p+2,
			//           eg[p].base, eg[p].num, eg[p+1].base, eg[p+1].num, eg[p+2].base, eg[p+2].num);
			p = p + 3;
		}
	}

	return 0;
}

int nfp_nbi_mac_eth_read_portchan(struct nfp_nbi_dev *nbi, int core,
				  struct nfp_nbi_mac_portchan *ig,
				  struct nfp_nbi_mac_portchan *eg)
{
	int ret;
	uint32_t d = 0;
	int i, p;

	if (nbi == NULL) {
		return -ENODEV;
	}
	if ((core < 0) || (core > 1)) {
		return -EINVAL;
	}
	if ((ig == NULL) && (eg == NULL)) {
		MACDBG("read_hydra_portchan: no portchan pointers specified\n");
		return -EINVAL;
	}

	if (ig != NULL) {
		// Ingress
		p = 0;
		for (i = 0; i < NFP_NBI_MAC_NUM_PORTCHAN_REGS / 2; i++) {
			ret = nfp_nbi_mac_regr(nbi, NFP_NBI_MACX_CSR,
					       nfp_nbi_mac_ig_portchan_regs[i +
									    (NFP_NBI_MAC_NUM_PORTCHAN_REGS
									     /
									     2)
									    *
									    core],
					       &d);
			if (ret < 0)
				return ret;

			ig[p + 0].base =
			    NFP_NBI_MACX_CSR_MacPortChanAssign_PortBaseChan0_of
			    (d);
			ig[p + 0].num =
			    NFP_NBI_MACX_CSR_MacPortChanAssign_PortNumOfChannels0_of
			    (d);

			ig[p + 1].base =
			    NFP_NBI_MACX_CSR_MacPortChanAssign_PortBaseChan1_of
			    (d);
			ig[p + 1].num =
			    NFP_NBI_MACX_CSR_MacPortChanAssign_PortNumOfChannels1_of
			    (d);

			ig[p + 2].base =
			    NFP_NBI_MACX_CSR_MacPortChanAssign_PortBaseChan2_of
			    (d);
			ig[p + 2].num =
			    NFP_NBI_MACX_CSR_MacPortChanAssign_PortNumOfChannels2_of
			    (d);
			//MACDBG("port %d: %d - %d; %d - %d; %d - %d\n", p,
			//           ig[p].base, ig[p].num, ig[p+1].base, ig[p+1].num, ig[p+2].base, ig[p+2].num);
			p = p + 3;
		}
	}

	if (eg != NULL) {
		// Egress
		p = 0;
		for (i = 0; i < NFP_NBI_MAC_NUM_PORTCHAN_REGS / 2; i++) {
			ret = nfp_nbi_mac_regr(nbi, NFP_NBI_MACX_CSR,
					       nfp_nbi_mac_eg_portchan_regs[i +
									    (NFP_NBI_MAC_NUM_PORTCHAN_REGS
									     /
									     2)
									    *
									    core],
					       &d);
			if (ret < 0)
				return ret;

			eg[p + 0].base =
			    NFP_NBI_MACX_CSR_MacPortChanAssign_PortBaseChan0_of
			    (d);
			eg[p + 0].num =
			    NFP_NBI_MACX_CSR_MacPortChanAssign_PortNumOfChannels0_of
			    (d);

			eg[p + 1].base =
			    NFP_NBI_MACX_CSR_MacPortChanAssign_PortBaseChan1_of
			    (d);
			eg[p + 1].num =
			    NFP_NBI_MACX_CSR_MacPortChanAssign_PortNumOfChannels1_of
			    (d);

			eg[p + 2].base =
			    NFP_NBI_MACX_CSR_MacPortChanAssign_PortBaseChan2_of
			    (d);
			eg[p + 2].num =
			    NFP_NBI_MACX_CSR_MacPortChanAssign_PortNumOfChannels2_of
			    (d);

			//MACDBG("port %d: %d - %d; %d - %d; %d - %d\n", p,
			//           eg[p].base, eg[p].num, eg[p+1].base, eg[p+1].num, eg[p+2].base, eg[p+2].num);
			p = p + 3;
		}
	}
	return 0;

}

/*
  void read_chanport(struct nfp_nbi_dev *nbi, int chan);
  void checkEthPort(int eth, int port);
  void nfp_nbi_mac_portstats(void);
  void stats(struct nfp_nbi_dev *nbi, int eth, int seg);
  void nfp_nbi_mac_reneg(void);
  void nfp_nbi_mac_status(void);
  void status(struct nfp_nbi_dev *nbi, int eth, int port);
  void nfp_nbi_mac_timestamp_read(void);
  void nfp_nbi_mac_timestamp_write(void);
  void nfp_mdio_regr(void);
  void nfp_mdio_regw(void);

*/

int nfp_nbi_mac_write_clock_enables(struct nfp_nbi_dev *nbi, uint32_t mask,
				    uint32_t state)
{
	int ret;
	uint32_t clkbits = NFP_NBI_MACX_CSR_MacBlkReset_MacCoreClkEnHy0 |
	    NFP_NBI_MACX_CSR_MacBlkReset_MacCoreClkEnHy1 |
	    NFP_NBI_MACX_CSR_MacBlkReset_MacCoreClkEnLk0 |
	    NFP_NBI_MACX_CSR_MacBlkReset_MacCoreClkEnLk1 |
	    NFP_NBI_MACX_CSR_MacBlkReset_MacX2ClkEnLk0 |
	    NFP_NBI_MACX_CSR_MacBlkReset_MacX2ClkEnLk1;

	if (nbi == NULL) {
		return -ENODEV;
	}

	mask &= clkbits;

	if (state == 0) {
		ret =
		    nfp_nbi_mac_regw(nbi, NFP_NBI_MACX_CSR,
				     NFP_NBI_MACX_CSR_MacBlkReset, mask, 0);
	} else {
		ret =
		    nfp_nbi_mac_regw(nbi, NFP_NBI_MACX_CSR,
				     NFP_NBI_MACX_CSR_MacBlkReset, mask, mask);
	}

	return ret;

}

// should we check if port is enabled?
int nfp_nbi_mac_eth_write_resets(struct nfp_nbi_dev *nbi, int core,
				 uint32_t mask)
{
	uint64_t r;
	uint32_t m = 0;

	if (nbi == NULL) {
		return -ENODEV;
	}
	if ((core < 0) || (core > 1)) {
		return -EINVAL;
	}

	m = NFP_NBI_MACX_CSR_MacHydBlkReset_MacHydRxSerDesIfRst(0xfff) |
	    NFP_NBI_MACX_CSR_MacHydBlkReset_MacHydTxSerDesIfRst(0xfff) |
	    NFP_NBI_MACX_CSR_MacHydBlkReset_MacHydRxFFRst |
	    NFP_NBI_MACX_CSR_MacHydBlkReset_MacHydTxFFRst |
	    NFP_NBI_MACX_CSR_MacHydBlkReset_MacHydRefRst |
	    NFP_NBI_MACX_CSR_MacHydBlkReset_MacHydRegRst;

	if (core == 0) {
		r = NFP_NBI_MACX_CSR_MacHyd0BlkReset;
	} else {
		r = NFP_NBI_MACX_CSR_MacHyd1BlkReset;
	}

	return nfp_nbi_mac_regw(nbi, NFP_NBI_MACX_CSR, r, m, mask);
}

int nfp_nbi_mac_eth_read_linkstate(struct nfp_nbi_dev *nbi, int core, int port,
				   uint32_t * linkstate)
{
	uint64_t r;
	uint32_t d = 0;
	uint32_t m = 0;
	uint32_t status = 0;
	int ret;

	if (nbi == NULL) {
		return -ENODEV;
	}
	if ((core < 0) || (core > 1)) {
		return -EINVAL;
	}
	if ((port < 0) || (port > 11)) {
		return -EINVAL;
	}
	if (linkstate) {
		*linkstate = 0;
	}

	ret = nfp_nbi_mac_regr(nbi, NFP_NBI_MACX_CSR,
			       NFP_NBI_MACX_CSR_MacMuxCtrl, &d);
	if (ret < 0)
		return ret;

	m = 1 << ((core * 12) + port);
	if ((d & m) > 0)
		status |= NFP_NBI_MAC_MacMuxCtrl_Error;

	r = NFP_NBI_MACX_ETH_MacEthGlobal_EthActCtlSeg;
	ret = nfp_nbi_mac_regr(nbi, NFP_NBI_MACX_ETH(core), r, &d);
	if (ret < 0)
		return ret;

	if (!(d & (0x1 << port)))
		status |= NFP_NBI_MAC_EthActCtlSeg_Disabled;

	r = NFP_NBI_MACX_ETH_MacEthChPcsSeg_EthChPcsStatus1(port);
	/* Double read to clear latch low on link down */
	ret = nfp_nbi_mac_regr(nbi, NFP_NBI_MACX_ETH(core), r, &d);
	if (ret < 0)
		return ret;

	ret = nfp_nbi_mac_regr(nbi, NFP_NBI_MACX_ETH(core), r, &d);
	if (ret < 0)
		return ret;

	if (!
	    (d &
	     NFP_NBI_MACX_ETH_MacEthChPcsSeg_EthChPcsStatus1_EthPcsRcvLinkStatus))
		status |= NFP_NBI_MAC_EthChPcsStatus1_EthPcsRcvLinkStatus_Down;

	r = NFP_NBI_MACX_ETH_MacEthChPcsSeg_EthChPcsBaseRStatus1(port);
	ret = nfp_nbi_mac_regr(nbi, NFP_NBI_MACX_ETH(core), r, &d);
	if (ret < 0)
		return ret;

	if (!
	    (d &
	     NFP_NBI_MACX_ETH_MacEthChPcsSeg_EthChPcsBaseRStatus1_EthPcsRcvLinkStatus))
		status |=
		    NFP_NBI_MAC_EthChPcsBaseRStatus1_EthPcsRcvLinkStatus_Down;

	if (!
	    (d &
	     NFP_NBI_MACX_ETH_MacEthChPcsSeg_EthChPcsBaseRStatus1_EthPcsBlockLocked))
		status |=
		    NFP_NBI_MAC_EthChPcsBaseRStatus1_EthPcsBlockLocked_False;

	r = NFP_NBI_MACX_ETH_MacEthSeg_EthCmdConfig(port);
	ret = nfp_nbi_mac_regr(nbi, NFP_NBI_MACX_ETH(core), r, &d);
	if (ret < 0)
		return ret;

	if (!(d & NFP_NBI_MACX_ETH_MacEthSeg_EthCmdConfig_EthTxEna))
		status |= NFP_NBI_MAC_EthCmdConfig_EthTxEna_False;

	if (!(d & NFP_NBI_MACX_ETH_MacEthSeg_EthCmdConfig_EthRxEna))
		status |= NFP_NBI_MAC_EthCmdConfig_EthRxEna_False;

	if (linkstate)
		*linkstate = status;

	return (status) ? 0 : 1;
}

/*   void lanemode(struct nfp_nbi_dev *nbi, int eth, int port); */

int nfp_nbi_mac_eth_read_mode(struct nfp_nbi_dev *nbi, int core, int port)
{
	int ret;
	uint64_t r;
	uint32_t d = 0;
	uint32_t m = 0;
	uint32_t mux = 0;
	int mode;
	int s;

	if (nbi == NULL) {
		return -ENODEV;
	}
	if ((core < 0) || (core > 1)) {
		return -EINVAL;
	}
	if ((port < 0) || (port > 11)) {
		return -EINVAL;
	}
	// Check the Serdes lane assignments
	ret =
	    nfp_nbi_mac_regr(nbi, NFP_NBI_MACX_CSR, NFP_NBI_MACX_CSR_MacMuxCtrl,
			     &mux);
	if (ret < 0)
		return ret;

	m = 1 << ((core * 12) + port);
	if ((mux & m) > 0) {
		return NFP_NBI_MAC_ILK;
	}

	/* check port 0 for 100G 0x2050 */
	r = NFP_NBI_MACX_ETH_MacEthChPcsSeg_EthChPcsCtl1(0);
	ret = nfp_nbi_mac_regr(nbi, NFP_NBI_MACX_ETH(core), r, &d);
	if (ret < 0)
		return ret;

	if ((d & NFP_NBI_MAC_EthChPcsCtl1_Mode_Mask) ==
	    NFP_NBI_MAC_EthChPcsCtl1_Mode_100GE) {
		// port 0-9 = 100G - ports 10, 11 can be 10G
		if (port < 10) {
			return NFP_NBI_MAC_ENET_100G;
		}
	}

	/* check ports 0,4,8 for 40G */
	s = port % 4;
	r = NFP_NBI_MACX_ETH_MacEthChPcsSeg_EthChPcsCtl1(port - s);
	ret = nfp_nbi_mac_regr(nbi, NFP_NBI_MACX_ETH(core), r, &d);
	if (ret < 0)
		return ret;

	if ((d & NFP_NBI_MAC_EthChPcsCtl1_Mode_Mask) ==
	    NFP_NBI_MAC_EthChPcsCtl1_Mode_40GE) {
		return NFP_NBI_MAC_ENET_40G;
	}
	// All that remains is 10G or less
	r = NFP_NBI_MACX_ETH_MacEthChPcsSeg_EthChPcsCtl1(port);
	ret = nfp_nbi_mac_regr(nbi, NFP_NBI_MACX_ETH(core), r, &d);
	if (ret < 0)
		return ret;

	switch (d & NFP_NBI_MAC_EthChPcsCtl1_Mode_Mask) {
	case (NFP_NBI_MAC_EthChPcsCtl1_Mode_10GE):
		// check if < 10G AE
		r = NFP_NBI_MACX_ETH_MacEthSeg_EthSgmiiIfMode(port);
		ret = nfp_nbi_mac_regr(nbi, NFP_NBI_MACX_ETH(core), r, &d);
		if (ret < 0)
			return ret;

		if (d &
		    NFP_NBI_MACX_ETH_MacEthSeg_EthSgmiiIfMode_EthSgmiiPcsEnable)
		{
			if (d &
			    NFP_NBI_MACX_ETH_MacEthSeg_EthSgmiiIfMode_EthSgmiiEna)
			{
				/* SGMII */
				switch
				    (NFP_NBI_MACX_ETH_MacEthSeg_EthSgmiiIfMode_EthSgmiiSpeed_of
				     (d)) {
				case (NFP_NBI_MACX_ETH_MacEthSeg_EthSgmiiIfMode_EthSgmiiSpeed_10Mbps):
					mode =
					    NFP_NBI_MAC_ENET_10M;
					break;
				case (NFP_NBI_MACX_ETH_MacEthSeg_EthSgmiiIfMode_EthSgmiiSpeed_100Mbps):
					mode =
					    NFP_NBI_MAC_ENET_100M;
					break;
				case (0x2):
					// AE case (NFP_NBI_MACX_ETH_MacEthSeg_EthSgmiiIfMode_EthSgmiiSpeed_100Mbps):
					mode = NFP_NBI_MAC_ENET_1G;
					break;
				default:
					mode = -EINVAL;
					break;
				}
			} else {
				// 100Base-X
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

/*
  void read_serdes_clock(struct nfp_nbi_dev *nbi, int serdes);
  void serdes_enable(struct nfp_nbi_dev *nbi, int mask);
  void serdes_rst_off(struct nfp_nbi_dev *nbi);
  void serdes_rst_on(struct nfp_nbi_dev *nbi);
  void set_serdes_clock(struct nfp_nbi_dev *nbi, int clk, int serdes);

// extra
void egress_crc_ena(int mask);
void egress_prepend_mask(int mask);
void mac_tm_oobfc_ena(struct nfp_nbi_dev *nbi, int enable);
void mac_tm_oobfc_get(struct nfp_nbi_dev *nbi, int entry);
*/

int nfp_nbi_mac_eth_write_vlantpid(struct nfp_nbi_dev *nbi, int slot,
				   int vlanid)
{
	uint64_t r;
	uint32_t d = 0;
	uint32_t m = 0;

	if (nbi == NULL) {
		return -ENODEV;
	}
	if ((slot < 0) || (slot > 7)) {
		return -EINVAL;
	}

	m = NFP_NBI_MACX_ETH_MacEthVlanTpidCfg_EthVlanTpid_EthVlanTpid(0xffff);
	d = NFP_NBI_MACX_ETH_MacEthVlanTpidCfg_EthVlanTpid_EthVlanTpid(vlanid);

	switch (slot) {
	case 0:
		r = NFP_NBI_MACX_ETH_MacEthVlanTpidCfg_EthVlanTpid0;
		break;
	case 1:
		r = NFP_NBI_MACX_ETH_MacEthVlanTpidCfg_EthVlanTpid1;
		break;
	case 2:
		r = NFP_NBI_MACX_ETH_MacEthVlanTpidCfg_EthVlanTpid2;
		break;
	case 3:
		r = NFP_NBI_MACX_ETH_MacEthVlanTpidCfg_EthVlanTpid3;
		break;
	case 4:
		r = NFP_NBI_MACX_ETH_MacEthVlanTpidCfg_EthVlanTpid4;
		break;
	case 5:
		r = NFP_NBI_MACX_ETH_MacEthVlanTpidCfg_EthVlanTpid5;
		break;
	case 6:
		r = NFP_NBI_MACX_ETH_MacEthVlanTpidCfg_EthVlanTpid6;
		break;
	case 7:
		r = NFP_NBI_MACX_ETH_MacEthVlanTpidCfg_EthVlanTpid7;
		break;
	default:
		MACDBG("Write VLAN TPID invalid slot %d\n", slot);
		return -EINVAL;
		break;
	}

	return nfp_nbi_mac_regw(nbi, NFP_NBI_MACX_CSR, r, m, d);
}

// * AEFIX - refactor enable into separate function?
int nfp_nbi_mac_eth_write_ingress_dqdwrr(struct nfp_nbi_dev *nbi, int core,
					 int port, int en, int weight)
{
	int ret;
	uint32_t m;
	uint32_t d;
	int timeout = NFP_NBI_MAC_DQDWRR_TO;
	uint32_t busy = 1;

	if (nbi == NULL) {
		return -ENODEV;
	}
	if ((core < 0) || (core > 1)) {
		return -EINVAL;
	}
	if ((port < 0) || (port > 12)) {
		return -EINVAL;
	}
	// Set write enable for ingress dequeue DWRR memory
	m = NFP_NBI_MACX_CSR_MacSysSupCtrl_DwrrWeightWrEnable;
	d = NFP_NBI_MACX_CSR_MacSysSupCtrl_DwrrWeightWrEnable;
	ret = nfp_nbi_mac_regw(nbi, NFP_NBI_MACX_CSR,
			       NFP_NBI_MACX_CSR_MacSysSupCtrl, m, d);
	if (ret < 0)
		return ret;

	m = -1;
	d = (en) ? NFP_NBI_MACX_CSR_IgDqTdmMemoryRW_TdmPortArbEnable : 0;
	d |= NFP_NBI_MACX_CSR_IgDqTdmMemoryRW_TdmMemRdWrAddr(port + 12 * core) |
	    NFP_NBI_MACX_CSR_IgDqTdmMemoryRW_TdmMemWrBusy |
	    NFP_NBI_MACX_CSR_IgDqTdmMemoryRW_TdmPortWeightWrData(weight);

	//MACDBG("nfp_nbi_mac_write_ingress_dqdwrr - port: %d, en: %d, weight: %d\n",
	//           port, en, weight);
	ret = nfp_nbi_mac_regw(nbi, NFP_NBI_MACX_CSR,
			       NFP_NBI_MACX_CSR_IgDqTdmMemoryRW, -1, d);
	if (ret < 0)
		return ret;

	while ((busy != 0) && (timeout > 0)) {
		ret = nfp_nbi_mac_regr(nbi, NFP_NBI_MACX_CSR,
				       NFP_NBI_MACX_CSR_IgDqTdmMemoryRW, &busy);
		if (ret < 0)
			return ret;
		busy &= NFP_NBI_MACX_CSR_IgDqTdmMemoryRW_TdmMemWrBusy;
		timeout--;
	}

	if (timeout <= 0) {
		MACDBG("nfp_nbi_mac_write_ingress_dqdwrr ***Timeout\n");
		return -ETIMEDOUT;
	}
	return 0;

}				// end nfp_nbi_mac_write_ingress_dqdwrr

int nfp_nbi_mac_eth_read_ingress_dqdwrr(struct nfp_nbi_dev *nbi, int core,
					int port)
{
	int ret;
	uint32_t m;
	uint32_t d;
	int timeout = NFP_NBI_MAC_DQDWRR_TO;
	uint32_t busy = 1;

	if (nbi == NULL) {
		return -ENODEV;
	}
	if ((core < 0) || (core > 1)) {
		return -EINVAL;
	}
	if ((port < 0) || (port > 11)) {
		return -EINVAL;
	}

	/* Check that core clock is enabled, accesses to dwrr can hang if not */
	if (core == 0) {
		ret =
		    nfp_nbi_mac_regr(nbi, NFP_NBI_MACX_CSR,
				     NFP_NBI_MACX_CSR_MacBlkReset, &d);
		if (ret < 0)
			return ret;

		if (((d & NFP_NBI_MACX_CSR_MacBlkReset_MacCoreClkEnHy0) == 0)) {
			return 0;
		}
	} else {
		ret =
		    nfp_nbi_mac_regr(nbi, NFP_NBI_MACX_CSR,
				     NFP_NBI_MACX_CSR_MacBlkReset, &d);
		if (ret < 0)
			return ret;

		if (((d & NFP_NBI_MACX_CSR_MacBlkReset_MacCoreClkEnHy1) == 0)) {
			return 0;
		}
	}

	m = -1;
	d = NFP_NBI_MACX_CSR_IgDqTdmMemoryRW_TdmMemRdWrAddr(port + 12 * core) |
	    NFP_NBI_MACX_CSR_IgDqTdmMemoryRW_TdmMemRdBusy;

	ret = nfp_nbi_mac_regw(nbi, NFP_NBI_MACX_CSR,
			       NFP_NBI_MACX_CSR_IgDqTdmMemoryRW, m, d);
	if (ret < 0)
		return ret;

	ret = nfp_nbi_mac_regr(nbi, NFP_NBI_MACX_CSR,
			       NFP_NBI_MACX_CSR_IgDqTdmMemoryRW, &busy);
	if (ret < 0)
		return ret;

	busy &= NFP_NBI_MACX_CSR_IgDqTdmMemoryRW_TdmMemRdBusy;

	while ((busy != 0) && (timeout > 0)) {
		ret = nfp_nbi_mac_regr(nbi, NFP_NBI_MACX_CSR,
				       NFP_NBI_MACX_CSR_IgDqTdmMemoryRW, &d);
		if (ret < 0)
			return ret;

		busy = d & NFP_NBI_MACX_CSR_IgDqTdmMemoryRW_TdmMemRdBusy;
		timeout--;
	}

	if (timeout <= 0) {
		MACDBG("nfp_nbi_mac_read_ingress_dqdwrr ***Timeout\n");
		return -ETIMEDOUT;
	}
	// read the data register
	ret = nfp_nbi_mac_regr(nbi, NFP_NBI_MACX_CSR,
			       NFP_NBI_MACX_CSR_IgDqTdmMemoryRdData, &d);
	if (ret < 0)
		return ret;

	if ((d & NFP_NBI_MACX_CSR_IgDqTdmMemoryRdData_TdmMemRdDataValid) == 0) {
		MACDBG
		    ("nfp_nbi_mac_read_ingress_dqdwrr: IgDqTdmMemoryRW[TdmMemRdBusy] is 0 but IgDqTdmMemoryRdData[TdmMemRdDataValid] is not set\n");
		return -EINVAL;
	}
	if ((NFP_NBI_MACX_CSR_IgDqTdmMemoryRdData_TdmMemRdAddr_of(d)) !=
	    port + core * 12) {
		MACDBG
		    ("nfp_nbi_mac_read_ingress_dqdwrr: IgDqTdmMemoryRdData[TdmMemRdAddr] is %0x but requested read port was %0x",
		     NFP_NBI_MACX_CSR_IgDqTdmMemoryRdData_TdmMemRdAddr_of(d),
		     port + core * 12);
		return -EINVAL;
	}
	// AEFIX do we care about enable?
	if ((d & NFP_NBI_MACX_CSR_IgDqTdmMemoryRdData_TdmPortArbEnable) != 0) {
		return
		    NFP_NBI_MACX_CSR_IgDqTdmMemoryRdData_TdmPortWeightRdData_of
		    (d);
	} else {
		return
		    NFP_NBI_MACX_CSR_IgDqTdmMemoryRdData_TdmPortWeightRdData_of
		    (d);
	}
	return 0;
}

int nfp_nbi_mac_eth_read_portlanes(struct nfp_nbi_dev *nbi, int core, int port,
				   int *lbase, int *lnum)
{
	int mode;

	if (nbi == NULL) {
		return -ENODEV;
	}
	if ((core < 0) || (core > 1)) {
		return -EINVAL;
	}
	if ((port < 0) || (port > 11)) {
		return -EINVAL;
	}
	if ((lbase == NULL) && (lnum == NULL)) {
		return -EINVAL;
	}

	mode = nfp_nbi_mac_eth_read_mode(nbi, core, port);
	if (mode < 0) {
		return mode;
	}
	switch (mode) {
	case (NFP_NBI_MAC_ENET_100G):
		if (lbase) {
			*lbase = 0;
		}
		if (lnum) {
			*lnum = 10;
		}
		break;
	case (NFP_NBI_MAC_ENET_40G):
		if (lbase) {
			*lbase = port - port % 4;
		}
		if (lnum) {
			*lnum = 4;
		}
		break;
	default:
		if (lbase) {
			*lbase = port;
		}
		if (lnum) {
			*lnum = 1;
		}
		break;
	}

	return 0;
}

int nfp_nbi_mac_eth_read_cmdconfig(struct nfp_nbi_dev *nbi, int core, int port)
{
	int ret;
	uint64_t r;
	uint32_t d = 0;

	if (nbi == NULL) {
		return -ENODEV;
	}
	if ((core < 0) || (core > 1)) {
		return -EINVAL;
	}
	if ((port < 0) || (port > 11)) {
		return -EINVAL;
	}

	r = NFP_NBI_MACX_ETH_MacEthSeg_EthCmdConfig(port);
	ret = nfp_nbi_mac_regr(nbi, NFP_NBI_MACX_ETH(core), r, &d);
	if (ret < 0)
		return ret;

	return d & 0x7fffffff;
}

int nfp_nbi_mac_eth_write_cmdconfig(struct nfp_nbi_dev *nbi, int core,
				    int port, uint32_t mask, uint32_t value)
{
	int ret;
	uint64_t r;

	if (nbi == NULL) {
		return -ENODEV;
	}
	if ((core < 0) || (core > 1)) {
		return -EINVAL;
	}
	if ((port < 0) || (port > 11)) {
		return -EINVAL;
	}

	r = NFP_NBI_MACX_ETH_MacEthSeg_EthCmdConfig(port);
	ret = nfp_nbi_mac_regw(nbi, NFP_NBI_MACX_ETH(core), r,
			       mask & EthCmdConfigMask, value);
	if (ret < 0)
		return ret;

	return 0;
}

int nfp_nbi_mac_eth_read_egress_crc(struct nfp_nbi_dev *nbi, int core)
{
	int ret;
	uint32_t d = 0;

	if (nbi == NULL) {
		return -ENODEV;
	}
	if ((core < 0) || (core > 1)) {
		return -EINVAL;
	}

	ret = nfp_nbi_mac_regr(nbi, NFP_NBI_MACX_CSR,
			       NFP_NBI_MACX_CSR_MacTdm1Mode1110CrcEn, &d);
	if (ret < 0)
		return ret;

	return NFP_NBI_MACX_CSR_MacTdmMode1110Crc_MacEgressPortCrcEn_of(d);
}

int nfp_nbi_mac_eth_write_egress_crc(struct nfp_nbi_dev *nbi, int core,
				     uint32_t mask)
{
	uint32_t m;
	uint32_t d;

	if (nbi == NULL) {
		return -ENODEV;
	}
	if ((core < 0) || (core > 1)) {
		return -EINVAL;
	}
	m = NFP_NBI_MACX_CSR_MacTdmMode1110Crc_MacEgressPortCrcEn(0xfff);
	d = NFP_NBI_MACX_CSR_MacTdmMode1110Crc_MacEgressPortCrcEn(mask);
	return nfp_nbi_mac_regw(nbi, NFP_NBI_MACX_CSR,
				NFP_NBI_MACX_CSR_MacTdm1Mode1110CrcEn, m, d);
}

int nfp_nbi_mac_eth_read_egress_dsa(struct nfp_nbi_dev *nbi, int core, int port)
{
	int ret;
	uint64_t r;
	uint32_t d = 0;

	if (nbi == NULL) {
		return -ENODEV;
	}
	if ((core < 0) || (core > 1)) {
		return -EINVAL;
	}
	if ((port < 0) || (port > 11)) {
		return -EINVAL;
	}

	if ((port + core * 12) <= 15) {
		r = NFP_NBI_MACX_CSR_MacEgPrePendDsaCtl15to00;
	} else {
		r = NFP_NBI_MACX_CSR_MacEgPrePendDsaCtlLkand23to16;
	}

	ret = nfp_nbi_mac_regr(nbi, NFP_NBI_MACX_CSR, r, &d);
	if (ret < 0)
		return ret;

	switch (port + core * 12) {
	case 0:
		d = NFP_NBI_MACX_CSR_MacPrePendDsaCtl1_DsaTagModePort0_of(d);
		break;
	case 1:
		d = NFP_NBI_MACX_CSR_MacPrePendDsaCtl1_DsaTagModePort1_of(d);
		break;
	case 2:
		d = NFP_NBI_MACX_CSR_MacPrePendDsaCtl1_DsaTagModePort2_of(d);
		break;
	case 3:
		d = NFP_NBI_MACX_CSR_MacPrePendDsaCtl1_DsaTagModePort3_of(d);
		break;
	case 4:
		d = NFP_NBI_MACX_CSR_MacPrePendDsaCtl1_DsaTagModePort4_of(d);
		break;
	case 5:
		d = NFP_NBI_MACX_CSR_MacPrePendDsaCtl1_DsaTagModePort5_of(d);
		break;
	case 6:
		d = NFP_NBI_MACX_CSR_MacPrePendDsaCtl1_DsaTagModePort6_of(d);
		break;
	case 7:
		d = NFP_NBI_MACX_CSR_MacPrePendDsaCtl1_DsaTagModePort7_of(d);
		break;
	case 8:
		d = NFP_NBI_MACX_CSR_MacPrePendDsaCtl1_DsaTagModePort8_of(d);
		break;
	case 9:
		d = NFP_NBI_MACX_CSR_MacPrePendDsaCtl1_DsaTagModePort9_of(d);
		break;
	case 10:
		d = NFP_NBI_MACX_CSR_MacPrePendDsaCtl1_DsaTagModePort10_of(d);
		break;
	case 11:
		d = NFP_NBI_MACX_CSR_MacPrePendDsaCtl1_DsaTagModePort11_of(d);
		break;
	case 12:
		d = NFP_NBI_MACX_CSR_MacPrePendDsaCtl1_DsaTagModePort12_of(d);
		break;
	case 13:
		d = NFP_NBI_MACX_CSR_MacPrePendDsaCtl1_DsaTagModePort13_of(d);
		break;
	case 14:
		d = NFP_NBI_MACX_CSR_MacPrePendDsaCtl1_DsaTagModePort14_of(d);
		break;
	case 15:
		d = NFP_NBI_MACX_CSR_MacPrePendDsaCtl1_DsaTagModePort15_of(d);
		break;
	case 16:
		d = NFP_NBI_MACX_CSR_MacPrePendDsaCtl2_DsaTagModePort16_of(d);
		break;
	case 17:
		d = NFP_NBI_MACX_CSR_MacPrePendDsaCtl2_DsaTagModePort17_of(d);
		break;
	case 18:
		d = NFP_NBI_MACX_CSR_MacPrePendDsaCtl2_DsaTagModePort18_of(d);
		break;
	case 19:
		d = NFP_NBI_MACX_CSR_MacPrePendDsaCtl2_DsaTagModePort19_of(d);
		break;
	case 20:
		d = NFP_NBI_MACX_CSR_MacPrePendDsaCtl2_DsaTagModePort20_of(d);
		break;
	case 21:
		d = NFP_NBI_MACX_CSR_MacPrePendDsaCtl2_DsaTagModePort21_of(d);
		break;
	case 22:
		d = NFP_NBI_MACX_CSR_MacPrePendDsaCtl2_DsaTagModePort22_of(d);
		break;
	case 23:
		d = NFP_NBI_MACX_CSR_MacPrePendDsaCtl2_DsaTagModePort23_of(d);
		break;
	default:
		MACDBG("Invalid Port: %d\n", port);
		return -EINVAL;
		break;
	}
	return d;
}

int nfp_nbi_mac_eth_read_egress_skip(struct nfp_nbi_dev *nbi, int core,
				     int port)
{
	int ret;
	uint64_t r;
	uint32_t d = 0;

	if (nbi == NULL) {
		return -ENODEV;
	}
	if ((core < 0) || (core > 1)) {
		return -EINVAL;
	}
	if ((port < 0) || (port > 11)) {
		return -EINVAL;
	}

	switch ((port + core * 12) / 4) {
	case 0:
		r = NFP_NBI_MACX_CSR_MacPrePendCtl03to00;
		break;
	case 1:
		r = NFP_NBI_MACX_CSR_MacPrePendCtl07to04;
		break;
	case 2:
		r = NFP_NBI_MACX_CSR_MacPrePendCtl11to08;
		break;
	case 3:
		r = NFP_NBI_MACX_CSR_MacPrePendCtl15to12;
		break;
	case 4:
		r = NFP_NBI_MACX_CSR_MacPrePendCtl19to16;
		break;
	case 5:
		r = NFP_NBI_MACX_CSR_MacPrePendCtl23to20;
		break;
	default:
		return -EINVAL;
		break;
	}

	ret = nfp_nbi_mac_regr(nbi, NFP_NBI_MACX_CSR, r, &d);
	if (ret < 0)
		return ret;

	switch (port) {
	case 0:
		d = NFP_NBI_MACX_CSR_MacPrePendCtl1_EGSkipOctetsPort0_of(d);
		break;
	case 1:
		d = NFP_NBI_MACX_CSR_MacPrePendCtl1_EGSkipOctetsPort1_of(d);
		break;
	case 2:
		d = NFP_NBI_MACX_CSR_MacPrePendCtl1_EGSkipOctetsPort2_of(d);
		break;
	case 3:
		d = NFP_NBI_MACX_CSR_MacPrePendCtl1_EGSkipOctetsPort3_of(d);
		break;
	case 4:
		d = NFP_NBI_MACX_CSR_MacPrePendCtl2_EGSkipOctetsPort4_of(d);
		break;
	case 5:
		d = NFP_NBI_MACX_CSR_MacPrePendCtl2_EGSkipOctetsPort5_of(d);
		break;
	case 6:
		d = NFP_NBI_MACX_CSR_MacPrePendCtl2_EGSkipOctetsPort6_of(d);
		break;
	case 7:
		d = NFP_NBI_MACX_CSR_MacPrePendCtl2_EGSkipOctetsPort7_of(d);
		break;
	case 8:
		d = NFP_NBI_MACX_CSR_MacPrePendCtl3_EGSkipOctetsPort8_of(d);
		break;
	case 9:
		d = NFP_NBI_MACX_CSR_MacPrePendCtl3_EGSkipOctetsPort9_of(d);
		break;
	case 10:
		d = NFP_NBI_MACX_CSR_MacPrePendCtl3_EGSkipOctetsPort10_of(d);
		break;
	case 11:
		d = NFP_NBI_MACX_CSR_MacPrePendCtl3_EGSkipOctetsPort11_of(d);
		break;
	default:
		return -EINVAL;
		break;
	}

	return d;

}

int nfp_nbi_mac_eth_read_ingress_dsa(struct nfp_nbi_dev *nbi, int core,
				     int port)
{
	int ret;
	uint64_t r;
	uint32_t d = 0;

	if (nbi == NULL) {
		return -ENODEV;
	}
	if ((core < 0) || (core > 1)) {
		return -EINVAL;
	}
	if ((port < 0) || (port > 11)) {
		return -EINVAL;
	}

	if ((port + core * 12) <= 15) {
		r = NFP_NBI_MACX_CSR_MacPrePendDsaCtl15to00;
	} else {
		r = NFP_NBI_MACX_CSR_MacPrePendDsaCtlLkand23to16;
	}

	ret = nfp_nbi_mac_regr(nbi, NFP_NBI_MACX_CSR, r, &d);
	if (ret < 0)
		return ret;

	switch (port + core * 12) {
	case 0:
		d = NFP_NBI_MACX_CSR_MacPrePendDsaCtl1_DsaTagModePort0_of(d);
		break;
	case 1:
		d = NFP_NBI_MACX_CSR_MacPrePendDsaCtl1_DsaTagModePort1_of(d);
		break;
	case 2:
		d = NFP_NBI_MACX_CSR_MacPrePendDsaCtl1_DsaTagModePort2_of(d);
		break;
	case 3:
		d = NFP_NBI_MACX_CSR_MacPrePendDsaCtl1_DsaTagModePort3_of(d);
		break;
	case 4:
		d = NFP_NBI_MACX_CSR_MacPrePendDsaCtl1_DsaTagModePort4_of(d);
		break;
	case 5:
		d = NFP_NBI_MACX_CSR_MacPrePendDsaCtl1_DsaTagModePort5_of(d);
		break;
	case 6:
		d = NFP_NBI_MACX_CSR_MacPrePendDsaCtl1_DsaTagModePort6_of(d);
		break;
	case 7:
		d = NFP_NBI_MACX_CSR_MacPrePendDsaCtl1_DsaTagModePort7_of(d);
		break;
	case 8:
		d = NFP_NBI_MACX_CSR_MacPrePendDsaCtl1_DsaTagModePort8_of(d);
		break;
	case 9:
		d = NFP_NBI_MACX_CSR_MacPrePendDsaCtl1_DsaTagModePort9_of(d);
		break;
	case 10:
		d = NFP_NBI_MACX_CSR_MacPrePendDsaCtl1_DsaTagModePort10_of(d);
		break;
	case 11:
		d = NFP_NBI_MACX_CSR_MacPrePendDsaCtl1_DsaTagModePort11_of(d);
		break;
	case 12:
		d = NFP_NBI_MACX_CSR_MacPrePendDsaCtl1_DsaTagModePort12_of(d);
		break;
	case 13:
		d = NFP_NBI_MACX_CSR_MacPrePendDsaCtl1_DsaTagModePort13_of(d);
		break;
	case 14:
		d = NFP_NBI_MACX_CSR_MacPrePendDsaCtl1_DsaTagModePort14_of(d);
		break;
	case 15:
		d = NFP_NBI_MACX_CSR_MacPrePendDsaCtl1_DsaTagModePort15_of(d);
		break;
	case 16:
		d = NFP_NBI_MACX_CSR_MacPrePendDsaCtl2_DsaTagModePort16_of(d);
		break;
	case 17:
		d = NFP_NBI_MACX_CSR_MacPrePendDsaCtl2_DsaTagModePort17_of(d);
		break;
	case 18:
		d = NFP_NBI_MACX_CSR_MacPrePendDsaCtl2_DsaTagModePort18_of(d);
		break;
	case 19:
		d = NFP_NBI_MACX_CSR_MacPrePendDsaCtl2_DsaTagModePort19_of(d);
		break;
	case 20:
		d = NFP_NBI_MACX_CSR_MacPrePendDsaCtl2_DsaTagModePort20_of(d);
		break;
	case 21:
		d = NFP_NBI_MACX_CSR_MacPrePendDsaCtl2_DsaTagModePort21_of(d);
		break;
	case 22:
		d = NFP_NBI_MACX_CSR_MacPrePendDsaCtl2_DsaTagModePort22_of(d);
		break;
	case 23:
		d = NFP_NBI_MACX_CSR_MacPrePendDsaCtl2_DsaTagModePort23_of(d);
		break;
	default:
		MACDBG("Invalid Port: %d\n", port);
		return -EINVAL;
		break;
	}
	return d;
}

int nfp_nbi_mac_eth_write_ingress_dsa(struct nfp_nbi_dev *nbi, int core,
				      int port, int octets)
{
	uint64_t r;
	uint32_t d = 0;
	uint32_t m = 0;

	if (nbi == NULL) {
		return -ENODEV;
	}
	if ((core < 0) || (core > 1)) {
		return -EINVAL;
	}
	if ((port < 0) || (port > 11)) {
		return -EINVAL;
	}

	if ((octets != 0) && (octets != 4) && (octets != 8)) {
		return -EINVAL;
	}

	if ((port + core * 12) <= 15) {
		r = NFP_NBI_MACX_CSR_MacPrePendDsaCtl15to00;
	} else {
		r = NFP_NBI_MACX_CSR_MacPrePendDsaCtlLkand23to16;
	}

	switch (port + core * 12) {
	case 0:
		m = NFP_NBI_MACX_CSR_MacPrePendDsaCtl1_DsaTagModePort0(0xf);
		d = NFP_NBI_MACX_CSR_MacPrePendDsaCtl1_DsaTagModePort0(octets /
								       2);
		break;
	case 1:
		m = NFP_NBI_MACX_CSR_MacPrePendDsaCtl1_DsaTagModePort1(0xf);
		d = NFP_NBI_MACX_CSR_MacPrePendDsaCtl1_DsaTagModePort1(octets /
								       2);
		break;
	case 2:
		m = NFP_NBI_MACX_CSR_MacPrePendDsaCtl1_DsaTagModePort2(0xf);
		d = NFP_NBI_MACX_CSR_MacPrePendDsaCtl1_DsaTagModePort2(octets /
								       2);
		break;
	case 3:
		m = NFP_NBI_MACX_CSR_MacPrePendDsaCtl1_DsaTagModePort3(0xf);
		d = NFP_NBI_MACX_CSR_MacPrePendDsaCtl1_DsaTagModePort3(octets /
								       2);
		break;
	case 4:
		m = NFP_NBI_MACX_CSR_MacPrePendDsaCtl1_DsaTagModePort4(0xf);
		d = NFP_NBI_MACX_CSR_MacPrePendDsaCtl1_DsaTagModePort4(octets /
								       2);
		break;
	case 5:
		m = NFP_NBI_MACX_CSR_MacPrePendDsaCtl1_DsaTagModePort5(0xf);
		d = NFP_NBI_MACX_CSR_MacPrePendDsaCtl1_DsaTagModePort5(octets /
								       2);
		break;
	case 6:
		m = NFP_NBI_MACX_CSR_MacPrePendDsaCtl1_DsaTagModePort6(0xf);
		d = NFP_NBI_MACX_CSR_MacPrePendDsaCtl1_DsaTagModePort6(octets /
								       2);
		break;
	case 7:
		m = NFP_NBI_MACX_CSR_MacPrePendDsaCtl1_DsaTagModePort7(0xf);
		d = NFP_NBI_MACX_CSR_MacPrePendDsaCtl1_DsaTagModePort7(octets /
								       2);
		break;
	case 8:
		m = NFP_NBI_MACX_CSR_MacPrePendDsaCtl1_DsaTagModePort8(0xf);
		d = NFP_NBI_MACX_CSR_MacPrePendDsaCtl1_DsaTagModePort8(octets /
								       2);
		break;
	case 9:
		m = NFP_NBI_MACX_CSR_MacPrePendDsaCtl1_DsaTagModePort9(0xf);
		d = NFP_NBI_MACX_CSR_MacPrePendDsaCtl1_DsaTagModePort9(octets /
								       2);
		break;
	case 10:
		m = NFP_NBI_MACX_CSR_MacPrePendDsaCtl1_DsaTagModePort10(0xf);
		d = NFP_NBI_MACX_CSR_MacPrePendDsaCtl1_DsaTagModePort10(octets /
									2);
		break;
	case 11:
		m = NFP_NBI_MACX_CSR_MacPrePendDsaCtl1_DsaTagModePort11(0xf);
		d = NFP_NBI_MACX_CSR_MacPrePendDsaCtl1_DsaTagModePort11(octets /
									2);
		break;
	case 12:
		m = NFP_NBI_MACX_CSR_MacPrePendDsaCtl1_DsaTagModePort12(0xf);
		d = NFP_NBI_MACX_CSR_MacPrePendDsaCtl1_DsaTagModePort12(octets /
									2);
		break;
	case 13:
		m = NFP_NBI_MACX_CSR_MacPrePendDsaCtl1_DsaTagModePort13(0xf);
		d = NFP_NBI_MACX_CSR_MacPrePendDsaCtl1_DsaTagModePort13(octets /
									2);
		break;
	case 14:
		m = NFP_NBI_MACX_CSR_MacPrePendDsaCtl1_DsaTagModePort14(0xf);
		d = NFP_NBI_MACX_CSR_MacPrePendDsaCtl1_DsaTagModePort14(octets /
									2);
		break;
	case 15:
		m = NFP_NBI_MACX_CSR_MacPrePendDsaCtl1_DsaTagModePort15(0xf);
		d = NFP_NBI_MACX_CSR_MacPrePendDsaCtl1_DsaTagModePort15(octets /
									2);
		break;
	case 16:
		m = NFP_NBI_MACX_CSR_MacPrePendDsaCtl2_DsaTagModePort16(0xf);
		d = NFP_NBI_MACX_CSR_MacPrePendDsaCtl2_DsaTagModePort16(octets /
									2);
		break;
	case 17:
		m = NFP_NBI_MACX_CSR_MacPrePendDsaCtl2_DsaTagModePort17(0xf);
		d = NFP_NBI_MACX_CSR_MacPrePendDsaCtl2_DsaTagModePort17(octets /
									2);
		break;
	case 18:
		m = NFP_NBI_MACX_CSR_MacPrePendDsaCtl2_DsaTagModePort18(0xf);
		d = NFP_NBI_MACX_CSR_MacPrePendDsaCtl2_DsaTagModePort18(octets /
									2);
		break;
	case 19:
		m = NFP_NBI_MACX_CSR_MacPrePendDsaCtl2_DsaTagModePort19(0xf);
		d = NFP_NBI_MACX_CSR_MacPrePendDsaCtl2_DsaTagModePort19(octets /
									2);
		break;
	case 20:
		m = NFP_NBI_MACX_CSR_MacPrePendDsaCtl2_DsaTagModePort20(0xf);
		d = NFP_NBI_MACX_CSR_MacPrePendDsaCtl2_DsaTagModePort20(octets /
									2);
		break;
	case 21:
		m = NFP_NBI_MACX_CSR_MacPrePendDsaCtl2_DsaTagModePort21(0xf);
		d = NFP_NBI_MACX_CSR_MacPrePendDsaCtl2_DsaTagModePort21(octets /
									2);
		break;
	case 22:
		m = NFP_NBI_MACX_CSR_MacPrePendDsaCtl2_DsaTagModePort22(0xf);
		d = NFP_NBI_MACX_CSR_MacPrePendDsaCtl2_DsaTagModePort22(octets /
									2);
		break;
	case 23:
		m = NFP_NBI_MACX_CSR_MacPrePendDsaCtl2_DsaTagModePort23(0xf);
		d = NFP_NBI_MACX_CSR_MacPrePendDsaCtl2_DsaTagModePort23(octets /
									2);
		break;
	default:
		MACDBG("Invalid Port: %d\n", port);
		return -EINVAL;
		break;
	}

	return nfp_nbi_mac_regw(nbi, NFP_NBI_MACX_CSR, r, m, d);
}

int nfp_nbi_mac_eth_read_ingress_skip(struct nfp_nbi_dev *nbi, int core,
				      int port)
{
	int ret;
	uint64_t r;
	uint32_t d = 0;

	if (nbi == NULL) {
		return -ENODEV;
	}
	if ((core < 0) || (core > 1)) {
		return -EINVAL;
	}
	if ((port < 0) || (port > 11)) {
		return -EINVAL;
	}

	switch ((port + core * 12) / 4) {
	case 0:
		r = NFP_NBI_MACX_CSR_MacPrePendCtl03to00;
		break;
	case 1:
		r = NFP_NBI_MACX_CSR_MacPrePendCtl07to04;
		break;
	case 2:
		r = NFP_NBI_MACX_CSR_MacPrePendCtl11to08;
		break;
	case 3:
		r = NFP_NBI_MACX_CSR_MacPrePendCtl15to12;
		break;
	case 4:
		r = NFP_NBI_MACX_CSR_MacPrePendCtl19to16;
		break;
	case 5:
		r = NFP_NBI_MACX_CSR_MacPrePendCtl23to20;
		break;
	default:
		//MACDBG("Invalid port\n");
		return -EINVAL;
		break;
	}

	ret = nfp_nbi_mac_regr(nbi, NFP_NBI_MACX_CSR, r, &d);
	if (ret < 0)
		return ret;

	switch (port) {
	case 0:
		d = NFP_NBI_MACX_CSR_MacPrePendCtl1_IGSkipOctetsPort0_of(d);
		break;
	case 1:
		d = NFP_NBI_MACX_CSR_MacPrePendCtl1_IGSkipOctetsPort1_of(d);
		break;
	case 2:
		d = NFP_NBI_MACX_CSR_MacPrePendCtl1_IGSkipOctetsPort2_of(d);
		break;
	case 3:
		d = NFP_NBI_MACX_CSR_MacPrePendCtl1_IGSkipOctetsPort3_of(d);
		break;
	case 4:
		d = NFP_NBI_MACX_CSR_MacPrePendCtl2_IGSkipOctetsPort4_of(d);
		break;
	case 5:
		d = NFP_NBI_MACX_CSR_MacPrePendCtl2_IGSkipOctetsPort5_of(d);
		break;
	case 6:
		d = NFP_NBI_MACX_CSR_MacPrePendCtl2_IGSkipOctetsPort6_of(d);
		break;
	case 7:
		d = NFP_NBI_MACX_CSR_MacPrePendCtl2_IGSkipOctetsPort7_of(d);
		break;
	case 8:
		d = NFP_NBI_MACX_CSR_MacPrePendCtl3_IGSkipOctetsPort8_of(d);
		break;
	case 9:
		d = NFP_NBI_MACX_CSR_MacPrePendCtl3_IGSkipOctetsPort9_of(d);
		break;
	case 10:
		d = NFP_NBI_MACX_CSR_MacPrePendCtl3_IGSkipOctetsPort10_of(d);
		break;
	case 11:
		d = NFP_NBI_MACX_CSR_MacPrePendCtl3_IGSkipOctetsPort11_of(d);
		break;
	default:
		//MACDBG("Invalid Port: %d\n", port);
		return -EINVAL;
		break;
	}

	//MACDBG("nfp_nbi_mac_eth_write_ingress_skip: Port %d, octets: %d\n", port, octets);
	return d;

}

int nfp_nbi_mac_eth_read_pause_quant(struct nfp_nbi_dev *nbi, int core,
				     int port, int pcpclass)
{
	int ret;
	uint64_t r;
	uint32_t d = 0;

	if (nbi == NULL) {
		return -ENODEV;
	}
	if ((core < 0) || (core > 1)) {
		return -EINVAL;
	}
	if ((port < 0) || (port > 11)) {
		return -EINVAL;
	}
	if ((pcpclass < 0) || (pcpclass > 7)) {
		return -EINVAL;
	}

	switch (pcpclass) {
	case 0:
		r = NFP_NBI_MACX_ETH_MacEthSeg_EthPauseQuantaCL01(port);
		break;
	case 1:
		r = NFP_NBI_MACX_ETH_MacEthSeg_EthPauseQuantaCL01(port);
		break;
	case 2:
		r = NFP_NBI_MACX_ETH_MacEthSeg_EthPauseQuantaCL23(port);
		break;
	case 3:
		r = NFP_NBI_MACX_ETH_MacEthSeg_EthPauseQuantaCL23(port);
		break;
	case 4:
		r = NFP_NBI_MACX_ETH_MacEthSeg_EthPauseQuantaCL45(port);
		break;
	case 5:
		r = NFP_NBI_MACX_ETH_MacEthSeg_EthPauseQuantaCL45(port);
		break;
	case 6:
		r = NFP_NBI_MACX_ETH_MacEthSeg_EthPauseQuantaCL67(port);
		break;
	case 7:
		r = NFP_NBI_MACX_ETH_MacEthSeg_EthPauseQuantaCL67(port);
		break;
	default:
		MACDBG("nfp_nbi_mac_pause_quanta: Invalid class\n");
		return -EINVAL;
	}

	ret = nfp_nbi_mac_regr(nbi, NFP_NBI_MACX_ETH(core), r, &d);
	if (ret < 0)
		return ret;

	switch (pcpclass) {
	case 0:
		d = NFP_NBI_MACX_ETH_MacEthSeg_EthPauseQuantaCL01_EthPauseQuantaCL0_of(d);
		break;
	case 1:
		d = NFP_NBI_MACX_ETH_MacEthSeg_EthPauseQuantaCL01_EthPauseQuantaCL1_of(d);
		break;
	case 2:
		d = NFP_NBI_MACX_ETH_MacEthSeg_EthPauseQuantaCL23_EthPauseQuantaCL2_of(d);
		break;
	case 3:
		d = NFP_NBI_MACX_ETH_MacEthSeg_EthPauseQuantaCL23_EthPauseQuantaCL3_of(d);
		break;
	case 4:
		d = NFP_NBI_MACX_ETH_MacEthSeg_EthPauseQuantaCL45_EthPauseQuantaCL4_of(d);
		break;
	case 5:
		d = NFP_NBI_MACX_ETH_MacEthSeg_EthPauseQuantaCL45_EthPauseQuantaCL5_of(d);
		break;
	case 6:
		d = NFP_NBI_MACX_ETH_MacEthSeg_EthPauseQuantaCL67_EthPauseQuantaCL6_of(d);
		break;
	case 7:
		d = NFP_NBI_MACX_ETH_MacEthSeg_EthPauseQuantaCL67_EthPauseQuantaCL7_of(d);
		break;
	default:
		MACDBG("nfp_nbi_mac_pause_quanta: Invalid class\n");
		return -EINVAL;
	}

	return d;

}

int nfp_nbi_mac_read_egress_prepend_enable(struct nfp_nbi_dev *nbi, int chan)
{
	int ret;
	uint64_t r;
	uint32_t d = 0;

	if (nbi == NULL) {
		return -ENODEV;
	}
	if ((chan < 0) || (chan > NFP_NBI_MAC_CHAN_MAX)) {
		return -EINVAL;
	}

	switch (chan / 4) {
	case 0:
		r = NFP_NBI_MACX_CSR_EgCmdPrependEn0Lo;
		break;
	case 1:
		r = NFP_NBI_MACX_CSR_EgCmdPrependEn0Hi;
		break;
	case 2:
		r = NFP_NBI_MACX_CSR_EgCmdPrependEn1Lo;
		break;
	case 3:
		r = NFP_NBI_MACX_CSR_EgCmdPrependEn1Hi;
		break;
	default:
		return -EINVAL;
	}

	ret = nfp_nbi_mac_regr(nbi, NFP_NBI_MACX_CSR, r, &d);
	if (ret < 0)
		return ret;

	return (d & (1 << (chan % 4))) > 0;

}

int nfp_nbi_mac_eth_read_pause_thresh(struct nfp_nbi_dev *nbi, int core,
				      int port, int pcpclass)
{
	int ret;
	uint64_t r;
	uint32_t d = 0;

	if (nbi == NULL) {
		return -ENODEV;
	}
	if ((core < 0) || (core > 1)) {
		return -EINVAL;
	}
	if ((port < 0) || (port > 11)) {
		return -EINVAL;
	}
	if ((pcpclass < 0) || (pcpclass > 7)) {
		return -EINVAL;
	}

	switch (pcpclass) {
	case 0:
		r = NFP_NBI_MACX_ETH_MacEthSeg_EthQuantaThreshCL01(port);
		break;
	case 1:
		r = NFP_NBI_MACX_ETH_MacEthSeg_EthQuantaThreshCL01(port);
		break;
	case 2:
		r = NFP_NBI_MACX_ETH_MacEthSeg_EthQuantaThreshCL23(port);
		break;
	case 3:
		r = NFP_NBI_MACX_ETH_MacEthSeg_EthQuantaThreshCL23(port);
		break;
	case 4:
		r = NFP_NBI_MACX_ETH_MacEthSeg_EthQuantaThreshCL45(port);
		break;
	case 5:
		r = NFP_NBI_MACX_ETH_MacEthSeg_EthQuantaThreshCL45(port);
		break;
	case 6:
		r = NFP_NBI_MACX_ETH_MacEthSeg_EthQuantaThreshCL67(port);
		break;
	case 7:
		r = NFP_NBI_MACX_ETH_MacEthSeg_EthQuantaThreshCL67(port);
		break;
	default:
		//MACDBG("nfp_nbi_mac_quanta_thresh: Invalid class\n");
		return -EINVAL;
	}

	ret = nfp_nbi_mac_regr(nbi, NFP_NBI_MACX_ETH(core), r, &d);
	if (ret < 0)
		return ret;

	switch (pcpclass) {
	case 0:
		d = NFP_NBI_MACX_ETH_MacEthSeg_EthQuantaThreshCL01_EthQuantaThreshCL0_of(d);
		break;
	case 1:
		d = NFP_NBI_MACX_ETH_MacEthSeg_EthQuantaThreshCL01_EthQuantaThreshCL1_of(d);
		break;
	case 2:
		d = NFP_NBI_MACX_ETH_MacEthSeg_EthQuantaThreshCL23_EthQuantaThreshCL2_of(d);
		break;
	case 3:
		d = NFP_NBI_MACX_ETH_MacEthSeg_EthQuantaThreshCL23_EthQuantaThreshCL3_of(d);
		break;
	case 4:
		d = NFP_NBI_MACX_ETH_MacEthSeg_EthQuantaThreshCL45_EthQuantaThreshCL4_of(d);
		break;
	case 5:
		d = NFP_NBI_MACX_ETH_MacEthSeg_EthQuantaThreshCL45_EthQuantaThreshCL5_of(d);
		break;
	case 6:
		d = NFP_NBI_MACX_ETH_MacEthSeg_EthQuantaThreshCL67_EthQuantaThreshCL6_of(d);
		break;
	case 7:
		d = NFP_NBI_MACX_ETH_MacEthSeg_EthQuantaThreshCL67_EthQuantaThreshCL7_of(d);
		break;
	default:
		//MACDBG("nfp_nbi_mac_quanta_thresh: Invalid class\n");
		return -EINVAL;
	}

	return d;
}

int nfp_nbi_mac_eth_read_port_hwm(struct nfp_nbi_dev *nbi, int core, int port)
{
	int ret;
	uint64_t r;
	uint32_t d = 0;
	uint32_t h = 0;

	if (nbi == NULL) {
		return -ENODEV;
	}
	if ((core < 0) || (core > 1)) {
		return -EINVAL;
	}
	if ((port < 0) || (port > 11)) {
		return -EINVAL;
	}

	r = NFP_NBI_MACX_CSR_MacPortHwm((port + core * 12) / 2);

	ret = nfp_nbi_mac_regr(nbi, NFP_NBI_MACX_CSR, r, &d);
	if (ret < 0)
		return ret;

	if ((port % 2) == 0) {
		h = NFP_NBI_MACX_CSR_MacPortHwm_PortHwm0_of(d);
		d = NFP_NBI_MACX_CSR_MacPortHwm_PortDropDelta0_of(d);
	} else {
		h = NFP_NBI_MACX_CSR_MacPortHwm_PortHwm1_of(d);
		d = NFP_NBI_MACX_CSR_MacPortHwm_PortDropDelta1_of(d);
	}

	return (d << 16) | h;
}

int nfp_nbi_mac_eth_write_mac_addr(struct nfp_nbi_dev *nbi, int core,
				   int port, uint64_t hwaddr)
{
	int ret;
	uint64_t r;
	uint32_t d = 0;
	uint32_t m = 0;

	if (nbi == NULL) {
		return -ENODEV;
	}
	if ((core < 0) || (core > 1)) {
		return -EINVAL;
	}
	if ((port < 0) || (port > 11)) {
		return -EINVAL;
	}
	if ((hwaddr >> 48) > 0) {
		return -EINVAL;
	}

	r = NFP_NBI_MACX_ETH_MacEthSeg_EthMacAddr0(port);
	m = NFP_NBI_MACX_ETH_MacEthSeg_EthMacAddr0_EthMacAddr0(0xffffffffffff);
	d = NFP_NBI_MACX_ETH_MacEthSeg_EthMacAddr0_EthMacAddr0(hwaddr);

	ret = nfp_nbi_mac_regw(nbi, NFP_NBI_MACX_ETH(core), r, m, d);
	if (ret < 0)
		return ret;

	r = NFP_NBI_MACX_ETH_MacEthSeg_EthMacAddr1(port);
	m = NFP_NBI_MACX_ETH_MacEthSeg_EthMacAddr1_EthMacAddr1(0xffff);
	d = NFP_NBI_MACX_ETH_MacEthSeg_EthMacAddr1_EthMacAddr1(hwaddr >> 32);

	return nfp_nbi_mac_regw(nbi, NFP_NBI_MACX_ETH(core), r, m, d);
}

int nfp_nbi_mac_eth_read_mac_addr(struct nfp_nbi_dev *nbi, int core,
				  int port, uint64_t * hwaddr)
{
	int ret;
	uint64_t r;
	uint32_t d = 0;
	uint32_t m = 0;

	if (nbi == NULL) {
		return -ENODEV;
	}
	if ((core < 0) || (core > 1)) {
		return -EINVAL;
	}
	if ((port < 0) || (port > 11)) {
		return -EINVAL;
	}
	if (hwaddr == NULL) {
		return -EINVAL;
	}

	r = NFP_NBI_MACX_ETH_MacEthSeg_EthMacAddr0(port);
	ret = nfp_nbi_mac_regr(nbi, NFP_NBI_MACX_ETH(core), r, &d);
	if (ret < 0)
		return ret;

	r = NFP_NBI_MACX_ETH_MacEthSeg_EthMacAddr1(port);
	ret = nfp_nbi_mac_regr(nbi, NFP_NBI_MACX_ETH(core), r, &m);
	if (ret < 0)
		return ret;

	*hwaddr = m;
	*hwaddr = (*hwaddr << 32) | d;
	return 0;
}

int nfp_nbi_mac_write_timestamp(struct nfp_nbi_dev *nbi, uint64_t ts_sec,
				uint64_t ts_nsec)
{
	int ret;
	uint64_t r;
	uint32_t d = 0;
	uint32_t m = 0;

	if (nbi == NULL) {
		return -ENODEV;
	}

	r = NFP_NBI_MACX_CSR_MacTimeStampSetSec;
	m = -1;
	d = NFP_NBI_MACX_CSR_MacTimeStampSetSec_MacTimeStampSetSec(ts_sec);
	ret = nfp_nbi_mac_regw(nbi, NFP_NBI_MACX_CSR, r, m, d);
	if (ret < 0)
		return ret;

	r = NFP_NBI_MACX_CSR_MacTimeStampSetNsec;
	m = -1;
	d = NFP_NBI_MACX_CSR_MacTimeStampSetNsec_MacTimeStampSetNsec(ts_nsec);
	ret = nfp_nbi_mac_regw(nbi, NFP_NBI_MACX_CSR, r, m, d);
	if (ret < 0)
		return ret;

	// set clock mode, enable and load timestamp regs.
	r = NFP_NBI_MACX_CSR_MacSysSupCtrl;
	m = NFP_NBI_MACX_CSR_MacSysSupCtrl_TimeStampFrc |
	    NFP_NBI_MACX_CSR_MacSysSupCtrl_TimeStampSet |
	    NFP_NBI_MACX_CSR_MacSysSupCtrl_TimeStampEn;
	d = NFP_NBI_MACX_CSR_MacSysSupCtrl_TimeStampSet |
	    NFP_NBI_MACX_CSR_MacSysSupCtrl_TimeStampEn;

	return nfp_nbi_mac_regw(nbi, NFP_NBI_MACX_CSR, r, m, d);
}

int nfp_nbi_mac_read_timestamp(struct nfp_nbi_dev *nbi, uint64_t * ts_sec,
			       uint64_t * ts_nsec)
{
	int ret;
	uint64_t r;
	uint32_t d = 0;

	if (nbi == NULL) {
		return -ENODEV;
	}
	if ((ts_sec == NULL) || (ts_nsec == NULL)) {
		return -EINVAL;
	}

	r = NFP_NBI_MACX_CSR_MacTimeStampSec;
	ret = nfp_nbi_mac_regr(nbi, NFP_NBI_MACX_CSR, r, &d);
	if (ret < 0)
		return ret;
	*ts_sec = NFP_NBI_MACX_CSR_MacTimeStampSec_MacTimeStampSec_of(d);

	r = NFP_NBI_MACX_CSR_MacTimeStampNsec;
	ret = nfp_nbi_mac_regr(nbi, NFP_NBI_MACX_CSR, r, &d);
	if (ret < 0)
		return ret;
	*ts_nsec = NFP_NBI_MACX_CSR_MacTimeStampNsec_MacTimeStampNsec_of(d);

	return 0;

}

int nfp_nbi_mac_write_tmoobfc_enables(struct nfp_nbi_dev *nbi, uint32_t mask)
{
	uint64_t r;
	uint32_t d = 0;
	uint32_t m = 0;

	if (nbi == NULL) {
		return -ENODEV;
	}

	r = NFP_NBI_MACX_CSR_MacOobFcTmCntl;
	m = NFP_NBI_MACX_CSR_MacOobFcTmCntl_Oob1023To512Mod32M1(0xf) |
	    NFP_NBI_MACX_CSR_MacOobFcTmCntl_Oob1023To512MsgEn |
	    NFP_NBI_MACX_CSR_MacOobFcTmCntl_Oob1023To512En |
	    NFP_NBI_MACX_CSR_MacOobFcTmCntl_Oob511To0Mod32M1(0xf) |
	    NFP_NBI_MACX_CSR_MacOobFcTmCntl_Oob511To0MsgEn |
	    NFP_NBI_MACX_CSR_MacOobFcTmCntl_Oob511To0En;
	d = mask;

	return nfp_nbi_mac_regw(nbi, NFP_NBI_MACX_CSR, r, m, d);
}

int nfp_nbi_mac_read_tmoobfc_enables(struct nfp_nbi_dev *nbi)
{
	int ret;
	uint64_t r;
	uint32_t d = 0;

	if (nbi == NULL) {
		return -ENODEV;
	}

	r = NFP_NBI_MACX_CSR_MacOobFcTmCntl;
	ret = nfp_nbi_mac_regr(nbi, NFP_NBI_MACX_CSR, r, &d);
	if (ret < 0)
		return ret;

	d |= NFP_NBI_MACX_CSR_MacOobFcTmCntl_Oob1023To512Mod32M1(0xf) |
	    NFP_NBI_MACX_CSR_MacOobFcTmCntl_Oob1023To512MsgEn |
	    NFP_NBI_MACX_CSR_MacOobFcTmCntl_Oob1023To512En |
	    NFP_NBI_MACX_CSR_MacOobFcTmCntl_Oob511To0Mod32M1(0xf) |
	    NFP_NBI_MACX_CSR_MacOobFcTmCntl_Oob511To0MsgEn |
	    NFP_NBI_MACX_CSR_MacOobFcTmCntl_Oob511To0En;

	return d;

}

int nfp_nbi_mac_eth_read_pause_status(struct nfp_nbi_dev *nbi, int core,
				      int port)
{
	int ret;
	uint64_t r;
	uint32_t d = 0;

	if (nbi == NULL) {
		return -ENODEV;
	}
	if ((core < 0) || (core > 1)) {
		return -EINVAL;
	}
	if ((port < 0) || (port > 11)) {
		return -EINVAL;
	}

	r = NFP_NBI_MACX_ETH_MacEthSeg_EthRxPauseStatus(port);
	ret = nfp_nbi_mac_regr(nbi, NFP_NBI_MACX_ETH(core), r, &d);
	if (ret < 0)
		return ret;

	return
	    NFP_NBI_MACX_ETH_MacEthSeg_EthRxPauseStatus_EthRxPauseStatus_of(d);

}

/*
int nfp_nbi_mac_eth_read_headdrop(struct nfp_nbi_dev *nbi, int core, int port)
*/

/* vim: set shiftwidth=8 noexpandtab: */
