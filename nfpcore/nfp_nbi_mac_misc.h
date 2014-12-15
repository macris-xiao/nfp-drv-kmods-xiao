/**
 * Copyright (C) 2013-2014 Netronome Systems, Inc.  All rights reserved.
 * Author: Tony Egan <tony.egan@netronome.com>
 *
 * @file nfp_nbi_mac_misc.h
 * nfp6000 MAC API functions
 *
 */

#ifndef __NFP_NBI_MAC_MISC_H__
#define __NFP_NBI_MAC_MISC_H__

#include "nfp_nbi.h"

/* / @cond */

enum Debug_Level_e {
		Emergency = 0,
		Alert,          /* 1:action must be taken immediately */
		Critical,       /* 2:critical conditions */
		Error,          /* 3:error conditions */
		Warning,        /* 4:warning conditions */
		Notice,         /* 5:normal but significant condition */
		Informational,  /* 6:informational messages */
		Debug           /* 7:debug-level messages */
};

/* refactor */
enum nfp_nbi_mac_tdm_e {
	NFP_NBI_MAC_TDM_ENET0 = 0,
	NFP_NBI_MAC_TDM_ENET1 = 1,
	NFP_NBI_MAC_TDM_ENET2 = 2,
	NFP_NBI_MAC_TDM_ENET3 = 3,
	NFP_NBI_MAC_TDM_ENET4 = 4,
	NFP_NBI_MAC_TDM_ENET5 = 5,
	NFP_NBI_MAC_TDM_ENET6 = 6,
	NFP_NBI_MAC_TDM_ENET7 = 7,
	NFP_NBI_MAC_TDM_ENET8 = 8,
	NFP_NBI_MAC_TDM_ENET9 = 9,
	NFP_NBI_MAC_TDM_ENET10 = 10,
	NFP_NBI_MAC_TDM_ENET11 = 11,
	NFP_NBI_MAC_TDM_BLANK = 12,
	NFP_NBI_MAC_TDM_UNUSED = 13,
	NFP_NBI_MAC_TDM_ILK0 = 14,
	NFP_NBI_MAC_TDM_ILK1 = 15
};


enum nfp_nbi_mac_lanemode_e {
	NFP_NBI_MAC_ENET_OFF,
	NFP_NBI_MAC_ILK,
	NFP_NBI_MAC_ENET_10M,
	NFP_NBI_MAC_ENET_100M,
	NFP_NBI_MAC_ENET_1G,
	NFP_NBI_MAC_ENET_10G,
	NFP_NBI_MAC_ENET_40G,
	NFP_NBI_MAC_ENET_100G
};

enum nfp_nbi_mac_tdm_mode_e {
	NFP_NBI_MAC_TDM_MODE_OFF = 0,
	NFP_NBI_MAC_TDM_MODE_1G = 1,
	NFP_NBI_MAC_TDM_MODE_10G = 2,
	NFP_NBI_MAC_TDM_MODE_40G = 3,
	NFP_NBI_MAC_TDM_MODE_100G = 4,
	NFP_NBI_MAC_TDM_MODE_ILK = 5
};

enum serdesbrate {
	NFP_NBI_SERDES_BR_1P25,
	NFP_NBI_SERDES_BR_10P3125,
	NFP_NBI_SERDES_BR_12P5
};


#define NFP_NBI_MAC_SINGLE_LANE(l) ((l == NFP_NBI_MAC_ENET_10M)  || \
				(l == NFP_NBI_MAC_ENET_100M) || \
				(l == NFP_NBI_MAC_ENET_1G)   || \
				(l == NFP_NBI_MAC_ENET_10G))

#define NFP_NBI_MAC_ONEG_MODE(l) ((l == NFP_NBI_MAC_ENET_10M)  || \
			      (l == NFP_NBI_MAC_ENET_100M) || \
			      (l == NFP_NBI_MAC_ENET_1G))


#define NFP_NBI_MAC_DQDWRR_TO 1000	/* wait for dwrr register access */

#define NFP_NBI_MAC_CHAN_MAX            127
#define NFP_NBI_MAC_CHAN_PAUSE_WM_MAX  2047
#define NFP_NBI_MAC_PORT_HWM_MAX       2047
#define NFP_NBI_MAC_PORT_HWM_DELTA_MAX   31

/* Temporary for stats access */
#define CPP_BASE (0x10000000000000)

/* Mac device */
struct nfp_nbi_macdev {
	int id;
	int cppid;
	int statsid;
	struct nfp_device *nfp;
	struct nfp_cpp *cpp;
	struct nfp_cpp_area *statsa;
};

/* / @endcond */

/**
 * Port channel assignment structure.  Specifies the range of channels
 * associated with a port.
 */
struct nfp_nbi_mac_portchan {
	/** base channel */
	int base;
	/** number of channels */
	int num;
};

/**
 * Channel remap structure. Maps eight PCP classes into eight or fewer
 * channels and specifies a channel for untagged packets.
 */
struct nfp_nbi_mac_chanremap {
	/** Channel offset relative to base channel assigned to each class */
	int ch_class[8];
	/**
	 * Channel for untagged packets.
	 * Note: this is an absolute channel - not an offset
	 */
	int untagd;
};



/**
 * Read a MAC register.
 * @ingroup nfp6000-only
 *
 * Read the value of a MAC register.  The register address is
 * specified as a base plus an offset.  Base and offset addresses for
 * all MAC registers are defined in nfp_nbi_mac.h.
 *
 *  @param nbi NBI handle
 *  @param base Base address, e.g. NFP_NBI_MACX_ETH(1) - Ethernet core 1.
 *  @param reg Register, e.g. NFP_NBI_MACX_ETH_MacEthSeg_EthCmdConfig(port)
 *  @param[out] data Value read from the register
 *
 *  @return bytes read on success. Set errno and return -1 on error.
 */
int nfp_nbi_mac_regr(struct nfp_nbi_dev *nbi, uint32_t base,
			  uint32_t reg, uint32_t *data);

/**
 * Write a MAC register.
 * @ingroup nfp6000-only
 *
 * Write a value to a MAC register.  The register address is specified
 * as a base plus an offset.  Base and offset addresses for all MAC
 * registers are defined in nfp_nbi_mac.h.
 *
 * The value to be written is specified by the parameters "data" and
 * "mask".  If mask is -1 the register is overwritten with the value
 * of data. Otherwise the register is read first and only the bits
 * specified by mask are allowed to be changed by data when the value
 * is written back.
 *
 *  @param nbi NBI handle
 *  @param base Base address, e.g. NFP_NBI_MACX_ETH(1) - Ethernet core 1.
 *  @param reg Register, e.g. NFP_NBI_MACX_ETH_MacEthSeg_EthCmdConfig(port)
 *  @param mask Mask specifying the bits that may be changed by data.
 *  @param data Value to be written.
 *  @return None
 */
int nfp_nbi_mac_regw(struct nfp_nbi_dev *nbi, uint32_t base, uint32_t reg,
		     uint32_t mask, uint32_t data);


/**
 * Read a SerDes register.
 * @ingroup nfp6000-only
 *
 * The register is specified as an address within a SerDes group
 * {0..5}.  All SerDes registers are defined in nfp_nbi_mac.h.
 *
 * @param nbi NBI handle
 * @param serdes SerDes group
 * @param reg Register
 * @param[out] data Value read from the register
 *
 * @return 0 on success. Set errno and return -1 on error.
 */
int nfp_nbi_serdes_regr(struct nfp_nbi_dev *nbi, int serdes, uint32_t reg,
			uint32_t *data);

/**
 * Write a SerDes register.
 * @ingroup nfp6000-only
 *
 * The register is specified as an address within a SerDes group
 * {0..5}.  All SerDes registers are defined in nfp_nbi_mac.h.
 *
 * The value to be written is specified by the parameters "data" and
 * "mask".  If mask is -1 the register is overwritten with the value
 * of data. Otherwise the register is read first and only the bits
 * specified by mask are allowed to be changed by data when the value
 * is written back.
 *
 * @param nbi NBI handle
 * @param serdes SerDes group
 * @param reg Register
 * @param mask Mask specifying the bits that may be changed by data.
 * @param data Value to be written.
 *
 * @return 0 on success. Set errno and return -1 on error.
 */
int nfp_nbi_serdes_regw(struct nfp_nbi_dev *nbi, int serdes, uint32_t reg,
			uint32_t mask, uint32_t data);

/**
 * Release the reset hold established by macinit
 * @ingroup nfp6000-only
 *
 * Enable the serdes lanes indicated by mask (serdesmask=0xffffff)
 * Initiate RX adaptation on the lanes specified by rxadaptmask.
 *
 *  @param nbi NBI handle
 *  @param rxadaptmask mask specifying lanes for RX adaptation
 *  @param serdesmask a bitmap of the enables for the 24 serdes lanes
 *  @return
 */
int nfp_nbi_mac_init_release(struct nfp_nbi_dev *nbi, uint32_t rxadaptmask,
			     uint32_t serdesmask);

#endif
