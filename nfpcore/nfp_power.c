/*
 * Copyright (C) 2010-2015, Netronome Systems, Inc.  All rights reserved.
 *
 */

#include <linux/kernel.h>

#include "nfp_cpp_kernel.h"

#include "nfp6000/nfp_xpb.h"
#include "nfp3200/nfp_xpb.h"
#include "nfp3200/nfp_pl.h"
#include "nfp_power.h"

#define CTMX_BASE       (0x60000)
#define NFP_CTMX_CFG    (CTMX_BASE + 0x000000)

#define NBIX_BASE                       (0xa0000)
#define NFP_NBIX_CSR                    (NBIX_BASE + 0x2f0000)
#define NFP_NBIX_CSR_NbiMuXlate         0x00000000
#define   NFP_NBIX_CSR_NbiMuXlate_Island1(_x)                (((_x) & 0x3f) << 6)
#define   NFP_NBIX_CSR_NbiMuXlate_AccMode(_x)                (((_x) & 0x7) << 13)
#define   NFP_NBIX_CSR_NbiMuXlate_Island0(_x)                (((_x) & 0x3f) << 0)


static const struct {
	uint32_t reset_mask;
	uint32_t enable_mask;
} target_to_mask[] = {
	[NFP3200_DEVICE_ARM] = {
		.reset_mask = NFP_PL_RE_ARM_CORE_RESET,
		.enable_mask = NFP_PL_RE_ARM_CORE_ENABLE,
	},
	[NFP3200_DEVICE_ARM_GASKET] = {
		.reset_mask = NFP_PL_RE_ARM_GASKET_RESET,
		.enable_mask = NFP_PL_RE_ARM_GASKET_ENABLE,
	},
	[NFP3200_DEVICE_DDR0] = {
		.reset_mask = NFP_PL_RE_DDR0_RESET,
		.enable_mask = NFP_PL_RE_DDR0_ENABLE,
	},
	[NFP3200_DEVICE_DDR1] = {
		.reset_mask = NFP_PL_RE_DDR1_RESET,
		.enable_mask = NFP_PL_RE_DDR1_ENABLE,
	},
	[NFP3200_DEVICE_MECL0] = {
		.reset_mask = NFP_PL_RE_MECL_ME_RESET(1),
		.enable_mask = NFP_PL_RE_MECL_ME_ENABLE(1),
	},
	[NFP3200_DEVICE_MECL1] = {
	.reset_mask = NFP_PL_RE_MECL_ME_RESET(2),
		.enable_mask = NFP_PL_RE_MECL_ME_ENABLE(2),
	},
	[NFP3200_DEVICE_MECL2] = {
	.reset_mask = NFP_PL_RE_MECL_ME_RESET(4),
		.enable_mask = NFP_PL_RE_MECL_ME_ENABLE(4),
	},
	[NFP3200_DEVICE_MECL3] = {
		.reset_mask = NFP_PL_RE_MECL_ME_RESET(8),
		.enable_mask = NFP_PL_RE_MECL_ME_ENABLE(8),
	},
	[NFP3200_DEVICE_MECL4] = {
		.reset_mask = NFP_PL_RE_MECL_ME_RESET(16),
		.enable_mask = NFP_PL_RE_MECL_ME_ENABLE(16),
	},
	[NFP3200_DEVICE_MSF0] = {
		.reset_mask = NFP_PL_RE_MSF0_RESET,
		.enable_mask = NFP_PL_RE_MSF0_ENABLE,
	},
	[NFP3200_DEVICE_MSF1] = {
		.reset_mask = NFP_PL_RE_MSF1_RESET,
		.enable_mask = NFP_PL_RE_MSF1_ENABLE,
	},
	[NFP3200_DEVICE_MU] = {
		.reset_mask = NFP_PL_RE_MU_RESET,
		.enable_mask = NFP_PL_RE_MU_ENABLE,
	},
	[NFP3200_DEVICE_PCIE] = {
	.reset_mask = NFP_PL_RE_PCIE_RESET,
		.enable_mask = NFP_PL_RE_PCIE_ENABLE,
	},
	[NFP3200_DEVICE_QDR0] = {
		.reset_mask = NFP_PL_RE_QDR0_RESET,
		.enable_mask = NFP_PL_RE_QDR0_ENABLE,
	},
	[NFP3200_DEVICE_QDR1] = {
		.reset_mask = NFP_PL_RE_QDR1_RESET,
		.enable_mask = NFP_PL_RE_QDR1_ENABLE,
	},
	[NFP3200_DEVICE_CRYPTO] = {
		.reset_mask = NFP_PL_RE_CRYPTO_RESET,
		.enable_mask = NFP_PL_RE_CRYPTO_ENABLE,
	},
};

static int nfp3200_reset_get(struct nfp_cpp *cpp, unsigned int subdevice,
			     int *reset, int *enable)
{
	uint32_t r_mask, e_mask, csr;
	int err;

	if (subdevice > ARRAY_SIZE(target_to_mask))
		return -EINVAL;

	r_mask = target_to_mask[subdevice].reset_mask;
	e_mask = target_to_mask[subdevice].enable_mask;

	if (r_mask == 0 && e_mask == 0)
		return -EINVAL;

	/* Special exception for ARM:
	 *   The NFP_PL_STRAPS register bit 5 overrides the
	 *   reset and enable bits, so if it is on, then
	 *   force them on.
	 */
	if (subdevice == NFP3200_DEVICE_ARM) {
		err = nfp_xpb_readl(cpp, NFP_XPB_PL + NFP_PL_STRAPS, &csr);
		if (err < 0)
			return err;
	} else {
		csr = 0;
	}

	if (csr & NFP_PL_STRAPS_CFG_PROM_BOOT) {
		csr = (r_mask | e_mask);
	} else {
		err = nfp_xpb_readl(cpp, NFP_XPB_PL + NFP_PL_RE, &csr);
		if (err < 0)
			return err;
	}

	if (reset != NULL)
		*reset = (csr & r_mask) ? 1 : 0;

	if (enable != NULL)
		*enable = (csr & e_mask) ? 1 : 0;

	return 0;
}

int nfp3200_reset_set(struct nfp_cpp *cpp, unsigned int subdevice, int reset,
		      int enable)
{
	uint32_t csr, r_mask, e_mask;
	uint16_t interface;
	int err;

	if (subdevice > ARRAY_SIZE(target_to_mask))
		return -EINVAL;

	/* Disallow changes to the PCIE core if that
	 * is our interface to the device.
	 */
	interface = nfp_cpp_interface(cpp);
	if ((NFP_CPP_INTERFACE_TYPE_of(interface) == NFP_CPP_INTERFACE_TYPE_PCI)
	    && (subdevice == NFP3200_DEVICE_PCIE))
		return -EBUSY;

	r_mask = target_to_mask[subdevice].reset_mask;
	e_mask = target_to_mask[subdevice].enable_mask;

	if (r_mask == 0 && e_mask == 0)
		return -EINVAL;

	err = nfp_xpb_readl(cpp, NFP_XPB_PL + NFP_PL_RE, &csr);
	if (err)
		return err;

	csr = (csr & ~r_mask) | (reset ? r_mask : 0);
	csr = (csr & ~e_mask) | (enable ? e_mask : 0);

	err = nfp_xpb_writel(cpp, NFP_XPB_PL + NFP_PL_RE, csr);
	if (err)
		return err;

	/* If it's the ARM device, clear the
	 * forced setting from the strap register.
	 */
	if (subdevice == NFP3200_DEVICE_ARM ||
	    subdevice == NFP3200_DEVICE_ARM_GASKET) {
		err = nfp_xpb_readl(cpp, NFP_XPB_PL + NFP_PL_STRAPS, &csr);
		if (err)
			return err;

		csr &= ~NFP_PL_STRAPS_CFG_PROM_BOOT;
		err = nfp_xpb_writel(cpp, NFP_XPB_PL + NFP_PL_STRAPS, csr);
		if (err)
			return err;
	}

	return 0;
}

/* The IMB island mask lists all islands with
 * an IMB. Since the number of islands without
 * an IMB is smaller than the number with,
 * we invert a mask of those without to get
 * the list of those with an IMB.
 *
 * Funny C syntax:
 *
 * 0xFULL => (unsigned long long)0xf 
 */
static const uint64_t imb_island_mask = ~(0 | (0xFULL << 8)	/* NBI */
					    | (0xFULL << 24)	/* IMU */
					    | (0xFULL << 28)	/* EMU */
					  );

static int nfp6000_reset_get(struct nfp_cpp *cpp, unsigned int subdevice,
			     int *reset, int *enable)
{
	uint32_t csr;
	int island, mask, err;

	if (subdevice < NFP6000_DEVICE(1, 0) ||
	    subdevice > NFP6000_DEVICE(63, 7))
		return -EINVAL;

	island = NFP6000_DEVICE_ISLAND_of(subdevice);
	mask = (1 << NFP6000_DEVICE_UNIT_of(subdevice));

	if (!((1ULL << island) & nfp_cpp_island_mask(cpp)))
		return -ENODEV;

	err = nfp_xpb_readl(cpp, (island << 24) | 0x45400, &csr);
	if (err < 0)
		return err;

	*enable = (((csr >> 24) & mask) == mask) ? 1 : 0;
	*reset = (((csr >> 16) & mask) == mask) ? 1 : 0;

	return 0;
}

int nfp6000_reset_set(struct nfp_cpp *cpp, unsigned int subdevice, int reset,
		      int enable)
{
	uint32_t csr, mem;
	int island, mask, err;

	if (subdevice < NFP6000_DEVICE(1, 0) ||
	    subdevice > NFP6000_DEVICE(63, 7))
		return -EINVAL;

	island = NFP6000_DEVICE_ISLAND_of(subdevice);
	mask = (1 << NFP6000_DEVICE_UNIT_of(subdevice));

	if (!((1ULL << island) & nfp_cpp_island_mask(cpp)))
		return -ENODEV;

	err = nfp_xpb_readl(cpp, (island << 24) | 0x45400, &csr);
	if (err < 0)
		return err;

	err = nfp_xpb_readl(cpp, (island << 24) | 0x45404, &mem);
	if (err < 0)
		return err;

	/* Determine if the island was down
	 */
	csr &= ~((mask << 24) | (mask << 16));

	if (enable)
		csr |= mask << 24;

	if (reset)
		csr |= mask << 16;

	if (enable || reset)
		mem |= mask;

	/* We must NEVER put the ARM Island into reset, otherwise
	 * there will be no ability to access the XPBM interface!
	 */
	if (island == 1) {
		csr |= 0x01010000;
		mem |= 0x01;
	}

	err = nfp_xpb_writel(cpp, (island << 24) | 0x45404, mem);
	if (err < 0)
		return err;

	err = nfp_xpb_writel(cpp, (island << 24) | 0x45400, csr);
	if (err < 0)
		return err;

	return 0;
}

int nfp_power_get(struct nfp_device *nfp, unsigned int subdevice, int *state)
{
	struct nfp_cpp *cpp;
	uint32_t model;
	int err, reset = 0, enable = 0;

	cpp = nfp_device_cpp(nfp);

	model = nfp_cpp_model(cpp);

	if (NFP_CPP_MODEL_IS_3200(model))
		err = nfp3200_reset_get(cpp, subdevice, &reset, &enable);
	else if (NFP_CPP_MODEL_IS_6000(model))
		err = nfp6000_reset_get(cpp, subdevice, &reset, &enable);
	else
		err = -EINVAL;

	/* Compute P0..P3 from reset/enable
	 */
	if (err >= 0)
		*state = (reset ? 0 : 2) | (enable ? 0 : 1);

	return err;
}

static int nfp6000_island_init(struct nfp_cpp *cpp, int island)
{
	/* If we have brought the island up, and we are
	 * taking the master out of reset, AND this island
	 * has an IMB, then we must program the island's IMB
	 *
	 * The ARM Island level must ALWAYS be out of reset
	 * for XPBM to work, so this is safe to assume.
	 */
	if (((1ULL << island) & imb_island_mask)) {
		int i, err;
		for (i = 0; i < 16; i++) {
			uint32_t xpb_src = 0x000a0000 + (i * 4);
			uint32_t xpb_dst = (island << 24) | xpb_src;
			uint32_t tmp;

			err = nfp_xpb_readl(cpp, xpb_src, &tmp);
			if (err < 0)
				return err;

			err = nfp_xpb_writel(cpp, xpb_dst, tmp);
			if (err < 0)
				return err;
		}

		/* If we're an NBI, initialize NbiMuXlate */
		if (island >= 8 && island < 12) {
			err =
			    nfp_xpb_writel(cpp,
					   NFP_XPB_ISLAND(island) +
					   NFP_NBIX_CSR +
					   NFP_NBIX_CSR_NbiMuXlate,
					   NFP_NBIX_CSR_NbiMuXlate_AccMode(7) |
					   NFP_NBIX_CSR_NbiMuXlate_Island1(24) |
					   NFP_NBIX_CSR_NbiMuXlate_Island0(0));
			if (err < 0)
				return err;
		}

		/* Set up island's CTMs for packet operation
		 * (all CTM islands have IMBs)
		 */
		err =
		    nfp_xpb_writel(cpp,
				   NFP_XPB_OVERLAY(island) + NFP_CTMX_CFG +
				   0x800,
				   (0xff000000 >> ((island & 1) * 8)) | 0xfc00 |
				   (island << 2));
		if (err < 0)
			return err;
	}

	return 0;
}

int nfp_power_set(struct nfp_device *nfp, unsigned int subdevice, int state)
{
	struct nfp_cpp *cpp;
	uint32_t model;
	int err, curr_state;

	err = nfp_power_get(nfp, subdevice, &curr_state);
	if (err < 0)
		return err;

	cpp = nfp_device_cpp(nfp);

	model = nfp_cpp_model(cpp);

	/* Transition to final state */
	while (state != curr_state) {
		int next_state;
		int enable;
		int reset;

		/* Ensure that we transition through P2
		 * to reach P0 or P1 from P3.
		 *
		 * Translated:
		 *
		 * Ensure that we transition through RESET
		 * to reach ON or SUSPEND from OFF.
		 */
		if (state == NFP_DEVICE_STATE_P0 ||
		    state == NFP_DEVICE_STATE_P1) {
			if (curr_state > NFP_DEVICE_STATE_P2)
				next_state = NFP_DEVICE_STATE_P2;
			else
				next_state = state;
		} else {
			next_state = state;
		}

		enable = (~next_state >> 0) & 1;
		reset = (~next_state >> 1) & 1;

		if (NFP_CPP_MODEL_IS_3200(model))
			err = nfp3200_reset_set(cpp, subdevice, reset, enable);
		else if (NFP_CPP_MODEL_IS_6000(model))
			err = nfp6000_reset_set(cpp, subdevice, reset, enable);
		else
			err = -EINVAL;

		if (err < 0)
			break;

		if (NFP_CPP_MODEL_IS_6000(model)) {
			/* If transitioned from RESET to ON, load the IMB */
			if (next_state == NFP_DEVICE_STATE_P0 &&
			    curr_state == NFP_DEVICE_STATE_P2) {
				if (NFP6000_DEVICE_UNIT_of(subdevice) == 0)
					nfp6000_island_init(cpp,
							    NFP6000_DEVICE_ISLAND_of
							    (subdevice));
			}
		}

		curr_state = next_state;
	}

	return err;
}

/* vim: set shiftwidth=8 noexpandtab: */
