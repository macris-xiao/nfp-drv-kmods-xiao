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
 */

#include "nfp.h"

#include "nfp_reset.h"
#include "nfp_power.h"
#include "nfp_nbi.h"
#include "nfp_nbi_mac_eth.h"

#include "nfp6000/nfp6000.h"

/* Perform a soft reset of the NFP3200:
 *   - TODO
 */
static int nfp3200_reset_soft(struct nfp_device *nfp)
{
	/* TODO: Determine soft reset sequence for the NFP3200 */
	return 0;
}

#define NBIX_BASE					(0xa0000)
#define NFP_NBI_MACX					(NBIX_BASE + 0x300000) 
#define NFP_NBI_MACX_CSR				(NFP_NBI_MACX + 0x00000)
#define NFP_NBI_MACX_CSR_MAC_BLOCK_RST			0x00000
#define  NFP_NBI_MACX_CSR_MAC_BLOCK_RST_MAC_HY1_STAT_RST	BIT(23)
#define  NFP_NBI_MACX_CSR_MAC_BLOCK_RST_MAC_HY0_STAT_RST	BIT(22)
#define  NFP_NBI_MACX_CSR_MAC_BLOCK_RST_MAC_TX_RST_MPB		BIT(21)
#define  NFP_NBI_MACX_CSR_MAC_BLOCK_RST_MAC_RX_RST_MPB		BIT(20)
#define  NFP_NBI_MACX_CSR_MAC_BLOCK_RST_MAC_TX_RST_CORE		BIT(19)
#define  NFP_NBI_MACX_CSR_MAC_BLOCK_RST_MAC_RX_RST_CORE		BIT(18)
#define NFP_NBI_MACX_CSR_IG_BUFFER_CREDIT_POOL_COUNT	0x000000a0

#define NFP_NBI_DMAX					(NBIX_BASE + 0x000000)
#define NFP_NBI_DMAX_CSR				(NFP_NBI_DMAX + 0x00000)
#define NFP_NBI_DMAX_CSR_NBI_DMA_BPE_CFG(_x) \
					(0x00000040 + (0x4 * ((_x) & 0x1f)))

int nfp6000_island_power(struct nfp_device *nfp, int state)
{
	int err;
	int i, u;

	/* Reset NBI cores */
	for (i = 0; i < 2; i++) {
		err = nfp_power_set(nfp, NFP6000_DEVICE_NBI(i,
					NFP6000_DEVICE_NBI_CORE), state);
		if (err < 0)
			return err;
	}

	/* Reset ILA cores */
	for (i = 0; i < 2; i++) {
		for (u = NFP6000_DEVICE_ILA_MEG1; u >= 0; u--) {
			err = nfp_power_set(nfp, NFP6000_DEVICE_ILA(i, u),
						 state);
			if (err < 0)
				return err;
		}
	}

	/* Reset FPC cores */
	for (i = 0; i < 7; i++) {
		for (u = NFP6000_DEVICE_FPC_MEG5; u >= 0; u--) {
			err = nfp_power_set(nfp, NFP6000_DEVICE_FPC(i, u),
						 state);
			if (err < 0)
				return err;
		}
	}

	/* Reset IMU islands */
	for (i = 0; i < 2; i++) {
		for (u = NFP6000_DEVICE_IMU_NLU; u >= 0; u--) {
			err = nfp_power_set(nfp, NFP6000_DEVICE_IMU(i, u),
						 state);
			if (err < 0)
				return err;
		}
	}

	/* Reset CRP islands */
	for (i = 0; i < 2; i++) {
		for (u = NFP6000_DEVICE_CRP_MEG1; u >= 0; u--) {
			err = nfp_power_set(nfp, NFP6000_DEVICE_CRP(i, u),
						 state);
			if (err < 0)
				return err;
		}
	}

	/* Reset PCI islands (MEGs only!) */
	for (i = 0; i < 4; i++) {
		for (u = NFP6000_DEVICE_PCI_MEG1; u >= NFP6000_DEVICE_PCI_MEG0;
		     u--) {
			err = nfp_power_set(nfp, NFP6000_DEVICE_PCI(i, u),
						 state);
			if (err < 0)
				return err;
		}
	}

	return 0;
}

#define NFP_ME_CtxEnables		0x00000018
#define  NFP_ME_CtxEnables_InUseContexts	BIT(31)
#define  NFP_ME_CtxEnables_CtxEnables(_x)	(((_x) & 0xff) << 8)
#define  NFP_ME_CtxEnables_CSEccError		BIT(29)
#define  NFP_ME_CtxEnables_Breakpoint		BIT(27)
#define  NFP_ME_CtxEnables_RegisterParityErr	BIT(25)
#define NFP_ME_ActCtxStatus		0x00000044
#define NFP_ME_ActCtxStatus_AB0			BIT(31)

#define NFP_CT_ME(_x)			(0x00010000 + (((_x + 4) & 0xf) << 10))

static int nfp6000_stop_me(struct nfp_device *nfp, int island, int menum)
{
	int err;
	struct nfp_cpp *cpp = nfp_device_cpp(nfp);
	uint32_t tmp;
	uint32_t me_r = NFP_CPP_ID(NFP_CPP_TARGET_CT_XPB, 2, 1);
	uint32_t me_w = NFP_CPP_ID(NFP_CPP_TARGET_CT_XPB, 3, 1);
	uint64_t mecsr = (island << 24) | NFP_CT_ME(menum);

	err = nfp_cpp_readl(cpp, me_r, mecsr + NFP_ME_CtxEnables, &tmp);
	if (err < 0)
		return err;

	tmp &= ~(NFP_ME_CtxEnables_InUseContexts |
		 NFP_ME_CtxEnables_CtxEnables(0xff));
	tmp &= ~NFP_ME_CtxEnables_CSEccError;
	tmp &= ~NFP_ME_CtxEnables_Breakpoint;
	tmp &= ~NFP_ME_CtxEnables_RegisterParityErr;

	err = nfp_cpp_writel(cpp, me_w, mecsr + NFP_ME_CtxEnables, tmp);
	if (err < 0)
		return err;

	udelay(1);

	/* This may seem like a rushed test, but in the 1 microsecond sleep
	 * the ME has executed about a 1000 instructions and even more during
	 * the time it took the host to execute this code and for the CPP
	 * command to reach the CSR in the test read anyway.
	 *
	 * If one of those instructions did not swap out, the code is a very
	 * inefficient single-threaded sequence of instructions which would
	 * be very rare or very specific.
	*/

	err = nfp_cpp_readl(cpp, me_r, mecsr + NFP_ME_ActCtxStatus, &tmp);
	if (err < 0)
		return err;

	if (tmp & NFP_ME_ActCtxStatus_AB0)
		return -EIO;

	return 0;
}

static int nfp6000_stop_me_island(struct nfp_device *nfp, int island)
{
	int i, err;
	int meg_device, megs;

	switch (island) {
	case 1:
		/* ARM MEs are not touched */
		return 0;
	case 4:
	case 5:
	case 6:
	case 7:
		meg_device = NFP6000_DEVICE_PCI_MEG0;
		megs = 2;
		break;
	case 12:
	case 13:
		meg_device = NFP6000_DEVICE_CRP_MEG0;
		megs = 2;
		break;
	case 32:
	case 33:
	case 34:
	case 35:
	case 36:
	case 37:
	case 38:
		meg_device = NFP6000_DEVICE_FPC_MEG0;
		megs = 6;
		break;
	case 48:
	case 49:
		meg_device = NFP6000_DEVICE_ILA_MEG0;
		megs = 2;
		break;
	default:
		return 0;
	}

	for (i = 0; i < megs; i++) {
		int state;

		err = nfp_power_get(nfp, NFP6000_DEVICE(island, 
						meg_device + i), &state);
		if (err < 0)
			return err;

		if (state != NFP_DEVICE_STATE_ON)
			continue;

		err = nfp6000_stop_me(nfp, island, i*2 + 0);
		if (err < 0)
			return err;

		err = nfp6000_stop_me(nfp, island, i*2 + 1);
		if (err < 0)
			return err;
	}

	return 0;
}

/* Perform a soft reset of the NFP6000:
 *   - Disable traffic ingress
 *   - Verify all NBI MAC packet buffers have returned
 *   - Wait for PCIE DMA Queues to empty
 *   - Stop all MEs
 *   - Clear all PCIe DMA Queues
 *   - Reset MAC NBI gaskets
 *   - Verify that all NBI/MAC buffers/credits have returned
 *   - Soft reset subcomponents relevant to this model
 *     - TODO: Crypto reset
 */
static int nfp6000_reset_soft(struct nfp_device *nfp)
{
	struct nfp_cpp *cpp = nfp_device_cpp(nfp);
	struct nfp_nbi_dev *nbi[2];
	int i, p, err;

	for (i = 0; i < 2; i++)
		nbi[i] = nfp_nbi_open(nfp, i);

	/* Disable traffic ingress */
	for (i = 0; i < 2; i++) {
		if (!nbi[i])
			continue;
		for (p = 0; p < 24; p++) {
			err = nfp_nbi_mac_eth_write_cmdconfig(nbi[i],
					p / 12, p % 12, (1 << 1), 0);
			if (err < 0)
				return err;
		}
	}

	/* Verify all NBI MAC packet buffers have returned */
	for (i = 0; i < 2; i++) {
		uint32_t tmp;
		struct timespec ts, timeout = {
			.tv_sec = 0,
			.tv_nsec = 500 * 1000 * 1000,
		};

		if (!nbi[i])
			continue;

		ts = CURRENT_TIME;
		timeout = timespec_add(ts, timeout);

		do {
			err = nfp_nbi_mac_regr(nbi[i], NFP_NBI_MACX_CSR,
				NFP_NBI_MACX_CSR_IG_BUFFER_CREDIT_POOL_COUNT,
				&tmp);

			if (err < 0)
				return err;

			ts = CURRENT_TIME;
			if (timespec_compare(&ts, &timeout) >= 0) {
				pr_info("%s:%d 0x%08x\n", __func__, __LINE__, tmp);
				return -ETIMEDOUT;
			}

		} while (tmp != 0);
	}

	/* Wait for PCIE DMA Queues to empty */
	for (i = 0; i < 4; i++) {
		uint32_t tmp;
		const uint32_t pci = NFP_CPP_ISLAND_ID(
						NFP_CPP_TARGET_PCIE, 2, 0, i+4);
		int state, ok;
		unsigned int subdev = NFP6000_DEVICE_PCI(i,
					NFP6000_DEVICE_PCI_CORE);
		struct timespec ts, timeout = {
			.tv_sec = 0,
			.tv_nsec = 500 * 1000 * 1000,
		};

		err = nfp_power_get(nfp, subdev, &state);
		if (err < 0)
			return err;

		if (state != NFP_DEVICE_STATE_ON)
			continue;

		ts = CURRENT_TIME;
		timeout = timespec_add(ts, timeout);

		do {
			err = nfp_cpp_readl(cpp, pci, 0x400e4, &tmp);
			if (err < 0)
				return err;

			ok = (tmp & 0xff00ff00) == 0x40004000;
			if (ok) {
				err = nfp_cpp_readl(cpp, pci, 0x400e0, &tmp);
				if (err < 0)
					return err;

				ok = (tmp & 0xff000000) == 0x80000000;
			}

			if (!ok) {
				ts = CURRENT_TIME;
				if (timespec_compare(&ts, &timeout) >= 0) {
					pr_info("%s:%d 0x%08x\n", __func__, __LINE__, tmp);
					return -ETIMEDOUT;
				}
			}

		} while (!ok);
	}

	/* Stop all MEs */
	for (i = 0; i < 64; i++) {
		err = nfp6000_stop_me_island(nfp, i);
		if (err < 0) {
			pr_info("%s:%d %d\n", __func__, __LINE__, i);
			return err;
		}
	}

	/* Clear all PCIe DMA Queues */
	for (i = 0; i < 4; i++) {
		const uint32_t pci = NFP_CPP_ISLAND_ID(
						NFP_CPP_TARGET_PCIE, 3, 0, i+4);

		for (p = 0; p < 256; p++) {
			uint32_t q = 0x80000 | (p << 11);

			err = nfp_cpp_writel(cpp, pci, q + 0x8, 0x80000000);
			if (err < 0)
				return err;

			err = nfp_cpp_writel(cpp, pci, q + 0xc, 0x04000000);
			if (err < 0)
				return err;
		}
	}

	/* Reset MAC NBI gaskets */
	for (i = 0; i < 2; i++) {
		uint32_t mask = NFP_NBI_MACX_CSR_MAC_BLOCK_RST_MAC_TX_RST_MPB |
				NFP_NBI_MACX_CSR_MAC_BLOCK_RST_MAC_RX_RST_MPB |
				NFP_NBI_MACX_CSR_MAC_BLOCK_RST_MAC_TX_RST_CORE |
				NFP_NBI_MACX_CSR_MAC_BLOCK_RST_MAC_RX_RST_CORE |
				NFP_NBI_MACX_CSR_MAC_BLOCK_RST_MAC_HY0_STAT_RST |
				NFP_NBI_MACX_CSR_MAC_BLOCK_RST_MAC_HY1_STAT_RST;
		err = nfp_nbi_mac_regw(nbi[i], NFP_NBI_MACX_CSR,
				NFP_NBI_MACX_CSR_MAC_BLOCK_RST, mask, mask);
		if (err < 0)
			return err;
		err = nfp_nbi_mac_regw(nbi[i], NFP_NBI_MACX_CSR,
				NFP_NBI_MACX_CSR_MAC_BLOCK_RST, mask, 0);
		if (err < 0)
			return err;
	}

	/* Verify all NBI MAC packet buffers have returned */
	for (i = 0; i < 2; i++) {
		uint32_t tmp;
		struct timespec ts, timeout = {
			.tv_sec = 0,
			.tv_nsec = 500 * 1000 * 1000,
		};

		if (!nbi[i])
			continue;

		ts = CURRENT_TIME;
		timeout = timespec_add(ts, timeout);

		do {
			err = nfp_nbi_mac_regr(nbi[i], NFP_NBI_MACX_CSR,
				NFP_NBI_MACX_CSR_IG_BUFFER_CREDIT_POOL_COUNT,
				&tmp);

			if (err < 0)
				return err;

			ts = CURRENT_TIME;
			if (timespec_compare(&ts, &timeout) >= 0) {
				pr_info("%s:%d 0x%08x\n", __func__, __LINE__, tmp);
				return -ETIMEDOUT;
			}

		} while (tmp != 0);
	}

	/* Verify that all NBI/MAC credits have returned */
	for (i = 0; i < 2; i++) {
		int ok;
		uint32_t tmp;
		struct timespec ts, timeout = {
			.tv_sec = 0,
			.tv_nsec = 500 * 1000 * 1000,
		};

		if (!nbi[i])
			continue;

		ts = CURRENT_TIME;
		timeout = timespec_add(ts, timeout);

		do {
			ok = 1;

			for (p = 0; p < 32; p++) {
				err = nfp_nbi_mac_regr(nbi[i], NFP_NBI_DMAX_CSR,
					NFP_NBI_DMAX_CSR_NBI_DMA_BPE_CFG(p),
					&tmp);

				if (err < 0)
					return err;

				ok &= (tmp == 0) ? 1 : 0;
			}

			if (!ok) {
				ts = CURRENT_TIME;
				if (timespec_compare(&ts, &timeout) >= 0) {
					pr_info("%s:%d 0x%08x\n", __func__, __LINE__, tmp);
					return -ETIMEDOUT;
				}
			}

		} while (!ok);
	}

	for (i = 0; i < 2; i++) {
		if (nbi[i])
			nfp_nbi_close(nbi[i]);
	}

	/* Soft reset subcomponents relevant to this model */
	err = nfp6000_island_power(nfp, NFP_DEVICE_STATE_RESET);
	if (err < 0)
		return err;

	err = nfp6000_island_power(nfp, NFP_DEVICE_STATE_ON);
	if (err < 0)
		return err;

	return 0;
}

/* Perform a soft reset of the NFP:
 */
int nfp_reset_soft(struct nfp_device *nfp)
{
	struct nfp_cpp *cpp = nfp_device_cpp(nfp);
	uint32_t model;
	int err;

	model = nfp_cpp_model(cpp);

	if (NFP_CPP_MODEL_IS_3200(model))
		err = nfp3200_reset_soft(nfp);
	else if (NFP_CPP_MODEL_IS_6000(model))
		err = nfp6000_reset_soft(nfp);
	else
		err = -EINVAL;

	return err;
}

/* vim: set shiftwidth=8 noexpandtab: */
