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

#define NFP_SUBSYS	"nfp_reset: "

#include "nfp.h"
#include "nfp_device.h"

#include "nfp_resource.h"
#include "nfp_reset.h"
#include "nfp_power.h"
#include "nfp_nbi.h"
#include "nfp_nbi_mac_eth.h"
#include "nfp_rtsym.h"

#include "nfp6000/nfp6000.h"
#include "nfp6000/nfp_xpb.h"

#ifndef NFP_APP_PACKET_CREDITS
#define NFP_APP_PACKET_CREDITS	128
#endif

#ifndef NFP_APP_BUFFER_CREDITS
#define NFP_APP_BUFFER_CREDITS	63
#endif

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
#define NFP_NBI_MACX_CSR_EG_BUFFER_CREDIT_POOL_COUNT	0x00000098
#define   NFP_NBI_MACX_CSR_EG_BUFFER_CREDIT_POOL_COUNT_EG_BUFFER_CREDIT_COUNT1_of(_x) (((_x) >> 16) & 0x3fff)
#define   NFP_NBI_MACX_CSR_EG_BUFFER_CREDIT_POOL_COUNT_EG_BUFFER_CREDIT_COUNT_of(_x) (((_x) >> 0) & 0x3fff)
#define NFP_NBI_MACX_CSR_IG_BUFFER_CREDIT_POOL_COUNT	0x000000a0
#define   NFP_NBI_MACX_CSR_IG_BUFFER_CREDIT_POOL_COUNT_IG_BUFFER_CREDIT_COUNT1_of(_x) (((_x) >> 16) & 0x3fff)
#define   NFP_NBI_MACX_CSR_IG_BUFFER_CREDIT_POOL_COUNT_IG_BUFFER_CREDIT_COUNT_of(_x) (((_x) >> 0) & 0x3fff)
#define NFP_NBI_MACX_ETH(_x)                                 (NFP_NBI_MACX + 0x40000 + ((_x) & 0x1) * 0x20000)
#define NFP_NBI_MACX_ETH_MACETHSEG_ETH_CMD_CONFIG(_x)	\
						(0x00000008 + (0x400 * ((_x) & 0xf)))
#define  NFP_NBI_MACX_ETH_MACETHSEG_ETH_CMD_CONFIG_ETH_RX_ENA	BIT(1)
#define NFP_NBI_MACX_CSR_MAC_SYS_SUPPORT_CTRL			0x00000014
#define  NFP_NBI_MACX_CSR_MAC_SYS_SUPPORT_CTRL_SPLIT_MEM_IG	BIT(8)


#define NFP_NBI_DMAX					(NBIX_BASE + 0x000000)
#define NFP_NBI_DMAX_CSR				(NFP_NBI_DMAX + 0x00000)
#define NFP_NBI_DMAX_CSR_NBI_DMA_BPE_CFG(_x) \
					(0x00000040 + (0x4 * ((_x) & 0x1f)))
#define   NFP_NBI_DMAX_CSR_NBI_DMA_BPE_CFG_CTM_of(_x)	(((_x) >> 21) & 0x3f)
#define   NFP_NBI_DMAX_CSR_NBI_DMA_BPE_CFG_PKT_CREDIT_of(_x) (((_x) >> 10) & 0x7ff)
#define   NFP_NBI_DMAX_CSR_NBI_DMA_BPE_CFG_BUF_CREDIT_of(_x) (((_x) >> 0) & 0x3ff)


#define CTMX_BASE                                            (0x60000)
#define NFP_CTMX_CFG                                         (CTMX_BASE + 0x000000)
#define NFP_CTMX_PKT                                         (CTMX_BASE + 0x010000)
#define NFP_CTMX_PKT_MU_PE_ACTIVE_PACKET_COUNT               0x00000400
#define   NFP_CTMX_PKT_MUPESTATS_MU_PE_STAT_of(_x)           (((_x) >> 0) & 0x3ff)

#define NFP_PCIE_DMA						(0x040000)
#define NFP_PCIE_DMA_QSTS0_TOPCI				0x000000e0
#define   NFP_PCIE_DMA_DMAQUEUESTATUS0_DMA_LO_AVAIL_of(_x)   (((_x) >> 24) & 0xff)
#define NFP_PCIE_DMA_QSTS1_TOPCI                             0x000000e4
#define   NFP_PCIE_DMA_DMAQUEUESTATUS1_DMA_HI_AVAIL_of(_x)   (((_x) >> 24) & 0xff)
#define   NFP_PCIE_DMA_DMAQUEUESTATUS1_DMA_MED_AVAIL_of(_x)  (((_x) >> 8) & 0xff)

#define NFP_PCIE_Q(_x)				(0x080000 + ((_x) & 0xff) * 0x10)
#define NFP_QCTLR_STS_LO                                     0x00000008
#define   NFP_QCTLR_STS_LO_RPTR_ENABLE				BIT(31)
#define NFP_QCTLR_STS_HI                                     0x0000000c
#define   NFP_QCTLR_STS_HI_EMPTY				BIT(26)



int nfp6000_island_power(struct nfp_device *nfp, int nbi_mask, int state)
{
	int err;
	int i, u;

	/* Reset NBI cores */
	for (i = 0; i < 2; i++) {
		if ((nbi_mask & BIT(i)) == 0)
			continue;

		err = nfp_power_set(nfp, NFP6000_DEVICE_NBI(i,
					NFP6000_DEVICE_NBI_CORE), state);
		if (err < 0) {
			if (err == -ENODEV)
				continue;
			return err;
		}
	}

	/* Reset ILA cores */
	for (i = 0; i < 2; i++) {
		for (u = NFP6000_DEVICE_ILA_MEG1; u >= 0; u--) {
			err = nfp_power_set(nfp, NFP6000_DEVICE_ILA(i, u),
						 state);
			if (err < 0) {
				if (err == -ENODEV)
					break;
				return err;
			}
		}
	}

	/* Reset FPC cores */
	for (i = 0; i < 7; i++) {
		for (u = NFP6000_DEVICE_FPC_MEG5; u >= 0; u--) {
			err = nfp_power_set(nfp, NFP6000_DEVICE_FPC(i, u),
						 state);
			if (err < 0) {
				if (err == -ENODEV)
					break;
				return err;
			}
		}
	}

	/* Reset IMU islands */
	for (i = 0; i < 2; i++) {
		for (u = NFP6000_DEVICE_IMU_NLU; u >= 0; u--) {
			err = nfp_power_set(nfp, NFP6000_DEVICE_IMU(i, u),
						 state);
			if (err < 0) {
				if (err == -ENODEV)
					break;
				return err;
			}
		}
	}

	/* Reset CRP islands */
	for (i = 0; i < 2; i++) {
		for (u = NFP6000_DEVICE_CRP_MEG1; u >= 0; u--) {
			err = nfp_power_set(nfp, NFP6000_DEVICE_CRP(i, u),
						 state);
			if (err < 0) {
				if (err == -ENODEV)
					break;
				return err;
			}
		}
	}

	/* Reset PCI islands (MEGs only!) */
	for (i = 0; i < 4; i++) {
		for (u = NFP6000_DEVICE_PCI_MEG1; u >= NFP6000_DEVICE_PCI_MEG0;
		     u--) {
			err = nfp_power_set(nfp, NFP6000_DEVICE_PCI(i, u),
						 state);
			if (err < 0) {
				if (err == -ENODEV)
					break;
				return err;
			}
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

	mdelay(1);

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

	if (tmp & NFP_ME_ActCtxStatus_AB0) {
		nfp_err(nfp, "ME%d.%d did not stop after 1000us\n", island, menum);
		return -EIO;
	}

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
		if (err < 0) {
			if (err == -ENODEV)
				continue;
			return err;
		}

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

static int nfp6000_nbi_mac_check_freebufs(struct nfp_device *nfp,
					  struct nfp_nbi_dev *nbi)
{
	uint32_t tmp;
	int err, ok, split;
	const int timeout_ms = 500;
	struct timespec ts, timeout = {
		.tv_sec = 0,
		.tv_nsec = timeout_ms * 1000 * 1000,
	};
	const int igsplit = 1007;
	const int egsplit = 495;

	err = nfp_nbi_mac_regr(nbi, NFP_NBI_MACX_CSR,
			NFP_NBI_MACX_CSR_MAC_SYS_SUPPORT_CTRL, &tmp);
	if (err < 0)
		return err;

	split = tmp & NFP_NBI_MACX_CSR_MAC_SYS_SUPPORT_CTRL_SPLIT_MEM_IG;

	ts = CURRENT_TIME;
	timeout = timespec_add(ts, timeout);

	ok = 1;
	do {
		int igcount, igcount1, egcount, egcount1;

		err = nfp_nbi_mac_regr(nbi, NFP_NBI_MACX_CSR,
			NFP_NBI_MACX_CSR_IG_BUFFER_CREDIT_POOL_COUNT,
			&tmp);
		if (err < 0)
			return err;

		igcount = NFP_NBI_MACX_CSR_IG_BUFFER_CREDIT_POOL_COUNT_IG_BUFFER_CREDIT_COUNT_of(tmp);
		igcount1 = NFP_NBI_MACX_CSR_IG_BUFFER_CREDIT_POOL_COUNT_IG_BUFFER_CREDIT_COUNT1_of(tmp);

		err = nfp_nbi_mac_regr(nbi, NFP_NBI_MACX_CSR,
			NFP_NBI_MACX_CSR_EG_BUFFER_CREDIT_POOL_COUNT,
			&tmp);
		if (err < 0)
			return err;

		egcount = NFP_NBI_MACX_CSR_EG_BUFFER_CREDIT_POOL_COUNT_EG_BUFFER_CREDIT_COUNT_of(tmp);
		egcount1 = NFP_NBI_MACX_CSR_EG_BUFFER_CREDIT_POOL_COUNT_EG_BUFFER_CREDIT_COUNT1_of(tmp);

		if (split) {
			ok &= (igcount >= igsplit);
			ok &= (egcount >= egsplit);
			ok &= (igcount1 >= igsplit);
			ok &= (egcount1 >= egsplit);
		} else {
			ok &= (igcount >= igsplit*2);
			ok &= (egcount >= egsplit*2);
		}

		if (!ok) {
			ts = CURRENT_TIME;
			if (timespec_compare(&ts, &timeout) >= 0) {
				nfp_err(nfp, "After %dms, NBI%d did not flush all packet buffers\n",
						timeout_ms, nfp_nbi_index(nbi));
				if (split) {
					nfp_err(nfp, "\t(ingress %d/%d != %d/%d, egress %d/%d != %d/%d)\n",
						igcount, igcount1,
						igsplit, igsplit,
						egcount, egcount1,
						egsplit, egsplit );
				} else {
					nfp_err(nfp, "\t(ingress %d != %d, egress %d != %d)\n",
						igcount, igsplit,
						egcount, egsplit);
				}
				return -ETIMEDOUT;
			}
		}
	} while (!ok);

	return 0;
}

static int nfp6000_nbi_check_dma_credits(struct nfp_device *nfp, struct nfp_nbi_dev *nbi, const uint32_t *bpe, int bpes )
{
	struct nfp_cpp *cpp = nfp_device_cpp(nfp);
	int err, p;
	uint32_t tmp;

	if (bpes < 1)
		return 0;

	for (p = 0; p < bpes; p++) {
		int ctm, pkt, buf, stat;
		int ctmb, pktb, bufb;

		err = nfp_nbi_mac_regr(nbi, NFP_NBI_DMAX_CSR,
			NFP_NBI_DMAX_CSR_NBI_DMA_BPE_CFG(p),
			&tmp);
		if (err < 0)
			return err;

		ctm = NFP_NBI_DMAX_CSR_NBI_DMA_BPE_CFG_CTM_of(tmp);
		if (ctm == 0)
			continue;
		ctmb = NFP_NBI_DMAX_CSR_NBI_DMA_BPE_CFG_CTM_of(bpe[p]);

		pkt = NFP_NBI_DMAX_CSR_NBI_DMA_BPE_CFG_PKT_CREDIT_of(tmp);
		pktb = NFP_NBI_DMAX_CSR_NBI_DMA_BPE_CFG_PKT_CREDIT_of(bpe[p]);

		buf = NFP_NBI_DMAX_CSR_NBI_DMA_BPE_CFG_BUF_CREDIT_of(tmp);
		bufb = NFP_NBI_DMAX_CSR_NBI_DMA_BPE_CFG_BUF_CREDIT_of(bpe[p]);

		if (ctm != ctmb) {
			nfp_err(nfp, "NBI%d DMA%d CTM%d, expected CTM%d\n",
					nfp_nbi_index(nbi), p, ctm, ctmb);
			return -EBUSY;
		}

		if (pkt != pktb) {
			nfp_err(nfp, "NBI%d DMA%d CTM%d did not drain packets (%d != %d)\n",
					nfp_nbi_index(nbi), p, ctm, pkt, pktb);
			return -EBUSY;
		}

		if (buf != bufb) {
			nfp_err(nfp, "NBI%d DMA%d CTM%d did not drain buffers (%d != %d)\n",
					nfp_nbi_index(nbi), p, ctm, buf, bufb);
			return -EBUSY;
		}

		err = nfp_xpb_readl(cpp, NFP_XPB_ISLAND(ctm) + NFP_CTMX_PKT
					+ NFP_CTMX_PKT_MU_PE_ACTIVE_PACKET_COUNT,
					&tmp);
		if (err < 0)
			return err;

		stat = NFP_CTMX_PKT_MUPESTATS_MU_PE_STAT_of(tmp);
		if (stat) {
			nfp_err(nfp, "NBI%d DMA%d (CTM%d) is still active (%d packets)\n",
					nfp_nbi_index(nbi), p, ctm, stat);
			return -EBUSY;
		}

	}

	return 0;
}

#define BPECFG_MAGIC_CHECK(x)	(((x) & 0xffffff00) == 0xdada0100)
#define BPECFG_MAGIC_COUNT(x)	((x) & 0x000000ff)

static int bpe_lookup(struct nfp_device *nfp, int nbi,
			uint32_t *bpe, int bpe_max)
{
	int err, i;
	const struct nfp_rtsym *sym;
	uint32_t id, tmp;
	uint32_t __iomem *ptr;
	struct nfp_cpp_area *area;
	char buff[] = "nbi0_dma_bpe_credits";

	buff[3] += nbi;

	sym = nfp_rtsym_lookup(nfp, buff);
	if (!sym) {
		nfp_info(nfp, "%s: Symbol not present\n", buff);
		return 0;
	}

	id = NFP_CPP_ISLAND_ID(sym->target, NFP_CPP_ACTION_RW, 0, sym->domain);
	area = nfp_cpp_area_alloc_acquire(nfp_device_cpp(nfp), id, sym->addr,
						sym->size);
	if (IS_ERR_OR_NULL(area)) {
		nfp_err(nfp, "%s: Can't acquire area\n", buff);
		return area ? PTR_ERR(area) : -ENOMEM;
	}

	ptr = nfp_cpp_area_iomem(area);
	if (IS_ERR_OR_NULL(ptr)) {
		nfp_err(nfp, "%s: Can't map area\n", buff);
		err = ptr ? PTR_ERR(ptr) : -ENOMEM;
		goto exit;
	}

	tmp = readl(ptr++);
	if (!BPECFG_MAGIC_CHECK(tmp)) {
		nfp_err(nfp, "%s: Magic value (0x%08x) unrecognized\n",
				buff, tmp);
		err = -EINVAL;
		goto exit;
	}

	if (BPECFG_MAGIC_COUNT(tmp) > bpe_max) {
		nfp_err(nfp, "%s: Magic count (%d) too large (> %d)\n",
				buff, BPECFG_MAGIC_COUNT(tmp), bpe_max);
		err = -EINVAL;
		goto exit;
	}

	for (i = 0; i < bpe_max; i++) {
		bpe[i] = readl(ptr++);
	}

	err = 0;

exit:
	nfp_cpp_area_release_free(area);
	return err;
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
	int mac_enable[2];
	int i, p, err, nbi_mask = 0;
	struct nfp_resource *res;
	struct nfp_cpp_area *area;
	uint32_t bpe[2][32];
	int bpes[2];

	/* Claim the nfp.nffw resource page */
	res = nfp_resource_acquire(nfp, NFP_RESOURCE_NFP_NFFW);
	if (!res) {
		nfp_err(nfp, "Can't aquire %s resource\n", NFP_RESOURCE_NFP_NFFW);
		return -EBUSY;
	}

	for (i = 0; i < 2; i++) {
		uint32_t tmp;
		int state;

		err = nfp_power_get(nfp, NFP6000_DEVICE_NBI(i, 0), &state);
		if (err < 0) {
			if (err == -ENODEV) {
				nbi[i] = NULL;
				continue;
			}
			goto exit;
		}

		if (state != NFP_DEVICE_STATE_ON) {
			nbi[i] = NULL;
			continue;
		}

		nbi[i] = nfp_nbi_open(nfp, i);
		if (nbi[i] == NULL)
			continue;

		nbi_mask |= BIT(i);

		err = nfp_nbi_mac_regr(nbi[i], NFP_NBI_MACX_CSR,
					NFP_NBI_MACX_CSR_MAC_BLOCK_RST,
					&tmp);
		if (err < 0)
			goto exit;

		mac_enable[i] = 0;
		if (!(tmp & NFP_NBI_MACX_CSR_MAC_BLOCK_RST_MAC_HY0_STAT_RST))
			mac_enable[i] |= BIT(0);
		if (!(tmp & NFP_NBI_MACX_CSR_MAC_BLOCK_RST_MAC_HY1_STAT_RST))
			mac_enable[i] |= BIT(1);

		/* No MACs at all? Then we don't care. */
		if (mac_enable[i] == 0) {
			nfp_nbi_close(nbi[i]);
			nbi[i] = NULL;
			continue;
		}

		/* Make sure we have the BPE list */
		err = bpe_lookup(nfp, i, &bpe[i][0], ARRAY_SIZE(bpe[i]));
		if (err < 0)
			goto exit;

		bpes[i] = err;
	}

	/* Disable traffic ingress */
	for (i = 0; i < 2; i++) {
		if (!nbi[i])
			continue;

		for (p = 0; p < 24; p++) {
			uint32_t r, mask;

			mask = NFP_NBI_MACX_ETH_MACETHSEG_ETH_CMD_CONFIG_ETH_RX_ENA;
			r = NFP_NBI_MACX_ETH_MACETHSEG_ETH_CMD_CONFIG(p % 12);

			err = nfp_nbi_mac_regw(nbi[i], NFP_NBI_MACX_ETH(p / 12),
						r, mask, 0);
			if (err < 0) {
				nfp_err(nfp, "Can't disable RX traffic for port %d.%d\n",
						i, p);
				goto exit;
			}
		}
	}

	mdelay(500);

	/* Verify all NBI MAC packet buffers have returned */
	for (i = 0; i < 2; i++) {
		if (!nbi[i])
			continue;

		err = nfp6000_nbi_mac_check_freebufs(nfp, nbi[i]);
		if (err < 0)
			goto exit;
	}

	/* Wait for PCIE DMA Queues to empty */
	for (i = 0; i < 4; i++) {
		const int timeout_ms = 500;
		uint32_t tmp;
		const uint32_t pci = NFP_CPP_ISLAND_ID(
						NFP_CPP_TARGET_PCIE, 2, 0, i+4);
		int state, ok;
		const int dma_low = 128, dma_med = 64, dma_hi = 64;
		unsigned int subdev = NFP6000_DEVICE_PCI(i,
					NFP6000_DEVICE_PCI_CORE);
		struct timespec ts, timeout = {
			.tv_sec = 0,
			.tv_nsec = timeout_ms * 1000 * 1000,
		};

		err = nfp_power_get(nfp, subdev, &state);
		if (err < 0) {
			if (err == -ENODEV)
				continue;
			goto exit;
		}

		if (state != NFP_DEVICE_STATE_ON)
			continue;

		ts = CURRENT_TIME;
		timeout = timespec_add(ts, timeout);

		do {
			int hi, med, low;

			ok = 1;
			err = nfp_cpp_readl(cpp, pci, NFP_PCIE_DMA +
						NFP_PCIE_DMA_QSTS0_TOPCI, &tmp);
			if (err < 0)
				goto exit;

			low = NFP_PCIE_DMA_DMAQUEUESTATUS0_DMA_LO_AVAIL_of(tmp);

			err = nfp_cpp_readl(cpp, pci, NFP_PCIE_DMA +
						NFP_PCIE_DMA_QSTS1_TOPCI, &tmp);
			if (err < 0)
				goto exit;

			med = NFP_PCIE_DMA_DMAQUEUESTATUS1_DMA_MED_AVAIL_of(tmp);
			hi  = NFP_PCIE_DMA_DMAQUEUESTATUS1_DMA_HI_AVAIL_of(tmp);

			ok &= low == dma_low;
			ok &= med == dma_med;
			ok &= hi  == dma_hi;

			if (!ok) {
				ts = CURRENT_TIME;
				if (timespec_compare(&ts, &timeout) >= 0) {
					nfp_err(nfp, "PCI%d DMA queues did not drain in %dms (%d/%d/%d != %d/%d/%d)\n",
							i, timeout_ms,
							low, med, hi,
							dma_low, dma_med, dma_hi);
					err = -ETIMEDOUT;
					goto exit;
				}
			}

		} while (!ok);
	}

	/* Stop all MEs */
	for (i = 0; i < 64; i++) {
		err = nfp6000_stop_me_island(nfp, i);
		if (err < 0)
			goto exit;
	}

	/* Clear all PCIe DMA Queues */
	for (i = 0; i < 4; i++) {
		unsigned int subdev = NFP6000_DEVICE_PCI(i,
					NFP6000_DEVICE_PCI_CORE);
		int state;
		const uint32_t pci = NFP_CPP_ISLAND_ID(
						NFP_CPP_TARGET_PCIE, 3, 0, i+4);

		err = nfp_power_get(nfp, subdev, &state);
		if (err < 0) {
			if (err == -ENODEV)
				continue;
			goto exit;
		}

		if (state != NFP_DEVICE_STATE_ON)
			continue;

		for (p = 0; p < 256; p++) {
			uint32_t q = NFP_PCIE_Q(p);

			err = nfp_cpp_writel(cpp, pci, q + NFP_QCTLR_STS_LO,
						NFP_QCTLR_STS_LO_RPTR_ENABLE);
			if (err < 0)
				goto exit;

			err = nfp_cpp_writel(cpp, pci, q + NFP_QCTLR_STS_HI,
						NFP_QCTLR_STS_HI_EMPTY);
			if (err < 0)
				goto exit;
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

		if (!nbi[i])
			continue;

		err = nfp_nbi_mac_regw(nbi[i], NFP_NBI_MACX_CSR,
				NFP_NBI_MACX_CSR_MAC_BLOCK_RST, mask, mask);
		if (err < 0)
			goto exit;

		err = nfp_nbi_mac_regw(nbi[i], NFP_NBI_MACX_CSR,
				NFP_NBI_MACX_CSR_MAC_BLOCK_RST, mask, 0);
		if (err < 0)
			goto exit;
	}

	/* Verify all NBI MAC packet buffers have returned */
	for (i = 0; i < 2; i++) {
		if (!nbi[i])
			continue;

		err = nfp6000_nbi_mac_check_freebufs(nfp, nbi[i]);
		if (err < 0)
			goto exit;
	}

	/* Verify that all NBI/MAC credits have returned */
	for (i = 0; i < 2; i++) {
		if (!nbi[i])
			continue;

		err = nfp6000_nbi_check_dma_credits(nfp, nbi[i],
						    &bpe[i][0], bpes[i]);
		if (err < 0)
			goto exit;
	}

	/* No need for NBI access anymore.. */
	for (i = 0; i < 2; i++) {
		if (nbi[i])
			nfp_nbi_close(nbi[i]);
	}

	/* Soft reset subcomponents relevant to this model */
	err = nfp6000_island_power(nfp, nbi_mask, NFP_DEVICE_STATE_RESET);
	if (err < 0)
		goto exit;

	err = nfp6000_island_power(nfp, nbi_mask, NFP_DEVICE_STATE_ON);
	if (err < 0)
		goto exit;

	/* Clear all NFP NFFW page */
	area = nfp_cpp_area_alloc_acquire(cpp, nfp_resource_cpp_id(res),
					  nfp_resource_address(res),
					  nfp_resource_size(res));
	if (!area) {
		nfp_err(nfp, "Can't acquire area for %s resource\n",
				NFP_RESOURCE_NFP_NFFW);
		err = -ENOMEM;
		goto exit;
	}

	for (i = 0; i < nfp_resource_size(res); i += 8) {
		err = nfp_cpp_area_writeq(area, i, 0);
		if (err < 0)
			break;
	}
	nfp_cpp_area_release_free(area);

	if (err < 0) {
		nfp_err(nfp, "Can't erase area of %s resource\n",
				NFP_RESOURCE_NFP_NFFW);
		goto exit;
	}

	err = 0;

exit:
	nfp_resource_release(res);

	return err;
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
