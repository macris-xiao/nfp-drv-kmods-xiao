/* Copyright (C) 2011,2014 Netronome Systems, Inc. All rights reserved.
 *
 * This software may be redistributed under either of two provisions:
 *
 * 1. The GNU General Public License version 2 (see
 *    http://www.gnu.org/licenses/old-licenses/gpl-2.0.html or
 *    COPYING.txt file) when it is used for Linux or other
 *    compatible free software as defined by GNU at
 *    http://www.gnu.org/licenses/license-list.html.
 *
 * 2. Or under a non-free commercial license executed directly with
 *    Netronome. The direct Netronome license does not apply when the
 *    software is used as part of the Linux kernel.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
 *
 * vim:shiftwidth=8:noexpandtab
 *
 * Multiplexes the NFP BARs between NFP internal resources and
 * implements the PCIe specific interface for generic CPP bus access.
 *
 * The BARs are managed with refcounts and are allocated/acquired
 * using target, token and offset/size matching.  The generic CPP bus
 * abstraction builds upon this BAR interface.
 */

#define NFP6000_LONGNAMES 1

#include <linux/kernel.h>
#include <linux/version.h>
#include <linux/kref.h>
#include <linux/io.h>
#include <linux/delay.h>
#include <linux/interrupt.h>
#include <linux/sort.h>

#include <asm/cacheflush.h>

#include "nfp_cpp_kernel.h"
#include "nfp_cpp_imp.h"

#include "nfp6000/nfp6000.h"
#include "nfp-bsp/nfp_target.h"

#include "nfp_common.h"
#include "nfp6000_pcie.h"
#include "nfp_em_manager.h"
#include "nfp_cpplib.h"

/* Although technically we can do 256, we don't
 * want to exhaust the IRQ table on systems
 * limited to 255 virtual IRQs, when 4 NFP6000s
 * are attached.
 */
#define NFP6000_MAX_MSIX_COUNT	32

/* Add your architecture here if it cannot
 * perform atomic readq()/writeq() transactions over
 * the PCI bus.
 */
#if defined(CONFIG_X86_32) || (defined(CONFIG_PPC) && !defined(CONFIG_PPC64))
#define CONFIG_NFP_PCI32
#endif


#define NFP_PCIE_BAR_EXPLICIT_BAR0(_x, _y) \
	(0x00000080 + (0x40 * ((_x) & 0x3)) + (0x10 * ((_y) & 0x3)))
#define   NFP_PCIE_BAR_EXPLICIT_BAR0_SignalType(_x) (((_x) & 0x3) << 30)
#define   NFP_PCIE_BAR_EXPLICIT_BAR0_SignalType_of(_x) (((_x) >> 30) & 0x3)
#define   NFP_PCIE_BAR_EXPLICIT_BAR0_Token(_x) (((_x) & 0x3) << 28)
#define   NFP_PCIE_BAR_EXPLICIT_BAR0_Token_of(_x) (((_x) >> 28) & 0x3)
#define   NFP_PCIE_BAR_EXPLICIT_BAR0_Address(_x) (((_x) & 0xffffff) << 0)
#define   NFP_PCIE_BAR_EXPLICIT_BAR0_Address_of(_x) (((_x) >> 0) & 0xffffff)
#define   NFP_PCIE_BAR_EXPLICIT_BAR0_Address(_x) (((_x) & 0xffffff) << 0)
#define   NFP_PCIE_BAR_EXPLICIT_BAR0_Address_of(_x) (((_x) >> 0) & 0xffffff)
#define   NFP_PCIE_BAR_EXPLICIT_BAR0_SignalType(_x) (((_x) & 0x3) << 30)
#define   NFP_PCIE_BAR_EXPLICIT_BAR0_SignalType_of(_x) (((_x) >> 30) & 0x3)
#define   NFP_PCIE_BAR_EXPLICIT_BAR0_Token(_x) (((_x) & 0x3) << 28)
#define   NFP_PCIE_BAR_EXPLICIT_BAR0_Token_of(_x) (((_x) >> 28) & 0x3)
#define NFP_PCIE_BAR_EXPLICIT_BAR1(_x, _y) \
	(0x00000084 + (0x40 * ((_x) & 0x3)) + (0x10 * ((_y) & 0x3)))
#define   NFP_PCIE_BAR_EXPLICIT_BAR1_SignalRef(_x) (((_x) & 0x7f) << 24)
#define   NFP_PCIE_BAR_EXPLICIT_BAR1_SignalRef_of(_x) (((_x) >> 24) & 0x7f)
#define   NFP_PCIE_BAR_EXPLICIT_BAR1_DataMaster(_x) (((_x) & 0x3ff) << 14)
#define   NFP_PCIE_BAR_EXPLICIT_BAR1_DataMaster_of(_x) (((_x) >> 14) & 0x3ff)
#define   NFP_PCIE_BAR_EXPLICIT_BAR1_DataRef(_x) (((_x) & 0x3fff) << 0)
#define   NFP_PCIE_BAR_EXPLICIT_BAR1_DataRef_of(_x) (((_x) >> 0) & 0x3fff)
#define   NFP_PCIE_BAR_EXPLICIT_BAR1_DataMaster(_x) (((_x) & 0x3ff) << 14)
#define   NFP_PCIE_BAR_EXPLICIT_BAR1_DataMaster_of(_x) (((_x) >> 14) & 0x3ff)
#define   NFP_PCIE_BAR_EXPLICIT_BAR1_DataRef(_x) (((_x) & 0x3fff) << 0)
#define   NFP_PCIE_BAR_EXPLICIT_BAR1_DataRef_of(_x) (((_x) >> 0) & 0x3fff)
#define   NFP_PCIE_BAR_EXPLICIT_BAR1_SignalRef(_x) (((_x) & 0x7f) << 24)
#define   NFP_PCIE_BAR_EXPLICIT_BAR1_SignalRef_of(_x) (((_x) >> 24) & 0x7f)
#define NFP_PCIE_BAR_EXPLICIT_BAR2(_x, _y) \
	(0x00000088 + (0x40 * ((_x) & 0x3)) + (0x10 * ((_y) & 0x3)))
#define   NFP_PCIE_BAR_EXPLICIT_BAR2_Target(_x) (((_x) & 0xf) << 28)
#define   NFP_PCIE_BAR_EXPLICIT_BAR2_Target_of(_x) (((_x) >> 28) & 0xf)
#define   NFP_PCIE_BAR_EXPLICIT_BAR2_Action(_x) (((_x) & 0x1f) << 23)
#define   NFP_PCIE_BAR_EXPLICIT_BAR2_Action_of(_x) (((_x) >> 23) & 0x1f)
#define   NFP_PCIE_BAR_EXPLICIT_BAR2_Length(_x) (((_x) & 0x1f) << 18)
#define   NFP_PCIE_BAR_EXPLICIT_BAR2_Length_of(_x) (((_x) >> 18) & 0x1f)
#define   NFP_PCIE_BAR_EXPLICIT_BAR2_ByteMask(_x) (((_x) & 0xff) << 10)
#define   NFP_PCIE_BAR_EXPLICIT_BAR2_ByteMask_of(_x) (((_x) >> 10) & 0xff)
#define   NFP_PCIE_BAR_EXPLICIT_BAR2_SignalMaster(_x) (((_x) & 0x3ff) << 0)
#define   NFP_PCIE_BAR_EXPLICIT_BAR2_SignalMaster_of(_x) (((_x) >> 0) & 0x3ff)
#define   NFP_PCIE_BAR_EXPLICIT_BAR2_Action(_x) (((_x) & 0x1f) << 23)
#define   NFP_PCIE_BAR_EXPLICIT_BAR2_Action_of(_x) (((_x) >> 23) & 0x1f)
#define   NFP_PCIE_BAR_EXPLICIT_BAR2_ByteMask(_x) (((_x) & 0xff) << 10)
#define   NFP_PCIE_BAR_EXPLICIT_BAR2_ByteMask_of(_x) (((_x) >> 10) & 0xff)
#define   NFP_PCIE_BAR_EXPLICIT_BAR2_Length(_x) (((_x) & 0x1f) << 18)
#define   NFP_PCIE_BAR_EXPLICIT_BAR2_Length_of(_x) (((_x) >> 18) & 0x1f)
#define   NFP_PCIE_BAR_EXPLICIT_BAR2_SignalMaster(_x) (((_x) & 0x3ff) << 0)
#define   NFP_PCIE_BAR_EXPLICIT_BAR2_SignalMaster_of(_x) (((_x) >> 0) & 0x3ff)
#define   NFP_PCIE_BAR_EXPLICIT_BAR2_Target(_x) (((_x) & 0xf) << 28)
#define   NFP_PCIE_BAR_EXPLICIT_BAR2_Target_of(_x) (((_x) >> 28) & 0xf)

#define   NFP_PCIE_BAR_PCIE2CPP_Action_BaseAddress(_x) (((_x) & 0x1f) << 16)
#define   NFP_PCIE_BAR_PCIE2CPP_Action_BaseAddress_of(_x) (((_x) >> 16) & 0x1f)
#define   NFP_PCIE_BAR_PCIE2CPP_BaseAddress(_x) (((_x) & 0xffff) << 0)
#define   NFP_PCIE_BAR_PCIE2CPP_BaseAddress_of(_x) (((_x) >> 0) & 0xffff)
#define   NFP_PCIE_BAR_PCIE2CPP_LengthSelect(_x) (((_x) & 0x3) << 27)
#define   NFP_PCIE_BAR_PCIE2CPP_LengthSelect_of(_x) (((_x) >> 27) & 0x3)
#define     NFP_PCIE_BAR_PCIE2CPP_LengthSelect_32BIT (0)
#define     NFP_PCIE_BAR_PCIE2CPP_LengthSelect_64BIT (1)
#define     NFP_PCIE_BAR_PCIE2CPP_LengthSelect_0BYTE (3)
#define   NFP_PCIE_BAR_PCIE2CPP_MapType(_x)     (((_x) & 0x7) << 29)
#define   NFP_PCIE_BAR_PCIE2CPP_MapType_of(_x)  (((_x) >> 29) & 0x7)
#define     NFP_PCIE_BAR_PCIE2CPP_MapType_FIXED (0)
#define     NFP_PCIE_BAR_PCIE2CPP_MapType_BULK  (1)
#define     NFP_PCIE_BAR_PCIE2CPP_MapType_TARGET (2)
#define     NFP_PCIE_BAR_PCIE2CPP_MapType_GENERAL (3)
#define     NFP_PCIE_BAR_PCIE2CPP_MapType_EXPLICIT0 (4)
#define     NFP_PCIE_BAR_PCIE2CPP_MapType_EXPLICIT1 (5)
#define     NFP_PCIE_BAR_PCIE2CPP_MapType_EXPLICIT2 (6)
#define     NFP_PCIE_BAR_PCIE2CPP_MapType_EXPLICIT3 (7)
#define   NFP_PCIE_BAR_PCIE2CPP_Target_BaseAddress(_x) (((_x) & 0xf) << 23)
#define   NFP_PCIE_BAR_PCIE2CPP_Target_BaseAddress_of(_x) (((_x) >> 23) & 0xf)
#define   NFP_PCIE_BAR_PCIE2CPP_Token_BaseAddress(_x) (((_x) & 0x3) << 21)
#define   NFP_PCIE_BAR_PCIE2CPP_Token_BaseAddress_of(_x) (((_x) >> 21) & 0x3)
#define NFP_PCIE_EM                                           (0x020000)
#define NFP_PCIE_SRAM                                         (0x000000)

#define NFP_PCIE_P2C_FIXED_SIZE(bar)                (1 << (bar)->bitsize)
#define NFP_PCIE_P2C_BULK_SIZE(bar)                 (1 << (bar)->bitsize)
#define NFP_PCIE_P2C_GENERAL_TARGET_OFFSET(bar, x) \
	((x) << ((bar)->bitsize - 2))
#define NFP_PCIE_P2C_GENERAL_TOKEN_OFFSET(bar, x) \
	((x) << ((bar)->bitsize - 4))
#define NFP_PCIE_P2C_GENERAL_SIZE(bar) \
	(1 << ((bar)->bitsize - 4))

#define NFP_PCIE_CFG_BAR_PCIeToCppExpansionBAR(bar, slot) \
	(0x400 + ((bar) * 8 + (slot)) * 4)

#define NFP_PCIE_CPP_BAR_PCIeToCppExpansionBAR(bar, slot) \
	(0x30000 + ((bar) * 8 + (slot)) * 4)

char const nfp6000_pcie_driver_name[] = "nfp6000_pcie";

/* The number of explicit BARs to reserve.
 * Minimum is 0, maximum is 4.
 */
static int nfp6000_explicit_bars = 2;
module_param(nfp6000_explicit_bars, int, 0444);
MODULE_PARM_DESC(nfp6000_explicit_bars, "Number of explicit BARs (0-4)");
#define NFP_PCIE_EXPLICIT_BARS	nfp6000_explicit_bars

/* Define to enable a bit more verbose debug output. */
/* Set to 1 to enable a bit more verbose debug output. */
static int nfp6000_debug;
module_param(nfp6000_debug, int, 0644);
MODULE_PARM_DESC(nfp6000_debug, "Enable debugging for the NFP6000 PCIe");
#define NFP_PCIE_VERBOSE_DEBUG nfp6000_debug

struct nfp6000_pcie;
struct nfp6000_area_priv;

/**
 * struct nfp_bar - describes BAR configuration and usage
 * @nfp:	backlink to owner
 * @barcfg:	cached contents of BAR config CSR
 * @offset:	the BAR's base CPP offset
 * @mask:       mask for the BAR aperture (read only)
 * @bitsize:	bitsize of BAR aperture (read only)
 * @index:	index of the BAR
 * @refcnt:	number of current users
 * @iomem:	mapped IO memory
 * @resource:	iomem resource window
 */
struct nfp_bar {
	struct nfp6000_pcie *nfp;
	uint32_t barcfg;
	uint64_t base;          /* CPP address base */
	uint64_t mask;          /* Bit mask of the bar */
	uint32_t bitsize;       /* Bit size of the bar */
	int index;
	atomic_t refcnt;

	void __iomem *iomem;
	struct resource *resource;
};

#define NFP_PCI_BARS    (PCI_64BIT_BAR_COUNT*8)

struct nfp6000_pcie {
	struct pci_dev *pdev;
	struct device *dev;

	struct nfp_cpp_operations ops;

	/* PCI BAR management */
	spinlock_t bar_lock;		/* Protect the PCI2CPP BAR cache */
	struct nfp_bar bars[NFP_PCI_BARS];
	wait_queue_head_t bar_waiters;

	/* Reserved BAR access */
	struct {
		void __iomem *general;
		void __iomem *lxpb;
		void __iomem *expl[4];
	} iomem;

	/* Explicit IO access */
	struct {
		struct mutex mutex; /* Lock access to this explicit group */
		uint8_t master_id;
		uint8_t signal_ref;
		void __iomem *data;
		struct {
			void __iomem *addr;
			int bitsize;
			int free[4];
		} group[4];
	} expl;

	/* Event management */
	struct nfp_em_manager event;
};

static inline uint32_t nfp_bar_maptype(struct nfp_bar *bar)
{
	return NFP_PCIE_BAR_PCIE2CPP_MapType_of(bar->barcfg);
}

static resource_size_t nfp_bar_resource_len(struct nfp_bar *bar)
{
	return pci_resource_len(bar->nfp->pdev, (bar->index / 8) * 2) / 8;
}

static resource_size_t nfp_bar_resource_start(struct nfp_bar *bar)
{
	return pci_resource_start(bar->nfp->pdev, (bar->index / 8) * 2)
		+ nfp_bar_resource_len(bar)*(bar->index & 7);
}

#define TARGET_WIDTH_32    4
#define TARGET_WIDTH_64    8

static int compute_bar(struct nfp6000_pcie *nfp,
		       struct nfp_bar *bar,
		       uint32_t *bar_config, uint64_t *bar_base,
		       int tgt, int act, int tok,
		       uint64_t offset, size_t size, int width)
{
	uint32_t newcfg;
	int bitsize;

	if (tgt >= NFP_CPP_NUM_TARGETS)
		return -EINVAL;

	switch (width) {
	case 8:
		newcfg = NFP_PCIE_BAR_PCIE2CPP_LengthSelect(
			NFP_PCIE_BAR_PCIE2CPP_LengthSelect_64BIT);
		break;
	case 4:
		newcfg = NFP_PCIE_BAR_PCIE2CPP_LengthSelect(
			NFP_PCIE_BAR_PCIE2CPP_LengthSelect_32BIT);
		break;
	case 0:
		newcfg = NFP_PCIE_BAR_PCIE2CPP_LengthSelect(
			NFP_PCIE_BAR_PCIE2CPP_LengthSelect_0BYTE);
		break;
	default:
		return -EINVAL;
	}

	if (act != NFP_CPP_ACTION_RW && act != 0) {
		/* Fixed CPP mapping with specific action */
		uint64_t mask = ~(NFP_PCIE_P2C_FIXED_SIZE(bar)-1);

		newcfg |= NFP_PCIE_BAR_PCIE2CPP_MapType(
			  NFP_PCIE_BAR_PCIE2CPP_MapType_FIXED);
		newcfg |= NFP_PCIE_BAR_PCIE2CPP_Target_BaseAddress(
				tgt);
		newcfg |= NFP_PCIE_BAR_PCIE2CPP_Action_BaseAddress(
				act);
		newcfg |= NFP_PCIE_BAR_PCIE2CPP_Token_BaseAddress(
				tok);

		if ((offset & mask) != ((offset + size - 1) & mask)) {
			dev_dbg(nfp->dev, "BAR%d: Failed to create Fixed mapping <%#llx,%#llx>, action=%d.  BAR too small (0x%llx).\n",
				bar->index, offset, offset + size, act,
				(unsigned long long)mask);
			return -EINVAL;
		}
		offset &= mask;

		if (NFP_PCIE_VERBOSE_DEBUG) {
			dev_dbg(nfp->dev, "BAR%d: Created Fixed mapping %d:%d:%d:0x%#llx-0x%#llx>\n",
				bar->index, tgt, act, tok,
				offset, offset + mask);
		}
		bitsize = 40 - 16;
#ifdef ENABLE_GENERAL_MAPPING
	} else if (offset < NFP_PCIE_P2C_GENERAL_SIZE(bar) &&
		   (offset + size - 1) < NFP_PCIE_P2C_GENERAL_SIZE(bar)) {
		uint64_t mask = ~(NFP_PCIE_P2C_GENERAL_SIZE(bar)-1);
		/* General CPP mapping */
		newcfg |= NFP_PCIE_BAR_PCIE2CPP_MapType(
			  NFP_PCIE_BAR_PCIE2CPP_MapType_GENERAL);

		if ((offset & mask) != ((offset + size - 1) & mask)) {
			dev_dbg(nfp->dev, "BAR%d: Failed to create CPP mapping <%#llx,%#llx>.  BAR too small.\n",
				bar->index, offset, offset + size);
			return -EINVAL;
		}
		offset &= mask;

		if (NFP_PCIE_VERBOSE_DEBUG) {
			dev_dbg(nfp->dev, "BAR%d: Created General mapping -:x:-:0x%#llx-%#llx\n",
				bar->index, offset, offset + ~mask);
		}
		bitsize = 40 - 27;
#endif
	} else {
		uint64_t mask = ~(NFP_PCIE_P2C_BULK_SIZE(bar)-1);
		/* Bulk mapping */
		newcfg |= NFP_PCIE_BAR_PCIE2CPP_MapType(
			NFP_PCIE_BAR_PCIE2CPP_MapType_BULK);
		newcfg |= NFP_PCIE_BAR_PCIE2CPP_Target_BaseAddress(
				tgt);
		newcfg |= NFP_PCIE_BAR_PCIE2CPP_Token_BaseAddress(
				tok);

		if ((offset & mask) != ((offset + size - 1) & mask)) {
			dev_dbg(nfp->dev, "BAR%d: Failed to create bulk mapping <%#llx,%#llx>, target=%d, token=%d. BAR too small (%#llx) - (%#llx != %#llx).\n",
				bar->index, offset, offset + size,
				tgt, tok, mask, offset & mask,
				(offset + size - 1) & mask
				);
			return -EINVAL;
		}

		offset &= mask;

		if (NFP_PCIE_VERBOSE_DEBUG) {
			dev_dbg(nfp->dev, "BAR%d: Created bulk mapping %d:x:%d:%#llx-%#llx\n",
				bar->index, tgt, tok, offset, offset + ~mask);
		}
		bitsize = 40 - 21;
	}

	if (bar->bitsize < bitsize) {
		if (NFP_PCIE_VERBOSE_DEBUG) {
			dev_dbg(nfp->dev, "BAR%d: Too small for %d:%d:%d\n",
				bar->index, tgt, tok, act);
		}
		return -EINVAL;
	}

	newcfg |= offset >> bitsize;

	if (bar_base)
		*bar_base = offset;

	if (bar_config)
		*bar_config = newcfg;

	return 0;
}

static int nfp6000_bar_write(struct nfp6000_pcie *nfp, struct nfp_bar *bar,
			     uint32_t newcfg)
{
	int base, slot;
	int xbar;

	if (NFP_PCIE_VERBOSE_DEBUG) {
		dev_dbg(nfp->dev, "BAR%d: updated to 0x%08x\n",
			bar->index, newcfg);
	}

	base = bar->index >> 3;
	slot = bar->index & 7;

	if (nfp->iomem.general) {
		xbar = NFP_PCIE_CPP_BAR_PCIeToCppExpansionBAR(base, slot);
		writel(newcfg, nfp->iomem.general + xbar);
	} else {
		xbar = NFP_PCIE_CFG_BAR_PCIeToCppExpansionBAR(base, slot);
		pci_write_config_dword(nfp->pdev, xbar, newcfg);
	}

	bar->barcfg = newcfg;

	return 0;
}

static int reconfigure_bar(struct nfp6000_pcie *nfp, struct nfp_bar *bar,
			   int tgt, int act, int tok, uint64_t offset,
			   size_t size, int width)
{
	uint32_t newcfg;
	uint64_t newbase;
	int err;

	err = compute_bar(nfp, bar, &newcfg, &newbase,
			  tgt, act, tok, offset, size, width);
	if (err < 0)
		return err;

	bar->base = newbase;

	return nfp6000_bar_write(nfp, bar, newcfg);
}
/*
 * Check if BAR can be used with the given parameters.
 */
static int matching_bar(struct nfp_bar *bar,
			uint32_t tgt, uint32_t act, uint32_t tok,
		uint64_t offset, size_t size, int width)
{
	struct nfp6000_pcie *nfp = bar->nfp;
	uint32_t maptype;
	int bartgt, baract, bartok;
	int barwidth;

	maptype = NFP_PCIE_BAR_PCIE2CPP_MapType_of(bar->barcfg);
	bartgt = NFP_PCIE_BAR_PCIE2CPP_Target_BaseAddress_of(
			bar->barcfg);
	bartok = NFP_PCIE_BAR_PCIE2CPP_Token_BaseAddress_of(
			bar->barcfg);
	baract = NFP_PCIE_BAR_PCIE2CPP_Action_BaseAddress_of(
			bar->barcfg);

	barwidth = NFP_PCIE_BAR_PCIE2CPP_LengthSelect_of(
			bar->barcfg);
	switch (barwidth) {
	case NFP_PCIE_BAR_PCIE2CPP_LengthSelect_32BIT:
		barwidth = 4;
		break;
	case NFP_PCIE_BAR_PCIE2CPP_LengthSelect_64BIT:
		barwidth = 8;
		break;
	case NFP_PCIE_BAR_PCIE2CPP_LengthSelect_0BYTE:
		barwidth = 0;
		break;
	default:
		barwidth = -1;
		break;
	}

	if (NFP_PCIE_VERBOSE_DEBUG) {
		dev_dbg(nfp->dev, "BAR[%d] want: %d:%d:%d:0x%llx-0x%llx (%d bit)\n",
			bar->index, tgt, act, tok,
			offset,
			offset+size-1, width * 8);

		switch (maptype) {
		case NFP_PCIE_BAR_PCIE2CPP_MapType_FIXED:
			dev_dbg(nfp->dev, "BAR[%d] have: %d:%d:%d:0x%llx-0x%llx (%d bit)\n",
				bar->index,
				bartgt, baract, bartok,
				bar->base,
				(bar->base + (1 << bar->bitsize)-1),
				barwidth * 8);
			break;
		case NFP_PCIE_BAR_PCIE2CPP_MapType_BULK:
			dev_dbg(nfp->dev, "BAR[%d] have: %d:x:%d:0x%llx-0x%llx (%d bit)\n",
				bar->index,
				bartgt, bartok,
				bar->base,
				(bar->base + (1 << bar->bitsize)-1),
				barwidth * 8);
			break;
		case NFP_PCIE_BAR_PCIE2CPP_MapType_TARGET:
			dev_dbg(nfp->dev, "BAR[%d] have: %d:x:-:0x%llx-0x%llx (%d bit)\n",
				bar->index,
				bartgt,
				bar->base,
				(bar->base + (1 << bar->bitsize)-1),
				barwidth * 8);
			break;
		case NFP_PCIE_BAR_PCIE2CPP_MapType_GENERAL:
			dev_dbg(nfp->dev, "BAR[%d] have: -:x:-:0x%llx-0x%llx (%d bit)\n",
				bar->index,
				bar->base,
				(bar->base + (1 << bar->bitsize)-1),
				barwidth * 8);
			break;
		default:
			dev_dbg(nfp->dev, "BAR[%d] is Explicit Group %d\n",
				bar->index, maptype&3);
			break;
		}
	}

	switch (maptype) {
#ifdef ENABLE_GENERAL_MAPPING
	case NFP_PCIE_BAR_PCIE2CPP_MapType_GENERAL:
		if (tgt == NFP_CPP_TARGET_PCIE && (act == 3 || act == 2)) {
			tgt = 0;
			act = NFP_CPP_ACTION_RW;
		}
		bartgt = -1;
		/* FALLTHROUGH */
#endif
	case NFP_PCIE_BAR_PCIE2CPP_MapType_TARGET:
		bartok = -1;
		/* FALLTHROUGH */
	case NFP_PCIE_BAR_PCIE2CPP_MapType_BULK:
		baract = NFP_CPP_ACTION_RW;
		if (act == 0)
			act = NFP_CPP_ACTION_RW;
		/* FALLTHROUGH */
	case NFP_PCIE_BAR_PCIE2CPP_MapType_FIXED:
		break;
	default:
		/* We don't match explicit bars through the area
		 * interface
		 */
		return 0;
	}

	/* Make sure to match up the width */
	if (barwidth != width)
		return 0;

	if ((bartgt < 0 || bartgt == tgt) &&
	    (bartok < 0 || bartok == tok) &&
	    (baract == act) &&
	    bar->base <= offset &&
	    (bar->base + (1 << bar->bitsize)) >= (offset + size))
		return 1;

	/* No match */
	return 0;
}

static int _find_matching_bar(struct nfp6000_pcie *nfp,
			     uint32_t tgt, uint32_t act, uint32_t tok,
		uint64_t offset, size_t size, int width,
		int prefetchable)
{
	int n;

	for (n = 0; n < ARRAY_SIZE(nfp->bars); n++) {
		struct nfp_bar *bar = &nfp->bars[n];

		if (bar->resource->flags & IORESOURCE_PREFETCH) {
			if (!prefetchable)
				continue;
		} else {
			if (prefetchable)
				continue;
		}

		if (matching_bar(bar, tgt, act, tok, offset, size, width)) {
			if (NFP_PCIE_VERBOSE_DEBUG) {
				dev_dbg(nfp->dev, "Found matching BAR%d for <%#llx,%#llx>, target=%d, action=%d, token=%d\n",
					bar->index, offset,
					offset + size, tgt, act, tok);
			}
			return n;
		}
	}

	return -1;
}

/* If the tgt/act/tok is prefetchable, try the IORESOURCE_PREFETCH BARs first,
 */
static int find_matching_bar(struct nfp6000_pcie *nfp,
			     uint32_t tgt, uint32_t act, uint32_t tok,
			     uint64_t offset, size_t size, int width)
{
	int prefetchable;
	int err = -1;

	prefetchable = __nfp_cpp_id_is_prefetchable(NFP_CPP_ID(tgt, act, tok));
	if (prefetchable)
		err = _find_matching_bar(nfp, tgt, act, tok,
					 offset, size, width, 1);
	if (err < 0)
		err = _find_matching_bar(nfp, tgt, act, tok,
					 offset, size, width, 0);

	return err;
}

/* Return EAGAIN if no resource is available
 */
static int _find_unused_bar_noblock(struct nfp6000_pcie *nfp, int prefetchable,
				    int tgt, int act, int tok,
				    uint64_t offset, size_t size, int width)
{
	int n, invalid = 0;

	for (n = 0; n < ARRAY_SIZE(nfp->bars); n++) {
		struct nfp_bar *bar = &nfp->bars[n];
		int err;

		if (bar->bitsize == 0) {
			invalid++;
			continue;
		}

		if (prefetchable &&
		    (bar->resource->flags & IORESOURCE_PREFETCH) == 0)
			continue;

		if (atomic_read(&bar->refcnt) != 0)
			continue;

		/* Just check to see if we can make it fit... */
		err = compute_bar(nfp, bar, NULL, NULL,
				  tgt, act, tok, offset, size, width);

		if (err < 0)
			invalid++;
		else
			return n;
	}

	return (n == invalid) ? -EINVAL : -EAGAIN;
}

static int find_unused_bar_noblock(struct nfp6000_pcie *nfp,
				   int tgt, int act, int tok,
				   uint64_t offset, size_t size, int width)
{
	int prefetchable;
	int err = -EAGAIN;

	prefetchable = __nfp_cpp_id_is_prefetchable(NFP_CPP_ID(tgt, act, tok));
	if (prefetchable)
		err = _find_unused_bar_noblock(nfp, 1, tgt, act, tok,
					       offset, size, width);
	if (err < 0)
		err = _find_unused_bar_noblock(nfp, 0, tgt, act, tok,
					       offset, size, width);

	return err;
}

/* Return -EAGAIN
 */
static int find_unused_bar_and_lock(struct nfp6000_pcie *nfp,
				    int tgt, int act, int tok,
				    uint64_t offset, size_t size, int width)
{
	int n;
	unsigned long flags;

	spin_lock_irqsave(&nfp->bar_lock, flags);

	n = find_unused_bar_noblock(nfp, tgt, act, tok, offset, size, width);
	if (n < 0)
		spin_unlock_irqrestore(&nfp->bar_lock, flags);

	return n;
}

static inline void nfp_bar_get(struct nfp6000_pcie *nfp, struct nfp_bar *bar)
{
	atomic_inc(&bar->refcnt);
}

static inline void nfp_bar_put(struct nfp6000_pcie *nfp, struct nfp_bar *bar)
{
	if (atomic_dec_and_test(&bar->refcnt))
		wake_up_interruptible(&nfp->bar_waiters);
}

static int nfp_alloc_bar(struct nfp6000_pcie *nfp,
			 uint32_t tgt, uint32_t act, uint32_t tok,
		 uint64_t offset, size_t size, int width, int nonblocking)
{
	int barnum, retval;
	unsigned long irqflags;

	if (size > (1 << 24))
		return -EINVAL;

	spin_lock_irqsave(&nfp->bar_lock, irqflags);
	barnum = find_matching_bar(nfp, tgt, act, tok, offset, size, width);
	if (barnum >= 0) {
		/* Found a perfect match. */
		nfp_bar_get(nfp, &nfp->bars[barnum]);
		spin_unlock_irqrestore(&nfp->bar_lock, irqflags);
		return barnum;
	}

	barnum = find_unused_bar_noblock(nfp, tgt, act, tok,
					 offset, size, width);
	if (barnum < 0) {
		if (nonblocking)
			goto err_nobar;

		/*
		 * Wait until a BAR becomes available.  The
		 * find_unused_bar function will reclaim the bar_lock
		 * if a free BAR is found.
		 */
		spin_unlock_irqrestore(&nfp->bar_lock, irqflags);
		retval = wait_event_interruptible(
			nfp->bar_waiters,
			-EAGAIN !=
			(barnum = find_unused_bar_and_lock(nfp,
							   tgt, act, tok,
							   offset, size,
							   width)));
		if (retval)
			return retval;
	}

	nfp_bar_get(nfp, &nfp->bars[barnum]);
	retval = reconfigure_bar(nfp, &nfp->bars[barnum],
				 tgt, act, tok, offset,
				 size, width);
	if (retval < 0) {
		nfp_bar_put(nfp, &nfp->bars[barnum]);
		barnum = retval;
	}

err_nobar:
	spin_unlock_irqrestore(&nfp->bar_lock, irqflags);
	return barnum;
}

/*
 * Sysfs interface for dumping the configuration of the BARs.
 */
static ssize_t show_barcfg(struct device *dev, struct device_attribute *attr,
			   char *buf)
{
	static char *bartype[8] = {
		"Fixed", "Bulk", "Target", "General",
		"Expl0", "Expl1", "Expl2", "Expl3"
	};
	struct nfp6000_pcie *nfp = nfp_cpp_priv(dev_get_drvdata(dev));
	int n, maptype, tgtact, tgttok, length, action;
	ssize_t off = 0;
	uint64_t base;

	BUG_ON(!nfp);
	for (n = 0; n < ARRAY_SIZE(nfp->bars); n++) {
		struct nfp_bar *bar = &nfp->bars[n];
		int users = atomic_read(&bar->refcnt);

		if (users == 0 && !NFP_PCIE_VERBOSE_DEBUG)
			continue;

		maptype = NFP_PCIE_BAR_PCIE2CPP_MapType_of(
				bar->barcfg);
		tgtact = NFP_PCIE_BAR_PCIE2CPP_Target_BaseAddress_of(
				    bar->barcfg);
		tgttok = NFP_PCIE_BAR_PCIE2CPP_Token_BaseAddress_of(
				bar->barcfg);
		action = NFP_PCIE_BAR_PCIE2CPP_Action_BaseAddress_of(
				bar->barcfg);
		length = NFP_PCIE_BAR_PCIE2CPP_LengthSelect_of(
				bar->barcfg) ? 64 : 32;
		base = NFP_PCIE_BAR_PCIE2CPP_BaseAddress_of(
				bar->barcfg);

		off += scnprintf(buf + off, PAGE_SIZE - off,
				 "BAR%d(%d): %s map, ",
				 bar->index, bar->bitsize, bartype[maptype]);
		switch (maptype) {
		case NFP_PCIE_BAR_PCIE2CPP_MapType_FIXED:
			off += scnprintf(buf + off, PAGE_SIZE - off,
					 "target: %#x, token: %#x, action: %#x, ",
					 tgtact, tgttok, action);
			base <<= (40 - 16);
			break;
		case NFP_PCIE_BAR_PCIE2CPP_MapType_BULK:
			off += scnprintf(buf + off, PAGE_SIZE - off,
					 "target: %#x, token: %#x, ",
					 tgtact, tgttok);
			base |= (uint64_t)action << 16;
			base <<= (40 - 21);
			break;
		case NFP_PCIE_BAR_PCIE2CPP_MapType_TARGET:
			off += scnprintf(buf + off, PAGE_SIZE - off,
					 "target: %#x, ",
					 tgtact);
			base |= (uint64_t)tgttok << 21;
			base |= (uint64_t)action << 16;
			base <<= (40 - 23);
			break;
		case NFP_PCIE_BAR_PCIE2CPP_MapType_GENERAL:
			off += scnprintf(buf + off, PAGE_SIZE - off,
					 "action: %#x, ", tgtact);
			base |= (uint64_t)tgtact << 23;
			base |= (uint64_t)tgttok << 21;
			base |= (uint64_t)action << 16;
			base <<= (40 - 27);
			break;
		default:
			break;
		}
		off += scnprintf(buf + off, PAGE_SIZE - off,
				"%d-bit, base: %#llx, users: %d\n", length,
				 base, users);
	}

	return off;
}

static DEVICE_ATTR(barcfg, S_IRUGO, show_barcfg, NULL);

static int nfp6000_pciebars_attr_add(struct device *dev)
{
	return device_create_file(dev, &dev_attr_barcfg);
}

static void nfp6000_pciebars_attr_remove(struct device *dev)
{
	device_remove_file(dev, &dev_attr_barcfg);
}

static void disable_bars(struct nfp6000_pcie *nfp);

static inline int bar_cmp(const void *aptr, const void *bptr)
{
	const struct nfp_bar *a = aptr, *b = bptr;

	if (a->bitsize == b->bitsize)
		return a->index - b->index;
	else
		return (a->bitsize - b->bitsize);
}

/*
 * Map all PCI bars and fetch the actual BAR configurations from the
 * board.  We assume that the BAR with the PCIe config block is
 * already mapped.
 *
 * BAR0.0: Reserved for General Mapping (and PCIe Scratch)
 * BAR0.1: Reserved for XPB access to PCIe CSRs
 * BAR0.2: --
 * BAR0.3: --
 * BAR0.4: Reserved for Explicit 0.0-0.3 access
 * BAR0.5: Reserved for Explicit 1.0-1.3 access
 * BAR0.6: Reserved for Explicit 2.0-2.3 access
 * BAR0.7: Reserved for Explicit 3.0-3.3 access
 *
 * BAR1.0-BAR1.7: --
 * BAR2.0-BAR2.7: --
 */
static int enable_bars(struct nfp6000_pcie *nfp)
{
	struct nfp_bar *bar = nfp->bars;
	int i;
	const uint32_t barcfg_pcie_xpb =
		NFP_PCIE_BAR_PCIE2CPP_MapType(
			NFP_PCIE_BAR_PCIE2CPP_MapType_BULK) |
		NFP_PCIE_BAR_PCIE2CPP_LengthSelect_32BIT |
		NFP_PCIE_BAR_PCIE2CPP_Target_BaseAddress(
				NFP_CPP_TARGET_ISLAND_XPB) |
		NFP_PCIE_BAR_PCIE2CPP_Token_BaseAddress(0) |
		NFP_PCIE_BAR_PCIE2CPP_BaseAddress(0);
	const uint32_t barcfg_general =
		NFP_PCIE_BAR_PCIE2CPP_MapType(
		NFP_PCIE_BAR_PCIE2CPP_MapType_GENERAL) |
		NFP_PCIE_BAR_PCIE2CPP_LengthSelect_32BIT;
	const uint32_t barcfg_explicit[4] = {
		NFP_PCIE_BAR_PCIE2CPP_MapType(
			NFP_PCIE_BAR_PCIE2CPP_MapType_EXPLICIT0),
		NFP_PCIE_BAR_PCIE2CPP_MapType(
			NFP_PCIE_BAR_PCIE2CPP_MapType_EXPLICIT1),
		NFP_PCIE_BAR_PCIE2CPP_MapType(
			NFP_PCIE_BAR_PCIE2CPP_MapType_EXPLICIT2),
		NFP_PCIE_BAR_PCIE2CPP_MapType(
			NFP_PCIE_BAR_PCIE2CPP_MapType_EXPLICIT3),
	};

	BUG_ON(!nfp->dev);
	BUG_ON(!nfp->pdev);

	for (i = 0; i < ARRAY_SIZE(nfp->bars); i++, bar++) {
		bar->resource = &nfp->pdev->resource[(i >> 3) * 2];
		bar->barcfg = 0;

		bar->nfp = nfp;
		bar->index = i;
		bar->mask = nfp_bar_resource_len(bar) - 1;
		bar->bitsize = fls(bar->mask);
		bar->base = 0;
		bar->iomem = NULL;
	}

	/* Convert unit ID (0..3) to signal master/data master ID (0x40..0x70)
	 */
	mutex_init(&nfp->expl.mutex);

	nfp->expl.master_id = ((NFP_CPP_INTERFACE_UNIT_of(nfp->ops.interface)
				& 3) + 4) << 4;
	nfp->expl.signal_ref = 0x10;

	/* Configure, and lock, BAR0.0 for General Target use */
	bar = &nfp->bars[0];
	bar->iomem = devm_ioremap_nocache(&nfp->pdev->dev,
			nfp_bar_resource_start(bar),
			nfp_bar_resource_len(bar));
	if (bar->iomem) {
		dev_info(nfp->dev, "BAR0.0 RESERVED: General Mapping\n");
		atomic_inc(&bar->refcnt);

		nfp6000_bar_write(nfp, bar, barcfg_general);

		nfp->expl.data = bar->iomem + NFP_PCIE_SRAM + 0x1000;
	}
	nfp->iomem.general = bar->iomem;

	/* Configure, and lock, BAR0.1 for PCIe Local XPB use */
	bar = &nfp->bars[1];
	bar->iomem = devm_ioremap_nocache(&nfp->pdev->dev,
			nfp_bar_resource_start(bar),
			nfp_bar_resource_len(bar));
	if (bar->iomem) {
		dev_info(nfp->dev, "BAR0.1 RESERVED: PCIe XPB CSRs\n");
		atomic_inc(&bar->refcnt);

		nfp6000_bar_write(nfp, bar, barcfg_pcie_xpb);
	}
	nfp->iomem.lxpb = bar->iomem;

	/* Use BAR0.4..BAR0.7 for EXPL IO */
	for (i = 0; i < 4; i++) {
		int j;

		if (i >= NFP_PCIE_EXPLICIT_BARS) {
			nfp->expl.group[i].bitsize = 0;
			continue;
		}

		bar = &nfp->bars[4 + i];
		bar->iomem = devm_ioremap_nocache(&nfp->pdev->dev,
						  nfp_bar_resource_start(bar),
						  nfp_bar_resource_len(bar));
		if (bar->iomem) {
			dev_info(nfp->dev, "BAR0.%d RESERVED: Explicit%d Mapping\n",
				 4 + i, i);
			atomic_inc(&bar->refcnt);

			nfp->expl.group[i].bitsize = bar->bitsize;
			nfp->expl.group[i].addr = bar->iomem;
			nfp6000_bar_write(nfp, bar, barcfg_explicit[i]);

			for (j = 0; j < 4; j++)
				nfp->expl.group[i].free[j] = 1;
		}
		nfp->iomem.expl[i] = bar->iomem;
	}

	/* Sort bars by bit size - use the smallest possible first.
	 */
	sort(&nfp->bars[0], ARRAY_SIZE(nfp->bars), sizeof(nfp->bars[0]),
	     bar_cmp, NULL);

	return 0;
}

static void disable_bars(struct nfp6000_pcie *nfp)
{
	struct nfp_bar *bar = nfp->bars;
	int n;

	for (n = 0; n < ARRAY_SIZE(nfp->bars); n++, bar++) {
		if (bar->iomem != NULL) {
			devm_iounmap(&nfp->pdev->dev, bar->iomem);
			bar->iomem = NULL;
		}
	}
}

/*
 * Generic CPP bus access interface.
 */

struct nfp6000_area_priv {
	atomic_t refcnt;

	struct nfp_bar *bar;
	uint32_t bar_offset;

	uint32_t target;
	uint32_t action;
	uint32_t token;
	uint64_t offset;
	struct {
		int read;
		int write;
		int bar;
	} width;
	size_t size;

	void __iomem *iomem;
	phys_addr_t phys;
	struct resource resource;

	struct nfp6000_area_priv *next;
};

static int nfp6000_area_init(
	struct nfp_cpp_area *area, uint32_t dest,
	unsigned long long address, unsigned long size)
{
	struct nfp6000_area_priv *priv = nfp_cpp_area_priv(area);
	uint32_t target = NFP_CPP_ID_TARGET_of(dest);
	uint32_t action = NFP_CPP_ID_ACTION_of(dest);
	uint32_t token = NFP_CPP_ID_TOKEN_of(dest);
	int pp;

	pp = nfp6000_target_pushpull(NFP_CPP_ID(target, action, token),
				     address);
	if (pp < 0)
		return pp;

	priv->width.read = PUSH_WIDTH(pp);
	priv->width.write = PULL_WIDTH(pp);
	if (priv->width.read > 0 &&
	    priv->width.write > 0 &&
	    priv->width.read != priv->width.write) {
		return -EINVAL;
	}

	if (priv->width.read > 0)
		priv->width.bar = priv->width.read;
	else
		priv->width.bar = priv->width.write;

	atomic_set(&priv->refcnt, 0);
	priv->bar = NULL;

	priv->target = target;
	priv->action = action;
	priv->token = token;
	priv->offset = address;
	priv->size = size;
	priv->next = NULL;
	memset(&priv->resource, 0, sizeof(priv->resource));

	return 0;
}

static void nfp6000_area_cleanup(struct nfp_cpp_area *area)
{
}

static void priv_area_get(struct nfp_cpp_area *area)
{
	struct nfp6000_area_priv *priv = nfp_cpp_area_priv(area);

	atomic_inc(&priv->refcnt);
}

static int priv_area_put(struct nfp_cpp_area *area)
{
	struct nfp6000_area_priv *priv = nfp_cpp_area_priv(area);

	BUG_ON(!atomic_read(&priv->refcnt));
	return atomic_dec_and_test(&priv->refcnt);
}

static int nfp6000_area_acquire(struct nfp_cpp_area *area)
{
	struct nfp6000_area_priv *priv = nfp_cpp_area_priv(area);
	struct nfp6000_pcie *nfp = nfp_cpp_priv(nfp_cpp_area_cpp(area));
	int barnum, err;

	if (priv->bar) {
		/* Already allocated. */
		priv_area_get(area);
		BUG_ON(!priv->iomem);
		return 0;
	}

	barnum = nfp_alloc_bar(nfp, priv->target, priv->action, priv->token,
			       priv->offset, priv->size, priv->width.bar, 1);

	if (barnum < 0) {
		if (NFP_PCIE_VERBOSE_DEBUG) {
			dev_dbg(nfp->dev, "Failed to allocate bar %d:%d:%d:0x%llx: %d\n",
				priv->target, priv->action,
				priv->token, priv->offset, barnum);
		}
		err = barnum;
		goto err_alloc_bar;
	}
	priv->bar = &nfp->bars[barnum];

	/* Calculate offset into BAR. */
	if (nfp_bar_maptype(priv->bar) ==
			NFP_PCIE_BAR_PCIE2CPP_MapType_GENERAL) {
		priv->bar_offset = priv->offset &
			(NFP_PCIE_P2C_GENERAL_SIZE(priv->bar) - 1);
		priv->bar_offset += NFP_PCIE_P2C_GENERAL_TARGET_OFFSET(
				priv->bar, priv->target);
		priv->bar_offset += NFP_PCIE_P2C_GENERAL_TOKEN_OFFSET(
				priv->bar, priv->token);
	} else {
		priv->bar_offset = priv->offset & priv->bar->mask;
	}

	/*
	 * We don't actually try to acquire the resource area using
	 * request_resource.  This would prevent sharing the mapped
	 * BAR between multiple CPP areas and prevent us from
	 * effectively utilizing the limited amount of BAR resources.
	 */
	priv->phys = nfp_bar_resource_start(priv->bar) + priv->bar_offset;
	priv->resource.name = nfp_cpp_area_name(area);
	priv->resource.start = priv->phys;
	priv->resource.end = priv->resource.start + priv->size - 1;
	priv->resource.flags = IORESOURCE_MEM;

	/* If the bar is already mapped in, use its mapping */
	if (priv->bar->iomem != NULL) {
		priv->iomem = priv->bar->iomem + priv->bar_offset;
	} else {
		/* Must have been too big. Sub-allocate. */
		priv->iomem = devm_ioremap_nocache(
			&nfp->pdev->dev, priv->phys, priv->size);
	}
	if (IS_ERR_OR_NULL(priv->iomem)) {
		dev_err(nfp->dev, "Can't ioremap() a %d byte region of BAR %d\n",
			(int)priv->size, priv->bar->index);
		err = (priv->iomem == NULL) ? -ENOMEM : PTR_ERR(priv->iomem);
		priv->iomem = NULL;
		goto err_iomem_remap;
	}

	priv_area_get(area);
	return 0;

err_iomem_remap:
	nfp_bar_put(nfp, priv->bar);
	priv->bar = NULL;
err_alloc_bar:
	return err;
}

static void nfp6000_area_release(struct nfp_cpp_area *area)
{
	struct nfp6000_area_priv *priv = nfp_cpp_area_priv(area);
	struct nfp6000_pcie *nfp = nfp_cpp_priv(nfp_cpp_area_cpp(area));

	BUG_ON(!priv->bar);
	BUG_ON(!priv->iomem);

	if (priv_area_put(area)) {
		if (priv->bar->iomem == NULL)
			devm_iounmap(&nfp->pdev->dev, priv->iomem);

		nfp_bar_put(nfp, priv->bar);

		priv->bar = NULL;
		priv->iomem = NULL;
	}
}

static phys_addr_t nfp6000_area_phys(struct nfp_cpp_area *area)
{
	struct nfp6000_area_priv *priv = nfp_cpp_area_priv(area);

	return priv->phys;
}

static void __iomem *nfp6000_area_iomem(struct nfp_cpp_area *area)
{
	struct nfp6000_area_priv *priv = nfp_cpp_area_priv(area);

	return priv->iomem;
}

static struct resource *nfp6000_area_resource(struct nfp_cpp_area *area)
{
	/*
	 * Use the BAR resource as the resource for the CPP area.
	 * This enables us to share the BAR among multiple CPP areas
	 * without resource conflicts.
	 */
	struct nfp6000_area_priv *priv = nfp_cpp_area_priv(area);

	return priv->bar->resource;
}

static int nfp6000_area_read(struct nfp_cpp_area *area, void *kernel_vaddr,
			     unsigned long offset, unsigned int length)
{
	struct nfp6000_area_priv *priv = nfp_cpp_area_priv(area);
	const uint32_t __iomem *rdptr32 = priv->iomem + offset;
	const uint64_t __iomem __maybe_unused *rdptr64 = priv->iomem + offset;
	uint32_t *wrptr32 = kernel_vaddr;
	uint64_t __maybe_unused *wrptr64 = kernel_vaddr;
	int is_64;
	int n;

	if (!priv->width.read)
		return -EINVAL;

	is_64 = (priv->width.read == TARGET_WIDTH_64) ? 1 : 0;

	if ((offset + length) > priv->size)
		return -EFAULT;

	if (is_64) {
		if (((offset % sizeof(uint64_t)) != 0) ||
		    ((length % sizeof(uint64_t)) != 0))
			return -EINVAL;
	} else {
		if (((offset % sizeof(uint32_t)) != 0) ||
		    ((length % sizeof(uint32_t)) != 0))
			return -EINVAL;
	}

	BUG_ON(!priv->bar);

	if (is_64)
#ifdef CONFIG_NFP_PCI32
		return -EINVAL;
#else
		for (n = 0; n < length; n += sizeof(uint64_t))
			*wrptr64++ = __raw_readq(rdptr64++);
#endif
	else
		for (n = 0; n < length; n += sizeof(uint32_t))
			*wrptr32++ = __raw_readl(rdptr32++);

	return n;
}

static int nfp6000_area_write(struct nfp_cpp_area *area,
			      const void *kernel_vaddr,
				   unsigned long offset, unsigned int length)
{
	struct nfp6000_area_priv *priv = nfp_cpp_area_priv(area);
	const uint32_t *rdptr32 = kernel_vaddr;
	const uint64_t __maybe_unused *rdptr64 = kernel_vaddr;
	uint32_t __iomem *wrptr32 = priv->iomem + offset;
	uint64_t __iomem __maybe_unused *wrptr64 = priv->iomem + offset;
	int is_64;
	int n;

	if ((offset + length) > priv->size)
		return -EFAULT;

	if (!priv->width.write)
		return -EINVAL;

	is_64 = (priv->width.write == TARGET_WIDTH_64) ? 1 : 0;

	if (is_64) {
		if (((offset % sizeof(uint64_t)) != 0) ||
		    ((length % sizeof(uint64_t)) != 0))
			return -EINVAL;
	} else {
		if (((offset % sizeof(uint32_t)) != 0) ||
		    ((length % sizeof(uint32_t)) != 0))
			return -EINVAL;
	}
	BUG_ON(!priv->bar);

	if (is_64) {
#ifdef CONFIG_NFP_PCI32
		return -EINVAL;
#else
		for (n = 0; n < length; n += sizeof(uint64_t)) {
			__raw_writeq(*rdptr64++, wrptr64++);
			/* Flush each write */
			wmb();
		}
#endif
	} else {
		for (n = 0; n < length; n += sizeof(uint32_t)) {
			__raw_writel(*rdptr32++, wrptr32++);
			/* Flush each write */
			wmb();
		}
	}

	return n;
}

struct nfp6000_explicit_priv {
	struct nfp6000_pcie *nfp;
	struct {
		int group;
		int area;
	} bar;
	int bitsize;
	void __iomem *data;
	void __iomem *addr;
};

static int nfp6000_explicit_acquire(struct nfp_cpp_explicit *expl)
{
	struct nfp6000_pcie *nfp = nfp_cpp_priv(nfp_cpp_explicit_cpp(expl));
	struct nfp6000_explicit_priv *priv = nfp_cpp_explicit_priv(expl);
	int i, j;

	mutex_lock(&nfp->expl.mutex);
	for (i = 0; i < ARRAY_SIZE(nfp->expl.group); i++) {
		if (nfp->expl.group[i].bitsize == 0)
			continue;
		for (j = 0; j < ARRAY_SIZE(nfp->expl.group[i].free); j++) {
			if (nfp->expl.group[i].free[j]) {
				uint16_t data_offset;

				priv->nfp = nfp;
				priv->bar.group = i;
				priv->bar.area = j;
				priv->bitsize = nfp->expl.group[i].bitsize - 2;

				data_offset = (priv->bar.group << 9) +
					(priv->bar.area << 7);
				priv->data = nfp->expl.data + data_offset;
				priv->addr = nfp->expl.group[i].addr +
					(priv->bar.area << priv->bitsize);
				nfp->expl.group[i].free[j] = 0;
				mutex_unlock(&nfp->expl.mutex);
				return 0;
			}
		}
	}
	mutex_unlock(&nfp->expl.mutex);
	return -EAGAIN;
}

static void nfp6000_explicit_release(struct nfp_cpp_explicit *expl)
{
	struct nfp6000_explicit_priv *priv = nfp_cpp_explicit_priv(expl);
	struct nfp6000_pcie *nfp = priv->nfp;

	mutex_lock(&nfp->expl.mutex);
	nfp->expl.group[priv->bar.group].free[priv->bar.area] = 1;
	mutex_unlock(&nfp->expl.mutex);
}

static int nfp6000_explicit_put(struct nfp_cpp_explicit *expl,
				const void *buff, size_t len)
{
	struct nfp6000_explicit_priv *priv = nfp_cpp_explicit_priv(expl);
	const uint32_t *src = buff;
	size_t i;

	for (i = 0; i < len; i += sizeof(uint32_t))
		writel(*(src++), priv->data + i);

	return i;
}

static int nfp6000_explicit_do(struct nfp_cpp_explicit *expl,
			       const struct nfp_cpp_explicit_command *cmd,
			       uint64_t address)
{
	struct nfp6000_explicit_priv *priv = nfp_cpp_explicit_priv(expl);
	struct nfp6000_pcie *nfp = priv->nfp;
	int sigmask = 0;
	uint32_t csr[3];
	uint8_t signal_master, signal_ref, data_master;
	uint16_t data_ref;

	if (cmd->siga_mode)
		sigmask |= (1 << cmd->siga);
	if (cmd->sigb_mode)
		sigmask |= (1 << cmd->sigb);

	signal_master = cmd->signal_master;
	if (!signal_master)
		signal_master = nfp->expl.master_id;

	if (signal_master == nfp->expl.master_id) {
		signal_ref = nfp->expl.signal_ref +
			(((priv->bar.group * 4) + priv->bar.area) << 1);
	} else {
		signal_ref = cmd->signal_ref;
	}

	data_master = cmd->data_master;
	if (!data_master)
		data_master = nfp->expl.master_id;

	if (data_master == nfp->expl.master_id) {
		/* Data defaults */
		uint32_t data_offset = (priv->bar.group << 9) +
					(priv->bar.area << 7);
		data_ref = 0x1000 + data_offset;
	} else {
		data_ref = cmd->data_ref;
	}

	csr[0] = NFP_PCIE_BAR_EXPLICIT_BAR0_SignalType(
			sigmask) |
		NFP_PCIE_BAR_EXPLICIT_BAR0_Token(
				NFP_CPP_ID_TOKEN_of(cmd->cpp_id)) |
		NFP_PCIE_BAR_EXPLICIT_BAR0_Address(
				address >> 16);

	csr[1] = NFP_PCIE_BAR_EXPLICIT_BAR1_SignalRef(
				signal_ref) |
		NFP_PCIE_BAR_EXPLICIT_BAR1_DataMaster(
				data_master) |
		NFP_PCIE_BAR_EXPLICIT_BAR1_DataRef(
				data_ref);

	csr[2] = NFP_PCIE_BAR_EXPLICIT_BAR2_Target(
			NFP_CPP_ID_TARGET_of(cmd->cpp_id)) |
		NFP_PCIE_BAR_EXPLICIT_BAR2_Action(
				NFP_CPP_ID_ACTION_of(cmd->cpp_id)) |
		NFP_PCIE_BAR_EXPLICIT_BAR2_Length(
				cmd->len) |
		NFP_PCIE_BAR_EXPLICIT_BAR2_ByteMask(
				cmd->byte_mask) |
		NFP_PCIE_BAR_EXPLICIT_BAR2_SignalMaster(
				signal_master);

	if (NFP_PCIE_VERBOSE_DEBUG) {
		int i;

		for (i = 0; i < 3; i++) {
			dev_dbg(nfp->dev, "EXPL%d.%d: BAR%d = 0x%08x\n",
				priv->bar.group, priv->bar.area,
				i, csr[i]);
		}
	}

	pci_write_config_dword(nfp->pdev, 0x400 +
			NFP_PCIE_BAR_EXPLICIT_BAR0(
				priv->bar.group, priv->bar.area),
			csr[0]);

	pci_write_config_dword(nfp->pdev, 0x400 +
			NFP_PCIE_BAR_EXPLICIT_BAR1(
				priv->bar.group, priv->bar.area),
			csr[1]);

	pci_write_config_dword(nfp->pdev, 0x400 +
			NFP_PCIE_BAR_EXPLICIT_BAR2(
				priv->bar.group, priv->bar.area),
			csr[2]);

	if (NFP_PCIE_VERBOSE_DEBUG) {
		dev_dbg(nfp->dev, "EXPL%d.%d: Kickoff 0x%llx (@0x%08x)\n",
			priv->bar.group, priv->bar.area,
			address,
			(unsigned)(address & ((1 << priv->bitsize)-1)));
	}

	/* Issue the 'kickoff' transaction */
	readb(priv->addr + (address & ((1 << priv->bitsize)-1)));

	return sigmask;
}

static int nfp6000_explicit_get(struct nfp_cpp_explicit *expl,
				void *buff, size_t len)
{
	struct nfp6000_explicit_priv *priv = nfp_cpp_explicit_priv(expl);
	uint32_t *dst = buff;
	size_t i;

	for (i = 0; i < len; i += sizeof(uint32_t))
		*(dst++) = readl(priv->data + i);

	return i;
}

static int nfp6000_init(struct nfp_cpp *cpp)
{
	return nfp6000_pciebars_attr_add(nfp_cpp_device(cpp));
}

struct nfp6000_event_priv {
	int filter;
};

static int nfp6000_event_acquire(struct nfp_cpp_event *event, uint32_t match,
				 uint32_t mask, uint32_t type)
{
	struct nfp_cpp *cpp = nfp_cpp_event_cpp(event);
	struct nfp6000_pcie *nfp = nfp_cpp_priv(cpp);
	struct nfp6000_event_priv *ev = nfp_cpp_event_priv(event);
	int filter;

	filter = nfp_em_manager_acquire(&nfp->event, event, match, mask, type);
	if (filter < 0)
		return filter;

	ev->filter = filter;

	return 0;
}

static void nfp6000_event_release(struct nfp_cpp_event *event)
{
	struct nfp_cpp *cpp = nfp_cpp_event_cpp(event);
	struct nfp6000_pcie *nfp = nfp_cpp_priv(cpp);
	struct nfp6000_event_priv *ev = nfp_cpp_event_priv(event);

	nfp_em_manager_release(&nfp->event, ev->filter);
}

static void nfp6000_free(struct nfp_cpp *cpp)
{
	struct nfp6000_pcie *nfp = nfp_cpp_priv(cpp);

	BUG_ON(!nfp);

	nfp6000_pciebars_attr_remove(nfp_cpp_device(cpp));
	nfp_em_manager_exit(&nfp->event);
	disable_bars(nfp);
	kfree(nfp);
}

struct nfp_cpp *nfp_cpp_from_nfp6000_pcie(struct pci_dev *pdev, int irq)
{
	struct nfp_cpp_operations *ops;
	struct nfp6000_pcie *nfp;
	int err, pos;

	/*  Finished with card initialization. */
	dev_info(&pdev->dev,
		 "Netronome Flow Processor (NFP6000) PCIe Card Probe\n");

	nfp = kzalloc(sizeof(*nfp), GFP_KERNEL);
	if (nfp == NULL) {
		err = -ENOMEM;
		goto err_nfpmem_alloc;
	}

	nfp->dev = &pdev->dev;
	nfp->pdev = pdev;
	init_waitqueue_head(&nfp->bar_waiters);
	spin_lock_init(&nfp->bar_lock);
	ops = &nfp->ops;
	ops->parent = &pdev->dev;
	ops->priv = nfp;

	spin_lock_init(&nfp->event.lock);

	pos = pci_find_ext_capability(pdev, PCI_EXT_CAP_ID_DSN);
	if (pos) {
		uint32_t serial[2];

		pci_read_config_dword(pdev, pos + 4, &serial[0]);
		pci_read_config_dword(pdev, pos + 8, &serial[1]);

		dev_info(&pdev->dev, "Serial Number: %02x-%02x-%02x-%02x-%02x-%02x\n",
			 (serial[1] >> 24) & 0xff,
			 (serial[1] >> 16) & 0xff,
			 (serial[1] >>  8) & 0xff,
			 (serial[1] >>  0) & 0xff,
			 (serial[0] >> 24) & 0xff,
			 (serial[0] >> 16) & 0xff);

		/* Set the NFP operations interface ID and serial number */
		ops->serial[0] = (serial[1] >> 24) & 0xff;
		ops->serial[1] = (serial[1] >> 16) & 0xff;
		ops->serial[2] = (serial[1] >>  8) & 0xff;
		ops->serial[3] = (serial[1] >>  0) & 0xff;
		ops->serial[4] = (serial[0] >> 24) & 0xff;
		ops->serial[5] = (serial[0] >> 16) & 0xff;

		ops->interface = serial[0] & 0xffff;
	} else {
		/* Fallback - only one PCI interface supported
		 * if no serial number is present
		 */
		ops->interface = NFP_CPP_INTERFACE(
				NFP_CPP_INTERFACE_TYPE_PCI, 0, 0xff);
	}

	if (NFP_CPP_INTERFACE_TYPE_of(ops->interface) !=
	    NFP_CPP_INTERFACE_TYPE_PCI) {
		dev_err(&pdev->dev, "Interface type %d is not the expected %d\n",
			NFP_CPP_INTERFACE_TYPE_of(ops->interface),
			NFP_CPP_INTERFACE_TYPE_PCI);
		kfree(nfp);
		return ERR_PTR(-ENODEV);
	}

	if (NFP_CPP_INTERFACE_CHANNEL_of(ops->interface) !=
		NFP_CPP_INTERFACE_CHANNEL_PEROPENER) {
		dev_err(&pdev->dev, "Interface channel %d is not the expected %d\n",
			NFP_CPP_INTERFACE_CHANNEL_of(ops->interface),
			NFP_CPP_INTERFACE_CHANNEL_PEROPENER);
		kfree(nfp);
		return ERR_PTR(-ENODEV);
	}

	ops->area_priv_size = sizeof(struct nfp6000_area_priv);
	ops->area_init = nfp6000_area_init;
	ops->area_cleanup = nfp6000_area_cleanup;
	ops->area_acquire = nfp6000_area_acquire;
	ops->area_release = nfp6000_area_release;
	ops->area_phys = nfp6000_area_phys;
	ops->area_iomem = nfp6000_area_iomem;
	ops->area_resource = nfp6000_area_resource;
	ops->area_read = nfp6000_area_read;
	ops->area_write = nfp6000_area_write;

	ops->explicit_priv_size = sizeof(struct nfp6000_explicit_priv);
	ops->explicit_acquire = nfp6000_explicit_acquire;
	ops->explicit_release = nfp6000_explicit_release;
	ops->explicit_put = nfp6000_explicit_put;
	ops->explicit_do = nfp6000_explicit_do;
	ops->explicit_get = nfp6000_explicit_get;

	ops->event_priv_size = sizeof(struct nfp6000_event_priv);
	ops->event_acquire = nfp6000_event_acquire;
	ops->event_release = nfp6000_event_release;

	ops->init = nfp6000_init;
	ops->free = nfp6000_free;

	ops->owner = THIS_MODULE;

	err = enable_bars(nfp);
	if (err)
		goto err_enable_bars;

	if (nfp->iomem.general && irq >= 0) {
		err = nfp_em_manager_init(&nfp->event,
					  nfp->iomem.general + NFP_PCIE_EM,
					  irq);
		if (err < 0)
			goto err_em_init;
	}

	/* Probe for all the common NFP devices */
	dev_info(&pdev->dev, "Found a NFP6000 on the PCIe bus.\n");
	return nfp_cpp_from_operations(&nfp->ops);

err_em_init:
	disable_bars(nfp);
err_enable_bars:
	kfree(nfp);
err_nfpmem_alloc:
	dev_err(&pdev->dev, "NFP6000 PCI setup failed\n");
	return ERR_PTR(err);
}

/*
 * Local variables:
 * c-file-style: "Linux"
 * indent-tabs-mode: t
 * End:
 */
