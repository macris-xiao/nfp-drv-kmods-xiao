/* Copyright (C) 2011 Netronome Systems, Inc. All rights reserved.
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
 * @file kernel/nfe.h
 *
 * Common declarations for the NFE drivers.
 */
#ifndef __KERNEL__NFE_H__
#define __KERNEL__NFE_H__

#include <linux/version.h>
#include <linux/pci.h>
#include <linux/device.h>
#include <linux/cdev.h>
#include <linux/sched.h>
#include <linux/mutex.h>
#include <linux/wait.h>
#include <linux/spinlock.h>
#include <linux/list.h>
#include <linux/slab.h>
#include <linux/module.h>

#include "nfp_cpp_kernel.h"

#include "nfe_compat.h"

#define PCI_64BIT_BAR_COUNT             3

/* SHaC/CAP register offsets. */
#define NFP_SHAC_INTERTHREAD_SIG	0x001c
extern struct class *nfe_class;
struct nfp_device;
struct nfe_rtsym;

/* Maximum number of NFE cards we expect in a system.  */
#define NFE_MAX_CARDS		16
/* Maximum number of MSI-X vectors per NFE. */
#define NFE_MAX_MSIX_COUNT	8
/* Maximum number of times we retry accessing an ME CSR. */
#define NFE_MAX_CSR_FAILCOUNT	50

/*
 * NFP hardware vendor/device ids.  Should be added to Linux.
 */
#define PCI_VENDOR_ID_NETRONOME		0x19ee
#define PCI_DEVICE_NFP3200		0x3200
#define PCI_DEVICE_NFP3240		0x3240
#define PCI_DEVICE_NFP6000		0x6000

/*
 * Determine whether the NFP's device is a PCIe card, or whether we
 * are running in the NFP's ARM.  For non-NFP we always return true
 * so that compiler can optimize away unused code.
 */
#ifdef CONFIG_ARCH_NFP
#define nfe_is_pcie(nfe) \
	((nfe)->dev->parent && ((nfe)->dev->parent->bus == &pci_bus_type))
#else
#define nfe_is_pcie(nfe) (1)
#endif

/* Convert an NFE-card structure the struct pci_dev that represents the NFE.
 * This has no meaning for the ARM's local NFP, for that is a platform device,
 * and not a PCI device.
 */
#define nfe_to_pci(nfe) \
	to_pci_dev((nfe)->dev->parent)

/*
 * Helper functions for accessing NFP memory directly.
 */

static inline u32 nfe_readl(const void __iomem *src)
{
	return readl(src);
}

static inline void nfe_writel(void __iomem *dst, u32 value)
{
	writel(value, dst);
}

static inline void nfe_read(const void __iomem *src, void *dst, u32 size)
{
	const u32 __iomem *s = src;
	u32 *d = dst;
	int n;

	for (n = 0; n < size / sizeof(u32); n++)
		d[n] = __raw_readl(s + n);
}

static inline void nfe_write(const void *src, void __iomem *dst, u32 size)
{
	const u32 *s = src;
	u32 __iomem *d = dst;
	int n;

	for (n = 0; n < size / sizeof(u32); n++)
		__raw_writel(s[n], d + n);
}

static inline void nfe_fill(void __iomem *dst, u32 size, u32 value)
{
	u32 __iomem *d = dst;
	int n;

	for (n = 0; n < size / sizeof(u32); n++)
		nfe_writel(d+n, value);
}

static inline void nfe_swizzle_words(void *buf, u32 size)
{
#ifdef __BIG_ENDIAN
	u32 *__buf = buf;
	int n;

	for (n = 0; n < size / sizeof(u32); n++)
		__buf[n] = le32_to_cpu(__buf[n]);
#endif
}

#define NFP_CPP_NUM_TARGETS		16

struct nfp_device_config {
	unsigned int chip_revision;

	const char *board_model;
};

#ifdef CONFIG_NFE_MSIX
int nfp3200_cpp_irq_to_msix(struct nfp_cpp *cpp, int irq);
int nfp3200_cpp_msix_to_irq(struct nfp_cpp *cpp, int idx);
int nfp6000_cpp_irq_to_msix(struct nfp_cpp *cpp, int irq);
int nfp6000_cpp_msix_to_irq(struct nfp_cpp *cpp, int idx);
#endif

/*
 * Local variables:
 * c-file-style: "Linux"
 * indent-tabs-mode: t
 * End:
 */

#endif  /* __KERNEL__NFE_H__ */
