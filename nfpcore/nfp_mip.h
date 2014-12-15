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
 * @file          nfp_mip.h
 * @brief         Microcode Information Page (MIP) interface
 *
 */
#ifndef __NFP_MIP_H__
#define __NFP_MIP_H__

#define NFP_MIP_SIGNATURE	0x0050494d  /* "MIP\0" */

/*
 * Version numbers.  Version number should be increased when the
 * corresponding structure layout changes.
 */
#define NFP_MIP_VERSION		1
#define NFP_MIP_QC_VERSION	1
#define NFP_MIP_VPCI_VERSION	1

/* MIP entry types */
#define NFP_MIP_TYPE_NONE	0
#define NFP_MIP_TYPE_QC		1
#define NFP_MIP_TYPE_VPCI	2

struct nfp_mip {
	u32 signature;
	u32 mip_version;
	u32 mip_size;
	u32 first_entry;

	u32 version;
	u32 buildnum;
	u32 buildtime;
	u32 loadtime;

	u32 symtab_addr;
	u32 symtab_size;
	u32 strtab_addr;
	u32 strtab_size;

	char name[16];
	char toolchain[32];
};

struct nfp_mip_entry {
	u32 type;
	u32 version;
	u32 offset_next;
};

#ifdef CONFIG_NFP_INTERNAL
#include <library/mip/microcode/mip.h> /* From microcode library */
#endif

struct nfp_device;

int nfp_miptab_init(struct nfp_device *nfp);
void nfp_miptab_cleanup(struct nfp_device *nfp);

const struct nfp_mip *nfp_mip_acquire(struct nfp_device *nfp);
void nfp_mip_release(const struct nfp_mip *mip);

const void *nfp_mip_find_entry(const struct nfp_mip *mip, u32 entry_type);

/*
 * Local variables:
 * c-file-style: "Linux"
 * indent-tabs-mode: t
 * End:
 */

#endif /* !__NFP_MIP_H__ */
