/*
 * Copyright (C) 2014-2015 Netronome Systems, Inc. All rights reserved.
 * Author: Jason McMullan <jason.mcmullan@netronome.com>
 *
 *   This program is free software; you can redistribute it and/or modify
 *   it under the terms of the GNU General Public License as published by
 *   the Free Software Foundation; either version 2 of the License, or
 *   (at your option) any later version.
 *
 *   This program is distributed in the hope that it will be useful,
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *   GNU General Public License for more details.
 *
 */

#ifndef NFP_NFFW_H
#define NFP_NFFW_H

/* Implemented in nfp_nffw.c */

int nfp_nffw_info_acquire(struct nfp_device *dev);
int nfp_nffw_info_release(struct nfp_device *dev);
int nfp_nffw_info_fw_mip(struct nfp_device *dev, uint8_t fwid,
			 uint32_t *cpp_id, uint64_t *off);
uint8_t nfp_nffw_info_fwid_first(struct nfp_device *dev);

/* Implemented in nfp_mip.c */

struct nfp_mip;

const struct nfp_mip *nfp_mip(struct nfp_device *dev);
int nfp_mip_probe(struct nfp_device *dev);

int nfp_mip_symtab(const struct nfp_mip *mip, uint32_t *addr, uint32_t *size);
int nfp_mip_strtab(const struct nfp_mip *mip, uint32_t *addr, uint32_t *size);

/* Implemented in nfp_rtsym.c */

#define NFP_RTSYM_TYPE_NONE		(0)
#define NFP_RTSYM_TYPE_OBJECT		(1)
#define NFP_RTSYM_TYPE_FUNCTION		(2)
#define NFP_RTSYM_TYPE_ABS		(3)

#define NFP_RTSYM_TARGET_NONE		(0)
#define NFP_RTSYM_TARGET_LMEM		(-1)
#define NFP_RTSYM_TARGET_USTORE		(-2)
#define NFP_RTSYM_TARGET_EMU_CACHE	(-7)

/**
 * struct nfp_rtsym - RTSYM descriptor
 * @name:		Symbol name
 * @addr:		Address in the domain/target's address space
 * @size:		Size (in bytes) of the symbol
 * @type:		NFP_RTSYM_TYPE_* of the symbol
 * @target:		CPP Target identifier, or NFP_RTSYM_TARGET_*
 * @domain:		CPP Target Domain (island)
 */
struct nfp_rtsym {
	const char *name;
	uint64_t addr;
	uint64_t size;
	int type;
	int target;
	int domain;
};

void nfp_rtsym_reload(struct nfp_device *nfp);
int nfp_rtsym_count(struct nfp_device *dev);
const struct nfp_rtsym *nfp_rtsym_entry(struct nfp_device *nfp, size_t idx);
const struct nfp_rtsym *nfp_rtsym_lookup(struct nfp_device *nfp,
					 const char *name);

#endif /* NFP_NFFW_H */
