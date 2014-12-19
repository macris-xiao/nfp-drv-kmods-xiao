/*
 * Copyright (C) 2014, Netronome, Inc.
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
 */

#ifndef KERNEL_NFP_RTSYMSTAB_H
#define KERNEL_NFP_RTSYMSTAB_H

#include "nfp.h"

#define NFP_RTSYM_TYPE_NONE		(0)
#define NFP_RTSYM_TYPE_OBJECT		(1)
#define NFP_RTSYM_TYPE_FUNCTION		(2)
#define NFP_RTSYM_TYPE_ABS		(3)

#define NFP_RTSYM_TARGET_NONE		(0)
#define NFP_RTSYM_TARGET_LMEM		(-1)
#define NFP_RTSYM_TARGET_USTORE		(-2)
#define NFP_RTSYM_TARGET_EMU_CACHE	(-7)

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

#endif /* KERNEL_NFP_SYMS_H */
/* vim: set shiftwidth=8 noexpandtab:  */
