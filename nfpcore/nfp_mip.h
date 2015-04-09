/*
 * Copyright (C) 2011-2015, Netronome, Inc.
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
#ifndef __NFP_MIP_H__
#define __NFP_MIP_H__

struct nfp_mip;

const struct nfp_mip *nfp_mip(struct nfp_device *dev);
int nfp_mip_probe(struct nfp_device *dev);

int nfp_mip_symtab(const struct nfp_mip *mip, uint32_t *addr, uint32_t *size);
int nfp_mip_strtab(const struct nfp_mip *mip, uint32_t *addr, uint32_t *size);

#endif /* !__NFP_MIP_H__ */
