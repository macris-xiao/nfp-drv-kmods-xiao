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

int nfp_nffw_info_acquire(struct nfp_device *dev);
int nfp_nffw_info_release(struct nfp_device *dev);
int nfp_nffw_info_fw_mip(struct nfp_device *dev, uint8_t fwid,
			 uint32_t *cpp_id, uint64_t *off);
uint8_t nfp_nffw_info_fwid_first(struct nfp_device *dev);

#endif /* NFP_NFFW_H */
