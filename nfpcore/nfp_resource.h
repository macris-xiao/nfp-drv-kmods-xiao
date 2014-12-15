/* Copyright (C) 2014 Netronome Systems, Inc. All rights reserved.
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
 */

#ifndef NFP_RESOURCE_H
#define NFP_RESOURCE_H

#include "nfp_cpp.h"
#include "nfp-bsp/nfp_resource.h"

struct nfp_device;

int nfp_cpp_resource_init(struct nfp_cpp *cpp,
			  struct nfp_cpp_mutex **resource_mutex);

struct nfp_resource *nfp_resource_acquire(struct nfp_device *nfp,
					  const char *name);

void nfp_resource_release(struct nfp_resource *res);

int nfp_cpp_resource_add(struct nfp_cpp *cpp, const char *name,
			 uint32_t cpp_id, uint64_t address, uint64_t size,
		struct nfp_cpp_mutex **resource_mutex);

uint32_t nfp_resource_cpp_id(struct nfp_resource *res);

const char *nfp_resource_name(struct nfp_resource *res);

uint64_t nfp_resource_address(struct nfp_resource *res);

uint64_t nfp_resource_size(struct nfp_resource *res);

#endif /* NFP_RESOURCE_H */
