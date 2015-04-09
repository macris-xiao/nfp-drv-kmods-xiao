/*
 * Copyright (C) 2008-2015, Netronome Systems, Inc. All rights reserved.
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
 */

#ifndef NFP_CPP_KERNEL_H
#define NFP_CPP_KERNEL_H

#include <linux/list.h>

#include "kcompat.h"

#include "nfp_cpp.h"
#include "nfp_explicit.h"

/*
 * The following section contains extensions to the
 * NFP CPP API, to be used in a Linux kernel-space context.
 */

/*
 * Use this channel ID for multiple virtual channel interfaces
 * (ie ARM and PCIe) when setting up the nfp_cpp_ops.interface field.
 */
#define NFP_CPP_INTERFACE_CHANNEL_PEROPENER	255

int nfp_cpp_area_acquire_nonblocking(struct nfp_cpp_area *area);
struct device *nfp_cpp_device(struct nfp_cpp *cpp);
int nfp_cpp_device_id(struct nfp_cpp *cpp);

struct resource;

struct resource *nfp_cpp_area_resource(struct nfp_cpp_area *area);
phys_addr_t nfp_cpp_area_phys(struct nfp_cpp_area *area);
void __iomem *nfp_cpp_area_iomem(struct nfp_cpp_area *area);

void nfp_cpp_event_callback(struct nfp_cpp_event *event);
int nfp_cpp_event_as_callback(struct nfp_cpp_event *event,
			      void (*callback)(void *), void *priv);

uint64_t nfp_cpp_island_mask(struct nfp_cpp *cpp);

#endif /* NFP_CPP_KERNEL_H */
