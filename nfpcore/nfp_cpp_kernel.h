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

/**
 * Use this channel ID for multiple virtual channel interfaces
 * (ie ARM and PCIe) when setting up the nfp_cpp_ops.interface field.
 */
#define NFP_CPP_INTERFACE_CHANNEL_PEROPENER	255

/**
 * Non-blocking version of nfp_cpp_area_acquire()
 *
 * @param[in]   area    NFP CPP Area to acquire
 * @return              0 on success, < 0 on failure
 */
int nfp_cpp_area_acquire_nonblocking(struct nfp_cpp_area *area);

/**
 * Get the parent device of the NFP CPP handle
 *
 * @param[in]   cpp     NFP CPP handle
 * @return              Kernel device pointer
 */
struct device *nfp_cpp_device(struct nfp_cpp *cpp);

/**
 * nfp_cpp_device_id - get device ID of CPP handle
 * @param[in]   cpp    NFP CPP handle
 */
int nfp_cpp_device_id(struct nfp_cpp *cpp);

struct resource;

/**
 * Report the allocated resource region that this area covers
 * The area must be acquired with 'nfp_cpp_area_acquire()' before
 * calling this operation.
 *
 * @param[in]   area    NFP CPP area handle
 * @return              iomem resource
 */
struct resource *nfp_cpp_area_resource(struct nfp_cpp_area *area);

/**
 * Return the CPU bus address of the beginning of the NFP CPP area handle
 * The area must be acquired with 'nfp_cpp_area_acquire()' before
 * calling this operation.
 *
 * @param[in]   area    NFP CPP area handle
 * @return              CPU bus address of the NFP CPP area
 */
phys_addr_t nfp_cpp_area_phys(struct nfp_cpp_area *area);

/**
 * Return an IO pointer to the beginning of the NFP CPP area handle
 * The area must be acquired with 'nfp_cpp_area_acquire()' before
 * calling this operation.
 *
 * @param[in]   area    NFP CPP area handle
 * @return              Void IO pointer
 */
void __iomem *nfp_cpp_area_iomem(struct nfp_cpp_area *area);

/**
 * Execute the event's callbacks (if set)
 *
 * Can be called in IRQ service context to inform the CPP layer
 * that an event has occurred, and that it's event callback needs
 * to be executed.
 */
void nfp_cpp_event_callback(struct nfp_cpp_event *event);

/**
 * Monitor a NFP CPP event handle via a callback
 *
 * @param	event		NFP CPP Event handle
 * @param	callback	Callback function (no locks held, signal handler context)
 * @param	callback_priv	Private data for the callback
 * @return			0 on success, -1 (and errno set) on failure.
 */
int nfp_cpp_event_as_callback(struct nfp_cpp_event *event,
			      void (*callback)(void *), void *priv);


#endif /* NFP_CPP_KERNEL_H */

/*
 * Local variables:
 * c-file-style: "Linux"
 * indent-tabs-mode: t
 * End:
 */
