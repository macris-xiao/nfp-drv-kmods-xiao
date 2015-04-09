/*
 * Copyright (C) 2014-2015, Netronome, Inc.
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

#ifndef NFP_DEVICE_H
#define NFP_DEVICE_H

#include <linux/list.h>
#include <linux/spinlock.h>

#ifndef NFP_SUBSYS
#define NFP_SUBSYS ""
#endif

#define nfp_err(nfp, fmt, args...) \
	dev_err(nfp_cpp_device(nfp_device_cpp(nfp))->parent, NFP_SUBSYS fmt, ## args)
#define nfp_warn(nfp, fmt, args...) \
	dev_warn(nfp_cpp_device(nfp_device_cpp(nfp))->parent, NFP_SUBSYS fmt, ## args)
#define nfp_info(nfp, fmt, args...) \
	dev_info(nfp_cpp_device(nfp_device_cpp(nfp))->parent, NFP_SUBSYS fmt, ## args)
#define nfp_dbg(nfp, fmt, args...) \
	dev_dbg(nfp_cpp_device(nfp_device_cpp(nfp))->parent, NFP_SUBSYS fmt, ## args)
#define nfp_trace(nfp, fmt, args...) \
	trace_printk("%s %s: " NFP_SUBSYS fmt, \
			dev_driver_string(nfp_cpp_device(nfp_device_cpp(nfp))->parent, \
			dev_name(nfp_cpp_device(nfp_device_cpp(nfp))->parent, ## args)

/** Opaque NFP device handle. */
struct nfp_device;
struct nfp_cpp;

/** Maximum device number for an NFP device. */
#define NFP_MAX_DEVICE_NUM              63

struct nfp_device *nfp_device_open(unsigned int devnum);
struct nfp_device *nfp_device_from_cpp(struct nfp_cpp *cpp);
void nfp_device_close(struct nfp_device *dev);

int nfp_device_id(struct nfp_device *nfp);
struct nfp_cpp *nfp_device_cpp(struct nfp_device *dev);

void *nfp_device_private(struct nfp_device *dev,
			 void *(*constructor) (struct nfp_device * dev));
void *nfp_device_private_alloc(struct nfp_device *dev, size_t private_size,
			       void (*destructor) (void *private_data));


#endif /* NFP_DEVICE_H */
