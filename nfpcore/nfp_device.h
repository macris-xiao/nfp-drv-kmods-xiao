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

#ifndef NFP_DEVICE_H
#define NFP_DEVICE_H

#include <linux/list.h>
#include <linux/spinlock.h>

#include "nfp_mip.h"
#include "nfp_rtsym.h"

struct nfp_device {
	int cpp_free;
	struct nfp_cpp *cpp;

	void *hwinfo;

	spinlock_t miptab_lock;	/* Lock protecting the MIP pointer */
	struct nfp_miptab *miptab;

	spinlock_t rtsymtab_lock; /* Lock protecting the rtsymtab pointer */
	struct nfp_rtsymtab *rtsymtab;

	spinlock_t private_lock;
	struct list_head private_list;
};

#define NFE_SUBSYS ""
#define nfp_err(nfe, fmt, args...) \
	dev_err(nfp_cpp_device((nfe)->cpp), NFE_SUBSYS fmt, ## args)
#define nfp_warn(nfe, fmt, args...) \
	dev_warn(nfp_cpp_device((nfe)->cpp), NFE_SUBSYS fmt, ## args)
#define nfp_info(nfe, fmt, args...) \
	dev_info(nfp_cpp_device((nfe)->cpp), NFE_SUBSYS fmt, ## args)
#define nfp_dbg(nfe, fmt, args...) \
	dev_dbg(nfp_cpp_device((nfe)->cpp), NFE_SUBSYS fmt, ## args)
#define nfp_trace(nfe, fmt, args...) \
	trace_printk("%s %s: " NFE_SUBSYS fmt, \
			dev_driver_string((nfe)->dev), \
			dev_name((nfe)->dev), ## args)

#endif /* NFP_DEVICE_H */
/* vim: set shiftwidth=4 expandtab:  */
