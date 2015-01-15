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

struct nfp_device {
	int cpp_free;
	struct nfp_cpp *cpp;

	void *hwinfo;

	spinlock_t private_lock;
	struct list_head private_list;
};

#define NFP_SUBSYS ""
#define nfp_err(nfp, fmt, args...) \
	dev_err(nfp_cpp_device((nfp)->cpp), NFP_SUBSYS fmt, ## args)
#define nfp_warn(nfp, fmt, args...) \
	dev_warn(nfp_cpp_device((nfp)->cpp), NFP_SUBSYS fmt, ## args)
#define nfp_info(nfp, fmt, args...) \
	dev_info(nfp_cpp_device((nfp)->cpp), NFP_SUBSYS fmt, ## args)
#define nfp_dbg(nfp, fmt, args...) \
	dev_dbg(nfp_cpp_device((nfp)->cpp), NFP_SUBSYS fmt, ## args)
#define nfp_trace(nfp, fmt, args...) \
	trace_printk("%s %s: " NFP_SUBSYS fmt, \
			dev_driver_string((nfp)->dev), \
			dev_name((nfp)->dev), ## args)

#endif /* NFP_DEVICE_H */
/* vim: set shiftwidth=4 expandtab:  */
