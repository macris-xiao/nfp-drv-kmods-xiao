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

#include <linux/kernel.h>
#include <linux/netdevice.h>
#include <linux/ethtool.h>

#include "nfp_nbi.h"
#include "nfp_nbi_mac_stats.h"
#include "nfp_resource.h"

struct nfp_nbi_dev {
	struct nfp_device *nfp;
	struct nfp_cpp *cpp;
	struct {
		uint32_t cpp_id;
		uint64_t cpp_addr;
	} stats;
	int mac;
};

struct nfp_nbi_dev *nfp_nbi_open(struct nfp_device *nfp, int mac)
{
	struct nfp_nbi_dev *nbi;
	struct nfp_resource *res;

	nbi = kzalloc(sizeof(*nbi), GFP_KERNEL);
	if (!nbi)
		return NULL;

	nbi->nfp = nfp;
	nbi->cpp = nfp_device_cpp(nfp);
	nbi->mac = mac;

	res = nfp_resource_acquire(nfp, NFP_RESOURCE_MAC_STATISTICS);
	if (!res) {
		kfree(nbi);
		nbi = NULL;
	} else {
		nbi->stats.cpp_id = nfp_resource_cpp_id(res);
		nbi->stats.cpp_addr = nfp_resource_address(res);
		nfp_resource_release(res);
	}

	return nbi;
}

void nfp_nbi_close(struct nfp_nbi_dev *nbi)
{
	kfree(nbi);
}

int nfp_nbi_mac_stats_read_port(struct nfp_nbi_dev *nbi, int port,
				struct nfp_nbi_mac_portstats *stats)
{
	uint64_t magic = 0;

	/* Check magic */
	nfp_cpp_readq(nbi->cpp, nbi->stats.cpp_id, nbi->stats.cpp_addr, &magic);
	if (magic != NFP_NBI_MAC_STATS_MAGIC)
		return -EINVAL;

	return nfp_cpp_read(nbi->cpp, nbi->stats.cpp_id, nbi->stats.cpp_addr +
			offsetof(struct nfp_nbi_mac_allstats,
				 mac[nbi->mac].portstats[port]),
			stats, sizeof(*stats));
}

/* vim: set shiftwidth=8 noexpandtab:  */
