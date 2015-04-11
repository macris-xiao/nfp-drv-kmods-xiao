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
#include <linux/module.h>

#include "nfp_nbi.h"
#include "nfp_resource.h"

#include "nfp6000/nfp_xpb.h"

struct nfp_nbi_dev {
	struct nfp_device *nfp;
	struct nfp_cpp *cpp;
	struct {
		uint32_t cpp_id;
		uint64_t cpp_addr;
	} stats;
	int nbi;
};

/*
 * Specification of the ports and channels to be monitored.  These are
 * initialized when the daemon is started and can be modified to
 * add ports and channels while the daemon is running. Ports/channels
 * cannot be removed from scan while the daemon is running.
 */
struct nfp_nbi_mac_stats_spec {
	/* One bit for each port to be monitored.  */
	uint64_t ports;
	/* One bit for each channel [0-63] to be monitored. */
	uint64_t chans63_0;
	/* One bit for each channel [64-127] to be monitored. */
	uint64_t chans127_64;
	/* Interlaken channels - one for each ilk core to be monitored. */
	uint32_t ilk[2];
};

/*
 * Structure used to maintain the state of the statistics daemon.
 *
 * The scan period of the statistics daemon is specified when the
 * daemon is started.  It may be changed while the daemon is running.
 *
 * When the daemon starts it zeroes all statistics registers and
 * cumulative memory counters and sets 'ready' true.
 *
 * Each period the daemon checks "active" to determine what
 * ports/channels must be scanned and then initiates an update of the
 * cumulative statistics for those ports/channels.  When the update is
 * complete the daemon will increment 'updated'.
 *
 * Each cycle the daemon also checks "clear" to see if any counters
 * should be cleared.  When the daemon clears a set of counters it increments
 * the 'clr_count' variable for that port/channel.
 *
 */
struct nfp_nbi_mac_stats_state {
	/* Scan period of the statistics daemon (mS) */
	uint32_t period;
	/* Flag indicating that the daemon is initialized */
	uint32_t ready;
	/* Counter incremented every cycle after the daemon completes a scan */
	uint64_t updated;
	/* Specification of the ports and channels to be monitored. */
	struct nfp_nbi_mac_stats_spec active;
	/* Specification of the port and channel counters to be cleared. */
	struct nfp_nbi_mac_stats_spec clear;
	/* Count of Ethernet port counter clears. */
	uint64_t portclr_count[24];
	/* Count of channel counter clears. */
	uint64_t chanclr_count[128];
	/* Count of Interlaken counter clears. */
	uint64_t ilkclr_count[2];
};

/*
 * Statistics structure for both MACs
 */
struct nfp_nbi_mac_stats {
	/* Port statistics */
	struct nfp_nbi_mac_portstats portstats[24];
	/* Channel statistics */
	struct nfp_nbi_mac_chanstats chanstats[128];
	/*Interlaken statistics */
	struct nfp_nbi_mac_ilkstats ilkstats[2];
	/* Daemon state */
	struct nfp_nbi_mac_stats_state state;
};

#define NFP_NBI_MAC_STATS_MAGIC 0xae6d730000000000ULL /* 0xae,'m','s', 0, .. */

struct nfp_nbi_mac_allstats {
	uint64_t magic;             /* NFP_NBI_MAC_STATS_MAGIC */
	struct nfp_nbi_mac_stats mac[2];
};

/**
 * nfp_nbi_open() - Acquire NFP NBI device handle
 * @nfp:	NFP Device handle
 * @nbi_id:	NFP NBI index to open (0..1)
 *
 * Return: struct nfp_nbi_dev *, or NULL
 */
struct nfp_nbi_dev *nfp_nbi_open(struct nfp_device *nfp, int nbi_id)
{
	struct nfp_nbi_dev *nbi;
	struct nfp_resource *res;

	if (nbi_id < 0 || nbi_id >= 2)
		return NULL;

	nbi = kzalloc(sizeof(*nbi), GFP_KERNEL);
	if (!nbi)
		return NULL;

	nbi->nfp = nfp;
	nbi->cpp = nfp_device_cpp(nfp);
	nbi->nbi = nbi_id;

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
EXPORT_SYMBOL(nfp_nbi_open);

/**
 * nfp_nbi_close() - Release NFP NBI device handle
 * @nbi:	NBI handle
 */
void nfp_nbi_close(struct nfp_nbi_dev *nbi)
{
	kfree(nbi);
}
EXPORT_SYMBOL(nfp_nbi_close);

/**
 * nfp_nbi_index() - Get the NFP NBI index of this NBI handle
 * @nbi:	NBI handle
 *
 * Return: NBI index of the NBI handle
 */
int nfp_nbi_index(struct nfp_nbi_dev *nbi)
{
	return nbi->nbi;
}
EXPORT_SYMBOL(nfp_nbi_index);

/**
 * nfp_nbi_mac_stats_read_port() - Read the statistics for an active port
 * @nbi:	NBI handle
 * @port:	Port number (0..23)
 * @stats:	Pointer to the stats buffer
 *
 * Return: size in bytes of the status area read, or -ERRNO
 */
int nfp_nbi_mac_stats_read_port(struct nfp_nbi_dev *nbi, int port,
				struct nfp_nbi_mac_portstats *stats)
{
	uint64_t magic = 0;

	if (port < 0 || port >= 24)
		return -EINVAL;

	/* Check magic */
	nfp_cpp_readq(nbi->cpp, nbi->stats.cpp_id, nbi->stats.cpp_addr, &magic);
	if (magic != NFP_NBI_MAC_STATS_MAGIC)
		return -EINVAL;

	return nfp_cpp_read(nbi->cpp, nbi->stats.cpp_id, nbi->stats.cpp_addr +
			    offsetof(struct nfp_nbi_mac_allstats,
				     mac[nbi->nbi].portstats[port]),
			    stats, sizeof(*stats));
}

/**
 * nfp_nbi_mac_stats_read_chan() - Read the statistics for a channel
 * @nbi:	NBI handle
 * @chan:	Channel number (0..127)
 * @stats:	Pointer to the stats buffer
 *
 * Return: size in bytes of the status area read, or -ERRNO
 */
int nfp_nbi_mac_stats_read_chan(struct nfp_nbi_dev *nbi, int chan,
				struct nfp_nbi_mac_chanstats *stats)
{
	uint64_t magic = 0;

	if (chan < 0 || chan >= 128)
		return -EINVAL;

	/* Check magic */
	nfp_cpp_readq(nbi->cpp, nbi->stats.cpp_id, nbi->stats.cpp_addr, &magic);
	if (magic != NFP_NBI_MAC_STATS_MAGIC)
		return -EINVAL;

	return nfp_cpp_read(nbi->cpp, nbi->stats.cpp_id, nbi->stats.cpp_addr +
			    offsetof(struct nfp_nbi_mac_allstats,
				     mac[nbi->nbi].chanstats[chan]),
			    stats, sizeof(*stats));
}

/**
 * nfp_nbi_mac_stats_read_ilks() - Read the statistics for a ilksnel
 * @nbi:	NBI handle
 * @ilk:	Interlaken (0..1)
 * @stats:	Pointer to the stats buffer
 *
 * Return: size in bytes of the status area read, or -ERRNO
 */
int nfp_nbi_mac_stats_read_ilks(struct nfp_nbi_dev *nbi, int ilk,
				struct nfp_nbi_mac_ilkstats *stats)
{
	uint64_t magic = 0;

	if (ilk < 0 || ilk >= 2)
		return -EINVAL;

	/* Check magic */
	nfp_cpp_readq(nbi->cpp, nbi->stats.cpp_id, nbi->stats.cpp_addr, &magic);
	if (magic != NFP_NBI_MAC_STATS_MAGIC)
		return -EINVAL;

	return nfp_cpp_read(nbi->cpp, nbi->stats.cpp_id, nbi->stats.cpp_addr +
			    offsetof(struct nfp_nbi_mac_allstats,
				     mac[nbi->nbi].ilkstats[ilk]),
			    stats, sizeof(*stats));
}

/**
 * nfp_nbi_mac_regr() - Read a MAC register
 * @nbi:	NBI handle
 * @base:	Base address, e.g. NFP_NBI_MACX_ETH(1)
 * @reg:	Register, e.g. NFP_NBI_MACX_ETH_MacEthSeg_EthCmdConfig(port)
 * @data:	Value read from register
 *
 * Read the value of a MAC register. The register address is
 * specified as a base plus an offset.
 *
 * Return: 0, or -ERRNO
 */
int nfp_nbi_mac_regr(struct nfp_nbi_dev *nbi, uint32_t base, uint32_t reg,
		     uint32_t * data)
{
	uint32_t r = NFP_XPB_ISLAND(nbi->nbi + 8) + base + reg;

	return nfp_xpb_readl(nbi->cpp, r, data);

}

/**
 * nfp_nbi_mac_regw() - Write a MAC register
 * @nbi:	NBI handle
 * @base:	Base address, e.g. NFP_NBI_MACX_ETH(1)
 * @reg:	Register, e.g. NFP_NBI_MACX_ETH_MacEthSeg_EthCmdConfig(port)
 * @mask:	Mask specifying the bits that may be changed by data
 * @data:	Value to write to the register
 *
 * Write a value to a MAC register.  The register address is specified
 * as a base plus an offset.
 *
 * The value to be written is specified by the parameters "data" and
 * "mask".  If mask is -1 the register is overwritten with the value
 * of data. Otherwise the register is read first and only the bits
 * specified by mask are allowed to be changed by data when the value
 * is written back.
 *
 * Return: 0, or -ERRNO
 */
int nfp_nbi_mac_regw(struct nfp_nbi_dev *nbi, uint32_t base, uint32_t reg,
		     uint32_t mask, uint32_t data)
{
	uint32_t r = NFP_XPB_ISLAND(nbi->nbi + 8) + base + reg;

	return nfp_xpb_writelm(nbi->cpp, r, mask, data);
}
