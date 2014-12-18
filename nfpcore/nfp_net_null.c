/*
 * Copyright (C) 2014, Netronome, Inc.
 * All right reserved.
 * Author: Jason McMullan <jason.mcmullan@netronome.com>
 *
 * Null network device, for use as an ethtool interface
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

#include <linux/kernel.h>
#include <linux/netdevice.h>
#include <linux/etherdevice.h>
#include <linux/platform_device.h>

#include "nfp_cpp_kernel.h"

#include "nfp_nbi_mac_stats.h"
#include "nfp_nbi_phymod.h"

#include "nfe.h"
#include "nfp_net_null.h"

#define TX_TIMEOUT	(2 * HZ)

static const char nfp_net_null_driver_name[] = NFP_NET_NULL_TYPE;
static const char nfp_net_null_driver_version[] = "0.0";

struct nfp_net_null {
	struct device *parent;
	struct nfp_device *nfp;
	int ports;
	struct net_device *port[48];
};

struct nfp_net_null_dev {
	struct ethtool_ops ethtool_ops;
	struct net_device_ops netdev_ops;
	int mac;
	int port;
	struct nfp_nbi_dev *nbi;
	struct nfp6000_mac_dev_stats {
		uint32_t cpp_id;
		uint64_t cpp_addr;
		struct nfp_nbi_mac_portstats cache;
	} stats;
};

static netdev_tx_t nfp_net_null_ndo_start_xmit(struct sk_buff *skb,
					       struct net_device *dev)
{
	dev->stats.tx_errors++;
	dev->stats.tx_carrier_errors++;
	kfree_skb(skb);
	return NETDEV_TX_OK;
}

static void nfp_net_null_eto_get_drvinfo(struct net_device *dev,
					 struct ethtool_drvinfo *di)
{
	struct nfp_net_null_dev *nm = netdev_priv(dev);

	/* Fill in the stats and flags info
	 */
	strlcpy(di->bus_info, dev_name(dev->dev.parent), sizeof(di->bus_info));


	di->n_priv_flags = 0;
	di->n_stats = sizeof(nm->stats.cache)/sizeof(uint64_t);
	di->testinfo_len = 0;
	di->eedump_len = 0;
	di->regdump_len = 0;

	/* Override the rest */
	strlcpy(di->driver, nfp_net_null_driver_name, sizeof(di->driver));
	strlcpy(di->version, nfp_net_null_driver_version, sizeof(di->version));

	/* FIXME: Get firmware version from hwinfo */
	di->fw_version[0] = 0;
}

static int nfp_net_null_eto_get_settings(struct net_device *dev,
					 struct ethtool_cmd *cmd)
{
	/* FIXME: Read the actual port config from the MAC */
	cmd->supported =   (SUPPORTED_10000baseT_Full | SUPPORTED_FIBRE);
	cmd->advertising = (ADVERTISED_10000baseT_Full | ADVERTISED_FIBRE);
	ethtool_cmd_speed_set(cmd, SPEED_10000);
	cmd->duplex = DUPLEX_FULL;
	cmd->port = PORT_FIBRE;
	cmd->transceiver = XCVR_INTERNAL;
	cmd->autoneg = AUTONEG_DISABLE;

	cmd->mdio_support = 0;
	cmd->phy_address = 0;

	cmd->maxtxpkt = 0;
	cmd->maxrxpkt = 0;
	cmd->eth_tp_mdix = 0;
#if (LINUX_VERSION_CODE >= KERNEL_VERSION(3, 7, 0))
	cmd->eth_tp_mdix_ctrl = 0;
#endif

	cmd->lp_advertising = cmd->advertising;

	return 0;
}

static int nfp_net_null_update_stats(struct net_device *dev)
{
	struct nfp_net_null_dev *nm = netdev_priv(dev);
	struct nfp_nbi_mac_portstats *ps = &nm->stats.cache;
	int err;

	err = nfp_nbi_mac_stats_read_port(nm->nbi, nm->port, ps);
	if (err < 0) {
		/* Return an error, or report the stale cache?
		 * For now, let's just print a debug message,
		 * and use the stale cache.
		 */
		netdev_dbg(dev, "Can't access mac%d.%d stats\n",
			   nm->mac, nm->port);
	}

	return err;
}

#if (LINUX_VERSION_CODE >= KERNEL_VERSION(3, 1, 0))
struct rtnl_link_stats64 *nfp_net_null_ndo_get_stats64(struct net_device *dev,
						       struct rtnl_link_stats64
						       *st)
{
	struct nfp_net_null_dev *nm = netdev_priv(dev);
	struct nfp_nbi_mac_portstats *ps = &nm->stats.cache;

	nfp_net_null_update_stats(dev);

	if (!st)
		return NULL;

	st->rx_packets = ps->RxPStatsPkts;
	/* FIXME: Shouldn't there be a txPStatsPkts? */
	st->tx_packets = ps->TxPStatsPkts1518toMAXoctets +
			 ps->TxPStatsPkts1024to1518octets +
			 ps->TxPStatsPkts512to1023octets +
			 ps->TxPStatsPkts256to511octets +
			 ps->TxPStatsPkts65to127octets +
			 ps->TxPStatsPkts64octets;
	st->rx_bytes = ps->RxPIfInOctets;
	st->tx_bytes = ps->TxPIfOutOctets;
	st->rx_errors = ps->RxPIfInErrors;
	st->tx_errors = ps->TxPIfOutErrors;
	st->rx_dropped = ps->RxPStatsDropEvents;
	/* FIXME: Are all errors dropped? */
	st->tx_dropped = ps->TxPIfOutErrors;
	st->multicast = ps->RxPIfInMultiCastPkts;
	/* CHECKME: Are jabbers collisions? */
	st->collisions = ps->RxPStatsJabbers;

	st->rx_length_errors = ps->RxInRangeLengthErrors;
	st->rx_over_errors = 0;
	st->rx_crc_errors = ps->RxFrameCheckSequenceErrors;
	st->rx_frame_errors = ps->RxAlignmentErrors;
	st->rx_fifo_errors = 0;
	st->rx_missed_errors = 0;

	st->tx_aborted_errors = 0;
	st->tx_carrier_errors = 0;
	st->tx_fifo_errors = 0;
	st->tx_heartbeat_errors = 0;
	st->tx_window_errors = 0;

	st->rx_compressed = 0;
	st->tx_compressed = 0;

	return st;
}
#endif /* >= KERNEL_VERSION(3, 1, 0) */

static void nfp_net_null_eto_get_ethtool_stats(struct net_device *dev,
					       struct ethtool_stats *stats,
					       u64 *data)
{
	struct nfp_net_null_dev *nm = netdev_priv(dev);

	nfp_net_null_update_stats(dev);

	memcpy(data, &nm->stats.cache, sizeof(nm->stats.cache));
}

/* NOTE: cp must be len+1 in size!
 */
static void _phymod_string(struct nfp_phymod *phy, int reg, char *cp, int len)
{
	int i, err;

	for (i = 0; i < len; i++) {
		err = nfp_phymod_read8(phy, reg + i, &cp[i]);
		if (err < 0)
			break;
	}

	cp[i] = 0;

	/* Remove trailing spaces */
	for (i--; i > 0 && cp[i] == ' '; cp[i--] = 0);
}
/* Allocate one netdev
 */
static int nfp_net_null_create(struct nfp_net_null *np,
			       int np_port, struct nfp_phymod *phy)
{
	struct nfp_net_null_dev *nd;
	struct net_device *dev;
	int err;
	int mac, port, type;

	err = nfp_phymod_get_type(phy, &type);
	if (err < 0)
		return err;

	err = nfp_phymod_get_nbi(phy, &mac);
	if (err < 0)
		return err;

	err = nfp_phymod_get_port(phy, &port, NULL);
	if (err < 0)
		return err;

	dev = alloc_etherdev(sizeof(*nd));
	if (!dev)
		return -ENOMEM;

	nd = netdev_priv(dev);

	nd->nbi = nfp_nbi_open(np->nfp, mac);
	if (!nd->nbi) {
		free_netdev(dev);
		return -ENOMEM;
	}

	nd->mac = mac;
	nd->port = port;

	/* Use the nfp6000_mac_netdev_ops as a baseline,
	 * and override as needed
	 */
	nd->netdev_ops.ndo_start_xmit = nfp_net_null_ndo_start_xmit;
#if (LINUX_VERSION_CODE >= KERNEL_VERSION(3, 1, 0))
	nd->netdev_ops.ndo_get_stats64 = nfp_net_null_ndo_get_stats64,
#endif

	dev->netdev_ops = &nd->netdev_ops;

	/* Use the nfp6000_mac_ethtool_ops as a baseline,
	 * and override as needed
	 */
	nd->ethtool_ops.get_drvinfo = nfp_net_null_eto_get_drvinfo;
	nd->ethtool_ops.get_settings = nfp_net_null_eto_get_settings;
	nd->ethtool_ops.get_ethtool_stats = nfp_net_null_eto_get_ethtool_stats;

	dev->ethtool_ops = &nd->ethtool_ops;

	SET_NETDEV_DEV(dev, np->parent);
	dev->watchdog_timeo = TX_TIMEOUT;

	netif_carrier_off(dev);

	err = register_netdev(dev);
	if (err < 0) {
		nfp_nbi_close(nd->nbi);
		free_netdev(dev);
		return err;
	}

	if (type == NFP_PHYMOD_TYPE_NONE) {
		netdev_info(dev, "mac%d.%d (No PHY)\n", mac, port);
	} else if (type == NFP_PHYMOD_TYPE_SFPP) {
		netdev_info(dev, "mac%d.%d SFP+\n", mac, port);
	} else if (type == NFP_PHYMOD_TYPE_QSFP) {
		char vendor[17], part[17], rev[3];

		_phymod_string(phy, 148, vendor, 16);
		_phymod_string(phy, 168, part, 16);
		_phymod_string(phy, 184, rev, 2);

		netdev_info(dev, "mac%d.%d QSFP %s %s.%s\n", mac, port,
				vendor, part, rev);
	} else if (type == NFP_PHYMOD_TYPE_CXP) {
		netdev_info(dev, "mac%d.%d CXP\n", mac, port);
	} else {
		netdev_info(dev, "mac%d.%d (Unknown PHY %d)\n",
			    mac, port, type);
	}

	np->port[np_port] = dev;

	return 0;
}

static void nfp_net_null_destroy(struct nfp_net_null *np, int port)
{
	struct net_device *dev = np->port[port];
	struct nfp_net_null_dev *nm = netdev_priv(dev);

	if (!dev)
		return;

	unregister_netdev(dev);
	nfp_nbi_close(nm->nbi);
	free_netdev(dev);
}

/**
 * nfp_net_null_add_device - callback for CPP devices being added
 * @cpp:	CPP handle
 */
static int nfp_net_null_probe(struct platform_device *pdev)
{
	struct nfp_device *nfp;
	uint32_t model;
	struct nfp_net_null *np;
	void *tmp = NULL;
	struct nfp_phymod *phy;

	nfp = nfp_device_open(pdev->id);
	if (nfp == NULL) {
		dev_err(&pdev->dev, "NFP Device %d does not exist.\n",
			pdev->id);
		return -ENODEV;
	}

	model = nfp_cpp_model(nfp_device_cpp(nfp));
	if (!NFP_CPP_MODEL_IS_6000(model)) {
		/* TODO: Add NFP3200 support */
		nfp_device_close(nfp);
		return -ENODEV;
	}

	np = kzalloc(sizeof(*np), GFP_KERNEL);
	if (!np) {
		nfp_device_close(nfp);
		return -ENOMEM;
	}

	np->nfp = nfp;
	np->ports = 0;
	np->parent = &pdev->dev;

	for (phy = nfp_phymod_next(nfp, &tmp);
	     phy && np->ports < ARRAY_SIZE(np->port);
	     phy = nfp_phymod_next(nfp, &tmp)) {
		int err;

		err = nfp_net_null_create(np, np->ports, phy);
		if (err < 0)
			continue;

		np->ports++;
	}

	platform_set_drvdata(pdev, np);

	return 0;
}

/**
 * nfp_net_null_remove_device - callback for removing CPP devices
 * @cpp:	CPP handle
 */
static int nfp_net_null_remove(struct platform_device *pdev)
{
	struct nfp_net_null *np = platform_get_drvdata(pdev);
	int port;

	for (port = 0; port < np->ports; port++)
		nfp_net_null_destroy(np, port);

	nfp_device_close(np->nfp);

	platform_set_drvdata(pdev, NULL);
	kfree(np);

	return 0;
}

static struct platform_driver nfp_net_null_driver = {
	.probe = nfp_net_null_probe,
	.remove = nfp_net_null_remove,
	.driver = {
		.name = NFP_NET_NULL_TYPE,
	},
};

/*
 *		Driver Initialization
 */

int __init nfp_net_null_init(void)
{
	int err;

	err = platform_driver_register(&nfp_net_null_driver);
	if (err)
		return err;

	pr_info("NFP Null Network Driver, Copyright (C) 2014 Netronome Systems\n");

	return 0;
}

void nfp_net_null_exit(void)
{
	platform_driver_unregister(&nfp_net_null_driver);
}

/* vim: set shiftwidth=8 noexpandtab:  */
