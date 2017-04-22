/*
 * Copyright (C) 2015-2017 Netronome Systems, Inc.
 *
 * This software is dual licensed under the GNU General License Version 2,
 * June 1991 as shown in the file COPYING in the top-level directory of this
 * source tree or the BSD 2-Clause License provided below.  You have the
 * option to license this software under the complete terms of either license.
 *
 * The BSD 2-Clause License:
 *
 *     Redistribution and use in source and binary forms, with or
 *     without modification, are permitted provided that the following
 *     conditions are met:
 *
 *      1. Redistributions of source code must retain the above
 *         copyright notice, this list of conditions and the following
 *         disclaimer.
 *
 *      2. Redistributions in binary form must reproduce the above
 *         copyright notice, this list of conditions and the following
 *         disclaimer in the documentation and/or other materials
 *         provided with the distribution.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
 * NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS
 * BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN
 * ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
 * CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */

/*
 * nfp_main.h
 * Author: Jason McMullan <jason.mcmullan@netronome.com>
 */

#ifndef NFP_MAIN_H
#define NFP_MAIN_H

#include <linux/list.h>
#include <linux/types.h>
#include <linux/msi.h>
#include <linux/mutex.h>
#include <linux/pci.h>
#include <linux/workqueue.h>

struct dentry;
struct device;
struct devlink_ops;
struct pci_dev;
struct platform_device;

struct nfp_cpp;
struct nfp_cpp_area;
struct nfp_eth_table;
struct nfp_hwinfo;
struct nfp_mip;
struct nfp_net;
struct nfp_nsp_identify;
struct nfp_rtsym_table;

/**
 * struct nfp_pf - NFP PF-specific device structure
 * @pdev:		Backpointer to PCI device
 * @cpp:		Pointer to the CPP handle
 * @app:		Pointer to the APP handle
 * @nfp_dev_cpp:	Pointer to the NFP Device handle
 * @nfp_net_vnic:	Handle for ARM VNIC device
 * @data_vnic_bar:	Pointer to the CPP area for the data vNICs' BARs
 * @ctrl_vnic_bar:	Pointer to the CPP area for the ctrl vNIC's BAR
 * @qc_area:		Pointer to the CPP area for the queues
 * @irq_entries:	Array of MSI-X entries for all vNICs
 * @msix:		Single MSI-X entry for non-netdev mode event monitor
 * @limit_vfs:		Number of VFs supported by firmware (~0 for PCI limit)
 * @num_vfs:		Number of SR-IOV VFs enabled
 * @fw_loaded:		Is the firmware loaded?
 * @ctrl_vnic:		Pointer to the control vNIC if available
 * @debug_ctrl_netdev:	Pointer to "debug pipe" netdev of the control vNIC
 * @mip:		MIP handle
 * @rtbl:		RTsym table
 * @hwinfo:		HWInfo table
 * @eth_tbl:		NSP ETH table
 * @nspi:		NSP identification info
 * @hwmon_dev:		pointer to hwmon device
 * @ddir:		Per-device debugfs directory
 * @max_data_vnics:	Number of data vNICs app firmware supports
 * @num_vnics:		Number of vNICs spawned
 * @vnics:		Linked list of vNIC structures (struct nfp_net)
 * @ports:		Linked list of port structures (struct nfp_port)
 * @port_refresh_work:	Work entry for taking netdevs out
 * @lock:		Protects all fields which may change after probe
 */
struct nfp_pf {
	struct pci_dev *pdev;

	struct nfp_cpp *cpp;

	struct nfp_app *app;

	struct platform_device *nfp_dev_cpp;
	struct platform_device *nfp_net_vnic;

	struct nfp_cpp_area *data_vnic_bar;
	struct nfp_cpp_area *ctrl_vnic_bar;
	struct nfp_cpp_area *qc_area;

	struct msix_entry *irq_entries;

	struct msix_entry msix;

	unsigned int limit_vfs;
	unsigned int num_vfs;

	bool fw_loaded;

	struct nfp_net *ctrl_vnic;
	struct net_device *debug_ctrl_netdev;

	const struct nfp_mip *mip;
	struct nfp_rtsym_table *rtbl;
	struct nfp_hwinfo *hwinfo;
	struct nfp_eth_table *eth_tbl;
	struct nfp_nsp_identify *nspi;

	struct device *hwmon_dev;

	struct dentry *ddir;

	unsigned int max_data_vnics;
	unsigned int num_vnics;

	struct list_head vnics;
	struct list_head ports;
	struct work_struct port_refresh_work;
	struct mutex lock;
};

extern int nfp_dev_cpp;
extern bool nfp_net_vnic;

extern struct pci_driver nfp_netvf_pci_driver;

extern const struct devlink_ops nfp_devlink_ops;

#ifdef CONFIG_NFP_NET_PF
int nfp_net_pci_probe(struct nfp_pf *pf, bool nfp_reset);
void nfp_net_pci_remove(struct nfp_pf *pf);
#else
static inline int nfp_net_pci_probe(struct nfp_pf *pf, bool nfp_reset)
{
	return -ENODEV;
}

static inline void nfp_net_pci_remove(struct nfp_pf *pf)
{
}
#endif

int nfp_hwmon_register(struct nfp_pf *pf);
void nfp_hwmon_unregister(struct nfp_pf *pf);

struct nfp_eth_table_port *
nfp_net_find_port(struct nfp_eth_table *eth_tbl, unsigned int id);
void
nfp_net_get_mac_addr(struct nfp_pf *pf, struct nfp_net *nn, unsigned int id);

bool nfp_ctrl_tx(struct nfp_net *nn, struct sk_buff *skb);

int nfp_ctrl_debug_start(struct nfp_pf *pf);
void nfp_ctrl_debug_stop(struct nfp_pf *pf);
void nfp_ctrl_debug_rx(struct nfp_pf *pf, struct sk_buff *skb);
void nfp_ctrl_debug_deliver_tx(struct nfp_pf *pf, struct sk_buff *skb);

#define NFP_DEV_CPP_TYPE	"nfp-dev-cpp"

#ifdef CONFIG_NFP_USER_SPACE_CPP
int nfp_dev_cpp_init(void);
void nfp_dev_cpp_exit(void);
#else
static inline int nfp_dev_cpp_init(void)
{
	return -ENODEV;
}

static inline void nfp_dev_cpp_exit(void)
{
}
#endif

#endif /* NFP_MAIN_H */
