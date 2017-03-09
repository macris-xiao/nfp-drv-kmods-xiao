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
#include <linux/pci.h>

struct dentry;
struct pci_dev;
struct platform_device;

struct nfp_cpp;
struct nfp_cpp_area;
struct nfp_eth_table;

/**
 * struct nfp_pf - NFP PF-specific device structure
 * @pdev:		Backpointer to PCI device
 * @cpp:		Pointer to the CPP handle
 * @nfp_dev_cpp:	Pointer to the NFP Device handle
 * @nfp_net_vnic:	Handle for ARM VNIC device
 * @ctrl_area:		Pointer to the CPP area for the control BAR
 * @tx_area:		Pointer to the CPP area for the TX queues
 * @rx_area:		Pointer to the CPP area for the FL/RX queues
 * @irq_entries:	Array of MSI-X entries for all ports
 * @msix:		Single MSI-X entry for non-netdev mode event monitor
 * @limit_vfs:		Number of VFs supported by firmware (~0 for PCI limit)
 * @num_vfs:		Number of SR-IOV VFs enabled
 * @fw_loaded:		Is the firmware loaded?
 * @eth_tbl:		NSP ETH table
 * @ddir:		Per-device debugfs directory
 * @num_ports:		Number of adapter ports app firmware supports
 * @num_netdevs:	Number of netdevs spawned
 * @ports:		Linked list of port structures (struct nfp_net)
 */
struct nfp_pf {
	struct pci_dev *pdev;

	struct nfp_cpp *cpp;
	struct platform_device *nfp_dev_cpp;
	struct platform_device *nfp_net_vnic;

	struct nfp_cpp_area *ctrl_area;
	struct nfp_cpp_area *tx_area;
	struct nfp_cpp_area *rx_area;

	struct msix_entry *irq_entries;

	struct msix_entry msix;

	unsigned int limit_vfs;
	unsigned int num_vfs;

	bool fw_loaded;

	struct nfp_eth_table *eth_tbl;

	struct dentry *ddir;

	unsigned int num_ports;
	unsigned int num_netdevs;

	struct list_head ports;
};

extern int nfp_dev_cpp;
extern bool nfp_net_vnic;

extern struct pci_driver nfp_netvf_pci_driver;

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
