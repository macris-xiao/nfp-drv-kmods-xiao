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
 * nfp_net_main.c
 * Netronome network device driver: Main entry point
 * Authors: Jakub Kicinski <jakub.kicinski@netronome.com>
 *          Alejandro Lucero <alejandro.lucero@netronome.com>
 *          Jason McMullan <jason.mcmullan@netronome.com>
 *          Rolf Neugebauer <rolf.neugebauer@netronome.com>
 */

#include <linux/etherdevice.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/lockdep.h>
#include <linux/pci.h>
#include <linux/pci_regs.h>
#include <linux/msi.h>
#include <linux/random.h>
#include <linux/rtnetlink.h>

#include "nfpcore/nfp.h"
#include "nfpcore/nfp_cpp.h"
#include "nfpcore/nfp_nffw.h"
#include "nfpcore/nfp_nsp.h"
#include "nfpcore/nfp6000_pcie.h"
#include "nfp_app.h"
#include "nfp_net_compat.h"
#include "nfp_net_ctrl.h"
#include "nfp_net.h"
#include "nfp_main.h"
#include "nfp_port.h"

#define NFP_PF_CSR_SLICE_SIZE	(32 * 1024)

static int nfp_is_ready(struct nfp_cpp *cpp)
{
	const char *cp;
	long state;
	int err;

	cp = nfp_hwinfo_lookup(cpp, "board.state");
	if (!cp)
		return 0;

	err = kstrtol(cp, 0, &state);
	if (err < 0)
		return 0;

	return state == 15;
}

/**
 * nfp_net_map_area() - Help function to map an area
 * @cpp:    NFP CPP handler
 * @name:   Name for the area
 * @target: CPP target
 * @addr:   CPP address
 * @size:   Size of the area
 * @area:   Area handle (returned).
 *
 * This function is primarily to simplify the code in the main probe
 * function. To undo the effect of this functions call
 * @nfp_cpp_area_release_free(*area);
 *
 * Return: Pointer to memory mapped area or ERR_PTR
 */
static u8 __iomem *nfp_net_map_area(struct nfp_cpp *cpp,
				    const char *name, int isl, int target,
				    unsigned long long addr, unsigned long size,
				    struct nfp_cpp_area **area)
{
	u8 __iomem *res;
	u32 dest;
	int err;

	dest = NFP_CPP_ISLAND_ID(target, NFP_CPP_ACTION_RW, 0, isl);

	*area = nfp_cpp_area_alloc_with_name(cpp, dest, name, addr, size);
	if (!*area) {
		err = -EIO;
		goto err_area;
	}

	err = nfp_cpp_area_acquire(*area);
	if (err < 0)
		goto err_acquire;

	res = nfp_cpp_area_iomem(*area);
	if (!res) {
		err = -EIO;
		goto err_map;
	}

	return res;

err_map:
	nfp_cpp_area_release(*area);
err_acquire:
	nfp_cpp_area_free(*area);
err_area:
	return (u8 __iomem *)ERR_PTR(err);
}

/**
 * nfp_net_get_mac_addr() - Get the MAC address.
 * @nn:       NFP Network structure
 * @cpp:      NFP CPP handle
 * @id:	      NFP port id
 *
 * First try to get the MAC address from NSP ETH table. If that
 * fails try HWInfo.  As a last resort generate a random address.
 */
void
nfp_net_get_mac_addr(struct nfp_net *nn, struct nfp_cpp *cpp, unsigned int id)
{
	struct nfp_eth_table_port *eth_port;
	struct nfp_net_dp *dp = &nn->dp;
	u8 mac_addr[ETH_ALEN];
	const char *mac_str;
	char name[32];

	eth_port = __nfp_port_get_eth_port(nn->port);
	if (eth_port) {
		ether_addr_copy(dp->netdev->dev_addr, eth_port->mac_addr);
		ether_addr_copy(dp->netdev->perm_addr, eth_port->mac_addr);
		return;
	}

	snprintf(name, sizeof(name), "eth%d.mac", id);

	mac_str = nfp_hwinfo_lookup(cpp, name);
	if (!mac_str) {
		dev_warn(dp->dev, "Can't lookup MAC address. Generate\n");
		eth_hw_addr_random(dp->netdev);
		return;
	}

	if (sscanf(mac_str, "%02hhx:%02hhx:%02hhx:%02hhx:%02hhx:%02hhx",
		   &mac_addr[0], &mac_addr[1], &mac_addr[2],
		   &mac_addr[3], &mac_addr[4], &mac_addr[5]) != 6) {
		dev_warn(dp->dev,
			 "Can't parse MAC address (%s). Generate.\n", mac_str);
		eth_hw_addr_random(dp->netdev);
		return;
	}

	ether_addr_copy(dp->netdev->dev_addr, mac_addr);
	ether_addr_copy(dp->netdev->perm_addr, mac_addr);
}

struct nfp_eth_table_port *
nfp_net_find_port(struct nfp_eth_table *eth_tbl, unsigned int id)
{
	int i;

	for (i = 0; eth_tbl && i < eth_tbl->count; i++)
		if (eth_tbl->ports[i].eth_index == id)
			return &eth_tbl->ports[i];

	return NULL;
}

static int
nfp_net_pf_rtsym_read_optional(struct nfp_pf *pf, const char *format,
			       unsigned int default_val)
{
	char name[256];
	int err = 0;
	u64 val;

	snprintf(name, sizeof(name), format, nfp_cppcore_pcie_unit(pf->cpp));

	val = nfp_rtsym_read_le(pf->cpp, name, &err);
	if (err) {
		if (err == -ENOENT)
			return default_val;
		nfp_err(pf->cpp, "Unable to read symbol %s\n", name);
		return err;
	}

	return val;
}

static int nfp_net_pf_get_num_ports(struct nfp_pf *pf)
{
	return nfp_net_pf_rtsym_read_optional(pf, "nfd_cfg_pf%u_num_ports", 1);
}

static int nfp_net_pf_get_app_id(struct nfp_pf *pf)
{
	return nfp_net_pf_rtsym_read_optional(pf, "_pf%u_net_app_id",
					      NFP_APP_CORE_NIC);
}

static u8 __iomem *
nfp_net_pf_map_rtsym(struct nfp_pf *pf, const char *name, const char *sym_fmt,
		     unsigned int min_size, struct nfp_cpp_area **area)
{
	const struct nfp_rtsym *sym;
	char pf_symbol[256];
	u8 __iomem *mem;

	snprintf(pf_symbol, sizeof(pf_symbol), sym_fmt,
		 nfp_cppcore_pcie_unit(pf->cpp));

	sym = nfp_rtsym_lookup(pf->cpp, pf_symbol);
	if (!sym) {
		nfp_err(pf->cpp, "Failed to find PF symbol %s\n", pf_symbol);
		return (u8 __iomem *)ERR_PTR(-ENOENT);
	}

	if (sym->size < min_size) {
		nfp_err(pf->cpp, "PF symbol %s too small\n", pf_symbol);
		return (u8 __iomem *)ERR_PTR(-EINVAL);
	}

	mem = nfp_net_map_area(pf->cpp, name, sym->domain, sym->target,
			       sym->addr, sym->size, area);
	if (IS_ERR(mem)) {
		nfp_err(pf->cpp, "Failed to map PF symbol %s: %ld\n",
			pf_symbol, PTR_ERR(mem));
		return mem;
	}

	return mem;
}

static void nfp_net_pf_free_vnic(struct nfp_pf *pf, struct nfp_net *nn)
{
	nfp_port_free(nn->port);
	list_del(&nn->vnic_list);
	pf->num_vnics--;
	nfp_net_free(nn);
}

static void nfp_net_pf_free_vnics(struct nfp_pf *pf)
{
	struct nfp_net *nn;

	while (!list_empty(&pf->vnics)) {
		nn = list_first_entry(&pf->vnics, struct nfp_net, vnic_list);
		nfp_net_pf_free_vnic(pf, nn);
	}
}

static struct nfp_net *
nfp_net_pf_alloc_vnic(struct nfp_pf *pf, bool needs_netdev,
		      void __iomem *ctrl_bar, void __iomem *qc_bar,
		      int stride, unsigned int eth_id)
{
	u32 tx_base, rx_base, n_tx_rings, n_rx_rings;
	struct nfp_net *nn;
	int err;

	tx_base = readl(ctrl_bar + NFP_NET_CFG_START_TXQ);
	rx_base = readl(ctrl_bar + NFP_NET_CFG_START_RXQ);
	n_tx_rings = readl(ctrl_bar + NFP_NET_CFG_MAX_TXRINGS);
	n_rx_rings = readl(ctrl_bar + NFP_NET_CFG_MAX_RXRINGS);

	/* Allocate and initialise the vNIC */
	nn = nfp_net_alloc(pf->pdev, needs_netdev, n_tx_rings, n_rx_rings);
	if (IS_ERR(nn))
		return nn;

	nn->app = pf->app;
	nfp_net_get_fw_version(&nn->fw_ver, ctrl_bar);
	nn->dp.ctrl_bar = ctrl_bar;
	nn->tx_bar = qc_bar + tx_base * NFP_QCP_QUEUE_ADDR_SZ;
	nn->rx_bar = qc_bar + rx_base * NFP_QCP_QUEUE_ADDR_SZ;
	nn->dp.is_vf = 0;
	nn->stride_rx = stride;
	nn->stride_tx = stride;

	err = nfp_app_vnic_init(pf->app, nn, eth_id);
	if (err) {
		nfp_net_free(nn);
		return ERR_PTR(err);
	}

	pf->num_vnics++;
	list_add_tail(&nn->vnic_list, &pf->vnics);

	return nn;
}

static int
nfp_net_pf_init_vnic(struct nfp_pf *pf, struct nfp_net *nn, unsigned int id)
{
	int err;

	/* Get ME clock frequency from ctrl BAR
	 * XXX for now frequency is hardcoded until we figure out how
	 * to get the value from nfp-hwinfo into ctrl bar
	 */
	nn->me_freq_mhz = 1200;

	err = nfp_net_init(nn);
	if (err)
		return err;

	nfp_net_debugfs_vnic_add(nn, pf->ddir, id);

	if (nn->port) {
		err = nfp_devlink_port_register(pf->app, nn->port);
		if (err)
			goto err_dfs_clean;
	}

	nfp_net_info(nn);

	return 0;

err_dfs_clean:
	nfp_net_debugfs_dir_clean(&nn->debugfs_dir);
	nfp_net_clean(nn);
	return err;
}

static int
nfp_net_pf_alloc_vnics(struct nfp_pf *pf, void __iomem *ctrl_bar,
		       void __iomem *qc_bar, int stride)
{
	struct nfp_net *nn;
	unsigned int i;
	int err;

	for (i = 0; i < pf->max_data_vnics; i++) {
		nn = nfp_net_pf_alloc_vnic(pf, true, ctrl_bar, qc_bar,
					   stride, i);
		if (IS_ERR(nn)) {
			err = PTR_ERR(nn);
			goto err_free_prev;
		}

		ctrl_bar += NFP_PF_CSR_SLICE_SIZE;

		/* Kill the vNIC if app init marked it as invalid */
		if (nn->port && nn->port->type == NFP_PORT_INVALID) {
			nfp_net_pf_free_vnic(pf, nn);
			continue;
		}
	}

	if (list_empty(&pf->vnics))
		return -ENODEV;

	return 0;

err_free_prev:
	nfp_net_pf_free_vnics(pf);
	return err;
}

static void nfp_net_pf_clean_vnic(struct nfp_pf *pf, struct nfp_net *nn)
{
	if (nn->port)
		nfp_devlink_port_unregister(nn->port);
	nfp_net_debugfs_dir_clean(&nn->debugfs_dir);
	nfp_net_clean(nn);
	nfp_app_vnic_clean(pf->app, nn);
}

static int nfp_net_pf_alloc_irqs(struct nfp_pf *pf)
{
	unsigned int wanted_irqs, num_irqs, vnics_left, irqs_left;
	struct nfp_net *nn;

	/* Get MSI-X vectors */
	wanted_irqs = 0;
	list_for_each_entry(nn, &pf->vnics, vnic_list)
		wanted_irqs += NFP_NET_NON_Q_VECTORS + nn->dp.num_r_vecs;
	pf->irq_entries = kcalloc(wanted_irqs, sizeof(*pf->irq_entries),
				  GFP_KERNEL);
	if (!pf->irq_entries)
		return -ENOMEM;

	num_irqs = nfp_net_irqs_alloc(pf->pdev, pf->irq_entries,
				      NFP_NET_MIN_VNIC_IRQS * pf->num_vnics,
				      wanted_irqs);
	if (!num_irqs) {
		nfp_warn(pf->cpp, "Unable to allocate MSI-X vectors\n");
		kfree(pf->irq_entries);
		return -ENOMEM;
	}

	/* Distribute IRQs to vNICs */
	irqs_left = num_irqs;
	vnics_left = pf->num_vnics;
	list_for_each_entry(nn, &pf->vnics, vnic_list) {
		unsigned int n;

		n = min(NFP_NET_NON_Q_VECTORS + nn->dp.num_r_vecs,
			DIV_ROUND_UP(irqs_left, vnics_left));
		nfp_net_irqs_assign(nn, &pf->irq_entries[num_irqs - irqs_left],
				    n);
		irqs_left -= n;
		vnics_left--;
	}

	return 0;
}

static void nfp_net_pf_free_irqs(struct nfp_pf *pf)
{
	nfp_net_irqs_disable(pf->pdev);
	kfree(pf->irq_entries);
}

static int nfp_net_pf_init_vnics(struct nfp_pf *pf)
{
	struct nfp_net *nn;
	unsigned int id;
	int err;

	/* Finish vNIC init and register */
	id = 0;
	list_for_each_entry(nn, &pf->vnics, vnic_list) {
		err = nfp_net_pf_init_vnic(pf, nn, id);
		if (err)
			goto err_prev_deinit;

		id++;
	}

	return 0;

err_prev_deinit:
	list_for_each_entry_continue_reverse(nn, &pf->vnics, vnic_list)
		nfp_net_pf_clean_vnic(pf, nn);
	return err;
}

static int nfp_net_pf_app_init(struct nfp_pf *pf)
{
	int err;

	pf->app = nfp_app_alloc(pf, nfp_net_pf_get_app_id(pf));
	if (IS_ERR(pf->app))
		return PTR_ERR(pf->app);

	err = nfp_app_init(pf->app);
	if (err)
		goto err_free;

	return 0;

err_free:
	nfp_app_free(pf->app);
	return err;
}

static void nfp_net_pf_app_clean(struct nfp_pf *pf)
{
	nfp_app_free(pf->app);
	pf->app = NULL;
}

static void nfp_net_pci_remove_finish(struct nfp_pf *pf)
{
	nfp_net_debugfs_dir_clean(&pf->ddir);

	nfp_net_pf_free_irqs(pf);

	nfp_net_pf_app_clean(pf);

	nfp_cpp_area_release_free(pf->qc_area);
	nfp_cpp_area_release_free(pf->data_vnic_bar);
}

static int
nfp_net_eth_port_update(struct nfp_cpp *cpp, struct nfp_port *port,
			struct nfp_eth_table *eth_table)
{
	struct nfp_eth_table_port *eth_port;

	ASSERT_RTNL();

	eth_port = nfp_net_find_port(eth_table, port->eth_id);
	if (!eth_port) {
		set_bit(NFP_PORT_CHANGED, &port->flags);
		nfp_warn(cpp, "Warning: port #%d not present after reconfig\n",
			 port->eth_id);
		return -EIO;
	}
	if (eth_port->override_changed) {
		nfp_warn(cpp, "Port #%d config changed, unregistering. Reboot required before port will be operational again.\n", port->eth_id);
		port->type = NFP_PORT_INVALID;
	}

	memcpy(port->eth_port, eth_port, sizeof(*eth_port));

	return 0;
}

int nfp_net_refresh_port_table_sync(struct nfp_pf *pf)
{
	struct nfp_eth_table *eth_table;
	struct nfp_net *nn, *next;
	struct nfp_port *port;

	lockdep_assert_held(&pf->lock);

	/* Check for nfp_net_pci_remove() racing against us */
	if (list_empty(&pf->vnics))
		return 0;

	/* Update state of all ports */
	rtnl_lock();
	list_for_each_entry(port, &pf->ports, port_list)
		clear_bit(NFP_PORT_CHANGED, &port->flags);

	eth_table = nfp_eth_read_ports(pf->cpp);
	if (!eth_table) {
		list_for_each_entry(port, &pf->ports, port_list)
			if (__nfp_port_get_eth_port(port))
				set_bit(NFP_PORT_CHANGED, &port->flags);
		rtnl_unlock();
		nfp_err(pf->cpp, "Error refreshing port config!\n");
		return -EIO;
	}

	list_for_each_entry(port, &pf->ports, port_list)
		if (__nfp_port_get_eth_port(port))
			nfp_net_eth_port_update(pf->cpp, port, eth_table);
	rtnl_unlock();

	kfree(eth_table);

	/* Shoot off the ports which became invalid */
	list_for_each_entry_safe(nn, next, &pf->vnics, vnic_list) {
		if (!nn->port || nn->port->type != NFP_PORT_INVALID)
			continue;

		nfp_net_pf_clean_vnic(pf, nn);
		nfp_net_pf_free_vnic(pf, nn);
	}

	if (list_empty(&pf->vnics))
		nfp_net_pci_remove_finish(pf);

	return 0;
}

static void nfp_net_refresh_vnics(struct work_struct *work)
{
	struct nfp_pf *pf = container_of(work, struct nfp_pf,
					 port_refresh_work);

	mutex_lock(&pf->lock);
	nfp_net_refresh_port_table_sync(pf);
	mutex_unlock(&pf->lock);
}

void nfp_net_refresh_port_table(struct nfp_port *port)
{
	struct nfp_pf *pf = port->app->pf;

	set_bit(NFP_PORT_CHANGED, &port->flags);

	schedule_work(&pf->port_refresh_work);
}

int nfp_net_refresh_eth_port(struct nfp_port *port)
{
	struct nfp_cpp *cpp = port->app->cpp;
	struct nfp_eth_table *eth_table;
	int ret;

	clear_bit(NFP_PORT_CHANGED, &port->flags);

	eth_table = nfp_eth_read_ports(cpp);
	if (!eth_table) {
		set_bit(NFP_PORT_CHANGED, &port->flags);
		nfp_err(cpp, "Error refreshing port state table!\n");
		return -EIO;
	}

	ret = nfp_net_eth_port_update(cpp, port, eth_table);

	kfree(eth_table);

	return ret;
}

/*
 * PCI device functions
 */
int nfp_net_pci_probe(struct nfp_pf *pf, bool nfp_reset)
{
	struct nfp_net_fw_version fw_ver;
	u8 __iomem *ctrl_bar, *qc_bar;
	u32 ctrl_bar_sz;
	int stride;
	int err;

	INIT_WORK(&pf->port_refresh_work, nfp_net_refresh_vnics);

	/* Verify that the board has completed initialization */
	if ((!pf->fw_loaded && nfp_reset) || !nfp_is_ready(pf->cpp)) {
		nfp_err(pf->cpp, "NFP is not ready for NIC operation.\n");
		return 1;
	}

	mutex_lock(&pf->lock);
	pf->max_data_vnics = nfp_net_pf_get_num_ports(pf);
	if ((int)pf->max_data_vnics < 0) {
		err = pf->max_data_vnics;
		goto err_unlock;
	}

	ctrl_bar_sz = pf->max_data_vnics * NFP_PF_CSR_SLICE_SIZE;
	ctrl_bar = nfp_net_pf_map_rtsym(pf, "net.ctrl", "_pf%d_net_bar0",
					ctrl_bar_sz, &pf->data_vnic_bar);
	if (IS_ERR(ctrl_bar)) {
		err = PTR_ERR(ctrl_bar) == -ENOENT ? 1 : PTR_ERR(ctrl_bar);
		goto err_unlock;
	}

	nfp_net_get_fw_version(&fw_ver, ctrl_bar);
	if (fw_ver.resv || fw_ver.class != NFP_NET_CFG_VERSION_CLASS_GENERIC) {
		nfp_err(pf->cpp, "Unknown Firmware ABI %d.%d.%d.%d\n",
			fw_ver.resv, fw_ver.class, fw_ver.major, fw_ver.minor);
		err = -EINVAL;
		goto err_ctrl_unmap;
	}

	/* Determine stride */
	if (nfp_net_fw_ver_eq(&fw_ver, 0, 0, 0, 1)) {
		stride = 2;
		nfp_warn(pf->cpp, "OBSOLETE Firmware detected - VF isolation not available\n");
	} else {
		switch (fw_ver.major) {
		case 1 ... 4:
			stride = 4;
			break;
		default:
			nfp_err(pf->cpp, "Unsupported Firmware ABI %d.%d.%d.%d\n",
				fw_ver.resv, fw_ver.class,
				fw_ver.major, fw_ver.minor);
			err = -EINVAL;
			goto err_ctrl_unmap;
		}
	}

	/* Map queues */
	qc_bar = nfp_net_map_area(pf->cpp, "net.qc", 0, 0,
				  NFP_PCIE_QUEUE(0), NFP_QCP_QUEUE_AREA_SZ,
				  &pf->qc_area);
	if (IS_ERR(qc_bar)) {
		nfp_err(pf->cpp, "Failed to map Queue Controller area.\n");
		err = PTR_ERR(qc_bar);
		goto err_ctrl_unmap;
	}

	err = nfp_net_pf_app_init(pf);
	if (err)
		goto err_unmap_qc;

	pf->ddir = nfp_net_debugfs_device_add(pf->pdev);

	/* Allocate the vnics and do basic init */
	err = nfp_net_pf_alloc_vnics(pf, ctrl_bar, qc_bar, stride);
	if (err)
		goto err_clean_ddir;

	err = nfp_net_pf_alloc_irqs(pf);
	if (err)
		goto err_free_vnics;

	err = nfp_net_pf_init_vnics(pf);
	if (err)
		goto err_free_irqs;

	mutex_unlock(&pf->lock);

	return 0;

err_free_irqs:
	nfp_net_pf_free_irqs(pf);
err_free_vnics:
	nfp_net_pf_free_vnics(pf);
err_clean_ddir:
	nfp_net_debugfs_dir_clean(&pf->ddir);
	nfp_net_pf_app_clean(pf);
err_unmap_qc:
	nfp_cpp_area_release_free(pf->qc_area);
err_ctrl_unmap:
	nfp_cpp_area_release_free(pf->data_vnic_bar);
err_unlock:
	mutex_unlock(&pf->lock);
	return err;
}

void nfp_net_pci_remove(struct nfp_pf *pf)
{
	struct nfp_net *nn;

	mutex_lock(&pf->lock);
	if (list_empty(&pf->vnics))
		goto out;

	list_for_each_entry(nn, &pf->vnics, vnic_list)
		nfp_net_pf_clean_vnic(pf, nn);

	nfp_net_pf_free_vnics(pf);

	nfp_net_pci_remove_finish(pf);
out:
	mutex_unlock(&pf->lock);

	cancel_work_sync(&pf->port_refresh_work);
}
