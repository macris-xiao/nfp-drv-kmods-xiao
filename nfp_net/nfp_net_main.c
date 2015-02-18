/*
 * Copyright (C) 2014-2015 Netronome Systems, Inc. All rights reserved.
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
 *
 * @file kernel/nfp_net_main.c
 *
 * Netronome network device driver: Main entry point
 */

#include <linux/version.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/pci.h>
#include <linux/pci_regs.h>
#include <linux/msi.h>
#include <linux/random.h>
#include <linux/firmware.h>

#include <linux/ktime.h>
#include <linux/hrtimer.h>

#include "nfpcore/nfp.h"
#include "nfpcore/nfp_common.h"
#include "nfpcore/nfp_cpplib.h"
#include "nfpcore/nfp3200_pcie.h"
#include "nfpcore/nfp6000_pcie.h"
#include "nfpcore/nfp_platform.h"
#include "nfpcore/nfp_dev_cpp.h"
#include "nfpcore/nfp_ca.h"
#include "nfpcore/nfp_rtsym.h"
#include "nfpcore/nfp_hwinfo.h"

#include "nfp_net_compat.h"
#include "nfp_net_ctrl.h"
#include "nfp_net.h"
#include "nfp_net_nic.h"

/* Default FW names */
static char *nfp3200_net_fw = "netronome/nfp3200_net.cat";
static char *nfp6000_net_fw = "netronome/nfp6000_net.cat";
MODULE_FIRMWARE("netronome/nfp3200_net.cat");
MODULE_FIRMWARE("netronome/nfp6000_net.cat");

static bool fw_noload;
module_param(fw_noload, bool, 0444);
MODULE_PARM_DESC(fw_noload, "Do not load FW (default = False)");

static bool fw_stop_on_fail;
module_param(fw_stop_on_fail, bool, 0444);
MODULE_PARM_DESC(fw_stop_on_fail, "Stop if FW load fails (default = False)");

const char nfp_net_driver_name[] = "nfp_net";
const char nfp_net_driver_version[] = "0.1";

/*
 * Firmware loading functions
 */

/**
 * nfp_net_fw_select - Select a FW image for a given device
 */
static const char *nfp_net_fw_select(struct nfp_cpp *cpp)
{
	uint32_t model = nfp_cpp_model(cpp);

	/* TODO: For now we simply use the default values defined
	 * above.  However, in the future we should provide module
	 * parameters allowing a user to change the default.  This
	 * should also allow for overriding the default for individual
	 * cards only.  We may have a per device no load option too,
	 * in which case, nn->fw_name should be set to Null
	 */

	if (NFP_CPP_MODEL_IS_3200(model))
		return nfp3200_net_fw;
	else
		return nfp6000_net_fw;
}

/**
 * nfp_net_fw_load - Load the firmware image
 */
static int nfp_net_fw_load(struct pci_dev *pdev,
			   struct nfp_cpp *cpp)
{
	const struct firmware *fw;
	const char *fw_name;

	int err;

	if (fw_noload)
		return 0;

	fw_name = nfp_net_fw_select(cpp);

	if (!fw_name)
		return 0;

	err = request_firmware(&fw, fw_name, &pdev->dev);
	if (err < 0)
		goto err_request;

	err = nfp_ca_replay(cpp, fw->data, fw->size);
	release_firmware(fw);
	if (err < 0)
		goto err_replay;

	dev_info(&pdev->dev, "Loaded FW image: %s\n", fw_name);
	return 0;

err_request:
	dev_err(&pdev->dev, "Failed to request FW with %d.%s\n",
		err, fw_stop_on_fail ? "" : " Continuing...");
	return fw_stop_on_fail ? err : 0;
err_replay:
	dev_err(&pdev->dev, "FW loading failed with %d.%s",
		err, fw_stop_on_fail ? "" : " Continuing...");
	return fw_stop_on_fail ? err : 0;
}

/*
 * Helper functions
 */

/**
 * nfp_net_map_area - Help function to map an area
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
 */
static u8 __iomem *nfp_net_map_area(struct nfp_cpp *cpp,
				    const char *name, int isl, int target,
				    unsigned long long addr, unsigned long size,
				    struct nfp_cpp_area **area)
{
	u8 __iomem *res;
	int err;

	*area = nfp_cpp_area_alloc_with_name(
		cpp, NFP_CPP_ISLAND_ID(target, NFP_CPP_ACTION_RW, 0, isl),
		name, addr, size);
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
	return ERR_PTR(err);
}

/**
 * nfp_net_get_mac_addr - Get the MAC address.
 * First try to look up the MAC address in the HWINFO table. If that
 * fails generate a random address.
 */
static void nfp_net_get_mac_addr(struct nfp_net *nn, struct nfp_device *nfp_dev)
{
	const char *mac_str;
	u8 mac_addr[ETH_ALEN];

	mac_str = nfp_hwinfo_lookup(nfp_dev, "eth0.mac");
	if (!mac_str)
		mac_str = nfp_hwinfo_lookup(nfp_dev, "eth.mac");
	if (mac_str) {
		if (sscanf(mac_str, "%02hhx:%02hhx:%02hhx:%02hhx:%02hhx:%02hhx",
			   &mac_addr[0], &mac_addr[1], &mac_addr[2],
			   &mac_addr[3], &mac_addr[4], &mac_addr[5]) != 6) {
			dev_warn(&nn->pdev->dev,
				 "Can't parse MAC address (%s). Generate.",
				 mac_str);
			random_ether_addr(mac_addr);
		}
	} else {
		dev_warn(&nn->pdev->dev,
			 "Can't lookup MAC address. Generate\n");
		random_ether_addr(mac_addr);
	}
	ether_addr_copy(nn->netdev->dev_addr, mac_addr);
}

static int nfp_net_msix_map(struct nfp_net *nn, unsigned nr_entries)
{
	resource_size_t phys_addr;
	u32 table_offset;
	u8 msix_cap;
	u8 bir;
	struct pci_dev *pdev = nn->pdev;

	nn_dbg(nn, "pdev->msi_enabled: %d\n", pdev->msi_enabled);
	nn_dbg(nn, "pdev->msix_enabled: %d\n", pdev->msix_enabled);

	if (!pdev->msix_enabled)
		return 0;

#if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 10, 0)
	msix_cap = pdev->msix_cap;
#else
	msix_cap = pci_find_capability(pdev, PCI_CAP_ID_MSIX);
#endif

	pci_read_config_dword(pdev, msix_cap + PCI_MSIX_TABLE,
			      &table_offset);
	bir = (u8)(table_offset & PCI_MSIX_TABLE_BIR);
	table_offset &= PCI_MSIX_TABLE_OFFSET;
	phys_addr = pci_resource_start(pdev, bir) + table_offset;

	nn->msix_table =
		ioremap_nocache(phys_addr, nr_entries * PCI_MSIX_ENTRY_SIZE);

	return (!nn->msix_table) ? -ENOMEM : 0;
}

static void nfp_net_msix_unmap(void __iomem *addr)
{
	iounmap(addr);
}

/*
 * Platform device functions
 */
static int nfp_net_nic_probe(struct platform_device *plat)
{
	struct nfp_platform_data *pdata;
	struct nfp_net *nn;
	struct nfp_cpp *cpp;
	struct platform_device *dev_cpp = NULL;
	struct nfp_device *nfp_dev;
	struct device *dev;
	struct pci_dev *pdev;

	uint16_t interface;
	int pcie_pf;
	char pf_symbol[256];

	const struct nfp_rtsym *ctrl_sym;
	struct nfp_cpp_area *ctrl_area;
	u8 __iomem *ctrl_bar;

	int max_tx_rings, max_rx_rings;
	uint32_t tx_area_sz, rx_area_sz;
	uint32_t start_q;

	int err;

	pdata = nfp_platform_device_data(plat);
	BUG_ON(!pdata);

	cpp = pdata->cpp;

	interface = nfp_cpp_interface(cpp);

	/* We only support the PCI interface, as this relies
	 * upon the PCI.IN/PCI.OUT microcode interface.
	 */
	if (NFP_CPP_INTERFACE_TYPE_of(interface) != NFP_CPP_INTERFACE_TYPE_PCI)
		return -EINVAL;

	dev = nfp_cpp_device(cpp);
	if (!dev || !dev_is_pci(dev))
		return -EINVAL;

	pdev = to_pci_dev(dev);

	err = nfp_net_fw_load(pdev, cpp);
	if (err) {
		dev_err(&pdev->dev, "Failed to load FW\n");
		goto err_fw_load;
	}

	nfp_dev = nfp_device_from_cpp(cpp);
	if (!nfp_dev) {
		err = -ENODEV;
		goto err_open_dev;
	}

	pcie_pf = NFP_CPP_INTERFACE_UNIT_of(interface);

	snprintf(pf_symbol, sizeof(pf_symbol), "_pf%d_net_bar0", pcie_pf);

	ctrl_sym = nfp_rtsym_lookup(nfp_dev, pf_symbol);
	if (!ctrl_sym) {
		dev_err(&pdev->dev,
			"Failed to find PF BAR0 symbol %s\n", pf_symbol);
		err = -ENOENT;
		goto err_ctrl_lookup;
	}

	ctrl_bar = nfp_net_map_area(cpp, "net.ctrl",
				    ctrl_sym->domain, ctrl_sym->target,
				    ctrl_sym->addr, ctrl_sym->size, &ctrl_area);
	if (IS_ERR_OR_NULL(ctrl_bar)) {
		dev_err(&pdev->dev, "Failed to map PF BAR0\n");
		err = PTR_ERR(ctrl_bar);
		goto err_map_ctrl;
	}

	/* Find how many rings are supported */
	max_tx_rings = nn_readl(ctrl_bar, NFP_NET_CFG_MAX_TXRINGS);
	max_rx_rings = nn_readl(ctrl_bar, NFP_NET_CFG_MAX_RXRINGS);

	tx_area_sz = NFP_QCP_QUEUE_ADDR_SZ * max_tx_rings * 2;
	rx_area_sz = NFP_QCP_QUEUE_ADDR_SZ * max_rx_rings * 2;

	/* Allocate and initialise the netdev */
	nn = nfp_net_netdev_alloc(pdev, max_tx_rings, max_rx_rings);
	if (IS_ERR(nn)) {
		err = PTR_ERR(nn);
		goto err_nn_init;
	}

	nn->cpp = cpp;
	nn->nfp_dev_cpp = dev_cpp;
	nn->ctrl_area = ctrl_area;
	nn->ctrl_bar = ctrl_bar;
	nn->is_vf = 0;
	nn->is_nfp3200 = NFP_CPP_MODEL_IS_3200(nfp_cpp_model(cpp));

#ifdef NFP_NET_HRTIMER_6000
	if (!nn->is_nfp3200)
		nn->hrtimer = 1;
	else
		nn->hrtimer = 0;
#endif

	spin_lock_init(&nn->msilock);

	/* Map TX queues */
	start_q = nn_readl(ctrl_bar, NFP_NET_CFG_START_TXQ);
	nn->tx_bar = nfp_net_map_area(cpp, "net.tx", 0, 0,
				      NFP_PCIE_QUEUE(start_q),
				      tx_area_sz, &nn->tx_area);
	if (IS_ERR_OR_NULL(nn->tx_bar)) {
		nn_err(nn, "Failed to map TX area.\n");
		err = PTR_ERR(nn->tx_bar);
		goto err_map_tx;
	}

	/* Map RX queues */
	start_q = nn_readl(ctrl_bar, NFP_NET_CFG_START_RXQ);
	nn->rx_bar = nfp_net_map_area(cpp, "net.rx", 0, 0,
				      NFP_PCIE_QUEUE(start_q),
				      rx_area_sz, &nn->rx_area);
	if (IS_ERR_OR_NULL(nn->rx_bar)) {
		nn_err(nn, "Failed to map RX area.\n");
		err =  PTR_ERR(nn->rx_bar);
		goto err_map_rx;
	}

	/* Get MSI/MSI-X vectors */
	err = nfp_net_irqs_alloc(nn);
	if (!err)
		goto err_vec;

	err = nfp_net_msix_map(nn, 255);
	if (err < 0)
		goto err_map_msix_table;

	/* Get MAC address */
	nfp_net_get_mac_addr(nn, nfp_dev);

	/*
	 * Finalise
	 */
	err = nfp_net_netdev_init(nn->netdev);
	if (err)
		goto err_netdev_init;

	platform_set_drvdata(plat, nn);

	nfp_device_close(nfp_dev);

	nfp_net_info(nn);
	return 0;

err_netdev_init:
	if (nn->msix_table)
		nfp_net_msix_unmap(nn->msix_table);
err_map_msix_table:
	nfp_net_irqs_disable(nn);
err_vec:
	nfp_cpp_area_release_free(nn->rx_area);
err_map_rx:
	nfp_cpp_area_release_free(nn->tx_area);
err_map_tx:
	nfp_net_netdev_free(nn);
err_nn_init:
	nfp_cpp_area_release_free(ctrl_area);
err_map_ctrl:
err_ctrl_lookup:
	nfp_device_close(nfp_dev);
err_open_dev:
err_fw_load:
	return err;
}

static int nfp_net_nic_remove(struct platform_device *plat)
{
	struct nfp_net *nn = platform_get_drvdata(plat);

	if (!nn)
		return 0;

	nfp_net_netdev_clean(nn->netdev);

	if (nn->msix_table)
		nfp_net_msix_unmap(nn->msix_table);
	nfp_net_irqs_disable(nn);

	nfp_cpp_area_release_free(nn->rx_area);
	nfp_cpp_area_release_free(nn->tx_area);
	nfp_cpp_area_release_free(nn->ctrl_area);

	nfp_net_netdev_free(nn);

	platform_set_drvdata(plat, NULL);

	return 0;
}

static struct platform_driver nfp_net_nic_driver = {
	.probe = nfp_net_nic_probe,
	.remove = nfp_net_nic_remove,
	.driver = {
		.name = NFP_NET_NIC_TYPE,
	},
};

/*
 *		Driver Initialization
 */

int __init nfp_net_nic_init(void)
{
	int err;

	err = platform_driver_register(&nfp_net_nic_driver);
	if (err)
		return err;

	pr_info("%s: NFP NIC Network Driver, Copyright (C) 2014-2015 Netronome Systems\n", NFP_NET_NIC_TYPE);

	return 0;
}

void nfp_net_nic_exit(void)
{
	platform_driver_unregister(&nfp_net_nic_driver);
}

/*
 * Local variables:
 * c-file-style: "Linux"
 * indent-tabs-mode: t
 * End:
 */
/* vim: set shiftwidth=8 noexpandtab:  */
