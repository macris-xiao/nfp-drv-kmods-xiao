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
#include "nfpcore/nfp_cpp.h"
#include "nfpcore/nfp_nffw.h"
#include "nfpcore/nfp3200_pcie.h"
#include "nfpcore/nfp6000_pcie.h"
#include "nfpcore/nfp_dev_cpp.h"

#include "nfp_net_compat.h"
#include "nfp_net_ctrl.h"
#include "nfp_net.h"

#include "nfp_modinfo.h"

static bool nfp_dev_cpp = 1;
module_param(nfp_dev_cpp, bool, 0444);
MODULE_PARM_DESC(nfp_dev_cpp,
		 "Enable NFP CPP user-space access (default = True)");

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

static bool nfp_fallback = 1;
module_param(nfp_fallback, bool, 0444);
MODULE_PARM_DESC(nfp_fallback,
		 "Fallback to nfp.ko behaviour if no suitable FW is present (default = True)");

static bool nfp_reset = 1;
module_param(nfp_reset, bool, 0444);
MODULE_PARM_DESC(nfp_reset,
		 "Soft reset the NFP during firmware unload (default = True)");

const char nfp_net_driver_name[] = "nfp_net";
const char nfp_net_driver_version[] = "0.1";

static const struct pci_device_id nfp_net_pci_device_ids[] = {
	{ PCI_VENDOR_ID_NETRONOME, PCI_DEVICE_NFP6000,
	  PCI_VENDOR_ID_NETRONOME, PCI_ANY_ID /* PCI_DEVICE_NFP6000 */,
	  PCI_ANY_ID, 0,
	},
	{ PCI_VENDOR_ID_NETRONOME, PCI_DEVICE_NFP3200,
	  PCI_VENDOR_ID_NETRONOME, PCI_DEVICE_NFP3200,
	  PCI_ANY_ID, 0,
	},
	{ PCI_VENDOR_ID_NETRONOME, PCI_DEVICE_NFP3200,
	  PCI_VENDOR_ID_NETRONOME, PCI_DEVICE_NFP3240,
	  PCI_ANY_ID, 0,
	},
	{ 0, } /* Required last entry. */
};
MODULE_DEVICE_TABLE(pci, nfp_net_pci_device_ids);

/* Firmware loading functions */

/**
 * nfp_net_fw_select() - Select a FW image for a given device
 * @pdev:       PCI Device structure
 *
 * Return: Name of the firmware image to load
 */
static const char *nfp_net_fw_select(struct pci_dev *pdev)
{
	/* TODO: For now we simply use the default values defined
	 * above.  However, in the future we should provide module
	 * parameters allowing a user to change the default.  This
	 * should also allow for overriding the default for individual
	 * cards only.  We may have a per device no load option too,
	 * in which case, nn->fw_name should be set to Null
	 */

	if (pdev->device == PCI_DEVICE_NFP3200)
		return nfp3200_net_fw;
	else
		return nfp6000_net_fw;
}

/**
 * nfp_net_fw_load() - Load the firmware image
 * @pdev:       PCI Device structure
 * @nfp:        NFP Device structure
 *
 * Return: -ERRNO, 0 for no firmware loaded, 1 for firmware loaded
 */
static int nfp_net_fw_load(struct pci_dev *pdev,
			   struct nfp_device *nfp)
{
	struct nfp_cpp *cpp = nfp_device_cpp(nfp);
	const struct firmware *fw;
	const char *fw_name;
	int timeout = 30; /* Seconds */
	int err;

	if (fw_noload)
		return 0;

	fw_name = nfp_net_fw_select(pdev);

	if (!fw_name)
		return 0;

	err = request_firmware(&fw, fw_name, &pdev->dev);
	if (err < 0)
		goto err_request;

	if (NFP_CPP_MODEL_IS_6000(nfp_cpp_model(cpp))) {
		/* Make sure we have the ARM service processor */
		dev_info(&pdev->dev, "Waiting for NSP to respond (%d sec max).\n", timeout);
		for (; timeout > 0; timeout--) {
			err = nfp_nsp_command(nfp, SPCODE_NOOP, 0, 0, 0);
			if (err != -EAGAIN)
				break;
			if (msleep_interruptible(1000) > 0) {
				err = -ETIMEDOUT;
				break;
			}
		}
		if (err < 0)
			goto err_armsp;
	}

	if (nfp_reset) {
		dev_info(&pdev->dev, "NFP soft-reset...\n");
		err = nfp_reset_soft(nfp);
		if (err < 0)
			goto err_sreset;
	}

	dev_info(&pdev->dev, "Loading FW image: %s\n", fw_name);

	err = nfp_ca_replay(cpp, fw->data, fw->size);
	release_firmware(fw);
	if (err < 0)
		goto err_replay;

	dev_info(&pdev->dev, "Finished loading FW image: %s\n", fw_name);
	return 1;

err_sreset:
	release_firmware(fw);
	dev_err(&pdev->dev, "Failed to soft reset the NFP %d.\n",
		err);
	return err;
err_armsp:
	release_firmware(fw);
	dev_err(&pdev->dev, "Failed to find NFP Service Processor with %d.%s\n",
		err, fw_stop_on_fail ? "" : " Continuing...");
	return fw_stop_on_fail ? err : 0;
err_request:
	dev_err(&pdev->dev, "Failed to request FW with %d.%s\n",
		err, fw_stop_on_fail ? "" : " Continuing...");
	return fw_stop_on_fail ? err : 0;
err_replay:
	dev_err(&pdev->dev, "FW loading failed with %d.%s",
		err, fw_stop_on_fail ? "" : " Continuing...");
	return fw_stop_on_fail ? err : 0;
}

/**
 * nfp_net_fallback_alloc() - Allocate dummy nfp_net structure
 * @pdev:       PCI Device structure
 *
 * If the main probe function fails to load the FW or if the FW is not
 * appropriate then there is the option for the driver to fall back to
 * standard nfp.ko functionality, ie, just being a shell driver which
 * provides user space access to the NFP.  This behaviour is
 * controlled by the @nfp_fallback module option. The cleanup is done
 * in @nfp_net_pci_remove().
 *
 * Return: Dummy struct nfp_net or ERR_PTR
 */
static struct nfp_net *nfp_net_fallback_alloc(struct pci_dev *pdev)
{
	struct nfp_net *nn;

	nn = kzalloc(sizeof(*nn), GFP_KERNEL);
	if (!nn)
		return ERR_PTR(-ENOMEM);

	nn->nfp_fallback = 1;
	nn->pdev = pdev;
	return nn;
}

/*
 * Helper functions
 */

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
 * nfp_net_get_mac_addr() - Get the MAC address.
 * @nn:       NFP Network structure
 * @nfp_dev:  NFP Device structure
 *
 * First try to look up the MAC address in the HWINFO table. If that
 * fails generate a random address.
 */
static void nfp_net_get_mac_addr(struct nfp_net *nn, struct nfp_device *nfp_dev)
{
	u8 mac_addr[ETH_ALEN];
	const char *mac_str;

	mac_str = nfp_hwinfo_lookup(nfp_dev, "eth0.mac");
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

/*
 * SR-IOV support
 */
static int nfp_pcie_sriov_enable(struct pci_dev *pdev, int num_vfs)
{
#ifdef CONFIG_PCI_IOV
	struct nfp_net *nn = pci_get_drvdata(pdev);
	int err = 0;

	if (num_vfs > 64) {
		err = -EPERM;
		goto err_out;
	}

	nn->num_vfs = num_vfs;

	err = pci_enable_sriov(pdev, num_vfs);
	if (err) {
		dev_warn(&pdev->dev, "Failed to enable PCI sriov: %d\n", err);
		goto err_out;
	}

	dev_dbg(&pdev->dev, "Created %d VFs.\n", nn->num_vfs);

	return num_vfs;

err_out:
	return err;
#endif
	return 0;
}

static int nfp_pcie_sriov_disable(struct pci_dev *pdev)
{
#ifdef CONFIG_PCI_IOV
	struct nfp_net *nn = pci_get_drvdata(pdev);

	/* If the VFs are assigned we cannot shut down SR-IOV without
	 * causing issues, so just leave the hardware available but
	 * disabled
	 */
	if (pci_vfs_assigned(pdev)) {
		dev_warn(&pdev->dev, "Disabling while VFs assigned - VFs will not be deallocated\n");
		return -EPERM;
	}

	nn->num_vfs = 0;

	pci_disable_sriov(pdev);
	dev_dbg(&pdev->dev, "Removed VFs.\n");
#endif
	return 0;
}

static int nfp_pcie_sriov_configure(struct pci_dev *pdev, int num_vfs)
{
	if (num_vfs == 0)
		return nfp_pcie_sriov_disable(pdev);
	else
		return nfp_pcie_sriov_enable(pdev, num_vfs);
}

#if (LINUX_VERSION_CODE < KERNEL_VERSION(3, 8, 0))
#ifdef CONFIG_PCI_IOV
/* Kernel version 3.8 introduced a standard, sysfs based interface for
 * managing VFs.  Here we implement that interface for older kernels.
 */
static ssize_t show_sriov_totalvfs(struct device *dev,
				   struct device_attribute *attr,
				   char *buf)
{
	struct pci_dev *pdev = to_pci_dev(dev);

	return sprintf(buf, "%u\n", pci_sriov_get_totalvfs(pdev));
}

static ssize_t show_sriov_numvfs(struct device *dev,
				 struct device_attribute *attr,
				 char *buf)
{
	struct pci_dev *pdev = to_pci_dev(dev);
	struct nfp_net *nn = pci_get_drvdata(pdev);

	return sprintf(buf, "%u\n", nn->num_vfs);
}

/*
 * num_vfs > 0; number of VFs to enable
 * num_vfs = 0; disable all VFs
 *
 * Note: SRIOV spec doesn't allow partial VF
 *       disable, so it's all or none.
 */
static ssize_t store_sriov_numvfs(struct device *dev,
				  struct device_attribute *attr,
				  const char *buf, size_t count)
{
	struct pci_dev *pdev = to_pci_dev(dev);
	struct nfp_net *nn = pci_get_drvdata(pdev);
	unsigned long num_vfs;
	int ret;

	ret = kstrtoul(buf, 0, &num_vfs);
	if (ret < 0)
		return ret;

	if (num_vfs > pci_sriov_get_totalvfs(pdev))
		return -ERANGE;

	if (num_vfs == nn->num_vfs)
		return count;           /* no change */

	if (num_vfs == 0) {
		/* disable VFs */
		ret = nfp_pcie_sriov_configure(pdev, 0);
		if (ret < 0)
			return ret;
		return count;
	}

	/* enable VFs */
	if (nn->num_vfs) {
		dev_warn(&pdev->dev, "%d VFs already enabled. Disable before enabling %d VFs\n",
			 nn->num_vfs, (int)num_vfs);
		return -EBUSY;
	}

	ret = nfp_pcie_sriov_configure(pdev, num_vfs);
	if (ret < 0)
		return ret;

	if (ret != num_vfs)
		dev_warn(&pdev->dev, "%d VFs requested; only %d enabled\n",
			 (int)num_vfs, ret);

	return count;
}

static DEVICE_ATTR(sriov_totalvfs, S_IRUGO, show_sriov_totalvfs, NULL);
static DEVICE_ATTR(sriov_numvfs, S_IRUGO | S_IWUSR | S_IWGRP,
		   show_sriov_numvfs, store_sriov_numvfs);

static int nfp_sriov_attr_add(struct device *dev)
{
	int err = 0;

	err = device_create_file(dev, &dev_attr_sriov_totalvfs);
	if (err)
		return err;

	return device_create_file(dev, &dev_attr_sriov_numvfs);
}

static void nfp_sriov_attr_remove(struct device *dev)
{
	device_remove_file(dev, &dev_attr_sriov_totalvfs);
	device_remove_file(dev, &dev_attr_sriov_numvfs);
}
#endif /* CONFIG_PCI_IOV */
#endif /* Linux kernel version */

static int nfp_is_ready(struct nfp_device *nfp)
{
	const char *cp;
	long state;
	int err;

	cp = nfp_hwinfo_lookup(nfp, "board.state");
	if (!cp)
		return 0;

	err = kstrtol(cp, 0, &state);
	if (err < 0)
		return 0;

	if (state != 15)
		return 0;

	return 1;
}

/*
 * PCI device functions
 */
static int nfp_net_pci_probe(struct pci_dev *pdev,
			     const struct pci_device_id *pci_id)
{
	struct platform_device *dev_cpp = NULL;
	const struct nfp_rtsym *ctrl_sym;
	uint32_t tx_area_sz, rx_area_sz;
	int max_tx_rings, max_rx_rings;
	struct nfp_cpp_area *ctrl_area;
	struct nfp_device *nfp_dev;
	u8 __iomem *ctrl_bar;
	struct nfp_cpp *cpp;
	char pf_symbol[256];
	uint16_t interface;
	struct nfp_net *nn;
	uint32_t version;
	uint32_t start_q;
	int is_nfp3200;
	int fw_loaded;
	int pcie_pf;
	int stride;
	int err;

	err = pci_enable_device(pdev);
	if (err < 0)
		return err;

	pci_set_master(pdev);

	err = pci_set_dma_mask(pdev,  DMA_BIT_MASK(40));
	if (err < 0) {
		dev_err(&pdev->dev, "Cannot set DMA mask\n");
		goto err_dma_mask;
	}

	err = pci_set_consistent_dma_mask(pdev,  DMA_BIT_MASK(40));
	if (err < 0) {
		dev_err(&pdev->dev, "Cannot set consistent DMA mask\n");
		goto err_dma_mask;
	}

	err = pci_request_regions(pdev, nfp_net_driver_name);
	if (err < 0) {
		dev_err(&pdev->dev, "Unable to reserve pci resources.\n");
		goto err_dma_mask;
	}

	switch (pdev->device) {
	case PCI_DEVICE_NFP3200:
		cpp = nfp_cpp_from_nfp3200_pcie(pdev, -1);
		is_nfp3200 = 1;
		break;
	case PCI_DEVICE_NFP6000:
		cpp = nfp_cpp_from_nfp6000_pcie(pdev, -1);
		is_nfp3200 = 0;
		break;
	default:
		err = -ENODEV;
		goto err_nfp_cpp;
	}

	if (IS_ERR_OR_NULL(cpp)) {
		err = PTR_ERR(cpp);
		if (err >= 0)
			err = -ENOMEM;
		goto err_nfp_cpp;
	}

#if (LINUX_VERSION_CODE < KERNEL_VERSION(3, 8, 0)) && defined(CONFIG_PCI_IOV)
	if (!is_nfp3200) {
		err = nfp_sriov_attr_add(&pdev->dev);
		if (err < 0)
			goto err_sriov;
	}
#endif

	nfp_dev = nfp_device_from_cpp(cpp);
	if (!nfp_dev) {
		err = -ENODEV;
		goto err_open_dev;
	}

	err = nfp_net_fw_load(pdev, nfp_dev);
	if (err < 0) {
		dev_err(&pdev->dev, "Failed to load FW\n");
		goto err_fw_load;
	}

	fw_loaded = !!err;

	if (nfp_dev_cpp) {
		dev_cpp = nfp_platform_device_register(cpp, NFP_DEV_CPP_TYPE);
		if (!dev_cpp)
			dev_err(&pdev->dev,
				"Failed to enable user space access. Ignored");
	}

	interface = nfp_cpp_interface(cpp);
	pcie_pf = NFP_CPP_INTERFACE_UNIT_of(interface);

	/* Verify that the board has completed initialization */
	if (nfp_is_ready(nfp_dev)) {
		snprintf(pf_symbol, sizeof(pf_symbol),
			 "_pf%d_net_bar0", pcie_pf);

		ctrl_sym = nfp_rtsym_lookup(nfp_dev, pf_symbol);
		if (!ctrl_sym)
			dev_err(&pdev->dev,
				"Failed to find PF BAR0 symbol %s\n",
				pf_symbol);
	} else {
		dev_err(&pdev->dev,
			"NFP is not ready for operation.\n");
		ctrl_sym = NULL;
	}

	if (!ctrl_sym) {
		if (!nfp_fallback) {
			err = -ENOENT;
			goto err_ctrl;
		} else {
			nn = nfp_net_fallback_alloc(pdev);
			if (IS_ERR(nn)) {
				err = PTR_ERR(nn);
				goto err_ctrl;
			}

			nn->nfp_dev_cpp = dev_cpp;
			nn->cpp = cpp;

			pci_set_drvdata(pdev, nn);
			nfp_device_close(nfp_dev);
			dev_info(&pdev->dev,
				 "Netronome NFP Fallback driver\n");
			return 0;
		}
	}

	ctrl_bar = nfp_net_map_area(cpp, "net.ctrl",
				    ctrl_sym->domain, ctrl_sym->target,
				    ctrl_sym->addr, ctrl_sym->size, &ctrl_area);
	if (IS_ERR_OR_NULL(ctrl_bar)) {
		dev_err(&pdev->dev, "Failed to map PF BAR0\n");
		err = PTR_ERR(ctrl_bar);
		goto err_ctrl;
	}

	/* Determine stride */
	version = nn_readl(ctrl_bar, NFP_NET_CFG_VERSION);
	if (((version >> 16) & 0xff) != 0) {
		/* We only support the Generic Class */
		dev_err(&pdev->dev, "Unknown Firmware ABI %d.%d.%d.%d\n",
				(version >> 24) & 0xff,
				(version >> 16) & 0xff,
				(version >>  8) & 0xff,
				(version >>  0) & 0xff);
		err = -EINVAL;
		goto err_nn_init;
	}

	switch (version) {
	case 0x0000:
	case 0x0001:
	case 0x1248:
		stride = 2;
		dev_warn(&pdev->dev, "OBSOLETE Firmware detected - VF isolation not available\n");
		break;
	case 0x0100:
		if (is_nfp3200)
			stride = 2;
		else
			stride = 4;
		break;
	default:
		dev_err(&pdev->dev, "Unsupported Firmware ABI %d.%d.%d.%d\n",
				(version >> 24) & 0xff,
				(version >> 16) & 0xff,
				(version >>  8) & 0xff,
				(version >>  0) & 0xff);
		err = -EINVAL;
		goto err_nn_init;
	}

	/* Find how many rings are supported */
	max_tx_rings = nn_readl(ctrl_bar, NFP_NET_CFG_MAX_TXRINGS);
	max_rx_rings = nn_readl(ctrl_bar, NFP_NET_CFG_MAX_RXRINGS);

	tx_area_sz = NFP_QCP_QUEUE_ADDR_SZ * max_tx_rings * stride;
	rx_area_sz = NFP_QCP_QUEUE_ADDR_SZ * max_rx_rings * stride;

	/* Allocate and initialise the netdev */
	nn = nfp_net_netdev_alloc(pdev, max_tx_rings, max_rx_rings);
	if (IS_ERR(nn)) {
		err = PTR_ERR(nn);
		goto err_nn_init;
	}

	nn->ver = version;
	nn->cpp = cpp;
	nn->nfp_dev_cpp = dev_cpp;
	nn->ctrl_area = ctrl_area;
	nn->ctrl_bar = ctrl_bar;
	nn->is_vf = 0;
	nn->is_nfp3200 = is_nfp3200;
	nn->fw_loaded = fw_loaded;
	nn->stride_rx = stride;
	nn->stride_tx = stride;

#ifdef NFP_NET_HRTIMER_6000
	if (!nn->is_nfp3200)
		nn->hrtimer = 1;
	else
		nn->hrtimer = 0;
#endif

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

	/* Get MSI-X vectors */
	err = nfp_net_irqs_alloc(nn);
	if (!err) {
		nn_warn(nn, "Unable to allocate MSI-X Vectors. Exiting\n");
		err = -EIO;
		goto err_vec;
	}

	if (pdev->msix_enabled) {
		nn->msix_table = nfp_net_msix_map(pdev, 255);
		if (!nn->msix_table) {
			err = -EIO;
			goto err_map_msix_table;
		}
	}

	/* Get MAC address */
	nfp_net_get_mac_addr(nn, nfp_dev);

	/* Get ME clock frequency from ctrl BAR
	 * XXX for now frequency is hardcoded until we figure out how
	 * to get the value from nfp-hwinfo into ctrl bar */
	nn->me_freq_mhz = 1200;

	/*
	 * Finalise
	 */
	err = nfp_net_netdev_init(nn->netdev);
	if (err)
		goto err_netdev_init;

	pci_set_drvdata(pdev, nn);

	nfp_device_close(nfp_dev);

	nfp_net_info(nn);
	return 0;

err_netdev_init:
	if (nn->msix_table)
		iounmap(nn->msix_table);
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
err_ctrl:
	if (fw_loaded) {
		if (nfp_reset) {
			int ret = nfp_reset_soft(nfp_dev);

			if (ret < 0)
				dev_warn(&pdev->dev,
					 "Couldn't unload firmware: %d\n", ret);
			else
				dev_info(&pdev->dev,
					 "Firmware safely unloaded\n");
		} else {
			dev_warn(&pdev->dev,
				 "Firmware was not unloaded (nfp_reset=0)\n");
		}
	}
err_fw_load:
	nfp_device_close(nfp_dev);
err_open_dev:
	if (dev_cpp)
		nfp_platform_device_unregister(dev_cpp);
#if (LINUX_VERSION_CODE < KERNEL_VERSION(3, 8, 0)) && defined(CONFIG_PCI_IOV)
	if (!is_nfp3200)
		nfp_sriov_attr_remove(&pdev->dev);
err_sriov:
#endif
	nfp_cpp_free(cpp);
err_nfp_cpp:
	pci_release_regions(pdev);
err_dma_mask:
	pci_disable_device(pdev);

	/* It is a bug to leave via this error path and
	 * have err be zero or positive.
	 */
	BUG_ON(err >= 0);

	return err;
}

static void nfp_net_pci_remove(struct pci_dev *pdev)
{
	struct nfp_net *nn = pci_get_drvdata(pdev);
	struct nfp_device *nfp_dev;
	int err;

#ifdef CONFIG_PCI_IOV
	/* TODO Need to better handle the case where the PF netdev
	 * gets disabled but the VFs are still around, because they
	 * are assigned.
	 */
	if (!nn->is_nfp3200)
		(void)nfp_pcie_sriov_disable(pdev);

#if (LINUX_VERSION_CODE < KERNEL_VERSION(3, 8, 0))
	if (!nn->is_nfp3200)
		nfp_sriov_attr_remove(&pdev->dev);
#endif

#endif

	if (!nn->nfp_fallback) {
		nfp_net_netdev_clean(nn->netdev);

		if (nn->msix_table)
			iounmap(nn->msix_table);
		nfp_net_irqs_disable(nn);

		nfp_cpp_area_release_free(nn->rx_area);
		nfp_cpp_area_release_free(nn->tx_area);
		nfp_cpp_area_release_free(nn->ctrl_area);
	}

	if (nn->fw_loaded) {
		nfp_dev = nfp_device_from_cpp(nn->cpp);

		if (nfp_dev && nfp_reset) {
			err = nfp_reset_soft(nfp_dev);
			if (err < 0)
				nn_warn(nn,
					"Couldn't unload firmware: %d\n", err);
			else
				nn_info(nn, "Firmware safely unloaded\n");
		} else {
			nn_warn(nn, "Firmware was not unloaded (%s=0)\n",
				nfp_dev ? "nfp_reset" : "nfp_dev");
		}
		if (nfp_dev)
			nfp_device_close(nfp_dev);
	}

	if (nn->nfp_dev_cpp)
		nfp_platform_device_unregister(nn->nfp_dev_cpp);

	nfp_cpp_free(nn->cpp);

	if (!nn->nfp_fallback)
		nfp_net_netdev_free(nn);
	else
		kfree(nn);

	pci_set_drvdata(pdev, NULL);
	pci_release_regions(pdev);
	pci_disable_device(pdev);
}

static struct pci_driver nfp_net_pci_driver = {
	.name        = nfp_net_driver_name,
	.id_table    = nfp_net_pci_device_ids,
	.probe       = nfp_net_pci_probe,
	.remove      = nfp_net_pci_remove,
#if (LINUX_VERSION_CODE >= KERNEL_VERSION(3, 8, 0))
	.sriov_configure = nfp_pcie_sriov_configure,
#endif
};

static int __init nfp_net_init(void)
{
	int err;

	if (find_module("nfp")) {
		pr_err("%s: Cannot be loaded while nfp is loaded\n",
		       nfp_net_driver_name);
		return -EBUSY;
	}

	pr_info("%s: NFP Network driver, Copyright (C) 2014-2015 Netronome Systems\n",
		nfp_net_driver_name);
	pr_info(NFP_BUILD_DESCRIPTION(nfp));

	err = nfp_cppcore_init();
	if (err < 0)
		goto fail_cppcore_init;

	err = nfp_dev_cpp_init();
	if (err < 0)
		goto fail_dev_cpp_init;

	err = pci_register_driver(&nfp_net_pci_driver);
	if (err < 0)
		goto fail_pci_init;

	return err;

fail_pci_init:
	nfp_dev_cpp_exit();
fail_dev_cpp_init:
	nfp_cppcore_exit();
fail_cppcore_init:
	return err;
}

static void __exit nfp_net_exit(void)
{
	pci_unregister_driver(&nfp_net_pci_driver);
	nfp_dev_cpp_exit();
	nfp_cppcore_exit();
}

module_init(nfp_net_init);
module_exit(nfp_net_exit);

MODULE_AUTHOR("Netronome Systems <support@netronome.com>");
MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("NFP network device driver");
MODULE_INFO_NFP();

/*
 * Local variables:
 * c-file-style: "Linux"
 * indent-tabs-mode: t
 * End:
 */
