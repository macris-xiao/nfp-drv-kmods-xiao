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
 * Netronome virtual function network device driver: Main entry point
 */

#include <linux/version.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>

#include "nfp_net_compat.h"
#include "nfp_net_ctrl.h"
#include "nfp_net.h"

/* Enable workaround for THB-350 */
#define NFP_NET_THB350

const char nfp_net_driver_name[] = "nfp_netvf";
const char nfp_net_driver_version[] = "0.1";
#define PCI_VENDOR_ID_NETRONOME         0x19ee
#define PCI_DEVICE_NFP6000VF		0x6003
static const struct pci_device_id nfp_netvf_pci_device_ids[] = {
	{ PCI_VENDOR_ID_NETRONOME, PCI_DEVICE_NFP6000VF,
	  PCI_VENDOR_ID_NETRONOME, PCI_ANY_ID,
	  PCI_ANY_ID, 0,
	},
	{ 0, } /* Required last entry. */
};
MODULE_DEVICE_TABLE(pci, nfp_netvf_pci_device_ids);

MODULE_AUTHOR("Netronome Systems <support@netronome.com>");
MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("NFP VF network device driver");

static int nfp_netvf_pci_probe(struct pci_dev *pdev,
			       const struct pci_device_id *pci_id)
{
	struct nfp_net *nn;
	u8 __iomem *ctrl_bar;
	int max_tx_rings, max_rx_rings;
	uint32_t tx_bar_off, rx_bar_off;
	uint32_t tx_bar_sz, rx_bar_sz;
	int err;
	int is_nfp3200;
	uint32_t startq;

	err = pci_enable_device_mem(pdev);
	if (err)
		return err;

	err = pci_request_regions(pdev, nfp_net_driver_name);
	if (err) {
		dev_err(&pdev->dev, "Unable to allocate device memory.\n");
		goto err_pci_regions;
	}

	switch (pdev->device) {
	case PCI_DEVICE_NFP6000VF:
		is_nfp3200 = 0;
		break;
	default:
		err = -ENODEV;
		goto err_dma_mask;
	}

	pci_set_master(pdev);

	err = dma_set_mask_and_coherent(&pdev->dev, DMA_BIT_MASK(NFP_NET_MAX_DMA_BITS));
	if (err)
		goto err_dma_mask;

	/* Map the Control BAR.
	 *
	 * Irrespective of the advertised BAR size we only map the
	 * first NFP_NET_CFG_BAR_SZ of the BAR.  This keeps the code
	 * the identical for PF and VF drivers.
	 */
	ctrl_bar = devm_ioremap_nocache(
		&pdev->dev, pci_resource_start(pdev, NFP_NET_CRTL_BAR),
		NFP_NET_CFG_BAR_SZ);
	if (!ctrl_bar) {
		dev_err(&pdev->dev,
			"Failed to map resource %d\n", NFP_NET_CRTL_BAR);
		err = -EIO;
		goto err_barmap_ctrl;
	}

	/* Find out how many rings are supported.  Note, for the VF we
	 * could derive this from the BAR size (except for THB-350),
	 * but to keep the code simple so we just read it from the
	 * control BAR. */
	max_tx_rings = nn_readl(ctrl_bar, NFP_NET_CFG_MAX_TXRINGS);
	max_rx_rings = nn_readl(ctrl_bar, NFP_NET_CFG_MAX_RXRINGS);

	tx_bar_sz = NFP_QCP_QUEUE_ADDR_SZ * max_tx_rings * 2;
	rx_bar_sz = NFP_QCP_QUEUE_ADDR_SZ * max_rx_rings * 2;

	/* Sanity checks */
	if (tx_bar_sz > pci_resource_len(pdev, NFP_NET_TX_BAR)) {
		dev_err(&pdev->dev,
			"TX BAR too small for number of TX rings. Adjusting");
		tx_bar_sz = pci_resource_len(pdev, NFP_NET_TX_BAR);
		max_tx_rings = (tx_bar_sz / NFP_QCP_QUEUE_ADDR_SZ) / 2;
	}
	if (rx_bar_sz > pci_resource_len(pdev, NFP_NET_RX_BAR)) {
		dev_err(&pdev->dev,
			"RX BAR too small for number of RX rings. Adjusting");
		rx_bar_sz = pci_resource_len(pdev, NFP_NET_RX_BAR);
		max_rx_rings = (rx_bar_sz / NFP_QCP_QUEUE_ADDR_SZ) / 2;
	}

	/* XXX Implement a workaround for THB-350 here.  Ideally, we
	 * have a different PCI ID for A rev VFs.
	 */
	switch (pdev->device) {
	case PCI_DEVICE_NFP6000VF:
#ifdef NFP_NET_THB350
		startq = nn_readl(ctrl_bar, NFP_NET_CFG_START_TXQ);
		tx_bar_off = NFP_PCIE_QUEUE(startq);
		startq = nn_readl(ctrl_bar, NFP_NET_CFG_START_RXQ);
		rx_bar_off = NFP_PCIE_QUEUE(startq);
#else
		tx_bar_off = 0;
		rx_bar_off = 0;
#endif
		break;
	default:
		err = -ENODEV;
		goto err_unknown_dev;
	}

	/* Allocate and initialise the netdev */
	nn = nfp_net_netdev_alloc(pdev, max_tx_rings, max_rx_rings);
	if (IS_ERR(nn)) {
		err = PTR_ERR(nn);
		goto err_nn_init;
	}

	nn->ctrl_bar = ctrl_bar;
	nn->is_vf = 1;
	nn->is_nfp3200 = is_nfp3200;

#ifdef NFP_NET_HRTIMER_6000
	nn->hrtimer = 1;
#endif

	/* TX queues */
	nn->tx_bar = devm_ioremap_nocache(
		&pdev->dev,
		pci_resource_start(pdev, NFP_NET_TX_BAR) + tx_bar_off,
		tx_bar_sz);
	if (!nn->tx_bar) {
		nn_err(nn, "Failed to map resource %d", NFP_NET_TX_BAR);
		err = -EIO;
		goto err_barmap_tx;
	}

	/* RX queues */
	nn->rx_bar = devm_ioremap_nocache(
		&pdev->dev,
		pci_resource_start(pdev, NFP_NET_RX_BAR) + rx_bar_off,
		rx_bar_sz);
	if (!nn->rx_bar) {
		nn_err(nn, "Failed to map resource %d", NFP_NET_RX_BAR);
		err = -EIO;
		goto err_barmap_rx;
	}

	/* XXX For now generate a MAC address until we figured out how
	 * to do this properly with VF.
	 */
	random_ether_addr(nn->netdev->dev_addr);

	err = nfp_net_irqs_alloc(nn);
	if (!err) {
		nn_warn(nn, "Unable to allocate MSI-X Vectors. Exiting\n");
		err = -EIO;
		goto err_irqs_alloc;
	}

	if (pdev->msix_enabled) {
		nn->msix_table = nfp_net_msix_map(pdev, 255);
		if (!nn->msix_table) {
			err = -EIO;
			goto err_map_msix_table;
		}
	}

	err = nfp_net_netdev_init(nn->netdev);
	if (err)
		goto err_netdev_init;

	pci_set_drvdata(pdev, nn);

	nfp_net_info(nn);
	return 0;

err_netdev_init:
	nfp_net_msix_unmap(nn->msix_table);
err_map_msix_table:
	nfp_net_irqs_disable(nn);
err_irqs_alloc:
	devm_iounmap(&pdev->dev, nn->rx_bar);
err_barmap_rx:
	devm_iounmap(&pdev->dev, nn->tx_bar);
err_barmap_tx:
	pci_set_drvdata(pdev, NULL);
	nfp_net_netdev_free(nn);
err_unknown_dev:
err_nn_init:
	devm_iounmap(&pdev->dev, ctrl_bar);
err_barmap_ctrl:
err_dma_mask:
	pci_release_regions(pdev);
err_pci_regions:
	pci_disable_device(pdev);
	return err;
}

static void nfp_netvf_pci_remove(struct pci_dev *pdev)
{
	struct nfp_net *nn = pci_get_drvdata(pdev);

	/* Note, the order is slightly different from above as we need
	 * to keep the nn pointer around till we have freed everything. */

	BUG_ON(!nn);

	nn->removing_pdev = 1;
	nfp_net_netdev_clean(nn->netdev);

	nfp_net_msix_unmap(nn->msix_table);
	nfp_net_irqs_disable(nn);

	devm_iounmap(&pdev->dev, nn->rx_bar);
	devm_iounmap(&pdev->dev, nn->tx_bar);
	devm_iounmap(&pdev->dev, nn->ctrl_bar);

	pci_set_drvdata(pdev, NULL);

	nfp_net_netdev_free(nn);

	pci_release_regions(pdev);
	pci_disable_device(pdev);
}

static struct pci_driver nfp_netvf_pci_driver = {
	.name        = nfp_net_driver_name,
	.id_table    = nfp_netvf_pci_device_ids,
	.probe       = nfp_netvf_pci_probe,
	.remove      = nfp_netvf_pci_remove,
};

static int __init nfp_netvf_init(void)
{
	int err;

	pr_info("%s: NFP VF Network driver, Copyright (C) 2014-2015 Netronome Systems\n",
		nfp_net_driver_name);

	err = pci_register_driver(&nfp_netvf_pci_driver);
	return err;
}

static void __exit nfp_netvf_exit(void)
{
	pci_unregister_driver(&nfp_netvf_pci_driver);
}

module_init(nfp_netvf_init);
module_exit(nfp_netvf_exit);

/*
 * Local variables:
 * c-file-style: "Linux"
 * indent-tabs-mode: t
 * End:
 */
