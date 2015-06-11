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
 * Netronome network device driver: Common functions between PF and VF
 */

/* This file is used by multiple drivers, in which case Kbuild does
 * not set @KBUILD_MODNAME. Unfortunately, this is required to be set
 * by a number of kernel components, used by this file.
 */
#ifndef KBUILD_MODNAME
#define KBUILD_MODNAME "nfp_net_common"
#endif

#include <linux/version.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/fs.h>
#include <linux/netdevice.h>
#include <linux/etherdevice.h>
#include <linux/interrupt.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/pci.h>
#include <linux/pci_regs.h>
#include <linux/msi.h>
#include <linux/ethtool.h>
#include <linux/log2.h>
#include <linux/if_vlan.h>
#include <linux/random.h>

#include <linux/ktime.h>
#include <linux/hrtimer.h>

#include "nfp_net_compat.h"
#include "nfp_net_ctrl.h"
#include "nfp_net.h"

static unsigned int num_rings;
module_param(num_rings, uint, 0);
MODULE_PARM_DESC(num_rings, "Number of RX/TX rings to use");

#ifdef NFP_NET_HRTIMER_6000
static unsigned int pollinterval = 500;
#endif

/**
 * nfp_net_reconfigure() - Reconfigure the firmware
 * @nn:      NFP Net device to reconfigure
 * @update:  The value for the update field in the BAR config
 *
 * Write the update word to the BAR and ping the reconfig queue.  The
 * poll until the firmware has acknowledged the update by zeroing the
 * update word.
 *
 * Return: Negative errno on error, 0 on success
 */
int nfp_net_reconfig(struct nfp_net *nn, u32 update)
{
	int cnt;
	u32 new;

	nn_writel(nn->ctrl_bar, NFP_NET_CFG_UPDATE, update);
	/* memory barrier to ensure update is written before pinging HW. */
	wmb();
	nfp_qcp_wr_ptr_add(nn->qcp_cfg, 1);

	/* Poll update field, waiting for NFP to ack the config */
	for (cnt = 0; ; cnt++) {
		new = nn_readl(nn->ctrl_bar, NFP_NET_CFG_UPDATE);
		if (new == 0)
			break;
		if (new & NFP_NET_CFG_UPDATE_ERR) {
			nn_err(nn, "Reconfig error: 0x%08x\n", new);
			return -EIO;
		} else if (cnt >= NFP_NET_POLL_TIMEOUT) {
			nn_err(nn, "Reconfig timeout for 0x%08x after %dms\n",
			       update, cnt);
			return -EIO;
		}
		mdelay(1);
	}
	return 0;
}

/**
 * nfp_net_msix_map() - Map the MSI-X table
 * @pdev:       PCI Device structure
 * @nr_entries: Number of entries in table to map
 *
 * If successful, the table must be un-mapped using iounmap(). 
 *
 * Return: Pointer to mapped table or PTR_ERR
 */
void __iomem *nfp_net_msix_map(struct pci_dev *pdev, unsigned nr_entries)
{
	resource_size_t phys_addr;
	u32 table_offset;
	u8 msix_cap;
	u8 bir;

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

	return ioremap_nocache(phys_addr, nr_entries * PCI_MSIX_ENTRY_SIZE);
}

/*
 * Interrupt configuration and handling
 */

/**
 * nfp_net_irq_unmask() - Unmask an interrupt
 * @nn:       NFP Network structure
 * @entry_nr: MSI-X table entry
 *
 * If MSI-X auto-masking is enabled clear the mask bit, otherwise
 * clear the ICR for the entry.
 */
static void nfp_net_irq_unmask(struct nfp_net *nn, unsigned int entry_nr)
{
	struct pci_dev *pdev = nn->pdev;
	int off;

	if (!pdev->msix_enabled)
		return;

	if (nn->ctrl & NFP_NET_CFG_CTRL_MSIXAUTO) {
		/* If MSI-X auto-masking is used, clear the entry */
		off = (PCI_MSIX_ENTRY_SIZE * entry_nr) +
			PCI_MSIX_ENTRY_VECTOR_CTRL;
		/* Make sure all updates are written before un-masking */
		wmb();
		nn_writel(nn->msix_table, off, 0);
	} else {
		/* Make sure all updates are written before un-masking */
		wmb();
		nn_writeb(nn->ctrl_bar,
			  NFP_NET_CFG_ICR(entry_nr), NFP_NET_CFG_ICR_UNMASKED);
	}
}

/**
 * nfp_net_msix_alloc() - Try to allocate MSI-X irqs
 * @nn:       NFP Network structure
 * @nr_vecs:  Number of MSI-X vectors to allocate
 *
 * For MSI-X we want at least NFP_NET_NON_Q_VECTORS + 1 vectors.
 *
 * Return: Number of MSI-X vectors obtained or 0 or error.
 */
static int nfp_net_msix_alloc(struct nfp_net *nn, int nr_vecs)
{
	struct pci_dev *pdev = nn->pdev;
	int nvecs;
	int i;

	for (i = 0; i < nr_vecs; i++)
		nn->irq_entries[i].entry = i;

	nvecs = pci_enable_msix_range(pdev, nn->irq_entries,
				      NFP_NET_NON_Q_VECTORS + 1, nr_vecs);
	if (nvecs < 0) {
		nn_warn(nn, "Failed to enable MSI-X. Wanted %d-%d (err=%d)\n",
			NFP_NET_NON_Q_VECTORS + 1, nr_vecs, nvecs);
		return 0;
	}

	nn->per_vector_masking = 1;

	return nvecs;
}

/**
 * nfp_net_irqs_wanted() - Work out how many interrupt vectors we want
 * @nn:       NFP Network structure
 *
 * We want a vector per CPU (or ring), whatever is smaller plus
 * NFP_NET_NON_Q_VECTORS for LSC etc.
 *
 * Return: Number of interrupts wanted
 */
static int nfp_net_irqs_wanted(struct nfp_net *nn)
{
	int ncpus;
	int vecs;

	ncpus =  num_online_cpus();

	vecs = max_t(int, nn->num_tx_rings, nn->num_rx_rings);
	vecs = min_t(int, vecs, ncpus);

	return vecs + NFP_NET_NON_Q_VECTORS;
}

/**
 * nfp_net_irqs_alloc() - allocates MSI-X irqs
 * @nn:       NFP Network structure
 *
 * Return: Number of irqs obtained or 0 on error.
 */
int nfp_net_irqs_alloc(struct nfp_net *nn)
{
	int wanted_vecs;
	int nvecs;

	wanted_vecs = nfp_net_irqs_wanted(nn);

	if (nn->hrtimer) {
		nn->num_vecs = wanted_vecs;
		nn->num_r_vecs = wanted_vecs - NFP_NET_NON_Q_VECTORS;
		return wanted_vecs;
	}

	nvecs = nfp_net_msix_alloc(nn, wanted_vecs);

	if (nvecs == 0) {
		nn_err(nn, "Failed to allocate MSI-X IRQs\n");
		return 0;
	}

	if (nvecs <= NFP_NET_NON_Q_VECTORS) {
		nn->num_vecs = 1;
		nn->num_r_vecs = 1;
	} else {
		nn->num_vecs = nvecs;
		nn->num_r_vecs = nn->num_vecs - NFP_NET_NON_Q_VECTORS;
	}

	if (nvecs < wanted_vecs)
		nn_warn(nn, "Unable to allocate %d vectors. Got %d instead\n",
			wanted_vecs, nvecs);

	return nn->num_vecs;
}

/**
 * nfp_net_irqs_disable() - Disable interrupts
 * @nn:       NFP Network structure
 *
 * Undoes what @nfp_net_irqs_alloc() does.
 */
void nfp_net_irqs_disable(struct nfp_net *nn)
{
	if (nn->pdev->msix_enabled)
		pci_disable_msix(nn->pdev);
}

/**
 * nfp_net_rxtx_irq() - Interrupt service routine for RX/TX rings.
 * @irq:      Interrupt
 * @data:     Opaque data structure
 *
 * Return: Indicate if the interrupt has been handled.
 */
static irqreturn_t nfp_net_irq_rxtx(int irq, void *data)
{
	struct nfp_net_r_vector *r_vec = data;
	struct napi_struct *napi = &r_vec->napi;

	if (!r_vec->rx_ring && !r_vec->tx_ring)
		return IRQ_HANDLED;

	/* The FW auto-masks any interrupt, either via the MASK bit in
	 * the MSI-X table or via the per entry ICR field.  So there
	 * is no need to disable interrupts here.
	 */

	/* There is a short period between enabling interrupts and
	 * enabling NAPI.  If a interrupt gets delivered during this
	 * period, NAPI will not get scheduled and the auto-masked
	 * interrupt will never get un-masked.  Handle this case here.
	 */
	if (unlikely(!test_bit(NFP_NET_RVEC_NAPI_STARTED, &r_vec->flags))) {
		nfp_net_irq_unmask(r_vec->nfp_net, r_vec->irq_idx);
		return IRQ_HANDLED;
	}

	if (napi_schedule_prep(napi))
		__napi_schedule(napi);

	return IRQ_HANDLED;
}

static void nfp_net_print_link(struct nfp_net *nn, bool isup)
{
	if (isup)
		netdev_info(nn->netdev, "NIC Link is Up\n");
	else
		netdev_info(nn->netdev, "NIC Link is Down\n");
}

/**
 * nfp_net_lsc_irq() - Interrupt service routine for link state changes
 * @irq:      Interrupt
 * @data:     Opaque data structure
 *
 * Return: Indicate if the interrupt has been handled.
 */
static irqreturn_t nfp_net_irq_lsc(int irq, void *data)
{
	struct net_device *netdev = data;
	struct nfp_net *nn = netdev_priv(netdev);
	bool link_up;
	u32 sts;

	sts = nn_readl(nn->ctrl_bar, NFP_NET_CFG_STS);
	link_up = !!(sts & NFP_NET_CFG_STS_LINK);

	if (nn->link_up == link_up)
		goto unmask_lsc_irq;

	nn->link_up = link_up;

	if (nn->link_up)
		netif_carrier_on(netdev);
	else
		netif_carrier_off(netdev);

	nfp_net_print_link(nn, sts & NFP_NET_CFG_STS_LINK);

unmask_lsc_irq:
	nfp_net_irq_unmask(nn, NFP_NET_IRQ_LSC_IDX);

	return IRQ_HANDLED;
}

/**
 * nfp_net_exn_irq() - Interrupt service routine for exceptions
 * @irq:      Interrupt
 * @data:     Opaque data structure
 *
 * Return: Indicate if the interrupt has been handled.
 */
static irqreturn_t nfp_net_irq_exn(int irq, void *data)
{
	struct net_device *netdev = data;
	struct nfp_net *nn = netdev_priv(netdev);

	nn_err(nn, "%s: UNIMPLEMENTED.\n", __func__);
	/* XXX TO BE IMPLEMENTED */
	return IRQ_HANDLED;
}

/**
 * nfp_net_intr() - Shared interrupt service routing for exceptions
 * @irq:      Interrupt
 * @data:     Opaque data structure
 *
 * Return: Indicate if the interrupt has been handled.
 */
static irqreturn_t nfp_net_intr(int irq, void *data)
{
	struct net_device *netdev = data;
	struct nfp_net *nn = netdev_priv(netdev);
	struct nfp_net_r_vector *r_vec = &nn->r_vecs[0];
	struct napi_struct *napi = &r_vec->napi;

	nfp_net_irq_lsc(irq, data);
	/* XXX Add exception when implemented */

	if (!r_vec->rx_ring && !r_vec->tx_ring)
		return IRQ_HANDLED;

	if (napi_schedule_prep(napi))
		__napi_schedule(napi);

	return IRQ_HANDLED;
}

/**
 * nfp_net_tx_rings_init() - Fill in the boilerplate for a TX ring
 * @tx_ring:  TX ring structure
 */
static void nfp_net_tx_ring_init(struct nfp_net_tx_ring *tx_ring)
{
	struct nfp_net_r_vector *r_vec = tx_ring->r_vec;
	struct nfp_net *nn = r_vec->nfp_net;

	tx_ring->qcidx = tx_ring->idx * nn->stride_tx;
	tx_ring->qcp_q = nn->tx_bar + NFP_QCP_QUEUE_OFF(tx_ring->qcidx);
}

/**
 * nfp_net_rx_rings_init() - Fill in the boilerplate for a RX ring
 * @rx_ring:  RX ring structure
 */
static void nfp_net_rx_ring_init(struct nfp_net_rx_ring *rx_ring)
{
	struct nfp_net_r_vector *r_vec = rx_ring->r_vec;
	struct nfp_net *nn = r_vec->nfp_net;

	rx_ring->fl_qcidx = rx_ring->idx * nn->stride_rx;
	rx_ring->rx_qcidx = rx_ring->fl_qcidx + (nn->stride_rx - 1);

	rx_ring->qcp_fl = nn->rx_bar + NFP_QCP_QUEUE_OFF(rx_ring->fl_qcidx);
	rx_ring->qcp_rx = nn->rx_bar + NFP_QCP_QUEUE_OFF(rx_ring->rx_qcidx);
}

/**
 * nfp_net_irqs_assign() - Assign IRQs and setup rvecs.
 * @netdev:   netdev structure
 */
static void nfp_net_irqs_assign(struct net_device *netdev)
{
	struct nfp_net *nn = netdev_priv(netdev);
	struct nfp_net_r_vector *r_vec;
	int i, r;

	nn_assert(nn->num_vecs > 0, "num_vecs is zero");
	nn_assert(nn->num_r_vecs > 0, "num_r_vecs is zero");

	/* Assumes nn->num_tx_rings == nn->num_rx_rings */
	if (nn->num_tx_rings > nn->num_r_vecs) {
		nn_warn(nn, "More rings (%d) than vectors (%d).\n",
			num_rings, nn->num_r_vecs);
		nn->num_tx_rings = nn->num_r_vecs;
		nn->num_rx_rings = nn->num_r_vecs;
	}

	if (nn->num_vecs == 1) {
		/* Shared IRQ, yuk */
		nn_assert(nn->num_r_vecs == 1, "num_rvecs should be 1");

		nn->shared_handler = nfp_net_intr;
		r_vec = &nn->r_vecs[0];
		r_vec->nfp_net = nn;
		r_vec->idx = 0;

		r_vec->tx_ring = &nn->tx_rings[0];
		nn->tx_rings[0].idx = 0;
		nn->tx_rings[0].r_vec = r_vec;
		nfp_net_tx_ring_init(r_vec->tx_ring);

		r_vec->rx_ring = &nn->rx_rings[0];
		nn->rx_rings[0].idx = 0;
		nn->rx_rings[0].r_vec = r_vec;
		nfp_net_rx_ring_init(r_vec->rx_ring);

		return;
	}

	/* Here we have at least 3 vectors */
	nn->lsc_handler = nfp_net_irq_lsc;
	nn->exn_handler = nfp_net_irq_exn;

	for (i = NFP_NET_NON_Q_VECTORS, r = 0; i < nn->num_vecs; i++, r++) {
		r_vec = &nn->r_vecs[r];
		r_vec->nfp_net = nn;
		r_vec->idx = r;
		r_vec->handler = nfp_net_irq_rxtx;
		r_vec->irq_idx = i;
		r_vec->requested = 0;

#ifdef NFP_NET_HRTIMER_6000
		spin_lock_init(&r_vec->txlock);
#endif
		cpumask_set_cpu(r, &r_vec->affinity_mask);

		r_vec->tx_ring = &nn->tx_rings[r];
		nn->tx_rings[r].idx = r;
		nn->tx_rings[r].r_vec = r_vec;
		nfp_net_tx_ring_init(r_vec->tx_ring);

		r_vec->rx_ring = &nn->rx_rings[r];
		nn->rx_rings[r].idx = r;
		nn->rx_rings[r].r_vec = r_vec;
		nfp_net_rx_ring_init(r_vec->rx_ring);
	}
}

/**
 * nfp_net_irq_request() - Request the common interrupts
 * @netdev:   netdev structure
 *
 * Interrupts for LSC and EXN (ring vectors are requested elsewhere)
 */
static void nfp_net_irqs_request(struct net_device *netdev)
{
	struct msix_entry *entry, *lsc_entry, *exn_entry;
	struct nfp_net *nn = netdev_priv(netdev);
	int err;

	if (nn->hrtimer)
		return;

	nn_assert(nn->num_vecs > 0, "num_vecs is zero");

	if (nn->num_vecs == 1) {
		/* Shared interrupt */
		entry = &nn->irq_entries[0];

		snprintf(nn->shared_name, sizeof(nn->shared_name),
			 "%s-shared", netdev->name);
		err = request_irq(entry->vector, nn->shared_handler, 0,
				  nn->shared_name, netdev);
		if (err) {
			nn_err(nn, "Failed to request IRQ %d (err=%d).\n",
			       entry->vector, err);
			return;
		}

		nn_writeb(nn->ctrl_bar, NFP_NET_CFG_LSC, 0);
		nn_writeb(nn->ctrl_bar, NFP_NET_CFG_EXN, 0);
		return;
	}

	lsc_entry = &nn->irq_entries[NFP_NET_IRQ_LSC_IDX];

	snprintf(nn->lsc_name, sizeof(nn->lsc_name), "%s-lsc", netdev->name);
	err = request_irq(lsc_entry->vector,
			  nn->lsc_handler, 0, nn->lsc_name, netdev);
	if (err) {
		nn_err(nn, "Failed to request IRQ %d (err=%d).\n",
		       lsc_entry->vector, err);
		goto err_lsc;
	}
	nn_writeb(nn->ctrl_bar, NFP_NET_CFG_LSC, NFP_NET_IRQ_LSC_IDX);

	exn_entry = &nn->irq_entries[NFP_NET_IRQ_EXN_IDX];

	snprintf(nn->exn_name, sizeof(nn->exn_name), "%s-exn", netdev->name);
	err = request_irq(exn_entry->vector,
			  nn->exn_handler, 0, nn->exn_name, netdev);
	if (err) {
		nn_err(nn, "Failed to request IRQ %d (err=%d).\n",
		       exn_entry->vector, err);
		goto err_exn;
	}

	nn_writeb(nn->ctrl_bar, NFP_NET_CFG_EXN, NFP_NET_IRQ_EXN_IDX);

	return;

err_exn:
	free_irq(lsc_entry->vector, netdev);
	nn_writeb(nn->ctrl_bar, NFP_NET_CFG_LSC, 0xff);
err_lsc:
	return;
}

/**
 * nfp_net_irq_free() - Free the requested common interrupts
 * @netdev:   netdev structure
 *
 * This frees the general interrupt (not the ring interrupts). It
 * undoes what @nfp_net_irqs_request set-up.
 */
static void nfp_net_irqs_free(struct net_device *netdev)
{
	struct nfp_net *nn = netdev_priv(netdev);

	nn_assert(nn->num_vecs > 0, "num_vecs is 0");

	if (nn->hrtimer)
		return;

	if (nn->num_vecs == 1) {
		synchronize_irq(nn->irq_entries[0].vector);
		free_irq(nn->irq_entries[0].vector, netdev);
		nn_writeb(nn->ctrl_bar, NFP_NET_CFG_EXN, 0xff);
		nn_writeb(nn->ctrl_bar, NFP_NET_CFG_LSC, 0xff);
		return;
	}

	synchronize_irq(nn->irq_entries[NFP_NET_IRQ_EXN_IDX].vector);
	free_irq(nn->irq_entries[NFP_NET_IRQ_EXN_IDX].vector, netdev);
	nn_writeb(nn->ctrl_bar, NFP_NET_CFG_EXN, 0xff);

	synchronize_irq(nn->irq_entries[NFP_NET_IRQ_LSC_IDX].vector);
	free_irq(nn->irq_entries[NFP_NET_IRQ_LSC_IDX].vector, netdev);
	nn_writeb(nn->ctrl_bar, NFP_NET_CFG_LSC, 0xff);
}

/*
 * Transmit
 *
 * One queue controller peripheral queue is used for transmit.  The
 * driver en-queues packets for transmit by advancing the write
 * pointer.  The device indicates that packets have transmitted by
 * advancing the read pointer.  The driver maintains a local copy of
 * the read and write pointer in @struct nfp_net_tx_ring.  The driver
 * keeps @wr_p in sync with the queue controller write pointer and can
 * determine how many packets have been transmitted by comparing its
 * copy of the read pointer @rd_p with the read pointer maintained by
 * the queue controller peripheral.
 */

/**
 * nfp_net_tx_full() - Check if the TX ring is full
 * @tx_ring: TX ring to check
 * @dcnt:    Number of descriptors that need to be enqueued (must be >= 1)
 *
 * This function checks, based on the *host copy* of read/write
 * pointer if a given TX ring is full.  The real TX queue may have
 * some newly made available slots.
 *
 * Return: True if the ring is full.
 */
static inline int nfp_net_tx_full(struct nfp_net_tx_ring *tx_ring, int dcnt)
{
	return (tx_ring->wr_p - tx_ring->rd_p) >= (tx_ring->cnt - dcnt);
}

/**
 * nfp_net_tx_csum() - Set TX CSUM offload flags in TX descriptor
 * @nn:  NFP Net device
 * @txd: Pointer to TX descriptor
 * @skb: Pointer to SKB
 *
 * This function sets the TX checksum flags in the TX descriptor based
 * on the configuration and the protocol of the packet to be
 * transmitted.
 */
static void nfp_net_tx_csum(struct nfp_net *nn,
			    struct nfp_net_tx_desc *txd, struct sk_buff *skb)
{
	u8 l4_hdr = 0;

	if (!(nn->ctrl & NFP_NET_CFG_CTRL_TXCSUM))
		return;

	if (skb->ip_summed != CHECKSUM_PARTIAL)
		return;

	switch (vlan_get_protocol(skb)) {
	case htons(ETH_P_IP):
		txd->flags |= PCIE_DESC_TX_IP4_CSUM;
		l4_hdr = ip_hdr(skb)->protocol;
		break;
	case htons(ETH_P_IPV6):
		l4_hdr = ipv6_hdr(skb)->nexthdr;
		break;
	default:
		if (unlikely(net_ratelimit())) {
			nn_warn(nn, "partial checksum but proto=%x!\n",
				skb->protocol);
		}
		return;
	}

	switch (l4_hdr) {
	case IPPROTO_TCP:
		txd->flags |= PCIE_DESC_TX_TCP_CSUM;
		break;
	case IPPROTO_UDP:
		txd->flags |= PCIE_DESC_TX_UDP_CSUM;
		break;
	default:
		if (unlikely(net_ratelimit())) {
			nn_warn(nn, "partial checksum but l4 proto=%x!\n",
				l4_hdr);
		}
		return;
	}

	txd->flags |= PCIE_DESC_TX_CSUM;
	nn->hw_csum_tx++;
}

/**
 * nfp_net_tx() - Main transmit entry point
 * @skb:    SKB to transmit
 * @netdev: netdev structure
 *
 * Return: NETDEV_TX_OK on success.
 */
static int nfp_net_tx(struct sk_buff *skb, struct net_device *netdev)
{
	struct nfp_net *nn = netdev_priv(netdev);
	const struct skb_frag_struct *frag;
	struct nfp_net_tx_desc *txd, txdg;
	struct nfp_net_tx_ring *tx_ring;
	struct netdev_queue *nd_q;
	dma_addr_t dma_addr;
	unsigned int fsize;
	int nr_frags;
	int wr_idx;
	u16 qidx;
	int f;

	qidx = skb_get_queue_mapping(skb);
	tx_ring = &nn->tx_rings[qidx];
	nd_q = netdev_get_tx_queue(nn->netdev, qidx);

	nn_assert((tx_ring->wr_p - tx_ring->rd_p) <= tx_ring->cnt,
		  "rd_p=%u wr_p=%u cnt=%u\n",
		  tx_ring->rd_p, tx_ring->wr_p, tx_ring->cnt);

	nr_frags = skb_shinfo(skb)->nr_frags;

	if (unlikely(nfp_net_tx_full(tx_ring, nr_frags + 1))) {
		if (unlikely(net_ratelimit()))
			nn_dbg(nn, "TX ring %d busy. wrp=%u rdp=%u\n",
			       qidx, tx_ring->wr_p, tx_ring->rd_p);
		netif_tx_stop_queue(nd_q);
		tx_ring->r_vec->tx_busy++;
		return NETDEV_TX_BUSY;
	}

	/* Start with the head skbuf */
	dma_addr = dma_map_single(&nn->pdev->dev, skb->data, skb_headlen(skb),
				  DMA_TO_DEVICE);
	if (dma_mapping_error(&nn->pdev->dev, dma_addr)) {
		dev_kfree_skb_any(skb);
		nn->stats.tx_errors++;
		nn_warn(nn, "Failed to map DMA TX buffer\n");
		return NETDEV_TX_OK;
	}

	wr_idx = tx_ring->wr_p % tx_ring->cnt;

	/* Stash SKB away so we can free it after transmission */
	tx_ring->txbufs[wr_idx].skb = skb;
	tx_ring->txbufs[wr_idx].dma_addr = dma_addr;
	tx_ring->txbufs[wr_idx].fidx = -1;

	/* Build TX descriptor (assume it was zeroed before) */
	txd = &tx_ring->txds[wr_idx];
	txd->eop = (nr_frags == 0);
	txd->dma_len = skb_headlen(skb);
	txd->dma_addr_hi = ((uint64_t)dma_addr >> 32) & 0xff;
	txd->dma_addr_lo = dma_addr & 0xffffffff;
	txd->data_len = skb->len;

	nfp_net_tx_csum(nn, txd, skb);

	if (vlan_tx_tag_present(skb) && nn->ctrl & NFP_NET_CFG_CTRL_TXVLAN) {
		txd->flags |= PCIE_DESC_TX_VLAN;
		txd->vlan = vlan_tx_tag_get(skb);
	}

	/* Gather DMA */
	if (nr_frags > 0) {
		/* all descs must match except for in addr, length and eop */
		txdg = *txd;

		for (f = 0; f < nr_frags; f++) {
			frag = &skb_shinfo(skb)->frags[f];
			fsize = skb_frag_size(frag);

			dma_addr = skb_frag_dma_map(&nn->pdev->dev, frag, 0,
						    fsize, DMA_TO_DEVICE);
			if (dma_mapping_error(&nn->pdev->dev, dma_addr)) {
				nn->stats.tx_errors++;
				nn_warn(nn,
					"Failed to map DMA TX gather buffer\n");
				goto err_map;
			}

			wr_idx = (wr_idx + 1) % tx_ring->cnt;
			tx_ring->txbufs[wr_idx].skb = skb;
			tx_ring->txbufs[wr_idx].dma_addr = dma_addr;
			tx_ring->txbufs[wr_idx].fidx = f;

			txd = &tx_ring->txds[wr_idx];
			*txd = txdg;
			txd->dma_len = fsize;
			txd->dma_addr_hi = ((uint64_t)dma_addr >> 32) & 0xff;
			txd->dma_addr_lo = dma_addr & 0xffffffff;
			txd->eop = (f == nr_frags - 1);
		}

		nn->tx_gather++;
	}

	/* Increment write pointers. Force memory write before we let HW know */
	wmb();
	tx_ring->wr_p += nr_frags + 1;
	nfp_qcp_wr_ptr_add(tx_ring->qcp_q, nr_frags + 1);

	skb_tx_timestamp(skb);

	nn_assert((tx_ring->wr_p - tx_ring->rd_p) <= tx_ring->cnt,
		  "rd_p=%u wr_p=%u cnt=%u\n",
		  tx_ring->rd_p, tx_ring->wr_p, tx_ring->cnt);

	return NETDEV_TX_OK;

err_map:
	--f;
	while (f >= 0) {
		frag = &skb_shinfo(skb)->frags[f];
		dma_unmap_page(&nn->pdev->dev,
			       tx_ring->txbufs[wr_idx].dma_addr,
			       skb_frag_size(frag), DMA_TO_DEVICE);
		tx_ring->txbufs[wr_idx].skb = NULL;
		tx_ring->txbufs[wr_idx].dma_addr = 0;
		tx_ring->txbufs[wr_idx].fidx = -2;
		wr_idx = wr_idx - 1;
		if (wr_idx < 0)
			wr_idx += tx_ring->cnt;
	}
	/* unmap the first skbuff */
	dma_unmap_single(&nn->pdev->dev, tx_ring->txbufs[wr_idx].dma_addr,
			 skb_headlen(skb), DMA_TO_DEVICE);
	dev_kfree_skb_any(skb);
	tx_ring->txbufs[wr_idx].skb = NULL;
	tx_ring->txbufs[wr_idx].dma_addr = 0;
	tx_ring->txbufs[wr_idx].fidx = -2;
	return NETDEV_TX_OK;
}

/**
 * nfp_net_tx_complete() - Handled completed TX packets
 * @tx_ring:   TX ring structure
 *
 * Return: Number of completed TX descriptors
 */
static int nfp_net_tx_complete(struct nfp_net_tx_ring *tx_ring)
{
	struct nfp_net_r_vector *r_vec = tx_ring->r_vec;
	struct nfp_net *nn = r_vec->nfp_net;
	const struct skb_frag_struct *frag;
	int todo, completed = 0;
	struct sk_buff *skb;
	int nr_frags;
	u32 qcp_rd_p;
	int fidx;
	int idx;

	nn_assert((tx_ring->wr_p - tx_ring->rd_p) <= tx_ring->cnt,
		  "rd_p=%u wr_p=%u cnt=%u\n",
		  tx_ring->rd_p, tx_ring->wr_p, tx_ring->cnt);

	/* Work out how many descriptors have been transmitted */
	qcp_rd_p = nfp_qcp_rd_ptr_read(tx_ring->qcp_q);

	if (qcp_rd_p == tx_ring->qcp_rd_p)
		return 0;

	if (qcp_rd_p > tx_ring->qcp_rd_p)
		todo = qcp_rd_p - tx_ring->qcp_rd_p;
	else
		todo = qcp_rd_p + tx_ring->cnt - tx_ring->qcp_rd_p;

	while (todo > 0) {
		idx = tx_ring->rd_p % tx_ring->cnt;
		skb = tx_ring->txbufs[idx].skb;
		if (skb) {
			nr_frags = skb_shinfo(skb)->nr_frags;
			fidx = tx_ring->txbufs[idx].fidx;

			if (fidx == -1) {
				/* unmap head */
				dma_unmap_single(&nn->pdev->dev,
						 tx_ring->txbufs[idx].dma_addr,
						 skb_headlen(skb),
						 DMA_TO_DEVICE);
			} else {
				/* unmap fragment */
				frag = &skb_shinfo(skb)->frags[fidx];
				dma_unmap_page(&nn->pdev->dev,
					       tx_ring->txbufs[idx].dma_addr,
					       skb_frag_size(frag),
					       DMA_TO_DEVICE);
			}

			/* check for last gather fragment */
			if (fidx == nr_frags - 1) {
				nn->stats.tx_packets++;
				nn->stats.tx_bytes += skb->len;
				r_vec->tx_pkts++;
				dev_kfree_skb_any(skb);
			}

			tx_ring->txbufs[idx].dma_addr = 0;
			tx_ring->txbufs[idx].skb = NULL;
			tx_ring->txbufs[idx].fidx = -2;
		}

		/* Zero the TX descriptor to be on the safe side */
		memset(&tx_ring->txds[idx], 0, sizeof(tx_ring->txds[idx]));

		tx_ring->rd_p++;
		completed++;
		todo--;
	}

	tx_ring->qcp_rd_p = qcp_rd_p;

	/* Make sure the Read Pointer update gets written to the device */
	wmb();
	return completed;
}

/**
 * nfp_net_tx_flush() - Free any untransmitted buffers currently on the TX ring
 * @tx_ring:     TX ring structure
 *
 * Assumes that the device is stopped
 */
static void nfp_net_tx_flush(struct nfp_net_tx_ring *tx_ring)
{
	struct nfp_net_r_vector *r_vec = tx_ring->r_vec;
	struct nfp_net *nn = r_vec->nfp_net;
	struct pci_dev *pdev = nn->pdev;
	const struct skb_frag_struct *frag;
	struct sk_buff *skb;
	int nr_frags;
	int fidx;
	int idx;
#ifdef NFP_NET_HRTIMER_6000
	unsigned long flags;
#endif

	nn_assert((tx_ring->wr_p - tx_ring->rd_p) <= tx_ring->cnt,
		  "rd_p=%u wr_p=%u cnt=%u\n",
		  tx_ring->rd_p, tx_ring->wr_p, tx_ring->cnt);

#ifdef NFP_NET_HRTIMER_6000
	spin_lock_irqsave(&r_vec->txlock, flags);
#endif

	while (tx_ring->rd_p != tx_ring->wr_p) {
		idx = tx_ring->rd_p % tx_ring->cnt;

		skb = tx_ring->txbufs[idx].skb;
		if (skb) {
			nr_frags = skb_shinfo(skb)->nr_frags;
			fidx = tx_ring->txbufs[idx].fidx;

			if (fidx == -1) {
				/* unmap head */
				dma_unmap_single(&pdev->dev,
						 tx_ring->txbufs[idx].dma_addr,
						 skb_headlen(skb),
						 DMA_TO_DEVICE);
			} else {
				/* unmap fragment */
				frag = &skb_shinfo(skb)->frags[fidx];
				dma_unmap_page(&pdev->dev,
					       tx_ring->txbufs[idx].dma_addr,
					       skb_frag_size(frag),
					       DMA_TO_DEVICE);
			}

			/* check for last gather fragment */
			if (fidx == nr_frags - 1)
				dev_kfree_skb_any(skb);

			tx_ring->txbufs[idx].dma_addr = 0;
			tx_ring->txbufs[idx].skb = NULL;
			tx_ring->txbufs[idx].fidx = -2;
		}

		memset(&tx_ring->txds[idx], 0, sizeof(tx_ring->txds[idx]));

		tx_ring->qcp_rd_p++;
		tx_ring->rd_p++;
	}

#ifdef NFP_NET_HRTIMER_6000
	spin_unlock_irqrestore(&r_vec->txlock, flags);
#endif
}

static void nfp_net_tx_timeout(struct net_device *netdev)
{
	struct nfp_net *nn = netdev_priv(netdev);
	int i;

	for (i = 0; i < nn->num_tx_rings; i++) {
		if (!netif_tx_queue_stopped(netdev_get_tx_queue(netdev, i)))
			continue;
		nn_warn(nn, "TX timeout on ring: %d\n", i);
	}
	nn_warn(nn, "TX watchdog timeout\n");
}

/**
 * nfp_net_tx_dump() - Print the ring contents into the buffer
 * @tx_ring:   TX ring to print
 * @p:         Buffer to print into
 *
 * Assumes that the buffer pointed to by @p is big enough.
 *
 * Return: Number of characters added
 */
int nfp_net_tx_dump(struct nfp_net_tx_ring *tx_ring, char *p)
{
	struct nfp_net_tx_desc *txd;
	int d_rd_p, d_wr_p, txd_cnt;
	struct sk_buff *skb;
	int off = 0;
	int i;

	txd_cnt = tx_ring->cnt;

	d_rd_p = nfp_qcp_rd_ptr_read(tx_ring->qcp_q);
	d_wr_p = nfp_qcp_wr_ptr_read(tx_ring->qcp_q);

	off += sprintf(p + off, "TX[%02d]: H_RD=%d H_WR=%d D_RD=%d D_WR=%d\n",
		       tx_ring->idx, tx_ring->rd_p, tx_ring->wr_p,
		       d_rd_p, d_wr_p);

	for (i = 0; i < txd_cnt; i++) {
		txd = &tx_ring->txds[i];
		off += sprintf(p + off,
			       "%04d: 0x%08x 0x%08x 0x%08x 0x%08x", i,
			       txd->vals[0], txd->vals[1],
			       txd->vals[2], txd->vals[3]);

		if (tx_ring->txbufs && tx_ring->txbufs[i].skb) {
			skb = tx_ring->txbufs[i].skb;
			off += sprintf(p + off, " skb->head=%p skb->data=%p",
				       skb->head, skb->data);
		}
		if (tx_ring->txbufs && tx_ring->txbufs[i].dma_addr)
			off += sprintf(p + off, " dma_addr=%#llx",
				       (unsigned long long)
				       tx_ring->txbufs[i].dma_addr);

		if (i == tx_ring->rd_p % txd_cnt)
			off += sprintf(p + off, " H_RD");
		if (i == tx_ring->wr_p % txd_cnt)
			off += sprintf(p + off, " H_WR");
		if (i == d_rd_p % txd_cnt)
			off += sprintf(p + off, " D_RD");
		if (i == d_wr_p % txd_cnt)
			off += sprintf(p + off, " D_WR");

		off += sprintf(p + off, "\n");
	}

	return off;
}

/*
 * Receive processing
 */

/**
 * nfp_net_rx_space() - return the number of free slots on the RX ring
 * @rx_ring:   RX ring structure
 *
 * Make sure we leave at least one slot free.
 *
 * Return: True if there is space on the RX ring
 */
static inline int nfp_net_rx_space(struct nfp_net_rx_ring *rx_ring)
{
	return (rx_ring->cnt - 1) - (rx_ring->wr_p - rx_ring->rd_p);
}

/**
 * nfp_net_rx_csum() - set SKB checksum field based on RX descriptor flags
 * @nn:  NFP Net device
 * @rxd: Pointer to RX descriptor
 * @skb: Pointer to SKB
 */
static void nfp_net_rx_csum(struct nfp_net *nn,
			    struct nfp_net_rx_desc *rxd, struct sk_buff *skb)
{
	skb->ip_summed = CHECKSUM_NONE;

	if (!(nn->netdev->features & NETIF_F_RXCSUM))
		return;

	/* If IPv4 and IP checksum error, fail */
	if ((rxd->rxd.flags & PCIE_DESC_RX_IP4_CSUM) &&
	    !(rxd->rxd.flags & PCIE_DESC_RX_IP4_CSUM_OK))
		goto err_csum;

	/* If neither UDP nor TCP return */
	if (!(rxd->rxd.flags & PCIE_DESC_RX_TCP_CSUM) &&
	    !(rxd->rxd.flags & PCIE_DESC_RX_UDP_CSUM))
		return;

	if ((rxd->rxd.flags & PCIE_DESC_RX_TCP_CSUM) &&
	    !(rxd->rxd.flags & PCIE_DESC_RX_TCP_CSUM_OK))
		goto err_csum;

	if ((rxd->rxd.flags & PCIE_DESC_RX_UDP_CSUM) &&
	    !(rxd->rxd.flags & PCIE_DESC_RX_UDP_CSUM_OK))
		goto err_csum;

	skb->ip_summed = CHECKSUM_UNNECESSARY;

	nn->hw_csum_rx_ok++;
	skb->ip_summed = CHECKSUM_UNNECESSARY;
	return;

err_csum:
	skb->ip_summed = CHECKSUM_NONE;
	nn->hw_csum_rx_error++;
}

/**
 * nfp_net_set_hash() - Set SKB hash data
 * @skb:   SKB to set the hash data on
 * @rxd:   RX descriptor
 *
 * The RSS hash and hash-type are pre-pended to the packet data.
 * Extract and decode it and set the skb fields.
 */
static void nfp_net_set_hash(struct sk_buff *skb, struct nfp_net_rx_desc *rxd)
{
	u32 hash, hash_type;

	if (!(rxd->rxd.flags & PCIE_DESC_RX_RSS)) {
		skb_set_hash(skb, 0, PKT_HASH_TYPE_NONE);
		return;
	}

	hash = be32_to_cpu(*(u32 *)((u8 *)skb->data - 4));
	hash_type = be32_to_cpu(*(u32 *)((u8 *)skb->data - 8));

	switch (hash_type) {
	case NFP_NET_RSS_IPV4:
	case NFP_NET_RSS_IPV6:
	case NFP_NET_RSS_IPV6_EX:
		skb_set_hash(skb, hash, PKT_HASH_TYPE_L3);
		break;
	default:
		skb_set_hash(skb, hash, PKT_HASH_TYPE_L4);
	}
}

/**
 * nfp_net_rx() - receive up to @budget packets on @rx_ring
 * @rx_ring:   RX ring to receive from
 * @budget:    NAPI budget
 *
 * Note, this function is separated out from the napi poll function to
 * more cleanly separate packet receive code from other bookkeeping
 * functions performed in the napi poll function.
 *
 * There are differences between the NFP-3200 firmware and the
 * NFP-6000 firmware.  The NFP-3200 firmware uses a dedicated RX queue
 * to indicate that new packets have arrived.  The NFP-6000 does not
 * have this queue and uses the DD bit in the RX descriptor. This
 * method cannot be used on the NFP-3200 as it causes a race
 * condition: The RX ring write pointer on the NFP-3200 is updated
 * after packets (and descriptors) have been DMAed.  If the DD bit is
 * used and subsequently the read pointer is updated this may lead to
 * the RX queue to underflow (if the firmware has not yet update the
 * write pointer).  Therefore we use slightly ugly conditional code
 * below to handle the differences.  We may, in the future update the
 * NFP-3200 firmware to behave the same as the firmware on the
 * NFP-6000.
 *
 * Return: Number of packets received.
 */
static int nfp_net_rx(struct nfp_net_rx_ring *rx_ring, int budget)
{
	struct nfp_net_r_vector *r_vec = rx_ring->r_vec;
	struct nfp_net *nn = r_vec->nfp_net;
	unsigned int data_len, meta_len;
	int avail = 0, pkts_polled = 0;
	struct nfp_net_rx_desc *rxd;
	struct sk_buff *skb;
	u32 qcp_wr_p;
	int idx;

	if (nn->is_nfp3200) {
		/* Work out how many packets arrived */
		qcp_wr_p = nfp_qcp_wr_ptr_read(rx_ring->qcp_rx);
		idx = rx_ring->rd_p % rx_ring->cnt;

		if (qcp_wr_p == idx)
			/* No new packets */
			return 0;

		if (qcp_wr_p > idx)
			avail = qcp_wr_p - idx;
		else
			avail = qcp_wr_p + rx_ring->cnt - idx;
	} else {
		avail = budget + 1;
	}

	while (avail > 0 && pkts_polled < budget) {
		idx = rx_ring->rd_p % rx_ring->cnt;

		skb = rx_ring->rxbufs[idx].skb;
		if (!skb) {
			nn_err(nn, "No SKB with RX descriptor %d:%u\n",
			       rx_ring->idx, idx);
			break;
		}

		/* Memory barrier to ensure that we won't do other reads
		 * before the DD bit.
		 */
		rmb();
		rxd = &rx_ring->rxds[idx];
		if (!rxd->rxd.dd) {
			if (nn->is_nfp3200)
				nn_dbg(nn, "RX descriptor not valid (DD)%d:%u rxd[0]=%#x rxd[1]=%#x\n",
				       rx_ring->idx, idx,
				       rxd->vals[0], rxd->vals[1]);
			break;
		}

		if (rxd->rxd.data_len > nn->fl_bufsz) {
			nn_err(nn, "RX data larger than freelist buffer (%u > %u) on %d:%u rxd[0]=%#x rxd[1]=%#x\n",
			       rxd->rxd.data_len, nn->fl_bufsz,
			       rx_ring->idx, idx, rxd->vals[0], rxd->vals[1]);
			/* Halt here. The device may have DMAed beyond the end
			 * of the freelist buffer and all bets are off.
			 */
			BUG();
			break;
		}

		dma_unmap_single(&nn->pdev->dev,
				 rx_ring->rxbufs[idx].dma_addr,
				 nn->fl_bufsz, DMA_FROM_DEVICE);

		meta_len = rxd->rxd.meta_len;
		data_len = rxd->rxd.data_len;

		/* The packet data starts at a fixed offset */
		skb_reserve(skb, NFP_NET_RX_OFFSET);

		/* Adjust the SKB for the meta data pre-pended */
		skb_put(skb, data_len - meta_len);

		nfp_net_set_hash(skb, rxd);

		/* Pad small frames to minimum */
		if (unlikely(skb->len < 60)) {
			int pad_len = 60 - skb->len;

			if (skb_pad(skb, pad_len))
				break;
			__skb_put(skb, pad_len);
		}

		/* Stats update */
		nn->stats.rx_packets++;
		nn->stats.rx_bytes += skb->len;
		r_vec->rx_pkts++;

		skb_record_rx_queue(skb, rx_ring->idx);
		skb->protocol = eth_type_trans(skb, nn->netdev);

		nfp_net_rx_csum(nn, rxd, skb);

		if (rxd->rxd.flags & PCIE_DESC_RX_VLAN)
			__vlan_hwaccel_put_tag(skb, htons(ETH_P_8021Q),
					       le16_to_cpu(rxd->rxd.vlan));

		netif_receive_skb(skb);

		/* Clear internal state to be on the safe side */
		rx_ring->rxbufs[idx].skb = NULL;
		rx_ring->rxbufs[idx].dma_addr = 0;
		memset(&rx_ring->rxds[idx], 0, sizeof(rx_ring->rxds[idx]));

		rx_ring->rd_p++;
		pkts_polled++;
		avail--;
	}

	if (nn->is_nfp3200)
		nfp_qcp_rd_ptr_add(rx_ring->qcp_rx, pkts_polled);

	return pkts_polled;
}

/**
 * nfp_net_rx_fill_freelist() - Attempt filling freelist with RX buffers
 * @rx_ring: RX ring to fill
 *
 * Try to fill as many buffers as possible into freelist.  Return
 * number of buffers added.
 *
 * Return: Number of freelist buffers added.
 */
static int nfp_net_rx_fill_freelist(struct nfp_net_rx_ring *rx_ring)
{
	struct nfp_net_r_vector *r_vec = rx_ring->r_vec;
	struct nfp_net *nn = r_vec->nfp_net;
	struct nfp_net_rx_desc *rxd;
	struct sk_buff *skb;
	dma_addr_t dma_addr;
	unsigned int bufsz;
	int i, wr_idx;
	int added = 0;

	bufsz = nn->fl_bufsz;

	while (nfp_net_rx_space(rx_ring) >= NFP_NET_FL_BATCH) {
		for (i = 0; i < NFP_NET_FL_BATCH; i++) {
			skb = netdev_alloc_skb(nn->netdev, bufsz);
			if (!skb) {
				nn_warn(nn, "Failed to alloc receive SKB\n");
				break;
			}

			dma_addr = dma_map_single(&nn->pdev->dev, skb->data,
						  bufsz, DMA_FROM_DEVICE);
			if (dma_mapping_error(&nn->pdev->dev, dma_addr)) {
				dev_kfree_skb_any(skb);
				nn_warn(nn, "Failed to map DMA RX buffer\n");
				break;
			}

			wr_idx = rx_ring->wr_p % rx_ring->cnt;

			/* Stash SKB and DMA address away */
			rx_ring->rxbufs[wr_idx].skb = skb;
			rx_ring->rxbufs[wr_idx].dma_addr = dma_addr;

			/* Fill freelist descriptor */
			rxd = &rx_ring->rxds[wr_idx];
			rxd->fld.dd = 0;
			rxd->fld.dma_addr_hi = ((uint64_t)dma_addr >> 32)
					       & 0xff;
			rxd->fld.dma_addr_lo = dma_addr & 0xffffffff;
			rx_ring->wr_p++;
		}

		/* Update write pointer of the freelist queue. Make
		 * sure all writes are flushed before telling the hardware.
		 */
		wmb();
		nfp_qcp_wr_ptr_add(rx_ring->qcp_fl, i);
		added += i;

		/* stop on error */
		if (i < NFP_NET_FL_BATCH)
			break;
	}

	return added;
}

/**
 * nfp_net_rx_flush() - Free any buffers currently on the RX ring
 * @rx_ring:  RX ring to remove buffers from
 *
 * Assumes that the device is stopped
 */
static void nfp_net_rx_flush(struct nfp_net_rx_ring *rx_ring)
{
	struct nfp_net_r_vector *r_vec = rx_ring->r_vec;
	struct nfp_net *nn = r_vec->nfp_net;
	struct pci_dev *pdev = nn->pdev;
	int idx;

	while (rx_ring->rd_p != rx_ring->wr_p) {
		idx = rx_ring->rd_p % rx_ring->cnt;

		if (rx_ring->rxbufs[idx].skb) {
			dma_unmap_single(&pdev->dev,
					 rx_ring->rxbufs[idx].dma_addr,
					 rx_ring->rxbufs[idx].skb->len,
					 DMA_FROM_DEVICE);
			dev_kfree_skb_any(rx_ring->rxbufs[idx].skb);
			rx_ring->rxbufs[idx].dma_addr = 0;
			rx_ring->rxbufs[idx].skb = NULL;
		}

		memset(&rx_ring->rxds[idx], 0, sizeof(rx_ring->rxds[idx]));

		rx_ring->rd_p++;
	}
}

/**
 * nfp_net_rx_dump() - Print the ring contents into the buffer
 * @rx_ring:   RX ring to print
 * @p:         Buffer to print into
 *
 * Assumes that the buffer pointed to by @p is big enough.
 *
 * Return: Number of characters added
 */
int nfp_net_rx_dump(struct nfp_net_rx_ring *rx_ring, char *p)
{
	int fl_rd_p, fl_wr_p, rx_rd_p, rx_wr_p, rxd_cnt;
	struct nfp_net_rx_desc *rxd;
	struct sk_buff *skb;
	int off = 0;
	int i;

	rxd_cnt = rx_ring->cnt;

	fl_rd_p = nfp_qcp_rd_ptr_read(rx_ring->qcp_fl);
	fl_wr_p = nfp_qcp_wr_ptr_read(rx_ring->qcp_fl);
	rx_rd_p = nfp_qcp_rd_ptr_read(rx_ring->qcp_rx);
	rx_wr_p = nfp_qcp_wr_ptr_read(rx_ring->qcp_rx);

	off += sprintf(p + off,
		       "RX[%02d]: H_RD=%d H_WR=%d FL_RD=%d FL_WR=%d RX_RD=%d RX_WR=%d\n",
		       rx_ring->idx, rx_ring->rd_p, rx_ring->wr_p,
		       fl_rd_p, fl_wr_p, rx_rd_p, rx_wr_p);

	for (i = 0; i < rxd_cnt; i++) {
		rxd = &rx_ring->rxds[i];
		off += sprintf(p + off, "%04d: 0x%08x 0x%08x",
			       i, rxd->vals[0], rxd->vals[1]);

		if (rx_ring->rxbufs && rx_ring->rxbufs[i].skb) {
			skb = rx_ring->rxbufs[i].skb;
			off += sprintf(p + off, " skb->head=%p skb->data=%p",
				       skb->head, skb->data);
		}
		if (rx_ring->rxbufs && rx_ring->rxbufs[i].dma_addr)
			off += sprintf(p + off, " dma_addr=%#llx",
				       (unsigned long long)
				       rx_ring->rxbufs[i].dma_addr);

		if (i == rx_ring->rd_p % rxd_cnt)
			off += sprintf(p + off, " H_RD ");
		if (i == rx_ring->wr_p % rxd_cnt)
			off += sprintf(p + off, " H_WR ");
		if (i == fl_rd_p % rxd_cnt)
			off += sprintf(p + off, " FL_RD");
		if (i == fl_wr_p % rxd_cnt)
			off += sprintf(p + off, " FL_WR");
		if (i == rx_rd_p % rxd_cnt)
			off += sprintf(p + off, " RX_RD");
		if (i == rx_wr_p % rxd_cnt)
			off += sprintf(p + off, " RX_WR");

		off += sprintf(p + off, "\n");
	}

	return off;
}

/**
 * nfp_net_poll() - napi poll function
 * @napi:    NAPI structure
 * @budget:  NAPI budget
 *
 * Return: 0 if done with polling.
 */
static int nfp_net_poll(struct napi_struct *napi, int budget)
{
	struct nfp_net_r_vector *r_vec =
		container_of(napi, struct nfp_net_r_vector, napi);
	struct nfp_net_rx_ring *rx_ring = r_vec->rx_ring;
	struct nfp_net_tx_ring *tx_ring = r_vec->tx_ring;
	struct nfp_net *nn = r_vec->nfp_net;
	struct netdev_queue *txq;
	bool complete = true;
	int pkts_completed;
	int pkts_polled;

	/* Handle completed TX. If the TX queue was stopped, re-enable it */
	tx_ring = &nn->tx_rings[rx_ring->idx];
	txq = netdev_get_tx_queue(nn->netdev, tx_ring->idx);

	pkts_completed = nfp_net_tx_complete(tx_ring);
	if (pkts_completed)
		complete = false;

	if (unlikely(netif_tx_queue_stopped(txq)) && pkts_completed)
		netif_tx_wake_queue(txq);

	/* Receive any packets */
	pkts_polled = nfp_net_rx(rx_ring, budget);
	if (pkts_polled)
		complete = false;

	/* refill freelist  */
	nfp_net_rx_fill_freelist(rx_ring);

	if (!complete)
		return budget;

	/* If there are no more packets to receive and no more TX
	 * descriptors to be cleaned, unmask the MSI-X vector and
	 * switch NAPI back into interrupt mode.
	 */
	napi_complete(napi);

	nfp_net_irq_unmask(nn, r_vec->irq_idx);

	return 0;
}

/*
 * Setup and Configuration
 */

/**
 * nfp_net_tx_ring_free() - Free resources allocated to a TX ring
 * @tx_ring:   TX ring to free
 */
static void nfp_net_tx_ring_free(struct nfp_net_tx_ring *tx_ring)
{
	struct nfp_net_r_vector *r_vec = tx_ring->r_vec;
	struct nfp_net *nn = r_vec->nfp_net;
	struct pci_dev *pdev = nn->pdev;

	nn_writeq(nn->ctrl_bar, NFP_NET_CFG_TXR_ADDR(tx_ring->idx), 0);
	nn_writeb(nn->ctrl_bar, NFP_NET_CFG_TXR_SZ(tx_ring->idx), 0);
	nn_writeb(nn->ctrl_bar, NFP_NET_CFG_TXR_VEC(tx_ring->idx), 0);

	kfree(tx_ring->txbufs);

	if (tx_ring->txds)
		dma_free_coherent(&pdev->dev, tx_ring->size,
				  tx_ring->txds, tx_ring->dma);

	tx_ring->cnt = 0;
	tx_ring->wr_p = 0;
	tx_ring->rd_p = 0;
	tx_ring->qcp_rd_p = 0;

	tx_ring->txbufs = NULL;
	tx_ring->txds = NULL;
	tx_ring->dma = 0;
	tx_ring->size = 0;
}

/**
 * nfp_net_tx_ring_alloc() - Allocate resource for a TX ring
 * *tx_ring:   TX Ring structure to allocate
 *
 * Return: 0 on success, negative errno otherwise.
 */
static int nfp_net_tx_ring_alloc(struct nfp_net_tx_ring *tx_ring)
{
	struct nfp_net_r_vector *r_vec = tx_ring->r_vec;
	struct nfp_net *nn = r_vec->nfp_net;
	struct pci_dev *pdev = nn->pdev;
	int err, sz;

	tx_ring->cnt = nn->txd_cnt;

	tx_ring->size = sizeof(*tx_ring->txds) * tx_ring->cnt;
	tx_ring->txds = dma_zalloc_coherent(&pdev->dev, tx_ring->size,
					    &tx_ring->dma, GFP_KERNEL);
	if (!tx_ring->txds) {
		err = -ENOMEM;
		goto err_alloc;
	}

	sz = sizeof(*tx_ring->txbufs) * tx_ring->cnt;
	tx_ring->txbufs = kzalloc(sz, GFP_KERNEL);
	if (!tx_ring->txbufs) {
		err = -ENOMEM;
		goto err_alloc;
	}

	/* Write the DMA address, size and MSI-X info to the device */
	nn_writeq(nn->ctrl_bar,
		  NFP_NET_CFG_TXR_ADDR(tx_ring->idx), tx_ring->dma);
	nn_writeb(nn->ctrl_bar,
		  NFP_NET_CFG_TXR_SZ(tx_ring->idx), ilog2(tx_ring->cnt));
	nn_writeb(nn->ctrl_bar,
		  NFP_NET_CFG_TXR_VEC(tx_ring->idx), r_vec->irq_idx);

	netif_set_xps_queue(nn->netdev, &r_vec->affinity_mask, tx_ring->idx);

	nn_dbg(nn, "TxQ%02d: QCidx=%02d cnt=%d dma=%#llx host=%p\n",
	       tx_ring->idx, tx_ring->qcidx,
	       tx_ring->cnt, (unsigned long long)tx_ring->dma, tx_ring->txds);

	return 0;

err_alloc:
	nfp_net_tx_ring_free(tx_ring);
	return err;
}

/**
 * nfp_net_rx_ring_free() - Free resources allocated to a RX ring
 * @rx_ring:  RX ring to free
 */
static void nfp_net_rx_ring_free(struct nfp_net_rx_ring *rx_ring)
{
	struct nfp_net_r_vector *r_vec = rx_ring->r_vec;
	struct nfp_net *nn = r_vec->nfp_net;
	struct pci_dev *pdev = nn->pdev;

	nn_writeq(nn->ctrl_bar, NFP_NET_CFG_RXR_ADDR(rx_ring->idx), 0);
	nn_writeb(nn->ctrl_bar, NFP_NET_CFG_RXR_SZ(rx_ring->idx), 0);
	nn_writeb(nn->ctrl_bar, NFP_NET_CFG_RXR_VEC(rx_ring->idx), 0);

	kfree(rx_ring->rxbufs);

	if (rx_ring->rxds)
		dma_free_coherent(&pdev->dev, rx_ring->size,
				  rx_ring->rxds, rx_ring->dma);

	rx_ring->cnt = 0;
	rx_ring->wr_p = 0;
	rx_ring->rd_p = 0;

	rx_ring->rxbufs = NULL;
	rx_ring->rxds = NULL;
	rx_ring->dma = 0;
	rx_ring->size = 0;
}

/**
 * nfp_net_rx_ring_alloc() - Allocate resource for a RX ring
 * @rx_ring:  RX ring to allocate
 *
 * Return: 0 on success, negative errno otherwise.
 */
static int nfp_net_rx_ring_alloc(struct nfp_net_rx_ring *rx_ring)
{
	struct nfp_net_r_vector *r_vec = rx_ring->r_vec;
	struct nfp_net *nn = r_vec->nfp_net;
	struct pci_dev *pdev = nn->pdev;
	int err, sz;

	rx_ring->cnt = nn->rxd_cnt;

	rx_ring->size = sizeof(*rx_ring->rxds) * rx_ring->cnt;
	rx_ring->rxds = dma_zalloc_coherent(&pdev->dev, rx_ring->size,
					    &rx_ring->dma, GFP_KERNEL);
	if (!rx_ring->rxds) {
		err = -ENOMEM;
		goto err_alloc;
	}

	sz = sizeof(*rx_ring->rxbufs) * rx_ring->cnt;
	rx_ring->rxbufs = kzalloc(sz, GFP_KERNEL);
	if (!rx_ring->rxbufs) {
		err = -ENOMEM;
		goto err_alloc;
	}

	/* Write the DMA address, size and MSI-X info to the device */
	nn_writeq(nn->ctrl_bar,
		  NFP_NET_CFG_RXR_ADDR(rx_ring->idx), rx_ring->dma);
	nn_writeb(nn->ctrl_bar,
		  NFP_NET_CFG_RXR_SZ(rx_ring->idx), ilog2(rx_ring->cnt));
	nn_writeb(nn->ctrl_bar,
		  NFP_NET_CFG_RXR_VEC(rx_ring->idx), r_vec->irq_idx);

	nn_dbg(nn, "RxQ%02d: FlQCidx=%02d RxQCidx=%02d cnt=%d dma=%#llx host=%p\n",
	       rx_ring->idx, rx_ring->fl_qcidx, rx_ring->rx_qcidx,
	       rx_ring->cnt, (unsigned long long)rx_ring->dma, rx_ring->rxds);

	return 0;

err_alloc:
	nfp_net_rx_ring_free(rx_ring);
	return err;
}

#ifdef NFP_NET_HRTIMER_6000
/**
 * nfp_net_timer() - Handler for nfp_net timer interrupts
 * @hrtimer:  HRTimer structure
 *
 * Handler invoked upon timer ticks. If we currently have napi
 * polling enabled we only do the TX completion polling here.
 *
 * @Return: HRTIMER_RESTAR to restart the timer.
 */
static enum hrtimer_restart nfp_net_timer(struct hrtimer *hrtimer)
{
	struct nfp_net_r_vector *r_vec =
		container_of(hrtimer, struct nfp_net_r_vector, timer);
	struct nfp_net_rx_ring *rx_ring = r_vec->rx_ring;
	struct nfp_net_tx_ring *tx_ring = r_vec->tx_ring;
	struct nfp_net *nn = r_vec->nfp_net;
	struct netdev_queue *txq;
	unsigned long flags;
	int pkts_completed;

	nn_assert(r_vec != 0, "r_vec = 0\n");
	nn_assert(rx_ring != 0, "rx_ring = 0\n");
	nn_assert(tx_ring != 0, "tx_ring = 0\n");
	nn_assert(nn != 0, "nn = 0\n");

	if (likely(napi_schedule_prep(&r_vec->napi))) {
		r_vec->napi_polling = 1;
		__napi_schedule(&r_vec->napi);
	}

	if (!r_vec->napi_polling) {
		nfp_net_rx(rx_ring, INT_MAX);

		/* refill freelist  */
		nfp_net_rx_fill_freelist(rx_ring);
		spin_lock_irqsave(&r_vec->txlock, flags);

		/* Handle completed TX. If TX queue was stopped, re-enable it */
		tx_ring = &nn->tx_rings[rx_ring->idx];
		txq = netdev_get_tx_queue(nn->netdev, tx_ring->idx);

		pkts_completed = nfp_net_tx_complete(tx_ring);

		if (unlikely(netif_tx_queue_stopped(txq)) && pkts_completed)
			netif_tx_wake_queue(txq);

		spin_unlock_irqrestore(&r_vec->txlock, flags);
	}

	hrtimer_add_expires(&r_vec->timer, r_vec->timer_interval);

	return HRTIMER_RESTART;
}
#endif

/**
 * nfp_net_alloc_resources() - Allocate resources for RX and TX rings
 * @nn:      NFP Net device to reconfigure
 *
 * Return: 0 on success or negative errno on error.
 */
static int nfp_net_alloc_resources(struct nfp_net *nn)
{
	struct nfp_net_r_vector *r_vec;
	struct msix_entry *entry;
	int err;
	int r;

	for (r = 0; r < nn->num_r_vecs; r++) {
		r_vec = &nn->r_vecs[r];

		clear_bit(NFP_NET_RVEC_NAPI_STARTED, &r_vec->flags);

		/* Setup NAPI */
		netif_napi_add(nn->netdev, &r_vec->napi,
			       nfp_net_poll, NFP_NET_NAPI_WEIGHT);

		if (!nn->hrtimer && nn->num_vecs > 1) {
			/* Request the interrupt if available */
			entry = &nn->irq_entries[r_vec->irq_idx];

			snprintf(r_vec->name, sizeof(r_vec->name),
				 "%s-rxtx-%d", nn->netdev->name, r);
			err = request_irq(entry->vector, r_vec->handler, 0,
					  r_vec->name, r_vec);
			if (err) {
				nn_dbg(nn, "Error requesting IRQ %d\n",
				       entry->vector);
				goto err_alloc;
			}

			r_vec->requested = 1;

			irq_set_affinity_hint(entry->vector,
					      &r_vec->affinity_mask);

			nn_dbg(nn, "RV%02d: irq=%03d/%03d\n",
			       r, entry->vector, entry->entry);
		}

		/* Allocate TX ring resources */
		if (r_vec->tx_ring) {
			err = nfp_net_tx_ring_alloc(r_vec->tx_ring);
			if (err)
				goto err_alloc;
		}

		/* Allocate RX ring resources */
		if (r_vec->rx_ring) {
			err = nfp_net_rx_ring_alloc(r_vec->rx_ring);
			if (err)
				goto err_alloc;
		}

		r_vec->tx_pkts = 0;
		r_vec->rx_pkts = 0;

#ifdef NFP_NET_HRTIMER_6000
		/* Setup a timer for polling Qs at regular intervals. */
		hrtimer_init(&r_vec->timer,
			     CLOCK_MONOTONIC, HRTIMER_MODE_REL);
		r_vec->timer.function = nfp_net_timer;
		if (!pollinterval)
			pollinterval = 1000;
		r_vec->timer_interval =
			ns_to_ktime(pollinterval * 1000UL);
#endif
	}

	return 0;

err_alloc:
	while (r--) {
		r_vec =  &nn->r_vecs[r];

		if (r_vec->rx_ring)
			nfp_net_rx_ring_free(r_vec->rx_ring);
		if (r_vec->tx_ring)
			nfp_net_tx_ring_free(r_vec->tx_ring);

		if (r_vec->requested) {
			entry = &nn->irq_entries[r_vec->irq_idx];
			irq_set_affinity_hint(entry->vector, NULL);
			free_irq(entry->vector, r_vec);
			r_vec->requested = 0;
		}
		netif_napi_del(&r_vec->napi);
	}
	return err;
}

/**
 * nfp_net_free_resources() - Free all resources
 * @nn:      NFP Net device to reconfigure
 */
static void nfp_net_free_resources(struct nfp_net *nn)
{
	struct nfp_net_r_vector *r_vec;
	struct msix_entry *entry;
	int i;

	for (i = 0; i < nn->num_r_vecs; i++) {
		r_vec = &nn->r_vecs[i];
		entry = &nn->irq_entries[r_vec->irq_idx];

		if (r_vec->rx_ring)
			nfp_net_rx_ring_free(r_vec->rx_ring);
		if (r_vec->tx_ring)
			nfp_net_tx_ring_free(r_vec->tx_ring);

		if (r_vec->requested) {
			irq_set_affinity_hint(entry->vector, NULL);
			synchronize_irq(entry->vector);
			free_irq(entry->vector, r_vec);
			r_vec->requested = 0;
		}

		netif_napi_del(&r_vec->napi);
	}
}

/**
 * nfp_net_rss_write_itbl() - Write RSS indirection table to device
 * @nn:      NFP Net device to reconfigure
 */
void nfp_net_rss_write_itbl(struct nfp_net *nn)
{
	u32 val;
	int i, j;

	for (i = 0, j = 0; i < NFP_NET_CFG_RSS_ITBL_SZ; i += 4) {
		val = nn->rss_itbl[j++];
		val |= nn->rss_itbl[j++] << 8;
		val |= nn->rss_itbl[j++] << 16;
		val |= nn->rss_itbl[j++] << 24;

		nn_writel(nn->ctrl_bar, NFP_NET_CFG_RSS_ITBL + i, val);
	}
}

/**
 * nfp_net_netdev_open() - Called when the device is upped
 * @netdev:      netdev structure
 *
 * Return: 0 on success or negative errno on error.
 */
static int nfp_net_netdev_open(struct net_device *netdev)
{
	struct nfp_net *nn = netdev_priv(netdev);
	struct nfp_net_r_vector *r_vec;
	int err, n, i, r;
	u32 update = 0;
	u32 new_ctrl;
	u32 rss_cfg;
	u32 sts;

	if (nn->ctrl & NFP_NET_CFG_CTRL_ENABLE) {
		nn_err(nn, "Dev is already enabled: 0x%08x\n", nn->ctrl);
		return -EBUSY;
	}

	netif_carrier_off(netdev);

	new_ctrl = nn->ctrl;

	/* Step 1: Allocate resources for rings and the like
	 * - Request interrupts
	 * - Allocate RX and TX ring resources
	 * - Setup initial RSS table
	 */
	nfp_net_irqs_request(netdev);

	err = nfp_net_alloc_resources(nn);
	if (err)
		goto err_alloc_rings;

	err = netif_set_real_num_tx_queues(netdev, nn->num_tx_rings);
	if (err)
		goto err_set_queues;

	err = netif_set_real_num_rx_queues(netdev, nn->num_rx_rings);
	if (err)
		goto err_set_queues;

	if (nn->cap & NFP_NET_CFG_CTRL_RSS) {
		for (i = 0; i < sizeof(nn->rss_itbl); i++)
			nn->rss_itbl[i] =
				ethtool_rxfh_indir_default(i, nn->num_rx_rings);
		nfp_net_rss_write_itbl(nn);

		new_ctrl |= NFP_NET_CFG_CTRL_RSS;

		/* Enable IPv4/IPv6 TCP by default */
		rss_cfg = NFP_NET_CFG_RSS_IPV4_TCP |
			NFP_NET_CFG_RSS_IPV6_TCP |
			NFP_NET_CFG_RSS_TOEPLITZ |
			NFP_NET_CFG_RSS_MASK;
		writel(cpu_to_le32(rss_cfg),
		       nn->ctrl_bar + NFP_NET_CFG_RSS_CTRL);
		update |= NFP_NET_CFG_UPDATE_RSS;
	}

	/* Step 2: Configure the NFP
	 * - Enable rings from 0 to tx_rings/rx_rings - 1.
	 * - Write MAC address (in case it changed)
	 * - Set the MTU
	 * - Set the Freelist buffer size
	 * - Enable the FW
	 */
	nn_writeq(nn->ctrl_bar, NFP_NET_CFG_TXRS_ENABLE,
		  nn->num_tx_rings == 64 ? 0xffffffffffffffff
		  : ((u64)1 << nn->num_tx_rings) - 1);

	nn_writeq(nn->ctrl_bar, NFP_NET_CFG_RXRS_ENABLE,
		  nn->num_rx_rings == 64 ? 0xffffffffffffffff
		  : ((u64)1 << nn->num_rx_rings) - 1);

	nn_writel(nn->ctrl_bar, NFP_NET_CFG_MACADDR,
		  cpu_to_be32(*(u32 *)nn->netdev->dev_addr));
	nn_writel(nn->ctrl_bar, NFP_NET_CFG_MACADDR + 4,
		  cpu_to_be32(*(u32 *)(nn->netdev->dev_addr + 4)));

	nn_writel(nn->ctrl_bar, NFP_NET_CFG_MTU, netdev->mtu);
	nn_writel(nn->ctrl_bar, NFP_NET_CFG_FLBUFSZ, nn->fl_bufsz);

	/* Enable device */
	new_ctrl |= NFP_NET_CFG_CTRL_ENABLE;
	update |= NFP_NET_CFG_UPDATE_GEN;
	update |= NFP_NET_CFG_UPDATE_RING;
	if (nn->cap & NFP_NET_CFG_CTRL_RINGCFG)
		new_ctrl |= NFP_NET_CFG_CTRL_RINGCFG;

	if (nn->pdev->msix_enabled)
		update |= NFP_NET_CFG_UPDATE_MSIX;

	if (nn->rss_cfg)
		update |= NFP_NET_CFG_UPDATE_RSS;

	nn_writel(nn->ctrl_bar, NFP_NET_CFG_CTRL, new_ctrl);
	err = nfp_net_reconfig(nn, update);
	if (err)
		goto err_reconfig;

	nn->ctrl = new_ctrl;

	/* Step 3: Enable for kernel
	 * - put some freelist descriptors on each RX ring
	 * - enable NAPI on each ring
	 * - enable all TX queues
	 * - set link state
	 * - start hrtimer
	 */
	for (r = 0; r < nn->num_r_vecs; r++) {
		r_vec = &nn->r_vecs[r];
		n = nfp_net_rx_fill_freelist(r_vec->rx_ring);
		nn_dbg(nn, "RV%02d RxQ%02d: Added %d freelist buffers\n",
		       r, r_vec->rx_ring->idx, n);

		napi_enable(&r_vec->napi);
		set_bit(NFP_NET_RVEC_NAPI_STARTED, &r_vec->flags);

#ifdef NFP_NET_HRTIMER_6000
		hrtimer_start(&r_vec->timer,
			      r_vec->timer_interval,
			      HRTIMER_MODE_REL);
#endif
	}

	netif_tx_wake_all_queues(netdev);

	sts = nn_readl(nn->ctrl_bar, NFP_NET_CFG_STS);
	nn->link_up = !!(sts & NFP_NET_CFG_STS_LINK);
	if (nn->link_up) {
		nfp_net_print_link(nn, true);
		netif_carrier_on(netdev);
	} else {
		nfp_net_print_link(nn, false);
	}

	/* If the firmware is receiving traffic, the RX rings
	 * can become full in the time between the configuration
	 * update and the NAPI initialization.
	 *
	 * If the RX ring is full, the firmware will drop packets,
	 * and we will not get an interrupt to trigger a NAPI
	 * schedule.
	 *
	 * Therefore, we call napi_schedule() explicitly here
	 * to kick all the RX rings so that they will start
	 * generating interrupts on RXed packets.
	 *
	 * Even though we are calling napi_schedule() on a
	 * single CPU here, this will only be done on device
	 * open time - NAPI processing will migrate to multiple
	 * CPUs after this scheduled NAPI poll.
	 */
	for (r = 0; r < nn->num_r_vecs; r++) {
		r_vec = &nn->r_vecs[r];
		napi_schedule(&r_vec->napi);
	}

	return 0;

err_reconfig:
	/* Could clean up some of the cfg BAR settings here */
#ifdef NFP_NET_HRTIMER_6000
	for (r = 0; r < nn->num_r_vecs; r++) {
		r_vec = &nn->r_vecs[r];
		hrtimer_cancel(&r_vec->timer);
	}
#endif
err_set_queues:
	nfp_net_free_resources(nn);
err_alloc_rings:
	nfp_net_irqs_free(netdev);
	return err;
}

/**
 * nfp_net_netdev_close() - Called when the device is downed
 * @netdev:      netdev structure
 */
static int nfp_net_netdev_close(struct net_device *netdev)
{
	struct nfp_net *nn = netdev_priv(netdev);
	unsigned int new_ctrl, update;
	int err, r, i;

	if (!(nn->ctrl & NFP_NET_CFG_CTRL_ENABLE)) {
		nn_err(nn, "Dev is not up: 0x%08x\n", nn->ctrl);
		return 0;
	}

	/*
	 * Step 1: Disable RX and TX rings from the Linux kernel perspective
	 */

	netif_carrier_off(netdev);

	for (r = 0; r < nn->num_r_vecs; r++) {
		clear_bit(NFP_NET_RVEC_NAPI_STARTED, &nn->r_vecs[r].flags);
		napi_disable(&nn->r_vecs[r].napi);
	}

	netif_tx_disable(netdev);

	/*
	 * Step 2: cancel hrtimers
	 */
#ifdef NFP_NET_HRTIMER_6000
	for (r = 0; r < nn->num_r_vecs; r++)
		hrtimer_cancel(&nn->r_vecs[r].timer);
#endif
	/*
	 * Step 3: Tell NFP
	 */
	new_ctrl = nn->ctrl;
	new_ctrl &= ~NFP_NET_CFG_CTRL_ENABLE;
	update = NFP_NET_CFG_UPDATE_GEN;
	update |= NFP_NET_CFG_UPDATE_RING;
	if (nn->pdev->msix_enabled)
		update |= NFP_NET_CFG_UPDATE_MSIX;

	if (nn->cap & NFP_NET_CFG_CTRL_RINGCFG)
		new_ctrl &= ~NFP_NET_CFG_CTRL_RINGCFG;

	nn_writeq(nn->ctrl_bar, NFP_NET_CFG_TXRS_ENABLE, 0);
	nn_writeq(nn->ctrl_bar, NFP_NET_CFG_RXRS_ENABLE, 0);

	/* Notify NFP */
	nn_writel(nn->ctrl_bar, NFP_NET_CFG_CTRL, new_ctrl);
	err = nfp_net_reconfig(nn, update);
	if (err)
		return err;

	nn->ctrl = new_ctrl;

	/*
	 * Step 4: Free resources
	 */
	for (i = 0; i < nn->num_r_vecs; i++) {
		nfp_net_rx_flush(nn->r_vecs[i].rx_ring);
		nfp_net_tx_flush(nn->r_vecs[i].tx_ring);
	}

	nfp_net_free_resources(nn);
	nfp_net_irqs_free(netdev);

	nn_dbg(nn, "%s down", netdev->name);
	return 0;
}

static void nfp_net_set_rx_mode(struct net_device *netdev)
{
	struct nfp_net *nn = netdev_priv(netdev);
	u32 new_ctrl, update;

	if (netdev->flags & IFF_PROMISC &&
	    !(nn->cap & NFP_NET_CFG_CTRL_PROMISC)) {
		nn_warn(nn, "FW does not support promiscuous mode");
		return;
	}

	new_ctrl = nn->ctrl;

	if (netdev->flags & IFF_PROMISC) {
		if (!(nn->cap & NFP_NET_CFG_CTRL_PROMISC)) {
			nn_warn(nn, "FW does not support promiscuous mode");
			return;
		}
		new_ctrl |= NFP_NET_CFG_CTRL_PROMISC;
	} else {
		new_ctrl &= ~NFP_NET_CFG_CTRL_PROMISC;
	}

	if (netdev->flags & IFF_ALLMULTI) {
		if (!(nn->cap & NFP_NET_CFG_CTRL_L2MC))
			nn_warn(nn, "FW does not support ALLMULTI");
		else
			new_ctrl |= NFP_NET_CFG_CTRL_L2MC;
	} else {
		new_ctrl &= ~NFP_NET_CFG_CTRL_L2MC;
	}

	if (new_ctrl != nn->ctrl) {
		update = NFP_NET_CFG_UPDATE_GEN;
		nn_writel(nn->ctrl_bar, NFP_NET_CFG_CTRL, new_ctrl);
		nfp_net_reconfig(nn, update);
		nn->ctrl = new_ctrl;
	}
}

static int nfp_net_change_mtu(struct net_device *netdev, int new_mtu)
{
	struct nfp_net *nn = netdev_priv(netdev);
	u32 tmp;

	nn_dbg(nn, "New MTU = %d", new_mtu);

	if (new_mtu < 68 || new_mtu > nn->max_mtu) {
		nn_err(nn, "New MTU (%d) is not valid\n", new_mtu);
		return -EINVAL;
	}

	netdev->mtu = new_mtu;

	/* Freelist buffer size rounded up to the nearest 1K */
	tmp = new_mtu + ETH_HLEN + VLAN_HLEN + NFP_NET_MAX_PREPEND;
	nn->fl_bufsz = tmp & ~(1024 - 1);
	if (tmp & (1024 - 1))
		nn->fl_bufsz += 1024;

	/* restart if running */
	if (netif_running(netdev)) {
		nfp_net_netdev_close(netdev);
		nfp_net_netdev_open(netdev);
	}

	return 0;
}

static struct net_device_stats *nfp_net_stats(struct net_device *netdev)
{
	struct nfp_net *nn = netdev_priv(netdev);

	return &nn->stats;
}

static int nfp_net_set_features(struct net_device *netdev,
				netdev_features_t features)
{
	netdev_features_t changed = netdev->features ^ features;
	struct nfp_net *nn = netdev_priv(netdev);
	u32 new_ctrl, update;
	int err;

	/* Assume this is not called with features we have not advertised */

	new_ctrl = nn->ctrl;

	if (changed & NETIF_F_RXCSUM) {
		if (new_ctrl & NFP_NET_CFG_CTRL_RXCSUM)
			new_ctrl &= ~NFP_NET_CFG_CTRL_RXCSUM;
		else
			new_ctrl |= NFP_NET_CFG_CTRL_RXCSUM;
	}

	if (changed & NETIF_F_IP_CSUM || changed & NETIF_F_IPV6_CSUM) {
		if (new_ctrl & NFP_NET_CFG_CTRL_TXCSUM)
			new_ctrl &= ~NFP_NET_CFG_CTRL_TXCSUM;
		else
			new_ctrl |= NFP_NET_CFG_CTRL_TXCSUM;
	}

	if (changed & NETIF_F_TSO || changed & NETIF_F_TSO6) {
		if (new_ctrl & NFP_NET_CFG_CTRL_LSO)
			new_ctrl &= ~NFP_NET_CFG_CTRL_LSO;
		else
			new_ctrl |= NFP_NET_CFG_CTRL_LSO;
	}

	if (changed & NETIF_F_RXHASH || changed & NETIF_F_NTUPLE) {
		if (new_ctrl & NFP_NET_CFG_CTRL_RSS)
			new_ctrl &= ~NFP_NET_CFG_CTRL_RSS;
		else
			new_ctrl |= NFP_NET_CFG_CTRL_RSS;
	}

	if (changed & NETIF_F_HW_VLAN_CTAG_RX) {
		if (new_ctrl & NFP_NET_CFG_CTRL_RXVLAN)
			new_ctrl &= ~NFP_NET_CFG_CTRL_RXVLAN;
		else
			new_ctrl |= NFP_NET_CFG_CTRL_RXVLAN;
	}

	if (changed & NETIF_F_HW_VLAN_CTAG_TX) {
		if (new_ctrl & NFP_NET_CFG_CTRL_TXVLAN)
			new_ctrl &= ~NFP_NET_CFG_CTRL_TXVLAN;
		else
			new_ctrl |= NFP_NET_CFG_CTRL_TXVLAN;
	}

	if (changed & NETIF_F_SG) {
		if (new_ctrl & NFP_NET_CFG_CTRL_GATHER)
			new_ctrl &= ~NFP_NET_CFG_CTRL_GATHER;
		else
			new_ctrl |= NFP_NET_CFG_CTRL_GATHER;
	}

	nn_dbg(nn, "Feature change 0x%llx -> 0x%llx (changed=0x%llx)\n",
	       (long long)netdev->features, (long long)features,
	       (long long)changed);

	if (new_ctrl != nn->ctrl) {
		nn_dbg(nn, "NIC ctrl: 0x%x -> 0x%x", nn->ctrl, new_ctrl);
		update = NFP_NET_CFG_UPDATE_GEN;
		nn_writel(nn->ctrl_bar, NFP_NET_CFG_CTRL, new_ctrl);
		err = nfp_net_reconfig(nn, update);
		if (err)
			return err;
		nn->ctrl = new_ctrl;
	}

	netdev->features = features;

	return 0;
}

#ifdef NFP_NET_NDO_SRIOV
/*
 * SR-IOV support (placeholders for now.
 */
#ifdef IFLA_VF_MAX
static int nfp_net_set_vf_mac(struct net_device *netdev, int vf_id, u8 *mac)
{
	struct nfp_net *nn = netdev_priv(netdev);

	nn_warn(nn, "Set MAC %pM on VF %d unimplemented\n",
		mac, vf_id);
	/* Once we have L2 filters, program them here. */
	return -EOPNOTSUPP;
}

static int nfp_net_set_vf_port_vlan(struct net_device *netdev,
				    int vf_id, u16 vlan_id, u8 qos)
{
	struct nfp_net *nn = netdev_priv(netdev);

	nn_warn(nn, "Set port vlan %d/qos %d on VF %d unimplemented\n",
		vlan_id, qos, vf_id);
	return -EOPNOTSUPP;
}

static int nfp_net_get_vf_config(struct net_device *netdev,
				 int vf_id, struct ifla_vf_info *ivi)
{
	struct nfp_net *nn = netdev_priv(netdev);

	nn_warn(nn, "Getting VF config unimplemented\n");
	return -EOPNOTSUPP;
}

#ifdef HAVE_NDO_SET_VF_LINK_STATE
static int nfp_net_set_vf_link_state(struct net_device *netdev,
				     int vf_id, int link)
{
	struct nfp_net *nn = netdev_priv(netdev);

	nn_warn(nn, "Set VF linkstate to %d on VF %d unimplemented\n",
		link, vf_id);
	return -EOPNOTSUPP;
}
#endif

#ifdef HAVE_VF_SPOOFCHK_CONFIGURE
static int nfp_net_set_vf_spoofchk(struct net_device *netdev,
				   int vf_id, bool enable)
{
	struct nfp_net *nn = netdev_priv(netdev);

	nn_warn(nn, "Set VF Spoof config on VF %d unimplemented\n", vf_id);
	return -EOPNOTSUPP;
}
#endif
#endif /* IFLA_VF_MAX */
#endif /* NFP_NET_NDO_SRIOV */

static struct net_device_ops nfp_net_netdev_ops = {
	.ndo_open		= nfp_net_netdev_open,
	.ndo_stop		= nfp_net_netdev_close,
	.ndo_start_xmit		= nfp_net_tx,
	.ndo_get_stats		= nfp_net_stats,
	.ndo_tx_timeout		= nfp_net_tx_timeout,
	.ndo_set_rx_mode	= nfp_net_set_rx_mode,
	.ndo_change_mtu		= nfp_net_change_mtu,
	.ndo_set_mac_address	= eth_mac_addr,
	.ndo_set_features	= nfp_net_set_features,

#ifdef NFP_NET_NDO_SRIOV
#ifdef IFLA_VF_MAX
	.ndo_set_vf_mac         = nfp_net_set_vf_mac,
	.ndo_set_vf_vlan        = nfp_net_set_vf_port_vlan,
	.ndo_get_vf_config      = nfp_net_get_vf_config,
#ifdef HAVE_NDO_SET_VF_LINK_STATE
	.ndo_set_vf_link_state  = nfp_net_set_vf_link_state,
#endif
#ifdef HAVE_VF_SPOOFCHK_CONFIGURE
	.ndo_set_vf_spoofchk    = nfp_net_set_vf_spoofchk,
#endif
#endif /* IFLA_VF_MAX */
#endif /* NFP_NET_NDO_SRIOV */
};

/**
 * nfp_net_info() - Print general info about the NIC
 * @nn:      NFP Net device to reconfigure
 */
void nfp_net_info(struct nfp_net *nn)
{
	nn_info(nn, "Netronome %s %sNetdev: TxQs=%d/%d RxQs=%d/%d using %s\n",
		nn->is_nfp3200 ? "NFP-32xx" : "NFP-6xxx",
		nn->is_vf ? "VF " : "",
		nn->num_tx_rings, nn->max_tx_rings,
		nn->num_rx_rings, nn->max_rx_rings,
		nn->hrtimer ? "HRTIMER" :
		(nn->pdev->msix_enabled ? "MSI-X" : "hrtimer"));
	nn_info(nn, "VER: %#x, Maximum supported MTU: %d\n",
		nn->ver, nn->max_mtu);
	nn_info(nn, "CAP: %#x %s%s%s%s%s%s%s%s%s%s%s%s%s\n",
		nn->cap,
		nn->cap & NFP_NET_CFG_CTRL_PROMISC  ? "PROMISC "  : "",
		nn->cap & NFP_NET_CFG_CTRL_L2BC     ? "L2BCFILT " : "",
		nn->cap & NFP_NET_CFG_CTRL_L2MC     ? "L2MCFILT " : "",
		nn->cap & NFP_NET_CFG_CTRL_RXCSUM   ? "RXCSUM "   : "",
		nn->cap & NFP_NET_CFG_CTRL_TXCSUM   ? "TXCSUM "   : "",
		nn->cap & NFP_NET_CFG_CTRL_RXVLAN   ? "RXVLAN "   : "",
		nn->cap & NFP_NET_CFG_CTRL_TXVLAN   ? "TXVLAN "   : "",
		nn->cap & NFP_NET_CFG_CTRL_SCATTER  ? "SCATTER "  : "",
		nn->cap & NFP_NET_CFG_CTRL_GATHER   ? "GATHER "   : "",
		nn->cap & NFP_NET_CFG_CTRL_LSO      ? "TSO "      : "",
		nn->cap & NFP_NET_CFG_CTRL_RSS      ? "RSS "      : "",
		nn->cap & NFP_NET_CFG_CTRL_L2SWITCH ? "L2SWITCH " : "",
		nn->cap & NFP_NET_CFG_CTRL_MSIXAUTO ? "AUTOMASK"  : "");
}

/**
 * nfp_net_netdev_alloc() - Allocate netdev and related structure
 * @pdev:         PCI device
 * @max_tx_rings: Maximum number of TX rings supported by device
 * @max_rx_rings: Maximum number of RX rings supported by device
 *
 * This function allocates a netdev device and fills in the initial
 * part of the @struct nfp_net structure.
 *
 * Return: NFP Net device structure, or ERR_PTR on error.
 */
struct nfp_net *nfp_net_netdev_alloc(struct pci_dev *pdev,
				     int max_tx_rings, int max_rx_rings)
{
	struct net_device *netdev;
	struct nfp_net *nn;
	int nqs;

	netdev = alloc_etherdev_mqs(sizeof(struct nfp_net),
				    max_tx_rings, max_rx_rings);
	if (!netdev)
		return ERR_PTR(-ENOMEM);

	SET_NETDEV_DEV(netdev, &pdev->dev);
	nn = netdev_priv(netdev);
	memset(nn, 0, sizeof(*nn));

	nn->netdev = netdev;
	nn->pdev = pdev;

	nn->max_tx_rings = max_tx_rings;
	nn->max_rx_rings = max_rx_rings;

	nqs = netif_get_num_default_rss_queues();
	nn->num_tx_rings = num_rings ? min_t(int, num_rings, max_tx_rings)
		: min_t(int, nqs, max_tx_rings);
	nn->num_rx_rings = num_rings ? min_t(int, num_rings, max_rx_rings)
		: min_t(int, nqs, max_rx_rings);

	nn->txd_cnt = NFP_NET_TX_DESCS_DEFAULT;
	nn->rxd_cnt = NFP_NET_RX_DESCS_DEFAULT;

	return nn;
}

/**
 * nfp_net_netdev_free() - Undo what @nfp_net_netdev_alloc() did
 * @nn:      NFP Net device to reconfigure
 */
void nfp_net_netdev_free(struct nfp_net *nn)
{
	free_netdev(nn->netdev);
}

/**
 * nfp_net_netdev_init() - Initialise/finalise the netdev structure
 * @netdev:      netdev structure
 *
 * Return: 0 on success or negative errno on error.
 */
int nfp_net_netdev_init(struct net_device *netdev)
{
	struct nfp_net *nn = netdev_priv(netdev);
	int i, err;

	/* Get some of the read-only fields from the BAR */
	nn->ver = nn_readl(nn->ctrl_bar, NFP_NET_CFG_VERSION);
	nn->cap = nn_readl(nn->ctrl_bar, NFP_NET_CFG_CAP);
	nn->max_mtu = nn_readl(nn->ctrl_bar, NFP_NET_CFG_MAX_MTU);

	/* Write the MAC address */
	nn_writel(nn->ctrl_bar, NFP_NET_CFG_MACADDR,
		  cpu_to_be32(*(u32 *)nn->netdev->dev_addr));
	nn_writel(nn->ctrl_bar, NFP_NET_CFG_MACADDR + 4,
		  cpu_to_be32(*(u32 *)(nn->netdev->dev_addr + 4)));

	/* Set default MTU and Freelist buffer size */
	if (nn->max_mtu < NFP_NET_DEFAULT_MTU)
		netdev->mtu = nn->max_mtu;
	else
		netdev->mtu = NFP_NET_DEFAULT_MTU;
	nn->fl_bufsz = NFP_NET_DEFAULT_RX_BUFSZ;

	/* Advertise/enable offloads based on capabilities
	 *
	 * Note: netdev->features show the currently enabled features
	 * and netdev->hw_features advertises which features are
	 * supported.  By default we enable most features.
	 */
	netdev->hw_features = NETIF_F_HIGHDMA;
	if (nn->cap & NFP_NET_CFG_CTRL_RXCSUM) {
		netdev->hw_features |= NETIF_F_RXCSUM;
		nn->ctrl |= NFP_NET_CFG_CTRL_RXCSUM;
	}
	if (nn->cap & NFP_NET_CFG_CTRL_TXCSUM) {
		netdev->hw_features |=
			NETIF_F_IP_CSUM | NETIF_F_IPV6_CSUM;
		nn->ctrl |= NFP_NET_CFG_CTRL_TXCSUM;
	}
	if (nn->cap & NFP_NET_CFG_CTRL_SCATTER &&
	    nn->cap & NFP_NET_CFG_CTRL_GATHER) {
		netdev->hw_features |= NETIF_F_SG;
		nn->ctrl |= NFP_NET_CFG_CTRL_SCATTER | NFP_NET_CFG_CTRL_GATHER;
	}
	if (nn->cap & NFP_NET_CFG_CTRL_LSO) {
		netdev->hw_features |= NETIF_F_TSO | NETIF_F_TSO6;
		nn->ctrl |= NFP_NET_CFG_CTRL_LSO;
	}
	if (nn->cap & NFP_NET_CFG_CTRL_RSS) {
		netdev->hw_features |= NETIF_F_RXHASH | NETIF_F_NTUPLE;
		nn->ctrl |= NFP_NET_CFG_CTRL_RSS;
	}
	if (nn->cap & NFP_NET_CFG_CTRL_GATHER) {
		netdev->hw_features |= NETIF_F_SG;
		nn->ctrl |= NFP_NET_CFG_CTRL_GATHER;
	}

	netdev->vlan_features = netdev->hw_features;

	if (nn->cap & NFP_NET_CFG_CTRL_RXVLAN) {
		netdev->hw_features |= NETIF_F_HW_VLAN_CTAG_RX;
		nn->ctrl |= NFP_NET_CFG_CTRL_RXVLAN;
	}
	if (nn->cap & NFP_NET_CFG_CTRL_TXVLAN) {
		netdev->hw_features |= NETIF_F_HW_VLAN_CTAG_TX;
		nn->ctrl |= NFP_NET_CFG_CTRL_TXVLAN;
	}
	netdev->features = netdev->hw_features;

	/* Allow L2 Broadcast through by default, if supported */
	if (nn->cap & NFP_NET_CFG_CTRL_L2BC)
		nn->ctrl |= NFP_NET_CFG_CTRL_L2BC;

	/* On NFP-3200 enable MSI-X auto-masking, if supported and the
	 * interrupts are not shared.
	 */
	if (nn->is_nfp3200 && nn->cap & NFP_NET_CFG_CTRL_MSIXAUTO &&
	    nn->num_vecs > 1 && nn->per_vector_masking)
		nn->ctrl |= NFP_NET_CFG_CTRL_MSIXAUTO;

	/* Generate some random bits for RSS and write to device */
	if (nn->cap & NFP_NET_CFG_CTRL_RSS) {
		get_random_bytes(nn->rss_key, NFP_NET_CFG_RSS_KEY_SZ);
		for (i = 0; i < NFP_NET_CFG_RSS_KEY_SZ; i += 4)
			nn_writel(nn->ctrl_bar, NFP_NET_CFG_RSS_KEY + i,
				  nn->rss_key[i / sizeof(u32)]);
	}

	/* Stash the re-configuration queue away.  First odd queue in TX Bar */
	nn->qcp_cfg = nn->tx_bar + NFP_QCP_QUEUE_ADDR_SZ;

	/* Make sure the FW knows the netdev is supposed to be disabled here */
	nn_writel(nn->ctrl_bar, NFP_NET_CFG_CTRL, 0);
	nn_writeq(nn->ctrl_bar, NFP_NET_CFG_TXRS_ENABLE, 0);
	nn_writeq(nn->ctrl_bar, NFP_NET_CFG_RXRS_ENABLE, 0);
	err = nfp_net_reconfig(
		nn, NFP_NET_CFG_UPDATE_RING | NFP_NET_CFG_UPDATE_GEN);
	if (err)
		goto err_reconfig;

	/* Finalise the netdev setup */
	ether_setup(netdev);
	netdev->netdev_ops = &nfp_net_netdev_ops;
	netdev->watchdog_timeo = msecs_to_jiffies(5 * 1000);

	nfp_net_set_ethtool_ops(netdev);

	err = register_netdev(netdev);
	if (err)
		return err;

	nfp_net_irqs_assign(netdev);

	if (nn->is_nfp3200) {
		/* YDS-155 workaround. */
		nn->spare_va = dma_zalloc_coherent(&nn->pdev->dev, 4096,
						   &nn->spare_dma, GFP_KERNEL);
		if (!nn->spare_va)
			return -ENOMEM;
		nn_writel(nn->ctrl_bar, NFP_NET_CFG_SPARE_ADDR, nn->spare_dma);
		nn_info(nn, "Enabled NFP-3200 workaround.");
	}
	return 0;

err_reconfig:
	return err;
}

/**
 * nfp_net_netdev_clean() - Undo what nfp_net_netdev_init() did.
 * @netdev:      netdev structure
 */
void nfp_net_netdev_clean(struct net_device *netdev)
{
	struct nfp_net *nn = netdev_priv(netdev);

	if (nn->is_nfp3200)
		dma_free_coherent(&nn->pdev->dev, 4096,
				  nn->spare_va, nn->spare_dma);

	unregister_netdev(netdev);
}

/*
 * Local variables:
 * c-file-style: "Linux"
 * indent-tabs-mode: t
 * End:
 */
