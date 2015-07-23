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
 * Common declarations for kernel backwards compat.
 */

#ifndef _NFP_NET_COMPAT_H_
#define _NFP_NET_COMPAT_H_

#ifndef LINUX_VERSION_CODE
#include <linux/version.h>
#else
#define KERNEL_VERSION(a, b, c) (((a) << 16) + ((b) << 8) + (c))
#endif

#include <linux/if_vlan.h>
#include <linux/interrupt.h>
#include <linux/msi.h>
#include <linux/pci.h>
#include <linux/skbuff.h>

#ifndef PCI_MSIX_TABLE_BIR
#define  PCI_MSIX_TABLE_BIR     0x00000007 /* BAR index */
#endif
#ifndef PCI_MSIX_TABLE_OFFSET
#define  PCI_MSIX_TABLE_OFFSET  0xfffffff8 /* Offset into specified BAR */
#endif

#if (LINUX_VERSION_CODE < KERNEL_VERSION(3, 3, 0))
typedef u32 netdev_features_t;
#endif /* KERNEL_VERSION(3, 3, 0) */

#if LINUX_VERSION_CODE < KERNEL_VERSION(3, 3, 0)
static inline u32 ethtool_rxfh_indir_default(u32 index, u32 n_rx_rings)
{
	return index % n_rx_rings;
}
#endif

#ifndef NETIF_F_HW_VLAN_CTAG_RX
#define NETIF_F_HW_VLAN_CTAG_RX NETIF_F_HW_VLAN_RX
#endif
#ifndef NETIF_F_HW_VLAN_CTAG_TX
#define NETIF_F_HW_VLAN_CTAG_TX NETIF_F_HW_VLAN_TX
#endif

#if (LINUX_VERSION_CODE <= KERNEL_VERSION(3, 6, 0))
static inline int netif_get_num_default_rss_queues(void)
{
	return min_t(int, 8, num_online_cpus());
}
#endif /* KERNEL_VERSION(3, 6, 0) */

#if LINUX_VERSION_CODE < KERNEL_VERSION(3, 10, 0)
static inline struct sk_buff *ns___vlan_hwaccel_put_tag(struct sk_buff *skb,
							__be16 vlan_proto,
							u16 vlan_tci)
{
	return __vlan_hwaccel_put_tag(skb, vlan_tci);
}

#define __vlan_hwaccel_put_tag ns___vlan_hwaccel_put_tag
#endif

#if (LINUX_VERSION_CODE <= KERNEL_VERSION(3, 8, 0))
static inline int netif_set_xps_queue(struct net_device *dev,
				      const struct cpumask *mask,
				      u16 index)
{
	return 0;
}
#endif

/* FIXME: Ubuntu 14.04 has this in some of their 3.13 kernels
 *
 * FIXME: Centos 7 has this in their 3.10 kernel.
 */
#if (LINUX_VERSION_CODE < KERNEL_VERSION(3, 14, 0))
enum compat_pkt_hash_types {
	compat_PKT_HASH_TYPE_NONE,     /* Undefined type */
	compat_PKT_HASH_TYPE_L2,       /* Input: src_MAC, dest_MAC */
	compat_PKT_HASH_TYPE_L3,       /* Input: src_IP, dst_IP */
	compat_PKT_HASH_TYPE_L4,       /* Input: src_IP, dst_IP,
						 src_port, dst_port */
};

#define PKT_HASH_TYPE_NONE	compat_PKT_HASH_TYPE_NONE
#define PKT_HASH_TYPE_L2	compat_PKT_HASH_TYPE_L2
#define PKT_HASH_TYPE_L3	compat_PKT_HASH_TYPE_L3
#define PKT_HASH_TYPE_L4	compat_PKT_HASH_TYPE_L4

static inline void compat_skb_set_hash(struct sk_buff *skb, __u32 hash,
				       enum compat_pkt_hash_types type)
{
/* XXX RN: Not entirely sure if this hasn't changed more before */
#if (LINUX_VERSION_CODE < KERNEL_VERSION(3, 15, 0))
	skb->l4_rxhash = (type == PKT_HASH_TYPE_L4);
	skb->rxhash = hash;
#else
	skb->l4_hash = (type == PKT_HASH_TYPE_L4);
	skb->sw_hash = 0;
	skb->hash = hash;
#endif
}

#define skb_set_hash(s, h, t)	compat_skb_set_hash(s, h, t)
#endif

#if (LINUX_VERSION_CODE < KERNEL_VERSION(3, 14, 0))
static inline int compat_pci_enable_msix_range(struct pci_dev *dev,
					       struct msix_entry *entries,
					       int minvec, int maxvec)
{
	int nvec = maxvec;
	int rc;

	if (maxvec < minvec)
		return -ERANGE;

	do {
		rc = pci_enable_msix(dev, entries, nvec);
		if (rc < 0) {
			return rc;
		} else if (rc > 0) {
			if (rc < minvec)
				return -ENOSPC;
			nvec = rc;
		}
	} while (rc);

	return nvec;
}

#define pci_enable_msix_range(dev, entries, minv, maxv) \
	compat_pci_enable_msix_range(dev, entries, minv, maxv)
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(3, 14, 0)
static inline int compat_pci_enable_msi_range(struct pci_dev *dev,
					      int minvec, int maxvec)
{
	int nvec = maxvec;
	int rc;

	if (maxvec < minvec)
		return -ERANGE;

	do {
		rc = pci_enable_msi_block(dev, nvec);
		if (rc < 0) {
			return rc;
		} else if (rc > 0) {
			if (rc < minvec)
				return -ENOSPC;
			nvec = rc;
		}
	} while (rc);

	return nvec;
}

/* Check in case we also pull in kcompat.h from nfpcore */
#ifndef pci_enable_msi_range
#define pci_enable_msi_range(dev, minv, maxv) \
	compat_pci_enable_msi_range(dev, minv, maxv)
#endif
#endif

#if (LINUX_VERSION_CODE < KERNEL_VERSION(3, 18, 0))
static inline void pci_msi_unmask_irq(struct irq_data *data)
{
	unmask_msi_irq(data);
}
#endif

#if (LINUX_VERSION_CODE < KERNEL_VERSION(3, 13, 0))
static inline
int compat_dma_set_mask_and_coherent(struct device *dev, u64 mask)
{
	int rc = dma_set_mask(dev, mask);
	if (rc == 0)
		dma_set_coherent_mask(dev, mask);
	return rc;
}
#define dma_set_mask_and_coherent(dev, mask) \
	compat_dma_set_mask_and_coherent(dev, mask)
#endif

#if (LINUX_VERSION_CODE < KERNEL_VERSION(4, 0, 0))
#define skb_vlan_tag_present(skb)	vlan_tx_tag_present(skb)
#define skb_vlan_tag_get(skb)		vlan_tx_tag_get(skb)
#endif

#endif /* _NFP_NET_COMPAT_H_ */
