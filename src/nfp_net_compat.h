/*
 * Copyright (C) 2015 Netronome Systems, Inc.
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
 * nfp_net_compat.h
 * Common declarations for kernel backwards-compatibility
 * Authors: Jakub Kicinski <jakub.kicinski@netronome.com>
 *          Jason McMullan <jason.mcmullan@netronome.com>
 *          Rolf Neugebauer <rolf.neugebauer@netronome.com>
 */

#ifndef _NFP_NET_COMPAT_H_
#define _NFP_NET_COMPAT_H_

#ifndef LINUX_VERSION_CODE
#include <linux/version.h>
#else
#define KERNEL_VERSION(a, b, c) (((a) << 16) + ((b) << 8) + (c))
#endif

#ifndef KBUILD_MODNAME
#define KBUILD_MODNAME "nfp_net_compat"
#endif

#include <linux/if_vlan.h>
#include <linux/interrupt.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/msi.h>
#include <linux/pci.h>
#include <linux/skbuff.h>
#include <linux/udp.h>

#include "nfp_net.h"

#define COMPAT__HAVE_VXLAN_OFFLOAD \
	(LINUX_VERSION_CODE >= KERNEL_VERSION(3, 12, 0))
#define COMPAT__HAVE_NDO_FEATURES_CHECK \
	(LINUX_VERSION_CODE >= KERNEL_VERSION(3, 19, 0))

#ifndef GENMASK
#define GENMASK(h, l) \
	((~0UL << (l)) & (~0UL >> (BITS_PER_LONG - (h) - 1)))
#endif

#ifndef dma_rmb
#define dma_rmb() rmb()
#endif

#ifndef PCI_MSIX_TABLE_BIR
#define  PCI_MSIX_TABLE_BIR     0x00000007 /* BAR index */
#endif
#ifndef PCI_MSIX_TABLE_OFFSET
#define  PCI_MSIX_TABLE_OFFSET  0xfffffff8 /* Offset into specified BAR */
#endif

#ifndef PCI_VENDOR_ID_NETRONOME
#define PCI_VENDOR_ID_NETRONOME		0x19ee
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
#ifndef ETH_RSS_HASH_NO_CHANGE
#define ETH_RSS_HASH_NO_CHANGE	0
#endif
#ifndef ETH_RSS_HASH_TOP
#define ETH_RSS_HASH_TOP	0
#endif

#ifndef READ_ONCE
#define READ_ONCE(x)	(x)
#endif

#ifndef NETIF_F_CSUM_MASK
#define NETIF_F_CSUM_MASK NETIF_F_ALL_CSUM
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

static inline int skb_xmit_more(struct sk_buff *skb)
{
#if LINUX_VERSION_CODE < KERNEL_VERSION(3, 18, 0)
	return false;
#else
	return skb->xmit_more;
#endif
}

#if LINUX_VERSION_CODE < KERNEL_VERSION(3, 19, 0)
static inline int skb_put_padto(struct sk_buff *skb, unsigned int len)
{
	unsigned int size = skb->len;

	if (unlikely(size < len)) {
		len -= size;
		if (skb_pad(skb, len))
			return -ENOMEM;
		__skb_put(skb, len);
	}
	return 0;
}
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(3, 4, 0)
static inline void eth_hw_addr_random(struct net_device *dev)
{
	dev->addr_assign_type |= NET_ADDR_RANDOM;
	random_ether_addr(dev->dev_addr);
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

static inline
void compat_incr_checksum_unnecessary(struct sk_buff *skb, bool encap)
{
#if LINUX_VERSION_CODE < KERNEL_VERSION(3, 18, 0)
	skb->ip_summed = CHECKSUM_UNNECESSARY;
	skb->encapsulation = encap;
#else
	__skb_incr_checksum_unnecessary(skb);
#endif
}

static inline int
compat_ndo_features_check(struct nfp_net *nn, struct sk_buff *skb)
{
#if !COMPAT__HAVE_NDO_FEATURES_CHECK
	u8 l4_hdr;

	if (!skb->encapsulation)
		return 0;

	/* TSO limitation checks */
	if (skb_is_gso(skb)) {
		u32 hdrlen;

		hdrlen = skb_inner_transport_header(skb) - skb->data +
			inner_tcp_hdrlen(skb);

		if (unlikely(hdrlen > NFP_NET_LSO_MAX_HDR_SZ)) {
			nn_warn_ratelimit(nn, "L4 offset too large for TSO!\n");
			return 1;
		}
	}

	/* Checksum encap validation */
	if (!(nn->ctrl & NFP_NET_CFG_CTRL_TXCSUM) ||
	    skb->ip_summed != CHECKSUM_PARTIAL)
		return 0;

	switch (vlan_get_protocol(skb)) {
	case htons(ETH_P_IP):
		l4_hdr = ip_hdr(skb)->protocol;
		break;
	case htons(ETH_P_IPV6):
		l4_hdr = ipv6_hdr(skb)->nexthdr;
		break;
	default:
		nn_warn_ratelimit(nn, "non-IP packet for checksumming!\n");
		return 1;
	}

	if (
#if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 11, 0)
	    skb->inner_protocol != htons(ETH_P_TEB) ||
#endif
#if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 18, 0)
	    skb->inner_protocol_type != ENCAP_TYPE_ETHER ||
#endif
	    (l4_hdr != IPPROTO_UDP && l4_hdr != IPPROTO_GRE) ||
	    (l4_hdr == IPPROTO_UDP &&
	     (skb_inner_mac_header(skb) - skb_transport_header(skb) !=
	      sizeof(struct udphdr) + 8))) {
		nn_warn_ratelimit(nn, "checksum on unsupported tunnel type!\n");
		return 1;
	}

#endif /* !COMPAT__HAVE_NDO_FEATURES_CHECK */
	return 0;
}

#if LINUX_VERSION_CODE < KERNEL_VERSION(3, 19, 0)
static inline void netdev_rss_key_fill(void *buffer, size_t len)
{
	get_random_bytes(buffer, len);
}

static inline void napi_schedule_irqoff(struct napi_struct *n)
{
	napi_schedule(n);
}

static inline void napi_complete_done(struct napi_struct *n, int work_done)
{
	napi_complete(n);
}
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 1, 0)
static inline netdev_features_t vlan_features_check(const struct sk_buff *skb,
						    netdev_features_t features)
{
	return features;
}
#endif

static inline struct list_head *
compat_get_msi_list_head(struct pci_dev *pdev)
{
#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 3, 0)
	return &pdev->msi_list;
#else
	return &pdev->dev.msi_list;
#endif
}

#endif /* _NFP_NET_COMPAT_H_ */
