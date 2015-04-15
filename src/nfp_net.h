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
 * Netronome network device driver
 */

#ifndef _NFP_NET_H_
#define _NFP_NET_H_

#define NFP_NET_DEBUG
#define nn_err(nn, fmt, args...)  netdev_err((nn)->netdev, fmt, ## args)
#define nn_warn(nn, fmt, args...) netdev_warn((nn)->netdev, fmt, ## args)
#define nn_info(nn, fmt, args...) netdev_info((nn)->netdev, fmt, ## args)
#ifdef NFP_NET_DEBUG
#define nn_dbg(nn, fmt, args...)  netdev_info((nn)->netdev, fmt, ## args)
#define nn_assert(cond, fmt, args...) {					\
		if (!(cond)) {						\
			pr_err("assertion %s failed: %s:%d\n",		\
			       #cond, __func__, __LINE__);		\
			pr_err(fmt, ## args);				\
			BUG();						\
		}							\
	}
#else
#define nn_dbg(nn, fmt, args...)
#define nn_assert(cond, fmt, args...)
#endif

/* On the 6k we offer using hrtimers for RX/TX polling instead of
 * MSI-X. By setting CONFIG _NFP_NET_HRTIMER_6000 this gets activated.
 */
#ifdef CONFIG_NFP_NET_HRTIMER_6000
#define NFP_NET_HRTIMER_6000
#else
#undef NFP_NET_HRTIMER_6000
#endif

/* Define to enable the SR-IOV related netdev operations */
#undef NFP_NET_NDO_SRIOV

/* Forward declaration */
struct nfp_net;

/* NAPI weight */
#define NFP_NET_NAPI_WEIGHT    64

/* Max time to wait for NFP to respond on updates (in ms) */
#define NFP_NET_POLL_TIMEOUT	5000

/* Bar allocation */
#define NFP_NET_CRTL_BAR	0
#define NFP_NET_TX_BAR		2
#define NFP_NET_RX_BAR		4

/* Max bits in DMA address */
#define NFP_NET_MAX_DMA_BITS	40

/* Default size for MTU and freelist buffer sizes */
#define NFP_NET_DEFAULT_MTU		1500
#define NFP_NET_DEFAULT_RX_BUFSZ	2048

/* Maximum number of bytes prepended to a packet */
#define NFP_NET_MAX_PREPEND		64

/* Interrupt definitions */
#define NFP_NET_NON_Q_VECTORS		2
#define NFP_NET_IRQ_LSC_IDX		0
#define NFP_NET_IRQ_EXN_IDX		1

/*
 * Queue definitions
 */
#define NFP_NET_MAX_TX_RINGS	64	/* Max. # of Tx rings per device */
#define NFP_NET_MAX_RX_RINGS	64	/* Max. # of Rx rings per device */

#define NFP_NET_MIN_TX_DESCS	256	/* Min. # of Tx descs per ring */
#define NFP_NET_MIN_RX_DESCS	256   /* Min. # of Rx descs per ring */
#define NFP_NET_MAX_TX_DESCS	(256 * 1024) /* Max. # of Tx descs per ring */
#define NFP_NET_MAX_RX_DESCS	(256 * 1024) /* Max. # of Rx descs per ring */

#define NFP_NET_TX_DESCS_DEFAULT 4096	/* Default # of Tx descs per ring */
#define NFP_NET_RX_DESCS_DEFAULT 4096	/* Default # of Rx descs per ring */

#define NFP_NET_FL_BATCH	16	/* Add freelist in this Batch size */

/*
 * Debug support
 */
#define NFP_NET_DUMP_TX_MIN	1000
#define NFP_NET_DUMP_TX_MAX	(NFP_NET_DUMP_TX_MIN + NFP_NET_MAX_TX_RINGS - 1)
#define NFP_NET_DUMP_RX_MIN	2000
#define NFP_NET_DUMP_RX_MAX	(NFP_NET_DUMP_RX_MIN + NFP_NET_MAX_RX_RINGS - 1)

/* Forward declaration */
struct nfp_net_r_vector;

/*
 * TX descriptor format
 */

/* Flags in the host TX descriptor */
#define PCIE_DESC_TX_CSUM		(1 << 7)
#define PCIE_DESC_TX_IP4_CSUM		(1 << 6)
#define PCIE_DESC_TX_TCP_CSUM		(1 << 5)
#define PCIE_DESC_TX_UDP_CSUM		(1 << 4)
#define PCIE_DESC_TX_VLAN		(1 << 3)
#define PCIE_DESC_TX_LSO		(1 << 2)
#define PCIE_DESC_TX_ENCAP_NONE		(0)
#define PCIE_DESC_TX_ENCAP_VXLAN	(1 << 1)
#define PCIE_DESC_TX_ENCAP_GRE		(1 << 0)

struct nfp_net_tx_desc {
	union {
		struct {
#if defined(__LITTLE_ENDIAN)
			u32 dma_addr_hi:8; /* High bits of host buf address */
			u32 dma_len:16;    /* Length to DMA for this desc */
			u32 offset:7;      /* Offset in buf where pkt starts */
			u32 eop:1;

			u32 dma_addr_lo;   /* Low 32bit of host buf addr */

			u32 lso:16;        /* MSS to be used for LSO */
			u32 l4_offset:8;   /* LSO, where the L4 data starts */
			u32 flags:8;       /* TX Flags, see @PCIE_DESC_TX_* */

			u32 vlan:16;       /* VLAN tag to add if indicated */
			u32 data_len:16;   /* Length of frame + meta data */
#else /* Endian */
			u32 eop:1;
			u32 offset:7;
			u32 dma_len:16;
			u32 dma_addr_hi:8;

			u32 dma_addr_lo;

			u32 flags:8;
			u32 l4_offset:8;
			u32 lso:16;

			u32 data_len:16;
			u32 vlan:16;
#endif
		};
		__le32 vals[4];
	};
};

struct nfp_net_tx_ring {
	struct nfp_net_r_vector *r_vec;	/* Backpointer to ring vector */

	/* Ring/Queue information: @idx is the ring index from Linux's
	 * perspective.  @qcidx is the index of the Queue Controller
	 * Peripheral queue relative to the TX queue BAR.  @qcp_q is a
	 * pointer to the base of the queue structure on the NFP */
	int idx;
	int qcidx;
	u8 __iomem *qcp_q;

	/* Read and Write pointers.  @wr_p and @rd_p are host side
	 * pointer, they are free running and have little relation to
	 * the QCP pointers. @qcp_rd_p is a local copy queue
	 * controller peripheral read pointer. @cnt is the
	 * size of the queue in number of descriptors. */
	int cnt;
	u32 wr_p;
	u32 rd_p;
	u32 qcp_rd_p;

	/* For each transmitted SKB keep a reference to the SKB and
	 * DMA address used until completion is signaled. */
	struct {
		struct sk_buff *skb;
		dma_addr_t dma_addr;
		int fidx;
	} *txbufs;

	/* Information about the host side ring location. @txds is
	 * the virtual address for the queue, @dma is the DMA address
	 * of the queue and @size is the size in bytes for the queue
	 * (needed for free) */
	struct nfp_net_tx_desc *txds;
	dma_addr_t dma;
	unsigned int size;
} ____cacheline_aligned;

/*
 * RX and freelist descriptor format
 */
/* Flags in the RX descriptor */
#define PCIE_DESC_RX_RSS		(1 << 15)
#define PCIE_DESC_RX_I_IP4_CSUM		(1 << 14)
#define PCIE_DESC_RX_I_IP4_CSUM_OK	(1 << 13)
#define PCIE_DESC_RX_I_TCP_CSUM		(1 << 12)
#define PCIE_DESC_RX_I_TCP_CSUM_OK	(1 << 11)
#define PCIE_DESC_RX_I_UDP_CSUM		(1 << 10)
#define PCIE_DESC_RX_I_UDP_CSUM_OK	(1 <<  9)
#define PCIE_DESC_RX_SPARE		(1 <<  8)
#define PCIE_DESC_RX_EOP		(1 <<  7)
#define PCIE_DESC_RX_IP4_CSUM		(1 <<  6)
#define PCIE_DESC_RX_IP4_CSUM_OK	(1 <<  5)
#define PCIE_DESC_RX_TCP_CSUM		(1 <<  4)
#define PCIE_DESC_RX_TCP_CSUM_OK	(1 <<  3)
#define PCIE_DESC_RX_UDP_CSUM		(1 <<  2)
#define PCIE_DESC_RX_UDP_CSUM_OK	(1 <<  1)
#define PCIE_DESC_RX_VLAN		(1 <<  0)

struct nfp_net_rx_desc {
	union {
		struct {
#if defined(__LITTLE_ENDIAN)
			u32 dma_addr_hi:8;  /* High bits of the buf address */
			u32 spare:23;
			u32 dd:1;	    /* Must be zero */

			u32 dma_addr_lo;    /* Low bits of the buffer address */
#else
			u32 dd:1;
			u32 spare:23;
			u32 dma_addr_hi:8;

			u32 dma_addr_lo;
#endif /* Endian */
		} fld;

		struct {
#if defined(__LITTLE_ENDIAN)
			u32 data_len:16; /* Length of the frame + meta data */
			u32 reserved:8;
			u32 meta_len:7;  /* Length of meta data prepended */
			u32 dd:1;	 /* Must be set to 1 */

			u32 flags:16;	 /* RX flags. See @PCIE_DESC_RX_* */
			u32 vlan:16;	 /* VLAN if stripped */
#else
			u32 dd:1;
			u32 meta_len:7;
			u32 reserved:8;
			u32 data_len:16;

			u32 vlan:16;
			u32 flags:16;
#endif /* Endian */
		} rxd;

		__le32 vals[2];
	};
};

struct nfp_net_rx_ring {
	struct nfp_net_r_vector *r_vec;	/* Backpointer to ring vector */

	/* Ring/Queue information: @idx is the ring index from Linux's
	 * perspective.  @fl_qcidx is the index of the Queue
	 * Controller peripheral queue relative to the RX queue BAR
	 * used for the freelist and @rx_qcidx is the Queue Controller
	 * Peripheral index for the RX queue.  @qcp_fl and @qcp_rx are
	 * pointers to the base addresses of the freelist and RX queue
	 * controller peripheral queue structures on the NFP.
	 */
	int idx;
	int fl_qcidx;
	int rx_qcidx;
	u8 __iomem *qcp_fl;
	u8 __iomem *qcp_rx;

	/* Read and Write pointers.  @wr_p and @rd_p are host side
	 * pointer, they are free running and have little relation to
	 * the QCP pointers. @wr_p is where the driver adds new
	 * freelist descriptors and @rd_p is where the driver starts
	 * reading descriptors for newly arrive packets from. @cnt is
	 * the size of the queue in number of descriptors. */
	int cnt;
	u32 wr_p;
	u32 rd_p;

	/* For each buffer placed on the freelist, record the
	 * associated SKB and the DMA address it is mapped to. */
	struct {
		struct sk_buff *skb;
		dma_addr_t dma_addr;
	} *rxbufs;

	/* Information about the host side ring location.  @rxds is
	 * the virtual address for the queue, @dma is the DMA address
	 * of the queue and @size is the size in bytes for the queue
	 * (needed for free) */
	struct nfp_net_rx_desc *rxds;
	dma_addr_t dma;
	unsigned int size;
} ____cacheline_aligned;

/*
 * Interrupt vector info
 */

/*
 * Per ring interrupt vector configuration
 *
 * This structure ties RX and TX rings to interrupt vectors and a NAPI
 * context. This currently only supports one RX and TX ring per
 * interrupt vector but might be extended in the future to allow
 * association of multiple rings per vector.
 */
struct nfp_net_r_vector {
	struct nfp_net *nfp_net;	/* Backpointer to nfp_net structure */
	struct napi_struct napi;	/* NAPI structure for this ring vec */

	unsigned long flags;
#define NFP_NET_RVEC_NAPI_STARTED	BIT(0)

#ifdef NFP_NET_HRTIMER_6000
	unsigned napi_polling:1;
	struct hrtimer timer;
	ktime_t timer_interval;
	spinlock_t txlock;		/* Lock to avoid timer race */
#endif

	int idx;

	/* Pointer to associated rings */
	struct nfp_net_tx_ring *tx_ring;
	struct nfp_net_rx_ring *rx_ring;

	irq_handler_t handler;		/* Interrupt handler */
	int irq_idx;			/* Index to MSI-X entries */
	int requested;			/* Has this vector been requested */
	char name[IFNAMSIZ + 8];	/* Name */

	cpumask_t affinity_mask;

	/* Packets handled by the ring vector */
	u64 tx_pkts;
	u64 rx_pkts;
	/* How often was the TX ring associated with this r vector full */
	u64 tx_busy;
};

/*
 * Device structure
 */
struct nfp_net {
	struct pci_dev *pdev;
	struct net_device *netdev;

	unsigned nfp_fallback:1;
	unsigned is_vf:1;
	unsigned is_nfp3200:1;
	unsigned removing_pdev:1;
	unsigned link_up:1;
	unsigned hrtimer:1;
	unsigned fw_loaded:1;

#ifdef CONFIG_PCI_IOV
	unsigned int num_vfs;
	struct vf_data_storage *vfinfo;
	int vf_rate_link_speed;
#endif

	struct nfp_cpp *cpp;
	struct platform_device *nfp_dev_cpp;
	struct nfp_cpp_area *ctrl_area;
	struct nfp_cpp_area *tx_area;
	struct nfp_cpp_area *rx_area;

	struct net_device_stats stats;
	u64 hw_csum_rx_ok;
	u64 hw_csum_rx_error;
	u64 hw_csum_tx;
	u64 tx_gather;

	u32 et_dump_flag;

	/* Info from the firmware */
	u32 ver;
	u32 cap;
	u32 max_mtu;

	/* RSS config */
	u32 rss_cfg;
	u32 rss_key[NFP_NET_CFG_RSS_KEY_SZ / sizeof(u32)];
	u8 rss_itbl[NFP_NET_CFG_RSS_ITBL_SZ];

	/* Current values for control and freelist buffer size */
	u32 ctrl;
	u32 fl_bufsz;

	/* Max number of RX/TX Qs support by the device.  The number
	 * is determined based on the BAR sizes */
	int max_tx_rings;
	int max_rx_rings;

	/* Configured number of RX/TX Qs.  By default this is set to
	 * the minimum of max_txqs|max_rxqs and the number of CPUs. */
	int num_tx_rings;
	int num_rx_rings;

	/* Size of the RX/TX queues in number of descriptors they can hold */
	int txd_cnt;
	int rxd_cnt;

	/* Array of queues */
	struct nfp_net_tx_ring tx_rings[NFP_NET_MAX_TX_RINGS];
	struct nfp_net_rx_ring rx_rings[NFP_NET_MAX_RX_RINGS];

	/* Interrupt configuration */
	unsigned per_vector_masking:1;
	u8 __iomem *msix_table;
	u8 num_vecs;
	u8 num_r_vecs;
	struct nfp_net_r_vector r_vecs[NFP_NET_MAX_TX_RINGS];
	struct msix_entry irq_entries[NFP_NET_NON_Q_VECTORS +
				      NFP_NET_MAX_TX_RINGS];

	irq_handler_t lsc_handler;	/* Interrupt handler */
	char lsc_name[IFNAMSIZ + 8];	/* Name */

	irq_handler_t exn_handler;	/* Interrupt handler */
	char exn_name[IFNAMSIZ + 8];	/* Name */

	irq_handler_t shared_handler;	/* Shared interrupt handler */
	char shared_name[IFNAMSIZ + 8];	/* Shared interrupt Name */

	/* Re Configuration queue */
	u8 __iomem *qcp_cfg;

	/* 3 BARs: Control, TX queues, and RX queues */
	u8 __iomem *ctrl_bar;
	u8 __iomem *tx_bar;
	u8 __iomem *rx_bar;

	/* DMA address for spare area to be sued by the NFP */
	void *spare_va;
	dma_addr_t spare_dma;
};

/* Functions to read/write from/to a BAR
 * Performs any endian conversion necessary.
 */
static inline void nn_writeb(u8 __iomem *base, int off, u8 val)
{
	writeb(val, base + off);
}

static inline u32 nn_readl(u8 __iomem *base, int off)
{
	return le32_to_cpu(readl(base + off));
}

static inline void nn_writel(u8 __iomem *base, int off, u32 val)
{
	writel(cpu_to_le32(val), base + off);
}

static inline u64 nn_readq(u8 __iomem *base, int off)
{
	return le64_to_cpu(readq(base + off));
}

static inline void nn_writeq(u8 __iomem *base, int off, u64 val)
{
	writeq(cpu_to_le64(val), base + off);
}

/* Queue Controller Peripheral access functions and definitions.
 *
 * Some of the BARs of the NFP are mapped to portions of the Queue
 * Controller Peripheral (QCP) address space on the NFP.  A QCP queue
 * has a read and a write pointer (as well as a size and flags,
 * indicating overflow etc).  The QCP offers a number of different
 * operation on queue pointers, but here we only offer function to
 * either add to a pointer or to read the pointer value.
 */
#define NFP_QCP_QUEUE_ADDR_SZ			0x800
#define NFP_QCP_QUEUE_OFF(_x)			((_x) * NFP_QCP_QUEUE_ADDR_SZ)
#define NFP_QCP_QUEUE_ADD_RPTR			0x0000
#define NFP_QCP_QUEUE_ADD_WPTR			0x0004
#define NFP_QCP_QUEUE_STS_LO			0x0008
#define NFP_QCP_QUEUE_STS_LO_READPTR_mask	0x3ffff
#define NFP_QCP_QUEUE_STS_HI			0x000c
#define NFP_QCP_QUEUE_STS_HI_WRITEPTR_mask	0x3ffff

/* The offset of a QCP queues in the PCIe Target (same on NFP3200 and NFP6000 */
#define NFP_PCIE_QUEUE(_q) (0x80000 + (NFP_QCP_QUEUE_ADDR_SZ * ((_q) & 0xff)))

/* nfp_qcp_ptr - Read or Write Pointer of a queue */
enum nfp_qcp_ptr {
	NFP_QCP_READ_PTR = 0,
	NFP_QCP_WRITE_PTR
};

/* There appear to be an *undocumented* upper limit on the value which
 * one can add to a queue and that value is either 0x3f or 0x7f.  We
 * go with 0x3f as a conservative measure.
 */
#define NFP_QCP_MAX_ADD				0x3f

/**
 * nfp_qcp_rd_ptr_add - Add the value to the read pointer of a queue
 * nfp_qcp_wr_ptr_add - Add the value to the write pointer of a queue
 *
 * @q: Base address for queue structure
 * @val: Value to add to the queue pointer
 *
 * If @val is greater than @NFP_QCP_MAX_ADD multiple writes are performed.
 */
static inline void _nfp_qcp_ptr_add(u8 __iomem *q,
				    enum nfp_qcp_ptr ptr, u32 val)
{
	u32 off;

	if (ptr == NFP_QCP_READ_PTR)
		off = NFP_QCP_QUEUE_ADD_RPTR;
	else
		off = NFP_QCP_QUEUE_ADD_WPTR;

	while (val > NFP_QCP_MAX_ADD) {
		writel(cpu_to_le32(NFP_QCP_MAX_ADD), q + off);
		val -= NFP_QCP_MAX_ADD;
	}

	nn_writel(q, off, val);
}

static inline void nfp_qcp_rd_ptr_add(u8 __iomem *q, u32 val)
{
	_nfp_qcp_ptr_add(q, NFP_QCP_READ_PTR, val);
}

static inline void nfp_qcp_wr_ptr_add(u8 __iomem *q, u32 val)
{
	_nfp_qcp_ptr_add(q, NFP_QCP_WRITE_PTR, val);
}

/**
 * nfp_qcp_rd_ptr_read - Read the current read pointer value for a queue
 * nfp_qcp_wr_ptr_read - Read the current read pointer value for a queue
 * @q:  Base address for queue structure
 * @return value read.
 */
static inline u32 _nfp_qcp_read(u8 __iomem *q, enum nfp_qcp_ptr ptr)
{
	u32 off;
	u32 val;

	if (ptr == NFP_QCP_READ_PTR)
		off = NFP_QCP_QUEUE_STS_LO;
	else
		off = NFP_QCP_QUEUE_STS_HI;

	val = nn_readl(q, off);

	if (ptr == NFP_QCP_READ_PTR)
		return val & NFP_QCP_QUEUE_STS_LO_READPTR_mask;
	else
		return val & NFP_QCP_QUEUE_STS_HI_WRITEPTR_mask;
}

static inline u32 nfp_qcp_rd_ptr_read(u8 __iomem *q)
{
	return _nfp_qcp_read(q, NFP_QCP_READ_PTR);
}

static inline u32 nfp_qcp_wr_ptr_read(u8 __iomem *q)
{
	return _nfp_qcp_read(q, NFP_QCP_WRITE_PTR);
}

/* Globals */
extern const char nfp_net_driver_name[];
extern const char nfp_net_driver_version[];

/* Prototypes */
struct nfp_net *nfp_net_netdev_alloc(struct pci_dev *pdev,
				     int max_tx_rings, int max_rx_rings);
void nfp_net_netdev_free(struct nfp_net *nn);
int nfp_net_netdev_init(struct net_device *netdev);
void nfp_net_netdev_clean(struct net_device *netdev);
void nfp_net_set_ethtool_ops(struct net_device *netdev);
void nfp_net_info(struct nfp_net *nn);
int nfp_net_tx_dump(struct nfp_net_tx_ring *tx_ring, char *p);
int nfp_net_rx_dump(struct nfp_net_rx_ring *rx_ring, char *p);
int nfp_net_reconfig(struct nfp_net *nn, u32 update);
void nfp_net_rss_write_itbl(struct nfp_net *nn);
int nfp_net_irqs_alloc(struct nfp_net *nn);
void nfp_net_irqs_disable(struct nfp_net *nn);
void __iomem *nfp_net_msix_map(struct pci_dev *pdev, unsigned nr_entries);
void nfp_net_msix_unmap(void __iomem *addr);
#endif /* _NFP_NET_H_ */

/*
 * Local variables:
 * c-file-style: "Linux"
 * indent-tabs-mode: t
 * End:
 */
