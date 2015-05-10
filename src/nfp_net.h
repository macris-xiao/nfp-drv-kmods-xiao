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

/* Queue/Ring definitions */
#define NFP_NET_MAX_TX_RINGS	64	/* Max. # of Tx rings per device */
#define NFP_NET_MAX_RX_RINGS	64	/* Max. # of Rx rings per device */

#define NFP_NET_MIN_TX_DESCS	256	/* Min. # of Tx descs per ring */
#define NFP_NET_MIN_RX_DESCS	256	/* Min. # of Rx descs per ring */
#define NFP_NET_MAX_TX_DESCS	(256 * 1024) /* Max. # of Tx descs per ring */
#define NFP_NET_MAX_RX_DESCS	(256 * 1024) /* Max. # of Rx descs per ring */

#define NFP_NET_TX_DESCS_DEFAULT 4096	/* Default # of Tx descs per ring */
#define NFP_NET_RX_DESCS_DEFAULT 4096	/* Default # of Rx descs per ring */

#define NFP_NET_FL_BATCH	16	/* Add freelist in this Batch size */

/* Debug support */
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


/**
 * struct nfp_net_tx_ring - TX ring structure
 * @r_vec:      Back pointer to ring vector structure
 * @idx:        Ring index from Linux's perspective
 * @qcidx:      Queue Controller Peripheral (QCP) queue index for the TX queue
 * @qcp_p:      Pointer to base of the QCP TX queue
 * @cnt:        Size of the queue in number of descriptors
 * @wr_p:       TX ring write pointer (free running)
 * @rd_p:       TX ring read pointer (free running)
 * @qcp_rd_p:   Local copy of QCP TX queue read pointer
 * @txbufs:     Array of transmitted TX buffers, to free on transmit
 * @txds:       Virtual address of TX ring in host memory
 * @dma:        DMA address of the TX ring
 * @size:       Size, in bytes, of the TX ring (needed to free)
 */
struct nfp_net_tx_ring {
	struct nfp_net_r_vector *r_vec;

	int idx;
	int qcidx;
	u8 __iomem *qcp_q;

	int cnt;
	u32 wr_p;
	u32 rd_p;
	u32 qcp_rd_p;

	struct {
		struct sk_buff *skb;
		dma_addr_t dma_addr;
		int fidx;
	} *txbufs;

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

/**
 * struct nfp_net_rx_ring - RX ring structure
 * @r_vec:      Back pointer to ring vector structure
 * @idx:        Ring index from Linux's perspective
 * @fl_qcidx:   Queue Controller Peripheral (QCP) queue index for the freelist
 * @rx_qcidx:   Queue Controller Peripheral (QCP) queue index for the RX queue
 * @qcp_fl:     Pointer to base of the QCP freelist queue
 * @qcp_rx:     Pointer to base of the QCP RX queue
 * @cnt:        Size of the queue in number of descriptors
 * @wr_p:       FL/RX ring write pointer (free running)
 * @rd_p:       FL/RX ring read pointer (free running)
 * @rxbufs:     Array of transmitted FL/RX buffers
 * @rxds:       Virtual address of FL/RX ring in host memory
 * @dma:        DMA address of the FL/RX ring
 * @size:       Size, in bytes, of the FL/RX ring (needed to free)
 */
struct nfp_net_rx_ring {
	struct nfp_net_r_vector *r_vec;

	int idx;
	int fl_qcidx;
	int rx_qcidx;
	u8 __iomem *qcp_fl;
	u8 __iomem *qcp_rx;

	int cnt;
	u32 wr_p;
	u32 rd_p;

	struct {
		struct sk_buff *skb;
		dma_addr_t dma_addr;
	} *rxbufs;

	struct nfp_net_rx_desc *rxds;
	dma_addr_t dma;
	unsigned int size;
} ____cacheline_aligned;

/**
 * struct nfp_net_r_vector - Per ring interrupt vector configuration
 * @nfp_net:        Backpointer to nfp_net structure
 * @napi:           NAPI structure for this ring vec
 * @flags:          Flags
 * @idx:            Index of this ring vector
 * @tx_ring:        Pointer to TX ring
 * @rx_ring:        Pointer to RX ring
 * @handler:        Interrupt handler for this ring vector
 * @irq_idx:        Index into MSI-X table
 * @requested:      Has this vector been requested?
 * @name:           Name of the interrupt vector
 * @affinity_mask:  SMP affinity mask for this vector
 * @tx_pkts:        Number of Transmitted packets
 * @rx_pkts:        Number of received packets
 * @tx_busy:        How often was TX busy (no space)?
 *
 * This structure ties RX and TX rings to interrupt vectors and a NAPI
 * context. This currently only supports one RX and TX ring per
 * interrupt vector but might be extended in the future to allow
 * association of multiple rings per vector.
 */
struct nfp_net_r_vector {
	struct nfp_net *nfp_net;
	struct napi_struct napi;
	unsigned long flags;
#define NFP_NET_RVEC_NAPI_STARTED	BIT(0)

#ifdef NFP_NET_HRTIMER_6000
	unsigned napi_polling:1;
	struct hrtimer timer;
	ktime_t timer_interval;
	spinlock_t txlock;		/* Lock to avoid timer race */
#endif

	int idx;
	struct nfp_net_tx_ring *tx_ring;
	struct nfp_net_rx_ring *rx_ring;

	irq_handler_t handler;
	int irq_idx;
	int requested;
	char name[IFNAMSIZ + 8];

	cpumask_t affinity_mask;

	u64 tx_pkts;
	u64 rx_pkts;
	u64 tx_busy;
};

/**
 * struct nfp_net - NFP network device structure
 * @pdev:               Backpointer to PCI device
 * @netdev:             Backpointer to net_device structure
 * @nfp_fallback:       Is the driver used in fallback mode?
 * @is_vf:              Is the driver attached to a VF?
 * @is_nfp3200:         Is the driver for a NFP-3200 card?
 * @removing_pdev:      Are we in the process of removing the device driver
 * @link_up:            Is the link up?
 * @hrtimer:            Are we using HRTIMER (instead of interrupts)?
 * @fw_loaded:          Is the firmware loaded?
 * @cpp:                Pointer to the CPP handle
 * @nfp_dev_cpp:        Pointer to the NFP Device handle
 * @ctrl_area:          Pointer to the CPP area for the control BAR
 * @tx_area:            Pointer to the CPP area for the TX queues
 * @rx_area:            Pointer to the CPP area for the FL/RX queues
 * @stats:              Standard netdev statistics
 * @hw_csum_rx_ok:      Counter of packets where the HW checksum was OK
 * @hw_csum_rx_error:   Counter of packets with bad checksums
 * @hw_csum_tx:         Counter of packets with TX checksum offload requested
 * @tx_gather:          Counter of packets with Gather DMA
 * @et_dump_flag:       Flag used to dump RX/TX ring information (via ethtool)
 * @ver:                Firmware version
 * @cap:                Capabilities advertised by the Firmware
 * @max_mtu:            Maximum support MTU advertised by the Firmware
 * @rss_cfg:            RSS configuration
 * @rss_key:            RSS secret key
 * @rss_itbl:           RSS indirection table
 * @ctrl:               Local copy of the control register/word.
 * @fl_bufsz:           Currently configured size of the freelist buffers
 * @max_tx_rings:       Maximum number of TX rings supported by the Firmware
 * @max_rx_rings:       Maximum number of RX rings supported by the Firmware
 * @num_tx_rings:       Currently configured number of TX rings
 * @num_rx_rings:       Currently configured number of RX rings
 * @txd_cnt:            Size of the TX ring in number of descriptors
 * @rxd_cnt:            Size of the RX ring in number of descriptors
 * @tx_rings:           Array of pre-allocated TX ring structures
 * @rx_rings:           Array of pre-allocated RX ring structures
 * @per_vector_masking: Are we using per vector masking?
 * @msix_table:         Pointer to mapped MSI-X table
 * @num_vecs:           Number of allocated vectors
 * @num_r_vecs:         Number of used ring vectors
 * @r_vecs:             Pre-allocated array of ring vectors
 * @irq_entries:        Pre-allocated array of MSI-X entries
 * @lsc_handler:        Handler for Link State Change interrupt
 * @lsc_name:           Name for Link State Change interrupt
 * @exn_handler:        Handler for Exception interrupt
 * @exn_name:           Name for Exception interrupt
 * @shared_handler:     Handler for shared interrupts
 * @shared_name:        Name for shared interrupt
 * @qcp_cfg:            Pointer to QCP queue used for configuration notification
 * @ctrl_bar:           Pointer to mapped control BAR
 * @tx_bar:             Pointer to mapped TX queues
 * @rx_bar:             Pointer to mapped FL/RX queues
 * @spare_va:           Pointer to a spare mapped area to be used by the NFP
 * @spare_dma:          DMA address for spare area
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

	u32 ver;
	u32 cap;
	u32 max_mtu;

	u32 rss_cfg;
	u32 rss_key[NFP_NET_CFG_RSS_KEY_SZ / sizeof(u32)];
	u8 rss_itbl[NFP_NET_CFG_RSS_ITBL_SZ];

	u32 ctrl;
	u32 fl_bufsz;

	int max_tx_rings;
	int max_rx_rings;

	int num_tx_rings;
	int num_rx_rings;

	int txd_cnt;
	int rxd_cnt;

	struct nfp_net_tx_ring tx_rings[NFP_NET_MAX_TX_RINGS];
	struct nfp_net_rx_ring rx_rings[NFP_NET_MAX_RX_RINGS];

	unsigned per_vector_masking:1;
	u8 __iomem *msix_table;
	u8 num_vecs;
	u8 num_r_vecs;
	struct nfp_net_r_vector r_vecs[NFP_NET_MAX_TX_RINGS];
	struct msix_entry irq_entries[NFP_NET_NON_Q_VECTORS +
				      NFP_NET_MAX_TX_RINGS];

	irq_handler_t lsc_handler;
	char lsc_name[IFNAMSIZ + 8];

	irq_handler_t exn_handler;
	char exn_name[IFNAMSIZ + 8];

	irq_handler_t shared_handler;
	char shared_name[IFNAMSIZ + 8];

	u8 __iomem *qcp_cfg;

	u8 __iomem *ctrl_bar;
	u8 __iomem *tx_bar;
	u8 __iomem *rx_bar;

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

/**
 * nfp_qcp_rd_ptr_add() - Add the value to the read pointer of a queue
 *
 * @q:   Base address for queue structure
 * @val: Value to add to the queue pointer
 *
 * If @val is greater than @NFP_QCP_MAX_ADD multiple writes are performed.
 */
static inline void nfp_qcp_rd_ptr_add(u8 __iomem *q, u32 val)
{
	_nfp_qcp_ptr_add(q, NFP_QCP_READ_PTR, val);
}

/**
 * nfp_qcp_wr_ptr_add() - Add the value to the write pointer of a queue
 *
 * @q:   Base address for queue structure
 * @val: Value to add to the queue pointer
 *
 * If @val is greater than @NFP_QCP_MAX_ADD multiple writes are performed.
 */
static inline void nfp_qcp_wr_ptr_add(u8 __iomem *q, u32 val)
{
	_nfp_qcp_ptr_add(q, NFP_QCP_WRITE_PTR, val);
}

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

/**
 * nfp_qcp_rd_ptr_read() - Read the current read pointer value for a queue
 * @q:  Base address for queue structure
 *
 * Return: Value read.
 */
static inline u32 nfp_qcp_rd_ptr_read(u8 __iomem *q)
{
	return _nfp_qcp_read(q, NFP_QCP_READ_PTR);
}

/**
 * nfp_qcp_wr_ptr_read() - Read the current write pointer value for a queue
 * @q:  Base address for queue structure
 *
 * Return: Value read.
 */
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
#endif /* _NFP_NET_H_ */

/*
 * Local variables:
 * c-file-style: "Linux"
 * indent-tabs-mode: t
 * End:
 */
