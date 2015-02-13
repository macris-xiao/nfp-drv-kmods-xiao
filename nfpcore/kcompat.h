/* Copyright (C) 2011 Netronome Systems, Inc. All rights reserved.
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
 * Common declarations for kernel backwards compatibility.
 */
#ifndef __KERNEL__NFP_COMPAT_H__
#define __KERNEL__NFP_COMPAT_H__

#include <linux/kernel.h>
#include <linux/version.h>
#include <linux/device.h>
#include <linux/io.h>
#include <linux/pci.h>
#include <linux/err.h>
#include <linux/etherdevice.h>

#ifndef CONFIG_MFD_NFP_EXPORT
#include <linux/export.h>
#undef EXPORT_SYMBOL
#define EXPORT_SYMBOL(x)        /**/
#endif

#if (LINUX_VERSION_CODE >= KERNEL_VERSION(3, 6, 0))
#include <linux/sizes.h>
#else
# if (LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 38))
#  include <asm-generic/sizes.h>
# else
#   define SZ_1M	(1024 * 1024)
#   define SZ_512M	(512 * 1024 * 1024)
# endif
#endif

/* RHEL has a tendency to heavily patch their kernels.  Sometimes it
 * is necessary to check for specific RHEL releases and not just for
 * Linux kernel version.  Define RHEL version macros for Linux kernels
 * which don't have them. */
#ifndef RHEL_RELEASE_VERSION
#define RHEL_RELEASE_VERSION(a, b) (((a) << 8) + (b))
#endif
#ifndef RHEL_RELEASE_CODE
#define RHEL_RELEASE_CODE 0
#endif

#if (LINUX_VERSION_CODE <= KERNEL_VERSION(2, 6, 27))
#if defined(CONFIG_X86_PAE) || defined(CONFIG_X86_64) || \
	defined(CONFIG_PHYS_ADDR_T_64BIT)
/* phys_addr_t was introduced in mainline after 2.6.27 but some older
 * vendor kernels define it as well. Use a #define to override these
 * definitions. */
#define phys_addr_t u64
#else
#define phys_addr_t u32
#endif
#endif /* KERNEL_VERSION(2, 6, 27)  */

#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 24)
typedef unsigned long uintptr_t;
#endif

#ifndef __maybe_unused
#define __maybe_unused  __attribute__((unused))
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 28)
#define IORESOURCE_TYPE_BITS	0x00000f00
static inline unsigned long resource_type(const struct resource *res)
{
	return res->flags & IORESOURCE_TYPE_BITS;
}
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 21)
static inline void __iomem *compat_devm_ioremap_nocache(
		struct device *dev, resource_size_t offset, unsigned long size)
{
	return ioremap_nocache(offset, size);
}

static inline void compat_devm_iounmap(struct device *dev, void __iomem *addr)
{
	iounmap(addr);
}
#undef devm_ioremap_nocache
#undef devm_iounmap
#define devm_ioremap_nocache(_d, _o, _s) compat_devm_ioremap_nocache(_d, _o, _s)
#define devm_iounmap(_d, _a) compat_devm_iounmap(_d, _a)
#endif /* < 2.6.21 */

#if LINUX_VERSION_CODE < KERNEL_VERSION(3, 0, 0)
static inline int compat_kstrtoul(const char *str, int base, unsigned long *res)
{
	char *cp;
	*res = simple_strtoul(str, &cp, base);
	if (cp && *cp == '\n')
		cp++;

	return (cp == NULL || *cp != 0 || (cp - str) == 0) ? -EINVAL : 0;
}
#define kstrtoul(str, base, res) compat_kstrtoul(str, base, res)
#endif /* < KERNEL_VERSION(3, 0, 0) */

#if LINUX_VERSION_CODE < KERNEL_VERSION(3, 0, 0)
#include <linux/netdevice.h>
#define compat_netdev_printk(dev, level, fmt, args...) \
	({ printk("%s%s: " fmt, level, dev->name , ##args); })
#ifndef netdev_info
#define netdev_info(dev, format, args...) \
	compat_netdev_printk(dev, KERN_INFO , format , ##args)
#endif
#ifndef netdev_dbg
#define netdev_dbg(dev, format, args...) \
	compat_netdev_printk(dev, KERN_DEBUG , format , ##args)
#endif
#ifndef netdev_warn
#define netdev_warn(dev, format, args...) \
	compat_netdev_printk(dev, KERN_WARNING , format , ##args)
#endif
#ifndef netdev_err
#define netdev_err(dev, format, args...) \
	compat_netdev_printk(dev, KERN_ERR , format , ##args)
#endif
#endif /* < KERNEL_VERSION(3, 0, 0) */

#if LINUX_VERSION_CODE < KERNEL_VERSION(3, 14, 0)
static inline int _pci_enable_msi_range(struct pci_dev *dev,
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
#define pci_enable_msi_range(dev, minv, maxv) \
	_pci_enable_msi_range(dev, minv, maxv)
#endif

#if LINUX_VERSION_CODE <= KERNEL_VERSION(2, 6, 26)
#include <linux/mm.h>
/*
 * This function was introduced after 2.6.26 and the implementation here
 * is suboptimal in that it potentially allocates more memory than necessary.
 * The in kernel implementation of alloc_pages_exact() calls a non-exported
 * function (split_page()) which we can't use in this wrapper.
 */
static inline void *alloc_pages_exact(size_t size, gfp_t gfp_mask)
{
	unsigned int order = get_order(size);
	unsigned long addr;

	addr = __get_free_pages(gfp_mask, order);

	return (void *)addr;
}

static inline void free_pages_exact(void *virt, size_t size)
{
	unsigned long addr = (unsigned long)virt;
	unsigned long end = addr + PAGE_ALIGN(size);

	while (addr < end) {
		free_page(addr);
		addr += PAGE_SIZE;
	}
}
#endif /* KERNEL_VERSION(2, 6, 26)  */

#if LINUX_VERSION_CODE <= KERNEL_VERSION(2, 6, 25)
#include <linux/device.h>
static inline const char *dev_name(const struct device *dev)
{
	return kobject_name(&dev->kobj);
}
#endif /* KERNEL_VERSION(2, 6, 25)  */

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 27)
#if LINUX_VERSION_CODE <= KERNEL_VERSION(2, 6, 29)
#include <linux/ftrace.h>
#define trace_printk ftrace_printk
#endif
#else
#define trace_printk(args...)
#endif

#if (LINUX_VERSION_CODE <= KERNEL_VERSION(2, 6, 24))
#define _NEED_PROC_CREATE
#endif

#if (RHEL_RELEASE_CODE > RHEL_RELEASE_VERSION(5, 0))
#undef _NEED_PROC_CREATE
#endif

#ifdef _NEED_PROC_CREATE
#include <linux/proc_fs.h>

static inline struct proc_dir_entry *proc_create(
	const char *name, mode_t mode,
	struct proc_dir_entry *parent, const struct file_operations *proc_fops)
{
	struct proc_dir_entry *pde;

	pde = create_proc_entry(name, mode, parent);
	if (pde != NULL)
		pde->proc_fops = proc_fops;

	return pde;
}
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 24)
#define DMA_BIT_MASK(n)	(((n) == 64) ? ~0ULL : ((1ULL<<(n))-1))
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 20)
/* Copied from fs/seq_file.c.  In the older kernels, the
 * seq_operations parameter is declared without the const, breaking
 * the build. */
#include <linux/seq_file.h>
#define seq_open(file, op) const_seq_open(file, op)
static inline int const_seq_open(struct file *file,
				 const struct seq_operations *op)
{
	struct seq_file *p = file->private_data;

	if (!p) {
		p = kmalloc(sizeof(*p), GFP_KERNEL);
		if (!p)
			return -ENOMEM;
		file->private_data = p;
	}
	memset(p, 0, sizeof(*p));
	mutex_init(&p->lock);
	p->op = (struct seq_operations *)op;
	file->f_version = 0;
	file->f_mode &= ~(FMODE_PREAD | FMODE_PWRITE);
	return 0;
}
#endif

#if LINUX_VERSION_CODE <= KERNEL_VERSION(2, 6, 33)
#ifndef sysfs_attr_init
#define sysfs_attr_init(x) do { } while (0)
#endif
#endif

#if LINUX_VERSION_CODE <= KERNEL_VERSION(2, 6, 32)
static inline long compat_IS_ERR_OR_NULL(const void *ptr)
{
	return !ptr || IS_ERR_VALUE((unsigned long)ptr);
}
#undef IS_ERR_OR_NULL
#define IS_ERR_OR_NULL(x) compat_IS_ERR_OR_NULL(x)
#endif

#if LINUX_VERSION_CODE <= KERNEL_VERSION(2, 6, 29)
int pci_enable_msi(struct pci_dev *dev);
static inline int pci_enable_msi_block(struct pci_dev *dev, unsigned int nvec)
{
	if (nvec > 1)
		return 1;
	return pci_enable_msi(dev);
}
#endif

#if LINUX_VERSION_CODE <= KERNEL_VERSION(2, 6, 28) && defined(CONFIG_X86_32)
static inline __u64 readq(const void __iomem *addr)
{
	const u32 __iomem *p = addr;
	u32 low, high;

	low = readl(p);
	high = readl(p + 1);

	return low + ((u64)high << 32);
}

static inline void writeq(__u64 val, void __iomem *addr)
{
	writel(val, addr);
	writel(val >> 32, addr+4);
}
#endif

#if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 0, 0)
#define HAVE_NET_DEVICE_OPS
#endif

#if (LINUX_VERSION_CODE < KERNEL_VERSION(3, 4, 0))
#define pci_stop_and_remove_bus_device pci_remove_bus_device
#endif

#if (LINUX_VERSION_CODE < KERNEL_VERSION(3, 10, 0))
#define PDE_DATA(inode) (PROC_I(inode)->pde->data)
#endif

#include <linux/mm.h>
#ifndef VM_RESERVED
#define VM_RESERVED (VM_DONTEXPAND | VM_DONTDUMP)
#endif


#if (LINUX_VERSION_CODE < KERNEL_VERSION(3, 4, 0))
#ifndef SIZE_MAX
#define SIZE_MAX        (~(size_t)0)
#endif
static inline void *_kmalloc_array(size_t n, size_t size, gfp_t flags)
{
	if (size != 0 && n > SIZE_MAX / size)
		return NULL;
	return __kmalloc(n * size, flags);
}
#define kmalloc_array(n, size, flags) _kmalloc_array(n, size, flags)
#endif

#if (LINUX_VERSION_CODE < KERNEL_VERSION(3, 7, 0))
#define SUPPORTED_10baseT_Half        (1 << 0)
#define SUPPORTED_10baseT_Full        (1 << 1)
#define SUPPORTED_100baseT_Half       (1 << 2)
#define SUPPORTED_100baseT_Full       (1 << 3)
#define SUPPORTED_1000baseT_Half      (1 << 4)
#define SUPPORTED_1000baseT_Full      (1 << 5)
#define SUPPORTED_Autoneg             (1 << 6)
#define SUPPORTED_TP                  (1 << 7)
#define SUPPORTED_AUI                 (1 << 8)
#define SUPPORTED_MII                 (1 << 9)
#define SUPPORTED_FIBRE               (1 << 10)
#define SUPPORTED_BNC                 (1 << 11)
#define SUPPORTED_10000baseT_Full     (1 << 12)
#define SUPPORTED_Pause               (1 << 13)
#define SUPPORTED_Asym_Pause          (1 << 14)
#define SUPPORTED_2500baseX_Full      (1 << 15)
#define SUPPORTED_Backplane           (1 << 16)
#define SUPPORTED_1000baseKX_Full     (1 << 17)
#define SUPPORTED_10000baseKX4_Full   (1 << 18)
#define SUPPORTED_10000baseKR_Full    (1 << 19)
#define SUPPORTED_10000baseR_FEC      (1 << 20)
#define SUPPORTED_20000baseMLD2_Full  (1 << 21)
#define SUPPORTED_20000baseKR2_Full   (1 << 22)
#define SUPPORTED_40000baseKR4_Full   (1 << 23)
#define SUPPORTED_40000baseCR4_Full   (1 << 24)
#define SUPPORTED_40000baseSR4_Full   (1 << 25)
#define SUPPORTED_40000baseLR4_Full   (1 << 26)

#define ADVERTISED_10baseT_Half       (1 << 0)
#define ADVERTISED_10baseT_Full       (1 << 1)
#define ADVERTISED_100baseT_Half      (1 << 2)
#define ADVERTISED_100baseT_Full      (1 << 3)
#define ADVERTISED_1000baseT_Half     (1 << 4)
#define ADVERTISED_1000baseT_Full     (1 << 5)
#define ADVERTISED_Autoneg            (1 << 6)
#define ADVERTISED_TP                 (1 << 7)
#define ADVERTISED_AUI                (1 << 8)
#define ADVERTISED_MII                (1 << 9)
#define ADVERTISED_FIBRE              (1 << 10)
#define ADVERTISED_BNC                (1 << 11)
#define ADVERTISED_10000baseT_Full    (1 << 12)
#define ADVERTISED_Pause              (1 << 13)
#define ADVERTISED_Asym_Pause         (1 << 14)
#define ADVERTISED_2500baseX_Full     (1 << 15)
#define ADVERTISED_Backplane          (1 << 16)
#define ADVERTISED_1000baseKX_Full    (1 << 17)
#define ADVERTISED_10000baseKX4_Full  (1 << 18)
#define ADVERTISED_10000baseKR_Full   (1 << 19)
#define ADVERTISED_10000baseR_FEC     (1 << 20)
#define ADVERTISED_20000baseMLD2_Full (1 << 21)
#define ADVERTISED_20000baseKR2_Full  (1 << 22)
#define ADVERTISED_40000baseKR4_Full  (1 << 23)
#define ADVERTISED_40000baseCR4_Full  (1 << 24)
#define ADVERTISED_40000baseSR4_Full  (1 << 25)
#define ADVERTISED_40000baseLR4_Full  (1 << 26)
#endif

/* SR-IOV related compat */
#if (LINUX_VERSION_CODE < KERNEL_VERSION(3, 8, 0)) && \
	(RHEL_RELEASE_CODE < RHEL_RELEASE_VERSION(6, 5))
static inline unsigned int pci_sriov_get_totalvfs(struct pci_dev *pdev)
{
	u16 total = 0;
	int pos;

	pos = pci_find_ext_capability(pdev, PCI_EXT_CAP_ID_SRIOV);
	if (pos)
		pci_read_config_word(pdev, pos + PCI_SRIOV_TOTAL_VF, &total);

	return total;
}
#endif

#if (LINUX_VERSION_CODE < KERNEL_VERSION(3, 2, 0))
/* In 3.2+ this is part of the  pci_dev_flags enum */
#define PCI_DEV_FLAGS_ASSIGNED 4
#endif

#if (LINUX_VERSION_CODE < KERNEL_VERSION(3, 10, 0)) && \
	(RHEL_RELEASE_CODE < RHEL_RELEASE_VERSION(6, 5))
static inline int pci_vfs_assigned(struct pci_dev *pdev)
{
	struct pci_dev *vfdev;
	unsigned int vfs_assigned = 0;
	unsigned short dev_id;
	int pos;

	/* only search if we are a PF */
	if (!pdev->is_physfn)
		return 0;

	pos = pci_find_ext_capability(pdev, PCI_EXT_CAP_ID_SRIOV);
	if (!pos)
		return 0;

	/*
	 * determine the device ID for the VFs, the vendor ID will be the
	 * same as the PF so there is no need to check for that one
	 */
	pci_read_config_word(pdev, pos + PCI_SRIOV_VF_DID, &dev_id);

	/* loop through all the VFs to see if we own any that are assigned */
	vfdev = pci_get_device(pdev->vendor, dev_id, NULL);
	while (vfdev) {
		/*
		 * It is considered assigned if it is a virtual function with
		 * our dev as the physical function and the assigned bit is set
		 */
		if (vfdev->is_virtfn && (vfdev->physfn == pdev) &&
		    (vfdev->dev_flags & PCI_DEV_FLAGS_ASSIGNED))
			vfs_assigned++;

		vfdev = pci_get_device(pdev->vendor, dev_id, vfdev);
	}

	return vfs_assigned;
}
#endif

#if (LINUX_VERSION_CODE < KERNEL_VERSION(3, 14, 0))
static inline void ether_addr_copy(u8 *dst, const u8 *src)
{
#if defined(CONFIG_HAVE_EFFICIENT_UNALIGNED_ACCESS)
	*(u32 *)dst = *(const u32 *)src;
	*(u16 *)(dst + 4) = *(const u16 *)(src + 4);
#else
	u16 *a = (u16 *)dst;
	const u16 *b = (const u16 *)src;

	a[0] = b[0];
	a[1] = b[1];
	a[2] = b[2];
#endif
}
#endif

#if (LINUX_VERSION_CODE < KERNEL_VERSION(3, 10, 0))
#define list_first_entry_or_null(ptr, type, member) \
	(!list_empty(ptr) ? list_first_entry(ptr, type, member) : NULL)
#endif

#if (LINUX_VERSION_CODE < KERNEL_VERSION(3, 0, 0))
static inline int compat_kstrtol(const char *cp, int base, long *valp)
{
	char *tmp;
	long val;

	val = simple_strtol(cp, &tmp, base);
	if (!tmp || *tmp != 0)
		return -EINVAL;

	if (valp)
		*valp = val;

	return 0;
}
#define kstrtol(cp, base, valp) compat_kstrtol(cp, base, valp)
#endif

/* v3.17.0
 * do_getttimeofday() moved from linux/time.h to linux/timekeeping.h
 */
#if (LINUX_VERSION_CODE < KERNEL_VERSION(3, 17, 0))
#include <linux/time.h>
#else
#include <linux/timekeeping.h>
#endif

/* v3.17.0
 * alloc_netdev() takes an additional parameter
 */
#if (LINUX_VERSION_CODE < KERNEL_VERSION(3, 17, 0))
#define NET_NAME_UNKNOWN ""
static inline struct net_device *compat_alloc_netdev(int sizeof_priv,
		const char *name, const char *assign_type,
		void (*setup)(struct net_device *))
{
	return alloc_netdev(sizeof_priv, name, setup);
}

#undef alloc_netdev
#define alloc_netdev(sz, nm, ty, setup) compat_alloc_netdev(sz, nm, ty, setup)
#endif


#endif	/* __KERNEL__NFP_COMPAT_H__ */

/*
 * Local variables:
 * c-file-style: "Linux"
 * indent-tabs-mode: t
 * End:
 */
