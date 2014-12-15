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
 */

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/slab.h>
#include <linux/proc_fs.h>
#include <linux/seq_file.h>
#include <linux/device.h>
#include <linux/platform_device.h>

#include "nfp_cpp_kernel.h"
#include "nfp_cpp_imp.h"
#include <linux/sched.h>
#include <linux/wait.h>
#include <linux/mutex.h>

#include "nfp_explicit.h"
#include "nfp3200/nfp3200.h"
#include "nfp3200/nfp_arm.h"
#include "nfp3200/nfp_xpb.h"
#include "nfp3200/nfp_event.h"
#include "nfp3200/nfp_em.h"
#include "nfp3200/nfp_im.h"

#include "nfe.h"
#include "nfp_cpplib.h"

#include "nfp-bsp/nfp_target.h"

#define NFP_CPP_DIR_NAME	"nfp_cpp"

struct nfp_cpp_resource {
	struct list_head list;
	const char *name;
	unsigned int target;
	uint64_t start;
	uint64_t end;
};

struct nfp_cpp {
	int id;
	struct device dev;
	struct kref kref;
	uint32_t model;
	const struct nfp_cpp_operations *op;
	struct list_head resource_list;	/** NFP CPP resource list */
	rwlock_t resource_lock;
	struct list_head list;
	wait_queue_head_t waitq;

	struct platform_device *feature[32];
};

struct nfp_cpp_area {
	struct nfp_cpp *cpp;
	struct kref kref;
	atomic_t refcount;
	struct mutex mutex;	/* Lock for the area's refcount */
	unsigned long long offset;
	unsigned long size;
	struct nfp_cpp_resource resource;
	void __iomem *iomem;
	/* Here follows the 'priv' part of nfp_cpp_area. */
};

struct nfp_cpp_explicit {
	struct nfp_cpp *cpp;
	struct nfp_cpp_explicit_command cmd;
	/* Here follows the 'priv' part of nfp_cpp_area. */
};

struct nfp_cpp_event {
	struct nfp_cpp *cpp;
	struct {
		spinlock_t lock;	/* Lock for the callback */
		void (*func)(void *priv);
		void *priv;
	} callback;
	/* Here follows the 'priv' part of nfp_cpp_area. */
};

#define NFP_CPP_MAX	256

static unsigned long nfp_cpp_id[
	(NFP_CPP_MAX + sizeof(unsigned long) * 8 - 1)
		/ (sizeof(unsigned long) * 8)];
static struct mutex nfp_cpp_id_lock;
static struct list_head nfp_cpp_list;
static rwlock_t nfp_cpp_list_lock;

static inline int nfp_cpp_id_acquire(void)
{
	int id;

	mutex_lock(&nfp_cpp_id_lock);
	id = find_first_zero_bit(nfp_cpp_id, NFP_CPP_MAX);
	if (id < NFP_CPP_MAX)
		set_bit(id, nfp_cpp_id);
	mutex_unlock(&nfp_cpp_id_lock);
	return (id < NFP_CPP_MAX) ? id : -1;
}

static inline void nfp_cpp_id_release(int id)
{
	mutex_lock(&nfp_cpp_id_lock);
	clear_bit(id, nfp_cpp_id);
	mutex_unlock(&nfp_cpp_id_lock);
}

#ifdef CONFIG_PROC_FS
static struct proc_dir_entry *nfp_cpp_dir;
#endif

static void __nfp_cpp_release(struct kref *kref)
{
	struct nfp_cpp *cpp = container_of(kref, struct nfp_cpp, kref);

#ifdef CONFIG_PROC_FS
	remove_proc_entry(dev_name(cpp->op->parent), nfp_cpp_dir);
#endif

	if (cpp->op->free)
		cpp->op->free(cpp);

	write_lock(&nfp_cpp_list_lock);
	list_del_init(&cpp->list);
	write_unlock(&nfp_cpp_list_lock);

	device_unregister(&cpp->dev);

	nfp_cpp_id_release(cpp->id);
	kfree(cpp);
}

#define CPP_GET(cpp)	kref_get(&(cpp)->kref)
#define CPP_PUT(cpp)	kref_put(&(cpp)->kref, __nfp_cpp_release)

static struct nfp_cpp *nfp_cpp_get(struct nfp_cpp *cpp)
{
	CPP_GET(cpp);

	return cpp;
}

static void nfp_cpp_put(struct nfp_cpp *cpp)
{
	CPP_PUT(cpp);
}

/**
 * nfp_cpp_from_device_id - open a CPP by ID
 * @id:		device ID
 */
struct nfp_cpp *nfp_cpp_from_device_id(int id)
{
	struct nfp_cpp *tmp, *cpp = NULL;

	read_lock(&nfp_cpp_list_lock);
	list_for_each_entry(tmp, &nfp_cpp_list, list) {
		if (tmp->id == id) {
			cpp = nfp_cpp_get(tmp);
			break;
		}
	}
	read_unlock(&nfp_cpp_list_lock);

	return cpp;
}
EXPORT_SYMBOL(nfp_cpp_from_device_id);

/**
 * nfp_cpp_device_id - get device ID of CPP handle
 * @cpp:	CPP handle
 */
int nfp_cpp_device_id(struct nfp_cpp *cpp)
{
	return cpp->id;
}
EXPORT_SYMBOL(nfp_cpp_device_id);

/**
 * nfp_cpp_free - free the CPP handle
 * @cpp:	CPP handle
 */
void nfp_cpp_free(struct nfp_cpp *cpp)
{
	nfp_cpp_put(cpp);
}
EXPORT_SYMBOL(nfp_cpp_free);

/**
 * \brief nfp_cpp_model - Retrieve the Model ID of the NFP
 *
 * @param[in]	cpp	NFP CPP handle
 * @return		NFP CPP Model ID
 */
uint32_t nfp_cpp_model(struct nfp_cpp *cpp)
{
	/* Check the cached model */
	return cpp->model;
}
EXPORT_SYMBOL(nfp_cpp_model);

/**
 * \brief nfp_cpp_interface - Retrieve the Interface ID of the NFP
 *
 * @param[in]	cpp	NFP CPP handle
 * @return		NFP CPP Interface ID
 */
uint16_t nfp_cpp_interface(struct nfp_cpp *cpp)
{
	return cpp->op->interface;
}
EXPORT_SYMBOL(nfp_cpp_interface);

/**
 * \brief nfp_cpp_serial - Retrieve the Serial ID of the NFP
 *
 * @param[in]	cpp	NFP CPP handle
 * @param[out]	serial	Pointer to NFP serial number
 * @return		Length of NFP serial number
 */
int nfp_cpp_serial(struct nfp_cpp *cpp, const uint8_t **serial)
{
	*serial = &cpp->op->serial[0];
	return sizeof(cpp->op->serial);
}
EXPORT_SYMBOL(nfp_cpp_serial);

static void __resource_add(struct list_head *head, struct nfp_cpp_resource *res)
{
	struct nfp_cpp_resource *tmp;
	struct list_head *pos;

	list_for_each(pos, head) {
		tmp = container_of(pos, struct nfp_cpp_resource, list);
		if (tmp->target > res->target)
			break;

		if (tmp->target == res->target &&
		    tmp->start > res->start)
			break;
	}

	list_add_tail(&res->list, pos);
}

static void __resource_del(struct nfp_cpp_resource *res)
{
	list_del_init(&res->list);
}

static void __release_cpp_area(struct kref *kref)
{
	struct nfp_cpp_area *area =
		container_of(kref, struct nfp_cpp_area, kref);
	struct nfp_cpp *cpp = nfp_cpp_area_cpp(area);

	if (area->cpp->op->area_cleanup)
		area->cpp->op->area_cleanup(area);

	write_lock(&cpp->resource_lock);
	__resource_del(&area->resource);
	write_unlock(&cpp->resource_lock);
	CPP_PUT(area->cpp);
	kfree(area);
}

static void nfp_cpp_area_put(struct nfp_cpp_area *area)
{
	BUG_ON(area == NULL);
	kref_put(&area->kref, __release_cpp_area);
}

static struct nfp_cpp_area *nfp_cpp_area_get(struct nfp_cpp_area *area)
{
	BUG_ON(area == NULL);
	kref_get(&area->kref);
	return area;
}

/**
 * nfp_cpp_area_priv - return private struct for CPP area
 * @cpp_area:	CPP area handle
 */
void *nfp_cpp_area_priv(struct nfp_cpp_area *cpp_area)
{
	return &cpp_area[1];
}
EXPORT_SYMBOL(nfp_cpp_area_priv);

/**
 * nfp_cpp_area_cpp - return CPP handle for CPP area
 * @cpp_area:	CPP area handle
 */
struct nfp_cpp *nfp_cpp_area_cpp(struct nfp_cpp_area *cpp_area)
{
	return cpp_area->cpp;
}
EXPORT_SYMBOL(nfp_cpp_area_cpp);

/**
 * nfp_cpp_area_name - return name of a CPP area
 * @cpp_area:	CPP area handle
 */
const char *nfp_cpp_area_name(struct nfp_cpp_area *cpp_area)
{
	return cpp_area->resource.name;
}
EXPORT_SYMBOL(nfp_cpp_area_name);

/**
 * nfp_cpp_area_alloc_with_name - allocate a new CPP area
 *
 * Allocate and initialize a CPP area structure.  The area must later
 * be locked down with an 'acquire' before it can be safely accessed.
 *
 * NOTE: @address and @size must be 32-bit aligned values.
 */
struct nfp_cpp_area *nfp_cpp_area_alloc_with_name(
	struct nfp_cpp *cpp, uint32_t dest,
	const char *name,
	unsigned long long address, unsigned long size)
{
	struct nfp_cpp_area *area;
	int name_len;

	BUG_ON(cpp == NULL);
	if (name == NULL)
		name = "(reserved)";

	name_len = strlen(name) + 1;
	area = kmalloc(sizeof(*area) +
			cpp->op->area_priv_size +
			name_len, GFP_KERNEL);
	if (!area)
		return NULL;

	/* Zero out area */
	memset(area, 0, sizeof(*area) + cpp->op->area_priv_size);

	CPP_GET(cpp);
	area->cpp = cpp;
	area->resource.name = (void *)area + sizeof(*area) +
				cpp->op->area_priv_size;
	memcpy((char *)(area->resource.name), name, name_len);

	area->resource.target = NFP_CPP_ID_TARGET_of(dest);
	area->resource.start = address;
	area->resource.end = area->resource.start + size - 1;
	INIT_LIST_HEAD(&area->resource.list);

	atomic_set(&area->refcount, 0);
	kref_init(&area->kref);
	mutex_init(&area->mutex);

	if (cpp->op->area_init != NULL) {
		int err;

		err = cpp->op->area_init(area, dest, address, size);
		if (err < 0) {
			CPP_PUT(area->cpp);
			kfree(area);
			return NULL;
		}
	}

	write_lock(&cpp->resource_lock);
	__resource_add(&cpp->resource_list, &area->resource);
	write_unlock(&cpp->resource_lock);

	area->offset = address;
	area->size = size;

	return area;
}
EXPORT_SYMBOL(nfp_cpp_area_alloc_with_name);

/**
 * nfp_cpp_area_alloc - allocate a new CPP area
 * @cpp:	CPP handle
 * @dest:	CPP id
 * @address:	start address on CPP target
 * @size:	size of area in bytes
 *
 * Allocate and initialize a CPP area structure.  The area must later
 * be locked down with an 'acquire' before it can be safely accessed.
 *
 * NOTE: @address and @size must be 32-bit aligned values.
 */
struct nfp_cpp_area *nfp_cpp_area_alloc(
	struct nfp_cpp *cpp, uint32_t dest,
	unsigned long long address, unsigned long size)
{
	return nfp_cpp_area_alloc_with_name(cpp, dest, NULL, address, size);
}
EXPORT_SYMBOL(nfp_cpp_area_alloc);

/**
 * nfp_cpp_area_alloc_acquire - allocate a new CPP area and lock it down
 * @cpp:	CPP handle
 * @dest:	CPP id
 * @address:	start address on CPP target
 * @size:	size of area
 *
 * Allocate and initilizae a CPP area structure, and lock it down so
 * that it can be accessed directly.
 *
 * NOTE: @address and @size must be 32-bit aligned values.
 *
 * NOTE: The area must also be 'released' when the structure is freed.
 */
struct nfp_cpp_area *nfp_cpp_area_alloc_acquire(
		  struct nfp_cpp *cpp, uint32_t destination,
		  unsigned long long address,
		  unsigned long size)
{
	struct nfp_cpp_area *area;

	area = nfp_cpp_area_alloc(cpp, destination, address, size);
	if (!area)
		return NULL;

	if (nfp_cpp_area_acquire(area)) {
		nfp_cpp_area_free(area);
		return NULL;
	}

	return area;
}
EXPORT_SYMBOL(nfp_cpp_area_alloc_acquire);

/**
 * nfp_cpp_area_free - free up the CPP area
 * area:	CPP area handle
 *
 * Frees up memory resources held by the CPP area.
 */
void nfp_cpp_area_free(struct nfp_cpp_area *area)
{
	nfp_cpp_area_put(area);
}
EXPORT_SYMBOL(nfp_cpp_area_free);

/**
 * nfp_cpp_area_release_free - release CPP area and free it
 * area:	CPP area handle
 *
 * Releases CPP area and frees up memory resources held by the it.
 */
void nfp_cpp_area_release_free(struct nfp_cpp_area *area)
{
	nfp_cpp_area_release(area);
	nfp_cpp_area_free(area);
}
EXPORT_SYMBOL(nfp_cpp_area_release_free);

/**
 * nfp_cpp_area_acquire - lock down a CPP area for access
 * @area:	CPP area handle
 *
 * Locks down the CPP area for a potential long term activity.  Area
 * must always be locked down before being accessed.
 */
int nfp_cpp_area_acquire(struct nfp_cpp_area *area)
{
	mutex_lock(&area->mutex);
	if (atomic_inc_return(&area->refcount) == 1) {
		int (*a_a)(struct nfp_cpp_area *);

		a_a = area->cpp->op->area_acquire;
		if (a_a) {
			int err;

			wait_event_interruptible(area->cpp->waitq,
						 (err = a_a(area)) != -EAGAIN);
			if (err < 0) {
				atomic_dec(&area->refcount);
				mutex_unlock(&area->mutex);
				return err;
			}
		}
	}
	mutex_unlock(&area->mutex);

	nfp_cpp_area_get(area);
	return 0;
}
EXPORT_SYMBOL(nfp_cpp_area_acquire);

/**
 * nfp_cpp_area_acquire_nonblocking - lock down a CPP area for access
 * @area:	CPP area handle
 *
 * Locks down the CPP area for a potential long term activity.  Area
 * must always be locked down before being accessed.
 *
 * Returns -EAGAIN is no area is available
 */
int nfp_cpp_area_acquire_nonblocking(struct nfp_cpp_area *area)
{
	mutex_lock(&area->mutex);
	if (atomic_inc_return(&area->refcount) == 1) {
		if (area->cpp->op->area_acquire) {
			int err = area->cpp->op->area_acquire(area);

			if (err < 0) {
				atomic_dec(&area->refcount);
				mutex_unlock(&area->mutex);
				return err;
			}
		}
	}
	mutex_unlock(&area->mutex);

	nfp_cpp_area_get(area);
	return 0;
}
EXPORT_SYMBOL(nfp_cpp_area_acquire_nonblocking);

/**
 * nfp_cpp_area_release - release a locked down CPP area
 * @area:	CPP area handle
 *
 * Releases a previously locked down CPP area.
 */
void nfp_cpp_area_release(struct nfp_cpp_area *area)
{
	mutex_lock(&area->mutex);
	/* Only call the release on refcount == 0 */
	if (atomic_dec_and_test(&area->refcount)) {
		if (area->cpp->op->area_release) {
			area->cpp->op->area_release(area);
			/* Let anyone waiting for a BAR try to get one.. */
			wake_up_interruptible_all(&area->cpp->waitq);
		}
	}
	mutex_unlock(&area->mutex);

	nfp_cpp_area_put(area);
}
EXPORT_SYMBOL(nfp_cpp_area_release);

/**
 * nfp_cpp_area_read - read data from CPP area
 * @area:		CPP area handle
 * @offset:		offset into CPP area
 * @kernel_vaddr:	kernel address to put data into
 * @length:		number of bytes to read
 *
 * Read data from indicated CPP region.
 *
 * NOTE: @offset and @length must be 32-bit aligned values.
 *
 * NOTE: Area must have been locked down with an 'acquire'.
 */
int nfp_cpp_area_read(struct nfp_cpp_area *area,
		      unsigned long offset, void *kernel_vaddr,
		      size_t length)
{
	return area->cpp->op->area_read(area, kernel_vaddr, offset, length);
}
EXPORT_SYMBOL(nfp_cpp_area_read);

/**
 * nfp_cpp_area_write - write data to CPP area
 * @area:		CPP area handle
 * @offset:		offset into CPP area
 * @kernel_vaddr:	kernel address to read data from
 * @length:		number of bytes to write
 *
 * Write data to indicated CPP region.
 *
 * NOTE: @offset and @length must be 32-bit aligned values.
 *
 * NOTE: Area must have been locked down with an 'acquire'.
 */
int nfp_cpp_area_write(struct nfp_cpp_area *area,
		       unsigned long offset, const void *kernel_vaddr,
		       size_t length)
{
	return area->cpp->op->area_write(area, kernel_vaddr, offset, length);
}
EXPORT_SYMBOL(nfp_cpp_area_write);

/**
 * nfp_cpp_area_check_range - check if address range fits in CPP area
 * @area:	CPP area handle
 * @offset:	offset into CPP target
 * @length:	size of address range in bytes
 *
 * Check if address range fits within CPP area.  Return 0 if area
 * fits or -EFAULT on error.
 */
int nfp_cpp_area_check_range(struct nfp_cpp_area *area,
			     unsigned long long offset, unsigned long length)
{
	if ((offset < area->offset) ||
	    ((offset + length) > (area->offset + area->size)))
		return -EFAULT;
	return 0;
}
EXPORT_SYMBOL(nfp_cpp_area_check_range);

/**
 * nfp_cpp_area_resource - get resource
 * @area:	CPP area handle
 *
 * NOTE: Area must have been locked down with an 'acquire'.
 */
struct resource *nfp_cpp_area_resource(struct nfp_cpp_area *area)
{
	struct resource *res = NULL;

	if (area->cpp->op->area_resource)
		res = area->cpp->op->area_resource(area);

	return res;
}
EXPORT_SYMBOL(nfp_cpp_area_resource);

/**
 * nfp_cpp_area_phys - get physical address of CPP area
 * @area:	CPP area handle
 *
 * NOTE: Area must have been locked down with an 'acquire'.
 */
phys_addr_t nfp_cpp_area_phys(struct nfp_cpp_area *area)
{
	phys_addr_t addr = ~0;

	if (area->cpp->op->area_phys)
		addr = area->cpp->op->area_phys(area);

	return addr;
}
EXPORT_SYMBOL(nfp_cpp_area_phys);

/**
 * nfp_cpp_area_iomem - get IOMEM region for CPP area
 * @area:	CPP area handle
 *
 * Returns an iomem pointer for use with readl()/writel() style
 * operations.
 *
 * NOTE: Area must have been locked down with an 'acquire'.
 */
void __iomem *nfp_cpp_area_iomem(struct nfp_cpp_area *area)
{
	void __iomem *iomem = NULL;

	if (area->cpp->op->area_iomem)
		iomem = area->cpp->op->area_iomem(area);

	return iomem;
}
EXPORT_SYMBOL(nfp_cpp_area_iomem);

int nfp_cpp_area_readl(struct nfp_cpp_area *area,
		       unsigned long offset, uint32_t *value)
{
	int err;
	uint32_t tmp;

	err = nfp_cpp_area_read(area, offset, &tmp, sizeof(tmp));
	*value = le32_to_cpu(tmp);

	return err;
}
EXPORT_SYMBOL(nfp_cpp_area_readl);

int nfp_cpp_area_writel(struct nfp_cpp_area *area,
			unsigned long offset, uint32_t value)
{
	value = cpu_to_le32(value);
	return nfp_cpp_area_write(area, offset, &value, sizeof(value));
}
EXPORT_SYMBOL(nfp_cpp_area_writel);

int nfp_cpp_area_readq(struct nfp_cpp_area *area,
		       unsigned long offset, uint64_t *value)
{
	int err;
	uint64_t tmp;

	err = nfp_cpp_area_read(area, offset, &tmp, sizeof(tmp));
	*value = le64_to_cpu(tmp);

	return err;
}
EXPORT_SYMBOL(nfp_cpp_area_readq);

int nfp_cpp_area_writeq(struct nfp_cpp_area *area,
			unsigned long offset, uint64_t value)
{
	value = cpu_to_le64(value);
	return nfp_cpp_area_write(area, offset, &value, sizeof(value));
}
EXPORT_SYMBOL(nfp_cpp_area_writeq);

int nfp_cpp_readl(struct nfp_cpp *cpp, uint32_t cpp_id,
		  unsigned long long address, uint32_t *value)
{
	int err;
	uint32_t tmp;

	err = nfp_cpp_read(cpp, cpp_id, address, &tmp, sizeof(tmp));
	*value = le32_to_cpu(tmp);

	return err;
}
EXPORT_SYMBOL(nfp_cpp_readl);

int nfp_cpp_writel(struct nfp_cpp *cpp, uint32_t cpp_id,
		   unsigned long long address, uint32_t value)
{
	value = cpu_to_le32(value);
	return nfp_cpp_write(cpp, cpp_id, address, &value, sizeof(value));
}
EXPORT_SYMBOL(nfp_cpp_writel);

int nfp_cpp_readq(struct nfp_cpp *cpp, uint32_t cpp_id,
		  unsigned long long address, uint64_t *value)
{
	int err;
	uint64_t tmp;

	err = nfp_cpp_read(cpp, cpp_id, address, &tmp, sizeof(tmp));
	*value = le64_to_cpu(tmp);

	return err;
}
EXPORT_SYMBOL(nfp_cpp_readq);

int nfp_cpp_writeq(struct nfp_cpp *cpp, uint32_t cpp_id,
		   unsigned long long address, uint64_t value)
{
	value = cpu_to_le64(value);
	return  nfp_cpp_write(cpp, cpp_id, address, &value, sizeof(value));
}
EXPORT_SYMBOL(nfp_cpp_writeq);

/* Return the correct CPP address, and fixup xpb_addr as needed,
 * based upon NFP model.
 */
static uint32_t nfp_xpb_to_cpp(struct nfp_cpp *cpp, uint32_t *xpb_addr)
{
	uint32_t xpb;

	if (NFP_CPP_MODEL_IS_3200(cpp->model)) {
		xpb = NFP_CPP_ID(13, NFP_CPP_ACTION_RW, 0);
		(*xpb_addr) |= 0x02000000;
	} else if (NFP_CPP_MODEL_IS_6000(cpp->model)) {
		xpb = NFP_CPP_ID(14, NFP_CPP_ACTION_RW, 0);
		/* Ensure that non-local XPB accesses go
		 * out through the global XPBM bus.
		 */
		if ((*xpb_addr) & 0x3f000000)
			(*xpb_addr) |= (1 << 30);
	} else {
		return 0;
	}

	return xpb;
}

int nfp_xpb_writel(struct nfp_cpp *cpp, uint32_t xpb_addr, uint32_t value)
{
	uint32_t cpp_dest = nfp_xpb_to_cpp(cpp, &xpb_addr);

	return nfp_cpp_writel(cpp, cpp_dest, xpb_addr, value);
}
EXPORT_SYMBOL(nfp_xpb_writel);

int nfp_xpb_readl(struct nfp_cpp *cpp, uint32_t xpb_addr, uint32_t *value)
{
	uint32_t cpp_dest = nfp_xpb_to_cpp(cpp, &xpb_addr);

	return nfp_cpp_readl(cpp, cpp_dest, xpb_addr, value);
}
EXPORT_SYMBOL(nfp_xpb_readl);

/**
 * nfp_cpp_explicit_priv - return private struct for CPP explicit
 * @cpp_explicit:	CPP explicit handle
 */
void *nfp_cpp_explicit_priv(struct nfp_cpp_explicit *cpp_explicit)
{
	return &cpp_explicit[1];
}
EXPORT_SYMBOL(nfp_cpp_explicit_priv);

/**
 * nfp_cpp_explicit_cpp - return CPP handle for CPP explicit
 * @cpp_explicit:	CPP explicit handle
 */
struct nfp_cpp *nfp_cpp_explicit_cpp(struct nfp_cpp_explicit *cpp_explicit)
{
	return cpp_explicit->cpp;
}
EXPORT_SYMBOL(nfp_cpp_explicit_cpp);

#define NFP_EXPL_OP(err, func, expl, args...) \
	do { \
		struct nfp_cpp *cpp = nfp_cpp_explicit_cpp(expl); \
		if (cpp->op->func != NULL) { \
			CPP_GET(cpp); \
			err = cpp->op->func(expl , ##args); \
			CPP_PUT(cpp); \
		} \
	} while (0)

#define NFP_EXPL_OP_NR(func, expl, args...) \
	do { \
		struct nfp_cpp *cpp = nfp_cpp_explicit_cpp(expl); \
		if (cpp->op->func != NULL) { \
			CPP_GET(cpp); \
			cpp->op->func(expl , ##args); \
			CPP_PUT(cpp); \
		} \
	} while (0)

/**
 * Acquire explicit access handle
 *
 * @param cpp		NFP CPP handle
 * @param data_ref	Pointer to the resulting 'data_ref'
 * @param signal_ref	Pointer to the resulting 'signal_ref'
 *
 * The 'data_ref' and 'signal_ref' values are useful when
 * constructing the NFP_EXPL_CSR1 and NFP_EXPL_POST values.
 */
struct nfp_cpp_explicit *nfp_cpp_explicit_acquire(struct nfp_cpp *cpp)
{
	struct nfp_cpp_explicit *expl;

	expl = kzalloc(sizeof(*expl) + cpp->op->explicit_priv_size, GFP_KERNEL);
	if (expl != NULL) {
		int err = -ENODEV;

		expl->cpp = cpp;
		NFP_EXPL_OP(err, explicit_acquire, expl);
		if (err < 0) {
			kfree(expl);
			expl = NULL;
		}
	}

	return expl;
}
EXPORT_SYMBOL(nfp_cpp_explicit_acquire);

int nfp_cpp_explicit_set_target(struct nfp_cpp_explicit *expl,
				uint32_t cpp_id, uint8_t len, uint8_t mask)
{
	expl->cmd.cpp_id = cpp_id;
	expl->cmd.len = len;
	expl->cmd.byte_mask = mask;

	return 0;
}
EXPORT_SYMBOL(nfp_cpp_explicit_set_target);

int nfp_cpp_explicit_set_data(struct nfp_cpp_explicit *expl,
			      uint8_t data_master, uint16_t data_ref)
{
	expl->cmd.data_master = data_master;
	expl->cmd.data_ref = data_ref;

	return 0;
}
EXPORT_SYMBOL(nfp_cpp_explicit_set_data);

int nfp_cpp_explicit_set_signal(struct nfp_cpp_explicit *expl,
				uint8_t signal_master, uint8_t signal_ref)
{
	expl->cmd.signal_master = signal_master;
	expl->cmd.signal_ref = signal_ref;

	return 0;
}
EXPORT_SYMBOL(nfp_cpp_explicit_set_signal);

int nfp_cpp_explicit_set_posted(struct nfp_cpp_explicit *expl, int posted,
				uint8_t siga,
				enum nfp_cpp_explicit_signal_mode siga_mode,
				uint8_t sigb,
				enum nfp_cpp_explicit_signal_mode sigb_mode)
{
	expl->cmd.posted = posted;
	expl->cmd.siga = siga;
	expl->cmd.sigb = sigb;
	expl->cmd.siga_mode = siga_mode;
	expl->cmd.sigb_mode = sigb_mode;

	return 0;
}
EXPORT_SYMBOL(nfp_cpp_explicit_set_posted);

/**
 * Set up the write (pull) data for a NFP CPP explicit access
 *
 * @param expl		NFP CPP Explicit handle
 * @param buff		Data to have the target pull in the transaction
 * @param len		Length of data, in bytes
 *
 * The 'len' parameter must be less than or equal to 32 bytes.
 *
 * If this function is called before the configuration
 * registers are set, it will return -1, with an errno of EINVAL.
 *
 * @return 0 on success, -1 on failure (and set errno accordingly).
 */
int nfp_cpp_explicit_put(struct nfp_cpp_explicit *expl,
			 const void *buff, size_t len)
{
	int err = -EINVAL;

	NFP_EXPL_OP(err, explicit_put, expl, buff, len);

	return err;
}
EXPORT_SYMBOL(nfp_cpp_explicit_put);

/**
 * Execute a transaction, and wait for it to complete
 *
 * @param expl		NFP CPP Explicit handle
 * @param address	Address to send in the explicit transaction
 *
 * If this function is called before the configuration
 * registers are set, it will return -1, with an errno of EINVAL.
 *
 * @return 0 on success, -1 on failure (and set errno accordingly).
 */
int nfp_cpp_explicit_do(struct nfp_cpp_explicit *expl, uint64_t address)
{
	int err = -EINVAL;

	NFP_EXPL_OP(err, explicit_do, expl, &expl->cmd, address);

	return err;
}
EXPORT_SYMBOL(nfp_cpp_explicit_do);

/**
 * Get the 'push' (read) data from a NFP CPP explicit access
 *
 * @param expl		NFP CPP Explicit handle
 * @param buff		Data that the target pushed in the transaction
 * @param len		Length of data, in bytes
 *
 * The 'len' parameter must be less than or equal to 32 bytes.
 *
 * If this function is called before all three configuration
 * registers are set, it will return -1, with an errno of EINVAL.
 *
 * If this function is called before nfp_cpp_explicit_wait()
 * has completed, it will return -1, with an errno of EBUSY.
 *
 * @return 0 on success, -1 on failure (and set errno accordingly).
 */
int nfp_cpp_explicit_get(struct nfp_cpp_explicit *expl, void *buff, size_t len)
{
	int err = -EINVAL;

	NFP_EXPL_OP(err, explicit_get, expl, buff, len);

	return err;
}
EXPORT_SYMBOL(nfp_cpp_explicit_get);

/**
 * Release explicit access handle
 *
 * @param expl		NFP CPP Explicit handle
 *
 */
void nfp_cpp_explicit_release(struct nfp_cpp_explicit *expl)
{
	NFP_EXPL_OP_NR(explicit_release, expl);
	kfree(expl);
}
EXPORT_SYMBOL(nfp_cpp_explicit_release);

/**
 * nfp_cpp_event_priv - return private struct for CPP event
 * @cpp_event:	CPP event handle
 */
void *nfp_cpp_event_priv(struct nfp_cpp_event *cpp_event)
{
	return &cpp_event[1];
}
EXPORT_SYMBOL(nfp_cpp_event_priv);

/**
 * nfp_cpp_event_cpp - return CPP handle for CPP event
 * @cpp_event:	CPP event handle
 */
struct nfp_cpp *nfp_cpp_event_cpp(struct nfp_cpp_event *cpp_event)
{
	return cpp_event->cpp;
}
EXPORT_SYMBOL(nfp_cpp_event_cpp);

struct nfp_cpp_event *nfp_cpp_event_alloc(
	struct nfp_cpp *cpp, uint32_t match, uint32_t mask, int type)
{
	struct nfp_cpp_event *event;
	int err;

	BUG_ON(cpp == NULL);

	if (cpp->op->event_acquire == NULL)
		return ERR_PTR(-ENODEV);

	if (type < 0)
		type = 0;

	if (type > 7)
		return ERR_PTR(-EINVAL);

	event = kzalloc(sizeof(*event) +
			cpp->op->event_priv_size,
			GFP_KERNEL);
	if (!event)
		return ERR_PTR(-ENOMEM);

	CPP_GET(cpp);
	event->cpp = cpp;

	spin_lock_init(&event->callback.lock);

	err = cpp->op->event_acquire(event, mask, match, type);
	if (err < 0) {
		CPP_PUT(cpp);
		kfree(event);
		return ERR_PTR(err);
	}

	return event;
}
EXPORT_SYMBOL(nfp_cpp_event_alloc);

int nfp_cpp_event_as_callback(struct nfp_cpp_event *event,
			      void (*func)(void *), void *priv)
{
	unsigned long flags;

	spin_lock_irqsave(&event->callback.lock, flags);
	event->callback.func = func;
	event->callback.priv = priv;
	spin_unlock_irqrestore(&event->callback.lock, flags);

	return 0;
}
EXPORT_SYMBOL(nfp_cpp_event_as_callback);

void nfp_cpp_event_callback(struct nfp_cpp_event *event)
{
	unsigned long flags;
	void (*func)(void *);
	void *priv;

	if (!event)
		return;

	/* This is expected to be called in IRQ context */
	spin_lock_irqsave(&event->callback.lock, flags);
	func = event->callback.func;
	priv = event->callback.priv;
	spin_unlock_irqrestore(&event->callback.lock, flags);

	if (func)
		func(priv);
}

void nfp_cpp_event_free(struct nfp_cpp_event *event)
{
	struct nfp_cpp *cpp = nfp_cpp_event_cpp(event);

	if (cpp->op->event_release != NULL)
		cpp->op->event_release(event);

	CPP_PUT(cpp);
	kfree(event);
}
EXPORT_SYMBOL(nfp_cpp_event_free);

#ifdef CONFIG_PROC_FS
static void *cpp_r_next(struct seq_file *m, void *v, loff_t *pos)
{
	struct nfp_cpp *cpp = m->private;
	struct list_head *p = v;

	(*pos)++;
	if (p->next == &cpp->resource_list)
		return NULL;

	return p->next;
}

static void *cpp_r_start(struct seq_file *m, loff_t *pos)
{
	struct nfp_cpp *cpp = m->private;
	struct list_head  *tmp;
	loff_t l = 0;

	read_lock(&cpp->resource_lock);

	if (list_empty(&cpp->resource_list))
		return NULL;

	for (tmp = cpp->resource_list.next;
	     tmp != NULL && l < *pos;
	     tmp = cpp_r_next(m, tmp, &l))
		;

	return tmp;
}

static void cpp_r_stop(struct seq_file *m, void *v)
{
	struct nfp_cpp *cpp = m->private;

	read_unlock(&cpp->resource_lock);
}

static const char * const cpp_target_name[] = {
	"tgt0", "msf0", "qdr", "msf1",
	"hash", "tgt5", "tgt6", "ddr",
	"gs", "pcie", "arm", "tgt11",
	"crypto", "cap", "ct", "cls",
};

static int cpp_r_show(struct seq_file *m, void *v)
{
	struct nfp_cpp_resource *r =
		container_of(v, struct nfp_cpp_resource, list);
	struct nfp_cpp_area *area =
		container_of(r, struct nfp_cpp_area, resource);
	const char *inactive = (atomic_read(&area->refcount) == 0) ?
		" [inactive]" : "";

	if (r->target >= ARRAY_SIZE(cpp_target_name))
		seq_printf(m, "tgt%d : %#llx-%#llx : %s%s\n",
			   r->target, r->start, r->end, r->name, inactive);
	else
		seq_printf(m, "%s : %#llx-%#llx : %s%s\n",
			   cpp_target_name[r->target],
			   r->start, r->end, r->name, inactive);

	return 0;
}

static const struct seq_operations cpp_resource_op = {
	.start = cpp_r_start,
	.next  = cpp_r_next,
	.stop  = cpp_r_stop,
	.show  = cpp_r_show,
};

static int iocpp_open(struct inode *inode, struct file *file)
{
	int res = seq_open(file, &cpp_resource_op);

	if (!res) {
		struct seq_file *m = file->private_data;

		m->private = PDE_DATA(inode);
	}
	return res;
}

static const struct file_operations iocpp_ops = {
	.open		= iocpp_open,
	.read		= seq_read,
	.llseek		= seq_lseek,
	.release	= seq_release,
};
#endif /* CONFIG_PROC_FS */

#ifdef CONFIG_LOCKDEP
/* Lockdep markers */
static struct lock_class_key nfp_cpp_resource_lock_key;
#endif

struct platform_device *nfp_cpp_register_device(struct nfp_cpp *cpp,
						const char *type)
{
	struct device *dev = nfp_cpp_device(cpp);
	struct platform_device *pdev;
	int err;

	pdev = platform_device_alloc(type, cpp->id);
	if (pdev == NULL) {
		dev_err(dev, "Can't create '%s.%d' platform device",
			type, cpp->id);
		return NULL;
	}

	pdev->dev.parent = dev;

	err = platform_device_add(pdev);
	if (err < 0) {
		dev_err(dev, "Can't register '%s.%d' platform device",
			type, cpp->id);
		platform_device_put(pdev);
		return NULL;
	}

	return pdev;
}

void nfp_cpp_unregister_device(struct platform_device *pdev)
{
	if (pdev)
		platform_device_unregister(pdev);
}

static void nfp_cpp_dev_release(struct device *dev)
{
	/* Nothing to do here - it just makes the kernel happy */
}

/**
 * Create a NFP CPP handle from an operations structure
 *
 * @param   cpp_ops  NFP CPP operations structure
 * @return           NFP CPP handle on success, ERR_PTR on failure
 *
 * NOTE: On failure, cpp_ops->free will be called!
 */
struct nfp_cpp *nfp_cpp_from_operations(const struct nfp_cpp_operations *ops)
{
	int id, err;
	struct nfp_cpp *cpp;
#ifdef CONFIG_PROC_FS
	struct proc_dir_entry *pde;
#endif

	BUG_ON(ops->parent == NULL);

	/* Argh. Out of IDs */
	id = nfp_cpp_id_acquire();
	if (id < 0) {
		dev_err(ops->parent, "Out of NFP CPP API slots.\n");
		return ERR_PTR(id);
	}

	cpp = kzalloc(sizeof(*cpp), GFP_KERNEL);
	cpp->id = id;
	cpp->op = ops;
	kref_init(&cpp->kref);
	rwlock_init(&cpp->resource_lock);
	init_waitqueue_head(&cpp->waitq);
#ifdef CONFIG_LOCKDEP
	lockdep_set_class(&cpp->resource_lock, &nfp_cpp_resource_lock_key);
#endif
	INIT_LIST_HEAD(&cpp->resource_list);
	cpp->dev.init_name = "cpp";
	cpp->dev.parent = ops->parent;
	cpp->dev.release = nfp_cpp_dev_release;
	err = device_register(&cpp->dev);
	if (err < 0) {
		kfree(cpp);
		return ERR_PTR(err);
	}

	dev_set_drvdata(&cpp->dev, cpp);

	if (cpp->op->model)
		cpp->model = cpp->op->model;

	/* NOTE: cpp_lock is NOT locked for op->init,
	 * since it may call NFP CPP API operations
	 */
	if (cpp->op->init) {
		err = cpp->op->init(cpp);
		if (err < 0) {
			dev_err(ops->parent, "NFP interface initialization failed\n");
			device_unregister(&cpp->dev);
			kfree(cpp);
			return ERR_PTR(err);
		}
	}

	/* If cpp->op->model == 0, then autodetection is requested */
	if (cpp->op->model == 0) {
		err = __nfp_cpp_model_autodetect(cpp, &cpp->model);
		if (err < 0) {
			dev_err(ops->parent, "NFP model detection failed\n");
			device_unregister(&cpp->dev);
			kfree(cpp);
			return ERR_PTR(err);
		}
	}

#ifdef CONFIG_PROC_FS
	pde = proc_create_data(dev_name(cpp->op->parent), 0, nfp_cpp_dir,
			       &iocpp_ops, cpp);
	if (pde == NULL) {
		dev_err(cpp->op->parent,
			"Can't create /proc/" NFP_CPP_DIR_NAME "/%s\n",
			dev_name(cpp->op->parent));
	}
#endif

	/* After initialization, do any model specific fixups */
	err = __nfp_cpp_model_fixup(cpp);
	if (err < 0) {
		dev_err(ops->parent, "NFP model fixup failed\n");
		nfp_cpp_free(cpp);
		return ERR_PTR(err);
	}

	write_lock(&nfp_cpp_list_lock);
	list_add_tail(&cpp->list, &nfp_cpp_list);
	write_unlock(&nfp_cpp_list_lock);

	dev_info(cpp->op->parent, "Model: 0x%08x, Interface: 0x%04x\n",
		 nfp_cpp_model(cpp), nfp_cpp_interface(cpp));

	return cpp;
}
EXPORT_SYMBOL(nfp_cpp_from_operations);

struct device *nfp_cpp_device(struct nfp_cpp *cpp)
{
	return &cpp->dev;
}
EXPORT_SYMBOL(nfp_cpp_device);

void *nfp_cpp_priv(struct nfp_cpp *cpp)
{
	return cpp->op->priv;
}
EXPORT_SYMBOL(nfp_cpp_priv);

int nfp_cppcore_init(void)
{
	pr_info("Netronome NFP CPP API\n");

	mutex_init(&nfp_cpp_id_lock);
	INIT_LIST_HEAD(&nfp_cpp_list);
	rwlock_init(&nfp_cpp_list_lock);

#ifdef CONFIG_PROC_FS
	nfp_cpp_dir = proc_mkdir(NFP_CPP_DIR_NAME, NULL);

	if (nfp_cpp_dir == NULL)
		return -ENOMEM;
#endif

	return 0;
}

void nfp_cppcore_exit(void)
{
	BUG_ON(!list_empty(&nfp_cpp_list));
#ifdef CONFIG_PROC_FS
	remove_proc_entry(NFP_CPP_DIR_NAME, NULL);
#endif
}

/*
 * Local variables:
 * c-file-style: "Linux"
 * indent-tabs-mode: t
 * End:
 */
