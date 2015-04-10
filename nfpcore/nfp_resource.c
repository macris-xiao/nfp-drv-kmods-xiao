/* Copyright (C) 2014-2015 Netronome Systems, Inc. All rights reserved.
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

#define NFP6000_LONGNAMES 1

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/slab.h>
#include <linux/sched.h>
#include <linux/delay.h>

#include "nfp_cpp_kernel.h"

#include "nfp.h"

#include "nfp-bsp/nfp_resource.h"
#include "nfp3200/nfp3200.h"

#include "crc32.h"
#include "nfp_resource.h"

#define NFP_XPB_OVERLAY(island)  (((island) & 0x3f) << 24)
#define NFP_XPB_ISLAND(island)   (NFP_XPB_OVERLAY(island) + 0x60000)

struct nfp_resource {
	char name[NFP_RESOURCE_ENTRY_NAME_SZ + 1];
	uint32_t cpp_id;
	uint64_t addr;
	uint64_t size;
	struct nfp_cpp_mutex *mutex;
};

/* If the EMU is not enabled, we probably don't
 * have any resources anyway.
 */
static int __nfp_resource_location(struct nfp_cpp *cpp, int *target,
				   uint64_t *base, size_t *sizep)
{
	uint32_t model = nfp_cpp_model(cpp);
	size_t size;

	*target = NFP_CPP_TARGET_MU;
	size   = 4096;

	if (NFP_CPP_MODEL_IS_3200(model))
		*base = 0;
	else if (NFP_CPP_MODEL_IS_6000(model))
		*base = 0x8100000000ULL;
	else
		return -EINVAL;

	if (sizep)
		*sizep = size;

	return size / sizeof(struct nfp_resource_entry);
}

static int __nfp_resource_entry_init(struct nfp_cpp *cpp,
			      int entry,
			      const struct nfp_resource_entry_region *region,
			      struct nfp_cpp_mutex **resource_mutex)
{
	uint32_t cpp_id;
	struct nfp_cpp_mutex *mutex;
	uint32_t key;
	int err;
	int target, entries;
	uint64_t base;
	size_t size;

	entries = __nfp_resource_location(cpp, &target, &base, &size);
	if (entries < 0)
		return entries;

	if (entry >= entries)
		return -EINVAL;

	base += sizeof(struct nfp_resource_entry) * entry;

	if (entry == 0)
		key = NFP_RESOURCE_TABLE_KEY;
	else
		key = crc32_posix(region->name, 8);

	err = nfp_cpp_mutex_init(cpp, target, base, key);
	if (err < 0)
		return err;

	/* We already own the initialized lock */
	mutex = nfp_cpp_mutex_alloc(cpp, target, base, key);
	if (mutex == NULL)
		return -ENOMEM;

	/* Mutex Owner and Key are already set */
	cpp_id = NFP_CPP_ID(target, 4, 0);  /* Atomic write */

	err = nfp_cpp_write(cpp, cpp_id, base +
			offsetof(struct nfp_resource_entry, region),
			region, sizeof(*region));
	if (err < 0) {
		/* Try to unlock in the face of adversity */
		nfp_cpp_mutex_unlock(mutex);
		nfp_cpp_mutex_free(mutex);
		return err;
	}

	if (resource_mutex) {
		*resource_mutex = mutex;
	} else {
		nfp_cpp_mutex_unlock(mutex);
		nfp_cpp_mutex_free(mutex);
	}

	return 0;
}

/**
 * nfp_cpp_resource_init() - Construct a new NFP Resource table
 * @cpp:		NFP CPP handle
 * @mutexp:		Location to place the resource table's mutex
 *
 * NOTE: If mutexp is NULL, the mutex of the resource table is
 * implictly unlocked.
 *
 * Return: 0, or -ERRNO
 */
int nfp_cpp_resource_init(struct nfp_cpp *cpp, struct nfp_cpp_mutex **mutexp)
{
	uint32_t cpp_id;
	struct nfp_cpp_mutex *mutex;
	int err;
	int target, i, entries;
	uint64_t base;
	size_t size;
	struct nfp_resource_entry_region region = {
		.name = { NFP_RESOURCE_TABLE_NAME },
		.cpp_action = NFP_CPP_ACTION_RW,
		.cpp_token  = 1
	};

	entries = __nfp_resource_location(cpp, &target, &base, &size);
	if (entries < 0)
		return entries;

	region.cpp_target = target;
	region.page_offset = base >> 8;
	region.page_size   = size >> 8;

	cpp_id = NFP_CPP_ID(target, 4, 0);  /* Atomic write */

	err = __nfp_resource_entry_init(cpp, 0, &region, &mutex);
	if (err < 0)
		return err;

	entries = size / sizeof(struct nfp_resource_entry);

	/* We have a lock, initialize entires after 0.*/
	for (i = sizeof(struct nfp_resource_entry); i < size; i += 4)
		err = nfp_cpp_writel(cpp, cpp_id, base + i, 0);
		if (err < 0)
			return err;

	if (mutexp) {
		*mutexp = mutex;
	} else {
		nfp_cpp_mutex_unlock(mutex);
		nfp_cpp_mutex_free(mutex);
	}

	return 0;
}

/**
 * nfp_cpp_resource_add() - Construct a new NFP Resource entry
 * @cpp:		NFP CPP handle
 * @name:		Name of the resource
 * @cpp_id:		NFP CPP ID of the resource
 * @address:		NFP CPP address of the resource
 * @size:		Size, in bytes, of the resource area
 * @resource_mutex:	Location to place the resource's mutex
 *
 * NOTE: If resource_mutex is NULL, the mutex of the resource is
 * implictly unlocked.
 *
 * Return: 0, or -ERRNO
 */
int nfp_cpp_resource_add(struct nfp_cpp *cpp, const char *name,
			 uint32_t cpp_id, uint64_t address, uint64_t size,
		struct nfp_cpp_mutex **resource_mutex)
{
	int target, err, i, entries, minfree;
	uint64_t base;
	uint32_t key;
	struct nfp_resource_entry_region region = {
		.cpp_action = NFP_CPP_ID_ACTION_of(cpp_id),
		.cpp_token  = NFP_CPP_ID_TOKEN_of(cpp_id),
		.cpp_target = NFP_CPP_ID_TARGET_of(cpp_id),
		.page_offset = (uint32_t)(address >> 8),
		.page_size  = (uint32_t)(size >> 8),
	};
	struct nfp_cpp_mutex *mutex;
	uint32_t tmp;

	for (i = 0; i < sizeof(region.name); i++) {
		if (*name != 0)
			region.name[i] = *(name++);
		else
			region.name[i] = 0;
	}

	entries = __nfp_resource_location(cpp, &target, &base, NULL);
	if (entries < 0)
		return entries;

	cpp_id = NFP_CPP_ID(target, 3, 0);  /* Atomic read */

	key = NFP_RESOURCE_TABLE_KEY;
	mutex = nfp_cpp_mutex_alloc(cpp, target, base, key);
	if (mutex == NULL)
		return -ENOMEM;

	/* Wait for the lock.. */
	err = nfp_cpp_mutex_lock(mutex);
	if (err < 0) {
		nfp_cpp_mutex_free(mutex);
		return err;
	}

	/* Search for a free entry, or a duplicate */
	minfree = 0;
	key = crc32_posix(name, 8);
	for (i = 1; i < entries; i++) {
		uint64_t addr = base + sizeof(struct nfp_resource_entry) * i;

		err = nfp_cpp_readl(cpp, cpp_id, addr +
				offsetof(struct nfp_resource_entry, mutex.key),
				&tmp);
		if (err < 0) {
			/* Unlikely to work if the read failed,
			 * but we should at least try... */
			nfp_cpp_mutex_unlock(mutex);
			nfp_cpp_mutex_free(mutex);
			return err;
		}

		if (tmp == key) {
			/* Duplicate key! */
			nfp_cpp_mutex_unlock(mutex);
			nfp_cpp_mutex_free(mutex);
			return -EEXIST;
		}

		if (tmp == 0 && minfree == 0)
			minfree = i;
	}

	/* No available space in the table! */
	if (minfree == 0)
		return -ENOSPC;

	err = __nfp_resource_entry_init(cpp, minfree, &region, resource_mutex);
	nfp_cpp_mutex_unlock(mutex);
	nfp_cpp_mutex_free(mutex);

	return err;
}

static int nfp_cpp_resource_acquire(struct nfp_cpp *cpp,
				    const char *name,
				    uint32_t *r_cpp,
				    uint64_t *r_addr,
				    uint64_t *r_size,
				    struct nfp_cpp_mutex **resource_mutex)
{
	int target, err, i, entries;
	uint64_t base;
	uint32_t key;
	struct nfp_resource_entry_region region;
	struct nfp_resource_entry tmp;
	struct nfp_cpp_mutex *mutex;
	uint32_t cpp_id;

	for (i = 0; i < sizeof(region.name); i++) {
		if (*name != 0)
			region.name[i] = *(name++);
		else
			region.name[i] = 0;
	}

	entries = __nfp_resource_location(cpp, &target, &base, NULL);
	if (entries < 0)
		return entries;

	cpp_id = NFP_CPP_ID(target, 3, 0);  /* Atomic read */

	key = NFP_RESOURCE_TABLE_KEY;
	mutex = nfp_cpp_mutex_alloc(cpp, target, base, key);
	if (mutex == NULL)
		return -ENOMEM;

	/* Wait for the lock.. */
	err = nfp_cpp_mutex_lock(mutex);
	if (err < 0) {
		nfp_cpp_mutex_free(mutex);
		return err;
	}

	/* Search for a matching entry */
	if (memcmp(region.name,
		   NFP_RESOURCE_TABLE_NAME "\0\0\0\0\0\0\0\0", 8) != 0)
		key = crc32_posix(&region.name[0], sizeof(region.name));
	for (i = 0; i < entries; i++) {
		uint64_t addr = base + sizeof(struct nfp_resource_entry) * i;

		err = nfp_cpp_read(cpp, cpp_id, addr, &tmp, sizeof(tmp));
		if (err < 0) {
			/* Unlikely to work if the read failed,
			 * but we should at least try... */
			nfp_cpp_mutex_unlock(mutex);
			nfp_cpp_mutex_free(mutex);
			return err;
		}

		if (tmp.mutex.key == key) {
			/* Found key! */
			if (resource_mutex)
				*resource_mutex = nfp_cpp_mutex_alloc(cpp,
							target, addr, key);

			if (r_cpp)
				*r_cpp = NFP_CPP_ID(tmp.region.cpp_target,
						tmp.region.cpp_action,
						tmp.region.cpp_token);

			if (r_addr)
				*r_addr = (uint64_t)tmp.region.page_offset << 8;

			if (r_size)
				*r_size = (uint64_t)tmp.region.page_size << 8;

			nfp_cpp_mutex_unlock(mutex);
			nfp_cpp_mutex_free(mutex);

			return 0;
		}
	}

	nfp_cpp_mutex_unlock(mutex);
	nfp_cpp_mutex_free(mutex);

	return -ENOENT;
}

/**
 * nfp_resource_acquire() - Acquire a resource handle
 * @nfp:		NFP Device handle
 * @name:		Name of the resource
 *
 * NOTE: This function implictly locks the acquired resource
 *
 * Return: NFP Resource handle, or NULL
 */
struct nfp_resource *nfp_resource_acquire(struct nfp_device *nfp,
					  const char *name)
{
	struct nfp_resource *res;
	struct nfp_cpp_mutex *mutex;
	struct nfp_cpp *cpp = nfp_device_cpp(nfp);
	int err;
	uint32_t cpp_id;
	uint64_t addr, size;

	err = nfp_cpp_resource_acquire(cpp, name, &cpp_id, &addr,
				       &size, &mutex);
	if (err < 0)
		return NULL;

	err = nfp_cpp_mutex_lock(mutex);
	if (err < 0) {
		nfp_cpp_mutex_free(mutex);
		return NULL;
	}

	res = kzalloc(sizeof(*res), GFP_KERNEL);
	if (res == NULL) {
		nfp_cpp_mutex_free(mutex);
		return NULL;
	}

	strncpy(res->name, name, NFP_RESOURCE_ENTRY_NAME_SZ);
	res->cpp_id = cpp_id;
	res->addr = addr;
	res->size = size;
	res->mutex = mutex;

	return res;
}

/**
 * nfp_resource_release() - Release a NFP Resource handle
 * @res:	NFP Resource handle
 *
 * NOTE: This function implictly unlocks the resource handle
 */
void nfp_resource_release(struct nfp_resource *res)
{
	nfp_cpp_mutex_unlock(res->mutex);
	nfp_cpp_mutex_free(res->mutex);
	kfree(res);
}

/**
 * nfp_resource_cpp_id() - Return the cpp_id of a resource handle
 * @res:	NFP Resource handle
 *
 * Return: NFP CPP ID
 */
uint32_t nfp_resource_cpp_id(struct nfp_resource *res)
{
	return res->cpp_id;
}

/**
 * nfp_resource_name() - Return the name of a resource handle
 * @res:	NFP Resource handle
 *
 * Return: const char pointer to the name of the resource
 */
const char *nfp_resource_name(struct nfp_resource *res)
{
	return res->name;
}

/**
 * nfp_resource_address() - Return the address of a resource handle
 * @res:	NFP Resource handle
 *
 * Return: Address of the resource
 */
uint64_t nfp_resource_address(struct nfp_resource *res)
{
	return res->addr;
}

/**
 * nfp_resource_size() - Return the size in bytes of a resource handle
 * @res:	NFP Resource handle
 *
 * Return: Size of the resource in bytes
 */
uint64_t nfp_resource_size(struct nfp_resource *res)
{
	return res->size;
}
