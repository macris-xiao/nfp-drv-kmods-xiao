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
 * Code for handling Microcode Information Page (MIP).
 *
 */

#include <linux/kernel.h>
#include <linux/kref.h>
#include <linux/slab.h>
#include <linux/ctype.h>

#include "nfp.h"
#include "nfp-bsp/nfp_resource.h"

#include "nfp_common.h"
#include "nfp_mip.h"
#include "nfp_resource.h"
#include "nfp_device.h"

#undef NFP_SUBSYS
#define NFP_SUBSYS "[MIP] "

struct nfp_miptab {
	struct kref kref;

	struct nfp_resource *res;
	struct nfp_device *nfp;

	struct nfp_mip mip;	/* MUST BE THE LAST ENTRY */
	/*... expanded to actual mip size ...*/
};

static void __release_miptab(struct kref *kref)
{
	unsigned long flags;

	struct nfp_miptab *miptab =
		container_of(kref, struct nfp_miptab, kref);

	spin_lock_irqsave(&miptab->nfp->miptab_lock, flags);
	miptab->nfp->miptab = NULL;
	spin_unlock_irqrestore(&miptab->nfp->miptab_lock, flags);

	nfp_resource_release(miptab->res);
	kfree(miptab);
}

static void nfp_miptab_put(struct nfp_miptab *miptab)
{
	kref_put(&miptab->kref, __release_miptab);
}

static struct nfp_miptab *nfp_miptab_get(struct nfp_miptab *miptab)
{
	kref_get(&miptab->kref);
	return miptab;
}

/**
 * nfp_mip_find_entry - Find an entry in a MIP
 * @mip:	MIP handle
 * @entry_type:	MIP entry type
 */
const void *nfp_mip_find_entry(const struct nfp_mip *mip, u32 entry_type)
{
	int mip_size;
	struct nfp_mip_entry mipent;
	u32 offset;

	mip_size = nfp_readl(&mip->mip_size);
	offset = nfp_readl(&mip->first_entry);

	while (offset < mip_size) {
		nfp_read(((void *)mip) + offset, &mipent, sizeof(mipent));

		if (mipent.type == entry_type)
			return ((void *)mip) + offset;
		else if (le32_to_cpu(mipent.type) == NFP_MIP_TYPE_NONE)
			break;

		offset += le32_to_cpu(mipent.offset_next);
	}

	return NULL;
}
EXPORT_SYMBOL(nfp_mip_find_entry);

/**
 * nfp_mip_acquire - Acquire a handle to the MIP
 * @nfp:	NFP device
 */
const struct nfp_mip *nfp_mip_acquire(struct nfp_device *nfp)
{
	struct nfp_resource *res;
	struct nfp_mip tmp;
	uint32_t mip_size;
	struct nfp_miptab *miptab;
	int err;
	unsigned long flags;

	spin_lock_irqsave(&nfp->miptab_lock, flags);
	if (nfp->miptab) {
		nfp_miptab_get(nfp->miptab);
		spin_unlock_irqrestore(&nfp->miptab_lock, flags);
		return &nfp->miptab->mip;
	}
	spin_unlock_irqrestore(&nfp->miptab_lock, flags);

	res = nfp_resource_acquire(nfp, NFP_RESOURCE_NFP_NFFW);
	if (!res)
		return NULL;

	err = nfp_cpp_read(nfp_device_cpp(nfp),
			   nfp_resource_cpp_id(res),
			   nfp_resource_address(res),
			   &tmp, sizeof(tmp));
	if (err < 0) {
		nfp_resource_release(res);
		return NULL;
	}

	if ((le32_to_cpu(tmp.signature) != NFP_MIP_SIGNATURE) ||
	    (le32_to_cpu(tmp.mip_version) != NFP_MIP_VERSION) ||
	    (le32_to_cpu(tmp.mip_size) < sizeof(tmp))) {
		nfp_resource_release(res);
		return NULL;
	}

	mip_size = le32_to_cpu(tmp.mip_size);

	/* Round up the size to multiples of 64b */
	mip_size = (mip_size + 7) & ~7;

	miptab = kmalloc(sizeof(*miptab) + (mip_size - sizeof(tmp)),
			 GFP_KERNEL);
	if (!miptab) {
		nfp_resource_release(res);
		return NULL;
	}

	err = nfp_cpp_read(nfp_device_cpp(nfp),
			   nfp_resource_cpp_id(res),
			   nfp_resource_address(res),
			   &miptab->mip, mip_size);
	if (err < 0) {
		kfree(miptab);
		nfp_resource_release(res);
		return NULL;
	}

	kref_init(&miptab->kref);
	nfp_miptab_get(miptab);
	miptab->res = res;
	miptab->nfp = NULL;

	spin_lock_irqsave(&nfp->miptab_lock, flags);
	if (nfp->miptab) {
		nfp_miptab_put(miptab);
		miptab = nfp->miptab;
	} else {
		nfp->miptab = miptab;
		miptab->nfp = nfp;
	}
	spin_unlock_irqrestore(&nfp->miptab_lock, flags);

	return &miptab->mip;
}
EXPORT_SYMBOL(nfp_mip_acquire);

/**
 * nfp_mip_release - Release a handle to the MIP
 * @mip:	MIP handle
 */
void nfp_mip_release(const struct nfp_mip *mip)
{
	struct nfp_miptab *miptab = container_of(mip, struct nfp_miptab, mip);

	nfp_miptab_put(miptab);
}
EXPORT_SYMBOL(nfp_mip_release);

int nfp_miptab_init(struct nfp_device *nfp)
{
	spin_lock_init(&nfp->miptab_lock);
	nfp->miptab = NULL;
	return 0;
}

void nfp_miptab_cleanup(struct nfp_device *nfp)
{
	BUG_ON(nfp->miptab != NULL);
}

/*
 * Local variables:
 * c-file-style: "Linux"
 * indent-tabs-mode: t
 * End:
 */
