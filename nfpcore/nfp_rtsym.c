/*
 * Copyright (C) 2012 Netronome Systems, Inc. All rights reserved.
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
 */

#include <linux/kernel.h>
#include <linux/kref.h>
#include <linux/slab.h>

#include "nfp_common.h"
#include "nfp_device.h"

#include "nfp3200/nfp3200.h"

/*
 * The layout of a symtab entry in NFP memory (little endian).
 */
struct nfp_mip_rtsym {
	u8	type;
	u8	target;
	u8	domain;
	u8	addr_hi;
	u32	addr_lo;
	u16	name;
	u8	__rsvd;
	u8	size_hi;
	u32	size_lo;
};

struct nfp_rtsymtab {
	struct kref kref;

	struct nfp_device *nfp;
	const struct nfp_mip *mip;
	struct nfp_rtsym *syms;
	size_t symcnt;
	char *strtab;
};

/*
 * Convenience function for reading from DRAM
 */
#define AREA_ALLOC_BOUNDARY	(1 << 24)
static int nfp_rtsym_read(struct nfp_device *nfp,
			  off_t offset, size_t size, void *dst)
{
	struct nfp_cpp_area *area;
	off_t moff, cur_offset = offset;
	size_t cur_size, remaining = size;
	int retval, err = 0;

	/* XXX: Allow unaligned offsets and/or sizes. */
	if (offset & 0x3 || size & 0x3)
		return -EINVAL;

	/*
	 * CPP areas can typically not span certain boundaries
	 * depending on which BAR type is used to map them.  Split the
	 * memory region into multiple CPP areas so that we can access
	 * the whole region.
	 */
	while (remaining > 0) {
		moff = cur_offset & (AREA_ALLOC_BOUNDARY - 1);
		if ((moff + remaining) > AREA_ALLOC_BOUNDARY)
			cur_size = AREA_ALLOC_BOUNDARY - moff;
		else
			cur_size = remaining;

		area = nfp_cpp_area_alloc_with_name(
			nfp->cpp, NFP_CPP_ID(NFP_CPP_TARGET_DDR,
					     NFP_CPP_ACTION_RW, 1),
			"nfp.rtsym",
			cur_offset, cur_size);
		if (!area)
			return -EIO;

		retval = nfp_cpp_area_acquire(area);
		if (retval < 0) {
			nfp_cpp_area_free(area);
			return retval;
		}

		retval = nfp_cpp_area_read(area, 0, dst, cur_size);

		nfp_cpp_area_release(area);
		nfp_cpp_area_free(area);
		if (retval < 0) {
			err = retval;
			break;
		}

		remaining -= cur_size;
		cur_offset += cur_size;
		dst += cur_size;
	}

	return err;
}

static void __release_rtsymtab(struct kref *kref)
{
	struct nfp_rtsymtab *symtab =
		container_of(kref, struct nfp_rtsymtab, kref);

	symtab->nfp->rtsymtab = NULL;

	nfp_mip_release(symtab->mip);
	kfree(symtab->syms);
	kfree(symtab->strtab);
	kfree(symtab);
}

static void nfp_rtsym_put(struct nfp_rtsymtab *symtab)
{
	kref_put(&symtab->kref, __release_rtsymtab);
}

static struct nfp_rtsymtab *nfp_rtsym_get(struct nfp_rtsymtab *symtab)
{
	kref_get(&symtab->kref);
	return symtab;
}

/*
 * Probes the on board MIP to see if there is a run-time symbol table.
 * If so, read in the table and translate it to a valid host
 * representation of the symtab.
 */
static const struct nfp_rtsymtab *nfp_rtsym_acquire(struct nfp_device *nfp)
{
	struct nfp_mip_rtsym *nfpsymtab;
	struct nfp_rtsymtab *symtab;
	const struct nfp_mip *mip;
	u32 symtab_addr, symtab_size, strtab_addr, strtab_size;
	unsigned long flags;
	int err, n;

	spin_lock_irqsave(&nfp->rtsymtab_lock, flags);
	if (nfp->rtsymtab) {
		nfp_rtsym_get(nfp->rtsymtab);
		spin_unlock_irqrestore(&nfp->rtsymtab_lock, flags);
		return nfp->rtsymtab;
	}
	spin_unlock_irqrestore(&nfp->rtsymtab_lock, flags);

	mip = nfp_mip_acquire(nfp);
	if (!mip)
		return NULL;

	symtab_addr = nfp_readl(&mip->symtab_addr);
	symtab_size = nfp_readl(&mip->symtab_size);
	strtab_addr = nfp_readl(&mip->strtab_addr);
	strtab_size = nfp_readl(&mip->strtab_size);

	/* Round up the size to multiples of 64b */
	symtab_size = (symtab_size + 7) & ~7;
	strtab_size = (strtab_size + 7) & ~7;

	if (symtab_size == 0 || strtab_size == 0 ||
	    (symtab_size % sizeof(struct nfp_mip_rtsym)) != 0) {
		nfp_mip_release(mip);
		return NULL;
	}

	nfpsymtab = kmalloc(symtab_size, GFP_KERNEL);
	if (!nfpsymtab) {
		nfp_mip_release(mip);
		return NULL;
	}

	symtab = kzalloc(sizeof(*symtab), GFP_KERNEL);
	if (!symtab)
		goto err_symtab;

	symtab->symcnt = symtab_size / sizeof(struct nfp_mip_rtsym);
	symtab->syms = kmalloc_array(symtab->symcnt, sizeof(struct nfp_rtsym),
			       GFP_KERNEL);
	if (!symtab->syms)
		goto err_syms;

	symtab->strtab = kmalloc(strtab_size + 1, GFP_KERNEL);
	if (!symtab->strtab)
		goto err_strtab;

	err = nfp_rtsym_read(nfp, symtab_addr, symtab_size, nfpsymtab);
	if (err)
		goto err_read_symtab;

	err = nfp_rtsym_read(nfp, strtab_addr, strtab_size, symtab->strtab);
	if (err)
		goto err_read_strtab;
	symtab->strtab[strtab_size] = '\0';

	nfp_swizzle_words(nfpsymtab, symtab_size);

	for (n = 0; n < symtab->symcnt; n++) {
		symtab->syms[n].type = nfpsymtab[n].type;
		symtab->syms[n].name = symtab->strtab +
			(nfpsymtab[n].name % strtab_size);
		symtab->syms[n].addr = (((uint64_t)nfpsymtab[n].addr_hi) << 32)
			+ nfpsymtab[n].addr_lo;
		symtab->syms[n].size = (((uint64_t)nfpsymtab[n].size_hi) << 32)
			+ nfpsymtab[n].size_lo;
		symtab->syms[n].domain = nfpsymtab[n].domain;
		symtab->syms[n].target = nfpsymtab[n].target;
	}

	kfree(nfpsymtab);

	/*
	 * Create an initial reference to the new symtab so that we
	 * can reuse it until mefw image changes.
	 */
	kref_init(&symtab->kref);
	nfp_rtsym_get(symtab);

	/* If a symtab already is present, release it and install new one */
	symtab->nfp = NULL;
	spin_lock_irqsave(&nfp->rtsymtab_lock, flags);
	if (nfp->rtsymtab) {
		nfp_rtsym_put(symtab);
		symtab = nfp->rtsymtab;
	} else {
		nfp->rtsymtab = symtab;
		symtab->nfp = nfp;
	}
	spin_unlock_irqrestore(&nfp->rtsymtab_lock, flags);

	return symtab;

err_read_strtab:
err_read_symtab:
	kfree(symtab->strtab);
err_strtab:
	kfree(symtab->syms);
err_syms:
	kfree(symtab);
err_symtab:
	kfree(nfpsymtab);
	nfp_mip_release(mip);
	return NULL;
}

static void nfp_rtsym_release(struct nfp_device *nfp)
{
	unsigned long flags;

	spin_lock_irqsave(&nfp->rtsymtab_lock, flags);
	if (nfp->rtsymtab) {
		nfp_rtsym_put(nfp->rtsymtab);
		nfp->rtsymtab = NULL;
	}
	spin_unlock_irqrestore(&nfp->rtsymtab_lock, flags);
}

void nfp_rtsym_reload(struct nfp_device *nfp)
{
	nfp_rtsym_release(nfp);
}

size_t nfp_rtsym_count(struct nfp_device *nfp)
{
	size_t count;
	const struct nfp_rtsymtab *symtab;

	symtab = nfp_rtsym_acquire(nfp);
	if (symtab) {
		count = symtab->symcnt;
		nfp_rtsym_release(nfp);
		return count;
	}

	return 0;
}
EXPORT_SYMBOL(nfp_rtsym_count);

const struct nfp_rtsym *nfp_rtsym_entry(struct nfp_device *nfp,
					size_t idx)
{
	const struct nfp_rtsymtab *symtab;
	const struct nfp_rtsym *sym = NULL;

	symtab = nfp_rtsym_acquire(nfp);
	if (symtab) {
		if (idx < symtab->symcnt)
			sym = &symtab->syms[idx];

		nfp_rtsym_release(nfp);
	}

	return sym;
}
EXPORT_SYMBOL(nfp_rtsym_entry);

const struct nfp_rtsym *nfp_rtsym_lookup(struct nfp_device *nfp,
					 const char *name)
{
	int n;
	const struct nfp_rtsymtab *symtab;
	const struct nfp_rtsym *sym = NULL;

	symtab = nfp_rtsym_acquire(nfp);
	if (symtab) {
		for (n = 0; n < symtab->symcnt; n++) {
			if (strcmp(name, symtab->syms[n].name) == 0) {
				sym = &symtab->syms[n];
				break;
			}
		}

		nfp_rtsym_release(nfp);
	}

	return sym;
}
EXPORT_SYMBOL(nfp_rtsym_lookup);

int nfp_rtsymtab_init(struct nfp_device *nfp)
{
	spin_lock_init(&nfp->rtsymtab_lock);
	nfp->rtsymtab = NULL;
	return 0;
}

void nfp_rtsymtab_cleanup(struct nfp_device *nfp)
{
	nfp_rtsym_release(nfp);
	BUG_ON(nfp->rtsymtab != NULL);
}

/*
 * Local variables:
 * c-file-style: "Linux"
 * indent-tabs-mode: t
 * End:
 */
