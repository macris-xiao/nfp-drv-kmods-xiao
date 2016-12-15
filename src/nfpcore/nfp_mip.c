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
 * nfp_mip.c
 * Authors: Jakub Kicinski <jakub.kicinski@netronome.com>
 *          Jason McMullan <jason.mcmullan@netronome.com>
 *          Espen Skoglund <espen.skoglund@netronome.com>
 */
#include <linux/kernel.h>

#include "nfp.h"
#include "nfp_cpp.h"
#include "nfp_nffw.h"
#include "nfp_target.h"

#define NFP_MIP_SIGNATURE	cpu_to_le32(0x0050494d)  /* "MIP\0" */
#define NFP_MIP_VERSION		cpu_to_le32(1)
#define NFP_MIP_MAX_OFFSET	(256 * 1024)

struct nfp_mip {
	__le32 signature;
	__le32 mip_version;
	__le32 mip_size;
	__le32 first_entry;

	__le32 version;
	__le32 buildnum;
	__le32 buildtime;
	__le32 loadtime;

	__le32 symtab_addr;
	__le32 symtab_size;
	__le32 strtab_addr;
	__le32 strtab_size;

	char name[16];
	char toolchain[32];
};

#define NFP_IMB_TGTADDRESSMODECFG_MODE_of(_x)		(((_x) >> 13) & 0x7)
#define NFP_IMB_TGTADDRESSMODECFG_ADDRMODE		BIT(12)
#define   NFP_IMB_TGTADDRESSMODECFG_ADDRMODE_32_BIT	0
#define   NFP_IMB_TGTADDRESSMODECFG_ADDRMODE_40_BIT	BIT(12)

static int nfp_mip_nfp6000_mu_locality_lsb(struct nfp_cpp *cpp)
{
	unsigned int mode, addr40;
	u32 xpbaddr, imbcppat;
	int err;

	/* Hardcoded XPB IMB Base, island 0 */
	xpbaddr = 0x000a0000 + NFP_CPP_TARGET_MU * 4;
	err = nfp_xpb_readl(cpp, xpbaddr, &imbcppat);
	if (err < 0)
		return err;

	mode = NFP_IMB_TGTADDRESSMODECFG_MODE_of(imbcppat);
	addr40 = !!(imbcppat & NFP_IMB_TGTADDRESSMODECFG_ADDRMODE);

	return _nfp6000_cppat_mu_locality_lsb(mode, addr40);
}

/* Read memory and check if it could be a valid MIP */
static int
nfp_mip_try_read(struct nfp_cpp *cpp, u32 cpp_id, u64 addr, struct nfp_mip *mip)
{
	int ret;

	ret = nfp_cpp_read(cpp, cpp_id, addr, mip, sizeof(*mip));
	if (ret != sizeof(*mip))
		return -EIO;
	if (mip->signature != NFP_MIP_SIGNATURE ||
	    mip->mip_version != NFP_MIP_VERSION)
		return -EINVAL;

	return 0;
}

/* Try to locate MIP using the resource table */
static int nfp_mip_read_resource(struct nfp_cpp *cpp, struct nfp_mip *mip)
{
	struct nfp_nffw_info *nffw_info;
	int mu_lsb, err;
	u32 cpp_id;
	u64 addr;

	nffw_info = nfp_nffw_info_open(cpp);
	if (IS_ERR(nffw_info))
		return PTR_ERR(nffw_info);

	err = nfp_mip_nfp6000_mu_locality_lsb(cpp);
	if (err < 0)
		goto exit_close_nffw;
	mu_lsb = err;

	err = nfp_nffw_info_mip_first(nffw_info, &cpp_id, &addr);
	if (err)
		goto exit_close_nffw;

	if (cpp_id &&
	    NFP_CPP_ID_TARGET_of(cpp_id) == NFP_CPP_TARGET_MU &&
	    addr & BIT_ULL(63)) {
		addr &= ~BIT_ULL(63);
		/* Direct Access */
		addr &= ~(3ULL << mu_lsb);
		addr |= 2ULL << mu_lsb;
	}

	err = nfp_mip_try_read(cpp, cpp_id, addr, mip);
exit_close_nffw:
	nfp_nffw_info_close(nffw_info);
	return err;
}

/* Try to locate MIP by scanning memory for the signature */
static int nfp_mip_read_mem_scan(struct nfp_cpp *cpp, struct nfp_mip *mip)
{
	u32 cpp_id;
	u64 addr;
	int err;

	cpp_id = NFP_CPP_ID(NFP_CPP_TARGET_MU, NFP_CPP_ACTION_RW, 0) |
		NFP_ISL_EMEM0;

	for (addr = 0; addr < NFP_MIP_MAX_OFFSET; addr += 4096) {
		err = nfp_mip_try_read(cpp, cpp_id, addr, mip);
		if (!err)
			return 0;
	}

	return err;
}

/**
 * nfp_mip_probe() - Check if MIP has been updated.
 * @cpp:	NFP CPP Handle
 *
 * Check if currently cached MIP needs to be updated, and read potential
 * new contents.  If a call to nfp_mip_probe() returns non-zero, the old
 * MIP structure returned by a previous callto nfp_mip() is no longer
 * guaranteed to be present and any references to the old structure is invalid.
 *
 * Return: 1 if MIP has been updated, 0 if no update has occurred, or -ERRNO
 */
static int nfp_mip_probe(struct nfp_cpp *cpp)
{
	struct nfp_mip *new_mip, *old_mip;
	int err;

	new_mip = kmalloc(sizeof(*new_mip), GFP_KERNEL);
	if (!new_mip)
		return -ENOMEM;

	err = nfp_mip_read_resource(cpp, new_mip);
	if (err) {
		nfp_dbg(cpp, "Couldn't locate MIP using resource table, trying memory scan\n");
		err = nfp_mip_read_mem_scan(cpp, new_mip);
	}
	if (err) {
		kfree(new_mip);
		return err;
	}

	old_mip = nfp_mip_cache(cpp);
	if (old_mip && old_mip->loadtime == new_mip->loadtime) {
		kfree(new_mip);
		return 0;
	}

	kfree(old_mip);
	nfp_mip_cache_set(cpp, new_mip);
	return 1;
}

/**
 * nfp_mip() - Get device MIP structure
 * @cpp:	NFP CPP Handle
 *
 * Copy MIP structure from NFP device and return it.  The returned
 * structure is handled internally by the library and should not be
 * explicitly freed by the caller. Any subsequent call to nfp_mip_probe()
 * returning non-zero renders references to any previously returned MIP
 * structure invalid.
 *
 * Return: pointer to mip, NULL on failure.
 */
const struct nfp_mip *nfp_mip(struct nfp_cpp *cpp)
{
	if (!nfp_mip_cache(cpp))
		nfp_mip_probe(cpp);

	return nfp_mip_cache(cpp);
}

/**
 * nfp_mip_symtab() - Get the address and size of the MIP symbol table
 * @mip:	MIP handle
 * @addr:	Location for NFP DDR address of MIP symbol table
 * @size:	Location for size of MIP symbol table
 */
void nfp_mip_symtab(const struct nfp_mip *mip, u32 *addr, u32 *size)
{
	*addr = le32_to_cpu(mip->symtab_addr);
	*size = le32_to_cpu(mip->symtab_size);
}

/**
 * nfp_mip_strtab() - Get the address and size of the MIP symbol name table
 * @mip:	MIP handle
 * @addr:	Location for NFP DDR address of MIP symbol name table
 * @size:	Location for size of MIP symbol name table
 */
void nfp_mip_strtab(const struct nfp_mip *mip, u32 *addr, u32 *size)
{
	*addr = le32_to_cpu(mip->strtab_addr);
	*size = le32_to_cpu(mip->strtab_size);
}

/**
 * nfp_mip_reload() - Invalidate the current MIP, if any, and related entries.
 * @cpp:	NFP CPP Handle
 *
 * The next nfp_mip() probe will then do the actual reload of MIP data.
 * Calling nfp_mip_reload() will also invalidate:
 * * rtsyms
 */
void nfp_mip_reload(struct nfp_cpp *cpp)
{
	struct nfp_mip *mip;

	mip = nfp_mip_cache(cpp);
	if (!mip)
		return;

	nfp_rtsym_reload(cpp);
	kfree(mip);
	nfp_mip_cache_set(cpp, NULL);
}
