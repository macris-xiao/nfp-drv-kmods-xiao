/*
 * Copyright (C) 2011-2015,  Netronome Systems, Inc.  All rights reserved.
 *
 * @file		  nfp_syms.c
 * @brief		 Interface for accessing run-time symbol table
 *
 */
#define NFP6000_LONGNAMES

#include <linux/kernel.h>
#include <linux/slab.h>

#include "nfp.h"
#include "nfp_rtsym.h"
#include "nfp_nffw.h"
#include "nfp_mip.h"
#include "nfp_cpp.h"
#include "nfp3200/nfp3200.h"

/* These need to match the linker */
#define _SYM_TGT_LMEM	   0
#define _SYM_TGT_UMEM	   0xFE /* Only NFP-32xx */
#define _SYM_TGT_EMU_CACHE  0x17

struct _rtsym {
	uint8_t  type;
	uint8_t  target;
	union {
		uint8_t  val;
		/* N/A, island or linear menum, depends on 'target' */
		uint8_t  nfp3200_domain;
		/* 0xff if N/A */
		uint8_t  nfp6000_island;
	} domain1;
	uint8_t  addr_hi;
	uint32_t addr_lo;
	uint16_t name;
	union {
		uint8_t  val;
		uint8_t  nfp3200___rsvd;
		/* 0xff if N/A */
		uint8_t  nfp6000_menum;
	} domain2;
	uint8_t  size_hi;
	uint32_t size_lo;
};

struct nfp_rtsym_priv {
	const struct nfp_mip *mip;
	int numrtsyms;
	struct nfp_rtsym *rtsymtab;
	char *rtstrtab;
};

static void nfp_rtsym_priv_des(void *data)
{
	struct nfp_rtsym_priv *priv = data;

	kfree(priv->rtsymtab);
	kfree(priv->rtstrtab);
}

static void *nfp_rtsym_priv_con(struct nfp_device *dev)
{
	struct nfp_rtsym_priv *priv;

	priv = nfp_device_private_alloc(dev, sizeof(*priv), nfp_rtsym_priv_des);

	return priv;
}

#define NFP3200_MEID(cluster_num, menum) \
	((((cluster_num) >= 0) && ((cluster_num) < 5) && \
	(((menum) & 0x7) == (menum))) ? \
	(((cluster_num) << 4) | (menum) | (0x8)) : -1)

#define NFP3200_MELIN2MEID(melinnum) \
	NFP3200_MEID(((melinnum) >> 3), ((melinnum) & 0x7))

#define NFP6000_MEID(island_id, menum) \
	(((((island_id) & 0x3F) == (island_id)) && \
	(((menum) >= 0) && ((menum) < 12))) ? \
	(((island_id) << 4) | ((menum) + 4)) : -1)

int __nfp_rtsymtab_probe(struct nfp_device *dev, struct nfp_rtsym_priv *priv)
{
	struct nfp_cpp *cpp = nfp_device_cpp(dev);
	struct _rtsym *rtsymtab;
	uint32_t *wptr;
	int err, n;
	uint32_t model = nfp_cpp_model(cpp);
	const uint32_t dram = NFP_CPP_ID(NFP_CPP_TARGET_MU,
					 NFP_CPP_ACTION_RW, 0);

	if (!priv->mip) {
		priv->mip = nfp_mip(dev);
		if (!priv->mip)
			return -ENODEV;
	}

	if (priv->mip->symtab_size == 0 || priv->mip->strtab_size == 0 ||
		(priv->mip->symtab_size % sizeof(*rtsymtab)) != 0)
		return -ENXIO;

	rtsymtab = kmalloc(priv->mip->symtab_size, GFP_KERNEL);
	if (!rtsymtab)
		return -ENOMEM;

	priv->numrtsyms = priv->mip->symtab_size / sizeof(*rtsymtab);
	priv->rtsymtab = kmalloc(priv->numrtsyms * sizeof(struct nfp_rtsym) + 7,
				 GFP_KERNEL);
	if (!priv->rtsymtab) {
		err = -ENOMEM;
		goto err_symtab;
	}

	priv->rtstrtab = kmalloc(priv->mip->strtab_size + 7, GFP_KERNEL);
	if (!priv->rtstrtab) {
		err = -ENOMEM;
		goto err_strtab;
	}

	if (NFP_CPP_MODEL_IS_3200(model)) {
		err = nfp_cpp_read(cpp, dram, priv->mip->symtab_addr,
				   rtsymtab,
				   (priv->mip->symtab_size + 7) & ~7);
		if (err < priv->mip->symtab_size)
			goto err_read_symtab;

		err = nfp_cpp_read(cpp, dram, priv->mip->strtab_addr,
				   priv->rtstrtab,
				   (priv->mip->strtab_size + 7) & ~7);
		if (err < priv->mip->strtab_size)
			goto err_read_strtab;
		priv->rtstrtab[priv->mip->strtab_size] = '\0';

		for (wptr = (uint32_t *) rtsymtab, n = 0;
		     n < priv->numrtsyms; n++)
			wptr[n] = le32_to_cpu(wptr[n]);

		for (n = 0; n < priv->numrtsyms; n++) {
			priv->rtsymtab[n].type = rtsymtab[n].type;
			priv->rtsymtab[n].name = priv->rtstrtab +
				(rtsymtab[n].name % priv->mip->strtab_size);
			priv->rtsymtab[n].addr = (((uint64_t)
						  rtsymtab[n].addr_hi) << 32) +
				rtsymtab[n].addr_lo;
			priv->rtsymtab[n].size = (((uint64_t)
						  rtsymtab[n].size_hi) << 32) +
				rtsymtab[n].size_lo;
			switch (rtsymtab[n].target) {
			case _SYM_TGT_LMEM:
				priv->rtsymtab[n].target =
					NFP_RTSYM_TARGET_LMEM;
				priv->rtsymtab[n].domain = NFP3200_MELIN2MEID(
					rtsymtab[n].domain1.nfp3200_domain);
				break;
			case _SYM_TGT_UMEM:
				priv->rtsymtab[n].target =
					NFP_RTSYM_TARGET_USTORE;
				priv->rtsymtab[n].domain = NFP3200_MELIN2MEID(
					rtsymtab[n].domain1.nfp3200_domain);
				break;
			default:
				priv->rtsymtab[n].target = rtsymtab[n].target;
				priv->rtsymtab[n].domain =
					rtsymtab[n].domain1.nfp3200_domain;
				break;
			}
		}
	} else if (NFP_CPP_MODEL_IS_6000(model)) {
		uint64_t emu_24 = 0x8100000000ULL;	/* Island 24 EMU */
		/*FIXME by using nfp_resource*/
		err = nfp_cpp_read(cpp, dram, emu_24 | priv->mip->symtab_addr,
				   rtsymtab, priv->mip->symtab_size);
		if (err != priv->mip->symtab_size)
			goto err_read_symtab;

		err = nfp_cpp_read(cpp, dram, emu_24 | priv->mip->strtab_addr,
				   priv->rtstrtab, priv->mip->strtab_size);
		if (err != priv->mip->strtab_size)
			goto err_read_strtab;
		priv->rtstrtab[priv->mip->strtab_size] = '\0';

		for (wptr = (uint32_t *) rtsymtab, n = 0;
		     n < priv->numrtsyms; n++)
			wptr[n] = le32_to_cpu(wptr[n]);

		for (n = 0; n < priv->numrtsyms; n++) {
			priv->rtsymtab[n].type = rtsymtab[n].type;
			priv->rtsymtab[n].name = priv->rtstrtab +
				(rtsymtab[n].name % priv->mip->strtab_size);
			priv->rtsymtab[n].addr = (((uint64_t)
						rtsymtab[n].addr_hi) << 32) +
				rtsymtab[n].addr_lo;
			priv->rtsymtab[n].size = (((uint64_t)
						rtsymtab[n].size_hi) << 32) +
				rtsymtab[n].size_lo;

			switch (rtsymtab[n].target) {
			case _SYM_TGT_LMEM:
				priv->rtsymtab[n].target =
					NFP_RTSYM_TARGET_LMEM;
				break;
			case _SYM_TGT_EMU_CACHE:
				priv->rtsymtab[n].target =
					NFP_RTSYM_TARGET_EMU_CACHE;
				break;
			case _SYM_TGT_UMEM:
				goto err_read_symtab;
			default:
				priv->rtsymtab[n].target = rtsymtab[n].target;
				break;
			}

			if (rtsymtab[n].domain2.nfp6000_menum != 0xff)
				priv->rtsymtab[n].domain = NFP6000_MEID(
					rtsymtab[n].domain1.nfp6000_island,
					rtsymtab[n].domain2.nfp6000_menum);
			else if (rtsymtab[n].domain1.nfp6000_island != 0xff)
				priv->rtsymtab[n].domain =
					rtsymtab[n].domain1.nfp6000_island;
			else
				priv->rtsymtab[n].domain = -1;
		}
	} else {
		err = -EINVAL;
		goto err_read_symtab;
	}

	kfree(rtsymtab);
	return 0;

err_read_strtab:
err_read_symtab:
	kfree(priv->rtstrtab);
	priv->rtstrtab = NULL;
err_strtab:
	kfree(priv->rtsymtab);
	priv->rtsymtab = NULL;
	priv->numrtsyms = 0;
err_symtab:
	kfree(rtsymtab);
	return err;
}

int nfp_rtsym_count(struct nfp_device *dev)
{
	struct nfp_rtsym_priv *priv = nfp_device_private(dev,
							 nfp_rtsym_priv_con);
	int err;

	if (!priv->rtsymtab) {
		err = __nfp_rtsymtab_probe(dev, priv);
		if (err < 0)
			return err;
	}

	return priv->numrtsyms;
}

const struct nfp_rtsym *nfp_rtsym_get(struct nfp_device *dev, int idx)
{
	struct nfp_rtsym_priv *priv = nfp_device_private(dev,
							 nfp_rtsym_priv_con);
	int err;

	if (!priv->rtsymtab) {
		err = __nfp_rtsymtab_probe(dev, priv);
		if (err < 0)
			return NULL;
	}

	if (idx >= priv->numrtsyms)
		return NULL;

	return &priv->rtsymtab[idx];
}

const struct nfp_rtsym *nfp_rtsym_lookup(struct nfp_device *dev,
					 const char *name)
{
	struct nfp_rtsym_priv *priv = nfp_device_private(dev,
							 nfp_rtsym_priv_con);
	int err, n;

	if (!priv->rtsymtab) {
		err = __nfp_rtsymtab_probe(dev, priv);
		if (err < 0)
			return NULL;
	}

	for (n = 0; n < priv->numrtsyms; n++) {
		if (strcmp(name, priv->rtsymtab[n].name) == 0)
			return &priv->rtsymtab[n];
	}

	return NULL;
}

void nfp_rtsym_reload(struct nfp_device *dev)
{
	struct nfp_rtsym_priv *priv = nfp_device_private(dev,
							 nfp_rtsym_priv_con);
	kfree(priv->rtsymtab);
	kfree(priv->rtstrtab);
	priv->numrtsyms = 0;
}
