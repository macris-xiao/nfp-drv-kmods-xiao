/*
 * Copyright (C) 2010-2015,  Netronome Systems, Inc.  All rights reserved.
 *
 * @file		  nfp_mip.c
 * @brief		 Interface for Microcode Information Page (MIP)
 *
 */

#define NFP6000_LONGNAMES

#include <linux/kernel.h>

#include "nfp3200/nfp3200.h"

#include "nfp_common.h"

#include "nfp.h"
#include "nfp_cpp.h"
#include "nfp_nffw.h"
#include "nfp_mip.h"
#include "nfp_rtsym.h"
#include "nfp-bsp/nfp_target.h"

#define NFP_MIP_SIGNATURE	0x0050494d  /* "MIP\0" */
#define NFP_MIP_VERSION	  1
#define NFP_MIP_MAX_OFFSET   (256*1024)

#define UINT32_MAX	(0xffffffff)

static void __mip_update_byteorder(struct nfp_mip *mip)
{
	struct nfp_mip_entry *ent;
	int offset;

	/* Convert main MIP structure. */
	mip->signature = le32_to_cpu(mip->signature);
	mip->mip_version = le32_to_cpu(mip->mip_version);
	mip->mip_size = le32_to_cpu(mip->mip_size);
	mip->first_entry = le32_to_cpu(mip->first_entry);
	mip->version = le32_to_cpu(mip->version);
	mip->buildnum = le32_to_cpu(mip->buildnum);
	mip->buildtime = le32_to_cpu(mip->buildtime);
	mip->loadtime = le32_to_cpu(mip->loadtime);
	mip->symtab_addr = le32_to_cpu(mip->symtab_addr);
	mip->symtab_size = le32_to_cpu(mip->symtab_size);
	mip->strtab_addr = le32_to_cpu(mip->strtab_addr);
	mip->strtab_size = le32_to_cpu(mip->strtab_size);

	/* Convert known MIP entries. */
	for (offset = mip->first_entry;
		 (offset + sizeof(*ent)) < mip->mip_size;
		 offset += ent->offset_next) {

		ent = (struct nfp_mip_entry *) (((char *) mip) + offset);
		ent->type = le32_to_cpu(ent->type);
		ent->version = le32_to_cpu(ent->version);
		ent->offset_next = le32_to_cpu(ent->offset_next);

		if ((offset + ent->offset_next) > mip->mip_size)
			break;

		switch (ent->type) {
		case NFP_MIP_TYPE_NONE:
			return;

		case NFP_MIP_TYPE_QC:
		{
			struct nfp_mip_qc *qc = (struct nfp_mip_qc *) ent;

			if (qc->version != NFP_MIP_QC_VERSION)
				break;
			qc->type_config = le32_to_cpu(qc->type_config);
			qc->type_config_size =
				le32_to_cpu(qc->type_config_size);
			qc->host_config = le32_to_cpu(qc->host_config);
			qc->host_config_size =
				le32_to_cpu(qc->host_config_size);
			qc->config_signal = le32_to_cpu(qc->config_signal);
			qc->nfp_queue_size = le32_to_cpu(qc->nfp_queue_size);
			qc->queue_base = le32_to_cpu(qc->queue_base);
			qc->sequence_base = le32_to_cpu(qc->sequence_base);
			qc->sequence_type = le32_to_cpu(qc->sequence_type);
			qc->status_base = le32_to_cpu(qc->status_base);
			qc->status_version = le32_to_cpu(qc->status_version);
			qc->error_base = le32_to_cpu(qc->error_base);
			break;
		}

		case NFP_MIP_TYPE_VPCI:
		{
			struct nfp_mip_vpci *vpci = (struct nfp_mip_vpci *) ent;

			if (vpci->version != NFP_MIP_VPCI_VERSION)
				break;
			vpci->vpci_epconfig =
				le32_to_cpu(vpci->vpci_epconfig);
			vpci->vpci_epconfig_size =
				le32_to_cpu(vpci->vpci_epconfig_size);
			break;
		}

		default:
			ent->type = cpu_to_le32(ent->type);
			ent->version = cpu_to_le32(ent->version);
			break;
		}
	}
}

struct nfp_mip_priv {
	struct nfp_mip *mip;
};

static void __nfp_mip_des(void *data)
{
	struct nfp_mip_priv *priv = data;

	kfree(priv->mip);
}

static void *__nfp_mip_con(struct nfp_device *dev)
{
	return nfp_device_private_alloc(dev,
			sizeof(struct nfp_mip_priv),
			__nfp_mip_des);
}

struct nfp_mip *nfp_mip(struct nfp_device *dev)
{
	struct nfp_mip_priv *priv = nfp_device_private(dev, __nfp_mip_con);

	if (priv->mip)
		return priv->mip;
	nfp_mip_probe(dev);
	return priv->mip;
}

static inline int _nfp6000_cppat_mu_locality_lsb(int mode,
	int addr40)
{
	switch (mode) {
	case 0:
	case 1:
	case 2:
	case 3:
		return (addr40) ? 38 : 30;
	default:
		break;
	}
	return -EINVAL;
}

#define   NFP_IMB_TgtAddressModeCfg_Mode_of(_x)      (((_x) >> 13) & 0x7)
#define   NFP_IMB_TgtAddressModeCfg_AddrMode                 (1 << 12)
#define     NFP_IMB_TgtAddressModeCfg_AddrMode_32_bit        (0 << 12)
#define     NFP_IMB_TgtAddressModeCfg_AddrMode_40_bit        (1 << 12)

static int nfp_mip_nfp6000_mu_locality_lsb(struct nfp_device *dev)
{
	struct nfp_cpp *cpp = nfp_device_cpp(dev);
	uint32_t xpbaddr, imbcppat;
	int err;

	if (!cpp)
		return -ENODEV;

	/* Hardcoded XPB IMB Base, island 0 */
	xpbaddr = 0x000a0000 + (NFP_CPP_TARGET_MU * 4);
	err = nfp_xpb_readl(cpp, xpbaddr, &imbcppat);
	if (err < 0)
		return err;

	return _nfp6000_cppat_mu_locality_lsb(
		NFP_IMB_TgtAddressModeCfg_Mode_of(imbcppat),
		(imbcppat & NFP_IMB_TgtAddressModeCfg_AddrMode) ==
		NFP_IMB_TgtAddressModeCfg_AddrMode_40_bit);
}

int __nfp_mip_location(struct nfp_device *dev,
		       uint32_t *cppid, uint64_t *addr,
		       unsigned long *size, unsigned long *load_time)
{
	int retval;
	uint32_t mip_cppid = 0;
	uint64_t mip_off = 0;
	struct nfp_cpp *cpp = nfp_device_cpp(dev);
	struct nfp_mip mip;

	/* First see if we can get it from the nfp.nffw resource */
	if (nfp_nffw_info_acquire(dev) == 0) {

		int mu_lsb = -1;

		if (NFP_CPP_MODEL_IS_6000(nfp_cpp_model(nfp_device_cpp(dev))))
			mu_lsb = nfp_mip_nfp6000_mu_locality_lsb(dev);
		else
			mu_lsb = 38; /* Assume 40-bit addressing */

		if ((nfp_nffw_info_fw_mip(dev, nfp_nffw_info_fwid_first(dev),
				&mip_cppid, &mip_off) == 0) &&
			(mip_cppid != 0) &&
			(NFP_CPP_ID_TARGET_of(mip_cppid) ==
						NFP_CPP_TARGET_MU)) {
			if ((mip_off >> 63) & 1) {
				mip_off &= ~(UINT64_C(1) << 63);
				mip_off &= ~(UINT64_C(0x3) << mu_lsb);
				/* Direct Access */
				mip_off |= ((uint64_t)2 << mu_lsb);
			}
		}
		nfp_nffw_info_release(dev);
	}

	/* Verify that the discovered area actually has a MIP signature */
	if (mip_cppid) {
		retval = nfp_cpp_read(cpp, mip_cppid,
				      mip_off,
				      &mip, sizeof(mip));
		if (retval < sizeof(mip) ||
		    le32_to_cpu(mip.signature) != NFP_MIP_SIGNATURE )
			mip_cppid = 0;
	}

	if (mip_cppid == 0) {
		for (mip_off = 0;
		     mip_off < NFP_MIP_MAX_OFFSET;
		     mip_off += 4096) {
			uint32_t cpp_id = NFP_CPP_ID(NFP_CPP_TARGET_MU,
						     NFP_CPP_ACTION_RW, 0);
			retval = nfp_cpp_read(cpp, cpp_id,
					      mip_off,
					      &mip, sizeof(mip));
			if (retval < sizeof(mip))
				goto err_probe;
			if (le32_to_cpu(mip.signature) == NFP_MIP_SIGNATURE) {
				mip_cppid = cpp_id;
				break;
			}
		}
	}

	if (mip_cppid == 0)
		goto err_probe;

	/* This limitation is not required any more, only recommended
	 if ((le32_to_cpu(mip_version) != NFP_MIP_VERSION) ||
		(mip_off + le32_to_cpu(mip_size) >= NFP_MIP_MAX_OFFSET))
		goto err_probe;
	*/
	*cppid = mip_cppid;
	*addr = mip_off;
	*size = (le32_to_cpu(mip.mip_size) + 7) & ~7;
	*load_time = le32_to_cpu(mip.loadtime);
	return 0;

err_probe:
	return -ENODEV;
}

int _nfp_mip_scan(struct nfp_device *dev, int is_load)
{
#if 1
	/* Since we scan from the host there is not need to ping the kernel */
	return 0;
#else
	char path[PATH_MAX];
	FILE *mipfile;
	int retval;

	/* Re-probe for the MIP. */
	snprintf(path, sizeof(path), NFP_SYSFS_DEVICE_DIR "/mip",
			nfp_device_number(dev));
	path[sizeof(path) - 1] = 0;

	mipfile = fopen(path, "w");
	if (!mipfile)
		return -1;

	retval = fprintf(mipfile, "%d\n", is_load);
	fclose(mipfile);

	if (retval < 0)
		return -1;

	return 0;
#endif
}

int nfp_mip_probe(struct nfp_device *dev)
{
	struct nfp_mip_priv *priv = nfp_device_private(dev, __nfp_mip_con);
	unsigned long size, time;
	uint32_t cpp_id;
	uint64_t addr;
	struct nfp_mip *mip;
	int retval;

	retval = __nfp_mip_location(dev, &cpp_id, &addr, &size, &time);
	if (retval != 0)
		return -ENODEV;

	if (priv->mip && priv->mip->loadtime == time)
		return 0; /* No change */

	/*
	 * Once we have confirmed a MIP update we discard old MIP and read
	 * new contents from DRAM.  We also discard the current symtab.
	 */

	if (priv->mip) {
		/* Invalidate rtsym first, it may want to
		 * still look at the mip
		 */
		nfp_rtsym_reload(dev);
		kfree(priv->mip);
		priv->mip = NULL;
	}

	mip = kmalloc(size, GFP_KERNEL);
	if (!mip)
		return -ENOMEM;

	retval = nfp_cpp_read(nfp_device_cpp(dev), cpp_id, addr, mip, size);
	if (retval != size) {
		kfree(mip);
		return -retval;
	}

	if ((le32_to_cpu(mip->signature) != NFP_MIP_SIGNATURE) ||
		(le32_to_cpu(mip->mip_version) != NFP_MIP_VERSION)) {
		kfree(mip);
		return -EIO;
	}

	__mip_update_byteorder(mip);

	priv->mip = mip;
	return 1;
}

void *nfp_mip_find_entry(struct nfp_mip *mip, enum nfp_mip_entry_type type)
{
	struct nfp_mip_entry *ent;
	int offset;

	for (offset = mip->first_entry;
		 (offset + sizeof(*ent)) < mip->mip_size;
		 offset += ent->offset_next) {

		ent = (struct nfp_mip_entry *) (((char *) mip) + offset);
		if (ent->type == NFP_MIP_TYPE_NONE)
			break;

		if (ent->type == type)
			return ent;
	}

	return NULL;
}
