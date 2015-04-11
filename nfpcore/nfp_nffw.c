/*
 * Copyright (C) 2014-2015, Netronome Systems, Inc.
 * All right reserved.
 *
 */

#include <linux/kernel.h>

#include "nfp.h"
#include "nfp_cpp.h"

#include "nfp_nffw.h"

/* Init-CSR owner IDs for firmware map to firmware IDs which start at 4.
 * Lower IDs are reserved for target and loader IDs.
 */
#define NFFW_FWID_EXT   3 /* For active MEs that we didn't load. */
#define NFFW_FWID_BASE  4

#define NFFW_FWID_ALL   255

/* Enough for all chip families */
#define NFFW_MEINFO_CNT 120
#define NFFW_FWINFO_CNT 120

/* Work in 32-bit words to make cross-platform endianness easier to handle */

/** nfp.nffw meinfo **/
struct nffw_meinfo {
	uint32_t ctxmask__fwid__meid;
};

struct nffw_fwinfo {
	uint32_t loaded__mu_da__mip_off_hi;
	uint32_t mip_cppid; /* 0 means no MIP */
	uint32_t mip_offset_lo;
};

/** Resource: nfp.nffw main **/
struct nfp_nffw_info {
	uint32_t flags[2];
	struct nffw_meinfo meinfo[NFFW_MEINFO_CNT];
	struct nffw_fwinfo fwinfo[NFFW_FWINFO_CNT];
};

struct nfp_nffw_info_priv {
	struct nfp_device *dev;
	struct nfp_resource *res;
	struct nfp_nffw_info fwinf;
};

/* NFFW_FWID_BASE is a firmware ID is the index
 * into the table plus this base */

/* loaded = loaded__mu_da__mip_off_hi<31:31> */
static inline uint32_t nffw_fwinfo_loaded_get(
	struct nffw_fwinfo *fi)
{
	return (fi->loaded__mu_da__mip_off_hi >> 31) & 1;
}

/* mip_cppid = mip_cppid */
static inline uint32_t nffw_fwinfo_mip_cppid_get(
	struct nffw_fwinfo *fi)
{
	return fi->mip_cppid;
}

/* loaded = loaded__mu_da__mip_off_hi<8:8> */
static inline uint32_t nffw_fwinfo_mip_mu_da_get(
	struct nffw_fwinfo *fi)
{
	return (fi->loaded__mu_da__mip_off_hi >> 8) & 1;
}

/* mip_offset = (loaded__mu_da__mip_off_hi<7:0> << 8) | mip_offset_lo */
static inline uint64_t nffw_fwinfo_mip_offset_get(
	struct nffw_fwinfo *fi)
{
	return (((uint64_t)fi->loaded__mu_da__mip_off_hi & 0xFF) << 32) |
		fi->mip_offset_lo;
}

/* flg_init = flags[0]<0> */
static inline uint32_t nffw_res_flg_init_get(
	struct nfp_nffw_info *res)
{
	return ((res->flags[0] >> 0) & 0x1);
}

static void __nfp_nffw_info_des(void *data)
{
	/* struct nfp_nffw_info_priv *priv = data; */
}

static void *__nfp_nffw_info_con(struct nfp_device *dev)
{
	return nfp_device_private_alloc(dev,
			sizeof(struct nfp_nffw_info_priv),
			__nfp_nffw_info_des);
}

/********/

static inline struct nfp_nffw_info_priv *_nfp_nffw_priv(
	struct nfp_device *dev)
{
	if (!dev)
		return NULL;
	return nfp_device_private(dev, __nfp_nffw_info_con);
}

static inline struct nfp_nffw_info *_nfp_nffw_info(
	struct nfp_device *dev)
{
	struct nfp_nffw_info_priv *priv = _nfp_nffw_priv(dev);

	if (!priv)
		return NULL;

	return &priv->fwinf;
}

/**
 * nfp_nffw_info_release() - Acquire the lock on the NFFW table
 * @dev:	NFP Device handle
 *
 * Return: 0, or -ERRNO
 */
int nfp_nffw_info_acquire(struct nfp_device *dev)
{
	struct nfp_resource *res;
	struct nfp_cpp *cpp = nfp_device_cpp(dev);
	struct nfp_nffw_info_priv *priv = _nfp_nffw_priv(dev);
	int err;

	res = nfp_resource_acquire(dev, NFP_RESOURCE_NFP_NFFW);
	if (res) {
		uint32_t cpp_id = nfp_resource_cpp_id(res);
		uint64_t addr = nfp_resource_address(res);
		size_t size = nfp_resource_size(res);

		if (sizeof(priv->fwinf) > size) {
			nfp_resource_release(res);
			return -ERANGE;
		}

		err = nfp_cpp_read(cpp, cpp_id, addr,
			&priv->fwinf, sizeof(priv->fwinf));
		if (err < 0) {
			nfp_resource_release(res);
			return err;
		}

#ifndef __LITTLE_ENDIAN
		/* Endian swap */
		{
			uint32_t *v;
			size_t i;

			for (i = 0, v = (uint32_t *)&priv->fwinf;
			     i < sizeof(priv->fwinfo);
			     i += sizeof(*v), v++) {
				*v = le32_to_cpu(*v);
			}
		}
#endif

		if (!nffw_res_flg_init_get(&priv->fwinf)) {
			nfp_resource_release(res);
			return -EINVAL;
		}
	} else {
		return -ENODEV;
	}

	priv->res = res;
	priv->dev = dev;
	return 0;
}

/**
 * nfp_nffw_info_release() - Release the lock on the NFFW table
 * @dev:	NFP Device handle
 *
 * Return: 0, or -ERRNO
 */
int nfp_nffw_info_release(struct nfp_device *dev)
{
	struct nfp_resource *res;
	struct nfp_cpp *cpp = nfp_device_cpp(dev);
	struct nfp_nffw_info_priv *priv = _nfp_nffw_priv(dev);
	int err;

	if (!priv->res) {
		/* Clear the device's nffw_info data to invalidate it */
		memset(&priv->fwinf, 0, sizeof(priv->fwinf));
		priv->dev = NULL;
		return 0;
	}

	res = priv->res;
	{
		uint32_t cpp_id = nfp_resource_cpp_id(res);
		uint64_t addr = nfp_resource_address(res);

#ifndef __LITTLE_ENDIAN
		/* Endian swap the buffer we are writing out in-place */
		{
			uint32_t *v;
			size_t i;

			for (i = 0, v = (uint32_t *)&priv->fwinf;
			     i < sizeof(priv->fwinfo);
			     i += sizeof(*v), v++) {
				*v = cpu_to_le32(*v);
			}
		}
#endif

		err = nfp_cpp_write(cpp, cpp_id, addr,
			&priv->fwinf, sizeof(priv->fwinf));
		nfp_resource_release(res);
		/* Clear the device's nffw_info data to invalidate it */
		memset(&priv->fwinf, 0, sizeof(priv->fwinf));
		priv->dev = NULL;
		priv->res = NULL;
		if (err < 0)
			return err;
	}

	return 0;
}

/**
 * nfp_nffw_info_fwid_first() - Return the first firmware ID in the NFFW
 * @dev:	NFP Device handle
 *
 * Return: First NFFW firmware ID
 */
uint8_t nfp_nffw_info_fwid_first(struct nfp_device *dev)
{
	size_t idx;
	struct nffw_fwinfo *fwinfo;
	struct nfp_nffw_info *fwinf = _nfp_nffw_info(dev);

	if (!fwinf)
		return 0;

	for (idx = 0, fwinfo = &fwinf->fwinfo[0];
		 idx < NFFW_FWINFO_CNT; idx++, fwinfo++) {
		if (nffw_fwinfo_loaded_get(fwinfo))
			return (idx + NFFW_FWID_BASE);
	}

	return 0;
}

/**
 * nfp_nffw_info_fw_mip() - Retrive the location of the MIP of a firmware
 * @dev:	NFP Device handle
 * @fwid:	NFFW firmware ID
 * @cpp_id:	Pointer to the CPP ID of the MIP
 * @off:	Pointer to the CPP Address of the MIP
 *
 * Return: 0, or -ERRNO
 */
int nfp_nffw_info_fw_mip(struct nfp_device *dev, uint8_t fwid,
			 uint32_t *cpp_id, uint64_t *off)
{
	struct nffw_fwinfo *fwinfo;
	struct nfp_nffw_info *fwinf = _nfp_nffw_info(dev);

	if (!fwinf)
		return -ENODEV;

	if (fwid < NFFW_FWID_BASE)
		return -EINVAL;

	fwinfo = &fwinf->fwinfo[fwid - NFFW_FWID_BASE];

	if (!nffw_fwinfo_loaded_get(fwinfo))
		return -ENOENT;

	if (cpp_id)
		*cpp_id = nffw_fwinfo_mip_cppid_get(fwinfo);
	if (off)
		*off = nffw_fwinfo_mip_offset_get(fwinfo);

	if (nffw_fwinfo_mip_mu_da_get(fwinfo))
		*off |= (1ULL << 63);

	return 0;
}
