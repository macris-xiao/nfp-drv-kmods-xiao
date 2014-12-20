/*
 * Copyright (C) 2014, Netronome Systems, Inc.
 * All right reserved.
 *
 */

#include <linux/kernel.h>

#include "nfp_common.h"
#include "nfp_resource.h"
#include "nfp-bsp/nfp_resource.h"
#include "nfp.h"
#include "nfp_nffw.h"
#include "nfp_device.h"
#include "nfp_cpp.h"

#define NFP_HOST_ENDIAN		0x3412
#define NFP_ENDIAN_LITTLE	0x3412
#define NFP_ENDIAN_BIG		0x1234
#define UINT64_C(x)	((uint64_t)(x))
#define NFP_HTOLE32(x)	cpu_to_le32(x)

struct nfp_nffw_info_priv {
	struct nfp_device *dev;
	struct nfp_resource *res;
	struct nfp_nffw_info fwinf;
};

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

int nfp_nffw_info_acquire(struct nfp_device *dev)
{
	struct nfp_resource *res;
	struct nfp_cpp *cpp = nfp_device_cpp(dev);
	struct nfp_nffw_info_priv *priv = _nfp_nffw_priv(dev);
	int err;
#if 0
	const struct nfp_chipdata_chip *chip = nfp_device_chip(dev);

	if (!chip)
		return -EINVAL;
#endif

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

#if (NFP_HOST_ENDIAN != NFP_ENDIAN_LITTLE)
		/* Endian swap */
		{
			uint32_t *v;
			size_t i;

			for (i = 0, v = (uint32_t *)&priv->fwinf;
			     i < sizeof(priv->fwinfo);
			     i += sizeof(*v), v++) {
				*v = NFP_LETOH32(*v);
			}
		}
#endif
	} else {
		return -ENODEV;
	}

	if (!nffw_res_flg_init_get(&priv->fwinf)) {
		/* First use since reset. */
#if 0
		int meid;
		size_t mecnt = 0;
#endif
		memset(&priv->fwinf, 0, sizeof(priv->fwinf));
#if 0
		for (meid = nfp_chipdata_meid_first(chip);
			 (meid != -1) && (mecnt < NFFW_MEINFO_CNT);
			 meid = nfp_chipdata_meid_next(chip, meid), mecnt++) {
			priv->fwinf.meinfo[mecnt].ctxmask__fwid__meid = 0;
			nffw_meinfo_meid_set(&priv->fwinf.meinfo[mecnt], meid);
		}
#endif
		nffw_res_flg_init_set(&priv->fwinf, 1);
	}

	priv->res = res;
	priv->dev = dev;
	return 0;
}

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

#if (NFP_HOST_ENDIAN != NFP_ENDIAN_LITTLE)
		/* Endian swap the buffer we are writing out in-place */
		{
			uint32_t *v;
			size_t i;

			for (i = 0, v = (uint32_t *)&priv->fwinf;
			     i < sizeof(priv->fwinfo);
			     i += sizeof(*v), v++) {
				*v = NFP_HTOLE32(*v);
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

int nfp_nffw_info_fw_loaded(struct nfp_device *dev)
{
	struct nfp_nffw_info *fwinf = _nfp_nffw_info(dev);

	if (!fwinf)
		return 0;

	return nffw_res_flg_loaded_get(fwinf);
}

int nfp_nffw_info_fw_loaded_set(struct nfp_device *dev, int is_loaded)
{
	struct nfp_nffw_info *fwinf = _nfp_nffw_info(dev);

	if (!fwinf)
		return -EINVAL;

	nffw_res_flg_loaded_set(fwinf, (is_loaded) ? 1 : 0);
	return 0;
}

int nfp_nffw_info_fw_modular(struct nfp_device *dev)
{
	struct nfp_nffw_info *fwinf = _nfp_nffw_info(dev);

	if (!fwinf)
		return 0;

	return nffw_res_flg_modular_get(fwinf);
}

int nfp_nffw_info_fw_modular_set(struct nfp_device *dev, int is_modular)
{
	struct nfp_nffw_info *fwinf = _nfp_nffw_info(dev);

	if (!fwinf)
		return -EINVAL;

	nffw_res_flg_modular_set(fwinf, (is_modular) ? 1 : 0);

	return 0;
}

uint8_t nfp_nffw_info_me_ctxmask(struct nfp_device *dev, int meid)
{
	size_t idx;
	struct nffw_meinfo *meinfo;
	struct nfp_nffw_info *fwinf = _nfp_nffw_info(dev);

	if (!fwinf)
		return 0;

	for (idx = 0, meinfo = &fwinf->meinfo[0];
		 idx < NFFW_MEINFO_CNT; idx++, meinfo++) {
		if ((int)nffw_meinfo_meid_get(meinfo) == meid)
			return nffw_meinfo_ctxmask_get(meinfo);
	}

	return 0;
}

int nfp_nffw_info_me_ctxmask_set(struct nfp_device *dev,
				 int meid, uint8_t ctxmask)
{
	size_t idx;
	struct nffw_meinfo *meinfo;
	struct nfp_nffw_info *fwinf = _nfp_nffw_info(dev);

	if (!fwinf)
		return -ENODEV;

	for (idx = 0, meinfo = &fwinf->meinfo[0];
		 idx < NFFW_MEINFO_CNT; idx++, meinfo++) {
		if ((int)nffw_meinfo_meid_get(meinfo) == meid) {
			nffw_meinfo_ctxmask_set(meinfo, ctxmask);
			return 0;
		}
	}

	return -ENOENT;
}

uint8_t nfp_nffw_info_me_fwid(struct nfp_device *dev, int meid)
{
	size_t idx;
	struct nffw_meinfo *meinfo;
	struct nfp_nffw_info *fwinf = _nfp_nffw_info(dev);

	if (!fwinf)
		return 0;

	for (idx = 0, meinfo = &fwinf->meinfo[0];
		 idx < NFFW_MEINFO_CNT; idx++, meinfo++) {
		if ((int)nffw_meinfo_meid_get(meinfo) == meid)
			return nffw_meinfo_fwid_get(meinfo);
	}

	return 0;
}

int nfp_nffw_info_me_fwid_set(struct nfp_device *dev, int meid,
							  uint8_t fwid)
{
	size_t idx;
	struct nffw_meinfo *meinfo;
	struct nfp_nffw_info *fwinf = _nfp_nffw_info(dev);

	if (!fwinf)
		return -ENODEV;

	if (fwid == NFFW_FWID_ALL)
		return -EINVAL;

	for (idx = 0, meinfo = &fwinf->meinfo[0];
		 idx < NFFW_MEINFO_CNT; idx++, meinfo++)
		if ((int)nffw_meinfo_meid_get(meinfo) == meid)
			break;

	if (idx == NFFW_MEINFO_CNT)
		return -ENOENT;

	if (fwid) {
		nffw_meinfo_fwid_set(meinfo, fwid);
	} else {
		nffw_meinfo_fwid_set(meinfo, 0);
		nffw_meinfo_ctxmask_set(meinfo, 0);
	}

	return 0;
}

uint8_t nfp_nffw_info_fwid_alloc(struct nfp_device *dev)
{
	size_t idx;
	struct nffw_fwinfo *fwinfo;
	struct nfp_nffw_info *fwinf = _nfp_nffw_info(dev);

	if (!fwinf)
		return 0;

	for (idx = 0, fwinfo = &fwinf->fwinfo[0];
		 idx < NFFW_FWINFO_CNT; idx++, fwinfo++) {
		if (!nffw_fwinfo_loaded_get(fwinfo)) {
			nffw_fwinfo_loaded_set(fwinfo, 1);
			return ((uint8_t)idx + NFFW_FWID_BASE);
		}
	}

	return 0;
}

int nfp_nffw_info_fwid_free(struct nfp_device *dev, uint8_t fwid)
{
	struct nffw_fwinfo *fwinfo;
	struct nffw_meinfo *meinfo;
	size_t idx;
	struct nfp_nffw_info *fwinf = _nfp_nffw_info(dev);

	if (!fwinf)
		return -ENODEV;

	if ((fwid == 0) || (fwid == NFFW_FWID_ALL)) {
		for (idx = 0, meinfo = &fwinf->meinfo[0];
			idx < NFFW_MEINFO_CNT; idx++, meinfo++) {
			nffw_meinfo_fwid_set(meinfo, 0);
			nffw_meinfo_ctxmask_set(meinfo, 0);
		}

		for (idx = 0, fwinfo = &fwinf->fwinfo[0];
			idx < NFFW_FWINFO_CNT; idx++, fwinfo++) {
			nffw_fwinfo_loaded_set(fwinfo, 0);
			nffw_fwinfo_mip_offset_set(fwinfo, 0);
			nffw_fwinfo_mip_cppid_set(fwinfo, 0);
		}

		return 0;
	}

	if (fwid < NFFW_FWID_BASE)
		return -EINVAL;

	fwinfo = &fwinf->fwinfo[fwid - NFFW_FWID_BASE];
	nffw_fwinfo_loaded_set(fwinfo, 0);
	for (idx = 0, meinfo = &fwinf->meinfo[0];
		 idx < NFFW_MEINFO_CNT; idx++, meinfo++) {
		if (nffw_meinfo_fwid_get(meinfo) == fwid) {
			nffw_meinfo_fwid_set(meinfo, 0);
			nffw_meinfo_ctxmask_set(meinfo, 0);
		}
	}
	return 0;
}

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

uint8_t nfp_nffw_info_fwid_next(struct nfp_device *dev, uint8_t fwid)
{
	size_t idx;
	struct nffw_fwinfo *fwinfo;
	struct nfp_nffw_info *fwinf = _nfp_nffw_info(dev);

	if (!fwinf)
		return 0;

	if (fwid < NFFW_FWID_BASE)
		return 0;

	for (idx = (fwid - NFFW_FWID_BASE) + 1,
		 fwinfo = &fwinf->fwinfo[(fwid - NFFW_FWID_BASE) + 1];
		 idx < NFFW_FWINFO_CNT; idx++, fwinfo++) {
		if (nffw_fwinfo_loaded_get(fwinfo))
			return (idx + NFFW_FWID_BASE);
	}

	return 0;
}

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
		*off |= (UINT64_C(1) << 63);

	return 0;
}

int nfp_nffw_info_fw_mip_set(struct nfp_device *dev, uint8_t fwid,
						 uint32_t cpp_id, uint64_t off)
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

	nffw_fwinfo_mip_cppid_set(fwinfo, cpp_id);
	nffw_fwinfo_mip_offset_set(fwinfo, off);
	nffw_fwinfo_mip_mu_da_set(fwinfo, ((off >> 63) & 1));
	return 0;
}
