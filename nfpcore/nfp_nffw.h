/*
 * Copyright (C) 2014 Netronome Systems, Inc. All rights reserved.
 * Author: Jason McMullan <jason.mcmullan@netronome.com>
 *
 *   This program is free software; you can redistribute it and/or modify
 *   it under the terms of the GNU General Public License as published by
 *   the Free Software Foundation; either version 2 of the License, or
 *   (at your option) any later version.
 *
 *   This program is distributed in the hope that it will be useful,
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *   GNU General Public License for more details.
 *
 */

#ifndef NFP_NFFW_H
#define NFP_NFFW_H

/** Init-CSR owner IDs for firmware map to firmware IDs which start at 4.
 * Lower IDs are reserved for target and loader IDs.
 */
#define NFFW_FWID_EXT   3 /* For active MEs that we didn't load. */
#define NFFW_FWID_BASE  4

#define NFFW_FWID_ALL   255

/* Enough for all chip families */
#define NFFW_MEINFO_CNT 120
#define NFFW_FWINFO_CNT 120

/* NFFW_FWID_BASE is a firmware ID is the index
 * into the table plus this base */

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

/* ctxmask = ctxmask__fwid__meid<31:24> */
static inline uint32_t nffw_meinfo_ctxmask_get(
	struct nffw_meinfo *mi)
{
	return (mi->ctxmask__fwid__meid >> 24) & 0xFF;
}

static inline void nffw_meinfo_ctxmask_set(
	struct nffw_meinfo *mi, uint32_t v)
{
	mi->ctxmask__fwid__meid &= ~(0xFF << 24);
	mi->ctxmask__fwid__meid |= ((v & 0xFF) << 24);
}

/* fwid = ctxmask__fwid__meid<23:16> */
static inline uint32_t nffw_meinfo_fwid_get(
	struct nffw_meinfo *mi)
{
	return (mi->ctxmask__fwid__meid >> 16) & 0xFF;
}
static inline void nffw_meinfo_fwid_set(
	struct nffw_meinfo *mi, uint32_t v)
{
	mi->ctxmask__fwid__meid &= ~(0xFF << 16);
	mi->ctxmask__fwid__meid |= ((v & 0xFF) << 16);
}

/* meid = ctxmask__fwid__meid<15:0> */
static inline uint32_t nffw_meinfo_meid_get(
	struct nffw_meinfo *mi)
{
	return (mi->ctxmask__fwid__meid & 0xFFFF);
}
static inline void nffw_meinfo_meid_set(
	struct nffw_meinfo *mi, uint32_t v)
{
	mi->ctxmask__fwid__meid &= ~(0xFFFF);
	mi->ctxmask__fwid__meid |= (v & 0xFFFF);
}


/* loaded = loaded__mu_da__mip_off_hi<31:31> */
static inline uint32_t nffw_fwinfo_loaded_get(
	struct nffw_fwinfo *fi)
{
	return (fi->loaded__mu_da__mip_off_hi >> 31) & 1;
}
static inline void nffw_fwinfo_loaded_set(
	struct nffw_fwinfo *fi, uint32_t v)
{
	fi->loaded__mu_da__mip_off_hi &= ~(1 << 31);
	fi->loaded__mu_da__mip_off_hi |= ((v & 1) << 31);
}

/* mip_cppid = mip_cppid */
static inline uint32_t nffw_fwinfo_mip_cppid_get(
	struct nffw_fwinfo *fi)
{
	return fi->mip_cppid;
}
static inline void nffw_fwinfo_mip_cppid_set(
	struct nffw_fwinfo *fi, uint32_t v)
{
	fi->mip_cppid = v;
}

/* loaded = loaded__mu_da__mip_off_hi<8:8> */
static inline uint32_t nffw_fwinfo_mip_mu_da_get(
	struct nffw_fwinfo *fi)
{
	return (fi->loaded__mu_da__mip_off_hi >> 8) & 1;
}
static inline void nffw_fwinfo_mip_mu_da_set(
	struct nffw_fwinfo *fi, uint32_t v)
{
	fi->loaded__mu_da__mip_off_hi &= ~(1 << 8);
	fi->loaded__mu_da__mip_off_hi |= ((v & 1) << 8);
}

/* mip_offset = (loaded__mu_da__mip_off_hi<7:0> << 8) | mip_offset_lo */
static inline uint64_t nffw_fwinfo_mip_offset_get(
	struct nffw_fwinfo *fi)
{
	return (((uint64_t)fi->loaded__mu_da__mip_off_hi & 0xFF) << 32) |
		fi->mip_offset_lo;
}
static inline void nffw_fwinfo_mip_offset_set(
	struct nffw_fwinfo *fi, uint64_t v)
{
	fi->mip_offset_lo = (uint32_t)(v & 0xFFFFffff);
	fi->loaded__mu_da__mip_off_hi &= ~(0xff);
	fi->loaded__mu_da__mip_off_hi |= ((v >> 32) & 0xff);
}

/* flg_init = flags[0]<0> */
static inline uint32_t nffw_res_flg_init_get(
	struct nfp_nffw_info *res)
{
	return ((res->flags[0] >> 0) & 0x1);
}
static inline void nffw_res_flg_init_set(
	struct nfp_nffw_info *res, uint32_t v)
{
	res->flags[0] &= ~(1 << 0);
	res->flags[0] |= ((v & 1) << 0);
}

/* flg_loaded = flags[0]<31> */
static inline uint32_t nffw_res_flg_loaded_get(
	struct nfp_nffw_info *res)
{
	return ((res->flags[0] >> 31) & 0x1);
}
static inline void nffw_res_flg_loaded_set(
	struct nfp_nffw_info *res, uint32_t v)
{
	res->flags[0] &= ~(1 << 31);
	res->flags[0] |= ((v & 1) << 31);
}

/* flg_modular = flags[0]<30> */
static inline uint32_t nffw_res_flg_modular_get(
	struct nfp_nffw_info *res)
{
	return ((res->flags[0] >> 30) & 0x1);
}
static inline void nffw_res_flg_modular_set(
	struct nfp_nffw_info *res, uint32_t v)
{
	res->flags[0] &= ~(1 << 30);
	res->flags[0] |= ((v & 1) << 30);
}

/* flg_debugger_attached = flags[0]<29> */
static inline uint32_t nffw_res_flg_debugger_attached_get(
	struct nfp_nffw_info *res)
{
	return ((res->flags[0] >> 29) & 0x1);
}
static inline void nffw_res_flg_debugger_attached_set(
	struct nfp_nffw_info *res, uint32_t v)
{
	res->flags[0] &= ~(1 << 29);
	res->flags[0] |= ((v & 1) << 29);
}

int nfp_nffw_info_acquire(struct nfp_device *dev);
int nfp_nffw_info_release(struct nfp_device *dev);
int nfp_nffw_info_fw_mip(struct nfp_device *dev, uint8_t fwid,
			 uint32_t *cpp_id, uint64_t *off);
uint8_t nfp_nffw_info_fwid_first(struct nfp_device *dev);


#endif /* NFP_NFFW_H */
/* vim: set shiftwidth=8 noexpandtab:  */
