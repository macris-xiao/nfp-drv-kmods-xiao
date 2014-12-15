/**
 * Copyright (C) 2013-2014 Netronome Systems, Inc.  All rights reserved.
 *
 * @file nfp_nbi.h
 * nfp6000 NBI API functions
 *
 */

#ifndef __NFP_NBI_H__
#define __NFP_NBI_H__

#include "nfp.h"
#include "nfp_cpp.h"

/**
 * NFP NBI device handle
 */
struct nfp_nbi_dev;

/**
 * Acquire NFP NBI device handle
 * @ingroup nfp6000-only
 *
 * @param nfp		NFP Device handle
 * @param nbi		NBI Index (0..1)
 * @return nfp_nbidma_dev * on success, NULL on failure.
 */
struct nfp_nbi_dev *nfp_nbi_open(struct nfp_device *nfp, int nbi);

/**
 * Release NFP NBI device handle
 * @ingroup nfp6000-only
 *
 * @param nfpnbidev	NFP NBI Device handle
 */
void nfp_nbi_close(struct nfp_nbi_dev *nfpnbidev);

/**
 * Get the NFP NBI index of this NBI handle
 * @ingroup nfp6000-only
 *
 * @param nfpnbidev     NFP NBI Device handle
 * @return              index of the NBI device
 */
int nfp_nbi_index(struct nfp_nbi_dev *nfpnbidev);

/**
 * 32Bit Write to NFP NBI CPP register
 * @ingroup nfp6000-only
 *
 * @param nfpnbi	NFP NBI device handle
 * @param base		NFP NBI cpp base address NFP_NBI_<>
 * @param reg		NFP NBI cpp register address
 * @param mask		NFP NBI register mask for write
 * @param data		NFP NBI register data
 *
 * @return number of bytes on success, -1 on failure.
 */
int nfp_nbi_cpp_regw(struct nfp_nbi_dev *nfpnbi, uint64_t base,
			uint64_t reg, uint32_t mask, uint32_t data);

/**
 * 32Bit Read to NFP NBI CPP register
 * @ingroup nfp6000-only
 *
 * @param nfpnbi	NFP NBI device handle
 * @param base		NFP NBI cpp base address NFP_NBI_<>
 * @param reg		NFP NBI cpp register address
 * @param data		NFP NBI register data
 *
 * @return number of bytes on success, -1 on failure.
 */
int nfp_nbi_cpp_regr(struct nfp_nbi_dev *nfpnbi, uint64_t base,
			uint64_t reg, uint32_t *data);

/**
 * 64Bit Write to NFP NBI CPP register
 * @ingroup nfp6000-only
 *
 * @param nfpnbi	NFP NBI device handle
 * @param base		NFP NBI cpp base address NFP_NBI_<>
 * @param reg		NFP NBI cpp register address
 * @param mask		NFP NBI register mask for write
 * @param data		NFP NBI register data
 *
 * @return number of bytes on success, -1 on failure.
 */
int nfp_nbi_cpp_regwq(struct nfp_nbi_dev *nfpnbi, uint64_t base,
			 uint64_t reg, uint64_t mask, uint64_t data);

/**
 * 64Bit Read to NFP NBI CPP register
 * @ingroup nfp6000-only
 *
 * @param nfpnbi	NFP NBI device handle
 * @param base		NFP NBI cpp base address NFP_NBI_<>
 * @param reg		NFP NBI cpp register address
 * @param data		NFP NBI register data
 *
 * @return number of bytes on success, -1 on failure.
 */
int nfp_nbi_cpp_regrq(struct nfp_nbi_dev *nfpnbi, uint64_t base,
			 uint64_t reg, uint64_t *data);

/**
 * 32Bit Write to NFP NBI XPB register
 * @ingroup nfp6000-only
 *
 * @param nfpnbi	NFP NBI device handle
 * @param base		NFP NBI xpb base address NFP_NBI_<>X
 * @param reg		NFP NBI xpb register address
 * @param mask		NFP NBI register mask for write
 * @param data		NFP NBI register data
 *
 * @return number of bytes on success, -1 on failure.
 */
int nfp_nbi_xpb_regw(struct nfp_nbi_dev *nfpnbi, uint64_t base,
			uint64_t reg, uint32_t mask, uint32_t data);

/**
 * 32Bit Read to NFP NBI XPB register
 * @ingroup nfp6000-only
 *
 * @param nfpnbi	NFP NBI device handle
 * @param base		NFP NBI xpb base address NFP_NBI_<>X
 * @param reg		NFP NBI xpb register address
 * @param data		NFP NBI register data
 *
 * @return number of bytes on success, -1 on failure.
 */
int nfp_nbi_xpb_regr(struct nfp_nbi_dev *nfpnbi, uint64_t base,
			uint64_t reg, uint32_t *data);

/**
 * 64Bit Write to NFP NBI XPB register
 * @ingroup nfp6000-only
 *
 * @param nfpnbi	NFP NBI device handle
 * @param base		NFP NBI xpb base address NFP_NBI_<>X
 * @param reg		NFP NBI xpb register address
 * @param mask		NFP NBI register mask for write
 * @param data		NFP NBI register data
 *
 * @return number of bytes on success, -1 on failure.
 */
int nfp_nbi_xpb_regwq(struct nfp_nbi_dev *nfpnbi, uint64_t base,
			 uint64_t reg, uint64_t mask, uint64_t data);

/**
 * 64Bit Read to NFP NBI XPB register
 * @ingroup nfp6000-only
 *
 * @param nfpnbi	NFP NBI device handle
 * @param base		NFP NBI xpb base address NFP_NBI_<>X
 * @param reg		NFP NBI xpb register address
 * @param data		NFP NBI register data
 *
 * @return number of bytes on success, -1 on failure.
 */
int nfp_nbi_xpb_regrq(struct nfp_nbi_dev *nfpnbi, uint64_t base,
			 uint64_t reg, uint64_t *data);
#endif
