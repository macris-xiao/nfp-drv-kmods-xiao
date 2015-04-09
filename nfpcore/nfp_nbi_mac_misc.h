/**
 * Copyright (C) 2013-2015 Netronome Systems, Inc.  All rights reserved.
 * Author: Tony Egan <tony.egan@netronome.com>
 *
 * @file nfp_nbi_mac_misc.h
 * nfp6000 MAC API functions
 *
 */

#ifndef __NFP_NBI_MAC_MISC_H__
#define __NFP_NBI_MAC_MISC_H__

#include "nfp_nbi.h"

int nfp_nbi_mac_regr(struct nfp_nbi_dev *nbi, uint32_t base,
			  uint32_t reg, uint32_t *data);
int nfp_nbi_mac_regw(struct nfp_nbi_dev *nbi, uint32_t base, uint32_t reg,
		     uint32_t mask, uint32_t data);

#endif
