/**
 * Copyright (C) 2013-2015 Netronome Systems, Inc.  All rights reserved.
 *
 * @file nfp_nbi.h
 * nfp6000 NBI API functions
 *
 */

#ifndef __NFP_NBI_H__
#define __NFP_NBI_H__

#include "nfp.h"
#include "nfp_cpp.h"

/*
 * NFP NBI device handle
 */
struct nfp_nbi_dev;

struct nfp_nbi_dev *nfp_nbi_open(struct nfp_device *nfp, int nbi);
void nfp_nbi_close(struct nfp_nbi_dev *nfpnbidev);

int nfp_nbi_index(struct nfp_nbi_dev *nfpnbidev);

#endif
