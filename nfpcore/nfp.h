/*
 * Copyright (C) 2010-2011,2014-2015  Netronome Systems, Inc.  All rights reserved.
 *
 * @file          nfp.h
 * @brief         Interface for NFP device access and query functions.
 *
 */
#ifndef __NFP_H__
#define __NFP_H__

#include "nfp_cpp_kernel.h"

/** Opaque NFP device handle. */
struct nfp_device;
struct nfp_cpp;

/** Maximum device number for an NFP device. */
#define NFP_MAX_DEVICE_NUM              63

struct nfp_device *nfp_device_open(unsigned int devnum);
struct nfp_device *nfp_device_from_cpp(struct nfp_cpp *cpp);
void nfp_device_close(struct nfp_device *dev);

int nfp_device_id(struct nfp_device *nfp);
struct nfp_cpp *nfp_device_cpp(struct nfp_device *dev);

void *nfp_device_private(struct nfp_device *dev,
			 void *(*constructor) (struct nfp_device * dev));
void *nfp_device_private_alloc(struct nfp_device *dev, size_t private_size,
			       void (*destructor) (void *private_data));

#endif /* !__NFP_H__ */
