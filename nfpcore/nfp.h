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
struct nfp_chipdata_chip;

/** Maximum device number for an NFP device. */
#define NFP_MAX_DEVICE_NUM              63

/**
 * Get a mask of valid NFP device numbers.
 *
 * @return bitmask indicating which device numbers are valid.
 */
uint64_t nfp_device_mask(void);

/**
 * Get number of NFP devices in the system.
 *
 * The device numbering may be non-contigous.  Use nfp_device_mask()
 * to determine which device numbers are valid.
 *
 * @return number of valid NFP devices.
 */
int nfp_num_devices(void);

/**
 * Open NFP device.
 *
 * @param devnum        NFP device number
 *
 * @return device struct pointer, or NULL on failure (and set errno
 * accordingly).
 */
struct nfp_device *nfp_device_open(unsigned int devnum);

/**
 * Create NFP device handle using pre-existing CPP handle
 *
 * @param cpp           NFP CPP handle
 *
 * @return device struct pointer, or NULL on failure (and set errno
 * accordingly).
 */
struct nfp_device *nfp_device_from_cpp(struct nfp_cpp *cpp);

/**
 * Free up resources and close NFP device.
 *
 * @param dev           NFP device
 */
void nfp_device_close(struct nfp_device *dev);

/**
 * Get device number.
 *
 * @param dev           NFP device
 */
int nfp_device_number(struct nfp_device *dev);

/**
 * Get NFP CPP access handle.
 *
 * @param dev           NFP device
 *
 * @return NFP CPP handle, or NULL on failure (and set errno
 * accordingly).
 */
struct nfp_cpp *nfp_device_cpp(struct nfp_device *dev);

/**
 * Get NFP ChipData chip handle for the given device.
 *
 * @param dev           NFP device
 *
 * @return NFP ChipData chip handle, or NULL on failure (and set errno
 * accordingly).
 */
const struct nfp_chipdata_chip *nfp_device_chip(struct nfp_device *dev);

/**
 * Return a private memory area, identified by the constructor,
 * that will atomatically be freed on nfp_device_close().
 *
 * @param dev           NFP device
 * @param constructor   Constructor for the private area
 */
void *nfp_device_private(struct nfp_device *dev,
			 void *(*constructor) (struct nfp_device * dev));

/**
 * Allocate your private area - must be called in the constructor
 * function passed to nfp_device_private().
 *
 * @param dev           NFP device
 * @param private_size  Size to allocate
 * @param destructor    Destructor function to call on device close, or NULL
 */
void *nfp_device_private_alloc(struct nfp_device *dev, size_t private_size,
			       void (*destructor) (void *private_data));

/**
 * Perform an advisory trylock on the NFP device
 *
 * @param dev           NFP device
 *
 * @return 0 on success, or -1 on error (and set errno accordingly)
 */
int nfp_device_trylock(struct nfp_device *dev);

/**
 * Perform an advisory lock on the NFP device
 *
 * @param dev           NFP device
 *
 * @return 0 on success, or -1 on error (and set errno accordingly)
 */
int nfp_device_lock(struct nfp_device *dev);

/**
 * Perform an advisory unlock on the NFP device
 *
 * @param dev           NFP device
 *
 * @return 0 on success, or -1 on error (and set errno accordingly)
 */
int nfp_device_unlock(struct nfp_device *dev);

#endif /* !__NFP_H__ */
