/*
 * Copyright (C) 2010-2011,2014-2015  Netronome Systems, Inc.  All rights reserved.
 *
 * @file          nfp.h
 * @brief         Interface for NFP device access and query functions.
 *
 */
#ifndef __NFP_H__
#define __NFP_H__

#include <linux/device.h>

#include "kcompat.h"

#include "nfp_cpp.h"

#define PCI_64BIT_BAR_COUNT             3

/*
 * NFP hardware vendor/device ids.  Should be added to Linux.
 */
#define PCI_VENDOR_ID_NETRONOME		0x19ee
#define PCI_DEVICE_NFP3200		0x3200
#define PCI_DEVICE_NFP3240		0x3240
#define PCI_DEVICE_NFP6000		0x6000

#define NFP_CPP_NUM_TARGETS		16

#ifndef NFP_SUBSYS
#define NFP_SUBSYS ""
#endif

#define nfp_err(nfp, fmt, args...) \
	dev_err(nfp_cpp_device(nfp_device_cpp(nfp))->parent, NFP_SUBSYS fmt, ## args)
#define nfp_warn(nfp, fmt, args...) \
	dev_warn(nfp_cpp_device(nfp_device_cpp(nfp))->parent, NFP_SUBSYS fmt, ## args)
#define nfp_info(nfp, fmt, args...) \
	dev_info(nfp_cpp_device(nfp_device_cpp(nfp))->parent, NFP_SUBSYS fmt, ## args)
#define nfp_dbg(nfp, fmt, args...) \
	dev_dbg(nfp_cpp_device(nfp_device_cpp(nfp))->parent, NFP_SUBSYS fmt, ## args)
#define nfp_trace(nfp, fmt, args...) \
	trace_printk("%s %s: " NFP_SUBSYS fmt, \
			dev_driver_string(nfp_cpp_device(nfp_device_cpp(nfp))->parent, \
			dev_name(nfp_cpp_device(nfp_device_cpp(nfp))->parent, ## args)

struct nfp_cpp;

/* Opaque NFP device handle. */
struct nfp_device;

/* Maximum device number for an NFP device. */
#define NFP_MAX_DEVICE_NUM              63

/* Implemented in nfp_device.c */

struct nfp_device *nfp_device_open(unsigned int devnum);
struct nfp_device *nfp_device_from_cpp(struct nfp_cpp *cpp);
void nfp_device_close(struct nfp_device *dev);

int nfp_device_id(struct nfp_device *nfp);
struct nfp_cpp *nfp_device_cpp(struct nfp_device *dev);

void *nfp_device_private(struct nfp_device *dev,
			 void *(*constructor) (struct nfp_device * dev));
void *nfp_device_private_alloc(struct nfp_device *dev, size_t private_size,
			       void (*destructor) (void *private_data));

/* Implemented in nfp_platform.c */

/**
 * struct nfp_platform_data - Per-device data
 * @cpp:	NFP CPP handle
 * @unit:	Device unit number
 */
struct nfp_platform_data {
	struct nfp_cpp *cpp;
	int unit;
};

#define nfp_platform_device_data(pdev)	((pdev)->dev.platform_data)

struct platform_device *nfp_platform_device_register_unit(struct nfp_cpp *cpp,
							  const char *type,
							  int unit, int units);
struct platform_device *nfp_platform_device_register(struct nfp_cpp *cpp,
						     const char *type);
void nfp_platform_device_unregister(struct platform_device *pdev);


#endif /* !__NFP_H__ */
