/* Copyright (C) 2011 Netronome Systems, Inc. All rights reserved.
 *
 * This software may be redistributed under either of two provisions:
 *
 * 1. The GNU General Public License version 2 (see
 *    http://www.gnu.org/licenses/old-licenses/gpl-2.0.html or
 *    COPYING.txt file) when it is used for Linux or other
 *    compatible free software as defined by GNU at
 *    http://www.gnu.org/licenses/license-list.html.
 *
 * 2. Or under a non-free commercial license executed directly with
 *    Netronome. The direct Netronome license does not apply when the
 *    software is used as part of the Linux kernel.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
 *
 * Common declarations for the NFP drivers.
 */
#ifndef __KERNEL__NFP_H__
#define __KERNEL__NFP_H__

#include <linux/version.h>
#include <linux/pci.h>
#include <linux/device.h>
#include <linux/cdev.h>
#include <linux/sched.h>
#include <linux/mutex.h>
#include <linux/wait.h>
#include <linux/spinlock.h>
#include <linux/list.h>
#include <linux/slab.h>
#include <linux/module.h>

#include "nfp_cpp_kernel.h"

#include "kcompat.h"

#define PCI_64BIT_BAR_COUNT             3

struct nfp_device;

/*
 * NFP hardware vendor/device ids.  Should be added to Linux.
 */
#define PCI_VENDOR_ID_NETRONOME		0x19ee
#define PCI_DEVICE_NFP3200		0x3200
#define PCI_DEVICE_NFP3240		0x3240
#define PCI_DEVICE_NFP6000		0x6000

#define NFP_CPP_NUM_TARGETS		16

#endif  /* __KERNEL__NFP_H__ */
