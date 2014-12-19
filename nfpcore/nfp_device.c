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
 * vim:shiftwidth=8:noexpandtab
 *
 * @file kernel/nfp_device.c
 *
 * The NFP CPP device wrapper
 */

#include <linux/version.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/init.h>
#include <linux/pci.h>
#include <linux/interrupt.h>
#include <linux/io.h>
#include <linux/ctype.h>

#include "nfp.h"

#include "nfp3200/nfp3200.h"
#include "nfp3200/nfp_xpb.h"

#include "nfp_common.h"
#include "nfp_hwinfo.h"

#include "nfp_device.h"

struct nfp_device_private {
	 struct list_head entry;
	 void *(*constructor)(struct nfp_device *dev);
	 void (*destructor)(void *priv);
	 /* Data is allocated immediately after */
};

/**
 * nfp_device_cpp - Get the CPP handle from a struct nfp_device
 * @nfp:	NFP device
 *
 * NOTE: Do not call nfp_cpp_free() on the returned handle,
 * 	as it is owned by the NFP device.
 */
struct nfp_cpp *nfp_device_cpp(struct nfp_device *nfp)
{
		return nfp->cpp;
}
EXPORT_SYMBOL(nfp_device_cpp);

/**
 * nfp_device_from_cpp - Construct a NFP device from a CPP handle
 * @cpp:	CPP handle
 */
struct nfp_device *nfp_device_from_cpp(struct nfp_cpp *cpp)
{
		int err = -ENODEV;
		struct nfp_device *nfp;

		nfp = kzalloc(sizeof(*nfp), GFP_KERNEL);
		if (!nfp) {
			err = -ENOMEM;
			goto err_nfp_alloc;
		}
		nfp->cpp = cpp;

		spin_lock_init(&nfp->private_lock);
		INIT_LIST_HEAD(&nfp->private_list);

		err = nfp_hwinfo_init(nfp);
		if (err) {
			dev_info(nfp_cpp_device(cpp), "NFP is unconfigured, ignoring this device.\n");
			goto err_hwinfo;
		}

		/*  Finished with card initialization. */
		dev_info(nfp_cpp_device(cpp),
			 "Netronome Flow Processor (NFP) 10-gigabit device.\n");
		return nfp;

err_hwinfo:
		kfree(nfp);
err_nfp_alloc:
		return NULL;
}
EXPORT_SYMBOL(nfp_device_from_cpp);

/**
 * nfp_device_close - Close a NFP device
 */
void nfp_device_close(struct nfp_device *nfp)
{
		struct nfp_device_private *priv;

		while (!list_empty(&nfp->private_list)) {
			priv = list_first_entry(&nfp->private_list,
						struct nfp_device_private,
						entry);
			list_del(&priv->entry);
			if (priv->destructor)
				priv->destructor(&priv[1]);
			kfree(priv);
		}

		nfp_hwinfo_cleanup(nfp);

		if (nfp->cpp_free)
			nfp_cpp_free(nfp->cpp);
		kfree(nfp);
}
EXPORT_SYMBOL(nfp_device_close);

/**
 * nfp_device_open - Open a NFP device by ID
 * @id:		NFP device ID
 */
struct nfp_device *nfp_device_open(unsigned int id)
{
		struct nfp_cpp *cpp;
		struct nfp_device *nfp;

		cpp = nfp_cpp_from_device_id(id);
		if (cpp == NULL)
			return NULL;

		nfp = nfp_device_from_cpp(cpp);
		if (nfp == NULL) {
			nfp_cpp_free(cpp);
			return NULL;
		}

		nfp->cpp_free = 1;
		return nfp;
}
EXPORT_SYMBOL(nfp_device_open);

/**
 * nfp_device_id - Get the device ID from a NFP handle
 * @nfp:	NFP device
 */
int nfp_device_id(struct nfp_device *nfp)
{
		return nfp_cpp_device_id(nfp->cpp);
}
EXPORT_SYMBOL(nfp_device_id);

/**
 * nfp_device_private - Allocate private memory for a NFP device
 * @dev:		NFP device
 * @constructor:	Constructor for the private area
 *
 * Returns a private memory area, identified by the constructor,
 * that will atomatically be freed on nfp_device_close().
 */
void *nfp_device_private(struct nfp_device *dev,
				 void *(*constructor)(struct nfp_device *dev))
{
	struct nfp_device_private *priv;

	spin_lock(&dev->private_lock);
	list_for_each_entry(priv, &dev->private_list, entry) {
		if (priv->constructor == constructor) {
			/* Return the data after the entry's metadata */
			spin_unlock(&dev->private_lock);
			return &priv[1];
		}
	}
	spin_unlock(&dev->private_lock);

	priv = constructor(dev);
	if (priv) {
		/* Set the constructor in the metadata */
		priv[-1].constructor = constructor;
	}

	return priv;
}
EXPORT_SYMBOL(nfp_device_private);

/**
 * nfp_device_private_alloc - Constructor allocation method
 * @dev:		NFP device
 * @private_size:	Size to allocate
 * @destructor:		Destructor function to call on device close, or NULL
 *
 * Allocate your private area - must be called in the constructor
 * function passed to nfp_device_private().
 */
void *nfp_device_private_alloc(struct nfp_device *dev,
		size_t private_size,
		void (*destructor)(void *private_data))
{
	struct nfp_device_private *priv;

	priv = kzalloc(sizeof(*priv) + private_size, GFP_KERNEL);
	if (!priv)
		return NULL;

	priv->destructor = destructor;
	spin_lock(&dev->private_lock);
	list_add(&priv->entry, &dev->private_list);
	spin_unlock(&dev->private_lock);
	return &priv[1];
}
EXPORT_SYMBOL(nfp_device_private_alloc);

/*
 * Local variables:
 * c-file-style: "Linux"
 * indent-tabs-mode: t
 * End:
 */
