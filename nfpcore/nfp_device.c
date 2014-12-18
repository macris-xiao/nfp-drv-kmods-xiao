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
#include "nfp_mip.h"
#include "nfp_rtsym.h"

#include "nfp_device.h"

struct nfp_device_private {
	 struct list_head entry;
	 void *(*constructor)(struct nfp_device *dev);
	 void (*destructor)(void *priv);
	 /* Data is allocated immediately after */
};

struct nfp_cpp *nfp_device_cpp(struct nfp_device *nfp)
{
		return nfp->cpp;
}

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

		err = nfp_miptab_init(nfp);
		if (err) {
			dev_err(nfp_cpp_device(cpp), "Can't initialize MIP\n");
			goto err_mip;
		}

		err = nfp_rtsymtab_init(nfp);
		if (err) {
			dev_err(nfp_cpp_device(cpp), "Can't initialize symtab\n");
			goto err_rtsymtab;
		}

		/*  Finished with card initialization. */
		dev_info(nfp_cpp_device(cpp),
			 "Netronome Flow Processor (NFP) 10-gigabit device.\n");
		return nfp;

err_rtsymtab:
		nfp_miptab_cleanup(nfp);
err_mip:
		nfp_hwinfo_cleanup(nfp);
err_hwinfo:
		kfree(nfp);
err_nfp_alloc:
		return NULL;
}
EXPORT_SYMBOL(nfp_device_from_cpp);

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

		nfp_rtsymtab_cleanup(nfp);
		nfp_miptab_cleanup(nfp);
		nfp_hwinfo_cleanup(nfp);

		if (nfp->cpp_free)
			nfp_cpp_free(nfp->cpp);
		kfree(nfp);
}
EXPORT_SYMBOL(nfp_device_close);

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

int nfp_device_id(struct nfp_device *nfp)
{
		return nfp_cpp_device_id(nfp->cpp);
}
EXPORT_SYMBOL(nfp_device_id);

/**
 * Return a private memory area, identified by the constructor,
 * that will atomatically be freed on nfp_device_close().
 *
 * @param dev           NFP device
 * @param constructor   Constructor for the private area
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
 * Allocate your private area - must be called in the constructor
 * function passed to nfp_device_private().
 *
 * @param dev           NFP device
 * @param private_size  Size to allocate
 * @param destructor    Destructor function to call on device close, or NULL
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
