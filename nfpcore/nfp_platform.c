/*
 * Copyright (C) 2015 Netronome Systems, Inc. All rights reserved.
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

#include <linux/kernel.h>
#include <linux/device.h>
#include <linux/platform_device.h>

#include "nfp.h"
#include "nfp_cpp.h"

/**
 * nfp_platform_device_register_unit() - Multi-unit NFP CPP bus devices
 * @cpp:	NFP CPP handle
 * @type:	Platform driver name to match to
 * @unit:	Unit number of this device
 * @units:	Maximum units per NFP CPP bus
 *
 * NOTE: Use nfp_platform_device_unregister() to release the
 * struct platform_device.
 *
 * Return: struct platform_device *, or NULL
 */
struct platform_device *nfp_platform_device_register_unit(struct nfp_cpp *cpp,
						     const char *type,
						     int unit, int units)
{
	struct device *dev = nfp_cpp_device(cpp);
	struct platform_device *pdev;
	int id;
	int err;
	const struct nfp_platform_data pdata = {
		.cpp = cpp,
		.unit = unit,
	};

	id = nfp_cpp_device_id(cpp) * units + unit;

	pdev = platform_device_alloc(type, id);
	if (pdev == NULL) {
		dev_err(dev, "Can't create '%s.%d' platform device",
			type, id);
		return NULL;
	}

	pdev->dev.parent = dev;
	platform_device_add_data(pdev, &pdata, sizeof(pdata));

	err = platform_device_add(pdev);
	if (err < 0) {
		dev_err(dev, "Can't register '%s.%d' platform device",
			type, id);
		platform_device_put(pdev);
		return NULL;
	}

	return pdev;
}

/**
 * nfp_platform_device_register() - NFP CPP bus device registration
 * @cpp:	NFP CPP handle
 * @type:	Platform driver name to match to
 *
 * NOTE: Use nfp_platform_device_unregister() to release the
 * struct platform_device.
 *
 * Return: struct platform_device *, or NULL
 */
struct platform_device *nfp_platform_device_register(struct nfp_cpp *cpp,
						     const char *type)
{
	return nfp_platform_device_register_unit(cpp, type, 0, 1);
}

/**
 * nfp_platform_device_unregister() - Unregister a NFP CPP bus device
 * @pdev:	Platform device
 *
 */
void nfp_platform_device_unregister(struct platform_device *pdev)
{
	if (pdev)
		platform_device_unregister(pdev);
}
