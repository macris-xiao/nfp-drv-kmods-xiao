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

#include "nfp_cpp_kernel.h"
#include "nfp_platform.h"

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

struct platform_device *nfp_platform_device_register(struct nfp_cpp *cpp,
						     const char *type)
{
	return nfp_platform_device_register_unit(cpp, type, 0, 1);
}

void nfp_platform_device_unregister(struct platform_device *pdev)
{
	if (pdev)
		platform_device_unregister(pdev);
}

/* vim: set shiftwidth=8 noexpandtab:  */
