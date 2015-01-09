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

#ifndef NFP_PLATFORM_H
#define NFP_PLATFORM_H

#include <linux/platform_device.h>

#include "nfp_cpp.h"

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

#endif /* NFP_PLATFORM_H */
/* vim: set shiftwidth=8 noexpandtab:  */
