/*
 * Copyright (C) 2014, Netronome Systems, Inc.
 * All right reserved.
 * Author: Jason McMullan <jason.mcmullan@netronome.com>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 */

#ifndef NFP_CPPLIB_H
#define NFP_CPPLIB_H

#include <linux/platform_device.h>
#include "nfp_cpp_kernel.h"

#include "nfp3200/nfp3200.h"
#include "nfp6000/nfp6000.h"

int __nfp_cpp_model_autodetect(struct nfp_cpp *cpp, uint32_t *model);
int __nfp_cpp_model_fixup(struct nfp_cpp *cpp);

/* Helpers for the nfpXXXX_pcie.c interfaces */

static inline int __nfp_cpp_id_is_prefetchable(uint32_t cpp_id)
{
	return (NFP_CPP_ID_TARGET_of(cpp_id) == NFP_CPP_TARGET_MU &&
		(NFP_CPP_ID_ACTION_of(cpp_id) == NFP_CPP_ACTION_RW ||
		 NFP_CPP_ID_ACTION_of(cpp_id) == 0));
}

/* nfp_cppcore.c */

int nfp_cppcore_init(void);
void nfp_cppcore_exit(void);

struct platform_device *nfp_cpp_register_device(struct nfp_cpp *cpp,
						const char *type,
						const void *data,
						size_t data_len);
void nfp_cpp_unregister_device(struct platform_device *pdev);

#endif /* NFP_CPPLIB_H */
