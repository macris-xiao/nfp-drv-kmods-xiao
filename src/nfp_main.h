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

#ifndef NFP_MAIN_H
#define NFP_MAIN_H

#include <linux/types.h>

/* Parameters visible to nfp3200_plat.c */

extern bool nfp_mon_err;
extern bool nfp_dev_cpp;
extern bool nfp_net_null;
extern bool nfp_net_vnic;

#endif /* NFP_MAIN_H */
/* vim: set shiftwidth=4 expandtab:  */
