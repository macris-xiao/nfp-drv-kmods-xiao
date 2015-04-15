/*
 * Copyright (C) 2014-2015, Netronome, Inc.
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

#ifndef LIBNFP_NFP3200_PLAT_H
#define LIBNFP_NFP3200_PLAT_H

#ifdef CONFIG_ARCH_NFP
int nfp3200_plat_init(void);
void nfp3200_plat_exit(void);
#else
static int nfp3200_plat_init(void) { return 0; }
static void nfp3200_plat_exit(void) { return; }
#endif

#endif /* LIBNFP_NFP3200_PLAT_H */
