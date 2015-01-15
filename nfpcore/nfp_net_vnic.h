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
 *
 */

#ifndef NFP_NET_VNIC_H
#define NFP_NET_VNIC_H

#define NFP_NET_VNIC_TYPE	"nfp-net-vnic"
#define NFP_NET_VNIC_UNITS	4

int nfp_net_vnic_init(void);
void nfp_net_vnic_exit(void);

#endif /* NFP_NET_VNIC_H */
/* vim: set shiftwidth=8 noexpandtab:  */
