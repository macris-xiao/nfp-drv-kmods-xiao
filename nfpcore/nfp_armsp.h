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

#ifndef NFP_ARMSP_H
#define NFP_ARMSP_H

#include "nfp.h"

#define SPCODE_NOOP             0       /* No operation */
#define SPCODE_SOFT_RESET       1       /* Soft reset the NFP */
#define SPCODE_FW_DEFAULT       2       /* Load default (UNDI) FW */
#define SPCODE_PHY_INIT         3       /* Initialize the PHY */
#define SPCODE_MAC_INIT         4       /* Initialize the MAC */
#define SPCODE_PHY_RXADAPT      5       /* Re-run PHY RX Adaptation */

int nfp_armsp_command(struct nfp_device *nfp, uint16_t spcode);

#endif /* NFP_ARMSP_H */
