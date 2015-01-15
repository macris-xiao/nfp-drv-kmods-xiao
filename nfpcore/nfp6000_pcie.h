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

#ifndef KERNEL_NFP6000_PCIE_H
#define KERNEL_NFP6000_PCIE_H

#include "nfp_cpp.h"

struct nfp_cpp *nfp_cpp_from_nfp6000_pcie(struct pci_dev *pdev, int event_irq);

#endif /* KERNEL_NFP6000_PCIE_H */
/* vim: set shiftwidth=8 noexpandtab:  */
