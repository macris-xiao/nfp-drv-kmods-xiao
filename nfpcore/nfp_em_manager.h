/*
 * Copyright (C) 2014-2015 Netronome Systems, Inc. All rights reserved.
 * Author: Jason McMullan <jason.mcmullan@netronome.com>
 *
 */

#ifndef NFP_EM_MANAGER_H
#define NFP_EM_MANAGER_H

#include <linux/spinlock.h>

#include "nfp_cpp.h"

struct nfp_em_manager;

struct nfp_em_manager *nfp_em_manager_create(void __iomem *em, int irq);
void nfp_em_manager_destroy(struct nfp_em_manager *evm);

int nfp_em_manager_acquire(struct nfp_em_manager *evm,
			   struct nfp_cpp_event *event,
			   uint32_t match, uint32_t mask, uint32_t type);
void nfp_em_manager_release(struct nfp_em_manager *evm, int filter);

#endif /* NFP_EM_MANAGER_H */
/* vim: set shiftwidth=8 noexpandtab:  */
