/*
 * Copyright (C) 2014 Netronome Systems, Inc. All rights reserved.
 * Author: Jason McMullan <jason.mcmullan@netronome.com>
 *
 */

#ifndef NFP_EM_MANAGER_H
#define NFP_EM_MANAGER_H

#include <linux/spinlock.h>

#include "nfp_cpp.h"

struct nfp_em_manager {
	spinlock_t lock;	/* Lock for the event filters */
	int irq;
	void __iomem *em;
	struct {
		uint32_t match;
		uint32_t mask;
		int type;
		struct nfp_cpp_event *event;
	} filter[32];
};

/**
 * Initialize the event manager struct
 */
int nfp_em_manager_init(struct nfp_em_manager *evm, void __iomem *em, int irq);

/**
 * Release resources attached to the event manager
 */
void nfp_em_manager_exit(struct nfp_em_manager *evm);

/**
 * Acquire an event filter slot
 */
int nfp_em_manager_acquire(struct nfp_em_manager *evm,
			   struct nfp_cpp_event *event,
			   uint32_t match, uint32_t mask, uint32_t type);

/**
 * Release an event filter slot
 */
void nfp_em_manager_release(struct nfp_em_manager *evm, int filter);

#endif /* NFP_EM_MANAGER_H */
/* vim: set shiftwidth=8 noexpandtab:  */
