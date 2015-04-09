/*
 * Copyright (C) 2012, Netronome Systems, Inc.  All rights reserved.
 *
 * @file          nfp_explicit.h
 * @brief         Interface for low-level NFP CPP access.
 *
 */
#ifndef __NFP_EXPLICIT_H__
#define __NFP_EXPLICIT_H__

#include "nfp_cpp.h"

/*
 * Return code masks for nfp_cpp_explicit_do()
 */
#define NFP_SIGNAL_MASK_A	(1 << 0)	/* Signal A fired */
#define NFP_SIGNAL_MASK_B	(1 << 1)	/* Signal B fired */

enum nfp_cpp_explicit_signal_mode {
	NFP_SIGNAL_NONE	= 0,
	NFP_SIGNAL_PUSH	= 1,
	NFP_SIGNAL_PUSH_OPTIONAL = -1,
	NFP_SIGNAL_PULL = 2,
	NFP_SIGNAL_PULL_OPTIONAL = -2,
};

struct nfp_cpp_explicit *nfp_cpp_explicit_acquire(struct nfp_cpp *cpp);
int nfp_cpp_explicit_set_target(struct nfp_cpp_explicit *expl, uint32_t cpp_id,
				uint8_t len, uint8_t mask);
int nfp_cpp_explicit_set_data(struct nfp_cpp_explicit *expl,
			      uint8_t data_master, uint16_t data_ref);
int nfp_cpp_explicit_set_signal(struct nfp_cpp_explicit *expl,
				uint8_t signal_master, uint8_t signal_ref);
int nfp_cpp_explicit_set_posted(struct nfp_cpp_explicit *expl, int posted,
				uint8_t siga,
				enum nfp_cpp_explicit_signal_mode siga_mode,
				uint8_t sigb,
				enum nfp_cpp_explicit_signal_mode sigb_mode);
int nfp_cpp_explicit_put(struct nfp_cpp_explicit *expl,
			 const void *buff, size_t len);
int nfp_cpp_explicit_do(struct nfp_cpp_explicit *expl, uint64_t address);
int nfp_cpp_explicit_get(struct nfp_cpp_explicit *expl, void *buff, size_t len);
void nfp_cpp_explicit_release(struct nfp_cpp_explicit *expl);
struct nfp_cpp *nfp_cpp_explicit_cpp(struct nfp_cpp_explicit *expl);

#endif /* __NFP_EXPLICIT_H__ */
