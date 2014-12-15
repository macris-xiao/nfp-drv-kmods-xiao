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

/**
 * @defgroup nfparm-only NFP features only available via the NFP ARM
 */

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

/**
 * Acquire explicit access handle
 *
 * @param cpp		NFP CPP handle
 *
 * @return struct nfp_cpp_explicit * on success, NULL on failure (and set errno accordingly).
 */
struct nfp_cpp_explicit *nfp_cpp_explicit_acquire(struct nfp_cpp *cpp);

/**
 * Set the NFP CPP target for an explicit transaction
 *
 * @param expl		NFP CPP Explicit transation
 * @param cpp_id	NFP CPP ID of the target/action/token
 * @param len		NFP CPP 'len' - specified in the databook for the cpp_id
 * @param mask		NFP CPP 'bytemask' - specified in the databook for the cpp_id
 *
 * @return 0 on success, -1 on failure (and set errno accordingly).
 */
int nfp_cpp_explicit_set_target(struct nfp_cpp_explicit *expl, uint32_t cpp_id,
				uint8_t len, uint8_t mask);

/**
 * @ingroup nfparm-only
 * Set the NFP CPP data push/pull destination for an explicit transaction
 *
 * @param expl		NFP CPP Explicit transation
 * @param data_master	NFP CPP data master ID
 * @param data_ref	NFP CPP data_ref for the the master
 *
 * NOTE: This function only affects NFP3200 transactions
 *
 * NOTE: If data_master is set to anything other than NFP_CPP_MASTER_ARM,
 *       then nfp_cpp_explicit_put/get will be unavailable.
 *
 * @return 0 on success, -1 on failure (and set errno accordingly).
 */
int nfp_cpp_explicit_set_data(struct nfp_cpp_explicit *expl,
			      uint8_t data_master, uint16_t data_ref);

/**
 * Set the NFP CPP target for an explicit transaction
 *
 * @param expl		NFP CPP Explicit transation
 * @param signal_master	NFP CPP master ID that will recieve the signals
 * @param signal_ref	NFP CPP reference signal base
 *
 * @return 0 on success, -1 on failure (and set errno accordingly).
 */
int nfp_cpp_explicit_set_signal(struct nfp_cpp_explicit *expl,
				uint8_t signal_master, uint8_t signal_ref);

/**
 * Set the NFP CPP target for an explicit transaction
 *
 * @param expl		NFP CPP Explicit transation
 * @param posted	Set to 1 to wait for transaction to complete
 * @param siga		NFP CPP signal id (one of two)
 * @param siga_mode	NFP CPP signal direction
 * @param sigb		NFP CPP signal id (one of two)
 * @param sigb_mode	NFP CPP signal direction
 *
 * @return 0 on success, -1 on failure (and set errno accordingly).
 */
int nfp_cpp_explicit_set_posted(struct nfp_cpp_explicit *expl, int posted,
				uint8_t siga,
				enum nfp_cpp_explicit_signal_mode siga_mode,
				uint8_t sigb,
				enum nfp_cpp_explicit_signal_mode sigb_mode);


/**
 * Set up the write (pull) data for a NFP CPP explicit access
 *
 * @param expl		NFP CPP Explicit handle
 * @param buff		Data to have the target pull in the transaction
 * @param len		Length of data, in bytes
 *
 * The 'len' parameter must be less than or equal to 128 bytes.
 *
 * If this function is called before the configuration
 * registers are set, it will return -1, with an errno of EINVAL.
 *
 * @return 0 on success, -1 on failure (and set errno accordingly).
 */
int nfp_cpp_explicit_put(struct nfp_cpp_explicit *expl,
			 const void *buff, size_t len);

/**
 * Execute a transaction, and wait for it to complete
 *
 * @param expl		NFP CPP Explicit handle
 * @param address	Address to send in the explicit transaction
 *
 * If this function is called before the configuration
 * registers are set, it will return -1, with an errno of EINVAL.
 *
 * @return >= 0 on success, -1 on failure (and set errno accordingly).
 *  returns NFP_SIGNAL_MASK of the received signals
 */
int nfp_cpp_explicit_do(struct nfp_cpp_explicit *expl, uint64_t address);

/**
 * Get the 'push' (read) data from a NFP CPP explicit access
 *
 * @param expl		NFP CPP Explicit handle
 * @param buff		Data that the target pushed in the transaction
 * @param len		Length of data, in bytes
 *
 * The 'len' parameter must be less than or equal to 128 bytes.
 *
 * If this function is called before all three configuration
 * registers are set, it will return -1, with an errno of EINVAL.
 *
 * If this function is called before nfp_cpp_explicit_wait()
 * has completed, it will return -1, with an errno of EBUSY.
 *
 * @return 0 on success, -1 on failure (and set errno accordingly).
 */
int nfp_cpp_explicit_get(struct nfp_cpp_explicit *expl, void *buff, size_t len);

/**
 * Release explicit access handle
 *
 * @param expl		NFP CPP Explicit handle
 *
 */
void nfp_cpp_explicit_release(struct nfp_cpp_explicit *expl);

/**
 * Get the NFP CPP handle that is the parent of a NFP CPP explicit handle
 *
 * @param	expl		NFP CPP explicit handle
 * @return			NFP CPP handle
 */
struct nfp_cpp *nfp_cpp_explicit_cpp(struct nfp_cpp_explicit *expl);

#endif /* __NFP_EXPLICIT_H__ */
