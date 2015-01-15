/*
 * Copyright (C) 2014-2015 Netronome Systems, Inc. All rights reserved.
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
 */

#include <linux/kernel.h>
#include <linux/delay.h>

#include "nfp_common.h"
#include "nfp_cpp.h"
#include "nfp_ca.h"

#include "crc32.h"

int nfp_ca_cb_cpp(void *priv, enum nfp_ca_action action,
		  uint32_t cpp_id, uint64_t cpp_addr, uint64_t val)
{
	struct nfp_cpp *cpp = priv;
	uint32_t tmp32;
	uint64_t tmp64;
	static unsigned int cnt;
	int timeout = 10;
	int poll_action = 0;
	int bit_len = 0;
	int err;

	switch (action) {
	case NFP_CA_ACTION_POLL32:
	case NFP_CA_ACTION_POLL64:
		timeout = 100; /* Allow 2 seconds for a poll before failing. */
		poll_action = 1;
		/* Fall through */

	case NFP_CA_ACTION_READ32:
	case NFP_CA_ACTION_READ64:
		do {
			if ((action == NFP_CA_ACTION_READ32) ||
			    (action == NFP_CA_ACTION_POLL32))
				bit_len = 32;
			else
				bit_len = 64;

			if (bit_len == 32) {
				err = nfp_cpp_readl(cpp, cpp_id,
						    cpp_addr, &tmp32);
				tmp64 = tmp32;
			} else {
				err = nfp_cpp_readq(cpp, cpp_id,
						    cpp_addr, &tmp64);
			}
			if (err < 0)
				break;

			if (val != tmp64) {
				msleep(20);
				timeout--;
			} else {
				break;
			}
		} while (timeout > 0);
		if (timeout == 0) {
			dev_warn(nfp_cpp_device(cpp),
				 "%sMISMATCH[%u]: %c%d 0x%08x 0x%010llx 0x%0*llx != 0x%0*llx\n",
				 (poll_action) ? "FATAL " : "", cnt,
				 (poll_action) ? 'P' : 'R',
				 bit_len, cpp_id, (unsigned long long)cpp_addr,
				 (bit_len == 32) ? 8 : 16,
				 (unsigned long long)val,
				 (bit_len == 32) ? 8 : 16,
				 (unsigned long long)tmp64);

			if (poll_action)
				err = -ETIMEDOUT;
			else
				err = 0;
		}
		break;

	case NFP_CA_ACTION_READ_IGNV32:
		err = nfp_cpp_readl(cpp, cpp_id, cpp_addr, &tmp32);
		break;
	case NFP_CA_ACTION_READ_IGNV64:
		err = nfp_cpp_readq(cpp, cpp_id, cpp_addr, &tmp64);
		break;
	case NFP_CA_ACTION_WRITE32:
		err = nfp_cpp_writel(cpp, cpp_id, cpp_addr, val);
		break;
	case NFP_CA_ACTION_WRITE64:
		err = nfp_cpp_writeq(cpp, cpp_id, cpp_addr, val);
		break;
	default:
		err = -EINVAL;
		break;
	}

	cnt++;
	return err;
}

static int cb_check(void *priv, enum nfp_ca_action action,
		    uint32_t cpp_id, uint64_t cpp_addr, uint64_t val)
{
	return 0;
}

#define NFP_CA_SZ(ca) (1 + NFP_CA_LEN(ca)*4)

int nfp_ca_replay(const void *buff, size_t bytes,
		  nfp_ca_callback cb, void *cb_priv)
{
	const uint8_t *byte = buff;
	uint32_t cpp_id = 0;
	uint64_t cpp_addr = 0;
	size_t loc;
	uint8_t ca;
	int err = -EINVAL;

	/* File too small? */
	if (bytes < (NFP_CA_SZ(NFP_CA_START) + NFP_CA_SZ(NFP_CA_END)))
		return -EINVAL;

	ca = byte[0];
	if (ca != NFP_CA_START || ca32_to_cpu(&byte[1]) != NFP_CA_START_MAGIC)
		return -EINVAL;

	if (cb != cb_check) {
		err = nfp_ca_replay(byte, bytes, cb_check, NULL);
		if (err < 0)
			return err;
	}

	for (loc = NFP_CA_SZ(NFP_CA_START); loc < bytes;
			loc += NFP_CA_SZ(byte[loc])) {
		const uint8_t *vp = &byte[loc+1];
		uint32_t tmp32;
		uint64_t tmp64;

		ca = byte[loc];
		if (ca == NFP_CA_END) {
			loc += NFP_CA_SZ(NFP_CA_END);
			break;
		}

		switch (ca) {
		case NFP_CA_CPP_ID:
			cpp_id = ca32_to_cpu(vp);
			err = 0;
			break;
		case NFP_CA_CPP_ADDR:
			cpp_addr = ca64_to_cpu(vp);
			err = 0;
			break;
		case NFP_CA_INC_READ_4:
			cpp_addr += 4;
			/* FALLTHROUGH */
		case NFP_CA_READ_4:
			tmp32 = ca32_to_cpu(vp);
			err = cb(cb_priv, NFP_CA_ACTION_READ32,
				 cpp_id, cpp_addr, tmp32);
			break;
		case NFP_CA_INC_READ_8:
			cpp_addr += 8;
			/* FALLTHROUGH */
		case NFP_CA_READ_8:
			tmp64 = ca64_to_cpu(vp);
			err = cb(cb_priv, NFP_CA_ACTION_READ64,
				 cpp_id, cpp_addr, tmp64);
			break;
		case NFP_CA_POLL_4:
			tmp32 = ca32_to_cpu(vp);
			err = cb(cb_priv, NFP_CA_ACTION_POLL32,
				 cpp_id, cpp_addr, tmp32);
			break;
		case NFP_CA_POLL_8:
			tmp64 = ca64_to_cpu(vp);
			err = cb(cb_priv, NFP_CA_ACTION_POLL64,
				 cpp_id, cpp_addr, tmp64);
			break;
		case NFP_CA_INC_READ_IGNV_4:
			cpp_addr += 4;
			/* FALLTHROUGH */
		case NFP_CA_READ_IGNV_4:
			tmp32 = ca32_to_cpu(vp);
			err = cb(cb_priv, NFP_CA_ACTION_READ_IGNV32,
				 cpp_id, cpp_addr, tmp32);
			break;
		case NFP_CA_INC_READ_IGNV_8:
			cpp_addr += 8;
			/* FALLTHROUGH */
		case NFP_CA_READ_IGNV_8:
			tmp64 = ca64_to_cpu(vp);
			err = cb(cb_priv, NFP_CA_ACTION_READ_IGNV64,
				 cpp_id, cpp_addr, tmp64);
			break;
		case NFP_CA_INC_WRITE_4:
		case NFP_CA_INC_ZERO_4:
			cpp_addr += 4;
			/* FALLTHROUGH */
		case NFP_CA_WRITE_4:
		case NFP_CA_ZERO_4:
			if (ca == NFP_CA_INC_ZERO_4 || ca == NFP_CA_ZERO_4)
				tmp32 = 0;
			else
				tmp32 = ca32_to_cpu(vp);
			err = cb(cb_priv, NFP_CA_ACTION_WRITE32,
				 cpp_id, cpp_addr, tmp32);
			break;
		case NFP_CA_INC_WRITE_8:
		case NFP_CA_INC_ZERO_8:
			cpp_addr += 8;
			/* FALLTHROUGH */
		case NFP_CA_WRITE_8:
		case NFP_CA_ZERO_8:
			if (ca == NFP_CA_INC_ZERO_8 || ca == NFP_CA_ZERO_8)
				tmp64 = 0;
			else
				tmp64 = ca64_to_cpu(vp);
			err = cb(cb_priv, NFP_CA_ACTION_WRITE64,
				 cpp_id, cpp_addr, tmp64);
			break;
		default:
			err = -EINVAL;
			break;
		}
		if (err < 0)
			break;
	}

	if (err >= 0 && ca == NFP_CA_END && loc == bytes) {
		if (cb == cb_check) {
			uint32_t crc;

			loc -= NFP_CA_SZ(NFP_CA_END);
			crc = crc32_posix(byte, loc);
			if (crc != ca32_to_cpu(&byte[loc+1]))
				return -EINVAL;
		}
		err = 0;
	} else if (err >= 0) {
		err = -EINVAL;
	}

	return err;
}

/* vim: set shiftwidth=8 noexpandtab:  */
/*
 * Local variables:
 * c-file-style: "Linux"
 * indent-tabs-mode: t
 * End:
 */
