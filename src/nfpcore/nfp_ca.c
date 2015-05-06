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
#include <linux/zlib.h>
#include <linux/slab.h>
#include <linux/vmalloc.h>

#include "nfp.h"
#include "nfp_cpp.h"

#include "crc32.h"

/* up to 32 IDs, and up to 7 words of control information */
#define NFP_CA_(id)         ((id) << 3)
#define NFP_CA(id, type)    (NFP_CA_(id) | (sizeof(type) / sizeof(uint32_t)))
#define NFP_CA_LEN(ca)      ((ca) & 0x7)
#define NFP_CA_SZ(ca)       (1 + NFP_CA_LEN(ca) * 4)

struct nfp_ca_start {
	uint32_t magic;
	uint32_t bytes;
};

#define NFP_CA_START_MAGIC  0x0066424e  /* "NBf\000" */
#define NFP_CA_ZSTART_MAGIC 0x007a424e  /* "NBz\000" - zlib compressed */

#define NFP_CA_START        NFP_CA(0, struct nfp_ca_start)
#define NFP_CA_END          NFP_CA(0, uint32_t) /* u32 is CRC32 */

#define NFP_CA_CPP_ID       NFP_CA(1, uint32_t)
#define NFP_CA_CPP_ADDR     NFP_CA(2, uint64_t)
#define NFP_CA_READ_4       NFP_CA(3, uint32_t)
#define NFP_CA_READ_8       NFP_CA(4, uint64_t)
#define NFP_CA_WRITE_4      NFP_CA(5, uint32_t)
#define NFP_CA_WRITE_8      NFP_CA(6, uint64_t)
#define NFP_CA_INC_READ_4   NFP_CA(7, uint32_t)
#define NFP_CA_INC_READ_8   NFP_CA(8, uint64_t)
#define NFP_CA_INC_WRITE_4  NFP_CA(9, uint32_t)
#define NFP_CA_INC_WRITE_8  NFP_CA(10, uint64_t)
#define NFP_CA_ZERO_4       NFP_CA_(11)
#define NFP_CA_ZERO_8       NFP_CA_(12)
#define NFP_CA_INC_ZERO_4   NFP_CA_(13)
#define NFP_CA_INC_ZERO_8   NFP_CA_(14)
#define NFP_CA_READ_IGNV_4  NFP_CA(15, uint32_t) /* Ignore read value */
#define NFP_CA_READ_IGNV_8  NFP_CA(16, uint64_t)
#define NFP_CA_INC_READ_IGNV_4  NFP_CA(17, uint32_t)
#define NFP_CA_INC_READ_IGNV_8  NFP_CA(18, uint64_t)
#define NFP_CA_POLL_4           NFP_CA(19, uint32_t)
#define NFP_CA_POLL_8           NFP_CA(20, uint64_t)
#define NFP_CA_MASK_4           NFP_CA(21, uint32_t)
#define NFP_CA_MASK_8           NFP_CA(22, uint64_t)

static inline void cpu_to_ca32(uint8_t *byte, uint32_t val)
{
	int i;

	for (i = 0; i < 4; i++)
		byte[i] = (val >> (8 * i)) & 0xff;
}

static inline uint32_t ca32_to_cpu(const uint8_t *byte)
{
	int i;
	uint32_t val = 0;

	for (i = 0; i < 4; i++)
		val |= ((uint32_t)byte[i]) << (8 * i);

	return val;
}

static inline uint64_t ca64_to_cpu(const uint8_t *byte)
{
	int i;
	uint64_t val = 0;

	for (i = 0; i < 8; i++)
		val |= ((uint64_t)byte[i]) << (8 * i);

	return val;
}

enum nfp_ca_action {
	NFP_CA_ACTION_NONE          = 0,
	NFP_CA_ACTION_READ32        = 1,
	NFP_CA_ACTION_READ64        = 2,
	NFP_CA_ACTION_WRITE32       = 3,
	NFP_CA_ACTION_WRITE64       = 4,
	NFP_CA_ACTION_READ_IGNV32   = 5, /* Read and ignore value */
	NFP_CA_ACTION_READ_IGNV64   = 6,
	NFP_CA_ACTION_POLL32        = 7,
	NFP_CA_ACTION_POLL64        = 8
};

typedef int (*nfp_ca_callback)(struct nfp_cpp *cpp, enum nfp_ca_action action,
			       uint32_t cpp_id, uint64_t cpp_addr,
			       uint64_t val, uint64_t mask);

/*
 * nfp_ca_null() - Null callback used for CRC calculation
 */
static int nfp_ca_null(struct nfp_cpp *cpp, enum nfp_ca_action action,
		       uint32_t cpp_id, uint64_t cpp_addr,
		       uint64_t val, uint64_t mask)
{
	return 0;
}

/*
 * nfp_ca_cpp() - Replay CPP transactions
 */
static int nfp_ca_cpp(struct nfp_cpp *cpp, enum nfp_ca_action action,
		      uint32_t cpp_id, uint64_t cpp_addr,
		      uint64_t val, uint64_t mask)
{
	uint32_t tmp32;
	uint64_t tmp64;
	static unsigned int cnt;
	int timeout = 100; /* 100 ms */
	int pcount = 0;
	int poll_action = 0;
	int bit_len = 0;
	int err;

	switch (action) {
	case NFP_CA_ACTION_POLL32:
	case NFP_CA_ACTION_POLL64:
		timeout = 2000; /* Allow 2 seconds for a poll before failing. */
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

			if (val != (tmp64 & mask)) {
				/* 'about 1ms' - see
				 * Documentation/timers/timers-howto.txt
				 * for why it is poor practice to use
				 * msleep() for < 20ms sleeps.
				 */
				usleep_range(800, 1200);
				timeout--;
				pcount++;
			} else {
				break;
			}
		} while (timeout > 0);
		if (timeout == 0) {
			dev_warn(nfp_cpp_device(cpp),
				 "%sMISMATCH[%u] in %dms: %c%d 0x%08x 0x%010llx 0x%0*llx != 0x%0*llx\n",
				 (poll_action) ? "FATAL " : "", cnt, pcount,
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
		} else if (pcount > 0) {
			dev_warn(nfp_cpp_device(cpp),
				 "MATCH[%u] in %dms: %c%d 0x%08x 0x%010llx 0x%0*llx == 0x%0*llx\n",
				 cnt, pcount,
				 (poll_action) ? 'P' : 'R',
				 bit_len, cpp_id, (unsigned long long)cpp_addr,
				 (bit_len == 32) ? 8 : 16,
				 (unsigned long long)val,
				 (bit_len == 32) ? 8 : 16,
				 (unsigned long long)tmp64);
		}
		break;

	case NFP_CA_ACTION_READ_IGNV32:
		err = nfp_cpp_readl(cpp, cpp_id, cpp_addr, &tmp32);
		break;
	case NFP_CA_ACTION_READ_IGNV64:
		err = nfp_cpp_readq(cpp, cpp_id, cpp_addr, &tmp64);
		break;
	case NFP_CA_ACTION_WRITE32:
		if (~(uint32_t)mask) {
			err = nfp_cpp_readl(cpp, cpp_id, cpp_addr, &tmp32);
			if (err < 0)
				return err;
			val |= tmp32 & ~mask;
		}
		err = nfp_cpp_writel(cpp, cpp_id, cpp_addr, val);
		break;
	case NFP_CA_ACTION_WRITE64:
		if (~(uint32_t)mask) {
			err = nfp_cpp_readq(cpp, cpp_id, cpp_addr, &tmp64);
			if (err < 0)
				return err;
			val |= tmp64 & ~mask;
		}
		err = nfp_cpp_writeq(cpp, cpp_id, cpp_addr, val);
		break;
	default:
		err = -EINVAL;
		break;
	}

	cnt++;
	return err;
}

static int uncompress(uint8_t *out, size_t out_size,
		      const uint8_t *in, size_t in_size)
{
	int err, ws_size;
	z_stream zs = {};

	ws_size = zlib_inflate_workspacesize();

	zs.next_in = in;
	zs.avail_in = in_size;
	zs.next_out = out;
	zs.avail_out = out_size;
	zs.workspace = kmalloc(ws_size, GFP_KERNEL);
	if (!zs.workspace)
		return -ENOMEM;

	err = zlib_inflateInit(&zs);
	if (err != Z_OK) {
		err = (err == Z_MEM_ERROR) ? -ENOMEM : -EIO;
		goto exit;
	}

	err = zlib_inflate(&zs, Z_FINISH);
	if (err != Z_STREAM_END) {
		err = (err == Z_MEM_ERROR) ? -ENOMEM : -EIO;
		goto exit;
	}

	zlib_inflateEnd(&zs);
	err = 0;

exit:
	kfree(zs.workspace);
	return err;
}

/*
 * nfp_ca_parse - Parse a CPP Action replay file
 * @cpp:   CPP handle
 * @buff:  Buffer with trace data
 * @bytes: Length of buffer
 * @cb:    A callback function to be called on each item in the trace.
 */
static int nfp_ca_parse(struct nfp_cpp *cpp, const void *buff, size_t bytes,
			nfp_ca_callback cb)
{
	const uint8_t *byte = buff;
	uint8_t *zbuff = NULL;
	uint32_t cpp_id = 0;
	uint64_t cpp_addr = 0;
	size_t loc, usize;
	uint8_t ca;
	int err = -EINVAL;
	uint32_t mask32 = ~(uint32_t)0;
	uint64_t mask64 = ~(uint64_t)0;

	/* File too small? */
	if (bytes < (NFP_CA_SZ(NFP_CA_START) + NFP_CA_SZ(NFP_CA_END)))
		return -EINVAL;

	ca = byte[0];
	if (ca != NFP_CA_START)
		return -EINVAL;

	switch (ca32_to_cpu(&byte[1])) {
	case NFP_CA_ZSTART_MAGIC:
		/* Decompress first... */
		usize = ca32_to_cpu(&byte[5]);

		/* We use vmalloc() since kmalloc() requests contigous pages,
		 * and this gets increasingly unlikely as the size of the
		 * area to allocate increases.
		 *
		 * As uncompressed NFP firmwares can exceed 32M in size,
		 * we will use vmalloc() to allocate the firmware's
		 * uncompressed buffer.
		 */
		zbuff = vmalloc(usize);
		if (!zbuff)
			return -ENOMEM;

		usize -= NFP_CA_SZ(NFP_CA_START);
		err = uncompress((uint8_t *)zbuff + NFP_CA_SZ(NFP_CA_START),
				 usize, &byte[NFP_CA_SZ(NFP_CA_START)],
				 bytes - NFP_CA_SZ(NFP_CA_START));
		if (err < 0) {
			vfree(zbuff);
			/* Uncompression error */
			return err;
		}

		/* Patch up start to look like a NFP_CA_START */
		usize += NFP_CA_SZ(NFP_CA_START);
		zbuff[0] = NFP_CA_START;
		cpu_to_ca32(&zbuff[1], NFP_CA_START_MAGIC);
		cpu_to_ca32(&zbuff[5], usize);

		bytes = usize;
		byte = zbuff;
		/* FALLTHROUGH */
	case NFP_CA_START_MAGIC:
		/* Uncompressed start */
		usize = ca32_to_cpu(&byte[5]);
		if (usize < bytes) {
			/* Too small! */
			err = -ENOSPC;
			goto exit;
		}
		break;
	default:
		return -ENOSPC;
	}

	err = 0;
	for (loc = NFP_CA_SZ(NFP_CA_START); loc < bytes;
			loc += NFP_CA_SZ(byte[loc])) {
		const uint8_t *vp = &byte[loc + 1];
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
			err = cb(cpp, NFP_CA_ACTION_READ32,
				 cpp_id, cpp_addr, tmp32, mask32);
			break;
		case NFP_CA_INC_READ_8:
			cpp_addr += 8;
			/* FALLTHROUGH */
		case NFP_CA_READ_8:
			tmp64 = ca64_to_cpu(vp);
			err = cb(cpp, NFP_CA_ACTION_READ64,
				 cpp_id, cpp_addr, tmp64, mask64);
			break;
		case NFP_CA_POLL_4:
			tmp32 = ca32_to_cpu(vp);
			err = cb(cpp, NFP_CA_ACTION_POLL32,
				 cpp_id, cpp_addr, tmp32, mask32);
			break;
		case NFP_CA_POLL_8:
			tmp64 = ca64_to_cpu(vp);
			err = cb(cpp, NFP_CA_ACTION_POLL64,
				 cpp_id, cpp_addr, tmp64, mask64);
			break;
		case NFP_CA_INC_READ_IGNV_4:
			cpp_addr += 4;
			/* FALLTHROUGH */
		case NFP_CA_READ_IGNV_4:
			tmp32 = ca32_to_cpu(vp);
			err = cb(cpp, NFP_CA_ACTION_READ_IGNV32,
				 cpp_id, cpp_addr, tmp32, mask32);
			break;
		case NFP_CA_INC_READ_IGNV_8:
			cpp_addr += 8;
			/* FALLTHROUGH */
		case NFP_CA_READ_IGNV_8:
			tmp64 = ca64_to_cpu(vp);
			err = cb(cpp, NFP_CA_ACTION_READ_IGNV64,
				 cpp_id, cpp_addr, tmp64, mask64);
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
			err = cb(cpp, NFP_CA_ACTION_WRITE32,
				 cpp_id, cpp_addr, tmp32, mask32);
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
			err = cb(cpp, NFP_CA_ACTION_WRITE64,
				 cpp_id, cpp_addr, tmp64, mask64);
			break;
		case NFP_CA_MASK_4:
			mask32 = ca32_to_cpu(vp);
			break;
		case NFP_CA_MASK_8:
			mask64 = ca64_to_cpu(vp);
			break;
		default:
			err = -EINVAL;
			break;
		}
		if (err < 0)
			goto exit;
	}

	if (ca == NFP_CA_END && loc == bytes) {
		if (cb == nfp_ca_null) {
			uint32_t crc;

			loc -= NFP_CA_SZ(NFP_CA_END);
			crc = crc32_posix(byte, loc);
			if (crc != ca32_to_cpu(&byte[loc + 1])) {
				err = -EINVAL;
				goto exit;
			}
		}
		err = 0;
	}

exit:
	vfree(zbuff);

	return err;
}

/**
 * nfp_ca_replay - Replay a CPP Action trace
 * @cpp:       CPP handle
 * @ca_buffer: Buffer with trace
 * @ca_size:   Size of Buffer
 *
 * The function performs two passes of the buffer.  The first is to
 * calculate and verify the CRC at the end of the buffer, and the
 * second replays the transaction set.
 *
 * Return: 0, or -ERRNO
 */
int nfp_ca_replay(struct nfp_cpp *cpp, const void *ca_buffer, size_t ca_size)
{
	int err;

	err = nfp_ca_parse(cpp, ca_buffer, ca_size, &nfp_ca_null);
	if (err < 0)
		return err;

	return nfp_ca_parse(cpp, ca_buffer, ca_size, &nfp_ca_cpp);
}
