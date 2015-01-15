/*
 * Copyright (C) 2014-2015 Netronome Systems, Inc. All rights reserved.
 * Author: Jason McMullan <jason.mcmullan@netronome.com>
 *
 * NFP CPP Action trace file format
 */

#ifndef NFP_CA_H
#define NFP_CA_H

/* up to 32 IDs, and up to 7 words of control information
 */
#define NFP_CA_(id)         ((id)<<3)
#define NFP_CA(id, type)    (NFP_CA_(id) | (sizeof(type)/sizeof(uint32_t)))
#define NFP_CA_LEN(ca)      ((ca) & 0x7)

struct nfp_ca_start {
	uint32_t magic;
	uint32_t bytes;
};

#define NFP_CA_START_MAGIC  0x0066424e  /* "NBf\000" */

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

static inline void cpu_to_ca32(uint8_t *byte, uint32_t val)
{
	int i;

	for (i = 0; i < 4; i++)
		byte[i] = (val >> (8 * i)) & 0xff;
}

static inline void cpu_to_ca64(uint8_t *byte, uint64_t val)
{
	int i;

	for (i = 0; i < 8; i++)
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

typedef int (*nfp_ca_callback)(void *priv, enum nfp_ca_action action,
	uint32_t cpp_id, uint64_t cpp_addr, uint64_t val);

int nfp_ca_replay(const void *ca_buffer, size_t ca_size,
		  nfp_ca_callback cb, void *cb_priv);

/* For this callback, 'priv' should be a 'struct nfp_cpp *'
 */
int nfp_ca_cb_cpp(void *priv, enum nfp_ca_action action,
		  uint32_t cpp_id, uint64_t cpp_addr, uint64_t val);

#endif /* NFP_CA_H */
/* vim: set shiftwidth=4 expandtab:  */
/*
 * Local variables:
 * c-file-style: "Linux"
 * indent-tabs-mode: t
 * End:
 */
