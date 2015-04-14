/*
 * Copyright (C) 2009 Netronome Systems, Inc.  All rights reserved.
 *
 */

#ifndef NFP_BSP_NFP_HWINFO_H
#define NFP_BSP_NFP_HWINFO_H

#include <asm/byteorder.h>

/*
 * The Hardware Info Table defines the properties of the system.
 *
 * HWInfo v1 Table (fixed size)
 *
 * 0x0000: uint32_t version	Hardware Info Table version (1.0)
 * 0x0004: uint32_t size	Total size of the table, including
 *				the CRC32 (IEEE 802.3)
 * 0x0008: uint32_t jumptab	Offset of key/value table
 * 0x000c: uint32_t keys	Total number of keys in the key/value table
 * NNNNNN:			Key/value jump table and string data
 * (size - 4): uint32_t crc32	CRC32 (same as IEEE 802.3, POSIX cksum, etc)
 *				CRC32("",0) = ~0, CRC32("a",1) = 0x48C279FE
 *
 * HWInfo v2 Table (variable size)
 *
 * 0x0000: uint32_t version	Hardware Info Table version (2.0)
 * 0x0004: uint32_t size	Current size of the data area, excluding CRC32
 * 0x0008: uint32_t limit	Maximum size of the table
 * 0x000c: uint32_t reserved	Unused, set to zero
 * NNNNNN:			Key/value data
 * (size - 4): uint32_t crc32	CRC32 (same as IEEE 802.3, POSIX cksum, etc)
 *				CRC32("",0) = ~0, CRC32("a",1) = 0x48C279FE
 *
 * If the HWInfo table is in the process of being updated, the low bit
 * of version will be set.
 *
 * HWInfo v1 Key/Value Table
 * -------------------------
 *
 *  The key/value table is a set of offsets to ASCIIZ strings which have
 *  been strcmp(3) sorted (yes, please use bsearch(3) on the table).
 *
 *  All keys are guaranteed to be unique.
 *
 * N+0:	uint32_t key_1		Offset to the first key
 * N+4:	uint32_t val_1		Offset to the first value
 * N+8: uint32_t key_2		Offset to the second key
 * N+c: uint32_t val_2		Offset to the second value
 * ...
 *
 * HWInfo v1 Key/Value Table
 * -------------------------
 *
 * Packed UTF8Z strings, ie 'key1\000value1\000key2\000value2\000'
 *
 * Unsorted.
 */

/* Hardware Info Version 1.0 */
#define NFP_HWINFO_VERSION_1 \
	(('H' << 24) | ('I' << 16) | (1 << 8) | (0 << 1) | 0)
/* Hardware Info Version 2.0 */
#define NFP_HWINFO_VERSION_2 \
	(('H' << 24) | ('I' << 16) | (2 << 8) | (0 << 1) | 0)
#define NFP_HWINFO_VERSION_UPDATING(ver) \
	((ver) & 1)

#define NFP_HWINFO_VERSION_in(base) \
	__le32_to_cpu(((uint32_t *)(base))[0])
#define NFP_HWINFO_VERSION_set(base, val) \
	(((uint32_t *)(base))[0] = __cpu_to_le32(val))

/***************** HWInfo v1 ****************/

/* Hardware Info Table Version 1.x */
#define NFP_HWINFO_SIZE_in(base) \
	__le32_to_cpu(((uint32_t *)(base))[1])
#define NFP_HWINFO_V1_TABLE_in(base) \
	__le32_to_cpu(((uint32_t *)(base))[2])
#define NFP_HWINFO_V1_KEYS_in(base) \
	__le32_to_cpu(((uint32_t *)(base))[3])
#define NFP_HWINFO_V2_LIMIT_in(base) \
	__le32_to_cpu(((uint32_t *)(base))[2])
#define NFP_HWINFO_CRC32_in(base) \
	__le32_to_cpu(((uint32_t *)NFP_HWINFO_DATA_END(base))[0])

#define NFP_HWINFO_SIZE_set(base, val) \
		(((uint32_t *)(base))[1] = __cpu_to_le32(val))

#define NFP_HWINFO_V1_TABLE_set(base, val) \
	(((uint32_t *)(base))[2] = __cpu_to_le32(val))
#define NFP_HWINFO_V1_KEYS_set(base, val) \
	(((uint32_t *)(base))[3] = __cpu_to_le32(val))

#define NFP_HWINFO_V2_LIMIT_set(base, val) \
	(((uint32_t *)(base))[2] = __cpu_to_le32(val))
#define NFP_HWINFO_V2_RESERVED_set(base, val) \
	(((uint32_t *)(base))[3] = __cpu_to_le32(val))

#define NFP_HWINFO_CRC32_set(base, val) \
	(((uint32_t *)NFP_HWINFO_DATA_END(base))[0] = __cpu_to_le32(val))

#define NFP_HWINFO_DATA_START(base) \
	((void *)&(((uint32_t *)base)[4]))
#define NFP_HWINFO_DATA_END(base) \
	((void *)(((char *)(base)) + \
		NFP_HWINFO_SIZE_in(base) - sizeof(uint32_t)))

/* Key/Value Table Version 1.x */
#define NFP_HWINFO_V1_KEY_in(base, key_id) \
	((const char *)((char *)(base) + \
		__le32_to_cpu(((uint32_t *)((base) + \
			      NFP_HWINFO_V1_TABLE_in(base)))[(key_id) * 2 + \
							     0])))
#define NFP_HWINFO_V1_VAL_in(base, key_id) \
	((const char *)((char *)(base) + \
		__le32_to_cpu(((uint32_t *)((base) + \
			      NFP_HWINFO_V1_TABLE_in(base)))[(key_id) * 2 + \
							     1])))

#endif /* NFP_BSP_NFP_HWINFO_H */
