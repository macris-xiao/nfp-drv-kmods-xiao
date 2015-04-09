/*
 * Copyright (C) 2008-2010, Netronome Systems, Inc.  All rights reserved.
 *
 * @file          nfp_cpp.h
 * @brief         Interface for low-level NFP CPP access.
 *
 */
#ifndef __NFP_CPP_H__
#define __NFP_CPP_H__

#include <linux/ctype.h>

/*
 * NFP CPP device area handle
 */
struct nfp_cpp_area;

/*
 * NFP CPP handle
 */
struct nfp_cpp;

/*
 * Wildcard indicating a CPP read or write action
 *
 * The action used will be either read or write depending on whether a
 * read or write instruction/call is performed on the NFP_CPP_ID.  It
 * is recomended that the RW action is used even if all actions to be
 * performed on a NFP_CPP_ID are known to be only reads or writes.
 * Doing so will in many cases save NFP CPP internal software
 * resources.
 */
#define NFP_CPP_ACTION_RW		32

#define NFP_CPP_TARGET_ID_MASK		0x1f

/*
 * NFP_CPP_ID() - pack target, token, and action into a CPP ID.
 * @target:	NFP CPP target id
 * @action:	NFP CPP action id
 * @token:	NFP CPP token id
 *
 * Create a 32-bit CPP identifier representing the access to be made.
 * These identifiers are used as parameters to other NFP CPP
 * functions.  Some CPP devices may allow wildcard identifiers to be
 * specified.
 *
 * Return:		NFP CPP ID
 */
#define NFP_CPP_ID(target, action, token) \
	((((target) & 0x7f) << 24) | (((token)  & 0xff) << 16) | \
	 (((action) & 0xff) <<  8))

/*
 * NFP_CPP_ISLAND_ID() - pack target, token, action, and island into a CPP ID.
 * @target:	NFP CPP target id
 * @action:	NFP CPP action id
 * @token:	NFP CPP token id
 * @island:	NFP CPP island id
 *
 * Create a 32-bit CPP identifier representing the access to be made.
 * These identifiers are used as parameters to other NFP CPP
 * functions.  Some CPP devices may allow wildcard identifiers to be
 * specified.
 *
 * Return:		NFP CPP ID
 */
#define NFP_CPP_ISLAND_ID(target, action, token, island) \
	((((target) & 0x7f) << 24) | (((token)  & 0xff) << 16) | \
	 (((action) & 0xff) <<  8) | (((island) & 0xff) << 0))

/**
 * NFP_CPP_ID_TARGET_of() - Return the NFP CPP target of a NFP CPP ID
 * @id:	NFP CPP ID
 *
 * Return:	NFP CPP target
 */
static inline uint8_t NFP_CPP_ID_TARGET_of(uint32_t id)
{
	return (id >> 24) & NFP_CPP_TARGET_ID_MASK;
}

/**
 * NFP_CPP_ID_TOKEN_of() - Return the NFP CPP token of a NFP CPP ID
 * @id:	NFP CPP ID
 * Return:	NFP CPP token
 */
static inline uint8_t NFP_CPP_ID_TOKEN_of(uint32_t id)
{
	return (id >> 16) & 0xff;
}

/**
 * NFP_CPP_ID_ACTION_of() - Return the NFP CPP action of a NFP CPP ID
 * @id:	NFP CPP ID
 *
 * Return:	NFP CPP action
 */
static inline uint8_t NFP_CPP_ID_ACTION_of(uint32_t id)
{
	return (id >> 8) & 0xff;
}

/**
 * NFP_CPP_ID_ISLAND_of() - Return the NFP CPP island of a NFP CPP ID
 * @id: NFP CPP ID
 *
 * Return:	NFP CPP island
 */
static inline uint8_t NFP_CPP_ID_ISLAND_of(uint32_t id)
{
	return (id >> 0) & 0xff;
}

struct nfp_cpp *nfp_cpp_from_device_id(int id);
void nfp_cpp_free(struct nfp_cpp *cpp);

/*
 * NFP_CPP_MODEL_INVALID - invalid model id
 */
#define NFP_CPP_MODEL_INVALID   0xffffffff

/**
 * NFP_CPP_MODEL_CHIP_of() - retrieve the chip ID from the model ID
 * @model:   NFP CPP model id
 *
 * The chip ID is a 16-bit BCD+A-F encoding for the chip type.
 *
 * Return:      NFP CPP chip id
 */
#define NFP_CPP_MODEL_CHIP_of(model)        (((model) >> 16) & 0xffff)

/**
 * NFP_CPP_MODEL_FAMILY_of() - retrieve the chip family from the model ID
 * @model:   NFP CPP model id
 *
 * The chip family is one of:
 * NFP_CHIP_FAMILY_NFP3200
 * NFP_CHIP_FAMILY_NFP6000
 *
 * Return:      NFP Chip family, -1 if family undetermined
 */
#define NFP_CPP_MODEL_FAMILY_of(model) \
	(NFP_CPP_MODEL_IS_6000(model) ? NFP_CHIP_FAMILY_NFP6000 : \
	 NFP_CPP_MODEL_IS_3200(model) ? NFP_CHIP_FAMILY_NFP3200 : -1)

/**
 * NFP_CPP_MODEL_STEPPING_of() - retrieve the revision ID from the model ID
 * @model:	NFP CPP model id
 *
 * The revison ID is a 8-bit encoding of the chip revision.
 * Model A0 is 0x00, B4 is 0x14, G2 is 0x12 etc.
 *
 * Return:		NFP CPP stepping id
 */
#define NFP_CPP_MODEL_STEPPING_of(model)	(((model) >>  0) & 0x00ff)

/**
 * NFP_CPP_STEPPING() - Generate a NFP CPP stepping code
 * @major_minor:	NFP CPP stepping major minor
 *
 * The revison ID is a 8-bit encoding of the chip revision.
 * Stepping A0 is 0x00, B4 is 0x14, G9 is 0xA9 etc.
 *
 * Return:		NFP CPP stepping
 */
#define NFP_CPP_STEPPING(major_minor)	NFP_CPP_STEPPING_decode(#major_minor)

static inline int NFP_CPP_STEPPING_decode(const char *_str_major_minor)
{
	return ((toupper(_str_major_minor[0]) - 'A') << 4) |
		((_str_major_minor[1] - '0'));
}

/**
 * NFP_CPP_MODEL_IS_3200() - Check for the NFP3200 family of devices
 * @model:	NFP CPP model id
 *
 * Return:		true if model is in the NFP3200 family, false otherwise.
 */
#define NFP_CPP_MODEL_IS_3200(model) \
	((0x3200 <= NFP_CPP_MODEL_CHIP_of(model)) && \
	 (NFP_CPP_MODEL_CHIP_of(model) < 0x3300))
/**
 * NFP_CPP_MODEL_IS_6000() - Check for the NFP6000 family of devices
 * @model:	NFP CPP model id
 *
 * Return:		true if model is in the NFP6000 family, false otherwise.
 */
#define NFP_CPP_MODEL_IS_6000(model) \
	((0x6000 <= NFP_CPP_MODEL_CHIP_of(model)) && \
	 (NFP_CPP_MODEL_CHIP_of(model) < 0x7000))

uint32_t nfp_cpp_model(struct nfp_cpp *cpp);

/*
 * NFP Interface types - logical interface for this CPP connection
 * 4 bits are reserved for interface type.
 */
#define NFP_CPP_INTERFACE_TYPE_INVALID		0x0
#define NFP_CPP_INTERFACE_TYPE_PCI		0x1
#define NFP_CPP_INTERFACE_TYPE_ARM		0x2
#define NFP_CPP_INTERFACE_TYPE_RPC		0x3
#define NFP_CPP_INTERFACE_TYPE_ILA		0x4

/**
 * NFP_CPP_INTERFACE() - Construct a 16-bit NFP Interface ID
 * @type:	NFP Interface Type
 * @unit:	Unit identifier for the interface type
 * @channel:	Channel identifier for the interface unit
 *
 * Interface IDs consists of 4 bits of interface type,
 * 4 bits of unit identifier, and 8 bits of channel identifier.
 *
 * The NFP Interface ID is used in the implementation of
 * NFP CPP API mutexes, which use the MU Atomic CompareAndWrite
 * operation - hence the limit to 16 bits to be able to
 * use the NFP Interface ID as a lock owner.
 *
 * Return:		Interface ID
 */
#define NFP_CPP_INTERFACE(type, unit, channel)	\
	((((type) & 0xf) << 12) | \
	 (((unit) & 0xf) <<  8) | \
	 (((channel) & 0xff) << 0))

/**
 * NFP_CPP_INTERFACE_TYPE_of() - Get the interface type
 * @interface:		NFP Interface ID
 * Return:		NFP Interface ID's type
 */
#define NFP_CPP_INTERFACE_TYPE_of(interface)	(((interface) >> 12) & 0xf)

/**
 * NFP_CPP_INTERFACE_UNIT_of() - Get the interface unit
 * @interface:		NFP Interface ID
 * Return:		NFP Interface ID's unit
 */
#define NFP_CPP_INTERFACE_UNIT_of(interface)	(((interface) >>  8) & 0xf)

/**
 * NFP_CPP_INTERFACE_CHANNEL_of() - Get the interface channel
 * @interface:		NFP Interface ID
 * Return:		NFP Interface ID's channel
 */
#define NFP_CPP_INTERFACE_CHANNEL_of(interface)	(((interface) >>  0) & 0xff)

uint16_t nfp_cpp_interface(struct nfp_cpp *cpp);
int nfp_cpp_serial(struct nfp_cpp *cpp, const uint8_t **serial);

struct nfp_cpp_area *nfp_cpp_area_alloc(struct nfp_cpp *cpp, uint32_t cpp_id,
					unsigned long long address,
					unsigned long size);
struct nfp_cpp_area *nfp_cpp_area_alloc_with_name(struct nfp_cpp *cpp,
						  uint32_t cpp_id,
						  const char *name,
						  unsigned long long address,
						  unsigned long size);
void nfp_cpp_area_free(struct nfp_cpp_area *area);
int nfp_cpp_area_acquire(struct nfp_cpp_area *area);
void nfp_cpp_area_release(struct nfp_cpp_area *area);
struct nfp_cpp_area *nfp_cpp_area_alloc_acquire(struct nfp_cpp *cpp,
						uint32_t cpp_id,
						unsigned long long address,
						unsigned long size);
void nfp_cpp_area_release_free(struct nfp_cpp_area *area);
void *nfp_cpp_area_mapped(struct nfp_cpp_area *area);
int nfp_cpp_area_read(struct nfp_cpp_area *area, unsigned long offset,
		      void *buffer, size_t length);
int nfp_cpp_area_write(struct nfp_cpp_area *area, unsigned long offset,
		       const void *buffer, size_t length);
int nfp_cpp_area_check_range(struct nfp_cpp_area *area,
			     unsigned long long offset, unsigned long size);
struct nfp_cpp *nfp_cpp_area_cpp(struct nfp_cpp_area *cpp_area);
const char *nfp_cpp_area_name(struct nfp_cpp_area *cpp_area);

int nfp_cpp_read(struct nfp_cpp *cpp, uint32_t cpp_id,
		 unsigned long long address, void *kernel_vaddr, size_t length);
int nfp_cpp_write(struct nfp_cpp *cpp, uint32_t cpp_id,
		  unsigned long long address, const void *kernel_vaddr,
		  size_t length);
int nfp_cpp_area_fill(struct nfp_cpp_area *area, unsigned long offset,
		      uint32_t value, size_t length);
int nfp_cpp_area_readl(struct nfp_cpp_area *area, unsigned long offset,
		       uint32_t *value);
int nfp_cpp_area_writel(struct nfp_cpp_area *area, unsigned long offset,
			uint32_t value);
int nfp_cpp_area_readq(struct nfp_cpp_area *area, unsigned long offset,
		       uint64_t *value);
int nfp_cpp_area_writeq(struct nfp_cpp_area *area, unsigned long offset,
			uint64_t value);

int nfp_xpb_writel(struct nfp_cpp *cpp, uint32_t xpb_tgt, uint32_t value);
int nfp_xpb_readl(struct nfp_cpp *cpp, uint32_t xpb_tgt, uint32_t *value);
int nfp_xpb_writelm(struct nfp_cpp *cpp, uint32_t xpb_tgt, uint32_t mask,
		    uint32_t value);
int nfp_xpb_waitlm(struct nfp_cpp *cpp, uint32_t xpb_tgt, uint32_t mask,
		   uint32_t value, int timeout_us);

int nfp_cpp_readl(struct nfp_cpp *cpp, uint32_t cpp_id,
		  unsigned long long address, uint32_t *value);
int nfp_cpp_writel(struct nfp_cpp *cpp, uint32_t cpp_id,
		   unsigned long long address, uint32_t value);
int nfp_cpp_readq(struct nfp_cpp *cpp, uint32_t cpp_id,
		  unsigned long long address, uint64_t *value);
int nfp_cpp_writeq(struct nfp_cpp *cpp, uint32_t cpp_id,
		   unsigned long long address, uint64_t value);

struct nfp_cpp_mutex;

int nfp_cpp_mutex_init(struct nfp_cpp *cpp, int target,
		       unsigned long long address, uint32_t key_id);
struct nfp_cpp_mutex *nfp_cpp_mutex_alloc(struct nfp_cpp *cpp, int target,
					  unsigned long long address,
					  uint32_t key_id);
struct nfp_cpp *nfp_cpp_mutex_cpp(struct nfp_cpp_mutex *mutex);
uint32_t nfp_cpp_mutex_key(struct nfp_cpp_mutex *mutex);
void nfp_cpp_mutex_free(struct nfp_cpp_mutex *mutex);

int nfp_cpp_mutex_lock(struct nfp_cpp_mutex *mutex);
int nfp_cpp_mutex_unlock(struct nfp_cpp_mutex *mutex);
int nfp_cpp_mutex_trylock(struct nfp_cpp_mutex *mutex);


struct nfp_cpp_event;
struct sigaction;

struct nfp_cpp_event *nfp_cpp_event_alloc(struct nfp_cpp *cpp,
					  uint32_t event_match,
					  uint32_t event_mask, int type);
struct nfp_cpp *nfp_cpp_event_cpp(struct nfp_cpp_event *cpp_event);
int nfp_cpp_event_as_signal(struct nfp_cpp_event *event, int signum,
			    const struct sigaction *act);
void nfp_cpp_event_free(struct nfp_cpp_event *event);

#endif /* !__NFP_CPP_H__ */
