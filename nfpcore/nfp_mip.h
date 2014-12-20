/*
 * Copyright (C) 2011-2014,  Netronome Systems, Inc.  All rights reserved.
 *
 * @file          nfp_mip.h
 * @brief         Microcode Information Page (MIP) interface
 *
 */
#ifndef __NFP_MIP_H__
#define __NFP_MIP_H__

#define NFP_MIP_SIGNATURE       0x0050494d /* "MIP\0" (little-endian) */

#define NFP_MIP_VERSION         1
#define NFP_MIP_QC_VERSION      1
#define NFP_MIP_VPCI_VERSION    1

enum nfp_mip_entry_type {
	NFP_MIP_TYPE_NONE = 0,
	NFP_MIP_TYPE_QC = 1,
	NFP_MIP_TYPE_VPCI = 2,
};

struct nfp_mip {
	uint32_t signature;
	uint32_t mip_version;
	uint32_t mip_size;
	uint32_t first_entry;

	uint32_t version;
	uint32_t buildnum;
	uint32_t buildtime;
	uint32_t loadtime;

	uint32_t symtab_addr;
	uint32_t symtab_size;
	uint32_t strtab_addr;
	uint32_t strtab_size;

	char name[16];
	char toolchain[32];
};

struct nfp_mip_entry {
	uint32_t type;
	uint32_t version;
	uint32_t offset_next;
};

struct nfp_mip_qc {
	uint32_t type;
	uint32_t version;
	uint32_t offset_next;
	uint32_t type_config;
	uint32_t type_config_size;
	uint32_t host_config;
	uint32_t host_config_size;
	uint32_t config_signal;
	uint32_t nfp_queue_size;
	uint32_t queue_base;
	uint32_t sequence_base;
	uint32_t sequence_type;
	uint32_t status_base;
	uint32_t status_version;
	uint32_t error_base;
};

struct nfp_mip_vpci {
	uint32_t type;
	uint32_t version;
	uint32_t offset_next;
	uint32_t vpci_epconfig;
	uint32_t vpci_epconfig_size;
};

struct nfp_device;

/**
 * Get MIP for NFP device.
 *
 * @param dev           NFP device
 *
 * Copy MIP structure from NFP device and return it.  The returned
 * structure is handled internally by the library and should not be
 * explicitly freed by the caller.  It will be implicitly freed when
 * closing the NFP device.  Further, any subsequent call to
 * nfp_mip_probe() returning non-zero renders references to any
 * previously returned MIP structure invalid.
 *
 * If the MIP is found, the main fields of the MIP structure are
 * automatically converted to the endianness of the host CPU, as are
 * any MIP entries known to the library.  If a MIP entry is not known
 * to the library, only the 'offset_next' field of the entry structure
 * is endian converted.  The remainder of the structure is left as-is.
 * Such entries must be searched for by explicitly converting the type
 * and version to/from little-endian.
 *
 * @return MIP structure, or NULL if not found (and set errno
 * accordingly).
 */
struct nfp_mip *nfp_mip(struct nfp_device *dev);

/**
 * Check if MIP has been updated.
 *
 * @param dev           NFP device
 *
 * Check if currently cached MIP has been updated on the NFP device,
 * and read potential new contents.  If a call to nfp_mip_probe()
 * returns non-zero, the old MIP structure returned by a previous call
 * to nfp_mip() is no longer guaranteed to be present and any
 * references to the old structure is invalid.
 *
 * @return 1 if MIP has been updated, 0 if no update has occured, or
 * -1 on error (and set errno accordingly).
 */
int nfp_mip_probe(struct nfp_device *dev);

/**
 * Find entry within MIP.
 *
 * @param mip           MIP structure
 * @param type          MIP entry type to locate
 *
 * @return pointer to MIP entry, or NULL if entry was not found (and
 * set errno accordingly).
 */
void *nfp_mip_find_entry(struct nfp_mip *mip, enum nfp_mip_entry_type type);

#endif /* !__NFP_MIP_H__ */
