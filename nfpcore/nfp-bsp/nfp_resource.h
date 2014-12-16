/*
 * Copyright (C) 2014, Netronome Systems, Inc.
 * All right reserved.
 *
 */

#ifndef NFP_BSP_NFP_RESOURCE_H
#define NFP_BSP_NFP_RESOURCE_H

#ifndef __KERNEL__
#include <stdint.h>
#endif

#define NFP_RESOURCE_ENTRY_NAME_SZ  8

/* NFP BSP Resource Reservation Entry
 */
struct nfp_resource_entry {
	struct nfp_resource_entry_mutex {
		uint32_t owner;       /* NFP CPP Lock, interface owner */
		uint32_t key;         /* NFP CPP Lock, posix_crc32(name, 8) */
	} mutex;
	struct nfp_resource_entry_region {
		/* ASCII, zero padded name */
		uint8_t  name[NFP_RESOURCE_ENTRY_NAME_SZ];
		uint32_t reserved_0x10;     /* -- reserved -- */
		uint8_t  reserved_0x11;     /* -- reserved -- */
		uint8_t  cpp_action;        /* CPP Action */
		uint8_t  cpp_token;         /* CPP Token */
		uint8_t  cpp_target;        /* CPP Target ID */
		uint32_t page_offset;       /* 256-byte page offset into
					     * target's CPP address */
		uint32_t page_size;         /* size, in 256-byte pages */
	} region;
} __attribute__((__packed__));

/**
 * NFP Resource Table self-identifier
 */
#define NFP_RESOURCE_TABLE_NAME     "nfp.res"
#define NFP_RESOURCE_TABLE_KEY      0x00000000  /* Special key for entry 0 */

/* All other keys are CRC32-POSIX of the 8-byte identification string */

/**
 * ARM Linux/Application Workspace
 */
#define NFP_RESOURCE_ARM_WORKSPACE      "arm.mem"

/**
 * ARM Linux Flattended Device Tree
 */
#define NFP_RESOURCE_ARM_FDT            "arm.fdt"

/**
 * ARM/PCI vNIC Interfaces 0..3
 */
#define NFP_RESOURCE_VNIC_PCI_0         "vnic.p0"
#define NFP_RESOURCE_VNIC_PCI_1         "vnic.p1"
#define NFP_RESOURCE_VNIC_PCI_2         "vnic.p2"
#define NFP_RESOURCE_VNIC_PCI_3         "vnic.p3"

/**
 * NFP Hardware Info Database
 */
#define NFP_RESOURCE_NFP_HWINFO         "nfp.info"

/**
 * ARM Diagnostic Area
 */
#define NFP_RESOURCE_ARM_DIAGNOSTIC     "arm.diag"

/**
 * Netronone Flow Firmware Table
 */
#define NFP_RESOURCE_NFP_NFFW           "nfp.nffw"

/**
 * MAC Statistics Accumulator
 */
#define NFP_RESOURCE_MAC_STATISTICS     "mac.stat"


#endif /* NFP_BSP_NFP_RESOURCE_H */
