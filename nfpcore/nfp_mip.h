/*
 * Copyright (C) 2011-2015, Netronome, Inc.
 * All right reserved.
 * Author: Jason McMullan <jason.mcmullan@netronome.com>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
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

const struct nfp_mip *nfp_mip(struct nfp_device *dev);
int nfp_mip_probe(struct nfp_device *dev);


#endif /* !__NFP_MIP_H__ */
