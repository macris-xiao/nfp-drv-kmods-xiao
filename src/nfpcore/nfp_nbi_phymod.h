/*
 * Copyright (C) 2015, Netronome, Inc.
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

#ifndef __NFP_PHYMOD_H__
#define __NFP_PHYMOD_H__

#include <linux/kernel.h>

/**
 * No module present
 */
#define NFP_PHYMOD_TYPE_NONE 0x00

/**
 * SFP  module
 */
#define NFP_PHYMOD_TYPE_SFP  1

/**
 * SFP+  module
 */
#define NFP_PHYMOD_TYPE_SFPP 10

/**
 * QSFP  module
 */
#define NFP_PHYMOD_TYPE_QSFP 40

/**
 * CXP  module
 */
#define NFP_PHYMOD_TYPE_CXP  100

/**
 * PHY module summary status
 */
#define NFP_PHYMOD_SUMSTAT_LOS 0x00000001

/**
 * PHY module summary status
 */
#define NFP_PHYMOD_SUMSTAT_FAULT 0x00000002

/**
 * PHY module summary status
 */
#define NFP_PHYMOD_SUMSTAT_OPTPWR 0x00000004

/**
 * PHY module summary status
 */
#define NFP_PHYMOD_SUMSTAT_OPTBIAS 0x00000008

/**
 * PHY module summary status
 */
#define NFP_PHYMOD_SUMSTAT_HILOVOLT 0x00000010

/**
 * PHY module summary status
 */
#define NFP_PHYMOD_SUMSTAT_HILOTEMP 0x00000020

struct nfp_phymod;
struct nfp_phymod_eth;

struct nfp_phymod *nfp_phymod_next(struct nfp_device *nfp, void **ptr);

int nfp_phymod_get_index(struct nfp_phymod *phymod, int *index);
int nfp_phymod_get_label(struct nfp_phymod *phymod, const char **label);
int nfp_phymod_get_nbi(struct nfp_phymod *phymod, int *nbi);
int nfp_phymod_get_port(struct nfp_phymod *phymod, int *base, int *lanes);
int nfp_phymod_get_type(struct nfp_phymod *phymod, int *type);

int nfp_phymod_read_status(struct nfp_phymod *phymod, uint32_t *txstatus,
			   uint32_t *rxstatus);
int nfp_phymod_read_status_los(struct nfp_phymod *phymod, uint32_t *txstatus,
			       uint32_t *rxstatus);
int nfp_phymod_read_status_fault(struct nfp_phymod *phymod, uint32_t *txstatus,
				 uint32_t *rxstatus);
int nfp_phymod_read_status_optpower(struct nfp_phymod *phymod,
				    uint32_t *txstatus,
				    uint32_t *rxstatus);
int nfp_phymod_read_status_optbias(struct nfp_phymod *phymod,
				   uint32_t *rxtstaus,
				   uint32_t *txstatus);
int nfp_phymod_read_status_voltage(struct nfp_phymod *phymod,
				   uint32_t *txstatus,
				   uint32_t *rxstatus);
int nfp_phymod_read_status_temp(struct nfp_phymod *phymod, uint32_t *txstatus,
				uint32_t *rxstatus);
int nfp_phymod_read_lanedisable(struct nfp_phymod *phymod, uint32_t *txstatus,
				uint32_t *rxstatus);
int nfp_phymod_write_lanedisable(struct nfp_phymod *phymod, uint32_t txstate,
				 uint32_t rxstate);

int nfp_phymod_read8(struct nfp_phymod *phymod, uint32_t addr, uint8_t *data);
int nfp_phymod_write8(struct nfp_phymod *phymod, uint32_t addr, uint8_t data);

struct nfp_phymod_eth *nfp_phymod_eth_next(struct nfp_device *dev,
					   struct nfp_phymod *phy, void **ptr);

int nfp_phymod_eth_get_index(struct nfp_phymod_eth *eth, int *index);
int nfp_phymod_eth_get_phymod(struct nfp_phymod_eth *eth,
			      struct nfp_phymod **phy, int *lane);
int nfp_phymod_eth_get_mac(struct nfp_phymod_eth *eth, const uint8_t **mac);
int nfp_phymod_eth_get_label(struct nfp_phymod_eth *eth, const char **label);
int nfp_phymod_eth_get_nbi(struct nfp_phymod_eth *eth, int *nbi);
int nfp_phymod_eth_get_port(struct nfp_phymod_eth *eth, int *base, int *lanes);
int nfp_phymod_eth_get_speed(struct nfp_phymod_eth *eth, int *speed);
int nfp_phymod_eth_get_fail_to_wire(struct nfp_phymod_eth *eth,
				    const char **eth_label, int *active);
int nfp_phymod_eth_set_fail_to_wire(struct nfp_phymod_eth *eth, int force);
int nfp_phymod_eth_read_disable(struct nfp_phymod_eth *eth, uint32_t *txstatus,
				uint32_t *rxstatus);
int nfp_phymod_eth_write_disable(struct nfp_phymod_eth *eth, uint32_t txstate,
				 uint32_t rxstate);

#endif
