/*
 * Copyright (C) 2010-2011,2014-2015  Netronome Systems, Inc.  All rights reserved.
 *
 * @file          nfp.h
 * @brief         Interface for NFP device access and query functions.
 *
 */
#ifndef __NFP_H__
#define __NFP_H__

#include <linux/device.h>

#include "kcompat.h"

#include "nfp_cpp.h"

#include "nfp-bsp/nfp_resource.h"

#ifndef NFP_SUBSYS
#define NFP_SUBSYS ""
#endif

#define nfp_err(nfp, fmt, args...) \
	dev_err(nfp_cpp_device(nfp_device_cpp(nfp))->parent, NFP_SUBSYS fmt, ## args)
#define nfp_warn(nfp, fmt, args...) \
	dev_warn(nfp_cpp_device(nfp_device_cpp(nfp))->parent, NFP_SUBSYS fmt, ## args)
#define nfp_info(nfp, fmt, args...) \
	dev_info(nfp_cpp_device(nfp_device_cpp(nfp))->parent, NFP_SUBSYS fmt, ## args)
#define nfp_dbg(nfp, fmt, args...) \
	dev_dbg(nfp_cpp_device(nfp_device_cpp(nfp))->parent, NFP_SUBSYS fmt, ## args)
#define nfp_trace(nfp, fmt, args...) \
	trace_printk("%s %s: " NFP_SUBSYS fmt, \
			dev_driver_string(nfp_cpp_device(nfp_device_cpp(nfp))->parent, \
			dev_name(nfp_cpp_device(nfp_device_cpp(nfp))->parent, ## args)

struct nfp_cpp;

/* Opaque NFP device handle. */
struct nfp_device;

/* Maximum device number for an NFP device. */
#define NFP_MAX_DEVICE_NUM              63

/* Implemented in nfp_device.c */

struct nfp_device *nfp_device_open(unsigned int devnum);
struct nfp_device *nfp_device_from_cpp(struct nfp_cpp *cpp);
void nfp_device_close(struct nfp_device *dev);

int nfp_device_id(struct nfp_device *nfp);
struct nfp_cpp *nfp_device_cpp(struct nfp_device *dev);

void *nfp_device_private(struct nfp_device *dev,
			 void *(*constructor) (struct nfp_device * dev));
void *nfp_device_private_alloc(struct nfp_device *dev, size_t private_size,
			       void (*destructor) (void *private_data));

/* Implemented in nfp_hwinfo.c */

const char *nfp_hwinfo_lookup(struct nfp_device *nfp, const char *lookup);

/* Implemented in nfp_power.c */

/*
 * NFP Device Power States
 *
 * NFP_DEVICE_STATE_P0          Clocked, reset released
 * NFP_DEVICE_STATE_P1          Not clocked, reset released
 * NFP_DEVICE_STATE_P2          Clocked, held in reset
 * NFP_DEVICE_STATE_P3          No clocking, held in reset
 *
 * NOTE: Transitioning a device from P0 to power state P2
 *       or P3 will imply that all running configuration
 *       of the device will be lost, and the device must
 *       be re-initialized when P0 state is re-entered.
 */
#define NFP_DEVICE_STATE_P0     0
#define NFP_DEVICE_STATE_P1     1
#define NFP_DEVICE_STATE_P2     2
#define NFP_DEVICE_STATE_P3     3

/*
 * Friendly aliases of the above device states
 */
#define NFP_DEVICE_STATE_ON             NFP_DEVICE_STATE_P0
#define NFP_DEVICE_STATE_SUSPEND        NFP_DEVICE_STATE_P1
#define NFP_DEVICE_STATE_RESET          NFP_DEVICE_STATE_P2
#define NFP_DEVICE_STATE_OFF            NFP_DEVICE_STATE_P3

/*
 * NFP3200 specific subdevice identifiers
 */
#define NFP3200_DEVICE(x)               ((x) & 0x1f)
#define     NFP3200_DEVICE_ARM          1
#define     NFP3200_DEVICE_ARM_GASKET   2
#define     NFP3200_DEVICE_DDR0         3
#define     NFP3200_DEVICE_DDR1         4
#define     NFP3200_DEVICE_MECL0        5
#define     NFP3200_DEVICE_MECL1        6
#define     NFP3200_DEVICE_MECL2        7
#define     NFP3200_DEVICE_MECL3        8
#define     NFP3200_DEVICE_MECL4        9
#define     NFP3200_DEVICE_MSF0         10
#define     NFP3200_DEVICE_MSF1         11
#define     NFP3200_DEVICE_MU           12
#define     NFP3200_DEVICE_PCIE         13
#define     NFP3200_DEVICE_QDR0         14
#define     NFP3200_DEVICE_QDR1         15
#define     NFP3200_DEVICE_CRYPTO       16

/*
 * NFP6000 specific subdevice identifiers
 */
#define NFP6000_DEVICE(island, unit)     ((((island) & 0x3f)<< 8) | ((unit) & 0xf))
#define NFP6000_DEVICE_ISLAND_of(x)      (((x) >> 8) & 0x3f)
#define NFP6000_DEVICE_UNIT_of(x)        (((x) >> 0) & 0x0f)

#define NFP6000_DEVICE_ARM(dev, unit)   NFP6000_DEVICE((dev)+1, unit)
#define     NFP6000_DEVICE_ARM_CORE  0
#define     NFP6000_DEVICE_ARM_ARM   1
#define     NFP6000_DEVICE_ARM_GSK   2
#define     NFP6000_DEVICE_ARM_PRH   3
#define     NFP6000_DEVICE_ARM_MEG0  4
#define     NFP6000_DEVICE_ARM_MEG1  5
#define NFP6000_DEVICE_PCI(dev, unit)    NFP6000_DEVICE((dev)+4, unit)
#define     NFP6000_DEVICE_PCI_CORE  0
#define     NFP6000_DEVICE_PCI_PCI   1
#define     NFP6000_DEVICE_PCI_MEG0  2
#define     NFP6000_DEVICE_PCI_MEG1  3
#define NFP6000_DEVICE_NBI(dev, unit)    NFP6000_DEVICE((dev)+8, unit)
#define     NFP6000_DEVICE_NBI_CORE  0
#define     NFP6000_DEVICE_NBI_MAC4  4
#define     NFP6000_DEVICE_NBI_MAC5  5
#define NFP6000_DEVICE_CRP(dev, unit)    NFP6000_DEVICE((dev)+12, unit)
#define     NFP6000_DEVICE_CRP_CORE  0
#define     NFP6000_DEVICE_CRP_CRP   1
#define     NFP6000_DEVICE_CRP_MEG0  2
#define     NFP6000_DEVICE_CRP_MEG1  3
#define NFP6000_DEVICE_EMU(dev, unit)    NFP6000_DEVICE((dev)+24, unit)
#define     NFP6000_DEVICE_EMU_CORE  0
#define     NFP6000_DEVICE_EMU_QUE   1
#define     NFP6000_DEVICE_EMU_LUP   2
#define     NFP6000_DEVICE_EMU_DAL   3
#define     NFP6000_DEVICE_EMU_EXT   4
#define     NFP6000_DEVICE_EMU_DDR0  5
#define     NFP6000_DEVICE_EMU_DDR1  6
#define NFP6000_DEVICE_IMU(dev, unit)    NFP6000_DEVICE((dev)+28, unit)
#define     NFP6000_DEVICE_IMU_CORE  0
#define     NFP6000_DEVICE_IMU_STS   1
#define     NFP6000_DEVICE_IMU_LBL   2
#define     NFP6000_DEVICE_IMU_CLU   3
#define     NFP6000_DEVICE_IMU_NLU   4
#define NFP6000_DEVICE_FPC(dev, unit)    NFP6000_DEVICE((dev)+32, unit)
#define     NFP6000_DEVICE_FPC_CORE  0
#define     NFP6000_DEVICE_FPC_MEG0  1
#define     NFP6000_DEVICE_FPC_MEG1  2
#define     NFP6000_DEVICE_FPC_MEG2  3
#define     NFP6000_DEVICE_FPC_MEG3  4
#define     NFP6000_DEVICE_FPC_MEG4  5
#define     NFP6000_DEVICE_FPC_MEG5  6
#define NFP6000_DEVICE_ILA(dev, unit)    NFP6000_DEVICE((dev)+48, unit)
#define     NFP6000_DEVICE_ILA_CORE  0
#define     NFP6000_DEVICE_ILA_ILA   1
#define     NFP6000_DEVICE_ILA_MEG0  2
#define     NFP6000_DEVICE_ILA_MEG1  3

int nfp_power_get(struct nfp_device *dev, unsigned int subdevice, int *state);

int nfp_power_set(struct nfp_device *dev, unsigned int subdevice, int state);

/* Implemented in nfp_reset.c */

int nfp_reset_soft(struct nfp_device *nfp);

/* Implemented in nfp_armsp.c */

#define SPCODE_NOOP             0       /* No operation */
#define SPCODE_SOFT_RESET       1       /* Soft reset the NFP */
#define SPCODE_FW_DEFAULT       2       /* Load default (UNDI) FW */
#define SPCODE_PHY_INIT         3       /* Initialize the PHY */
#define SPCODE_MAC_INIT         4       /* Initialize the MAC */
#define SPCODE_PHY_RXADAPT      5       /* Re-run PHY RX Adaptation */

int nfp_armsp_command(struct nfp_device *nfp, uint16_t spcode);

/* Implemented in nfp_resource.c */

int nfp_cpp_resource_init(struct nfp_cpp *cpp,
			  struct nfp_cpp_mutex **resource_mutex);

struct nfp_resource *nfp_resource_acquire(struct nfp_device *nfp,
					  const char *name);

void nfp_resource_release(struct nfp_resource *res);

int nfp_cpp_resource_add(struct nfp_cpp *cpp, const char *name,
			 uint32_t cpp_id, uint64_t address, uint64_t size,
		struct nfp_cpp_mutex **resource_mutex);

uint32_t nfp_resource_cpp_id(struct nfp_resource *res);

const char *nfp_resource_name(struct nfp_resource *res);

uint64_t nfp_resource_address(struct nfp_resource *res);

uint64_t nfp_resource_size(struct nfp_resource *res);

#endif /* !__NFP_H__ */
