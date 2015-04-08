/*
 * Copyright (C) 2014, Netronome Systems, Inc.
 * All right reserved.
 *
 */

#ifndef __NFP_POWER_H__
#define __NFP_POWER_H__

#include "nfp.h"

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

#endif /* __NFP_POWER_H__ */
