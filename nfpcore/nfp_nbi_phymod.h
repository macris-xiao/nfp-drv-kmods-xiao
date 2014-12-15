/**
 * Copyright (C) 2013-2014 Netronome Systems, Inc.  All rights reserved.
 *
 * @file nfp_phymod.h
 *
 * This header file declares the API functions relating to
 * the PHY modules (SFP, SFP+, QSFP, CXP) used with Netronome systems.
 *
 * This API is designed to operate with devices that conform to the
 * following specifications:

 * SFF-8472 Diagnostic Monitoring Interface for Optical Transceivers (SFP+)

 * SFF-8436 QSFP+ 10 Gbs 4X PLUGGABLE TRANSCEIVER

 * Supplement to InfiniBandTM Architecture Specification Volume 2 Release 1.2.1
 * Annex A6:120 Gb/s 12x Small Form-factor Pluggable (CXP)

 * Many parts of the diagnosic monitoring information described in these
 * specifications are optional.  This API uses a subset of the
 * information that may or may not be available on a specific device.
 * This API has been tested on the following devices:

 *
 * **** ADD REFERENCE TO DATABOOK OR OTHER SOURCE OF VERIFIED DEVICES LIST ****

 */

#ifndef __NFP_PHYMOD_H__
#define __NFP_PHYMOD_H__

#include <linux/kernel.h>

/**
 * No module present
 */
#define NFP_PHYMOD_TYPE_NONE 0x00

/**
 * SFP(+)  module
 */
#define NFP_PHYMOD_TYPE_SFPP 0x01

/**
 * QSFP  module
 */
#define NFP_PHYMOD_TYPE_QSFP 0x04

/**
 * CXP  module
 */
#define NFP_PHYMOD_TYPE_CXP 0x0a

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

/**
 * PHY Module enumeration
 * @ingroup nfp6000-only
 *
 * This function allows enumeration of the PHY Modules
 * attached to the system.
 *
 * @param nfp   NFP device
 * @param ptr   Abstract pointer, must be NULL to get the first port
 * @return  On succes: phymod
 * @return  On error: NULL
 */
struct nfp_phymod *nfp_phymod_next(struct nfp_device *nfp, void **ptr);

/**
 * Get the index for a phymode
 * @ingroup nfp6000-only
 *
 * @param phymod
 * @param index	Pointer to a int for the index
 * @return 0 on success, -1 and errno on error
 */
int nfp_phymod_get_index(struct nfp_phymod *phymod, int *index);

/**
 * Get the string (UTF8) label for a phymode
 * @ingroup nfp6000-only
 *
 * @param phymod
 * @param label		Pointer to a const char * for the label
 * @return 0 on success, -1 and errno on error
 */
int nfp_phymod_get_label(struct nfp_phymod *phymod, const char **label);

/**
 * Get the MAC address of the port
 * @ingroup nfp6000-only
 *
 * @param phymod
 * @param mac		Pointer to a const uint8_t * for the 6-byte MAC
 * @return 0 on success, -1 and errno on error
 */
int nfp_phymod_get_mac(struct nfp_phymod *phymod, const uint8_t **mac);

/**
 * Get the NBI ID for a phymode
 * @ingroup nfp6000-only
 *
 * @param phymod
 * @param nbi		Pointer to a int for the NBI
 * @return 0 on success, -1 and errno on error
 */
int nfp_phymod_get_nbi(struct nfp_phymod *phymod, int *nbi);

/**
 * Get the base port and/or lanes
 * @ingroup nfp6000-only
 *
 * @param phymod
 * @param base		Pointer to a int for base port (0..23)
 * @param lanes		Pointer to a int for number of phy lanes
 * @return 0 on success, -1 and errno on error
 */
int nfp_phymod_get_port(struct nfp_phymod *phymod, int *base, int *lanes);

/**
 * Get the type ID for the port
 * @ingroup nfp6000-only
 *
 * @param phymod
 * @param type		Pointer to a int for the type (see NFP_PHYMOD_TYPE_*)
 * @return 0 on success, -1 and errno on error
 */
int nfp_phymod_get_type(struct nfp_phymod *phymod, int *type);

/**
 * Report status for a PHY module.
 * @ingroup nfp6000-only
 *
 * The returned txstatus parameter indicates the type of PHY module in
 * the most significant byte.  The other bytes contain the summary
 * status for Transmit Loss of Signal (LOS), Fault, Optical Power,
 * Optical Bias, High/Low Voltage and High/Low Temperature.
 *
 * The returned rxstatus parameter contains the summary status for
 * Receive Loss of Signal (LOS), Fault, Optical Power, High/Low
 * Voltage and High/Low Temperature.
 *
 * For the SFP(+) case these summary statuses are the full status for
 * these alarms.  For CXP and QSFP a detailed per-lane status can be
 * obtained for each of these alarms using the associated
 * type-specific function.
 *
 * @param phymod PHY module
 * @param[out] txstatus Transmit status summary for the module
 * @param[out] rxstatus Receive status summary for the module
 *
 * @return 0 on success. Set errno and return -1 on error.
 *
 */
int nfp_phymod_read_status(struct nfp_phymod *phymod, uint32_t *txstatus,
			   uint32_t *rxstatus);

/**
 * Report Loss Of Signal status for a PHY module.
 * @ingroup nfp6000-only
 *
 * The returned txstatus parameter indicates the type of PHY module in
 * the most significant byte.  The other bytes contain the status
 * of Transmit Loss of Signal (LOS) for each lane.  For the SFP(+) case
 * the LOS status is in bit zero; for QSFP bits 0-4 and for CXP
 * bits 0-9.
 *
 * The returned rxstatus parameter indicates the status of Receive
 * Loss of Signal (LOS) for each lane.  For the SFP(+) case the LOS
 * status is in bit zero; for QSFP bits 0-4 and for CXP bits 0-9.
 *
 * @param phymod PHY module
 * @param[out] txstatus Transmit LOS status for the module
 * @param[out] rxstatus Receive LOS status for the module
 *
 * @return 0 on success. Set errno and return -1 on error.
 *
 */
int nfp_phymod_read_status_los(struct nfp_phymod *phymod, uint32_t *txstatus,
			       uint32_t *rxstatus);

/**
 * Report Fault status for a PHY module.
 *
 * The returned txstatus parameter indicates the type of PHY module in
 * the most significant byte.  The other bytes contain the Transmit
 * Fault status for each lane.  For the SFP(+) case the Fault status is
 * in bit zero; for QSFP bits 0-4 and for CXP bits 0-9.
 *
 * The returned rxstatus parameter indicates the Receive Fault status
 * for each lane.  For the SFP(+) case the LOS status is in bit zero;
 * for QSFP bits 0-4 and for CXP bits 0-9.
 *
 * @param phymod PHY module
 * @param[out] txstatus Transmit Fault status for the module
 * @param[out] rxstatus Receive Fault status for the module
 *
 * @return 0 on success. Set errno and return -1 on error.
 *
 */
int nfp_phymod_read_status_fault(struct nfp_phymod *phymod, uint32_t *txstatus,
				 uint32_t *rxstatus);

/**
 * Report Optical Power status for a PHY module.
 * @ingroup nfp6000-only
 *
 * The returned txstatus parameter indicates the type of PHY module in
 * the most significant byte.  The other bytes contain the status of
 * Transmit Optical Power for each lane.  Two bits are used to
 * represent the status for each lane - the MSB for High Power and the
 * LSB for Low Power.  For the SFP(+) case the Optical Power status will
 * be in bits 0-1; for QSFP bits 0-7 and for CXP bits 0-19.
 *
 * The returned rxstatus parameter indicates the status of
 * Receive Optical Power for each lane.  Two bits are used to
 * represent the status for each lane - the MSB for High Power and the
 * LSB for Low Power.  For the SFP(+) case the Optical Power status will
 * be in bits 0-1; for QSFP bits 0-7 and for CXP bits 0-19.
 *
 * @param phymod PHY module
 * @param[out] txstatus Transmit Optical Power status for the module
 * @param[out] rxstatus Receive Optical Power status for the module
 *
 * @return 0 on success. Set errno and return -1 on error.
 *
 */
int nfp_phymod_read_status_optpower(struct nfp_phymod *phymod,
				    uint32_t *txstatus,
				    uint32_t *rxstatus);

/**
 * Report Optical Bias status for a PHY module.
 * @ingroup nfp6000-only
 *
 * The returned txstatus parameter indicates the type of PHY module in
 * the most significant byte.  The other bytes contain the status of
 * Transmit Optical Bias for each lane.  Two bits are used to
 * represent the status for each lane - the MSB for High Bias and the
 * LSB for Low Bias.  For the SFP(+) case the Optical Bias status will
 * be in bits 0-1; for QSFP bits 0-7 and for CXP bits 0-19.
 *
 * @param phymod PHY module
 * @param[out] txstatus Transmit Optical Bias status for the module
 *
 * @return 0 on success. Set errno and return -1 on error.
 *
 */
int nfp_phymod_read_status_optbias(struct nfp_phymod *phymod,
				   uint32_t *rxtstaus,
				   uint32_t *txstatus);

/**
 * Report High/Low Voltage status for a PHY module.
 * @ingroup nfp6000-only
 *
 * The returned txstatus parameter indicates the type of PHY module in
 * the most significant byte.  The other bytes contain the status of
 * Transmit High/Low Voltage alarms for the module.  Two bits are used
 * to represent the status for each monitored voltage - the most
 * significant bit for High Voltage and the least significant bit for
 * Low Voltage.  For the SFP(+) case only one voltage is monitored and
 * the High/Low Voltage status will be in bits 0-1.  For the QSFP and
 * CXP two voltages are monitored Vcc12 and Vcc3.3.  Two bits are used
 * for each voltage - Vcc3.3 status is in bits 0-1; Vcc12 status is in
 * bits 2-3.
 *
 * The returned rxstatus parameter indicates the status of Receive
 * High/Low Voltage for the module.  Two bits are used to represent
 * the status for each monitored voltage - the most significant bit
 * for High Voltage and the least significant bit for Low Voltage.
 * For the SFP(+) case only one voltage is monitored and the High/Low
 * Voltage status will be in bits 0-1.  For the QSFP and CXP two
 * voltages are monitored Vcc12 and Vcc3.3.  Two bits are used for
 * each voltage - Vcc3.3 status is in bits 0-1; Vcc12 status is in
 * bits 2-3.
 *
 * @param phymod PHY module
 * @param[out] txstatus Transmit High/Low Voltage status for the module
 * @param[out] rxstatus Receive High/Low Voltage status for the module
 *
 * @return 0 on success. Set errno and return -1 on error.
 *
 */
int nfp_phymod_read_status_voltage(struct nfp_phymod *phymod,
				   uint32_t *txstatus,
				   uint32_t *rxstatus);

/**
 * Report High/Low Temperature status for a PHY module.
 * @ingroup nfp6000-only
 *
 * The returned txstatus parameter indicates the type of PHY module in
 * the most significant byte.  The other bytes contain the status of
 * Transmit High/Low Temperature alarms for the module.  Two bits are
 * used to represent the status for temperature - the most significant
 * bit for High Temperature and the least significant bit for Low
 * Temperature.  For all modules the High/Low Temperature status will
 * be in bits 0-1.
 *
 * The returned rxstatus parameter indicates the status of Receive
 * High/Low Temperature for the module.  Two bits are used to
 * represent the status for temperature - the most significant bit for
 * High Temperature and the least significant bit for Low
 * Temperature. For all modules the High/Low Temperature status will be
 * in bits 0-1.
 *
 *
 * @param phymod PHY module
 * @param[out] txstatus Transmit High/Low Temperature status for the module
 * @param[out] rxstatus Receive High/Low Temperature status for the module
 *
 * @return 0 on success. Set errno and return -1 on error.
 *
 */
int nfp_phymod_read_status_temp(struct nfp_phymod *phymod, uint32_t *txstatus,
				uint32_t *rxstatus);

/**
 * Read Lane Disable state for a PHY module.
 * @ingroup nfp6000-only
 *
 * The returned txstatus parameter indicates the type of PHY module in
 * the most significant byte.  The other bytes contain the status of
 * Lane Disable for each lane in the module.
 *
 * The SFP(+) supports a hardware TX_DISABLE (bit-0) and a software
 * TX_DISABLE (bit-1).  These are returned in txstatus.
 *
 * The QSFP supports independent Transmit and Receive software
 * disables for each lane.  The Transmit Lane Disable states are
 * returned in txstatus bits 0-3, the Receive Lane Disable states are
 * returned in rxstatus bits 0-3.
 *
 * The CXP supports independent Transmit and Receive software disables
 * for each lane and two software disable modes: an Output Disable and
 * a Lane (Channel) Disable.  The Transmit Lane Disable states are
 * returned in txstatus bits 0-23, the Receive Lane Disable states are
 * returned in rxstatus bits 0-23.
 *
 *
 * @param phymod PHY module
 * @param[out] txstatus Lane Disable status for the module
 * @param[out] rxstatus Lane Disable status for the module
 *
 * @return 0 on success. Set errno and return -1 on error.
 *
 */
int nfp_phymod_read_lanedisable(struct nfp_phymod *phymod, uint32_t *txstatus,
				uint32_t *rxstatus);

/**
 * Write Lane Disable state for a PHY module.
 * @ingroup nfp6000-only
 *
 * Enable/Disable lanes in a PHY module as specified by the txstates
 * (transmit) and rxstates (receive) parameters.
 *
 * The SFP(+) supports a hardware TX_DISABLE (bit-0) and a software
 * TX_DISABLE (bit-1).  These are specified in txstates.
 *
 * The QSFP supports independent Transmit and Receive software
 * disables for each lane.  The Transmit Lane Disable states are
 * specified in txstates bits 0-3, the Receive Lane Disable states are
 * specified in rxstates bits 0-3.
 *
 * The CXP supports independent Transmit and Receive software disables
 * for each lane and two software disable modes: an Output Disable and
 * a Lane (Channel) Disable.  The Transmit Lane Disable states are
 * specified in txstates bits 0-23, the Receive Lane Disable states are
 * specified in rxstates bits 0-23.
 *
 *
 * @param phymod PHY module
 * @param[in] txstates Lane Disable states for the module
 * @param[in] rxstates Lane Disable states for the module
 *
 * @return 0 on success. Set errno and return -1 on error.
 *
 */
int nfp_phymod_write_lanedisable(struct nfp_phymod *phymod, uint32_t txstate,
				 uint32_t rxstate);

/**
 * Read a PHY module address (8-bit).
 * @ingroup nfp6000-only
 *
 * @param phymod PHY module
 * @param[in] addr address
 * @param[out] data return value
 *
 * @return 0 on success. Set errno and return -1 on error.
 *
 */
int nfp_phymod_read8(struct nfp_phymod *phymod, uint32_t addr, uint8_t *data);

/**
 * Write a PHY module address (8-bit).
 * @ingroup nfp6000-only
 *
 * @param phymod PHY module
 * @param[in] addr address
 * @param[in] data value
 *
 * @return 0 on success. Set errno and return -1 on error.
 *
 */
int nfp_phymod_write8(struct nfp_phymod *phymod, uint32_t addr, uint8_t data);

#endif
