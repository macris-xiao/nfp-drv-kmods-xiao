/*
 * Copyright (C) 2008-2011, Netronome Systems, Inc.  All rights reserved.
 *
 * Disclaimer: this file is provided without any warranty
 * as part of an early-access program, and the content is
 * bound to change before the final release.
 */

#ifndef NFP3200_NFP_EVENT_H
#define NFP3200_NFP_EVENT_H

/* Event bus providers */
#define NFP_EVENT_SOURCE_LOCAL_SCRATCH(cluster)	(cluster)
#define NFP_EVENT_SOURCE_MSF0			8
#define NFP_EVENT_SOURCE_PCIE			9
#define NFP_EVENT_SOURCE_MSF1			10
#define NFP_EVENT_SOURCE_CRYPTO			11
#define NFP_EVENT_SOURCE_ARM			12
#define NFP_EVENT_SOURCE_DDR			14
#define NFP_EVENT_SOURCE_SHAC			15

/* Event bus types */
#define NFP_EVENT_TYPE_FIFO_NOT_EMPTY		0
#define NFP_EVENT_TYPE_FIFO_NOT_FULL		1
#define NFP_EVENT_TYPE_DMA			2
#define NFP_EVENT_TYPE_PROCESS			3
#define NFP_EVENT_TYPE_STATUS			4
#define NFP_EVENT_TYPE_FIFO_UNDERFLOW		8
#define NFP_EVENT_TYPE_FIFO_OVERFLOW		9
#define NFP_EVENT_TYPE_ECC_SINGLE_CORRECTION	10
#define NFP_EVENT_TYPE_ECC_MULTI_ERROR		11
#define NFP_EVENT_TYPE_ECC_SINGLE_ERROR		12

#endif /* NFP3200_NFP_EVENT_H */
