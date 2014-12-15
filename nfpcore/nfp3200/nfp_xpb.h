/*
 * Copyright (C) 2008-2011, Netronome Systems, Inc.  All rights reserved.
 *
 * Disclaimer: this file is provided without any warranty
 * as part of an early-access program, and the content is
 * bound to change before the final release.
 */

#ifndef NFP3200_NFP_XPB_H
#define NFP3200_NFP_XPB_H

#define NFP_XPB_SIZE		0x02000000

#define NFP_XPB_DEST(cluster, device)	\
	((((cluster) & 0x1f) << 20) | (((device) & 0x3f) << 14))
#define NFP_XPB_DEST_SIZE	(1 << 14)

#define NFP_XPB_DEST_CLUSTER_of(xpb_dest)	(((xpb_dest) >> 20) & 0x1f)
#define NFP_XPB_DEST_DEVICE_of(xpb_dest)	(((xpb_dest) >> 14) & 0x3f)
#define NFP_XPB_DEST_ADDR_of(xpb_addr)		((xpb_addr) & 0x3fff)


#define NFP_ME_CLUSTER_START(me) \
	NFP_XPB_DEST(me, 1)	/* Cluster Config */
#define NFP_ME_LSCRATCH_CSR_START(me) \
	NFP_XPB_DEST(me, 2)	/* Local scratch Config */
#define NFP_ME_LSCRATCH_ECC_START(me) \
	NFP_XPB_DEST(me, 3)	/* Local scratch ECC Monitor */

/* Crypto CSRs */
#define NFP_CRYPTO_CIF_START \
	NFP_XPB_DEST(19, 1)	/* CIF CSRs */
/* ... */

/* ARM CSRs */
/* ... */
#define NFP_ARM_INTR_START \
	NFP_XPB_DEST(20, 5)	/* Interrupt manager */
#define NFP_ARM_CFG_START \
	NFP_XPB_DEST(20, 6)	/* Local CSRs */

#endif /* NFP3200_NFP_XPB_H */
