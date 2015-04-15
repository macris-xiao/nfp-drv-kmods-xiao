/**
 * Copyright (C) 2013-2015 Netronome Systems, Inc.  All rights reserved.
 *
 * @file nfp_nbi.h
 * nfp6000 NBI API functions
 *
 */

#ifndef __NFP_NBI_H__
#define __NFP_NBI_H__

#include "nfp.h"
#include "nfp_cpp.h"

/* Implemented in nfp_nbi.c */

/*
 * NFP NBI device handle
 */
struct nfp_nbi_dev;

struct nfp_nbi_dev *nfp_nbi_open(struct nfp_device *nfp, int nbi);
void nfp_nbi_close(struct nfp_nbi_dev *nfpnbidev);

int nfp_nbi_index(struct nfp_nbi_dev *nfpnbidev);

int nfp_nbi_mac_regr(struct nfp_nbi_dev *nbi, uint32_t base,
		     uint32_t reg, uint32_t *data);
int nfp_nbi_mac_regw(struct nfp_nbi_dev *nbi, uint32_t base, uint32_t reg,
		     uint32_t mask, uint32_t data);

/* Offset into CTM */
#define NFP_NBI_MAC_STATS_OFFSET          0xed000

/* Single chan stats - 0:7   chan */
#define NFP_NBI_MAC_STATS_ACCCMD_INIT     0x00000000
/* read access */
#define NFP_NBI_MAC_STATS_ACCCMD_READ     0x01000000
/* reset counters */
#define NFP_NBI_MAC_STATS_ACCCMD_RESET    0x04000000
/* clear ECC/parity errors */
#define NFP_NBI_MAC_STATS_ACCCMD_ECCCLR   0x05000000
/* Packets, Bytes, Bad Packets */
#define NFP_NBI_MAC_STATS_ACCTYPE_PKTS    0x00000000
/* FC_Error */
#define NFP_NBI_MAC_STATS_ACCTYPE_FC      0x00010000
/* RX_CRC_Error */
#define NFP_NBI_MAC_STATS_ACCTYPE_RXCRC   0x00020000

/**
 * MAC statistics are accumulated by the nfp_nbi_mac_statsd daemon into
 * 64-bit counters in a reserved memory area. The following structures
 * define the Ethernet port, Channel and Interlaken statistics
 * counters.
 *
 * Port statistics counters
 */
struct nfp_nbi_mac_portstats {
	uint64_t RxAlignmentErrors;
	uint64_t RxCBFCPauseFramesReceived0;
	uint64_t RxCBFCPauseFramesReceived1;
	uint64_t RxCBFCPauseFramesReceived2;
	uint64_t RxCBFCPauseFramesReceived3;
	uint64_t RxCBFCPauseFramesReceived4;
	uint64_t RxCBFCPauseFramesReceived5;
	uint64_t RxCBFCPauseFramesReceived6;
	uint64_t RxCBFCPauseFramesReceived7;
	uint64_t RxFrameCheckSequenceErrors;
	uint64_t RxFrameTooLongErrors;
	uint64_t RxFramesReceivedOK;
	uint64_t RxInRangeLengthErrors;
	uint64_t RxPIfInBroadCastPkts;
	uint64_t RxPIfInErrors;
	uint64_t RxPIfInMultiCastPkts;
	uint64_t RxPIfInUniCastPkts;
	uint64_t RxPStatsDropEvents;
	uint64_t RxPStatsFragments;
	uint64_t RxPStatsJabbers;
	uint64_t RxPStatsOversizePkts;
	uint64_t RxPStatsPkts;
	uint64_t RxPStatsPkts1024to1518octets;
	uint64_t RxPStatsPkts128to255octets;
	uint64_t RxPStatsPkts1519toMaxoctets;
	uint64_t RxPStatsPkts256to511octets;
	uint64_t RxPStatsPkts512to1023octets;
	uint64_t RxPStatsPkts64octets;
	uint64_t RxPStatsPkts65to127octets;
	uint64_t RxPStatsUndersizePkts;
	uint64_t RxPauseMacCtlFramesReceived;
	uint64_t RxVlanReceivedOK;
	uint64_t TxCBFCPauseFramesTransmitted0;
	uint64_t TxCBFCPauseFramesTransmitted1;
	uint64_t TxCBFCPauseFramesTransmitted2;
	uint64_t TxCBFCPauseFramesTransmitted3;
	uint64_t TxCBFCPauseFramesTransmitted4;
	uint64_t TxCBFCPauseFramesTransmitted5;
	uint64_t TxCBFCPauseFramesTransmitted6;
	uint64_t TxCBFCPauseFramesTransmitted7;
	uint64_t TxFramesTransmittedOK;
	uint64_t TxPIfOutBroadCastPkts;
	uint64_t TxPIfOutErrors;
	uint64_t TxPIfOutMultiCastPkts;
	uint64_t TxPIfOutUniCastPkts;
	uint64_t TxPStatsPkts1024to1518octets;
	uint64_t TxPStatsPkts128to255octets;
	uint64_t TxPStatsPkts1518toMAXoctets;
	uint64_t TxPStatsPkts256to511octets;
	uint64_t TxPStatsPkts512to1023octets;
	uint64_t TxPStatsPkts64octets;
	uint64_t TxPStatsPkts65to127octets;
	uint64_t TxPauseMacCtlFramesTransmitted;
	uint64_t TxVlanTransmittedOK;
	uint64_t RxPIfInOctets;
	uint64_t TxPIfOutOctets;
};

/**
 * Channel statistics counters
 */
struct nfp_nbi_mac_chanstats {
	uint64_t RxCIfInErrors;
	uint64_t RxCIfInUniCastPkts;
	uint64_t RxCIfInMultiCastPkts;
	uint64_t RxCIfInBroadCastPkts;
	uint64_t RxCStatsPkts;
	uint64_t RxCStatsPkts64octets;
	uint64_t RxCStatsPkts65to127octets;
	uint64_t RxCStatsPkts128to255octets;
	uint64_t RxCStatsPkts256to511octets;
	uint64_t RxCStatsPkts512to1023octets;
	uint64_t RxCStatsPkts1024to1518octets;
	uint64_t RxCStatsPkts1519toMaxoctets;
	uint64_t RxChanFramesReceivedOK;
	uint64_t RxChanVlanReceivedOK;
	uint64_t TxCIfOutBroadCastPkts;
	uint64_t TxCIfOutErrors;
	uint64_t TxCIfOutUniCastPkts;
	uint64_t TxChanFramesTransmittedOK;
	uint64_t TxChanVlanTransmittedOK;
	uint64_t TxCIfOutMultiCastPkts;
	uint64_t RxCIfInOctets;
	uint64_t RxCStatsOctets;
	uint64_t TxCIfOutOctets;
};

/**
 * Interlaken single channel statistics counters
 */
struct nfp_nbi_mac_ilkstats {
	uint64_t LkTxStatsFill;
	uint64_t LkTxStatsParity;
	uint64_t LkTxStatsRdParity;
	uint64_t LkTxStatsWrParity;

	uint64_t LkTxStatsWrByte;
	uint64_t LkTxStatsWrPkt;
	uint64_t LkTxStatsWrErr;
	uint64_t LkTxStatsRdByte;
	uint64_t LkTxStatsRdPkt;
	uint64_t LkTxStatsRdErr;

	uint64_t LkRxStatsFill;
	uint64_t LkRxStatsParity;
	uint64_t LkRxStatsRdParity;
	uint64_t LkRxStatsWrParity;

	uint64_t LkRxStatsWrByte;
	uint64_t LkRxStatsWrPkt;
	uint64_t LkRxStatsWrErr;
	uint64_t LkRxStatsRdByte;
	uint64_t LkRxStatsRdPkt;
	uint64_t LkRxStatsRdErr;
};

int nfp_nbi_mac_stats_read_port(struct nfp_nbi_dev *nbi, int port,
				struct nfp_nbi_mac_portstats *stats);

int nfp_nbi_mac_stats_read_chan(struct nfp_nbi_dev *nbi, int chan,
				struct nfp_nbi_mac_chanstats *stats);

int nfp_nbi_mac_stats_read_ilks(struct nfp_nbi_dev *nbi, int core,
				struct nfp_nbi_mac_ilkstats *stats);

/* Implemented in nfp_nbi_mac_eth.c */

#define NFP_NBI_MAC_DQDWRR_TO 1000	/* wait for dwrr register access */

#define NFP_NBI_MAC_CHAN_MAX            127
#define NFP_NBI_MAC_CHAN_PAUSE_WM_MAX  2047
#define NFP_NBI_MAC_PORT_HWM_MAX       2047
#define NFP_NBI_MAC_PORT_HWM_DELTA_MAX   31

#define NFP_NBI_MAC_ENET_OFF		0
#define NFP_NBI_MAC_ILK			1
#define NFP_NBI_MAC_ENET_10M		2
#define NFP_NBI_MAC_ENET_100M		3
#define NFP_NBI_MAC_ENET_1G		4
#define NFP_NBI_MAC_ENET_10G		5
#define NFP_NBI_MAC_ENET_40G		6
#define NFP_NBI_MAC_ENET_100G		7

#define NFP_NBI_MAC_SINGLE_LANE(l) ((l == NFP_NBI_MAC_ENET_10M)  || \
				(l == NFP_NBI_MAC_ENET_100M) || \
				(l == NFP_NBI_MAC_ENET_1G)   || \
				(l == NFP_NBI_MAC_ENET_10G))

#define NFP_NBI_MAC_ONEG_MODE(l) ((l == NFP_NBI_MAC_ENET_10M)  || \
			      (l == NFP_NBI_MAC_ENET_100M) || \
			      (l == NFP_NBI_MAC_ENET_1G))

int nfp_nbi_mac_eth_ifdown(struct nfp_nbi_dev *nbi, int core, int port);
int nfp_nbi_mac_eth_ifup(struct nfp_nbi_dev *nbi, int core, int port);
int nfp_nbi_mac_eth_read_linkstate(struct nfp_nbi_dev *nbi,
				   int core, int port, uint32_t *linkstate);
int nfp_nbi_mac_eth_write_mac_addr(struct nfp_nbi_dev *nbi,
				   int core, int port, uint64_t hwaddr);
int nfp_nbi_mac_eth_read_mac_addr(struct nfp_nbi_dev *nbi, int core,
				  int port, uint64_t *waddr);
int nfp_nbi_mac_eth_read_mode(struct nfp_nbi_dev *nbi, int core, int port);

#endif
