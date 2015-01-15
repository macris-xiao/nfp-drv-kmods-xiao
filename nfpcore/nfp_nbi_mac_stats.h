/**
 * Copyright (C) 2013-2015 Netronome Systems, Inc.  All rights reserved.
 * Author: Tony Egan <tony.egan@netronome.com>
 *
 * @file nfp_nbi_mac_stats.h
 * nfp6000 MAC API statistics functions
 */

/*
 * MAC statistics are accumulated by the nfp_nbi_mac_statsd daemon into
 * 64-bit counters in a reserved memory area.  Deamon parameters will
 * specify ports (active_ports) & channels (active_chans) to be
 * monitored and how often the statistics registers are read (period). At
 * initialization the daemon will zero all statistics registers and
 * cumulative memory counters and set 'ready' true.
 *
 * Each period the deamon will check "active" and update the
 * cumulative statistics for the specified ports/channels. When
 * complete it will increment 'updated'.  Each cycle It will also
 * check "clear" to see if any counters should be cleared.  When the
 * daemon clears a counter it increments the 'cleared' variable for
 * that port/channel.
 *
 * Multiple clients may read the cumulative statistics collected by
 * the daemon.  The API calls facilitate access by providing three
 * statistics read calls; one for port statistics, one for channel
 * statistics and one for Interlaken statistics.  A range of ports or
 * channels may be specified.  The daemon's state variables are also
 * accessible via an API call so that clients can read active
 * channels, period, ready and updated status.
 *
 * An API call is provided to allow clients to add to the active ports
 * list but they are not allowed remove ports from the list.
 *
 * An API call is provided allowing clients to clear the stats for a
 * particular port or channel range.
 *
 * There is no protection against multiple clients requesting port or
 * channel clears - but each clear action will be reflected in the
 * 'cleared' counter included in each port and channel stats block.
 */

#ifndef __NFP_NBI_MAC_STATS_H__
#define __NFP_NBI_MAC_STATS_H__

#include "nfp.h"
#include "nfp_cpp.h"

#include "nfp_nbi_mac_misc.h"

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

/**
 * Specification of the ports and channels to be monitored.  These are
 * initialized when the daemon is started and can be modified to
 * add ports and channels while the daemon is running. Ports/channels
 * cannot be removed from scan while the daemon is running.
 */
struct nfp_nbi_mac_stats_spec {
/**
 * One bit for each port to be monitored.
 */
	uint64_t ports;
/**
 * One bit for each channel [0-63] to be monitored.
 */
	uint64_t chans63_0;
/**
 * One bit for each channel [64-127] to be monitored.
 */
	uint64_t chans127_64;
/**
 * Interlaken channels - one for each ilk core to be monitored.
 */
	uint32_t ilk[2];
};

/**
 * Structure used to maintain the state of the statistics daemon.
 *
 * The scan period of the statistics daemon is specified when the
 * daemon is started.  It may be changed while the daemon is running.
 *
 * When the daemon starts it zeroes all statistics registers and
 * cumulative memory counters and sets 'ready' true.
 *
 * Each period the daemon checks "active" to determine what
 * ports/channels must be scanned and then initiates an update of the
 * cumulative statistics for those ports/channels.  When the update is
 * complete the daemon will increment 'updated'.
 *
 * Each cycle the daemon also checks "clear" to see if any counters
 * should be cleared.  When the daemon clears a set of counters it increments
 * the 'clr_count' variable for that port/channel.
 *
 */
struct nfp_nbi_mac_stats_state {
	/**
	 * Scan period of the statistics daemon (mS)
	 */
	uint32_t period;
	/**
	 * Flag indicating that the daemon is initialized
	 */
	uint32_t ready;
	/**
	 * Counter incremented every cycle after the daemon completes a scan and update.
	 */
	uint64_t updated;
	/**
	 * Specification of the ports and channels to be monitored.  These are
	 */
	struct nfp_nbi_mac_stats_spec active;
	/**
	 * Specification of the port and channel counters to be cleared.
	 */
	struct nfp_nbi_mac_stats_spec clear;
	/**
	 * Count of Ethernet port counter clears.
	 */
	uint64_t portclr_count[24];
	/**
	 * Count of channel counter clears.
	 */
	uint64_t chanclr_count[128];
	/**
	 * Count of Interlaken counter clears.
	 */
	uint64_t ilkclr_count[2];
};

/**
 * Statistics structure for one MAC
 *
 * Two of these will be used - one per NBI
 */
struct nfp_nbi_mac_stats {
	/**
	 * Port statistics
	 */
	struct nfp_nbi_mac_portstats portstats[24];
	/**
	 * Channel statistics
	 */
	struct nfp_nbi_mac_chanstats chanstats[128];
	/**
	 * Interlaken statistics
	 */
	struct nfp_nbi_mac_ilkstats ilkstats[2];
	/**
	 * Daemon state
	 */
	struct nfp_nbi_mac_stats_state state;
};

/**
 * Statistics structure for both MACs
 */
#define NFP_NBI_MAC_STATS_MAGIC 0xae6d730000000000ULL /* 0xae,'m','s', 0, .. */

struct nfp_nbi_mac_allstats {
	uint64_t magic;             /* NFP_NBI_MAC_STATS_MAGIC */
	struct nfp_nbi_mac_stats mac[2];
};

/* / @cond */
/* Daemon functions */

/*
 * Aquire the NFP memory area reserved for cumulative stats.
 * @ingroup nfp6000-only
 *
 *
 * mac->statsa is set to the handle for the reserved area.
 *
 *  @param nbi NBI handle
 *  @return 0 on success, -1 if can't aquire the area or range check fails.
 */
int nfp_nbi_mac_stats_reserve_mem(struct nfp_nbi_dev *nbi);

/*
 * Write cumulative stats to the NFP Memory area.
 * @ingroup nfp6000-only
 *
 *  Only writes active ports/channels.
 *
 *  @param nbi NBI handle
 *  @param stats pointer to cumulative stats structure
 *  @return 0 on success, -1 on error
 */
int nfp_nbi_mac_stats_write_mem(struct nfp_nbi_dev *nbi,
				struct nfp_nbi_mac_allstats *stats);

/*
 * Initialize the MAC statistics collection.
 * @ingroup nfp6000-only
 *
 * Accepts a pointer to a memory area for the 64-bit cumulative stats
 * counters, and a specification of the ports & channels to be
 * monitored.
 *
 * Calls the init functions for port, channel & interlaken stats
 * Initializes the statistics state variables.
 * Sets ready true when done.
 *
 *  @param nbi NBI handle
 *  @param stats pointer to nfp memory area for stats
 *  @param spec  pointer to stats specification
 *
 *
 */
int nfp_nbi_mac_stats_init(struct nfp_nbi_dev *nbi,
			   struct nfp_nbi_mac_allstats *stats,
			   struct nfp_nbi_mac_stats_spec *spec);

/*
 * Initialize the parameters for port stats collection.
 * @ingroup nfp6000-only
 *
 *  @param nbi NBI handle
 *  @param stats pointer to memory area for stats
 *  @param spec pointer to stats specification
 *
 */
int nfp_nbi_mac_stats_init_ports(struct nfp_nbi_dev *nbi,
				 struct nfp_nbi_mac_allstats *stats,
				 struct nfp_nbi_mac_stats_spec *spec);

/*
 *  Initialize the parameters for channel stats collection.
 * @ingroup nfp6000-only
 *
 *  @param nbi NBI handle
 *  @param stats pointer to memory area for stats
 *  @param spec pointer to stats specification
 *
 */
int nfp_nbi_mac_stats_init_chans(struct nfp_nbi_dev *nbi,
				 struct nfp_nbi_mac_allstats *stats,
				 struct nfp_nbi_mac_stats_spec *spec);

/*
 *  Initialize the parameters for Interlaken stats collection.
 * @ingroup nfp6000-only
 *
 *  @param nbi NBI handle
 *  @param stats pointer to memory area for stats
 *  @param spec pointer to stats specification
 *
 */
int nfp_nbi_mac_stats_init_ilks(struct nfp_nbi_dev *nbi,
				struct nfp_nbi_mac_allstats *stats,
				struct nfp_nbi_mac_stats_spec *spec);

/*
 *  Accumulate the port stats registers into statistics memory.
 * @ingroup nfp6000-only
 *
 *  @param nbi NBI handle
 *  @param stats pointer to memory area for stats
 *
 */
int nfp_nbi_mac_stats_update_ports(struct nfp_nbi_dev *nbi,
				   struct nfp_nbi_mac_allstats *stats);

/*
 *  Accumulate the channel stats registers into statistics memory.
 * @ingroup nfp6000-only
 *
 *  @param nbi NBI handle
 *  @param stats pointer to memory area for stats
 *
 */
int nfp_nbi_mac_stats_update_chans(struct nfp_nbi_dev *nbi,
				   struct nfp_nbi_mac_allstats *stats);

/*
 *  Accumulate the Interlaken stats registers into statistics memory.
 * @ingroup nfp6000-only
 *
 *  @param nbi NBI handle
 *  @param stats pointer to memory area for stats
 *
 */
int nfp_nbi_mac_stats_update_ilks(struct nfp_nbi_dev *nbi,
				  struct nfp_nbi_mac_allstats *stats);


/* / @endcond */

/* Client functions */

/**
 *  Read the statistics for all active ports and channels from stats
 *  memory. Caller must reserve space for the full stats struct.
 * @ingroup nfp6000-only
 *
 *  @param nbi NBI handle
 *  @param[out] stats pointer to memory area for stats
 *
 */
int nfp_nbi_mac_stats_read_all(struct nfp_nbi_dev *nbi,
			       struct nfp_nbi_mac_allstats *stats);

/**
 *  Read the statistics for an active port
 *  from stats memory. Caller must reserve space for the stats.
 * @ingroup nfp6000-only
 *
 *  @param nbi NBI handle
 *  @param port Port
 *  @param[out] stats pointer to memory area for stats
 *
 */
int nfp_nbi_mac_stats_read_port(struct nfp_nbi_dev *nbi, int port,
				struct nfp_nbi_mac_portstats *stats);

/**
 *  Read the statistics for an active channel
 *  from stats memory. Caller must reserve space for the
 *  stats.
 * @ingroup nfp6000-only
 *
 *  @param nbi NBI handle
 *  @param chan Channel
 *  @param[out] stats pointer to memory area for channel stats
 *
 */
int nfp_nbi_mac_stats_read_chan(struct nfp_nbi_dev *nbi, int chan,
				struct nfp_nbi_mac_chanstats *stats);

/**
 * Read the statistics for the specified Interlaken core from stats
 * memory.  Possible two interlaken cores active per MAC.
 * @ingroup nfp6000-only
 *
 *  @param nbi NBI handle
 *  @param core interlaken core
 *  @param[out] stats pointer to memory area for stats
 *
 */
int nfp_nbi_mac_stats_read_ilks(struct nfp_nbi_dev *nbi, int core,
				struct nfp_nbi_mac_ilkstats *stats);

/**
 * Read the statistics state variables.
 * @ingroup nfp6000-only
 *
 *  @param nbi NBI handle
 *  @param[out] state pointer to memory area for stats state
 *
 */
int nfp_nbi_mac_stats_read_state(struct nfp_nbi_dev *nbi,
				 struct nfp_nbi_mac_stats_state *state);

/**
 *  Add a port to the daemon's active scan list.
 * @ingroup nfp6000-only
 *
 *  Note ports/channels cannot be removed from the daemon's scan list
 *  by this call.
 *
 *  @param nbi NBI handle
 *  @param active pointer to memory area for stats state
 *
 */
int nfp_nbi_mac_stats_write_active(struct nfp_nbi_dev *nbi,
				   struct nfp_nbi_mac_stats_spec *active);

/**
 *  Ask the daemon to clear specified port/channels stats counters
 * @ingroup nfp6000-only
 *
 *  Note: The daemon's clear state variables are set by this
 *  call. There is nothing to prevent multiple clients posting
 *  clear requests.  The daemon will honor all clear requests -
 *  i.e. it ORs them together.
 *
 *  @param nbi NBI handle
 *  @param clear pointer to memory area for stats state
 *
 */
int nfp_nbi_mac_stats_write_clear(struct nfp_nbi_dev *nbi,
				  struct nfp_nbi_mac_stats_spec *clear);

#endif
