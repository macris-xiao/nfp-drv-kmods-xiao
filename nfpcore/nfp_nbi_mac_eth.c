/**
 * Copyright (C) 2013-2014 Netronome Systems, Inc.  All rights reserved.
 *
 * @file nfp_nbi_mac_eth.c
 * nfp6000 MAC API functions
 *
 * Functions mostly related to the MAC Ethernet
 * (Hydra) core and the MAC-NBI channel interface.
 */

#include <linux/kernel.h>
#include <linux/module.h>

#include "nfp.h"
#include "nfp_nbi.h"
#include "nfp_nbi_mac_eth.h"

#define NFP_MAC                                     0x3a0000
#define NFP_MAC_EgCmdPrependEn0Hi                   0x00000204
#define NFP_MAC_EgCmdPrependEn0Lo                   0x00000200
#define NFP_MAC_EgCmdPrependEn1Hi                   0x0000020c
#define NFP_MAC_EgCmdPrependEn1Lo                   0x00000208
#define NFP_MAC_IgDqTdmMemoryRdData                 0x000007f8
#define   NFP_MAC_IgDqTdmMemoryRdData_TdmMemRdAddr_of(_x) (((_x) >> 24) & 0x3f)
#define   NFP_MAC_IgDqTdmMemoryRdData_TdmMemRdDataValid (1 << 21)
#define   NFP_MAC_IgDqTdmMemoryRdData_TdmPortArbEnable (1 << 15)
#define   NFP_MAC_IgDqTdmMemoryRdData_TdmPortWeightRdData_of(_x) \
						(((_x) >> 0) & 0x7fff)
#define NFP_MAC_IgDqTdmMemoryRW                     0x000007d8
#define   NFP_MAC_IgDqTdmMemoryRW_TdmMemRdBusy      (1 << 21)
#define   NFP_MAC_IgDqTdmMemoryRW_TdmMemRdWrAddr(_x) (((_x) & 0x3f) << 24)
#define   NFP_MAC_IgDqTdmMemoryRW_TdmMemWrBusy      (1 << 20)
#define   NFP_MAC_IgDqTdmMemoryRW_TdmPortArbEnable  (1 << 15)
#define   NFP_MAC_IgDqTdmMemoryRW_TdmPortWeightWrData(_x) (((_x) & 0x7fff) << 0)
#define NFP_MAC_IgPortPrependEn0                    0x000001dc
#define NFP_MAC_IgPortPrependEn1                    0x000001e0
#define   NFP_MAC_IgPrependEn_PrependEn0(_x)        (((_x) & 0x3) << 0)
#define     NFP_MAC_IgPrependEn_PrependEn0_No_Prepend (0)
#define   NFP_MAC_IgPrependEn_PrependEn0_of(_x)     (((_x) >> 0) & 0x3)
#define     NFP_MAC_IgPrependEn_PrependEn0_Prepend_CHK (1)
#define     NFP_MAC_IgPrependEn_PrependEn0_Prepend_TS (2)
#define     NFP_MAC_IgPrependEn_PrependEn0_Prepend_TS_CHK (3)
#define   NFP_MAC_IgPrependEn_PrependEn1(_x)        (((_x) & 0x3) << 2)
#define   NFP_MAC_IgPrependEn_PrependEn10(_x)       (((_x) & 0x3) << 20)
#define   NFP_MAC_IgPrependEn_PrependEn10_of(_x)    (((_x) >> 20) & 0x3)
#define   NFP_MAC_IgPrependEn_PrependEn11(_x)       (((_x) & 0x3) << 22)
#define   NFP_MAC_IgPrependEn_PrependEn11_of(_x)    (((_x) >> 22) & 0x3)
#define   NFP_MAC_IgPrependEn_PrependEn1_of(_x)     (((_x) >> 2) & 0x3)
#define   NFP_MAC_IgPrependEn_PrependEn2(_x)        (((_x) & 0x3) << 4)
#define   NFP_MAC_IgPrependEn_PrependEn2_of(_x)     (((_x) >> 4) & 0x3)
#define   NFP_MAC_IgPrependEn_PrependEn3(_x)        (((_x) & 0x3) << 6)
#define   NFP_MAC_IgPrependEn_PrependEn3_of(_x)     (((_x) >> 6) & 0x3)
#define   NFP_MAC_IgPrependEn_PrependEn4(_x)        (((_x) & 0x3) << 8)
#define   NFP_MAC_IgPrependEn_PrependEn4_of(_x)     (((_x) >> 8) & 0x3)
#define   NFP_MAC_IgPrependEn_PrependEn5(_x)        (((_x) & 0x3) << 10)
#define   NFP_MAC_IgPrependEn_PrependEn5_of(_x)     (((_x) >> 10) & 0x3)
#define   NFP_MAC_IgPrependEn_PrependEn6(_x)        (((_x) & 0x3) << 12)
#define   NFP_MAC_IgPrependEn_PrependEn6_of(_x)     (((_x) >> 12) & 0x3)
#define   NFP_MAC_IgPrependEn_PrependEn7(_x)        (((_x) & 0x3) << 14)
#define   NFP_MAC_IgPrependEn_PrependEn7_of(_x)     (((_x) >> 14) & 0x3)
#define   NFP_MAC_IgPrependEn_PrependEn8(_x)        (((_x) & 0x3) << 16)
#define   NFP_MAC_IgPrependEn_PrependEn8_of(_x)     (((_x) >> 16) & 0x3)
#define   NFP_MAC_IgPrependEn_PrependEn9(_x)        (((_x) & 0x3) << 18)
#define   NFP_MAC_IgPrependEn_PrependEn9_of(_x)     (((_x) >> 18) & 0x3)
#define   NFP_MAC_IGPREPENDEN_PREPEND_LK(_x)        (((_x) & 0x3) << 24)
#define NFP_MAC_MacBlkReset                         0x00000000
#define   NFP_MAC_MacBlkReset_MacCoreClkEnHy0       (1 << 4)
#define   NFP_MAC_MacBlkReset_MacCoreClkEnHy1       (1 << 5)
#define   NFP_MAC_MacBlkReset_MacCoreClkEnLk0       (1 << 6)
#define   NFP_MAC_MacBlkReset_MacCoreClkEnLk1       (1 << 7)
#define   NFP_MAC_MacBlkReset_MacX2ClkEnLk0         (1 << 8)
#define   NFP_MAC_MacBlkReset_MacX2ClkEnLk1         (1 << 9)
#define NFP_MAC_MacEgPort11to9ChanAssign            0x0000024c
#define NFP_MAC_MacEgPort14to12ChanAssign           0x00000250
#define NFP_MAC_MacEgPort17to15ChanAssign           0x00000254
#define NFP_MAC_MacEgPort20to18ChanAssign           0x00000258
#define NFP_MAC_MacEgPort23to21ChanAssign           0x0000025c
#define NFP_MAC_MacEgPort2to0ChanAssign             0x00000240
#define NFP_MAC_MacEgPort5to3ChanAssign             0x00000244
#define NFP_MAC_MacEgPort8to6ChanAssign             0x00000248
#define NFP_MAC_MacEgPrePendDsaCtl15to00            0x000001cc
#define NFP_MAC_MacEgPrePendDsaCtlLkand23to16       0x000001d0
#define NFP_MAC_MacHyd0BlkReset                     0x00000004
#define NFP_MAC_MacHyd1BlkReset                     0x00000008
#define   NFP_MAC_MacHydBlkReset_MacHydRefRst       (1 << 0)
#define   NFP_MAC_MacHydBlkReset_MacHydRegRst       (1 << 1)
#define   NFP_MAC_MacHydBlkReset_MacHydRxFFRst      (1 << 3)
#define   NFP_MAC_MacHydBlkReset_MacHydRxSerDesIfRst(_x) (((_x) & 0xfff) << 20)
#define   NFP_MAC_MacHydBlkReset_MacHydTxFFRst      (1 << 2)
#define   NFP_MAC_MacHydBlkReset_MacHydTxSerDesIfRst(_x) (((_x) & 0xfff) << 4)
#define NFP_MAC_MacMuxCtrl                          0x0000000c
#define NFP_MAC_MacOobFcTmCntl                      0x00000268
#define   NFP_MAC_MacOobFcTmCntl_Oob1023To512En     (1 << 16)
#define   NFP_MAC_MacOobFcTmCntl_Oob1023To512Mod32M1(_x) (((_x) & 0xf) << 18)
#define   NFP_MAC_MacOobFcTmCntl_Oob1023To512MsgEn  (1 << 17)
#define   NFP_MAC_MacOobFcTmCntl_Oob511To0En        (1 << 0)
#define   NFP_MAC_MacOobFcTmCntl_Oob511To0Mod32M1(_x) (((_x) & 0xf) << 2)
#define   NFP_MAC_MacOobFcTmCntl_Oob511To0MsgEn     (1 << 1)
#define NFP_MAC_MacPcpReMap(_x)        (0x00000680 + (0x4 * ((_x) & 0x1f)))
#define   NFP_MAC_MacPcpReMap_PcpReMap0(_x)         (((_x) & 0x7) << 0)
#define   NFP_MAC_MacPcpReMap_PcpReMap0_of(_x)      (((_x) >> 0) & 0x7)
#define   NFP_MAC_MacPcpReMap_PcpReMap1(_x)         (((_x) & 0x7) << 3)
#define   NFP_MAC_MacPcpReMap_PcpReMap1_of(_x)      (((_x) >> 3) & 0x7)
#define   NFP_MAC_MacPcpReMap_PcpReMap2(_x)         (((_x) & 0x7) << 6)
#define   NFP_MAC_MacPcpReMap_PcpReMap2_of(_x)      (((_x) >> 6) & 0x7)
#define   NFP_MAC_MacPcpReMap_PcpReMap3(_x)         (((_x) & 0x7) << 9)
#define   NFP_MAC_MacPcpReMap_PcpReMap3_of(_x)      (((_x) >> 9) & 0x7)
#define   NFP_MAC_MacPcpReMap_PcpReMap4(_x)         (((_x) & 0x7) << 12)
#define   NFP_MAC_MacPcpReMap_PcpReMap4_of(_x)      (((_x) >> 12) & 0x7)
#define   NFP_MAC_MacPcpReMap_PcpReMap5(_x)         (((_x) & 0x7) << 15)
#define   NFP_MAC_MacPcpReMap_PcpReMap5_of(_x)      (((_x) >> 15) & 0x7)
#define   NFP_MAC_MacPcpReMap_PcpReMap6(_x)         (((_x) & 0x7) << 18)
#define   NFP_MAC_MacPcpReMap_PcpReMap6_of(_x)      (((_x) >> 18) & 0x7)
#define   NFP_MAC_MacPcpReMap_PcpReMap7(_x)         (((_x) & 0x7) << 21)
#define   NFP_MAC_MacPcpReMap_PcpReMap7_of(_x)      (((_x) >> 21) & 0x7)
#define   NFP_MAC_MacPcpReMap_UntaggedChan(_x)      (((_x) & 0x3f) << 24)
#define   NFP_MAC_MacPcpReMap_UntaggedChan_of(_x)   (((_x) >> 24) & 0x3f)
#define NFP_MAC_MacPort11to9ChanAssign              0x0000005c
#define NFP_MAC_MacPort14to12ChanAssign             0x00000060
#define NFP_MAC_MacPort17to15ChanAssign             0x00000064
#define NFP_MAC_MacPort20to18ChanAssign             0x00000068
#define NFP_MAC_MacPort23to21ChanAssign             0x0000006c
#define NFP_MAC_MacPort2to0ChanAssign               0x00000050
#define NFP_MAC_MacPort5to3ChanAssign               0x00000054
#define NFP_MAC_MacPort8to6ChanAssign               0x00000058
#define   NFP_MAC_MacPortChanAssign_PortBaseChan0(_x) (((_x) & 0x3f) << 0)
#define   NFP_MAC_MacPortChanAssign_PortBaseChan0_of(_x) (((_x) >> 0) & 0x3f)
#define   NFP_MAC_MacPortChanAssign_PortBaseChan1(_x) (((_x) & 0x3f) << 10)
#define   NFP_MAC_MacPortChanAssign_PortBaseChan1_of(_x) (((_x) >> 10) & 0x3f)
#define   NFP_MAC_MacPortChanAssign_PortBaseChan2(_x) (((_x) & 0x3f) << 20)
#define   NFP_MAC_MacPortChanAssign_PortBaseChan2_of(_x) (((_x) >> 20) & 0x3f)
#define   NFP_MAC_MacPortChanAssign_PortNumOfChannels0(_x) (((_x) & 0xf) << 6)
#define   NFP_MAC_MacPortChanAssign_PortNumOfChannels0_of(_x) \
					(((_x) >> 6) & 0xf)
#define   NFP_MAC_MacPortChanAssign_PortNumOfChannels1(_x) (((_x) & 0xf) << 16)
#define   NFP_MAC_MacPortChanAssign_PortNumOfChannels1_of(_x) \
					(((_x) >> 16) & 0xf)
#define   NFP_MAC_MacPortChanAssign_PortNumOfChannels2(_x) (((_x) & 0xf) << 26)
#define   NFP_MAC_MacPortChanAssign_PortNumOfChannels2_of(_x) \
					(((_x) >> 26) & 0xf)
#define NFP_MAC_MacPortHwm(_x)         (0x00000700 + (0x4 * ((_x) & 0xf)))
#define   NFP_MAC_MacPortHwm_PortDropDelta0(_x)     (((_x) & 0x1f) << 11)
#define   NFP_MAC_MacPortHwm_PortDropDelta0_of(_x)  (((_x) >> 11) & 0x1f)
#define   NFP_MAC_MacPortHwm_PortDropDelta1(_x)     (((_x) & 0x1f) << 27)
#define   NFP_MAC_MacPortHwm_PortDropDelta1_of(_x)  (((_x) >> 27) & 0x1f)
#define   NFP_MAC_MacPortHwm_PortHwm0(_x)           (((_x) & 0x7ff) << 0)
#define   NFP_MAC_MacPortHwm_PortHwm0_of(_x)        (((_x) >> 0) & 0x7ff)
#define   NFP_MAC_MacPortHwm_PortHwm1(_x)           (((_x) & 0x7ff) << 16)
#define   NFP_MAC_MacPortHwm_PortHwm1_of(_x)        (((_x) >> 16) & 0x7ff)
#define NFP_MAC_MacPrePendCtl03to00                 0x00000070
#define NFP_MAC_MacPrePendCtl07to04                 0x00000074
#define NFP_MAC_MacPrePendCtl11to08                 0x00000078
#define NFP_MAC_MacPrePendCtl15to12                 0x0000007c
#define NFP_MAC_MacPrePendCtl19to16                 0x00000080
#define   NFP_MAC_MacPrePendCtl1_EGSkipOctetsPort0(_x) (((_x) & 0xf) << 4)
#define   NFP_MAC_MacPrePendCtl1_EGSkipOctetsPort0_of(_x) (((_x) >> 4) & 0xf)
#define   NFP_MAC_MacPrePendCtl1_EGSkipOctetsPort1(_x) (((_x) & 0xf) << 12)
#define   NFP_MAC_MacPrePendCtl1_EGSkipOctetsPort1_of(_x) (((_x) >> 12) & 0xf)
#define   NFP_MAC_MacPrePendCtl1_EGSkipOctetsPort2(_x) (((_x) & 0xf) << 20)
#define   NFP_MAC_MacPrePendCtl1_EGSkipOctetsPort2_of(_x) (((_x) >> 20) & 0xf)
#define   NFP_MAC_MacPrePendCtl1_EGSkipOctetsPort3(_x) (((_x) & 0xf) << 28)
#define   NFP_MAC_MacPrePendCtl1_EGSkipOctetsPort3_of(_x) (((_x) >> 28) & 0xf)
#define   NFP_MAC_MacPrePendCtl1_IGSkipOctetsPort0(_x) (((_x) & 0xf) << 0)
#define   NFP_MAC_MacPrePendCtl1_IGSkipOctetsPort0_of(_x) (((_x) >> 0) & 0xf)
#define   NFP_MAC_MacPrePendCtl1_IGSkipOctetsPort1(_x) (((_x) & 0xf) << 8)
#define   NFP_MAC_MacPrePendCtl1_IGSkipOctetsPort1_of(_x) (((_x) >> 8) & 0xf)
#define   NFP_MAC_MacPrePendCtl1_IGSkipOctetsPort2(_x) (((_x) & 0xf) << 16)
#define   NFP_MAC_MacPrePendCtl1_IGSkipOctetsPort2_of(_x) (((_x) >> 16) & 0xf)
#define   NFP_MAC_MacPrePendCtl1_IGSkipOctetsPort3(_x) (((_x) & 0xf) << 24)
#define   NFP_MAC_MacPrePendCtl1_IGSkipOctetsPort3_of(_x) (((_x) >> 24) & 0xf)
#define NFP_MAC_MacPrePendCtl23to20                 0x00000084
#define   NFP_MAC_MacPrePendCtl2_EGSkipOctetsPort4(_x) (((_x) & 0xf) << 4)
#define   NFP_MAC_MacPrePendCtl2_EGSkipOctetsPort4_of(_x) (((_x) >> 4) & 0xf)
#define   NFP_MAC_MacPrePendCtl2_EGSkipOctetsPort5(_x) (((_x) & 0xf) << 12)
#define   NFP_MAC_MacPrePendCtl2_EGSkipOctetsPort5_of(_x) (((_x) >> 12) & 0xf)
#define   NFP_MAC_MacPrePendCtl2_EGSkipOctetsPort6(_x) (((_x) & 0xf) << 20)
#define   NFP_MAC_MacPrePendCtl2_EGSkipOctetsPort6_of(_x) (((_x) >> 20) & 0xf)
#define   NFP_MAC_MacPrePendCtl2_EGSkipOctetsPort7(_x) (((_x) & 0xf) << 28)
#define   NFP_MAC_MacPrePendCtl2_EGSkipOctetsPort7_of(_x) (((_x) >> 28) & 0xf)
#define   NFP_MAC_MacPrePendCtl2_IGSkipOctetsPort4(_x) (((_x) & 0xf) << 0)
#define   NFP_MAC_MacPrePendCtl2_IGSkipOctetsPort4_of(_x) (((_x) >> 0) & 0xf)
#define   NFP_MAC_MacPrePendCtl2_IGSkipOctetsPort5(_x) (((_x) & 0xf) << 8)
#define   NFP_MAC_MacPrePendCtl2_IGSkipOctetsPort5_of(_x) (((_x) >> 8) & 0xf)
#define   NFP_MAC_MacPrePendCtl2_IGSkipOctetsPort6(_x) (((_x) & 0xf) << 16)
#define   NFP_MAC_MacPrePendCtl2_IGSkipOctetsPort6_of(_x) (((_x) >> 16) & 0xf)
#define   NFP_MAC_MacPrePendCtl2_IGSkipOctetsPort7(_x) (((_x) & 0xf) << 24)
#define   NFP_MAC_MacPrePendCtl2_IGSkipOctetsPort7_of(_x) (((_x) >> 24) & 0xf)
#define   NFP_MAC_MacPrePendCtl3_EGSkipOctetsPort10(_x) (((_x) & 0xf) << 20)
#define   NFP_MAC_MacPrePendCtl3_EGSkipOctetsPort10_of(_x) (((_x) >> 20) & 0xf)
#define   NFP_MAC_MacPrePendCtl3_EGSkipOctetsPort11(_x) (((_x) & 0xf) << 28)
#define   NFP_MAC_MacPrePendCtl3_EGSkipOctetsPort11_of(_x) (((_x) >> 28) & 0xf)
#define   NFP_MAC_MacPrePendCtl3_EGSkipOctetsPort8(_x) (((_x) & 0xf) << 4)
#define   NFP_MAC_MacPrePendCtl3_EGSkipOctetsPort8_of(_x) (((_x) >> 4) & 0xf)
#define   NFP_MAC_MacPrePendCtl3_EGSkipOctetsPort9(_x) (((_x) & 0xf) << 12)
#define   NFP_MAC_MacPrePendCtl3_EGSkipOctetsPort9_of(_x) (((_x) >> 12) & 0xf)
#define   NFP_MAC_MacPrePendCtl3_IGSkipOctetsPort10(_x) (((_x) & 0xf) << 16)
#define   NFP_MAC_MacPrePendCtl3_IGSkipOctetsPort10_of(_x) (((_x) >> 16) & 0xf)
#define   NFP_MAC_MacPrePendCtl3_IGSkipOctetsPort11(_x) (((_x) & 0xf) << 24)
#define   NFP_MAC_MacPrePendCtl3_IGSkipOctetsPort11_of(_x) (((_x) >> 24) & 0xf)
#define   NFP_MAC_MacPrePendCtl3_IGSkipOctetsPort8(_x) (((_x) & 0xf) << 0)
#define   NFP_MAC_MacPrePendCtl3_IGSkipOctetsPort8_of(_x) (((_x) >> 0) & 0xf)
#define   NFP_MAC_MacPrePendCtl3_IGSkipOctetsPort9(_x) (((_x) & 0xf) << 8)
#define   NFP_MAC_MacPrePendCtl3_IGSkipOctetsPort9_of(_x) (((_x) >> 8) & 0xf)
#define NFP_MAC_MacPrePendDsaCtl15to00              0x00000088
#define   NFP_MAC_MacPrePendDsaCtl1_DsaTagModePort0(_x) (((_x) & 0x3) << 0)
#define   NFP_MAC_MacPrePendDsaCtl1_DsaTagModePort0_of(_x) \
							(((_x) >> 0) & 0x3)
#define   NFP_MAC_MacPrePendDsaCtl1_DsaTagModePort1(_x) (((_x) & 0x3) << 2)
#define   NFP_MAC_MacPrePendDsaCtl1_DsaTagModePort1_of(_x) \
							(((_x) >> 2) & 0x3)
#define   NFP_MAC_MacPrePendDsaCtl1_DsaTagModePort2(_x) (((_x) & 0x3) << 4)
#define   NFP_MAC_MacPrePendDsaCtl1_DsaTagModePort2_of(_x) \
							(((_x) >> 4) & 0x3)
#define   NFP_MAC_MacPrePendDsaCtl1_DsaTagModePort3(_x) (((_x) & 0x3) << 6)
#define   NFP_MAC_MacPrePendDsaCtl1_DsaTagModePort3_of(_x) \
							(((_x) >> 6) & 0x3)
#define   NFP_MAC_MacPrePendDsaCtl1_DsaTagModePort4(_x) (((_x) & 0x3) << 8)
#define   NFP_MAC_MacPrePendDsaCtl1_DsaTagModePort4_of(_x) \
							(((_x) >> 8) & 0x3)
#define   NFP_MAC_MacPrePendDsaCtl1_DsaTagModePort5(_x) (((_x) & 0x3) << 10)
#define   NFP_MAC_MacPrePendDsaCtl1_DsaTagModePort5_of(_x) \
							(((_x) >> 10) & 0x3)
#define   NFP_MAC_MacPrePendDsaCtl1_DsaTagModePort6(_x) (((_x) & 0x3) << 12)
#define   NFP_MAC_MacPrePendDsaCtl1_DsaTagModePort6_of(_x) \
							(((_x) >> 12) & 0x3)
#define   NFP_MAC_MacPrePendDsaCtl1_DsaTagModePort7(_x) (((_x) & 0x3) << 14)
#define   NFP_MAC_MacPrePendDsaCtl1_DsaTagModePort7_of(_x) \
							(((_x) >> 14) & 0x3)
#define   NFP_MAC_MacPrePendDsaCtl1_DsaTagModePort8(_x) (((_x) & 0x3) << 16)
#define   NFP_MAC_MacPrePendDsaCtl1_DsaTagModePort8_of(_x) \
							(((_x) >> 16) & 0x3)
#define   NFP_MAC_MacPrePendDsaCtl1_DsaTagModePort9(_x) (((_x) & 0x3) << 18)
#define   NFP_MAC_MacPrePendDsaCtl1_DsaTagModePort9_of(_x) \
							(((_x) >> 18) & 0x3)
#define   NFP_MAC_MacPrePendDsaCtl1_DsaTagModePort10(_x) (((_x) & 0x3) << 20)
#define   NFP_MAC_MacPrePendDsaCtl1_DsaTagModePort10_of(_x) \
							(((_x) >> 20) & 0x3)
#define   NFP_MAC_MacPrePendDsaCtl1_DsaTagModePort11(_x) (((_x) & 0x3) << 22)
#define   NFP_MAC_MacPrePendDsaCtl1_DsaTagModePort11_of(_x) \
							(((_x) >> 22) & 0x3)
#define   NFP_MAC_MacPrePendDsaCtl1_DsaTagModePort12(_x) (((_x) & 0x3) << 24)
#define   NFP_MAC_MacPrePendDsaCtl1_DsaTagModePort12_of(_x) \
							(((_x) >> 24) & 0x3)
#define   NFP_MAC_MacPrePendDsaCtl1_DsaTagModePort13(_x) (((_x) & 0x3) << 26)
#define   NFP_MAC_MacPrePendDsaCtl1_DsaTagModePort13_of(_x) \
							(((_x) >> 26) & 0x3)
#define   NFP_MAC_MacPrePendDsaCtl1_DsaTagModePort14(_x) (((_x) & 0x3) << 28)
#define   NFP_MAC_MacPrePendDsaCtl1_DsaTagModePort14_of(_x) \
							(((_x) >> 28) & 0x3)
#define   NFP_MAC_MacPrePendDsaCtl1_DsaTagModePort15(_x) (((_x) & 0x3) << 30)
#define   NFP_MAC_MacPrePendDsaCtl1_DsaTagModePort15_of(_x) \
							(((_x) >> 30) & 0x3)
#define   NFP_MAC_MacPrePendDsaCtl2_DsaTagModePort16(_x) (((_x) & 0x3) << 0)
#define   NFP_MAC_MacPrePendDsaCtl2_DsaTagModePort16_of(_x) \
							(((_x) >> 0) & 0x3)
#define   NFP_MAC_MacPrePendDsaCtl2_DsaTagModePort17(_x) (((_x) & 0x3) << 2)
#define   NFP_MAC_MacPrePendDsaCtl2_DsaTagModePort17_of(_x) \
							(((_x) >> 2) & 0x3)
#define   NFP_MAC_MacPrePendDsaCtl2_DsaTagModePort18(_x) (((_x) & 0x3) << 4)
#define   NFP_MAC_MacPrePendDsaCtl2_DsaTagModePort18_of(_x) \
							(((_x) >> 4) & 0x3)
#define   NFP_MAC_MacPrePendDsaCtl2_DsaTagModePort19(_x) (((_x) & 0x3) << 6)
#define   NFP_MAC_MacPrePendDsaCtl2_DsaTagModePort19_of(_x) \
							(((_x) >> 6) & 0x3)
#define   NFP_MAC_MacPrePendDsaCtl2_DsaTagModePort20(_x) (((_x) & 0x3) << 8)
#define   NFP_MAC_MacPrePendDsaCtl2_DsaTagModePort20_of(_x) \
							(((_x) >> 8) & 0x3)
#define   NFP_MAC_MacPrePendDsaCtl2_DsaTagModePort21(_x) (((_x) & 0x3) << 10)
#define   NFP_MAC_MacPrePendDsaCtl2_DsaTagModePort21_of(_x) \
							(((_x) >> 10) & 0x3)
#define   NFP_MAC_MacPrePendDsaCtl2_DsaTagModePort22(_x) (((_x) & 0x3) << 12)
#define   NFP_MAC_MacPrePendDsaCtl2_DsaTagModePort22_of(_x) \
							(((_x) >> 12) & 0x3)
#define   NFP_MAC_MacPrePendDsaCtl2_DsaTagModePort23(_x) (((_x) & 0x3) << 14)
#define   NFP_MAC_MacPrePendDsaCtl2_DsaTagModePort23_of(_x) \
							(((_x) >> 14) & 0x3)
#define NFP_MAC_MacPrePendDsaCtlLkand23to16         0x0000008c
#define NFP_MAC_MacSerDesEn                         0x00000010
#define   NFP_MAC_MacSerDesEn_SerDesEnable(_x)      (((_x) & 0xffffff) << 0)
#define NFP_MAC_MacSysSupCtrl                       0x00000014
#define   NFP_MAC_MacSysSupCtrl_DwrrWeightWrEnable  (1 << 16)
#define   NFP_MAC_MacSysSupCtrl_TimeStampEn         (1 << 0)
#define   NFP_MAC_MacSysSupCtrl_TimeStampFrc        (1 << 3)
#define   NFP_MAC_MacSysSupCtrl_TimeStampSet        (1 << 2)
#define NFP_MAC_MacTdm1Mode1110CrcEn                0x0000004c
#define   NFP_MAC_MacTdmMode1110Crc_MacEgressPortCrcEn(_x) \
					(((_x) & 0xfff) << 16)
#define   NFP_MAC_MacTdmMode1110Crc_MacEgressPortCrcEn_of(_x) \
					(((_x) >> 16) & 0xfff)
#define NFP_MAC_MacTimeStampNsec                    0x0000001c
#define   NFP_MAC_MacTimeStampNsec_MacTimeStampNsec_of(_x) \
					(((_x) >> 0) & 0xffffffff)
#define NFP_MAC_MacTimeStampSec                     0x00000020
#define   NFP_MAC_MacTimeStampSec_MacTimeStampSec_of(_x) \
					(((_x) >> 0) & 0xffffffff)
#define NFP_MAC_MacTimeStampSetNsec                 0x00000028
#define   NFP_MAC_MacTimeStampSetNsec_MacTimeStampSetNsec(_x) \
					(((_x) & 0xffffffff) << 0)
#define NFP_MAC_MacTimeStampSetSec                  0x0000002c
#define   NFP_MAC_MacTimeStampSetSec_MacTimeStampSetSec(_x) \
					(((_x) & 0xffffffff) << 0)
#define NFP_MAC_PauseWaterMark(_x) \
					(0x000000cc + (0x4 * ((_x) & 0x3f)))
#define   NFP_MAC_PauseWaterMark_PauseWaterMark0(_x) (((_x) & 0xfff) << 0)
#define   NFP_MAC_PauseWaterMark_PauseWaterMark0_of(_x) \
					(((_x) >> 0) & 0xfff)
#define   NFP_MAC_PauseWaterMark_PauseWaterMark1(_x) (((_x) & 0xfff) << 16)
#define   NFP_MAC_PauseWaterMark_PauseWaterMark1_of(_x) \
					(((_x) >> 16) & 0xfff)
#define NFP_MAC_ETH(_x)	\
	(NFP_MAC + 0x40000 + ((_x) & 0x1) * 0x20000)
#define NFP_MAC_ETH_MacEthSeg_EthQuantaThreshCL(_p, _x) \
	(0x00000064 + 4 * ((_p) >> 1) + (0x400 * ((_x) & 0xf)))
#define NFP_MAC_ETH_MacEthSeg_EthQuantaThreshCL_EthQuantaThresh_of(_p, _x)\
	(((_x) >> (16 * ((_p) & 1))) & 0xffff)
#define NFP_MAC_ETH_MacEthSeg_EthQuantaThreshCL_EthQuantaThresh(_p, _x)\
	(((_x) & 0xffff) << (16 * ((_p) & 1)))

#define NFP_MAC_ETH_MacEthChPcsSeg_BaseRStatus1(_x) \
					(0x00004080 + (0x400 * ((_x) & 0xf)))
#define   NFP_MAC_ETH_MacEthChPcsSeg_BaseRStatus1_BlockLocked \
					(1 << 0)
#define   NFP_MAC_ETH_MacEthChPcsSeg_BaseRStatus1_RcvLinkStatus \
					(1 << 12)
#define NFP_MAC_ETH_MacEthChPcsSeg_Ctl1(_x)     \
					(0x00004000 + (0x400 * ((_x) & 0xf)))
#define   NFP_MAC_ETH_MacEthChPcsSeg_Ctl1_Loopback \
					(1 << 14)
#define   NFP_MAC_ETH_MacEthChPcsSeg_Ctl1_SpeedSel(_x) \
					(((_x) & 0xf) << 2)
#define   NFP_MAC_ETH_MacEthChPcsSeg_Ctl1_SpeedSelection13 \
					(1 << 13)
#define   NFP_MAC_ETH_MacEthChPcsSeg_Ctl1_SpeedSelection6 \
					(1 << 6)
#define NFP_MAC_ETH_MacEthChPcsSeg_Status1(_x)  \
					(0x00004004 + (0x400 * ((_x) & 0xf)))
#define   NFP_MAC_ETH_MacEthChPcsSeg_Status1_RcvLinkStatus \
					(1 << 2)
#define NFP_MAC_ETH_MacEthGlobal_EthActCtlSeg           0x00003000
#define   NFP_MAC_ETH_MacEthGlobal_EthActCtlSeg_EthActivateSegment(_x) \
					(((_x) & 0xfff) << 0)
#define NFP_MAC_ETH_MacEthSeg_EthCmdConfig(_x)          \
					(0x00000008 + (0x400 * ((_x) & 0xf)))
#define   NFP_MAC_ETH_MacEthSeg_EthCmdConfig_EthRxEna   \
					(1 << 1)
#define   NFP_MAC_ETH_MacEthSeg_EthCmdConfig_EthTxEna   \
					(1 << 0)
#define NFP_MAC_ETH_MacEthSeg_EthFrmLength(_x)          \
					(0x00000014 + (0x400 * ((_x) & 0xf)))
#define   NFP_MAC_ETH_MacEthSeg_EthFrmLength_EthFrmLength(_x) \
					(((_x) & 0xffff) << 0)
#define   NFP_MAC_ETH_MacEthSeg_EthFrmLength_EthFrmLength_of(_x) \
					(((_x) >> 0) & 0xffff)
#define NFP_MAC_ETH_MacEthSeg_EthMacAddr0(_x)           \
					(0x0000000c + (0x400 * ((_x) & 0xf)))
#define   NFP_MAC_ETH_MacEthSeg_EthMacAddr0_EthMacAddr0(_x) \
					(((_x) & 0xffffffff) << 0)
#define NFP_MAC_ETH_MacEthSeg_EthMacAddr1(_x)           \
					(0x00000010 + (0x400 * ((_x) & 0xf)))
#define   NFP_MAC_ETH_MacEthSeg_EthMacAddr1_EthMacAddr1(_x) \
					(((_x) & 0xffff) << 0)
#define NFP_MAC_ETH_MacEthSeg_EthPauseQuantaCL(_p, _x)    \
			(0x00000054 + 4 * ((_p) >> 1) + (0x400 * ((_x) & 0xf)))
#define   NFP_MAC_ETH_MacEthSeg_EthPauseQuantaCL_EthPauseQuanta(_p, _x) \
					(((_x) & 0xffff) << (((_p)&1) * 16))
#define NFP_MAC_ETH_MacEthSeg_EthRxPauseStatus(_x)      \
					(0x00000074 + (0x400 * ((_x) & 0xf)))
#define   NFP_MAC_ETH_MacEthSeg_EthRxPauseStatus_EthRxPauseStatus_of(_x) \
					(((_x) >> 0) & 0xff)
#define NFP_MAC_ETH_EthSgmiiIfMode(_x)        \
					(0x00000350 + (0x400 * ((_x) & 0xf)))
#define   NFP_MAC_ETH_EthSgmiiIfMode_EthSgmiiEna \
					(1 << 0)
#define   NFP_MAC_ETH_EthSgmiiIfMode_EthSgmiiPcsEnable \
					(1 << 5)
#define     NFP_MAC_ETH_EthSgmiiIfMode_Speed_100Mbps (1)
#define     NFP_MAC_ETH_EthSgmiiIfMode_Speed_10Mbps (0)
#define   NFP_MAC_ETH_EthSgmiiIfMode_Speed_of(_x) \
					(((_x) >> 2) & 0x3)
#define NFP_MAC_ETH_MacEthVlanTpidCfg_EthVlanTpid0      0x00003800
#define NFP_MAC_ETH_MacEthVlanTpidCfg_EthVlanTpid1      0x00003804
#define NFP_MAC_ETH_MacEthVlanTpidCfg_EthVlanTpid2      0x00003808
#define NFP_MAC_ETH_MacEthVlanTpidCfg_EthVlanTpid3      0x0000380c
#define NFP_MAC_ETH_MacEthVlanTpidCfg_EthVlanTpid4      0x00003810
#define NFP_MAC_ETH_MacEthVlanTpidCfg_EthVlanTpid5      0x00003814
#define NFP_MAC_ETH_MacEthVlanTpidCfg_EthVlanTpid6      0x00003818
#define NFP_MAC_ETH_MacEthVlanTpidCfg_EthVlanTpid7      0x0000381c
#define   NFP_MAC_ETH_MacEthVlanTpidCfg_EthVlanTpid_EthVlanTpid(_x) \
					(((_x) & 0xffff) << 0)

/* Loopbacks (TH-7382) */
/**
 * Disable all Ethernet port loopbacks
 */
#define NFP_NBI_MAC_LOOP_OFF       0x0
/**
 * Enable Tx-Rx loopback at the PCS
 */
#define NFP_NBI_MAC_LOOP_SYSPCS    0x1

/**
 * Maximum supported frame length
 */
#define NFP_MAX_ETH_FRAME_LEN   16352

/* TM OOBFC */
/**
 * Enable out-of-band flow control for Traffic Manager queues 0-511
 */
#define NFP_NBI_MAC_Oob511to0en     0x1
/**
 * Enable out-of-band flow control for Traffic Manager queues 512-1023
 */
#define NFP_NBI_MAC_Oob1023to512en  0x10000

/**
 * Mask used for writes to EthCmdConfig register
 */
#define EthCmdConfigMask 0x387f7bfb

/**
 * Ethernet mode mask for register NFP_MAC_ETH_MacEthChPcsSeg_Ctl1
 */
#define NFP_NBI_MAC_EthChPcsCtl1_Mode_Mask \
	(NFP_MAC_ETH_MacEthChPcsSeg_Ctl1_SpeedSelection13 | \
	 NFP_MAC_ETH_MacEthChPcsSeg_Ctl1_SpeedSelection6 | \
	 NFP_MAC_ETH_MacEthChPcsSeg_Ctl1_SpeedSel(0xf))

/**
 * Ethernet 10GE mode mask for register NFP_MAC_ETH_MacEthChPcsSeg_Ctl1
 */
#define NFP_NBI_MAC_EthChPcsCtl1_Mode_10GE \
	(NFP_MAC_ETH_MacEthChPcsSeg_Ctl1_SpeedSelection13 | \
	 NFP_MAC_ETH_MacEthChPcsSeg_Ctl1_SpeedSelection6 | \
	 NFP_MAC_ETH_MacEthChPcsSeg_Ctl1_SpeedSel(0))
/**
 * Ethernet 10PASS-TS/2BASE-TL mode mask for register NFP_MAC_ETH_MacEthChPcsSeg_Ctl1
 */
#define NFP_NBI_MAC_EthChPcsCtl1_Mode_10PASSTS \
	(NFP_MAC_ETH_MacEthChPcsSeg_Ctl1_SpeedSelection13 | \
	 NFP_MAC_ETH_MacEthChPcsSeg_Ctl1_SpeedSelection6 | \
	 NFP_MAC_ETH_MacEthChPcsSeg_Ctl1_SpeedSel(0x1))
/**
 * Ethernet 802.3av mode mask for register NFP_MAC_ETH_MacEthChPcsSeg_Ctl1
 */
#define NFP_NBI_MAC_EthChPcsCtl1_Mode_8023AV \
	(NFP_MAC_ETH_MacEthChPcsSeg_Ctl1_SpeedSelection13 | \
	 NFP_MAC_ETH_MacEthChPcsSeg_Ctl1_SpeedSelection6 | \
	 NFP_MAC_ETH_MacEthChPcsSeg_Ctl1_SpeedSel(0x2))
/**
 * Ethernet 40GE mode mask for register NFP_MAC_ETH_MacEthChPcsSeg_Ctl1
 */
#define NFP_NBI_MAC_EthChPcsCtl1_Mode_40GE \
	(NFP_MAC_ETH_MacEthChPcsSeg_Ctl1_SpeedSelection13 | \
	 NFP_MAC_ETH_MacEthChPcsSeg_Ctl1_SpeedSelection6 | \
	 NFP_MAC_ETH_MacEthChPcsSeg_Ctl1_SpeedSel(0x3))
/**
 * Ethernet 100GE mode mask for register NFP_MAC_ETH_MacEthChPcsSeg_Ctl1
 */
#define NFP_NBI_MAC_EthChPcsCtl1_Mode_100GE \
	(NFP_MAC_ETH_MacEthChPcsSeg_Ctl1_SpeedSelection13 | \
	 NFP_MAC_ETH_MacEthChPcsSeg_Ctl1_SpeedSelection6 | \
	 NFP_MAC_ETH_MacEthChPcsSeg_Ctl1_SpeedSel(0x4))

/**
 * Ethernet link state indication for register MacMuxCtrl Ilk selected.
 */
#define NFP_NBI_MAC_MacMuxCtrl_Error 0x1

/**
 * Ethernet link state indication for register MacEthGlobal_EthActCtlSeg segment active
 */
#define NFP_NBI_MAC_EthActCtlSeg_Disabled 0x2

/**
 * Ethernet link state indication for register
 * MacEthChPcsSeg_EthChPcsStatus1 receive link down.
 */
#define NFP_NBI_MAC_EthChPcsStatus1_RcvLinkStatus_Down 0x4

/**
 * Ethernet link state indication for register EthChPcsBaseRStatus1
 * receive link down.
 */
#define NFP_NBI_MAC_EthChPcsBaseRStatus1_RcvLinkStatus_Down 0x8

/**
 * Ethernet link state indication for register EthChPcsBaseRStatus1
 * block not locked.
 */
#define NFP_NBI_MAC_EthChPcsBaseRStatus1_BlockLocked_False 0x10

/**
 * Ethernet link state indication for register EthCmdConfig transmit not enabled.
 */
#define NFP_NBI_MAC_EthCmdConfig_EthTxEna_False 0x20

/**
 * Ethernet link state indication for register EthCmdConfig receive not enabled.
 */
#define NFP_NBI_MAC_EthCmdConfig_EthRxEna_False 0x40

/**
 * Interlaken link state indication for register LkRxAlignStatus not aligned.
 */
#define NFP_MAC_ILK_LkRxAlignStatus_False 0x80

/**
 * Interlaken link state indication for register LkRxStatusMessage remote Rx not aligned.
 */
#define NFP_MAC_ILK_LkRxStatusMessage_False 0x100


#define NFP_NBI_MAC_NUM_PORTCHAN_REGS 8
static const int nfp_nbi_mac_ig_portchan_regs[] = {
	NFP_MAC_MacPort2to0ChanAssign,
	NFP_MAC_MacPort5to3ChanAssign,
	NFP_MAC_MacPort8to6ChanAssign,
	NFP_MAC_MacPort11to9ChanAssign,
	NFP_MAC_MacPort14to12ChanAssign,
	NFP_MAC_MacPort17to15ChanAssign,
	NFP_MAC_MacPort20to18ChanAssign,
	NFP_MAC_MacPort23to21ChanAssign
};

static const int nfp_nbi_mac_eg_portchan_regs[] = {
	NFP_MAC_MacEgPort2to0ChanAssign,
	NFP_MAC_MacEgPort5to3ChanAssign,
	NFP_MAC_MacEgPort8to6ChanAssign,
	NFP_MAC_MacEgPort11to9ChanAssign,
	NFP_MAC_MacEgPort14to12ChanAssign,
	NFP_MAC_MacEgPort17to15ChanAssign,
	NFP_MAC_MacEgPort20to18ChanAssign,
	NFP_MAC_MacEgPort23to21ChanAssign
};

/*
  void nfp_nbi_mac_addr(void); r =
  NFP_MAC_ETH_MacEthSeg_EthMacAddr0_EthMacAddr0(_x) */

int nfp_nbi_mac_eth_ifdown(struct nfp_nbi_dev *nbi, int core, int port)
{
	uint64_t r;
	uint32_t d = 0;
	uint32_t m = 0;
	int mode = 0;

	if (nbi == NULL)
		return -ENODEV;

	if ((core < 0) || (core > 1))
		return -EINVAL;

	if ((port < 0) || (port > 11))
		return -EINVAL;

	/* Disable the serdes lanes */
	mode = nfp_nbi_mac_eth_read_mode(nbi, core, port);
	if (mode < 0)
		return mode;
	switch (mode) {
	case (NFP_NBI_MAC_ENET_100G):
		m = 0x3ff << (core * 12);
		break;
	case (NFP_NBI_MAC_ENET_40G):
		m = (0xf << (port + core * 12));
		break;
	default:
		m = (0x1 << (port + core * 12));
		break;
	}
	r = NFP_MAC_MacSerDesEn;
	m = NFP_MAC_MacSerDesEn_SerDesEnable(m);
	d = 0;

	return nfp_nbi_mac_regw(nbi, NFP_MAC, r, m, d);
}
EXPORT_SYMBOL(nfp_nbi_mac_eth_ifdown);

int nfp_nbi_mac_eth_ifup(struct nfp_nbi_dev *nbi, int core, int port)
{
	int ret;
	uint64_t r;
	uint32_t d = 0;
	uint32_t m = 0;
	int mode = 0;

	if (nbi == NULL)
		return -ENODEV;

	if ((core < 0) || (core > 1))
		return -EINVAL;

	if ((port < 0) || (port > 11))
		return -EINVAL;


	/* Activate the segment */
	r = NFP_MAC_ETH_MacEthGlobal_EthActCtlSeg;
	d = NFP_MAC_ETH_MacEthGlobal_EthActCtlSeg_EthActivateSegment(port);
	m = d;
	ret = nfp_nbi_mac_regw(nbi, NFP_MAC_ETH(core), r, m, d);
	if (ret < 0)
		return ret;

	/* Enable transmit & receive paths */
	r = NFP_MAC_ETH_MacEthSeg_EthCmdConfig(port);
	d = NFP_MAC_ETH_MacEthSeg_EthCmdConfig_EthRxEna |
	    NFP_MAC_ETH_MacEthSeg_EthCmdConfig_EthTxEna;
	m = d;
	ret = nfp_nbi_mac_regw(nbi, NFP_MAC_ETH(core), r, m, d);
	if (ret < 0)
		return ret;

	/* Enable the serdes lanes */
	mode = nfp_nbi_mac_eth_read_mode(nbi, core, port);
	if (mode < 0)
		return mode;
	switch (mode) {
	case (NFP_NBI_MAC_ENET_100G):
		m = 0x3ff << (core * 12);
		break;
	case (NFP_NBI_MAC_ENET_40G):
		m = (0xf << (port + core * 12));
		break;
	default:
		m = (0x1 << (port + core * 12));
		break;
	}
	r = NFP_MAC_MacSerDesEn;
	m = NFP_MAC_MacSerDesEn_SerDesEnable(m);
	d = m;

	return nfp_nbi_mac_regw(nbi, NFP_MAC, r, m, d);
}
EXPORT_SYMBOL(nfp_nbi_mac_eth_ifup);

int nfp_nbi_mac_eth_write_egress_dsa(struct nfp_nbi_dev *nbi, int core,
				     int port, int octets)
{
	uint64_t r;
	uint32_t d = 0;
	uint32_t m = 0;

	if (nbi == NULL)
		return -ENODEV;

	if ((core < 0) || (core > 1))
		return -EINVAL;

	if ((port < 0) || (port > 11))
		return -EINVAL;


	if ((octets != 0) && (octets != 4) && (octets != 8))
		return -EINVAL;


	if ((port + core * 12) <= 15)
		r = NFP_MAC_MacEgPrePendDsaCtl15to00;
	else
		r = NFP_MAC_MacEgPrePendDsaCtlLkand23to16;

	switch (port + core * 12) {
	case 0:
		m = NFP_MAC_MacPrePendDsaCtl1_DsaTagModePort0(0xf);
		d = NFP_MAC_MacPrePendDsaCtl1_DsaTagModePort0(octets /
								       2);
		break;
	case 1:
		m = NFP_MAC_MacPrePendDsaCtl1_DsaTagModePort1(0xf);
		d = NFP_MAC_MacPrePendDsaCtl1_DsaTagModePort1(octets /
								       2);
		break;
	case 2:
		m = NFP_MAC_MacPrePendDsaCtl1_DsaTagModePort2(0xf);
		d = NFP_MAC_MacPrePendDsaCtl1_DsaTagModePort2(octets /
								       2);
		break;
	case 3:
		m = NFP_MAC_MacPrePendDsaCtl1_DsaTagModePort3(0xf);
		d = NFP_MAC_MacPrePendDsaCtl1_DsaTagModePort3(octets /
								       2);
		break;
	case 4:
		m = NFP_MAC_MacPrePendDsaCtl1_DsaTagModePort4(0xf);
		d = NFP_MAC_MacPrePendDsaCtl1_DsaTagModePort4(octets /
								       2);
		break;
	case 5:
		m = NFP_MAC_MacPrePendDsaCtl1_DsaTagModePort5(0xf);
		d = NFP_MAC_MacPrePendDsaCtl1_DsaTagModePort5(octets /
								       2);
		break;
	case 6:
		m = NFP_MAC_MacPrePendDsaCtl1_DsaTagModePort6(0xf);
		d = NFP_MAC_MacPrePendDsaCtl1_DsaTagModePort6(octets /
								       2);
		break;
	case 7:
		m = NFP_MAC_MacPrePendDsaCtl1_DsaTagModePort7(0xf);
		d = NFP_MAC_MacPrePendDsaCtl1_DsaTagModePort7(octets /
								       2);
		break;
	case 8:
		m = NFP_MAC_MacPrePendDsaCtl1_DsaTagModePort8(0xf);
		d = NFP_MAC_MacPrePendDsaCtl1_DsaTagModePort8(octets /
								       2);
		break;
	case 9:
		m = NFP_MAC_MacPrePendDsaCtl1_DsaTagModePort9(0xf);
		d = NFP_MAC_MacPrePendDsaCtl1_DsaTagModePort9(octets /
								       2);
		break;
	case 10:
		m = NFP_MAC_MacPrePendDsaCtl1_DsaTagModePort10(0xf);
		d = NFP_MAC_MacPrePendDsaCtl1_DsaTagModePort10(octets /
									2);
		break;
	case 11:
		m = NFP_MAC_MacPrePendDsaCtl1_DsaTagModePort11(0xf);
		d = NFP_MAC_MacPrePendDsaCtl1_DsaTagModePort11(octets /
									2);
		break;
	case 12:
		m = NFP_MAC_MacPrePendDsaCtl1_DsaTagModePort12(0xf);
		d = NFP_MAC_MacPrePendDsaCtl1_DsaTagModePort12(octets /
									2);
		break;
	case 13:
		m = NFP_MAC_MacPrePendDsaCtl1_DsaTagModePort13(0xf);
		d = NFP_MAC_MacPrePendDsaCtl1_DsaTagModePort13(octets /
									2);
		break;
	case 14:
		m = NFP_MAC_MacPrePendDsaCtl1_DsaTagModePort14(0xf);
		d = NFP_MAC_MacPrePendDsaCtl1_DsaTagModePort14(octets /
									2);
		break;
	case 15:
		m = NFP_MAC_MacPrePendDsaCtl1_DsaTagModePort15(0xf);
		d = NFP_MAC_MacPrePendDsaCtl1_DsaTagModePort15(octets /
									2);
		break;
	case 16:
		m = NFP_MAC_MacPrePendDsaCtl2_DsaTagModePort16(0xf);
		d = NFP_MAC_MacPrePendDsaCtl2_DsaTagModePort16(octets /
									2);
		break;
	case 17:
		m = NFP_MAC_MacPrePendDsaCtl2_DsaTagModePort17(0xf);
		d = NFP_MAC_MacPrePendDsaCtl2_DsaTagModePort17(octets /
									2);
		break;
	case 18:
		m = NFP_MAC_MacPrePendDsaCtl2_DsaTagModePort18(0xf);
		d = NFP_MAC_MacPrePendDsaCtl2_DsaTagModePort18(octets /
									2);
		break;
	case 19:
		m = NFP_MAC_MacPrePendDsaCtl2_DsaTagModePort19(0xf);
		d = NFP_MAC_MacPrePendDsaCtl2_DsaTagModePort19(octets /
									2);
		break;
	case 20:
		m = NFP_MAC_MacPrePendDsaCtl2_DsaTagModePort20(0xf);
		d = NFP_MAC_MacPrePendDsaCtl2_DsaTagModePort20(octets /
									2);
		break;
	case 21:
		m = NFP_MAC_MacPrePendDsaCtl2_DsaTagModePort21(0xf);
		d = NFP_MAC_MacPrePendDsaCtl2_DsaTagModePort21(octets /
									2);
		break;
	case 22:
		m = NFP_MAC_MacPrePendDsaCtl2_DsaTagModePort22(0xf);
		d = NFP_MAC_MacPrePendDsaCtl2_DsaTagModePort22(octets /
									2);
		break;
	case 23:
		m = NFP_MAC_MacPrePendDsaCtl2_DsaTagModePort23(0xf);
		d = NFP_MAC_MacPrePendDsaCtl2_DsaTagModePort23(octets /
									2);
		break;
	default:
		return -EINVAL;
	}

	return nfp_nbi_mac_regw(nbi, NFP_MAC, r, m, d);
}

int nfp_nbi_mac_write_egress_prepend_enable(struct nfp_nbi_dev *nbi, int chan,
					    int state)
{
	uint64_t r;
	/* uint32_t d = 0; */
	uint32_t m;

	if (nbi == NULL)
		return -ENODEV;

	if ((chan < 0) || (chan > NFP_NBI_MAC_CHAN_MAX))
		return -EINVAL;

	if ((state < 0) || (state > 1))
		return -EINVAL;


	switch (chan / 4) {
	case 0:
		r = NFP_MAC_EgCmdPrependEn0Lo;
		break;
	case 1:
		r = NFP_MAC_EgCmdPrependEn0Hi;
		break;
	case 2:
		r = NFP_MAC_EgCmdPrependEn1Lo;
		break;
	case 3:
		r = NFP_MAC_EgCmdPrependEn1Hi;
		break;
	default:
		return -EINVAL;
	}

	m = 1 << (chan % 4);
	return nfp_nbi_mac_regw(nbi, NFP_MAC, r, m, state);
}

int nfp_nbi_mac_eth_write_egress_skip(struct nfp_nbi_dev *nbi, int core,
				      int port, int octets)
{
	uint64_t r;
	uint32_t d = 0;
	uint32_t m = 0;

	if (nbi == NULL)
		return -ENODEV;

	if ((core < 0) || (core > 1))
		return -EINVAL;

	if ((port < 0) || (port > 11))
		return -EINVAL;


	if ((octets < 0) || (octets > 8))
		return -EINVAL;


	switch ((port + core * 12) / 4) {
	case 0:
		r = NFP_MAC_MacPrePendCtl03to00;
		break;
	case 1:
		r = NFP_MAC_MacPrePendCtl07to04;
		break;
	case 2:
		r = NFP_MAC_MacPrePendCtl11to08;
		break;
	case 3:
		r = NFP_MAC_MacPrePendCtl15to12;
		break;
	case 4:
		r = NFP_MAC_MacPrePendCtl19to16;
		break;
	case 5:
		r = NFP_MAC_MacPrePendCtl23to20;
		break;
	default:
		return -EINVAL;
	}

	switch (port) {
	case 0:
		m = NFP_MAC_MacPrePendCtl1_EGSkipOctetsPort0(0xf);
		d = NFP_MAC_MacPrePendCtl1_EGSkipOctetsPort0(octets);
		break;
	case 1:
		m = NFP_MAC_MacPrePendCtl1_EGSkipOctetsPort1(0xf);
		d = NFP_MAC_MacPrePendCtl1_EGSkipOctetsPort1(octets);
		break;
	case 2:
		m = NFP_MAC_MacPrePendCtl1_EGSkipOctetsPort2(0xf);
		d = NFP_MAC_MacPrePendCtl1_EGSkipOctetsPort2(octets);
		break;
	case 3:
		m = NFP_MAC_MacPrePendCtl1_EGSkipOctetsPort3(0xf);
		d = NFP_MAC_MacPrePendCtl1_EGSkipOctetsPort3(octets);
		break;
	case 4:
		m = NFP_MAC_MacPrePendCtl2_EGSkipOctetsPort4(0xf);
		d = NFP_MAC_MacPrePendCtl2_EGSkipOctetsPort4(octets);
		break;
	case 5:
		m = NFP_MAC_MacPrePendCtl2_EGSkipOctetsPort5(0xf);
		d = NFP_MAC_MacPrePendCtl2_EGSkipOctetsPort5(octets);
		break;
	case 6:
		m = NFP_MAC_MacPrePendCtl2_EGSkipOctetsPort6(0xf);
		d = NFP_MAC_MacPrePendCtl2_EGSkipOctetsPort6(octets);
		break;
	case 7:
		m = NFP_MAC_MacPrePendCtl2_EGSkipOctetsPort7(0xf);
		d = NFP_MAC_MacPrePendCtl2_EGSkipOctetsPort7(octets);
		break;
	case 8:
		m = NFP_MAC_MacPrePendCtl3_EGSkipOctetsPort8(0xf);
		d = NFP_MAC_MacPrePendCtl3_EGSkipOctetsPort8(octets);
		break;
	case 9:
		m = NFP_MAC_MacPrePendCtl3_EGSkipOctetsPort9(0xf);
		d = NFP_MAC_MacPrePendCtl3_EGSkipOctetsPort9(octets);
		break;
	case 10:
		m = NFP_MAC_MacPrePendCtl3_EGSkipOctetsPort10(0xf);
		d = NFP_MAC_MacPrePendCtl3_EGSkipOctetsPort10(octets);
		break;
	case 11:
		m = NFP_MAC_MacPrePendCtl3_EGSkipOctetsPort11(0xf);
		d = NFP_MAC_MacPrePendCtl3_EGSkipOctetsPort11(octets);
		break;
	default:
		return -EINVAL;
	}

	return nfp_nbi_mac_regw(nbi, NFP_MAC, r, m, d);
}

/* void nfp_nbi_mac_ethfifo_rxwm(void);
   void nfp_nbi_mac_ethfifo_txwm(void);
*/

int nfp_nbi_mac_eth_write_port_hwm(struct nfp_nbi_dev *nbi, int core, int port,
				   int hwm, int delta)
{
	uint64_t r;
	uint32_t d = 0;
	uint32_t m = 0;

	if (nbi == NULL)
		return -ENODEV;

	if ((core < 0) || (core > 1))
		return -EINVAL;

	if ((port < 0) || (port > 11))
		return -EINVAL;


	if ((hwm < 0) || (hwm > NFP_NBI_MAC_PORT_HWM_MAX))
		return -EINVAL;

	if ((delta < 0) || (delta > NFP_NBI_MAC_PORT_HWM_DELTA_MAX))
		return -EINVAL;

	/* register = MAC + "csr_porthwm%d" % ((seg + hyd * 12) / 2) */
	r = NFP_MAC_MacPortHwm((port + core * 12) / 2);

	if ((port % 2) == 0) {
		m = NFP_MAC_MacPortHwm_PortHwm0(0x7ff) |
		    NFP_MAC_MacPortHwm_PortDropDelta0(0x1f);
		d = NFP_MAC_MacPortHwm_PortHwm0(hwm) |
		    NFP_MAC_MacPortHwm_PortDropDelta0(delta);
	} else {
		m = NFP_MAC_MacPortHwm_PortHwm1(0x7ff) |
		    NFP_MAC_MacPortHwm_PortDropDelta1(0x1f);
		d = NFP_MAC_MacPortHwm_PortHwm1(hwm) |
		    NFP_MAC_MacPortHwm_PortDropDelta1(delta);
	}

	return nfp_nbi_mac_regw(nbi, NFP_MAC, r, m, d);
}

/* void read_port_hwm(struct nfp_nbi_dev *nbi, int eth, int port); */

/*
 *
 *   Enable/disable timestamp/parse-result prepend on ingress.
 *
 *  @param nbi NBI device
 *  @param core mac ethernet core: [0-1]
 *  @param port mac ethernet port: [0-11]
 *  @param feature disable = 0; parse-result = 1; timestamp = 2; both = 3.
 */
int nfp_nbi_mac_eth_write_ingress_prepend_enable(struct nfp_nbi_dev *nbi,
						 int core, int port,
						 int feature)
{
	uint64_t r;
	uint32_t d = 0;
	uint32_t m = 0;

	if (nbi == NULL)
		return -ENODEV;


	switch (feature) {
	case NFP_MAC_IgPrependEn_PrependEn0_No_Prepend:
	case NFP_MAC_IgPrependEn_PrependEn0_Prepend_CHK:
	case NFP_MAC_IgPrependEn_PrependEn0_Prepend_TS:
	case NFP_MAC_IgPrependEn_PrependEn0_Prepend_TS_CHK:
		break;
	default:
		return -EINVAL;
	}

	if (core == 0)
		r = NFP_MAC_IgPortPrependEn0;
	else if (core == 1)
		r = NFP_MAC_IgPortPrependEn1;
	else
		return -EINVAL;


	switch (port) {
	case 0:
		m = NFP_MAC_IgPrependEn_PrependEn0(0x3);
		d = NFP_MAC_IgPrependEn_PrependEn0(feature);
		break;
	case 1:
		m = NFP_MAC_IgPrependEn_PrependEn1(0x3);
		d = NFP_MAC_IgPrependEn_PrependEn1(feature);
		break;
	case 2:
		m = NFP_MAC_IgPrependEn_PrependEn2(0x3);
		d = NFP_MAC_IgPrependEn_PrependEn2(feature);
		break;
	case 3:
		m = NFP_MAC_IgPrependEn_PrependEn3(0x3);
		d = NFP_MAC_IgPrependEn_PrependEn3(feature);
		break;
	case 4:
		m = NFP_MAC_IgPrependEn_PrependEn4(0x3);
		d = NFP_MAC_IgPrependEn_PrependEn4(feature);
		break;
	case 5:
		m = NFP_MAC_IgPrependEn_PrependEn5(0x3);
		d = NFP_MAC_IgPrependEn_PrependEn5(feature);
		break;
	case 6:
		m = NFP_MAC_IgPrependEn_PrependEn6(0x3);
		d = NFP_MAC_IgPrependEn_PrependEn6(feature);
		break;
	case 7:
		m = NFP_MAC_IgPrependEn_PrependEn7(0x3);
		d = NFP_MAC_IgPrependEn_PrependEn7(feature);
		break;
	case 8:
		m = NFP_MAC_IgPrependEn_PrependEn8(0x3);
		d = NFP_MAC_IgPrependEn_PrependEn8(feature);
		break;
	case 9:
		m = NFP_MAC_IgPrependEn_PrependEn9(0x3);
		d = NFP_MAC_IgPrependEn_PrependEn9(feature);
		break;
	case 10:
		m = NFP_MAC_IgPrependEn_PrependEn10(0x3);
		d = NFP_MAC_IgPrependEn_PrependEn10(feature);
		break;
	case 11:
		m = NFP_MAC_IgPrependEn_PrependEn11(0x3);
		d = NFP_MAC_IgPrependEn_PrependEn11(feature);
		break;
	default:
		/* NFP_MAC_IGPREPENDEN_PREPEND_LK(_x) */
		return -EINVAL;
	}

	return nfp_nbi_mac_regw(nbi, NFP_MAC, r, m, d);
}

/*
 *
 *   Read timestamp/parse-result prepend on ingress.
 *
 *  @param nbi NBI device
 *  @param core mac ethernet core: [0-1]
 *  @param port mac ethernet port: [0-11]
 *  @return  disable = 0; parse-result = 1; timestamp = 2; both = 3.
 *  @return  < 0 Error
 */
int nfp_nbi_mac_eth_read_ingress_prepend_state(struct nfp_nbi_dev *nbi,
					       int core, int port)
{
	uint64_t r;
	uint32_t d = 0;
	int ret;

	if (nbi == NULL)
		return -ENODEV;


	if (core == 0)
		r = NFP_MAC_IgPortPrependEn0;
	else if (core == 1)
		r = NFP_MAC_IgPortPrependEn1;
	else
		return -EINVAL;


	ret = nfp_nbi_mac_regr(nbi, NFP_MAC, r, &d);
	if (ret < 0)
		return ret;

	switch (port) {
	case 0:
		ret = NFP_MAC_IgPrependEn_PrependEn0_of(d);
		break;
	case 1:
		ret = NFP_MAC_IgPrependEn_PrependEn1_of(d);
		break;
	case 2:
		ret = NFP_MAC_IgPrependEn_PrependEn2_of(d);
		break;
	case 3:
		ret = NFP_MAC_IgPrependEn_PrependEn3_of(d);
		break;
	case 4:
		ret = NFP_MAC_IgPrependEn_PrependEn4_of(d);
		break;
	case 5:
		ret = NFP_MAC_IgPrependEn_PrependEn5_of(d);
		break;
	case 6:
		ret = NFP_MAC_IgPrependEn_PrependEn6_of(d);
		break;
	case 7:
		ret = NFP_MAC_IgPrependEn_PrependEn7_of(d);
		break;
	case 8:
		ret = NFP_MAC_IgPrependEn_PrependEn8_of(d);
		break;
	case 9:
		ret = NFP_MAC_IgPrependEn_PrependEn9_of(d);
		break;
	case 10:
		ret = NFP_MAC_IgPrependEn_PrependEn10_of(d);
		break;
	case 11:
		ret = NFP_MAC_IgPrependEn_PrependEn11_of(d);
		break;
	default:
		/* NFP_MAC_IGPREPENDEN_PREPEND_LK(_x) */
		return -EINVAL;
	}

	return ret;
}

/*
 * Set the number of octets to skip on ingress packets.
 *  @param nbi NBI device
 *  @param core mac ethernet core: [0-1]
 *  @param port mac ethernet port: [0-11]
 *  @param octets Number of octets to skip [0-8]
 */
int nfp_nbi_mac_eth_write_ingress_skip(struct nfp_nbi_dev *nbi, int core,
				       int port, int octets)
{
	uint64_t r;
	uint32_t d = 0;
	uint32_t m = 0;

	if (nbi == NULL)
		return -ENODEV;

	if ((core < 0) || (core > 1))
		return -EINVAL;

	if ((port < 0) || (port > 11))
		return -EINVAL;


	if ((octets < 0) || (octets > 8))
		return -EINVAL;


	switch ((port + core * 12) / 4) {
	case 0:
		r = NFP_MAC_MacPrePendCtl03to00;
		break;
	case 1:
		r = NFP_MAC_MacPrePendCtl07to04;
		break;
	case 2:
		r = NFP_MAC_MacPrePendCtl11to08;
		break;
	case 3:
		r = NFP_MAC_MacPrePendCtl15to12;
		break;
	case 4:
		r = NFP_MAC_MacPrePendCtl19to16;
		break;
	case 5:
		r = NFP_MAC_MacPrePendCtl23to20;
		break;
	default:
		return -EINVAL;
	}

	switch (port) {
	case 0:
		m = NFP_MAC_MacPrePendCtl1_IGSkipOctetsPort0(0xf);
		d = NFP_MAC_MacPrePendCtl1_IGSkipOctetsPort0(octets);
		break;
	case 1:
		m = NFP_MAC_MacPrePendCtl1_IGSkipOctetsPort1(0xf);
		d = NFP_MAC_MacPrePendCtl1_IGSkipOctetsPort1(octets);
		break;
	case 2:
		m = NFP_MAC_MacPrePendCtl1_IGSkipOctetsPort2(0xf);
		d = NFP_MAC_MacPrePendCtl1_IGSkipOctetsPort2(octets);
		break;
	case 3:
		m = NFP_MAC_MacPrePendCtl1_IGSkipOctetsPort3(0xf);
		d = NFP_MAC_MacPrePendCtl1_IGSkipOctetsPort3(octets);
		break;
	case 4:
		m = NFP_MAC_MacPrePendCtl2_IGSkipOctetsPort4(0xf);
		d = NFP_MAC_MacPrePendCtl2_IGSkipOctetsPort4(octets);
		break;
	case 5:
		m = NFP_MAC_MacPrePendCtl2_IGSkipOctetsPort5(0xf);
		d = NFP_MAC_MacPrePendCtl2_IGSkipOctetsPort5(octets);
		break;
	case 6:
		m = NFP_MAC_MacPrePendCtl2_IGSkipOctetsPort6(0xf);
		d = NFP_MAC_MacPrePendCtl2_IGSkipOctetsPort6(octets);
		break;
	case 7:
		m = NFP_MAC_MacPrePendCtl2_IGSkipOctetsPort7(0xf);
		d = NFP_MAC_MacPrePendCtl2_IGSkipOctetsPort7(octets);
		break;
	case 8:
		m = NFP_MAC_MacPrePendCtl3_IGSkipOctetsPort8(0xf);
		d = NFP_MAC_MacPrePendCtl3_IGSkipOctetsPort8(octets);
		break;
	case 9:
		m = NFP_MAC_MacPrePendCtl3_IGSkipOctetsPort9(0xf);
		d = NFP_MAC_MacPrePendCtl3_IGSkipOctetsPort9(octets);
		break;
	case 10:
		m = NFP_MAC_MacPrePendCtl3_IGSkipOctetsPort10(0xf);
		d = NFP_MAC_MacPrePendCtl3_IGSkipOctetsPort10(octets);
		break;
	case 11:
		m = NFP_MAC_MacPrePendCtl3_IGSkipOctetsPort11(0xf);
		d = NFP_MAC_MacPrePendCtl3_IGSkipOctetsPort11(octets);
		break;
	default:
		return -EINVAL;
	}

	return nfp_nbi_mac_regw(nbi, NFP_MAC, r, m, d);
}

/* void nfp_nbi_mac_krneg(void); */

int nfp_nbi_mac_eth_write_loopback_mode(struct nfp_nbi_dev *nbi, int core,
					int port, int mode)
{
	uint64_t r;
	uint32_t d = 0;
	uint32_t m = 0;

	if (nbi == NULL)
		return -ENODEV;

	if ((core < 0) || (core > 1))
		return -EINVAL;

	if ((port < 0) || (port > 11))
		return -EINVAL;


	/* 10G Base-R: The PCS transmits the constant pattern of 0x00ff/0x00 */
	/* 40G/100G Base-R: The PCS transmits the MAC transmit data unchanged */
	r = NFP_MAC_ETH_MacEthChPcsSeg_Ctl1(port);
	m = NFP_MAC_ETH_MacEthChPcsSeg_Ctl1_Loopback;
	if ((mode & NFP_NBI_MAC_LOOP_SYSPCS) > 0)
		d = NFP_MAC_ETH_MacEthChPcsSeg_Ctl1_Loopback;

	return nfp_nbi_mac_regw(nbi, NFP_MAC_ETH(core), r, m, d);
}

int nfp_nbi_mac_eth_read_loopback_mode(struct nfp_nbi_dev *nbi, int core,
				       int port)
{
	int ret;
	uint64_t r;
	uint32_t d = 0;
	int mode = 0;

	if (nbi == NULL)
		return -ENODEV;

	if ((core < 0) || (core > 1))
		return -EINVAL;

	if ((port < 0) || (port > 11))
		return -EINVAL;


	r = NFP_MAC_ETH_MacEthChPcsSeg_Ctl1(port);
	ret = nfp_nbi_mac_regr(nbi, NFP_MAC_ETH(core), r, &d);
	if (ret < 0)
		return ret;

	if ((d & NFP_MAC_ETH_MacEthChPcsSeg_Ctl1_Loopback) >
	    0)
		mode |= NFP_NBI_MAC_LOOP_SYSPCS;


	return mode;
}

int nfp_nbi_mac_eth_write_mru(struct nfp_nbi_dev *nbi, int core, int port,
			      int framelen)
{
	uint64_t r;
	uint32_t d = 0;
	uint32_t m = 0;

	if (nbi == NULL)
		return -ENODEV;

	if ((core < 0) || (core > 1))
		return -EINVAL;

	if ((port < 0) || (port > 11))
		return -EINVAL;

	if ((framelen < 0) || (framelen > NFP_MAX_ETH_FRAME_LEN))
		return -EINVAL;


	r = NFP_MAC_ETH_MacEthSeg_EthFrmLength(port);
	m = NFP_MAC_ETH_MacEthSeg_EthFrmLength_EthFrmLength(0xffff);
	d = NFP_MAC_ETH_MacEthSeg_EthFrmLength_EthFrmLength(framelen);

	return nfp_nbi_mac_regw(nbi, NFP_MAC_ETH(core), r, m, d);
}

int nfp_nbi_mac_eth_read_mru(struct nfp_nbi_dev *nbi, int core, int port)
{
	int ret;
	uint64_t r;
	uint32_t d = 0;

	if (nbi == NULL)
		return -ENODEV;

	if ((core < 0) || (core > 1))
		return -EINVAL;

	if ((port < 0) || (port > 11))
		return -EINVAL;


	r = NFP_MAC_ETH_MacEthSeg_EthFrmLength(port);

	ret = nfp_nbi_mac_regr(nbi, NFP_MAC_ETH(core), r, &d);
	if (ret < 0)
		return ret;

	return NFP_MAC_ETH_MacEthSeg_EthFrmLength_EthFrmLength_of(d);
}

int nfp_nbi_mac_eth_write_pause_quant(struct nfp_nbi_dev *nbi, int core,
				      int port, int pcpclass, int quant)
{
	uint64_t r;
	uint32_t d = 0;
	uint32_t m = 0;

	if (nbi == NULL)
		return -ENODEV;

	if ((core < 0) || (core > 1))
		return -EINVAL;

	if ((port < 0) || (port > 11))
		return -EINVAL;

	if ((pcpclass < 0) || (pcpclass > 7))
		return -EINVAL;

	if ((quant < 0) || (quant > 0xffff))
		return -EINVAL;


	r = NFP_MAC_ETH_MacEthSeg_EthPauseQuantaCL(pcpclass, port);
	m = NFP_MAC_ETH_MacEthSeg_EthPauseQuantaCL_EthPauseQuanta(
				pcpclass, 0xffff);
	d = NFP_MAC_ETH_MacEthSeg_EthPauseQuantaCL_EthPauseQuanta(
				pcpclass, quant);

	return nfp_nbi_mac_regw(nbi, NFP_MAC_ETH(core), r, m, d);
}

int nfp_nbi_mac_eth_write_pause_thresh(struct nfp_nbi_dev *nbi, int core,
				       int port, int pcpclass, int thresh)
{
	uint64_t r;
	uint32_t d = 0;
	uint32_t m = 0;

	if (nbi == NULL)
		return -ENODEV;

	if ((core < 0) || (core > 1))
		return -EINVAL;

	if ((port < 0) || (port > 11))
		return -EINVAL;

	if ((pcpclass < 0) || (pcpclass > 7))
		return -EINVAL;

	if ((thresh < 0) || (thresh > 0xffffffff))
		return -EINVAL;

	r = NFP_MAC_ETH_MacEthSeg_EthQuantaThreshCL(pcpclass, port);
	m = NFP_MAC_ETH_MacEthSeg_EthQuantaThreshCL_EthQuantaThresh(
			pcpclass, 0xffff);
	d = NFP_MAC_ETH_MacEthSeg_EthQuantaThreshCL_EthQuantaThresh(
			pcpclass, thresh);

	return nfp_nbi_mac_regw(nbi, NFP_MAC_ETH(core), r, m, d);
}

int nfp_nbi_mac_read_chan_pausewm(struct nfp_nbi_dev *nbi, int chan)
{
	int ret;
	uint32_t d = 0;

	if (nbi == NULL)
		return -ENODEV;


	if ((chan < 0) || (chan > NFP_NBI_MAC_CHAN_MAX))
		return -EINVAL;

	/* MAC + "csr_pausewatermark%d" % (chan / 2) */
	ret = nfp_nbi_mac_regr(nbi, NFP_MAC,
			       NFP_MAC_PauseWaterMark(chan / 2), &d);
	if (ret < 0)
		return ret;

	if (chan % 2 == 0)
		d = NFP_MAC_PauseWaterMark_PauseWaterMark0_of(d);
	else
		d = NFP_MAC_PauseWaterMark_PauseWaterMark1_of(d);

	return d;
}

int nfp_nbi_mac_write_chan_pausewm(struct nfp_nbi_dev *nbi, int chan, int pwm)
{
	uint64_t r;
	uint32_t d = 0;
	uint32_t m = 0;

	if (nbi == NULL)
		return -ENODEV;


	if ((chan < 0) || (chan > NFP_NBI_MAC_CHAN_MAX))
		return -EINVAL;


	if ((pwm < 0) || (pwm > NFP_NBI_MAC_CHAN_PAUSE_WM_MAX))
		return -EINVAL;

	/* MAC + "csr_pausewatermark%d" % (chan / 2) */
	r = NFP_MAC_PauseWaterMark(chan / 2);

	if (chan % 2 == 0) {
		m = NFP_MAC_PauseWaterMark_PauseWaterMark0
		    (NFP_NBI_MAC_CHAN_PAUSE_WM_MAX);
		d = NFP_MAC_PauseWaterMark_PauseWaterMark0(pwm);
	} else {
		m = NFP_MAC_PauseWaterMark_PauseWaterMark1
		    (NFP_NBI_MAC_CHAN_PAUSE_WM_MAX);
		d = NFP_MAC_PauseWaterMark_PauseWaterMark1(pwm);
	}

	return nfp_nbi_mac_regw(nbi, NFP_MAC, r, m, d);
}

/*
  void read_pause_status(struct nfp_nbi_dev *nbi, int eth, int port);
*/

int nfp_nbi_mac_eth_read_pcpremap(struct nfp_nbi_dev *nbi, int core, int port,
				  struct nfp_nbi_mac_chanremap *chanremap)
{
	int ret;
	uint32_t d = 0;

	if (nbi == NULL)
		return -ENODEV;

	if ((core < 0) || (core > 1))
		return -EINVAL;

	if ((port < 0) || (port > 11))
		return -EINVAL;

	if (chanremap == NULL)
		return -EINVAL;


	ret =
	    nfp_nbi_mac_regr(nbi, NFP_MAC,
			     NFP_MAC_MacPcpReMap(port + 12 * core),
			     &d);
	if (ret < 0)
		return ret;

	chanremap->ch_class[0] = NFP_MAC_MacPcpReMap_PcpReMap0_of(d);
	chanremap->ch_class[1] = NFP_MAC_MacPcpReMap_PcpReMap1_of(d);
	chanremap->ch_class[2] = NFP_MAC_MacPcpReMap_PcpReMap2_of(d);
	chanremap->ch_class[3] = NFP_MAC_MacPcpReMap_PcpReMap3_of(d);
	chanremap->ch_class[4] = NFP_MAC_MacPcpReMap_PcpReMap4_of(d);
	chanremap->ch_class[5] = NFP_MAC_MacPcpReMap_PcpReMap5_of(d);
	chanremap->ch_class[6] = NFP_MAC_MacPcpReMap_PcpReMap6_of(d);
	chanremap->ch_class[7] = NFP_MAC_MacPcpReMap_PcpReMap7_of(d);
	chanremap->untagd = NFP_MAC_MacPcpReMap_UntaggedChan_of(d);

	return 0;

}

int nfp_nbi_mac_eth_write_pcpremap(struct nfp_nbi_dev *nbi, int core, int port,
				   struct nfp_nbi_mac_chanremap *chanremap)
{
	/* uint64_t r; */
	uint32_t d = 0;
	uint32_t m = 0;

	if (nbi == NULL)
		return -ENODEV;

	if ((core < 0) || (core > 1))
		return -EINVAL;

	if ((port < 0) || (port > 11))
		return -EINVAL;

	if (chanremap == NULL)
		return -EINVAL;


	m = NFP_MAC_MacPcpReMap_PcpReMap0(7);
	m |= NFP_MAC_MacPcpReMap_PcpReMap1(7);
	m |= NFP_MAC_MacPcpReMap_PcpReMap2(7);
	m |= NFP_MAC_MacPcpReMap_PcpReMap3(7);
	m |= NFP_MAC_MacPcpReMap_PcpReMap4(7);
	m |= NFP_MAC_MacPcpReMap_PcpReMap5(7);
	m |= NFP_MAC_MacPcpReMap_PcpReMap6(7);
	m |= NFP_MAC_MacPcpReMap_PcpReMap7(7);
	m |= NFP_MAC_MacPcpReMap_UntaggedChan(0x3f);

	d = NFP_MAC_MacPcpReMap_PcpReMap0(chanremap->ch_class[0]);
	d |= NFP_MAC_MacPcpReMap_PcpReMap1(chanremap->ch_class[1]);
	d |= NFP_MAC_MacPcpReMap_PcpReMap2(chanremap->ch_class[2]);
	d |= NFP_MAC_MacPcpReMap_PcpReMap3(chanremap->ch_class[3]);
	d |= NFP_MAC_MacPcpReMap_PcpReMap4(chanremap->ch_class[4]);
	d |= NFP_MAC_MacPcpReMap_PcpReMap5(chanremap->ch_class[5]);
	d |= NFP_MAC_MacPcpReMap_PcpReMap6(chanremap->ch_class[6]);
	d |= NFP_MAC_MacPcpReMap_PcpReMap7(chanremap->ch_class[7]);
	d |= NFP_MAC_MacPcpReMap_UntaggedChan(chanremap->untagd);

	return nfp_nbi_mac_regw(nbi, NFP_MAC,
				NFP_MAC_MacPcpReMap(port + 12 * core),
				m, d);
}

/*
  void nfp_nbi_mac_port_config(void);
  void set_speed(struct nfp_nbi_dev *nbi, int eth, int port, int speed);
*/

int nfp_nbi_mac_eth_write_portchan(struct nfp_nbi_dev *nbi, int core,
				   struct nfp_nbi_mac_portchan *ig,
				   struct nfp_nbi_mac_portchan *eg)
{
	int ret;
	uint64_t r;
	uint32_t d = 0;
	uint32_t m = 0;
	int i, j, p;

	if (nbi == NULL)
		return -ENODEV;

	if ((core < 0) || (core > 1))
		return -EINVAL;

	if ((ig == NULL) && (eg == NULL))
		return -EINVAL;


	m = NFP_MAC_MacPortChanAssign_PortBaseChan0(0x3f) |
	    NFP_MAC_MacPortChanAssign_PortNumOfChannels0(0xf) |
	    NFP_MAC_MacPortChanAssign_PortBaseChan1(0x3f) |
	    NFP_MAC_MacPortChanAssign_PortNumOfChannels1(0xf) |
	    NFP_MAC_MacPortChanAssign_PortBaseChan2(0x3f) |
	    NFP_MAC_MacPortChanAssign_PortNumOfChannels2(0xf);

	if (ig != NULL) {
		/* Ingress */
		p = 0;
		for (j = 0; j < NFP_NBI_MAC_NUM_PORTCHAN_REGS / 2; j++) {
			for (i = 0; i < 3; i++) {
				if ((ig[p + i].base < 0)
				    || (ig[p + i].base > 63))
					return -EINVAL;

				if ((ig[p + i].num < 0) || (ig[p + i].num > 8))
					return -EINVAL;

			}
			d = NFP_MAC_MacPortChanAssign_PortBaseChan0(
				ig[p + 0].base);
			d |= NFP_MAC_MacPortChanAssign_PortNumOfChannels0(
				ig[p + 0].num);
			d |= NFP_MAC_MacPortChanAssign_PortBaseChan1(
				ig[p + 1].base);
			d |= NFP_MAC_MacPortChanAssign_PortNumOfChannels1(
				ig[p + 1].num);
			d |= NFP_MAC_MacPortChanAssign_PortBaseChan2(
				ig[p + 2].base);
			d |= NFP_MAC_MacPortChanAssign_PortNumOfChannels2(
				ig[p + 2].num);
			r = nfp_nbi_mac_ig_portchan_regs[j +
				(NFP_NBI_MAC_NUM_PORTCHAN_REGS / 2) * core];
			ret = nfp_nbi_mac_regw(nbi, NFP_MAC, r, m, d);
			if (ret < 0)
				return ret;

			p = p + 3;
		}
	}

	if (eg != NULL) {
		/* Egress */
		p = 0;
		for (j = 0; j < NFP_NBI_MAC_NUM_PORTCHAN_REGS / 2; j++) {
			for (i = 0; i < 3; i++) {
				if ((eg[p + i].base < 0)
				    || (eg[p + i].base > 63))
					return -EINVAL;

				if ((eg[p + i].num < 0) || (eg[p + i].num > 8))
					return -EINVAL;

			}
			d = NFP_MAC_MacPortChanAssign_PortBaseChan0(
				eg[p + 0].base);
			d |= NFP_MAC_MacPortChanAssign_PortNumOfChannels0(
				eg[p + 0].num);
			d |= NFP_MAC_MacPortChanAssign_PortBaseChan1(
				eg[p + 1].base);
			d |= NFP_MAC_MacPortChanAssign_PortNumOfChannels1(
				eg[p + 1].num);

			d |= NFP_MAC_MacPortChanAssign_PortBaseChan2(
				eg[p + 2].base);
			d |= NFP_MAC_MacPortChanAssign_PortNumOfChannels2(
				eg[p + 2].num);
			r = nfp_nbi_mac_eg_portchan_regs[j +
				 (NFP_NBI_MAC_NUM_PORTCHAN_REGS / 2) * core];
			ret = nfp_nbi_mac_regw(nbi, NFP_MAC, r, m, d);
			if (ret < 0)
				return ret;

			p = p + 3;
		}
	}

	return 0;
}

int nfp_nbi_mac_eth_read_portchan(struct nfp_nbi_dev *nbi, int core,
				  struct nfp_nbi_mac_portchan *ig,
				  struct nfp_nbi_mac_portchan *eg)
{
	int ret;
	uint32_t d = 0;
	int i, p;

	if (nbi == NULL)
		return -ENODEV;

	if ((core < 0) || (core > 1))
		return -EINVAL;

	if ((ig == NULL) && (eg == NULL))
		return -EINVAL;


	if (ig != NULL) {
		/* Ingress */
		p = 0;
		for (i = 0; i < NFP_NBI_MAC_NUM_PORTCHAN_REGS / 2; i++) {
			ret = nfp_nbi_mac_regr(nbi, NFP_MAC,
					nfp_nbi_mac_ig_portchan_regs[i +
					  (NFP_NBI_MAC_NUM_PORTCHAN_REGS / 2)
					  * core], &d);
			if (ret < 0)
				return ret;

			ig[p + 0].base =
			    NFP_MAC_MacPortChanAssign_PortBaseChan0_of(d);
			ig[p + 0].num =
			    NFP_MAC_MacPortChanAssign_PortNumOfChannels0_of
			    (d);

			ig[p + 1].base =
			    NFP_MAC_MacPortChanAssign_PortBaseChan1_of(d);
			ig[p + 1].num =
			    NFP_MAC_MacPortChanAssign_PortNumOfChannels1_of
			    (d);

			ig[p + 2].base =
			    NFP_MAC_MacPortChanAssign_PortBaseChan2_of(d);
			ig[p + 2].num =
			    NFP_MAC_MacPortChanAssign_PortNumOfChannels2_of
			    (d);

			p = p + 3;
		}
	}

	if (eg != NULL) {
		/* Egress */
		p = 0;
		for (i = 0; i < NFP_NBI_MAC_NUM_PORTCHAN_REGS / 2; i++) {
			ret = nfp_nbi_mac_regr(nbi, NFP_MAC,
				nfp_nbi_mac_eg_portchan_regs[i +
					(NFP_NBI_MAC_NUM_PORTCHAN_REGS / 2)
					* core], &d);
			if (ret < 0)
				return ret;

			eg[p + 0].base =
			    NFP_MAC_MacPortChanAssign_PortBaseChan0_of(d);
			eg[p + 0].num =
			    NFP_MAC_MacPortChanAssign_PortNumOfChannels0_of(d);

			eg[p + 1].base =
			    NFP_MAC_MacPortChanAssign_PortBaseChan1_of(d);
			eg[p + 1].num =
			    NFP_MAC_MacPortChanAssign_PortNumOfChannels1_of(d);

			eg[p + 2].base =
			    NFP_MAC_MacPortChanAssign_PortBaseChan2_of(d);
			eg[p + 2].num =
			    NFP_MAC_MacPortChanAssign_PortNumOfChannels2_of(d);

			p = p + 3;
		}
	}
	return 0;

}

/*
  void read_chanport(struct nfp_nbi_dev *nbi, int chan);
  void checkEthPort(int eth, int port);
  void nfp_nbi_mac_portstats(void);
  void stats(struct nfp_nbi_dev *nbi, int eth, int seg);
  void nfp_nbi_mac_reneg(void);
  void nfp_nbi_mac_status(void);
  void status(struct nfp_nbi_dev *nbi, int eth, int port);
  void nfp_nbi_mac_timestamp_read(void);
  void nfp_nbi_mac_timestamp_write(void);
  void nfp_mdio_regr(void);
  void nfp_mdio_regw(void);

*/

int nfp_nbi_mac_write_clock_enables(struct nfp_nbi_dev *nbi, uint32_t mask,
				    uint32_t state)
{
	int ret;
	uint32_t clkbits = NFP_MAC_MacBlkReset_MacCoreClkEnHy0 |
	    NFP_MAC_MacBlkReset_MacCoreClkEnHy1 |
	    NFP_MAC_MacBlkReset_MacCoreClkEnLk0 |
	    NFP_MAC_MacBlkReset_MacCoreClkEnLk1 |
	    NFP_MAC_MacBlkReset_MacX2ClkEnLk0 |
	    NFP_MAC_MacBlkReset_MacX2ClkEnLk1;

	if (nbi == NULL)
		return -ENODEV;


	mask &= clkbits;

	if (state == 0) {
		ret =
		    nfp_nbi_mac_regw(nbi, NFP_MAC,
				     NFP_MAC_MacBlkReset, mask, 0);
	} else {
		ret =
		    nfp_nbi_mac_regw(nbi, NFP_MAC,
				     NFP_MAC_MacBlkReset, mask, mask);
	}

	return ret;

}

/* should we check if port is enabled? */
int nfp_nbi_mac_eth_write_resets(struct nfp_nbi_dev *nbi, int core,
				 uint32_t mask)
{
	uint64_t r;
	uint32_t m = 0;

	if (nbi == NULL)
		return -ENODEV;

	if ((core < 0) || (core > 1))
		return -EINVAL;


	m = NFP_MAC_MacHydBlkReset_MacHydRxSerDesIfRst(0xfff) |
	    NFP_MAC_MacHydBlkReset_MacHydTxSerDesIfRst(0xfff) |
	    NFP_MAC_MacHydBlkReset_MacHydRxFFRst |
	    NFP_MAC_MacHydBlkReset_MacHydTxFFRst |
	    NFP_MAC_MacHydBlkReset_MacHydRefRst |
	    NFP_MAC_MacHydBlkReset_MacHydRegRst;

	if (core == 0)
		r = NFP_MAC_MacHyd0BlkReset;
	else
		r = NFP_MAC_MacHyd1BlkReset;

	return nfp_nbi_mac_regw(nbi, NFP_MAC, r, m, mask);
}

int nfp_nbi_mac_eth_read_linkstate(struct nfp_nbi_dev *nbi, int core, int port,
				   uint32_t *linkstate)
{
	uint64_t r;
	uint32_t d = 0;
	uint32_t m = 0;
	uint32_t status = 0;
	int ret;

	if (nbi == NULL)
		return -ENODEV;

	if ((core < 0) || (core > 1))
		return -EINVAL;

	if ((port < 0) || (port > 11))
		return -EINVAL;

	if (linkstate)
		*linkstate = 0;


	ret = nfp_nbi_mac_regr(nbi, NFP_MAC,
			       NFP_MAC_MacMuxCtrl, &d);
	if (ret < 0)
		return ret;

	m = 1 << ((core * 12) + port);
	if ((d & m) > 0)
		status |= NFP_NBI_MAC_MacMuxCtrl_Error;

	r = NFP_MAC_ETH_MacEthGlobal_EthActCtlSeg;
	ret = nfp_nbi_mac_regr(nbi, NFP_MAC_ETH(core), r, &d);
	if (ret < 0)
		return ret;

	if (!(d & (0x1 << port)))
		status |= NFP_NBI_MAC_EthActCtlSeg_Disabled;

	r = NFP_MAC_ETH_MacEthChPcsSeg_Status1(port);
	/* Double read to clear latch low on link down */
	ret = nfp_nbi_mac_regr(nbi, NFP_MAC_ETH(core), r, &d);
	if (ret < 0)
		return ret;

	ret = nfp_nbi_mac_regr(nbi, NFP_MAC_ETH(core), r, &d);
	if (ret < 0)
		return ret;

	if (!(d & NFP_MAC_ETH_MacEthChPcsSeg_Status1_RcvLinkStatus))
		status |= NFP_NBI_MAC_EthChPcsStatus1_RcvLinkStatus_Down;

	r = NFP_MAC_ETH_MacEthChPcsSeg_BaseRStatus1(port);
	ret = nfp_nbi_mac_regr(nbi, NFP_MAC_ETH(core), r, &d);
	if (ret < 0)
		return ret;

	if (!(d & NFP_MAC_ETH_MacEthChPcsSeg_BaseRStatus1_RcvLinkStatus))
		status |=
		    NFP_NBI_MAC_EthChPcsBaseRStatus1_RcvLinkStatus_Down;

	if (!(d & NFP_MAC_ETH_MacEthChPcsSeg_BaseRStatus1_BlockLocked))
		status |=
		    NFP_NBI_MAC_EthChPcsBaseRStatus1_BlockLocked_False;

	r = NFP_MAC_ETH_MacEthSeg_EthCmdConfig(port);
	ret = nfp_nbi_mac_regr(nbi, NFP_MAC_ETH(core), r, &d);
	if (ret < 0)
		return ret;

	if (!(d & NFP_MAC_ETH_MacEthSeg_EthCmdConfig_EthTxEna))
		status |= NFP_NBI_MAC_EthCmdConfig_EthTxEna_False;

	if (!(d & NFP_MAC_ETH_MacEthSeg_EthCmdConfig_EthRxEna))
		status |= NFP_NBI_MAC_EthCmdConfig_EthRxEna_False;

	if (linkstate)
		*linkstate = status;

	return (status) ? 0 : 1;
}
EXPORT_SYMBOL(nfp_nbi_mac_eth_read_linkstate);

/*   void lanemode(struct nfp_nbi_dev *nbi, int eth, int port); */

int nfp_nbi_mac_eth_read_mode(struct nfp_nbi_dev *nbi, int core, int port)
{
	int ret;
	uint64_t r;
	uint32_t d = 0;
	uint32_t m = 0;
	uint32_t mux = 0;
	int mode;
	int s;

	if (nbi == NULL)
		return -ENODEV;

	if ((core < 0) || (core > 1))
		return -EINVAL;

	if ((port < 0) || (port > 11))
		return -EINVAL;

	/* Check the Serdes lane assignments */
	ret =
	    nfp_nbi_mac_regr(nbi, NFP_MAC, NFP_MAC_MacMuxCtrl,
			     &mux);
	if (ret < 0)
		return ret;

	m = 1 << ((core * 12) + port);
	if ((mux & m) > 0)
		return NFP_NBI_MAC_ILK;


	/* check port 0 for 100G 0x2050 */
	r = NFP_MAC_ETH_MacEthChPcsSeg_Ctl1(0);
	ret = nfp_nbi_mac_regr(nbi, NFP_MAC_ETH(core), r, &d);
	if (ret < 0)
		return ret;

	if ((d & NFP_NBI_MAC_EthChPcsCtl1_Mode_Mask) ==
	    NFP_NBI_MAC_EthChPcsCtl1_Mode_100GE) {
		/* port 0-9 = 100G - ports 10, 11 can be 10G */
		if (port < 10)
			return NFP_NBI_MAC_ENET_100G;

	}

	/* check ports 0,4,8 for 40G */
	s = port % 4;
	r = NFP_MAC_ETH_MacEthChPcsSeg_Ctl1(port - s);
	ret = nfp_nbi_mac_regr(nbi, NFP_MAC_ETH(core), r, &d);
	if (ret < 0)
		return ret;

	if ((d & NFP_NBI_MAC_EthChPcsCtl1_Mode_Mask) ==
	    NFP_NBI_MAC_EthChPcsCtl1_Mode_40GE)
		return NFP_NBI_MAC_ENET_40G;

	/* All that remains is 10G or less */
	r = NFP_MAC_ETH_MacEthChPcsSeg_Ctl1(port);
	ret = nfp_nbi_mac_regr(nbi, NFP_MAC_ETH(core), r, &d);
	if (ret < 0)
		return ret;

	switch (d & NFP_NBI_MAC_EthChPcsCtl1_Mode_Mask) {
	case (NFP_NBI_MAC_EthChPcsCtl1_Mode_10GE):
		/* check if < 10G AE */
		r = NFP_MAC_ETH_EthSgmiiIfMode(port);
		ret = nfp_nbi_mac_regr(nbi, NFP_MAC_ETH(core), r, &d);
		if (ret < 0)
			return ret;

		if (d & NFP_MAC_ETH_EthSgmiiIfMode_EthSgmiiPcsEnable) {
			if (d & NFP_MAC_ETH_EthSgmiiIfMode_EthSgmiiEna) {
				/* SGMII */
				switch
				    (NFP_MAC_ETH_EthSgmiiIfMode_Speed_of
				     (d)) {
				case (NFP_MAC_ETH_EthSgmiiIfMode_Speed_10Mbps):
					mode =
					    NFP_NBI_MAC_ENET_10M;
					break;
				case (NFP_MAC_ETH_EthSgmiiIfMode_Speed_100Mbps):
					mode =
					    NFP_NBI_MAC_ENET_100M;
					break;
				case (0x2):
					/* AE case */
					mode = NFP_NBI_MAC_ENET_1G;
					break;
				default:
					mode = -EINVAL;
					break;
				}
			} else {
				/* 100Base-X */
				mode = NFP_NBI_MAC_ENET_1G;
			}
			return mode;
		} else
			return NFP_NBI_MAC_ENET_10G;

		break;
	case (NFP_NBI_MAC_EthChPcsCtl1_Mode_8023AV):
		break;
	case (NFP_NBI_MAC_EthChPcsCtl1_Mode_10PASSTS):
		break;
	default:
		break;
	}

	return -EINVAL;
}
EXPORT_SYMBOL(nfp_nbi_mac_eth_read_mode);

/*
  void read_serdes_clock(struct nfp_nbi_dev *nbi, int serdes);
  void serdes_enable(struct nfp_nbi_dev *nbi, int mask);
  void serdes_rst_off(struct nfp_nbi_dev *nbi);
  void serdes_rst_on(struct nfp_nbi_dev *nbi);
  void set_serdes_clock(struct nfp_nbi_dev *nbi, int clk, int serdes);

// extra
void egress_crc_ena(int mask);
void egress_prepend_mask(int mask);
void mac_tm_oobfc_ena(struct nfp_nbi_dev *nbi, int enable);
void mac_tm_oobfc_get(struct nfp_nbi_dev *nbi, int entry);
*/

int nfp_nbi_mac_eth_write_vlantpid(struct nfp_nbi_dev *nbi, int slot,
				   int vlanid)
{
	uint64_t r;
	uint32_t d = 0;
	uint32_t m = 0;

	if (nbi == NULL)
		return -ENODEV;

	if ((slot < 0) || (slot > 7))
		return -EINVAL;


	m = NFP_MAC_ETH_MacEthVlanTpidCfg_EthVlanTpid_EthVlanTpid(0xffff);
	d = NFP_MAC_ETH_MacEthVlanTpidCfg_EthVlanTpid_EthVlanTpid(vlanid);

	switch (slot) {
	case 0:
		r = NFP_MAC_ETH_MacEthVlanTpidCfg_EthVlanTpid0;
		break;
	case 1:
		r = NFP_MAC_ETH_MacEthVlanTpidCfg_EthVlanTpid1;
		break;
	case 2:
		r = NFP_MAC_ETH_MacEthVlanTpidCfg_EthVlanTpid2;
		break;
	case 3:
		r = NFP_MAC_ETH_MacEthVlanTpidCfg_EthVlanTpid3;
		break;
	case 4:
		r = NFP_MAC_ETH_MacEthVlanTpidCfg_EthVlanTpid4;
		break;
	case 5:
		r = NFP_MAC_ETH_MacEthVlanTpidCfg_EthVlanTpid5;
		break;
	case 6:
		r = NFP_MAC_ETH_MacEthVlanTpidCfg_EthVlanTpid6;
		break;
	case 7:
		r = NFP_MAC_ETH_MacEthVlanTpidCfg_EthVlanTpid7;
		break;
	default:
		return -EINVAL;
	}

	return nfp_nbi_mac_regw(nbi, NFP_MAC, r, m, d);
}

/* * AEFIX - refactor enable into separate function? */
int nfp_nbi_mac_eth_write_ingress_dqdwrr(struct nfp_nbi_dev *nbi, int core,
					 int port, int en, int weight)
{
	int ret;
	uint32_t m;
	uint32_t d;
	int timeout = NFP_NBI_MAC_DQDWRR_TO;
	uint32_t busy = 1;

	if (nbi == NULL)
		return -ENODEV;

	if ((core < 0) || (core > 1))
		return -EINVAL;

	if ((port < 0) || (port > 12))
		return -EINVAL;

	/* Set write enable for ingress dequeue DWRR memory */
	m = NFP_MAC_MacSysSupCtrl_DwrrWeightWrEnable;
	d = NFP_MAC_MacSysSupCtrl_DwrrWeightWrEnable;
	ret = nfp_nbi_mac_regw(nbi, NFP_MAC,
			       NFP_MAC_MacSysSupCtrl, m, d);
	if (ret < 0)
		return ret;

	m = -1;
	d = (en) ? NFP_MAC_IgDqTdmMemoryRW_TdmPortArbEnable : 0;
	d |= NFP_MAC_IgDqTdmMemoryRW_TdmMemRdWrAddr(port + 12 * core) |
	    NFP_MAC_IgDqTdmMemoryRW_TdmMemWrBusy |
	    NFP_MAC_IgDqTdmMemoryRW_TdmPortWeightWrData(weight);

	ret = nfp_nbi_mac_regw(nbi, NFP_MAC,
			       NFP_MAC_IgDqTdmMemoryRW, -1, d);
	if (ret < 0)
		return ret;

	while ((busy != 0) && (timeout > 0)) {
		ret = nfp_nbi_mac_regr(nbi, NFP_MAC,
				       NFP_MAC_IgDqTdmMemoryRW, &busy);
		if (ret < 0)
			return ret;
		busy &= NFP_MAC_IgDqTdmMemoryRW_TdmMemWrBusy;
		timeout--;
	}

	if (timeout <= 0)
		return -ETIMEDOUT;

	return 0;

}				/* end nfp_nbi_mac_write_ingress_dqdwrr */

int nfp_nbi_mac_eth_read_ingress_dqdwrr(struct nfp_nbi_dev *nbi, int core,
					int port)
{
	int ret;
	uint32_t m;
	uint32_t d;
	int timeout = NFP_NBI_MAC_DQDWRR_TO;
	uint32_t busy = 1;

	if (nbi == NULL)
		return -ENODEV;

	if ((core < 0) || (core > 1))
		return -EINVAL;

	if ((port < 0) || (port > 11))
		return -EINVAL;


	/* Check that core clock is enabled, accesses to dwrr can hang if not */
	if (core == 0) {
		ret =
		    nfp_nbi_mac_regr(nbi, NFP_MAC,
				     NFP_MAC_MacBlkReset, &d);
		if (ret < 0)
			return ret;

		if (((d & NFP_MAC_MacBlkReset_MacCoreClkEnHy0) == 0))
			return 0;

	} else {
		ret =
		    nfp_nbi_mac_regr(nbi, NFP_MAC,
				     NFP_MAC_MacBlkReset, &d);
		if (ret < 0)
			return ret;

		if (((d & NFP_MAC_MacBlkReset_MacCoreClkEnHy1) == 0))
			return 0;

	}

	m = -1;
	d = NFP_MAC_IgDqTdmMemoryRW_TdmMemRdWrAddr(port + 12 * core) |
	    NFP_MAC_IgDqTdmMemoryRW_TdmMemRdBusy;

	ret = nfp_nbi_mac_regw(nbi, NFP_MAC,
			       NFP_MAC_IgDqTdmMemoryRW, m, d);
	if (ret < 0)
		return ret;

	ret = nfp_nbi_mac_regr(nbi, NFP_MAC,
			       NFP_MAC_IgDqTdmMemoryRW, &busy);
	if (ret < 0)
		return ret;

	busy &= NFP_MAC_IgDqTdmMemoryRW_TdmMemRdBusy;

	while ((busy != 0) && (timeout > 0)) {
		ret = nfp_nbi_mac_regr(nbi, NFP_MAC,
				       NFP_MAC_IgDqTdmMemoryRW, &d);
		if (ret < 0)
			return ret;

		busy = d & NFP_MAC_IgDqTdmMemoryRW_TdmMemRdBusy;
		timeout--;
	}

	if (timeout <= 0)
		return -ETIMEDOUT;

	/* read the data register */
	ret = nfp_nbi_mac_regr(nbi, NFP_MAC,
			       NFP_MAC_IgDqTdmMemoryRdData, &d);
	if (ret < 0)
		return ret;

	if ((d & NFP_MAC_IgDqTdmMemoryRdData_TdmMemRdDataValid) == 0)
		return -EINVAL;

	if ((NFP_MAC_IgDqTdmMemoryRdData_TdmMemRdAddr_of(d)) !=
	    port + core * 12)
		return -EINVAL;

	/* AEFIX do we care about enable? */
	if ((d & NFP_MAC_IgDqTdmMemoryRdData_TdmPortArbEnable) != 0) {
		return
		    NFP_MAC_IgDqTdmMemoryRdData_TdmPortWeightRdData_of
		    (d);
	} else {
		return
		    NFP_MAC_IgDqTdmMemoryRdData_TdmPortWeightRdData_of
		    (d);
	}
	return 0;
}

int nfp_nbi_mac_eth_read_portlanes(struct nfp_nbi_dev *nbi, int core, int port,
				   int *lbase, int *lnum)
{
	int mode;

	if (nbi == NULL)
		return -ENODEV;

	if ((core < 0) || (core > 1))
		return -EINVAL;

	if ((port < 0) || (port > 11))
		return -EINVAL;

	if ((lbase == NULL) && (lnum == NULL))
		return -EINVAL;

	mode = nfp_nbi_mac_eth_read_mode(nbi, core, port);
	if (mode < 0)
		return mode;

	switch (mode) {
	case (NFP_NBI_MAC_ENET_100G):
		if (lbase)
			*lbase = 0;

		if (lnum)
			*lnum = 10;

		break;
	case (NFP_NBI_MAC_ENET_40G):
		if (lbase)
			*lbase = port - port % 4;

		if (lnum)
			*lnum = 4;

		break;
	default:
		if (lbase)
			*lbase = port;

		if (lnum)
			*lnum = 1;

		break;
	}

	return 0;
}

int nfp_nbi_mac_eth_read_cmdconfig(struct nfp_nbi_dev *nbi, int core, int port)
{
	int ret;
	uint64_t r;
	uint32_t d = 0;

	if (nbi == NULL)
		return -ENODEV;

	if ((core < 0) || (core > 1))
		return -EINVAL;

	if ((port < 0) || (port > 11))
		return -EINVAL;

	r = NFP_MAC_ETH_MacEthSeg_EthCmdConfig(port);
	ret = nfp_nbi_mac_regr(nbi, NFP_MAC_ETH(core), r, &d);
	if (ret < 0)
		return ret;

	return d & 0x7fffffff;
}

int nfp_nbi_mac_eth_write_cmdconfig(struct nfp_nbi_dev *nbi, int core,
				    int port, uint32_t mask, uint32_t value)
{
	int ret;
	uint64_t r;

	if (nbi == NULL)
		return -ENODEV;

	if ((core < 0) || (core > 1))
		return -EINVAL;

	if ((port < 0) || (port > 11))
		return -EINVAL;

	r = NFP_MAC_ETH_MacEthSeg_EthCmdConfig(port);
	ret = nfp_nbi_mac_regw(nbi, NFP_MAC_ETH(core), r,
			       mask & EthCmdConfigMask, value);
	if (ret < 0)
		return ret;

	return 0;
}

int nfp_nbi_mac_eth_read_egress_crc(struct nfp_nbi_dev *nbi, int core)
{
	int ret;
	uint32_t d = 0;

	if (nbi == NULL)
		return -ENODEV;

	if ((core < 0) || (core > 1))
		return -EINVAL;

	ret = nfp_nbi_mac_regr(nbi, NFP_MAC,
			       NFP_MAC_MacTdm1Mode1110CrcEn, &d);
	if (ret < 0)
		return ret;

	return NFP_MAC_MacTdmMode1110Crc_MacEgressPortCrcEn_of(d);
}

int nfp_nbi_mac_eth_write_egress_crc(struct nfp_nbi_dev *nbi, int core,
				     uint32_t mask)
{
	uint32_t m;
	uint32_t d;

	if (nbi == NULL)
		return -ENODEV;

	if ((core < 0) || (core > 1))
		return -EINVAL;

	m = NFP_MAC_MacTdmMode1110Crc_MacEgressPortCrcEn(0xfff);
	d = NFP_MAC_MacTdmMode1110Crc_MacEgressPortCrcEn(mask);
	return nfp_nbi_mac_regw(nbi, NFP_MAC,
				NFP_MAC_MacTdm1Mode1110CrcEn, m, d);
}

int nfp_nbi_mac_eth_read_egress_dsa(struct nfp_nbi_dev *nbi, int core, int port)
{
	int ret;
	uint64_t r;
	uint32_t d = 0;

	if (nbi == NULL)
		return -ENODEV;

	if ((core < 0) || (core > 1))
		return -EINVAL;

	if ((port < 0) || (port > 11))
		return -EINVAL;

	if ((port + core * 12) <= 15)
		r = NFP_MAC_MacEgPrePendDsaCtl15to00;
	else
		r = NFP_MAC_MacEgPrePendDsaCtlLkand23to16;

	ret = nfp_nbi_mac_regr(nbi, NFP_MAC, r, &d);
	if (ret < 0)
		return ret;

	switch (port + core * 12) {
	case 0:
		d = NFP_MAC_MacPrePendDsaCtl1_DsaTagModePort0_of(d);
		break;
	case 1:
		d = NFP_MAC_MacPrePendDsaCtl1_DsaTagModePort1_of(d);
		break;
	case 2:
		d = NFP_MAC_MacPrePendDsaCtl1_DsaTagModePort2_of(d);
		break;
	case 3:
		d = NFP_MAC_MacPrePendDsaCtl1_DsaTagModePort3_of(d);
		break;
	case 4:
		d = NFP_MAC_MacPrePendDsaCtl1_DsaTagModePort4_of(d);
		break;
	case 5:
		d = NFP_MAC_MacPrePendDsaCtl1_DsaTagModePort5_of(d);
		break;
	case 6:
		d = NFP_MAC_MacPrePendDsaCtl1_DsaTagModePort6_of(d);
		break;
	case 7:
		d = NFP_MAC_MacPrePendDsaCtl1_DsaTagModePort7_of(d);
		break;
	case 8:
		d = NFP_MAC_MacPrePendDsaCtl1_DsaTagModePort8_of(d);
		break;
	case 9:
		d = NFP_MAC_MacPrePendDsaCtl1_DsaTagModePort9_of(d);
		break;
	case 10:
		d = NFP_MAC_MacPrePendDsaCtl1_DsaTagModePort10_of(d);
		break;
	case 11:
		d = NFP_MAC_MacPrePendDsaCtl1_DsaTagModePort11_of(d);
		break;
	case 12:
		d = NFP_MAC_MacPrePendDsaCtl1_DsaTagModePort12_of(d);
		break;
	case 13:
		d = NFP_MAC_MacPrePendDsaCtl1_DsaTagModePort13_of(d);
		break;
	case 14:
		d = NFP_MAC_MacPrePendDsaCtl1_DsaTagModePort14_of(d);
		break;
	case 15:
		d = NFP_MAC_MacPrePendDsaCtl1_DsaTagModePort15_of(d);
		break;
	case 16:
		d = NFP_MAC_MacPrePendDsaCtl2_DsaTagModePort16_of(d);
		break;
	case 17:
		d = NFP_MAC_MacPrePendDsaCtl2_DsaTagModePort17_of(d);
		break;
	case 18:
		d = NFP_MAC_MacPrePendDsaCtl2_DsaTagModePort18_of(d);
		break;
	case 19:
		d = NFP_MAC_MacPrePendDsaCtl2_DsaTagModePort19_of(d);
		break;
	case 20:
		d = NFP_MAC_MacPrePendDsaCtl2_DsaTagModePort20_of(d);
		break;
	case 21:
		d = NFP_MAC_MacPrePendDsaCtl2_DsaTagModePort21_of(d);
		break;
	case 22:
		d = NFP_MAC_MacPrePendDsaCtl2_DsaTagModePort22_of(d);
		break;
	case 23:
		d = NFP_MAC_MacPrePendDsaCtl2_DsaTagModePort23_of(d);
		break;
	default:
		return -EINVAL;
	}
	return d;
}

int nfp_nbi_mac_eth_read_egress_skip(struct nfp_nbi_dev *nbi, int core,
				     int port)
{
	int ret;
	uint64_t r;
	uint32_t d = 0;

	if (nbi == NULL)
		return -ENODEV;

	if ((core < 0) || (core > 1))
		return -EINVAL;

	if ((port < 0) || (port > 11))
		return -EINVAL;


	switch ((port + core * 12) / 4) {
	case 0:
		r = NFP_MAC_MacPrePendCtl03to00;
		break;
	case 1:
		r = NFP_MAC_MacPrePendCtl07to04;
		break;
	case 2:
		r = NFP_MAC_MacPrePendCtl11to08;
		break;
	case 3:
		r = NFP_MAC_MacPrePendCtl15to12;
		break;
	case 4:
		r = NFP_MAC_MacPrePendCtl19to16;
		break;
	case 5:
		r = NFP_MAC_MacPrePendCtl23to20;
		break;
	default:
		return -EINVAL;
	}

	ret = nfp_nbi_mac_regr(nbi, NFP_MAC, r, &d);
	if (ret < 0)
		return ret;

	switch (port) {
	case 0:
		d = NFP_MAC_MacPrePendCtl1_EGSkipOctetsPort0_of(d);
		break;
	case 1:
		d = NFP_MAC_MacPrePendCtl1_EGSkipOctetsPort1_of(d);
		break;
	case 2:
		d = NFP_MAC_MacPrePendCtl1_EGSkipOctetsPort2_of(d);
		break;
	case 3:
		d = NFP_MAC_MacPrePendCtl1_EGSkipOctetsPort3_of(d);
		break;
	case 4:
		d = NFP_MAC_MacPrePendCtl2_EGSkipOctetsPort4_of(d);
		break;
	case 5:
		d = NFP_MAC_MacPrePendCtl2_EGSkipOctetsPort5_of(d);
		break;
	case 6:
		d = NFP_MAC_MacPrePendCtl2_EGSkipOctetsPort6_of(d);
		break;
	case 7:
		d = NFP_MAC_MacPrePendCtl2_EGSkipOctetsPort7_of(d);
		break;
	case 8:
		d = NFP_MAC_MacPrePendCtl3_EGSkipOctetsPort8_of(d);
		break;
	case 9:
		d = NFP_MAC_MacPrePendCtl3_EGSkipOctetsPort9_of(d);
		break;
	case 10:
		d = NFP_MAC_MacPrePendCtl3_EGSkipOctetsPort10_of(d);
		break;
	case 11:
		d = NFP_MAC_MacPrePendCtl3_EGSkipOctetsPort11_of(d);
		break;
	default:
		return -EINVAL;
	}

	return d;

}

int nfp_nbi_mac_eth_read_ingress_dsa(struct nfp_nbi_dev *nbi, int core,
				     int port)
{
	int ret;
	uint64_t r;
	uint32_t d = 0;

	if (nbi == NULL)
		return -ENODEV;

	if ((core < 0) || (core > 1))
		return -EINVAL;

	if ((port < 0) || (port > 11))
		return -EINVAL;


	if ((port + core * 12) <= 15)
		r = NFP_MAC_MacPrePendDsaCtl15to00;
	else
		r = NFP_MAC_MacPrePendDsaCtlLkand23to16;

	ret = nfp_nbi_mac_regr(nbi, NFP_MAC, r, &d);
	if (ret < 0)
		return ret;

	switch (port + core * 12) {
	case 0:
		d = NFP_MAC_MacPrePendDsaCtl1_DsaTagModePort0_of(d);
		break;
	case 1:
		d = NFP_MAC_MacPrePendDsaCtl1_DsaTagModePort1_of(d);
		break;
	case 2:
		d = NFP_MAC_MacPrePendDsaCtl1_DsaTagModePort2_of(d);
		break;
	case 3:
		d = NFP_MAC_MacPrePendDsaCtl1_DsaTagModePort3_of(d);
		break;
	case 4:
		d = NFP_MAC_MacPrePendDsaCtl1_DsaTagModePort4_of(d);
		break;
	case 5:
		d = NFP_MAC_MacPrePendDsaCtl1_DsaTagModePort5_of(d);
		break;
	case 6:
		d = NFP_MAC_MacPrePendDsaCtl1_DsaTagModePort6_of(d);
		break;
	case 7:
		d = NFP_MAC_MacPrePendDsaCtl1_DsaTagModePort7_of(d);
		break;
	case 8:
		d = NFP_MAC_MacPrePendDsaCtl1_DsaTagModePort8_of(d);
		break;
	case 9:
		d = NFP_MAC_MacPrePendDsaCtl1_DsaTagModePort9_of(d);
		break;
	case 10:
		d = NFP_MAC_MacPrePendDsaCtl1_DsaTagModePort10_of(d);
		break;
	case 11:
		d = NFP_MAC_MacPrePendDsaCtl1_DsaTagModePort11_of(d);
		break;
	case 12:
		d = NFP_MAC_MacPrePendDsaCtl1_DsaTagModePort12_of(d);
		break;
	case 13:
		d = NFP_MAC_MacPrePendDsaCtl1_DsaTagModePort13_of(d);
		break;
	case 14:
		d = NFP_MAC_MacPrePendDsaCtl1_DsaTagModePort14_of(d);
		break;
	case 15:
		d = NFP_MAC_MacPrePendDsaCtl1_DsaTagModePort15_of(d);
		break;
	case 16:
		d = NFP_MAC_MacPrePendDsaCtl2_DsaTagModePort16_of(d);
		break;
	case 17:
		d = NFP_MAC_MacPrePendDsaCtl2_DsaTagModePort17_of(d);
		break;
	case 18:
		d = NFP_MAC_MacPrePendDsaCtl2_DsaTagModePort18_of(d);
		break;
	case 19:
		d = NFP_MAC_MacPrePendDsaCtl2_DsaTagModePort19_of(d);
		break;
	case 20:
		d = NFP_MAC_MacPrePendDsaCtl2_DsaTagModePort20_of(d);
		break;
	case 21:
		d = NFP_MAC_MacPrePendDsaCtl2_DsaTagModePort21_of(d);
		break;
	case 22:
		d = NFP_MAC_MacPrePendDsaCtl2_DsaTagModePort22_of(d);
		break;
	case 23:
		d = NFP_MAC_MacPrePendDsaCtl2_DsaTagModePort23_of(d);
		break;
	default:
		return -EINVAL;
	}
	return d;
}

int nfp_nbi_mac_eth_write_ingress_dsa(struct nfp_nbi_dev *nbi, int core,
				      int port, int octets)
{
	uint64_t r;
	uint32_t d = 0;
	uint32_t m = 0;

	if (nbi == NULL)
		return -ENODEV;

	if ((core < 0) || (core > 1))
		return -EINVAL;

	if ((port < 0) || (port > 11))
		return -EINVAL;

	if ((octets != 0) && (octets != 4) && (octets != 8))
		return -EINVAL;

	if ((port + core * 12) <= 15)
		r = NFP_MAC_MacPrePendDsaCtl15to00;
	else
		r = NFP_MAC_MacPrePendDsaCtlLkand23to16;

	switch (port + core * 12) {
	case 0:
		m = NFP_MAC_MacPrePendDsaCtl1_DsaTagModePort0(0xf);
		d = NFP_MAC_MacPrePendDsaCtl1_DsaTagModePort0(octets /
								       2);
		break;
	case 1:
		m = NFP_MAC_MacPrePendDsaCtl1_DsaTagModePort1(0xf);
		d = NFP_MAC_MacPrePendDsaCtl1_DsaTagModePort1(octets /
								       2);
		break;
	case 2:
		m = NFP_MAC_MacPrePendDsaCtl1_DsaTagModePort2(0xf);
		d = NFP_MAC_MacPrePendDsaCtl1_DsaTagModePort2(octets /
								       2);
		break;
	case 3:
		m = NFP_MAC_MacPrePendDsaCtl1_DsaTagModePort3(0xf);
		d = NFP_MAC_MacPrePendDsaCtl1_DsaTagModePort3(octets /
								       2);
		break;
	case 4:
		m = NFP_MAC_MacPrePendDsaCtl1_DsaTagModePort4(0xf);
		d = NFP_MAC_MacPrePendDsaCtl1_DsaTagModePort4(octets /
								       2);
		break;
	case 5:
		m = NFP_MAC_MacPrePendDsaCtl1_DsaTagModePort5(0xf);
		d = NFP_MAC_MacPrePendDsaCtl1_DsaTagModePort5(octets /
								       2);
		break;
	case 6:
		m = NFP_MAC_MacPrePendDsaCtl1_DsaTagModePort6(0xf);
		d = NFP_MAC_MacPrePendDsaCtl1_DsaTagModePort6(octets /
								       2);
		break;
	case 7:
		m = NFP_MAC_MacPrePendDsaCtl1_DsaTagModePort7(0xf);
		d = NFP_MAC_MacPrePendDsaCtl1_DsaTagModePort7(octets /
								       2);
		break;
	case 8:
		m = NFP_MAC_MacPrePendDsaCtl1_DsaTagModePort8(0xf);
		d = NFP_MAC_MacPrePendDsaCtl1_DsaTagModePort8(octets /
								       2);
		break;
	case 9:
		m = NFP_MAC_MacPrePendDsaCtl1_DsaTagModePort9(0xf);
		d = NFP_MAC_MacPrePendDsaCtl1_DsaTagModePort9(octets /
								       2);
		break;
	case 10:
		m = NFP_MAC_MacPrePendDsaCtl1_DsaTagModePort10(0xf);
		d = NFP_MAC_MacPrePendDsaCtl1_DsaTagModePort10(octets /
									2);
		break;
	case 11:
		m = NFP_MAC_MacPrePendDsaCtl1_DsaTagModePort11(0xf);
		d = NFP_MAC_MacPrePendDsaCtl1_DsaTagModePort11(octets /
									2);
		break;
	case 12:
		m = NFP_MAC_MacPrePendDsaCtl1_DsaTagModePort12(0xf);
		d = NFP_MAC_MacPrePendDsaCtl1_DsaTagModePort12(octets /
									2);
		break;
	case 13:
		m = NFP_MAC_MacPrePendDsaCtl1_DsaTagModePort13(0xf);
		d = NFP_MAC_MacPrePendDsaCtl1_DsaTagModePort13(octets /
									2);
		break;
	case 14:
		m = NFP_MAC_MacPrePendDsaCtl1_DsaTagModePort14(0xf);
		d = NFP_MAC_MacPrePendDsaCtl1_DsaTagModePort14(octets /
									2);
		break;
	case 15:
		m = NFP_MAC_MacPrePendDsaCtl1_DsaTagModePort15(0xf);
		d = NFP_MAC_MacPrePendDsaCtl1_DsaTagModePort15(octets /
									2);
		break;
	case 16:
		m = NFP_MAC_MacPrePendDsaCtl2_DsaTagModePort16(0xf);
		d = NFP_MAC_MacPrePendDsaCtl2_DsaTagModePort16(octets /
									2);
		break;
	case 17:
		m = NFP_MAC_MacPrePendDsaCtl2_DsaTagModePort17(0xf);
		d = NFP_MAC_MacPrePendDsaCtl2_DsaTagModePort17(octets /
									2);
		break;
	case 18:
		m = NFP_MAC_MacPrePendDsaCtl2_DsaTagModePort18(0xf);
		d = NFP_MAC_MacPrePendDsaCtl2_DsaTagModePort18(octets /
									2);
		break;
	case 19:
		m = NFP_MAC_MacPrePendDsaCtl2_DsaTagModePort19(0xf);
		d = NFP_MAC_MacPrePendDsaCtl2_DsaTagModePort19(octets /
									2);
		break;
	case 20:
		m = NFP_MAC_MacPrePendDsaCtl2_DsaTagModePort20(0xf);
		d = NFP_MAC_MacPrePendDsaCtl2_DsaTagModePort20(octets /
									2);
		break;
	case 21:
		m = NFP_MAC_MacPrePendDsaCtl2_DsaTagModePort21(0xf);
		d = NFP_MAC_MacPrePendDsaCtl2_DsaTagModePort21(octets /
									2);
		break;
	case 22:
		m = NFP_MAC_MacPrePendDsaCtl2_DsaTagModePort22(0xf);
		d = NFP_MAC_MacPrePendDsaCtl2_DsaTagModePort22(octets /
									2);
		break;
	case 23:
		m = NFP_MAC_MacPrePendDsaCtl2_DsaTagModePort23(0xf);
		d = NFP_MAC_MacPrePendDsaCtl2_DsaTagModePort23(octets /
									2);
		break;
	default:
		return -EINVAL;
	}

	return nfp_nbi_mac_regw(nbi, NFP_MAC, r, m, d);
}

int nfp_nbi_mac_eth_read_ingress_skip(struct nfp_nbi_dev *nbi, int core,
				      int port)
{
	int ret;
	uint64_t r;
	uint32_t d = 0;

	if (nbi == NULL)
		return -ENODEV;

	if ((core < 0) || (core > 1))
		return -EINVAL;

	if ((port < 0) || (port > 11))
		return -EINVAL;

	switch ((port + core * 12) / 4) {
	case 0:
		r = NFP_MAC_MacPrePendCtl03to00;
		break;
	case 1:
		r = NFP_MAC_MacPrePendCtl07to04;
		break;
	case 2:
		r = NFP_MAC_MacPrePendCtl11to08;
		break;
	case 3:
		r = NFP_MAC_MacPrePendCtl15to12;
		break;
	case 4:
		r = NFP_MAC_MacPrePendCtl19to16;
		break;
	case 5:
		r = NFP_MAC_MacPrePendCtl23to20;
		break;
	default:
		return -EINVAL;
	}

	ret = nfp_nbi_mac_regr(nbi, NFP_MAC, r, &d);
	if (ret < 0)
		return ret;

	switch (port) {
	case 0:
		d = NFP_MAC_MacPrePendCtl1_IGSkipOctetsPort0_of(d);
		break;
	case 1:
		d = NFP_MAC_MacPrePendCtl1_IGSkipOctetsPort1_of(d);
		break;
	case 2:
		d = NFP_MAC_MacPrePendCtl1_IGSkipOctetsPort2_of(d);
		break;
	case 3:
		d = NFP_MAC_MacPrePendCtl1_IGSkipOctetsPort3_of(d);
		break;
	case 4:
		d = NFP_MAC_MacPrePendCtl2_IGSkipOctetsPort4_of(d);
		break;
	case 5:
		d = NFP_MAC_MacPrePendCtl2_IGSkipOctetsPort5_of(d);
		break;
	case 6:
		d = NFP_MAC_MacPrePendCtl2_IGSkipOctetsPort6_of(d);
		break;
	case 7:
		d = NFP_MAC_MacPrePendCtl2_IGSkipOctetsPort7_of(d);
		break;
	case 8:
		d = NFP_MAC_MacPrePendCtl3_IGSkipOctetsPort8_of(d);
		break;
	case 9:
		d = NFP_MAC_MacPrePendCtl3_IGSkipOctetsPort9_of(d);
		break;
	case 10:
		d = NFP_MAC_MacPrePendCtl3_IGSkipOctetsPort10_of(d);
		break;
	case 11:
		d = NFP_MAC_MacPrePendCtl3_IGSkipOctetsPort11_of(d);
		break;
	default:
		return -EINVAL;
	}

	return d;

}

#define NFP_MAC_ETH_MacEthSeg_EthPauseQuantaCL(_p, _x) \
	(0x00000054 + 4 * ((_p) >> 1) + (0x400 * ((_x) & 0xf)))
#define NFP_MAC_ETH_MacEthSeg_EthPauseQuantaCL_EthPauseQuantaCL_of(_p, _x)\
	(((_x) >> (16 * ((_p) & 1))) & 0xffff)


int nfp_nbi_mac_eth_read_pause_quant(struct nfp_nbi_dev *nbi, int core,
				     int port, int pcpclass)
{
	int ret;
	uint64_t r;
	uint32_t d = 0;

	if (nbi == NULL)
		return -ENODEV;

	if ((core < 0) || (core > 1))
		return -EINVAL;

	if ((port < 0) || (port > 11))
		return -EINVAL;

	if ((pcpclass < 0) || (pcpclass > 7))
		return -EINVAL;

	r = NFP_MAC_ETH_MacEthSeg_EthPauseQuantaCL(pcpclass, port);

	ret = nfp_nbi_mac_regr(nbi, NFP_MAC_ETH(core), r, &d);
	if (ret < 0)
		return ret;

	d = NFP_MAC_ETH_MacEthSeg_EthPauseQuantaCL_EthPauseQuantaCL_of(
			pcpclass, port);

	return d;

}

int nfp_nbi_mac_read_egress_prepend_enable(struct nfp_nbi_dev *nbi, int chan)
{
	int ret;
	uint64_t r;
	uint32_t d = 0;

	if (nbi == NULL)
		return -ENODEV;

	if ((chan < 0) || (chan > NFP_NBI_MAC_CHAN_MAX))
		return -EINVAL;


	switch (chan / 4) {
	case 0:
		r = NFP_MAC_EgCmdPrependEn0Lo;
		break;
	case 1:
		r = NFP_MAC_EgCmdPrependEn0Hi;
		break;
	case 2:
		r = NFP_MAC_EgCmdPrependEn1Lo;
		break;
	case 3:
		r = NFP_MAC_EgCmdPrependEn1Hi;
		break;
	default:
		return -EINVAL;
	}

	ret = nfp_nbi_mac_regr(nbi, NFP_MAC, r, &d);
	if (ret < 0)
		return ret;

	return (d & (1 << (chan % 4))) > 0;

}

int nfp_nbi_mac_eth_read_pause_thresh(struct nfp_nbi_dev *nbi, int core,
				      int port, int pcpclass)
{
	int ret;
	uint64_t r;
	uint32_t d = 0;

	if (nbi == NULL)
		return -ENODEV;

	if ((core < 0) || (core > 1))
		return -EINVAL;

	if ((port < 0) || (port > 11))
		return -EINVAL;

	if ((pcpclass < 0) || (pcpclass > 7))
		return -EINVAL;

	r = NFP_MAC_ETH_MacEthSeg_EthQuantaThreshCL(pcpclass, port);

	ret = nfp_nbi_mac_regr(nbi, NFP_MAC_ETH(core), r, &d);
	if (ret < 0)
		return ret;

	d = NFP_MAC_ETH_MacEthSeg_EthQuantaThreshCL_EthQuantaThresh_of(
								pcpclass, d);

	return d;
}

int nfp_nbi_mac_eth_read_port_hwm(struct nfp_nbi_dev *nbi, int core, int port)
{
	int ret;
	uint64_t r;
	uint32_t d = 0;
	uint32_t h = 0;

	if (nbi == NULL)
		return -ENODEV;

	if ((core < 0) || (core > 1))
		return -EINVAL;

	if ((port < 0) || (port > 11))
		return -EINVAL;

	r = NFP_MAC_MacPortHwm((port + core * 12) / 2);

	ret = nfp_nbi_mac_regr(nbi, NFP_MAC, r, &d);
	if (ret < 0)
		return ret;

	if ((port % 2) == 0) {
		h = NFP_MAC_MacPortHwm_PortHwm0_of(d);
		d = NFP_MAC_MacPortHwm_PortDropDelta0_of(d);
	} else {
		h = NFP_MAC_MacPortHwm_PortHwm1_of(d);
		d = NFP_MAC_MacPortHwm_PortDropDelta1_of(d);
	}

	return (d << 16) | h;
}

int nfp_nbi_mac_eth_write_mac_addr(struct nfp_nbi_dev *nbi, int core,
				   int port, uint64_t hwaddr)
{
	int ret;
	uint64_t r;
	uint32_t d = 0;
	uint32_t m = 0;

	if (nbi == NULL)
		return -ENODEV;

	if ((core < 0) || (core > 1))
		return -EINVAL;

	if ((port < 0) || (port > 11))
		return -EINVAL;

	if ((hwaddr >> 48) > 0)
		return -EINVAL;

	r = NFP_MAC_ETH_MacEthSeg_EthMacAddr0(port);
	m = NFP_MAC_ETH_MacEthSeg_EthMacAddr0_EthMacAddr0(0xffffffffffff);
	d = NFP_MAC_ETH_MacEthSeg_EthMacAddr0_EthMacAddr0(hwaddr);

	ret = nfp_nbi_mac_regw(nbi, NFP_MAC_ETH(core), r, m, d);
	if (ret < 0)
		return ret;

	r = NFP_MAC_ETH_MacEthSeg_EthMacAddr1(port);
	m = NFP_MAC_ETH_MacEthSeg_EthMacAddr1_EthMacAddr1(0xffff);
	d = NFP_MAC_ETH_MacEthSeg_EthMacAddr1_EthMacAddr1(hwaddr >> 32);

	return nfp_nbi_mac_regw(nbi, NFP_MAC_ETH(core), r, m, d);
}
EXPORT_SYMBOL(nfp_nbi_mac_eth_write_mac_addr);

int nfp_nbi_mac_eth_read_mac_addr(struct nfp_nbi_dev *nbi, int core,
				  int port, uint64_t *hwaddr)
{
	int ret;
	uint64_t r;
	uint32_t d = 0;
	uint32_t m = 0;

	if (nbi == NULL)
		return -ENODEV;

	if ((core < 0) || (core > 1))
		return -EINVAL;

	if ((port < 0) || (port > 11))
		return -EINVAL;

	if (hwaddr == NULL)
		return -EINVAL;

	r = NFP_MAC_ETH_MacEthSeg_EthMacAddr0(port);
	ret = nfp_nbi_mac_regr(nbi, NFP_MAC_ETH(core), r, &d);
	if (ret < 0)
		return ret;

	r = NFP_MAC_ETH_MacEthSeg_EthMacAddr1(port);
	ret = nfp_nbi_mac_regr(nbi, NFP_MAC_ETH(core), r, &m);
	if (ret < 0)
		return ret;

	*hwaddr = m;
	*hwaddr = (*hwaddr << 32) | d;
	return 0;
}
EXPORT_SYMBOL(nfp_nbi_mac_eth_read_mac_addr);

int nfp_nbi_mac_write_timestamp(struct nfp_nbi_dev *nbi, uint64_t ts_sec,
				uint64_t ts_nsec)
{
	int ret;
	uint64_t r;
	uint32_t d = 0;
	uint32_t m = 0;

	if (nbi == NULL)
		return -ENODEV;

	r = NFP_MAC_MacTimeStampSetSec;
	m = -1;
	d = NFP_MAC_MacTimeStampSetSec_MacTimeStampSetSec(ts_sec);
	ret = nfp_nbi_mac_regw(nbi, NFP_MAC, r, m, d);
	if (ret < 0)
		return ret;

	r = NFP_MAC_MacTimeStampSetNsec;
	m = -1;
	d = NFP_MAC_MacTimeStampSetNsec_MacTimeStampSetNsec(ts_nsec);
	ret = nfp_nbi_mac_regw(nbi, NFP_MAC, r, m, d);
	if (ret < 0)
		return ret;

	/* set clock mode, enable and load timestamp regs.
	 */
	r = NFP_MAC_MacSysSupCtrl;
	m = NFP_MAC_MacSysSupCtrl_TimeStampFrc |
	    NFP_MAC_MacSysSupCtrl_TimeStampSet |
	    NFP_MAC_MacSysSupCtrl_TimeStampEn;
	d = NFP_MAC_MacSysSupCtrl_TimeStampSet |
	    NFP_MAC_MacSysSupCtrl_TimeStampEn;

	return nfp_nbi_mac_regw(nbi, NFP_MAC, r, m, d);
}

int nfp_nbi_mac_read_timestamp(struct nfp_nbi_dev *nbi, uint64_t *ts_sec,
			       uint64_t *ts_nsec)
{
	int ret;
	uint64_t r;
	uint32_t d = 0;

	if (nbi == NULL)
		return -ENODEV;

	if ((ts_sec == NULL) || (ts_nsec == NULL))
		return -EINVAL;

	r = NFP_MAC_MacTimeStampSec;
	ret = nfp_nbi_mac_regr(nbi, NFP_MAC, r, &d);
	if (ret < 0)
		return ret;
	*ts_sec = NFP_MAC_MacTimeStampSec_MacTimeStampSec_of(d);

	r = NFP_MAC_MacTimeStampNsec;
	ret = nfp_nbi_mac_regr(nbi, NFP_MAC, r, &d);
	if (ret < 0)
		return ret;
	*ts_nsec = NFP_MAC_MacTimeStampNsec_MacTimeStampNsec_of(d);

	return 0;

}

int nfp_nbi_mac_write_tmoobfc_enables(struct nfp_nbi_dev *nbi, uint32_t mask)
{
	uint64_t r;
	uint32_t d = 0;
	uint32_t m = 0;

	if (nbi == NULL)
		return -ENODEV;

	r = NFP_MAC_MacOobFcTmCntl;
	m = NFP_MAC_MacOobFcTmCntl_Oob1023To512Mod32M1(0xf) |
	    NFP_MAC_MacOobFcTmCntl_Oob1023To512MsgEn |
	    NFP_MAC_MacOobFcTmCntl_Oob1023To512En |
	    NFP_MAC_MacOobFcTmCntl_Oob511To0Mod32M1(0xf) |
	    NFP_MAC_MacOobFcTmCntl_Oob511To0MsgEn |
	    NFP_MAC_MacOobFcTmCntl_Oob511To0En;
	d = mask;

	return nfp_nbi_mac_regw(nbi, NFP_MAC, r, m, d);
}

int nfp_nbi_mac_read_tmoobfc_enables(struct nfp_nbi_dev *nbi)
{
	int ret;
	uint64_t r;
	uint32_t d = 0;

	if (nbi == NULL)
		return -ENODEV;

	r = NFP_MAC_MacOobFcTmCntl;
	ret = nfp_nbi_mac_regr(nbi, NFP_MAC, r, &d);
	if (ret < 0)
		return ret;

	d |= NFP_MAC_MacOobFcTmCntl_Oob1023To512Mod32M1(0xf) |
	    NFP_MAC_MacOobFcTmCntl_Oob1023To512MsgEn |
	    NFP_MAC_MacOobFcTmCntl_Oob1023To512En |
	    NFP_MAC_MacOobFcTmCntl_Oob511To0Mod32M1(0xf) |
	    NFP_MAC_MacOobFcTmCntl_Oob511To0MsgEn |
	    NFP_MAC_MacOobFcTmCntl_Oob511To0En;

	return d;

}

int nfp_nbi_mac_eth_read_pause_status(struct nfp_nbi_dev *nbi, int core,
				      int port)
{
	int ret;
	uint64_t r;
	uint32_t d = 0;

	if (nbi == NULL)
		return -ENODEV;

	if ((core < 0) || (core > 1))
		return -EINVAL;

	if ((port < 0) || (port > 11))
		return -EINVAL;

	r = NFP_MAC_ETH_MacEthSeg_EthRxPauseStatus(port);
	ret = nfp_nbi_mac_regr(nbi, NFP_MAC_ETH(core), r, &d);
	if (ret < 0)
		return ret;

	return
	    NFP_MAC_ETH_MacEthSeg_EthRxPauseStatus_EthRxPauseStatus_of(d);

}

/*
int nfp_nbi_mac_eth_read_headdrop(struct nfp_nbi_dev *nbi, int core, int port)
*/

/* vim: set shiftwidth=8 noexpandtab: */
