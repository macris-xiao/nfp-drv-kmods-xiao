#
# Copyright (C) 2018,  Netronome Systems, Inc.  All rights reserved.
#

class XDP_ACTION:
    ABORTED	= 0
    DROP	= 1
    PASS	= 2
    TX		= 3
    REDIRECT	= 4

class BPF_TLV:
    FUNC		= 1
    ADJUST_HEAD		= 2
    MAPS		= 3
    RANDOM		= 4

class BPF_HELPER:
    MAP_LOOKUP_ELEM	= 1
    MAP_UPDATE_ELEM	= 2
    MAP_DELETE_ELEM	= 3
