#
# Copyright (C) 2018,  Netronome Systems, Inc.  All rights reserved.
#
"""
Driver System class
"""

import re
import netro.testinfra
from netro.testinfra.system import *
from netro.testinfra.system import _parse_ethtool
from netro.testinfra.nti_exceptions import NtiError, NtiGeneralError
from common_test import NtiSkip

class LinuxSystem(System):
    def ethtool_drvinfo(self, ifc):
        _, out = self.cmd('ethtool -i %s' % (ifc))

        ret = {}

        lines = out.split('\n')
        for l in lines:
            vals = l.split(': ')
            ret[vals[0]] = ': '.join(vals[1:])

        return ret

    def ethtool_stats(self, ifc):
        _, out = self.cmd('ethtool -S %s' % (ifc))

        return _parse_ethtool(out)
