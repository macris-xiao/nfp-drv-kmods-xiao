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
    ###############################
    # bpftool
    ###############################
    def bpftool(self, param, fail=True):
        ret, out = self.cmd("bpftool -p " + param, fail=fail)
        if len(out) == 0:
            return ret, {}
        return ret, json.loads(out)

    def bpftool_prog_show(self, ident):
        return self.bpftool("prog show id %d" % (ident))

    def bpftool_prog_list(self, fail=True):
        return self.bpftool("prog", fail=fail)

    def bpftool_map_show(self, ident):
        return self.bpftool("map show id %d" % (ident))

    def bpftool_map_list(self, fail=True):
        return self.bpftool("map", fail=fail)

    ###############################
    # ethtool
    ###############################
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

    def ethtool_pause_get(self, ifc):
        ret = None

        LOG_sec("GET PAUSE %s for %s" % (self.host, ifc))
        try:
            _, out = self.cmd("ethtool -a " + ifc)
            m = re.search("Autonegotiate:\s+(\w+)\s+RX:\s+(\w+)\s+TX:\s+(\w+)",
                          out, flags=re.M)

            ret = { "autoneg"	: m.groups()[0] == "on",
                    "rx"	: m.groups()[1] == "on",
                    "tx"	: m.groups()[2] == "on",
            }
            LOG(str(ret))
        finally:
            LOG_endsec()

        return ret

    def ethtool_pause_set(self, ifc, settings, force=False, fail=True):
        ret = None

        LOG_sec("SET PAUSE %s for %s to %s" % (self.host, ifc, str(settings)))
        try:
            if not force:
                # ethtool will return an error if we set the same thing twice
                current = self.ethtool_pause_get(ifc)
                if current == settings:
                    LOG("Correct values already set")
                    return

                cmd = 'ethtool -A ' + ifc
                for k in settings.keys():
                    cmd += ' %s %s' % (k, "on" if settings[k] else "off")

                ret = self.cmd(cmd)
        finally:
            LOG_endsec()

        return ret
