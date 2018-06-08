#
# Copyright (C) 2018,  Netronome Systems, Inc.  All rights reserved.
#
"""
Driver System class
"""

import re
import json
import netro.testinfra
from netro.testinfra.system import *
from netro.testinfra.system import _parse_ethtool
from netro.testinfra.nti_exceptions import NtiError, NtiGeneralError
from common_test import NtiSkip

class LinuxSystem(System):
    ###############################
    # Traffic generation
    ###############################
    def tcpping(self, addr, ifc=None, count=10, sport=100, dport=58, size=50,
                tos=None, keep=True, speed="fast",
                fail=False, should_fail=False):
        opts = "--{speed} --syn ".format(speed=speed)
        if keep:
            opts += "-k "
        if ifc:
            opts += "-I %s " % (ifc)
        if tos is not None:
            opts += "-o %d " % (tos)
        cmd = 'hping3 {addr} -c {cnt} -s {sport} -p {dport} -d {size} {opts}'
        cmd = cmd.format(addr=addr, cnt=count, sport=sport,
                         dport=dport, size=size, opts=opts)
        ret, out = self.cmd(cmd, fail=False)
        if fail == False:
            return ret, out
        if ret and should_fail == False:
            raise NtiGeneralError("Couldn't TCP ping endpoint")
        if ret == 0 and should_fail == True:
            raise NtiGeneralError("Could TCP ping endpoint")
        return ret

    ###############################
    # ip
    ###############################
    def ip(self, param, first=False, fail=True):
        ret, out = self.cmd("ip -j " + param, fail=fail)
        if len(out) == 0:
            return ret, {}
        if first:
            return ret, json.loads(out)[0]
        return ret, json.loads(out)

    def ip_link_set_up(self, ifc):
        self.cmd('ip link set dev {ifc} up'.format(ifc=ifc))

    def ip_link_set_down(self, ifc):
        self.cmd('ip link set dev {ifc} down'.format(ifc=ifc))

    def ip_link_stats(self, ifc=None):
        cmd = '-s link show'
        if ifc:
            cmd += ' dev ' + ifc
        return self.ip(cmd, first=bool(ifc))

    def link_wait(self, ifc, timeout=8, state=True):
        tgt_time = time.time() + timeout
        up_time = 0
        down_time = 0

        LOG_sec(self.host + " waiting for link on " + ifc)
        try:
            while True:
                ret, _ = self.cmd('ip link show dev %s | grep LOWER_UP' %
                                  (ifc), fail=False)

                now = time.time()
                # Carbon triggers spurious up events, which are followed by an
                # immediate down.  We need to make sure link is stable for at
                # least half a second.
                if ret == 0:
                    down_time = 0
                    if up_time == 0:
                        up_time = now
                    if state and (now - up_time >= 0.5):
                        return
                else:
                    up_time = 0
                    if down_time == 0:
                        down_time = now
                    if (not state) and (now - down_time >= 0.5):
                        return

                if now >= tgt_time:
                    raise NtiError("Timeout waiting for LINK %s on interface %s" %
                                   ("UP" if state else "DOWN", ifc))
                time.sleep(0.05)
        finally:
            LOG_endsec()

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

    def ethtool_channels_get(self, ifc):
        ret = {}

        LOG_sec("GET CHAN %s for %s" % (self.host, ifc))
        try:
            r = \
"""Channel parameters for \w+:
Pre-set maximums:
RX:		(\d+)
TX:		(\d+)
Other:		(\d+)
Combined:	(\d+)
Current hardware settings:
RX:		(\d+)
TX:		(\d+)
Other:		(\d+)
Combined:	(\d+)"""

            _, out = self.cmd("ethtool -l " + ifc)
            m = re.search(r, out, flags=re.M)

            ret = {
                "max"		: {
                    "rx"	: int(m.groups()[0]),
                    "tx"	: int(m.groups()[1]),
                    "other"	: int(m.groups()[2]),
                    "combined"	: int(m.groups()[3]),
                },
                "current"	: {
                    "rx"	: int(m.groups()[4]),
                    "tx"	: int(m.groups()[5]),
                    "other"	: int(m.groups()[6]),
                    "combined"	: int(m.groups()[7]),
                },
            }
            LOG(str(ret))
        finally:
            LOG_endsec()

        return ret

    def ethtool_channels_set(self, ifc, settings):
        LOG_sec("SET CHAN %s for %s to %s" % (self.host, ifc, str(settings)))
        try:
                cmd = 'ethtool -L ' + ifc
                for k in settings.keys():
                    cmd += ' %s %s' % (k, settings[k])

                ret = self.cmd(cmd)
        finally:
            LOG_endsec()

        return ret

    def ethtool_rings_get(self, ifc):
        ret = {}

        LOG_sec("SET RING %s for %s" % (self.host, ifc))
        try:
            r = \
"""Ring parameters for \w+:
Pre-set maximums:
RX:		(\d+)
RX Mini:	(\d+)
RX Jumbo:	(\d+)
TX:		(\d+)
Current hardware settings:
RX:		(\d+)
RX Mini:	(\d+)
RX Jumbo:	(\d+)
TX:		(\d+)

"""

            _, out = self.cmd("ethtool -g " + ifc)
            m = re.search(r, out, flags=re.M)

            ret = {
                "max"		: {
                    "rx"	: int(m.groups()[0]),
                    "rx-mini"	: int(m.groups()[1]),
                    "rx-jumbo"	: int(m.groups()[2]),
                    "tx"	: int(m.groups()[3]),
                },
                "current"	: {
                    "rx"	: int(m.groups()[4]),
                    "rx-mini"	: int(m.groups()[5]),
                    "rx-jumbo"	: int(m.groups()[6]),
                    "tx"	: int(m.groups()[7]),
                },
            }
            LOG(str(ret))
        finally:
            LOG_endsec()

        return ret

    def ethtool_rings_set(self, ifc, settings):
        LOG_sec("GET RING %s for %s to %s" % (self.host, ifc, str(settings)))
        try:
                cmd = 'ethtool -G ' + ifc
                for k in settings.keys():
                    cmd += ' %s %s' % (k, settings[k])

                ret = self.cmd(cmd)
        finally:
            LOG_endsec()

        return ret
