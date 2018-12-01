#
# Copyright (C) 2018,  Netronome Systems, Inc.  All rights reserved.
#
"""
Driver System class
"""

import os
import re
import struct
import json
import netro.testinfra
from netro.testinfra.system import *
from netro.testinfra.system import _parse_ethtool
from netro.testinfra.nti_exceptions import NtiError, NtiGeneralError
from common_test import assert_eq, NtiSkip

################################################################################
# Helpers
################################################################################

def int2str(fmt, val):
    ret = list(bytearray(struct.pack(fmt, val)))
    return " ".join(map(lambda x: str(x), ret))

def str2int(strtab):
    inttab = []
    for i in strtab:
        inttab.append(int(i, 16))
    ba = bytearray(inttab)
    if len(strtab) == 4:
        fmt = "I"
    elif len(strtab) == 8:
        fmt = "Q"
    else:
        raise Exception("String array of len %d can't be unpacked to an int" %
                        (len(strtab)))
    return struct.unpack(fmt, ba)[0]

################################################################################
# Linux System class
################################################################################

class LinuxSystem(System):
    def __init__(self, host, group, quick=False, _noendsec=False):
        super(LinuxSystem, self).__init__(host, quick, _noendsec)

        self.group = group
        self._bck_pids = []

    ###############################
    # Standard OS helpers
    ###############################
    def background_procs_add(self, pid):
        self._bck_pids.append(pid)

    def background_procs_remove(self, pid):
        self._bck_pids.remove(pid)

    def background_procs_cleanup(self):
        cmds = ""
        for pid in self._bck_pids:
            cmds += 'kill -9 $(cat %s);' % pid
        if cmds:
            self.cmd(cmds, fail=False)
        self._bck_pids = []

    ###############################
    # Version checks
    ###############################
    def _kernel_ver_detect_net_next(self):
        _, (_, err) = self.cmd("ip link add przejrzystosc type strzelista",
                               fail=False, include_stderr=True)
        if err.rstrip() == "Error: Unknown device type.":
            return "4.21.0"
        return self.kernel_ver

    def _kernel_ver_read(self):
        if not hasattr(self, '_kernel_maj') or not hasattr(self, '_kernel_min'):
            if not hasattr(self, 'kernel_ver') or self.kernel_ver is None:
                _, self.kernel_ver = self.cmd('uname -r')

            self.kernel_ver = self._kernel_ver_detect_net_next()
            self._kernel_maj = int(self.kernel_ver.split('.')[0])
            self._kernel_min = int(self.kernel_ver.split('.')[1])

    def get_kernel_ver(self):
        self._kernel_ver_read()
        return self.kernel_ver

    def kernel_ver_ge(self, major, minor):
        self._kernel_ver_read()
        return (self._kernel_maj == major and self._kernel_min >= minor) or \
            self._kernel_maj > major

    def kernel_ver_lt(self, major, minor):
        return not self.kernel_ver_ge(major, minor)

    ###############################
    # Stats handling
    ###############################
    def stats_diff(self, old_stats, new_stats):
        res = {}

        assert_eq(len(new_stats.keys()), len(old_stats.keys()),
                  "stat dict key count")

        for k in new_stats.keys():
            if k not in old_stats:
                raise NtiError("old stats don't have key '%s'" % (k))

            if isinstance(new_stats[k], int) or isinstance(new_stats[k], long):
                res[k] = new_stats[k] - old_stats[k]
            elif isinstance(new_stats[k], dict):
                res[k] = self.stats_diff(old_stats[k], new_stats[k])
            else:
                raise NtiError("unhandled value type for key '%s': %r" %
                               (k, new_stats[k]))

        return res

    ###############################
    # Traffic generation
    ###############################
    def _ping(self, prog, wait, addr, ifc, count, size, pattern, ival, tos,
              flood, should_fail):
        cmd = "%s -W%d %s " % (prog, wait, addr)
        if ifc is not None:
            cmd += "-I %s " % (ifc)
        if count is not None:
            cmd += "-c %d " % (count)
        if size is not None:
            cmd += "-s %d " % (size)
        if pattern:
            cmd += "-p %s " % (pattern)
        if ival is not None and not flood:
            cmd += "-i %s " % (ival)
        if tos is not None:
            cmd += "-Q %d " % (tos)
        if flood:
            cmd += "-f "

        ret, _ = self.cmd(cmd, fail=False)
        if ret and should_fail == False:
            raise NtiError("Couldn't %s endpoint" % (prog))
        if ret == 0 and should_fail == True:
            raise NtiError("Could %s endpoint" % (prog))
        return ret

    def ping(self, addr, ifc=None, count=10, size=None, pattern="",
             ival="0.05", tos=None, flood=False, should_fail=False):
        return self._ping("ping", 2, addr, ifc, count, size, pattern, ival,
                          tos, flood, should_fail)

    def ping6(self, addr, ifc=None, count=10, size=None, pattern="",
              ival="0.05", tos=None, flood=False, should_fail=False):
        return self._ping("ping6", 5, addr, ifc, count, size, pattern, ival,
                          tos, flood, should_fail)

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

    def ip_link_set_mtu(self, ifc, mtu, fail=True):
        return self.cmd('ip link set dev {ifc} mtu {mtu}'.format(ifc=ifc,
                                                                 mtu=mtu),
                        fail=fail)

    ###############################
    # bpftool
    ###############################
    def _bpftool_obj_id(self, bpf_obj, ident, pin):
        if bpf_obj is not None:
            return ' id ' + str(bpf_obj["id"])
        elif ident is not None:
            return ' id ' + str(ident)
        elif pin is not None:
            return ' pinned ' + pin
        return ''

    def bpftool(self, param, fail=True):
        ret, out = self.cmd("bpftool -p " + param, fail=fail)
        if len(out) == 0:
            return ret, {}
        return ret, json.loads(out)

    def bpftool_prog_show(self, prog=None, ident=None, pin=None):
        cmd = 'prog show' + self._bpftool_obj_id(prog, ident, pin)
        return self.bpftool(cmd)

    def bpftool_prog_list(self, fail=True):
        return self.bpftool("prog", fail=fail)

    def bpftool_prog_load(self, obj, pin, ifc=None, prog_type=None, maps=None,
                          fail=True):
        cmd = 'prog load %s %s' % (obj, pin)
        if ifc is not None:
            cmd += ' dev ' + ifc
        if prog_type is not None:
            cmd += ' type ' + prog_type
        if maps is not None:
            for k in maps:
                cmd += ' map'
                if isinstance(k, str):
                    cmd += ' name ' + k
                elif isinstance(k, int):
                    cmd += ' idx ' + k
                else:
                    raise NtiError('maps key of unknown type %r' % k)

                if isinstance(maps[k], str):
                    cmd += ' pinned ' + maps[k]
                elif isinstance(maps[k], int):
                    cmd += ' id ' + maps[k]
                else:
                    raise NtiError('maps value of unknown type %r' % k)

        return self.bpftool(cmd, fail=fail)

    def bpftool_prog_load_xdp(self, obj, pin, maps=None, ifc=None, fail=True):
        obj = os.path.join(self.xdp_samples_dir, obj)
        return self.bpftool_prog_load(obj=obj, pin=pin, ifc=ifc,
                                      prog_type="xdp", maps=maps, fail=fail)

    def bpftool_map_show(self, m=None, ident=None, pin=None):
        cmd = 'map show' + self._bpftool_obj_id(m, ident, pin)
        return self.bpftool(cmd)

    def bpftool_map_dump(self, m=None, ident=None, pin=None):
        cmd = 'map dump' + self._bpftool_obj_id(m, ident, pin)
        return self.bpftool(cmd)

    def bpftool_map_del_int(self, m=None, ident=None, pin=None, key=None,
                            fail=True):
        cmd = 'map delete %s key %s' % (self._bpftool_obj_id(m, ident, pin),
                                        int2str("I", key))
        return self.bpftool(cmd, fail=fail)

    def bpftool_map_list(self, fail=True):
        return self.bpftool("map", fail=fail)

    def bpftool_map_create(self, pin, map_type=None, key_size=None,
                           value_size=None, entries=None, name=None, flags=None,
                           ifc=None, fail=True):
        cmd = 'map create %s' % (pin)
        if map_type is not None:
            cmd += ' type ' + map_type
        if key_size is not None:
            cmd += ' key ' + str(key_size)
        if value_size is not None:
            cmd += ' value ' + str(value_size)
        if entries is not None:
            cmd += ' entries ' + str(entries)
        if name is not None:
            cmd += ' name ' + name
        if flags is not None:
            cmd += ' flags ' + str(flags)
        if ifc is not None:
            cmd += ' dev ' + ifc

        return self.bpftool(cmd)

    def bpftool_map_perf_capture_start(self, m=None, ident=None, pin=None,
                                       name=None):
        if name is None:
            name = str(ident) if ident is not None else str(m["id"])

        bpftool_pid = os.path.join(self.tmpdir, 'bpftool%s_pid' % (name))
        events = os.path.join(self.tmpdir, 'events%s.json' % (name))

        self.cmd('bpftool -jp map event_pipe %s > %s 2>/dev/null ' \
                 '& command ; echo $! > %s' %
                 (self._bpftool_obj_id(m, ident, pin), events, bpftool_pid))
        self.background_procs_add(bpftool_pid)

        return events, bpftool_pid

    def bpftool_map_perf_capture_stop(self, events, bpftool_pid):
        self.cmd('PID=$(cat {pid}) && echo $PID && rm {pid} && ' \
                 'kill -INT $PID && ' \
                 'while [ -d /proc/$PID ]; do true; done'
                 .format(pid=bpftool_pid))
        self.background_procs_remove(bpftool_pid)

        self.mv_from(events, self.group.tmpdir)
        return os.path.join(self.group.tmpdir, os.path.basename(events))

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

    def ethtool_stats_diff(self, ifc, old_stats):
        new_stats = self.ethtool_stats(ifc)
        return self.stats_diff(old_stats, new_stats)

    def ethtool_features_get(self, ifc):
        _, out = self.cmd('ethtool -k %s' % (ifc))

        ret = {}

        lines = out.split('\n')
        for l in lines:
            vals = l.split(': ')
            k = vals[0].strip()
            if k and not k.startswith('Features for '):
                ret[k] = ': '.join(vals[1:])

        return ret

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

    def ethtool_rings_set(self, ifc, settings, fail=True):
        LOG_sec("GET RING %s for %s to %s" % (self.host, ifc, str(settings)))
        try:
                cmd = 'ethtool -G ' + ifc
                for k in settings.keys():
                    cmd += ' %s %s' % (k, settings[k])

                ret = self.cmd(cmd, fail=fail)
        finally:
            LOG_endsec()

        return ret
