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
        self.tmpdir = self.make_temp_dir()

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

    def wait_online(self):
        ret = -1
        stop_time = time.time() + 400
        # Fall back to ssh instead of an xmlrpc connection as the
        # server is terminated during a reboot
        self.cmd_proxy = None
        while ret != 0:
            ret, _ = self.cmd('ip link', fail=False)
            if time.time() >= stop_time:
                raise NtiError('Waiting for reboot timed out')
            time.sleep(1)
        # Once the machine is back on, re-initiate xmlrpc server
        # on the machine
        self.bootstrap_xmlrpc()

    ###############################
    # Version checks
    ###############################
    def _kernel_ver_detect_net_next(self):
        """
        Wrapper in case some version checks needs to be done on versions
        that has not been tagged properly yet, e.g for a while it was needed
        to detect version 4.21 before it was changed to 5.0.
        """
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
    # Samples
    ###############################
    def copy_c_samples(self):
        if hasattr(self, 'c_samples_dir'):
            return

        self.c_samples_dir = os.path.join(self.tmpdir, 'c')
        self.cmd('mkdir %s' % self.c_samples_dir)
        self.cp_dir_to(os.path.join(self.group.samples_c, '*'),
                       self.c_samples_dir)

        return

    def copy_bpf_samples(self):
        if hasattr(self, 'bpf_samples_dir'):
            return

        self.bpf_samples_dir = os.path.join(self.tmpdir, 'bpf')
        self.cmd('mkdir %s' % self.bpf_samples_dir)
        self.cp_to(os.path.join(self.group.samples_bpf, '*.o'),
                   self.bpf_samples_dir)

        return

    def copy_xdp_samples(self):
        if hasattr(self, 'xdp_samples_dir'):
            return

        self.xdp_samples_dir = os.path.join(self.tmpdir, 'xdp')
        self.cmd('mkdir %s' % self.xdp_samples_dir)
        self.cp_to(os.path.join(self.group.samples_xdp, '*.o'),
                   self.xdp_samples_dir)

        return

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

    def spawn_netperfs(self, host, tag="nti", n=16):
        name = 'netperf_' + tag + '.pid'

        cmd = ''' # spawn_netperfs
        echo > {pidfile};
        for i in `seq {n}`; do
            netperf -H {host} -l 0 -t TCP_STREAM -- -m 400 -M 400 \
                >/dev/null 2>/dev/null & command;
            echo $! >> {pidfile}
            sleep 0.1 # otherwise some fail to connect and kill barfs
        done
        '''

        pidfile = os.path.join(self.tmpdir, name)
        self.cmd(cmd.format(n=n, host=host, pidfile=pidfile))
        return pidfile

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

    def ip_link_set_up(self, ifc, fail=True):
        return self.cmd('ip link set dev %s up' % ifc, fail=fail)

    def ip_link_set_down(self, ifc, fail=True):
        return self.cmd('ip link set dev %s down' % ifc, fail=fail)

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

    def is_legal_interface_name(self, if_name):
        error = ""
        name_suggestion = if_name

        # Ensure interface name length does not exceed IFNAMSIZ.
        if len(if_name) > 15:
            error = "Invalid interface name '%s': Exceeds IFNAMSIZ" % if_name

        # Ensure interface name is not in use already
        _, out = self.cmd('ls /sys/class/net/')
        used_interface_names = out.split()
        if if_name in used_interface_names:
            error = ("Invalid interface name '%s': Name in use already"
                     % if_name)

        # Generate a valid name if the provided one is invalid
        is_legal = (len(error) == 0)
        if not is_legal:
            temp = 0
            name_suggestion = 'testintf%s' % temp
            while name_suggestion in used_interface_names:
                temp = temp + 1
                name_suggestion = 'testintf%s' % temp

        return is_legal, error, name_suggestion

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
    def ethtool_drvinfo(self, ifc, ns=None):
        if ns:
            _, out = self.netns_cmd('ethtool -i %s' % (ifc), ns)
        else:
            _, out = self.cmd('ethtool -i %s' % (ifc))

        ret = {}

        lines = out.split('\n')
        for l in lines:
            vals = l.split(': ')
            ret[vals[0]] = ': '.join(vals[1:])

        return ret

    def ethtool_stats(self, ifc, ns=None):
        if ns:
            _, out = self.netns_cmd('ethtool -S %s' % (ifc), ns)
        else:
            _, out = self.cmd('ethtool -S %s' % (ifc))

        return _parse_ethtool(out)

    def ethtool_stats_diff(self, ifc, old_stats):
        new_stats = self.ethtool_stats(ifc)
        return self.stats_diff(old_stats, new_stats)

    def ethtool_features_get(self, ifc, ns=None):
        if ns:
            _, out = self.netns_cmd('ethtool -k %s' % (ifc), ns)
        else:
            _, out = self.cmd('ethtool -k %s' % (ifc))

        ret = {}

        lines = out.split('\n')
        for l in lines:
            vals = l.split(': ')
            k = vals[0].strip()
            if k and not k.startswith('Features for '):
                ret[k] = ': '.join(vals[1:])

        return ret

    def ethtool_pause_get(self, ifc, fail=True, return_code=False, ns=None):
        ret = None
        ret_code = 0
        LOG_sec("GET PAUSE %s for %s" % (self.host, ifc))
        try:
            if ns:
                ret_code, out = self.netns_cmd("ethtool -a " + ifc, ns, fail=fail)
            else:
                ret_code, out = self.cmd("ethtool -a " + ifc, fail=fail)
            m = re.search("Autonegotiate:\s+(\w+)\s+RX:\s+(\w+)\s+TX:\s+(\w+)",
                          out, flags=re.M)

            ret = { "autoneg"	: m.groups()[0] == "on",
                    "rx"	: m.groups()[1] == "on",
                    "tx"	: m.groups()[2] == "on",
            }
            LOG(str(ret))
        except:
            pass
        finally:
            LOG_endsec()

        if return_code:
            return int(ret_code), ret

        return ret

    def ethtool_pause_set(self, ifc, settings, force=False, fail=True, ns=None):
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

                if ns:
                    ret = self.netns_cmd(cmd, ns)
                else:
                    ret = self.cmd(cmd)
        finally:
            LOG_endsec()

        return ret

    def ethtool_channels_get(self, ifc, ns=None):
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

            if ns:
                _, out = self.netns_cmd("ethtool -l " + ifc, ns)
            else:
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

    def ethtool_channels_set(self, ifc, settings, ns=None):
        LOG_sec("SET CHAN %s for %s to %s" % (self.host, ifc, str(settings)))
        try:
                cmd = 'ethtool -L ' + ifc
                for k in settings.keys():
                    cmd += ' %s %s' % (k, settings[k])

                if ns:
                    ret = self.netns_cmd(cmd, ns)
                else:
                    ret = self.cmd(cmd)
        finally:
            LOG_endsec()

        return ret

    def ethtool_rings_get(self, ifc, ns=None):
        ret = {}

        LOG_sec("SET RING %s for %s" % (self.host, ifc))
        try:
            r = \
"""Ring parameters for \w+:
Pre-set maximums:
RX:		(\d+)
RX Mini:	(\d+|n\/a)
RX Jumbo:	(\d+|n\/a)
TX:		(\d+)
Current hardware settings:
RX:		(\d+)
RX Mini:	(\d+|n\/a)
RX Jumbo:	(\d+|n\/a)
TX:		(\d+)"""

            if ns:
                _, out = self.netns_cmd("ethtool -g " + ifc, ns)
            else:
                _, out = self.cmd("ethtool -g " + ifc)
            m = re.search(r, out, flags=re.M)

            ret = {
                "max"		: {
                    "rx"	: int(m.groups()[0]),
                    "rx-mini"	: int(m.groups()[1]) \
                                    if "n/a" not in m.groups()[1] else None,
                    "rx-jumbo"	: int(m.groups()[2]) \
                                    if "n/a" not in m.groups()[2] else None,
                    "tx"	: int(m.groups()[3]),
                },
                "current"	: {
                    "rx"	: int(m.groups()[4]),
                    "rx-mini"	: int(m.groups()[5]) \
                                    if "n/a" not in m.groups()[5] else None,
                    "rx-jumbo"	: int(m.groups()[6]) \
                                    if "n/a" not in m.groups()[6] else None,
                    "tx"	: int(m.groups()[7]),
                },
            }
            LOG(str(ret))
        finally:
            LOG_endsec()

        return ret

    def ethtool_rings_set(self, ifc, settings, fail=True, ns=None):
        LOG_sec("GET RING %s for %s to %s" % (self.host, ifc, str(settings)))
        try:
                cmd = 'ethtool -G ' + ifc
                for k in settings.keys():
                    if settings[k] is not None:
                        cmd += ' %s %s' % (k, settings[k])

                if ns:
                    ret = self.netns_cmd(cmd, ns, fail=fail)
                else:
                    ret = self.cmd(cmd, fail=fail)
        finally:
            LOG_endsec()

        return ret

    def ethtool_get_version(self):
        _, out = self.cmd('ethtool --version')
        out = out.split()[2]
        return float(out)

    def ethtool_set_autoneg(self, ifc, mode, fail=True):
        return self.cmd('ethtool -s %s autoneg %s' %
                        (ifc, mode),
                        include_stderr=True, fail=fail)

    def ethtool_get_autoneg(self, ifc, ns=None):
        if ns:
            _, out = self.netns_cmd('ethtool %s | grep Auto-negotiation' % (ifc), ns)
        else:
            _, out = self.cmd('ethtool %s | grep Auto-negotiation' % (ifc))

        if out.find(': on') != -1:
            return True
        if out.find(': off') != -1:
            return False
        raise NtiError('Invalid ethtool response: %s' % (out))

    def ethtool_get_speed(self, ifc, ns=None):
        if ns:
            _, out = self.netns_cmd('ethtool %s' % (ifc), ns)
        else:
            _, out = self.cmd('ethtool %s' % (ifc))

        speed = re.search('Speed: (\d*)Mb/s', out)

        return int(speed.groups()[0])

    def ethtool_set_speed(self, ifc, speed, fail=True):
        self.ip_link_set_down(ifc, fail=fail)
        return self.cmd('ethtool -s %s speed %d' % (ifc, speed),
                        include_stderr=True, fail=fail)

    def ethtool_set_fec(self, ifc, fec, fail=True):
        return self.cmd('ethtool --set-fec %s encoding %s' %
                        (ifc, fec),
                        include_stderr=True, fail=fail)

    def ethtool_get_fec(self, ifc, fail=True, ns=None):
        if ns:
            return self.netns_cmd('ethtool --show-fec %s' %
                                  (ifc), ns, fail=fail)
        else:
            return self.cmd('ethtool --show-fec %s' %
                            (ifc), fail=fail)

    def ethtool_get_fwdump(self, ifc, level, fail=True):
        self.cmd('ethtool -W %s %d' % (ifc, level), fail=fail)
        self.cmd('ethtool -w %s' % (ifc), fail=fail)

        cmd = ('F=`mktemp -p %s`; '
               'ethtool -w %s data $F && echo -n $F || rm $F' %
               (self.tmpdir, ifc))
        ret, out = self.cmd(cmd, fail=fail)
        if ret != 0:
            return ret, out

        self.mv_from(out, self.grp.tmpdir)
        file_name = os.path.join(self.grp.tmpdir, os.path.basename(out))
        return 0, file_name

    def ethtool_get_module_eeprom(self, ifc, ns=None):
        if ns:
            _, out = self.netns_cmd('ethtool -m %s' % (ifc), ns)
        else:
            _, out = self.cmd('ethtool -m %s' % (ifc))
        return _parse_ethtool(out)

    def ethtool_get_coalesce(self, ifc):
        """
        ethtool -c sample output:
        Coalesce parameters for <netdev>:
        Adaptive RX: off  TX: off
        stats-block-usecs: 0
        sample-interval: 0
        pkt-rate-low: 0

        This output is converted into a dictionary. The adaptive
        parameters are returned in a different method compared to
        the rest of the parameters. Therefore, an extra check
        is required.
        """
        _, out = self.cmd('ethtool -c %s' % (ifc))

        ret = {}

        parameters = out.split('\n')
        for param in parameters:
            vals = param.split(': ')
            k = vals[0].strip()
            if k.startswith('Adaptive'):
                rx = vals[1].split(' ')
                ret['Adaptive RX'] = rx[0]
                ret['Adaptive TX'] = vals[2]
            elif k and not k.startswith('Coalesce parameters for '):
                ret[k] = vals[1]

        return ret

    def ethtool_get_test(self, ifc, fail=True, ns=None):
        """
        ethtool -t sample output:
        The test result is FAIL
        The test extra info:
        Link Test        1
        NSP Test         0
        Firmware Test    0
        Register Test    0

        This output is converted into a dictionary. The
        PASS/FAIL result is stored using the key "result".
        The "outcome" key stores the number of tests that
        return a fail. "1" is considered a FAIL and "0" is
        considered a PASS.
        """
        if ns:
            _, out = self.netns_cmd('ethtool -t %s' % (ifc), ns, fail=fail)
        else:
            _, out = self.cmd('ethtool -t %s' % (ifc), fail=fail)

        ret = {}

        lines = out.split('\n')
        outcome_count = 0
        for line in lines:
            if line.startswith('The test result'):
                result = line.split(' ')
                ret['result'] = result[4].strip()
            elif line and not line.startswith('The test'):
                k = line.split(' ')
                key = k[0].strip()
                ret[key] = int(k[2].strip())
                if k[2].strip() == '1':
                    outcome_count += 1

        ret['outcome'] = outcome_count

        return ret

    ###############################
    # devlink
    ###############################
    def devlink_get_info(self, dev=None):
        ret, out = self.cmd('devlink -jp dev info %s' % (dev if dev else ""))
        if ret == 0:
            if dev:
                out = json.loads(out)["info"][dev]
            else:
                out = json.loads(out)["info"]
        return ret, out
