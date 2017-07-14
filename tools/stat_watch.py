#!/usr/bin/python

# Copyright (C) 2017 Netronome Systems, Inc.
#
# This software is dual licensed under the GNU General License Version 2,
# June 1991 as shown in the file COPYING in the top-level directory of this
# source tree or the BSD 2-Clause License provided below.  You have the
# option to license this software under the complete terms of either license.
#
# The BSD 2-Clause License:
#
#     Redistribution and use in source and binary forms, with or
#     without modification, are permitted provided that the following
#     conditions are met:
#
#      1. Redistributions of source code must retain the above
#         copyright notice, this list of conditions and the following
#         disclaimer.
#
#      2. Redistributions in binary form must reproduce the above
#         copyright notice, this list of conditions and the following
#         disclaimer in the documentation and/or other materials
#         provided with the distribution.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
# EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
# MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
# NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS
# BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN
# ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
# CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.

import os
import subprocess
import signal
import sys
import time
import re

ONLY_ETHTOOL = False
COLORS=[]
COLOR_DIM = False
IFC=""
INCL=[]
EXCL=[]

def intr(signal, frame):
        print(' Exiting...')
        sys.exit(0)
signal.signal(signal.SIGINT, intr)


def now():
        return int(time.time() * 1000)

def usage():
        print "Usage: %s [-E] [-c] [-crx] [-ctx] [-f pattern] [-x pattern] IFC" % \
                sys.argv[0]
        print "\tSources"
        print "\t\t-E show only ethtool -S stats (exclude ifconfig statistics)"
        print "\tColors"
        print "\t\t-crx color RX stats"
        print "\t\t-ctx color TX stats"
        print "\t\t-cerr color error stats"
        print "\t\t-cdisc color discard stats"
        print "\t\t-cd dim idle stats"
        print "\t\t-c enable all colors"
        print "\tFilters"
        print "\t\t-f <pattern> include only stats that match the pattern"
        print "\t\t-x <pattern> exclude stats which match the pattern"
        print "\t\texclude takes precedence, both can be repeated"
        print ""
        print "\tOrder of parameters doesn't matter."
        sys.exit(1)


skip=0
for i in range(1, len(sys.argv)):
        if skip:
                skip -= 1
                continue

        if sys.argv[i] == '-E':
                ONLY_ETHTOOL = True
        elif sys.argv[i] == '-c':
                COLOR_DIM = True
                COLORS.append(('discard', "33m"))
                COLORS.append(('drop', "33m"))
                COLORS.append(('error', "31m"))
                COLORS.append(('illegal', "31m"))
                COLORS.append(('fault', "31m"))
                COLORS.append(('rx', "32m"))
                COLORS.append(('tx', "36m"))
        elif sys.argv[i] == '-ctx':
                COLORS.append(('tx', "36m"))
        elif sys.argv[i] == '-crx':
                COLORS.append(('rx', "32m"))
        elif sys.argv[i] == '-cerr':
                COLORS.append(('error', "31m"))
                COLORS.append(('illegal', "31m"))
                COLORS.append(('fault', "31m"))
        elif sys.argv[i] == '-cdisc':
                COLORS.append(('discard', "33m"))
                COLORS.append(('drop', "33m"))
        elif sys.argv[i] == '-cd':
                COLOR_DIM = True
        elif sys.argv[i] == '-f':
                INCL.append(re.compile(sys.argv[i + 1]))
                skip += 1
        elif sys.argv[i] == '-x':
                EXCL.append(re.compile(sys.argv[i + 1]))
                skip += 1
        elif IFC == '':
                IFC = sys.argv[i]
        else:
                print('What is %s?' % sys.argv[i])
                usage()

if IFC == '':
        usage()

stats = {}
session = {}

def key_ok(key):
        if len(INCL) == 0 and len(EXCL) == 0:
                return True
        res = len(INCL) == 0
        for p in INCL:
                res = p.search(key) or res
        for p in EXCL:
                res = not p.search(key) and res

        return res

sysfs_stats_path = os.path.join('/sys/class/net/', IFC, 'statistics')

def get_sysfs_stats():
        out = ''

        for filename in reversed(os.listdir(sysfs_stats_path)):
                filepath = os.path.join(sysfs_stats_path, filename)
                data = ''
                with open(filepath, 'r') as filedata:
                        data += filedata.read()
                out += '%s:%s' % (filename, data)

        return out

while True:
        clock = now()

        try:
                out = ''

                if not ONLY_ETHTOOL:
                       out += get_sysfs_stats()

                out += subprocess.check_output(['ethtool', '-S', IFC])
        except:
                os.system("clear")
                print "Reading stats from device \033[1m%s\033[0m failed" % IFC
                stats = {}
                session = {}
                time.sleep(0.5)
                continue

        pr = "\033[4;1mSTAT % 35s % 19s % 19s\033[0m\n" % \
             ("RATE", "SESSION", "TOTAL")
        for l in out.split('\n'):
                s = l.split(':')
                if len(s) != 2 or s[1] == '':
                        continue
                key = s[0].strip()
                value = int(s[1].strip())

                if not key_ok(key):
                        continue

                if not key in stats:
                        stats[key] = value
                        session[key] = value
                        continue

                if value != 0:
                        color = "37m"
                        for (needle, c) in COLORS:
                                if key.find(needle) != -1:
                                        color = c
                                        break

                        if not value - stats[key] and COLOR_DIM:
                                color = '2;' + color
                        color = '\033[' + color

                        pr += '{:}{:<26} {:>13,} {:>19,} {:>19,}\033[31;0m\n'.\
                              format(color, key, value - stats[key],
                                     value - session[key], value)

                stats[key] = value

        os.system("clear")
        sys.stdout.write(pr)

        time.sleep(max(0, 1.0 - (now() - clock) / 1000.0))
