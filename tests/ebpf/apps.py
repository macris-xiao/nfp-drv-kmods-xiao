#
# Copyright (C) 2018,  Netronome Systems, Inc.  All rights reserved.
#

import netro.testinfra
from netro.testinfra.nti_exceptions import NtiError
from netro.testinfra.system import cmd_log
from netro.testinfra.test import *
from scapy.all import TCP, IP
from ..common_test import *
from maps import MapTest
from ..linux_system import int2str, str2int

class LoadBalancer(MapTest):
    def fill_l4lb(self, mapid):
            cmd = ""
            for i in range (0, 512):
                s_addr = "127 0 0 1"
                d_addr = "127 0 0 %d" % (i & 255)

                cmd += "map update id %d key %s value %s %s %s %s %s\n" % \
                         (mapid["id"], int2str("I", i), s_addr, d_addr,
                          int2str("Q", 0), int2str("Q", 0), int2str("Q", i))
            self.bpftool_batch(cmd)

    def execute(self):
        self.xdp_start("app_l4lb.o", mode=self.group.xdp_mode())

        m = self.bpftool_maps_get()[0]
        self.fill_l4lb(m)
        self.bpftool_map_dump(m)

        ifn = self.src_ifn[0]
        cmd = self.hping3_cmd(port=0, size=0, count=1024, speed="faster",
                              keep=False)
        cmd += '|| true'
        result_pkts = self.tcpdump_cmd(self.src, ifn, self.src, cmd)

        l4lb_pkts = 0
        for p in result_pkts:
            if p.haslayer(IP) and p.haslayer(TCP):
                    if p[IP].proto != 4:
                        raise NtiError('Proto: %d expecting: 4' % p[IP].proto)
                    if p[IP].len != 60:
                        raise NtiError('TotLen: %d expecting: 60' % p[IP].len)
                    l4lb_pkts += 1

        if l4lb_pkts != 1024:
            raise NtiError('Got TCP packets: %d expecting: 1024' % l4lb_pkts)

        map_cnt = 0
        keys_used = 0

        elems = self.bpftool_map_dump(m)
        for e in elems:
            val = str2int(e["value"][16:24])
            if val > 0:
                keys_used += 1
            map_cnt += val

        if map_cnt != 1024:
            raise NtiError('Map total: %d expecting: 1024' % map_cnt)

        if keys_used < 256: # Ensure load balancer delivers > 50% distribution
            raise NtiError('Key distribution: %d expecting: > 256' % keys_used)
