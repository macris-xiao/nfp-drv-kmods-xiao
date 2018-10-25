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

class PacketRead(MapTest):
    def mac_to_int_str(self, mac_hex):
            mac = [str(int(byte, 16)) for byte in mac_hex.split(':')]
            return ("%s %s %s %s %s %s" %
                    (mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]))

    def fill_ethmap(self, mapid):
            smac = self.mac_to_int_str(self.group.hwaddr_a[0])
            dmac = self.mac_to_int_str(self.group.hwaddr_x[0])

            cmd = "map update id %d key %s value %s %s 8 00\n" % \
                   (mapid["id"], int2str("I", 0), dmac, smac)
            self.bpftool_batch(cmd)

    def fill_ipmap(self, mapid, total_len=64, ip_id=5, ttl=64):
            version_len_tos = "00 00"
            flag_frag = "00 00"
            ip_csum = "00 00"

            saddr = (self.group.addr_a[0][:-3].replace(".", " "))
            daddr = (self.group.addr_x[0][:-3].replace(".", " "))
            ip_totlen = total_len - 20
            proto = "06"

            cmd = "map update id %d key %s value %s %s %s %s %s %s %s %s %s\n" % \
                   (mapid["id"], int2str("I", 0),
                    version_len_tos, int2str(">h", ip_totlen),
                    int2str(">h", ip_id), flag_frag, ttl, proto,
                    ip_csum, saddr, daddr)
            self.bpftool_batch(cmd)

    def fill_tcpmap(self, mapid, sport=1, dport=2, seq=3, ack=4, flags=0, win=0):
            offset = "80"
            csum = "00 00"
            urg = "00 00"

            cmd = "map update id %d key %s value %s %s %s %s %s %d %s %s %s\n" % \
                   (mapid["id"], int2str("I", 0),
                    int2str(">h", sport), int2str(">h", dport),
                    int2str(">I", seq), int2str(">I",ack),
                    offset, flags, int2str(">h", win), csum, urg)
            self.bpftool_batch(cmd)

    def send_packets(self, count=5, psize=64, ip_id=5, ttl=64, sport=1, dport=2,
                     seq=3, ack=4, win=0):
        cmd = self.hping3_cmd(port=0, count=count, size=psize - 60, ip_id=ip_id,
                              ttl=ttl, sport=sport, dport=dport, seq=seq,
                              ack=ack, win=win, speed="faster")
        cmd += ' || true'
        result_pkts = self.tcpdump_cmd(self.src, self.src_ifn[0], self.src, cmd)

        pkts_recv = 0
        for p in result_pkts:
            if p.haslayer(IP) and p.haslayer(TCP):
                    pkts_recv += 1
        return pkts_recv

class PacketReadFail(PacketRead):
    def execute(self):
        self.xdp_start("app_packet_read.o", mode=self.group.xdp_mode())
        m = self.bpftool_maps_get()
        self.fill_ethmap(m[0])
        self.fill_ipmap(m[1])
        self.fill_tcpmap(m[2])

        pkts = self.send_packets(dport=1337) # send incorrect pkt
        if pkts != 0:
            raise NtiError('Got TCP packets: %d expecting: 0' % pkts)

class PacketReadPass(PacketRead):
    def execute(self):
        self.xdp_start("app_packet_read.o", mode=self.group.xdp_mode())
        m = self.bpftool_maps_get()
        self.fill_ethmap(m[0])

        for size in range(500, 1501, 500):
            for i in range(0, 1024, 256):
                    ip_id = i *    5 + size
                    sport = i *   14 + size
                    dport = i *   28 + size
                    win   = i *   37 + size
                    seq   = i *  728 + size
                    ack   = i * 1999 + size

                    self.fill_ipmap(m[1], total_len=size, ip_id=ip_id)
                    self.fill_tcpmap(m[2], sport=sport, dport=dport, seq=seq,
                                     ack=ack, win=win)

                    perf, pid = self.dut.bpftool_map_perf_capture_start(m=m[3])

                    pkts = self.send_packets(psize=size, count=5, ip_id=ip_id,
                                             sport=sport, dport=dport,
                                             seq=seq, ack=ack, win=win)

                    map_dump = self.dut.bpftool_map_perf_capture_stop(perf, pid)
                    cmd_log('cat ' + map_dump)

                    event_cnt = len(json.load(open(map_dump)))
                    if event_cnt > 0:
                        raise NtiError('Perf events: %d expecting: 0' % event_cnt)

                    if pkts != 5:
                        raise NtiError('TCP packets: %d expecting: 5' % pkts)
