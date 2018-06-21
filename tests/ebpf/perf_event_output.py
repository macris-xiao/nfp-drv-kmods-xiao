#
# Copyright (C) 2018,  Netronome Systems, Inc.  All rights reserved.
#

import json
import os
import struct
import tempfile
import netro.testinfra
from netro.testinfra.nti_exceptions import NtiError
from netro.testinfra.system import cmd_log
from netro.testinfra.test import *
from ..common_test import *
from defs import *
from maps import MapTest
from xdp import xdp_test_name_to_prog

################################################################################
# Base classes
################################################################################

class PerfEventOutputTest(MapTest):
    def event_data(self):
        """
        Method to be reimplemented by inheriting classes, return event data.
        """
        pass

    def get_src_pkt(self):
        return self.std_pkt()

    def prepare(self):
        res = require_helper(self, BPF_HELPER.PERF_EVENT_OUTPUT, "event output")
        if res:
            return res
        return super(PerfEventOutputTest, self).prepare()

    def start_capture(self, m):
        bpftool_pid = os.path.join(self.dut.tmpdir, 'bpftool%s_pid' % (m["id"]))
        events = os.path.join(self.dut.tmpdir, 'events%s.json' % (m["id"]))

        self.dut.cmd('bpftool -jp map event_pipe id %d > %s 2>/dev/null ' \
                     '& command ; echo $! > %s' %
                     (m["id"], events, bpftool_pid))
        self.dut.background_procs_add(bpftool_pid)

        return events, bpftool_pid

    def send_packets(self, port=0):
        pkt = self.get_src_pkt()
        pcap_src = self.prep_pcap(pkt)

        self.test_with_traffic(pcap_src, pkt,
                               (self.dut, self.dut_ifn[port], self.src))

    def stop_capture(self, events, bpftool_pid):
        self.dut.cmd('PID=$(cat {pid}) && echo $PID && rm {pid} && ' \
                     'kill -INT $PID && ' \
                     'while [ -d /proc/$PID ]; do true; done'
                     .format(pid=bpftool_pid))
        self.dut.background_procs_remove(bpftool_pid)

        self.dut.mv_from(events, self.group.tmpdir)
        return os.path.join(self.group.tmpdir, os.path.basename(events))

    def validate_capture(self, events, event_data):
        LOG_sec('Events from: ' + events)
        cmd_log('cat ' + events)
        LOG_endsec()

        events = json.load(open(events))
        exp_data = [ord(c) for c in event_data]

        exp_num = 100
        found = 0

        assert_ge(100, len(events), 'Number of events')
        LOG_sec('Looking for samples')
        try:
            for e in events:
                assert_equal(9, e["type"], 'Event type')
                if exp_data == e["data"][:len(event_data)] and \
                   len(exp_data) + 8 > len(e["data"]):
                    found += 1
                else:
                    self.log('Bad sample',
                             ':'.join("%02x" % x for x in e["data"])
                             + "\n\n" +
                             ':'.join("%02x" % x for x in exp_data))
        finally:
            LOG_endsec()

        if found < exp_num:
            raise NtiError("Found %d events, was looking for %d" %
                           (found, exp_num))

        LOG_sec("Events OK exp: %d got: %d/%d" % (exp_num, found, len(events)))
        LOG_endsec()

    def execute(self):
        self.xdp_start(xdp_test_name_to_prog(self), mode=self.group.xdp_mode())

        m = self.bpftool_maps_get()[0]

        events, bpftool_pid = self.start_capture(m)
        self.send_packets()
        events = self.stop_capture(events, bpftool_pid)
        self.validate_capture(events, self.event_data())

    def cleanup(self):
        self.dut.background_procs_cleanup()

        super(PerfEventOutputTest, self).cleanup()

class PerfEventOutputMapValueTest(PerfEventOutputTest):
    def execute(self):
        self.xdp_start(xdp_test_name_to_prog(self), mode=self.group.xdp_mode())

        maps = self.bpftool_maps_get()
        pa  = maps[0] if maps[0]["type"] == "perf_event_array" else maps[1]
        arr = maps[0] if maps[0]["type"] == "array" else maps[1]

        self.dut.bpftool("map update id %d key 0 0 0 0 value 4 3 2 1 1 1 1 1" %
                         (arr["id"]))

        events, bpftool_pid = self.start_capture(pa)
        self.send_packets()
        events = self.stop_capture(events, bpftool_pid)
        self.validate_capture(events, self.event_data())

class PerfEventOutputTwoTest(PerfEventOutputTest):
    def execute(self):
        self.xdp_start(xdp_test_name_to_prog(self), mode=self.group.xdp_mode())

        m = self.bpftool_maps_get()[0]

        events, bpftool_pid = self.start_capture(m)
        self.send_packets()
        events = self.stop_capture(events, bpftool_pid)
        event_data = self.event_data()
        self.validate_capture(events, event_data[0])
        self.validate_capture(events, event_data[1])

class PerfEventOutputDualTest(PerfEventOutputTest):
    def execute(self):
        self.xdp_start(xdp_test_name_to_prog(self), mode=self.group.xdp_mode())

        maps = self.bpftool_maps_get()
        pa1 = maps[0] if maps[0]["max_entries"] == 64 else maps[1]
        pa2 = maps[0] if maps[0]["max_entries"] == 65 else maps[1]

        events1, bpftool_pid1 = self.start_capture(pa1)
        events2, bpftool_pid2 = self.start_capture(pa2)
        self.send_packets()
        events1 = self.stop_capture(events1, bpftool_pid1)
        events2 = self.stop_capture(events2, bpftool_pid2)
        event_data = self.event_data()
        self.validate_capture(events1, event_data[0])
        self.validate_capture(events2, event_data[1])

class PerfEventOutput2BigTest(PerfEventOutputTest):
    def execute(self):
        self.xdp_start(xdp_test_name_to_prog(self), mode=self.group.xdp_mode())

        m = self.bpftool_maps_get()[0]

        events, bpftool_pid = self.start_capture(m)
        self.send_packets()
        events = self.stop_capture(events, bpftool_pid)
        if self.group.xdp_mode() == "drv":
            self.validate_capture(events, self.event_data())
        else:
            assert_lt(50, len(events), "Number of captured events")

################################################################################
# Actual test classes
################################################################################

stack_data = '\x00\x00\x00\x00\x00\x00\x00\x00xV4\x12\x00\x00\x00\x00' \
            '\x01\x00\x00\x00\x00\x00\x00\x00\x07\x00\x00\x00\x00\x00' \
            '\x00\x00'
stack_data2 = '\xdd\xcc\xbb\xaa\x00\x00\x00\x003"\x11\x00\xff\xee\x00' \
            '\x00\x0f\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x07' \
            '\x00\x00\x00'

class PerfEventOutputPktTest(PerfEventOutputTest):
    def event_data(self):
        return self.std_pkt()[:32]

class PerfEventOutputStackTest(PerfEventOutputTest):
    def event_data(self):
        return stack_data

class PerfEventOutputMapTest(PerfEventOutputMapValueTest):
    def event_data(self):
        return '\x03\x02'

class PerfEventOutputBothTest(PerfEventOutputTest):
    def event_data(self):
        return stack_data + self.std_pkt()[:32]

class PerfEventOutputOnesTest(PerfEventOutputTest):
    def get_src_pkt(self):
        return '\xff' + self.std_pkt()[1:]

    def event_data(self):
        return '\x04\xff'

class PerfEventOutputDynTest(PerfEventOutputTest):
    def event_data(self):
        return self.std_pkt()

class PerfEventOutputTwiceTest(PerfEventOutputTwoTest):
    def event_data(self):
        pkt = self.std_pkt()
        res = [None] * 2
        res[0] = stack_data + pkt[:32]
        res[1] = stack_data2 + pkt[:50]
        return res

class PerfEventOutputDoubleTest(PerfEventOutputDualTest):
    def event_data(self):
        pkt = self.std_pkt()
        res = [None] * 2
        res[0] = stack_data + pkt[:32]
        res[1] = stack_data2 + pkt[:50]
        return res

class PerfEventOutputOversizeTest(PerfEventOutput2BigTest):
    def get_src_pkt(self):
        return self.std_pkt(size=1400)

    def event_data(self):
        return '\x00' * (8 * 32) + self.get_src_pkt()
