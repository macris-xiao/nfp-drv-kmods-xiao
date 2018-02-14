#
# Copyright (C) 2017,  Netronome Systems, Inc.  All rights reserved.
#

import os
import struct
import tempfile
import netro.testinfra
from netro.testinfra.nti_exceptions import NtiError
from netro.testinfra.test import *
from ..common_test import *

class XDP_ACTION:
    ABORTED	= 0
    DROP	= 1
    PASS	= 2
    TX		= 3
    REDIRECT	= 4

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
# Base classes
################################################################################

class MapTest(CommonTest):
    def prepare(self):
        if not self.dut.bpf_caps["maps"]["present"]:
            return NrtResult(name=self.name, testtype=self.__class__.__name__,
                             passed=None, comment="no FW map cap")

    def bpftool_maps_get(self, port=0):
        links = self.dut.ip_link_show(ifc=self.dut_ifn[port])
        _, prog = self.dut.bpftool_prog_show(links[0]["xdp"]["prog"]["id"])
        _, maps = self.dut.bpftool_map_list()

        res = []
        for m in maps:
            if m["id"] in prog["map_ids"]:
                res.append(m)
        return res

    def bpftool_map_dump(self, m):
        _, elems = self.dut.bpftool("map dump id %d" % (m["id"]))
        return elems

    def bpftool_map_del(self, m, key, fail=True):
        cmd = 'map delete id %d key %s' % (m["id"], int2str("I", key))
        return self.dut.bpftool(cmd, fail=fail)

    def bpftool_batch(self, cmds):
        fd, bf = tempfile.mkstemp(dir=self.group.tmpdir, text=True)
        f = os.fdopen(fd, 'w')
        f.write(cmds)
        f.close()
        fn = os.path.basename(bf)
        try:
            LOG_sec("BPFTOOL batch %s" % (fn))
            LOG(cmds)
            self.dut.mv_to(bf, self.dut.tmpdir)
            self.dut.bpftool('batch file %s' %
                             (os.path.join(self.dut.tmpdir, fn)))
        finally:
            LOG_endsec()

    def map_fill_simple(self, m, mul=3):
        batch = ""
        sw_map = {}
        for i in range(0, m["max_entries"]):
            batch += "map update id %d key %s value %s\n" % \
                     (m["id"], int2str("I", i), int2str("Q", i * mul))
            sw_map[i] = i * mul
        self.bpftool_batch(batch)
        return sw_map

    def map_validate(self, m, sw_map):
        elems = self.bpftool_map_dump(m)
        if len(elems) != len(sw_map):
            raise NtiError("Bad elem cnt %d != %d" % (len(sw_map), len(elems)))

        for e in elems:
            idx = str2int(e["key"])
            val = str2int(e["value"])
            if sw_map[idx] != val:
                raise NtiError("Bad value %s != %d" % (sw_map[idx], val))

    def map_validate_empty(self, m):
        elems = self.bpftool_map_dump(m)

        for e in elems:
            for byte in e["value"]:
                assert_equal("0x00", byte, "Initial array value")

    def map_clear(self, m):
        batch = ""
        elems = self.bpftool_map_dump(m)
        for e in elems:
            batch += "map delete id %d key %s\n" % (m["id"], " ".join(e["key"]))
        self.bpftool_batch(batch)


class XDPlookup(MapTest):
    def get_prog_name(self):
        """
        Return the name of XDP program to load for the test.
        Program should use single map and do one look up in it.
        """
        pass

    def execute(self):
        self.xdp_start(self.get_prog_name(), mode=self.group.xdp_mode())

        m = self.bpftool_maps_get()[0]

        pkt = self.std_pkt()
        key = bytearray(pkt[14])[0]
        pcap_src = self.prep_pcap(pkt)

        self.test_with_traffic(pcap_src, None,
                               (self.dut, self.dut_ifn[0], self.src))

        # Add to a different key
        self.dut.bpftool("map update id %d key %s value %s" %
                         (m["id"], int2str("I", key + 1),
                          int2str("Q", XDP_ACTION.PASS)))
        self.dut.bpftool("map update id %d key %s value %s" %
                         (m["id"], int2str("I", key - 1),
                          int2str("Q", XDP_ACTION.PASS)))

        self.test_with_traffic(pcap_src, None,
                               (self.dut, self.dut_ifn[0], self.src))

        # Add to a correct key, PASS
        self.dut.bpftool("map update id %d key %s value %s" %
                         (m["id"], int2str("I", key),
                          int2str("Q", XDP_ACTION.PASS)))

        self.test_with_traffic(pcap_src, pkt,
                               (self.dut, self.dut_ifn[0], self.src))

        # Add to a correct key, DROP
        self.dut.bpftool("map update id %d key %s value %s" %
                         (m["id"], int2str("I", key),
                          int2str("Q", XDP_ACTION.DROP)))

        self.test_with_traffic(pcap_src, None,
                               (self.dut, self.dut_ifn[0], self.src))

    def cleanup(self):
        self.xdp_stop(mode=self.group.xdp_mode())


class XDPlookupTwice(MapTest):
    def get_prog_name(self):
        """
        Return the name of XDP program to load for the test.
        Program should use two maps and do look ups in both.
        """
        pass

    def execute(self):
        self.xdp_start(self.get_prog_name(), mode=self.group.xdp_mode())

        maps = self.bpftool_maps_get()

        pkt = self.std_pkt()
        keys = bytearray(pkt[14:16])
        pcap_src = self.prep_pcap(pkt)

        # if the key bytes are identical we should tell the user this test
        # will have more limited coverage
        if keys[0] == keys[1]:
            raise NtiSkip("packet bytes are identical")

        self.test_with_traffic(pcap_src, None,
                               (self.dut, self.dut_ifn[0], self.src))

        # Add to a correct key, 2xPASS
        self.dut.bpftool("map update id %d key %s value %s" %
                         (maps[0]["id"], int2str("I", keys[0]),
                          int2str("Q", XDP_ACTION.PASS)))
        self.dut.bpftool("map update id %d key %s value %s" %
                         (maps[1]["id"], int2str("I", keys[1]),
                          int2str("Q", XDP_ACTION.PASS)))

        self.test_with_traffic(pcap_src, pkt,
                               (self.dut, self.dut_ifn[0], self.src))

        # Add to a correct key, PASS+DROP
        self.dut.bpftool("map update id %d key %s value %s" %
                         (maps[0]["id"], int2str("I", keys[0]),
                          int2str("Q", XDP_ACTION.DROP)))
        self.dut.bpftool("map update id %d key %s value %s" %
                         (maps[1]["id"], int2str("I", keys[1]),
                          int2str("Q", XDP_ACTION.PASS)))

        self.test_with_traffic(pcap_src, None,
                               (self.dut, self.dut_ifn[0], self.src))

        # Add to a correct key, DROP+PASS
        self.dut.bpftool("map update id %d key %s value %s" %
                         (maps[0]["id"], int2str("I", keys[0]),
                          int2str("Q", XDP_ACTION.PASS)))
        self.dut.bpftool("map update id %d key %s value %s" %
                         (maps[1]["id"], int2str("I", keys[1]),
                          int2str("Q", XDP_ACTION.DROP)))

        self.test_with_traffic(pcap_src, None,
                               (self.dut, self.dut_ifn[0], self.src))

    def cleanup(self):
        self.xdp_stop(mode=self.group.xdp_mode())


class XDPupdate2lookup(MapTest):
    def get_prog_name(self):
        """
        Return the name of XDP program to load for the test.
        Program should perform map update intermediately followed by lookup.
        """
        pass

    def execute(self):
        self.xdp_start(self.get_prog_name(), mode=self.group.xdp_mode())

        m = self.bpftool_maps_get()[0]

        pkt = self.std_pkt()
        pkts = []
        for i in range(100):
            pkt = pkt[:14] + chr(i) + '\x00\x00\x00' + pkt[18:]
            pkts.append(Ether(pkt))
        pcap_src = self.prep_pcap(pkts)

        self.test_with_traffic(pcap_src, pkt[:14] + '\x00' * 4 + pkt[18:],
                               (self.dut, self.dut_ifn[0], self.src))

        elems = self.bpftool_map_dump(m)
        if len(elems) != 100:
            raise NtiError("Expected 100 entries in the map after test")

        for e in elems:
            idx = str2int(e["key"])
            val = str2int(e["value"])
            assert_equal(str2int(e["key"]), str2int(e["value"]),
                         "Key and value are equal")

    def cleanup(self):
        self.xdp_stop(mode=self.group.xdp_mode())


class XDPupdateFlagsAndDelete(MapTest):
    def get_prog_name(self):
        """
        Return the name of XDP program to load for the test.
        Program should perform map updates followed by delete.
        """
        pass

    def execute(self):
        self.xdp_start(self.get_prog_name(), mode=self.group.xdp_mode())

        m = self.bpftool_maps_get()[0]

        pkt = self.std_pkt()
        pcap_src = self.prep_pcap_simple_seq(pkt)

        self.test_with_traffic(pcap_src, pkt[:14] + '\x00' * 4 + pkt[18:],
                               (self.dut, self.dut_ifn[0], self.src))

        elems = self.bpftool_map_dump(m)
        if m["type"] == "array":
            exp_cnt = 100
        else:
            exp_cnt = 0

        assert_equal(exp_cnt, len(elems),
                     "Expected %d entries in the map after test")

        for e in elems:
            idx = str2int(e["key"])
            val = str2int(e["value"])
            assert_equal(str2int(e["key"]), str2int(e["value"]),
                         "Key and value are equal")

    def cleanup(self):
        self.xdp_stop(mode=self.group.xdp_mode())

################################################################################
# Actual test classes - control path
################################################################################

class XDPmapStress(MapTest):
    def execute(self):
        self.dut.bpftool("prog")

        stress_prog = os.path.join(self.dut.c_samples_dir, "map_stress")
        ret, _ = self.dut.cmd('ls %s' % (stress_prog), fail=False)
        if ret != 0:
            raise NtiSkip("no map_stress sample")

        self.xdp_start('map_htab1k_array1k.o', mode=self.group.xdp_mode())

        maps = self.bpftool_maps_get()

        self.log("Maps", maps)

        if maps[0]["type"] == "array":
            array = maps[0]
            htab = maps[1]
        else:
            array = maps[1]
            htab = maps[0]

        n_threads = 16
        n_rep = 2000

        # Run the stress program
        self.dut.cmd("%s %d %d %d %d" % (stress_prog, array["id"],
                                         n_threads, n_rep, 1100))
        self.dut.cmd("%s %d %d %d %d" % (stress_prog, htab["id"],
                                         n_threads, n_rep, 1 << 20))

        # Dump for logs
        self.bpftool_map_dump(array)
        self.bpftool_map_dump(htab)

        # Clean the htab and see if it's empty
        self.map_clear(htab)

        elems = self.bpftool_map_dump(htab)
        if len(elems):
            raise NtiError("hash tab has %d elems after clear" % (len(elems)))

        # Check if we can fill the maps and values are correct
        htab_sw = self.map_fill_simple(htab)
        array_sw = self.map_fill_simple(array)

        self.map_validate(htab, htab_sw)
        self.map_validate(array, array_sw)

        # Check too many entries
        ret, _ = self.dut.bpftool("map update id %d key %s value %s" %
                                  (htab["id"],
                                   int2str("I", htab["max_entries"] * 2),
                                   int2str("Q", 1)), fail=False)
        if ret == 0:
            raise NtiError("table overflow allowed!")

    def cleanup(self):
        self.xdp_stop(mode=self.group.xdp_mode())


class XDPmapLimits(MapTest):
    def execute(self):
        _, maps = self.dut.bpftool_map_list()
        self.n_start_maps = len(maps)

        mode = self.group.xdp_mode()
        should_fail = mode == "offload"

        # Basic element geometry
        self.xdp_start('map_bad_key.o', mode=mode, should_fail=should_fail)
        self.xdp_start('map_bad_value.o', mode=mode, should_fail=should_fail)
        self.xdp_start('map_bad_elem.o', mode=mode, should_fail=should_fail)
        self.xdp_start('map_bad_key_array.o', mode=mode, should_fail=True)
        self.xdp_start('map_bad_flags.o', mode=mode, should_fail=should_fail)
        self.xdp_start('map_bad_numa.o', mode=mode, should_fail=should_fail)

        # Too many ...
        map_elems = 1 << 18
        cap = self.dut.bpf_caps["maps"]

        self.dut.cmd("mkdir -p /sys/fs/bpf/nfp/")

        # Too many elements for FW to handle
        LOG_sec("Too many elements")
        try:
            for i in range(0, cap["max_elems"] / map_elems):
                self.xdp_start('map_htab256k.o', mode=mode)
                link = self.dut.ip_link_show(port=0)
                # Keep the program around so it won't get unloaded
                prog_id = link[0]["xdp"]["prog"]["id"]
                self.dut.bpftool("prog pin id %d /sys/fs/bpf/nfp/%d" %
                                 (prog_id, prog_id))

            self.xdp_stop(mode=mode)
            self.xdp_start('map_htab256k.o',
                           mode=mode, should_fail=should_fail)
            self.xdp_stop(mode=mode)

            self.dut.cmd("rm -f /sys/fs/bpf/nfp/*")
        finally:
            LOG_endsec()

        self.dut.bpf_wait_maps_clear(expected=self.n_start_maps)

        # Too many maps for FW to handle
        LOG_sec("Too many maps")
        try:
            for i in range(0, cap["max_maps"] / 16):
                self.xdp_start('map_htab2x16.o', mode=mode)
                link = self.dut.ip_link_show(port=0)
                # Keep the program around so it won't get unloaded
                prog_id = link[0]["xdp"]["prog"]["id"]
                self.dut.bpftool("prog pin id %d /sys/fs/bpf/nfp/%d" %
                                 (prog_id, prog_id))

            self.xdp_stop(mode=mode)
            self.xdp_start('map_array1.o',
                           mode=mode, should_fail=should_fail)
            self.xdp_stop(mode=mode)

            self.dut.cmd("rm -f /sys/fs/bpf/nfp/*")
        finally:
            LOG_endsec()

        self.dut.bpf_wait_maps_clear(expected=self.n_start_maps)

    def cleanup(self):
        self.xdp_stop(mode=self.group.xdp_mode())
        self.dut.cmd("rm -rf /sys/fs/bpf/nfp/")
        self.dut.bpf_wait_maps_clear(expected=self.n_start_maps)


class XDPhtabCtrl(MapTest):
    def execute(self):
        self.xdp_start('map_htab256.o', mode=self.group.xdp_mode())

        m = self.bpftool_maps_get()[0]

        # Dump empty
        _, elems = self.dut.bpftool("map dump id %d" % (m["id"]))
        if len(elems):
            raise NtiError("Map is not empty")

        # Check get next on empty
        ret, elem = self.dut.bpftool("map getnext id %d" % (m["id"]),
                                     fail=False)
        if ret == 0:
            raise NtiError("getnext is OK on empty map")

        # Populate all entries
        self.map_fill_simple(m)

        # Check too many entries
        ret, _ = self.dut.bpftool("map update id %d key %s value %s" %
                                  (m["id"],
                                   int2str("I", m["max_entries"] * 2),
                                   int2str("Q", 1)), fail=False)
        if ret == 0:
            raise NtiError("table overflow allowed!")

        # Dump full
        _, elems = self.dut.bpftool("map dump id %d" % (m["id"]))
        if len(elems) != 256:
            raise NtiError("Bad elem cnt %d != %d" % (len(elems), 256))

        for e in elems:
            idx = str2int(e["key"])
            val = str2int(e["value"])
            if idx * 3 != val:
                raise NtiError("Bad value key: %d value: %d" % (idx, val))

        # Remove one from the middle
        idx = str2int(elems[128]["key"])
        self.bpftool_map_del(m, idx)

        deleted_idx = idx

        # Remove non-existing
        ret, _ = self.bpftool_map_del(m, idx, fail=False)
        if ret == 0:
            raise NtiError("deleted element twice")

        ret, _ = self.bpftool_map_del(m, 1024, fail=False)
        if ret == 0:
            raise NtiError("deleted element which was never added")

        # Dump again, see if chain is not broken
        _, elems = self.dut.bpftool("map dump id %d" % (m["id"]))
        if len(elems) != 255:
            raise NtiError("Bad elem cnt %d != %d" % (len(elems), 255))

        for e in elems:
            idx = str2int(e["key"])
            val = str2int(e["value"])
            if idx * 3 != val:
                raise NtiError("Bad value key: %d value: %d" % (idx, val))
            if idx == deleted_idx:
                raise NtiError("Index %d was deleted!" % (deleted_idx))

        # Test flags - bad
        ret, _ = self.dut.bpftool("map update id %d key %s value %s exist" %
                                  (m["id"], int2str("I", deleted_idx),
                                   int2str("Q", deleted_idx * 3)), fail=False)
        if ret == 0:
            raise NtiError("Flag 'exist' test failed")

        readd_idx = str2int(elems[0]["key"])
        ret, _ = self.dut.bpftool("map update id %d key %s value %s noexist" %
                                  (m["id"], int2str("I", readd_idx),
                                   int2str("Q", readd_idx * 3)), fail=False)
        if ret == 0:
            raise NtiError("Flag 'noexist' test failed")

        # Test flags - good
        self.dut.bpftool("map update id %d key %s value %s exist" %
                         (m["id"], int2str("I", readd_idx),
                          int2str("Q", readd_idx * 4)))

        self.dut.bpftool("map update id %d key %s value %s noexist" %
                         (m["id"], int2str("I", deleted_idx),
                          int2str("Q", deleted_idx * 4)))

        # And dump once more...
        _, elems = self.dut.bpftool("map dump id %d" % (m["id"]))
        if len(elems) != 256:
            raise NtiError("Bad elem cnt %d != %d" % (len(elems), 256))

        for e in elems:
            idx = str2int(e["key"])
            val = str2int(e["value"])
            mul = 3
            if idx == deleted_idx or idx == readd_idx:
                mul = 4
            if idx * mul != val:
                raise NtiError("Bad value key: %d value: %d" % (idx, val))

    def cleanup(self):
        self.xdp_stop(mode=self.group.xdp_mode())


class XDParrayCtrl(MapTest):
    def array_check_getnext(self, m, max_idx):
        _, elem = self.dut.bpftool("map getnext id %d" % (m["id"]))
        idx = str2int(elem["next_key"])
        if idx != 0:
            raise NtiError("getnext NULL returned idx %d, expected 0" % (idx))

        _, elem = self.dut.bpftool("map getnext id %d key %s" %
                                   (m["id"], int2str("I", max_idx + 1)))
        idx = str2int(elem["next_key"])
        if idx != 0:
            raise NtiError("getnext max+1 returned idx %d, expected 0" % (idx))

        ret, elem = self.dut.bpftool("map getnext id %d key %s" %
                                     (m["id"], int2str("I", max_idx)),
                                     fail=False)
        if ret == 0:
            raise NtiError("getnext is OK on last elem")
        if elem["error"].find("No such file") == -1:
            raise NtiError("array delete did not say ENOENT")

    def execute(self):
        self.xdp_start('map_array256.o', mode=self.group.xdp_mode())

        m = self.bpftool_maps_get()[0]
        max_idx = m["max_entries"] - 1

        # Validate pre-allocation
        sw_m = { key: 0 for key in range(0, m["max_entries"]) }
        self.map_validate(m, sw_m)

        # Check we can't delete
        ret, elem = self.bpftool_map_del(m, 0, fail=False)
        if ret == 0:
            raise NtiError("Delete allowed on array map")
        if elem["error"].find("Invalid argument") == -1:
            raise NtiError("array delete did not say EINVAL")

        # Check get next
        self.array_check_getnext(m, max_idx)

        # Populate all entries
        sw_m = self.map_fill_simple(m)
        self.map_validate(m, sw_m)

        # Check too many entries
        ret, _ = self.dut.bpftool("map update id %d key %s value %s" %
                                  (m["id"],
                                   int2str("I", max_idx * 2),
                                   int2str("Q", 1)), fail=False)
        if ret == 0:
            raise NtiError("array overflow allowed!")

        ret, _ = self.dut.bpftool("map update id %d key %s value %s" %
                                  (m["id"],
                                   int2str("I", max_idx + 1),
                                   int2str("Q", 1)), fail=False)
        if ret == 0:
            raise NtiError("array overflow allowed!")

        # Test flags - bad
        ret, _ = self.dut.bpftool("map update id %d key %s value %s noexist" %
                                  (m["id"], int2str("I", 0),
                                   int2str("Q", 0)), fail=False)
        if ret == 0:
            raise NtiError("Flag 'noexist' test failed")

        ret, _ = self.dut.bpftool("map update id %d key %s value %s noexist" %
                                  (m["id"], int2str("I", max_idx),
                                   int2str("Q", 0)), fail=False)
        if ret == 0:
            raise NtiError("Flag 'noexist' test failed")

        # Test flags - good
        self.dut.bpftool("map update id %d key %s value %s exist" %
                         (m["id"], int2str("I", 0),
                          int2str("Q", 0)))
        sw_m[max_idx] = 0

        self.dut.bpftool("map update id %d key %s value %s exist" %
                         (m["id"], int2str("I", max_idx),
                          int2str("Q", max_idx * 3)))
        sw_m[max_idx] = max_idx * 3

        # And dump once more...
        self.map_validate(m, sw_m)

    def cleanup(self):
        self.xdp_stop(mode=self.group.xdp_mode())

class XDParrayInitialise(MapTest):
    def execute(self):
        self.xdp_start('map_array_256_varying_val_size.o',
                       mode=self.group.xdp_mode())

        maps = self.bpftool_maps_get()

        # Validate pre-allocation to zero
        self.map_validate_empty(maps[0])
        self.map_validate_empty(maps[1])
        self.map_validate_empty(maps[2])
        self.map_validate_empty(maps[3])
        self.map_validate_empty(maps[4])

    def cleanup(self):
        self.xdp_stop(mode=self.group.xdp_mode())

################################################################################
# Actual test classes - data path
################################################################################

class XDParrayLookup(XDPlookup):
    def get_prog_name(self):
        return 'map_array256.o'

class XDParrayLookupTwice(XDPlookupTwice):
    def get_prog_name(self):
        return 'map_array256_256.o'

class XDPhtabLookup(XDPlookup):
    def get_prog_name(self):
        return 'map_htab256.o'

class XDPhtabLookupTwice(XDPlookupTwice):
    def get_prog_name(self):
        return 'map_htab256_256.o'

class XDParrayU2L(XDPupdate2lookup):
    def get_prog_name(self):
        return 'map_array_u2l.o'

class XDPhtabU2L(XDPupdate2lookup):
    def get_prog_name(self):
        return 'map_htab_u2l.o'

class XDParrayUpdateFlagsAndDelete(XDPupdateFlagsAndDelete):
    def get_prog_name(self):
        return 'map_array_update_delete.o'

class XDPhtabUpdateFlagsAndDelete(XDPupdateFlagsAndDelete):
    def get_prog_name(self):
        return 'map_htab_update_delete.o'
