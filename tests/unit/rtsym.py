import os
from ..common_test import CommonTest, NtiFail, assert_eq, assert_ge

class RTSymTest(CommonTest):
    def __init__(self, src, dut, group=None, name="", summary=None):
        CommonTest.__init__(self, src, dut, group, name, summary)

        self.fws = [('rm_rts_3', 3), ('rm_rts_17', 17), (None, -22),
                    ('rm1_rts_100', 100),
                    # MIPv2 not supported, yet
                    ('rm2_rts_100', -22),
                    ('rts_100', -22),
                    ('rm_rts_17', 17), ('rm_rts_1', 1),
                    ('rm_rts_0', -22), ('rm_rts_2', 2),
                    ('rm_rts_100', 100)]

        self.syms = ['_o', 'i32._two', '_three',
                '_thisisaverylongname000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000end',
        ]
        self.syms += ['_a%d' % i for i in range(5, 101)]

        self.loaded = False
        return

    def check_cnt(self, name, exp):
        val = self.dut.dfs_read('nth/rtsym_count')
        if int(val) != exp:
            self.dut.dfs_read('nth/rtsym_dump')
            raise NtiFail('RTSym count not %d (%s, %s)' % (exp, name, val))

    def check_syms(self, name, num):
        self.dut.dfs_write('nth/rtsym_key', '_o', do_fail=(num < 0))

	if (num < 0):
		return

        syms = self.dut.dfs_read('nth/rtsym_dump')
        sym_get = syms.split()
        sym_get.sort()
        sym_comp = self.syms[0:num]
        sym_comp.sort()

        if sym_get != sym_comp:
            raise NtiFail('RTSym dump differs for %s (%s, %s)' %
                          (name, sym_comp, sym_get))

    def test_all(self, user_space_load=True):
        fwdir_base = os.path.basename(self.group.mefw)
        fwdir = os.path.join('/lib/firmware/netronome/', fwdir_base)

        for tu in self.fws:
            # Intermediary for kernel/user space firmware loading
            fw = [tu[0], tu[1]]

            if not fw[0]:
                # Reset NFP
                self.dut.dfs_read('nth/reset')
            else:
                # Load sample firmware
                if self.dut.get_pci_device_id() == '3800':
                    # Kestrel (nfp-3800) cannot use -mip_v2
                    if tu[0] == 'rm2_rts_100':
                        continue

                    # Use Kestrel pre-built firmware
                    fw = ['%s_nfp-38xxc' % tu[0], tu[1]]
                else:
                    # Use Osprey pre-built firmware
                    fw = ['%s_nfp-4xxx-b0' % tu[0], tu[1]]

                if not user_space_load:
                    # Kernel space firmware load
                    sample_fw_path = 'netronome/%s/%s.nffw' % \
                                     (fwdir_base, fw[0])
                    self.dut.dfs_write('nth/fw_load', sample_fw_path)
                else:
                    # User space firmware load
                    if self.loaded:
                        self.dut.nffw_unload()
                    sample_fw_path = '%s.nffw' % (os.path.join(fwdir, fw[0]))
                    self.dut.nffw_load(sample_fw_path)

            # Verify loaded firmware
            self.loaded = bool(fw[0])
            self.check_cnt(fw[0], fw[1])
            self.check_syms(fw[0], fw[1])


    def execute(self):
        self.dut.cmd('mkdir -p /lib/firmware/netronome')
        self.dut.cp_to(self.group.mefw, '/lib/firmware/netronome/')

        self.dut.insmod()
        self.dut.nfp_reset()
        self.dut.insmod(module="nth")

        self.check_cnt('insmod', -22)

        self.test_all()
        self.test_all(user_space_load=False)

    def cleanup(self):
        self.dut.cmd('rm -rf /lib/firmware/netronome')
        self.dut.reset_mods()

class RTSymDataTest(CommonTest):
    def rtsym_read_raw(self, key):
        cmd = '-R %s | hexdump -v -e "1/1 \\"%%02x\\""' % (key)
        _, data = self.dut.bsp_cmd('rtsym', cmd, fail=True)
        return data

    def nth_rtsym_data_read(self, key, seek=None, bs=None):
        self.dut.dfs_write('nth/rtsym_key', key)

        cmd = 'dd if=%s ' % (os.path.join(self.dut.dfs_dir, 'nth/rtsym_val'))
        if seek is not None:
            cmd += 'seek=%d ' % (seek)
        if bs is not None:
            cmd += 'bs=%d ' % (bs)
        cmd +='| hexdump -v -e "1/1 \\"%02x\\""'

        _, data = self.dut.cmd(cmd)
        return data

    def nth_rtsym_data_write(self, key, val, seek=None, do_fail=False):
        self.dut.dfs_write('nth/rtsym_key', key)

        cmd = 'echo -ne "%s"' % (val)
        cmd += ' | dd of=%s bs=4 conv=notrunc' % \
            (os.path.join(self.dut.dfs_dir, 'nth/rtsym_val'))
        if seek:
            cmd += ' seek=%d' % (seek / 4)
        ret, _ = self.dut.cmd(cmd, fail=not do_fail)
        if bool(ret) != do_fail:
            raise NtiFail("Write to '%s' did not fail" % (key))

    def rtsym_val_match(self, key):
        # Check full values
        tool = self.rtsym_read_raw(key=key)
        kernel = self.nth_rtsym_data_read(key=key)

        # Workaround for nfp-rtsym adding a new line
        if len(tool) == len(kernel) + 2 and tool[-2:] == '0a':
            tool = tool[:-2]

        assert_eq(tool, kernel, "Read rtsym '%s'" % (key))

        # Check read byte-by-byte
        kernel = self.nth_rtsym_data_read(key=key, bs=8)
        assert_eq(tool, kernel, "Read rtsym '%s' (bytes)" % (key))

        return tool

    def test_rw_sym(self, key):
        val = self.rtsym_val_match(key)

        self.nth_rtsym_data_write(key, 'abcd')
        modified = self.rtsym_val_match(key)
        expected = '61626364' + val[8:]

        assert_eq(expected, modified, "Modified RTsym value")

        self.nth_rtsym_data_write(key, val='abcd', seek=28)
        modified = self.rtsym_val_match(key)
        expected = expected[:56] + '61626364' + expected[64:]

        assert_eq(expected, modified, "Modified RTsym value")

    def test_wr_out_of_bounds(self, key, seek):
        self.nth_rtsym_data_write(key=key, val='a', seek=seek, do_fail=True)
        _, data = self.dut.cmd('dmesg | tail -3')
        assert_ge(1, data.count("write out of bounds"),
                  "Kernel error on  write out of bounds")

    def execute(self):
        self.fw_loaded = False
        if self.dut.get_pci_device_id() == '3800':
            fw = 'rts_vals_nfp-38xxc.nffw'
        else:
            fw = 'rts_vals_nfp-4xxx-b0.nffw'
        self.fw_path = os.path.join(self.dut.tmpdir, fw)
        self.dut.cp_to(os.path.join(self.group.mefw, fw),
                       self.dut.tmpdir)

        self.dut.insmod()
        self.dut.nfp_reset()
        self.dut.insmod(module="nth")

        self.dut.nffw_load(self.fw_path)
        self.fw_loaded = True

        # Check we can read the ABS symbol
        tool = self.rtsym_read_raw(key='sample_abs_sym:0')
        kernel = self.nth_rtsym_data_read(key='sample_abs_sym')
        assert_eq(tool, kernel, "ABS rtsym read")

        # Check read byte-by-byte
        kernel = self.nth_rtsym_data_read(key='sample_abs_sym', bs=1)
        assert_eq(tool, kernel, "ABS rtsym read")

        # Check we can't write an ABS symbol
        self.nth_rtsym_data_write(key='sample_abs_sym', val="abcd",
                                  do_fail=True)

        _, data = self.dut.cmd('dmesg | tail -3')
        assert_ge(1, data.count("direct access to non-object rtsym"),
                  "Kernel error on direct access to non-object rtsym")

        self.test_rw_sym('i32._sym_ctm')
        self.test_rw_sym('_sym_emem')
        self.test_rw_sym('_sym_cache')

        self.test_wr_out_of_bounds(key='sample_abs_sym', seek=16)
        self.test_wr_out_of_bounds(key='_sym_emem', seek=136)
        self.test_wr_out_of_bounds(key='_sym_cache', seek=136)

    def cleanup(self):
        self.dut.cmd('rm -rf %s' % (self.fw_path))
        if self.fw_loaded:
            self.dut.nfp_reset()
        self.dut.reset_mods()
