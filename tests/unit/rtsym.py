import os
from ..common_test import CommonTest, NtiFail

class RTSymTest(CommonTest):
    def __init__(self, src, dut, group=None, name="", summary=None):
        CommonTest.__init__(self, src, dut, group, name, summary)

        self.fws = [('rm_rts_3', 3), ('rm_rts_17', 17), (None, -22),
                    ('rm1_rts_100', 100),
                    # MIPv2 not supported, yet
                    ('rm2_rts_100', -22),
                    ('rts_100', -22),
                    ('rm_rts_17', 17), ('rm_rts_1', 1),
                    ('rm_rts_0', 0), ('rm_rts_2', 2),
                    ('rm_rts_100', 100)]

        self.syms = ['.mip', '_o', 'i32._two', '_three',
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
        last = ['_o', '.mip'][num == 1]
        self.dut.dfs_write('nth/rtsym_key', last, do_fail=(num < 1))

        syms = self.dut.dfs_read('nth/rtsym_dump')
        syms = syms.split().sort()
        dump = self.syms[0:num].sort()
        if syms != dump:
            raise NtiFail('RTSym dump differs for %s (%s, %s)' %
                          (name, dump, syms))

    def test_all(self, user_space_load=True):
        fwdir_base = os.path.basename(self.group.mefw)
        fwdir = os.path.join('/lib/firmware/netronome/', fwdir_base)

        for tu in self.fws:
            if not tu[0]:
                self.dut.dfs_read('nth/reset')
            elif not user_space_load:
                self.dut.dfs_write('nth/fw_load', 'netronome/%s/%s.nffw' % \
                                   (fwdir_base, tu[0]))
            else:
                if self.loaded:
                    self.dut.nffw_unload()
                self.dut.nffw_load('%s.nffw' % (os.path.join(fwdir, tu[0])))

            self.loaded = bool(tu[0])

            num = tu[1]
            # Account for ".mip" symbol
            if num >= 0:
                num = num + 1
            self.check_cnt(tu[0], num)
            self.check_syms(tu[0], num)


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
