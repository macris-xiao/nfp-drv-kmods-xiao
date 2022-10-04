import errno
import os
import netro.testinfra
from netro.testinfra.test import *
from netro.testinfra.nti_exceptions import NtiGeneralError
from netro.testinfra.nrt_result import NrtResult
from ..common_test import *
from ..drv_fwdump import *

class FwDumpTest(CommonTest):
    '''
    Tests for fw debug dumps, by providing different dump specs, and
    performing dumps using these specs.
    '''

    def __init__(self, src, dut, group=None, name='', summary=None):
        CommonTest.__init__(self, src, dut, group, name, summary)

    def prep(self):
        self.dut.cmd('mkdir -p /lib/firmware/netronome')
        self.dut.cp_to(self.group.mefw, '/lib/firmware/netronome/')
        self.dut.insmod()
        self.dut.nfp_reset()
        self.dut.insmod(module='nth')
        fwdir_base = os.path.basename(self.group.mefw)
        fwdir = os.path.join('/lib/firmware/netronome/', fwdir_base)
        if self.dut.get_pci_device_id() == '3800':
            fw = 'rts_dump_nfp-38xxc'
        else:
            fw = 'rts_dump_nfp-4xxx-b0'
        self.dut.nffw_load('%s.nffw' % os.path.join(fwdir, fw))

    def load_spec_bytes(self, spec_bytes):
        self.dut.dfs_write_bytes('nth/fw_dump_spec', spec_bytes)

    def load_spec(self, spec):
        self.load_spec_bytes(spec.to_bytes())

    def set_dump_level(self, level):
        self.dut.dfs_write('nth/fw_dump_level', repr(level))

    def trigger_dump(self, expected_ret=0):
        ret = int(self.dut.dfs_read('nth/fw_dump_trigger'))
        assert_equal(expected_ret, ret, 'Dump trigger result unexpected')

    def get_dump(self):
        return FwDump(self.dut.dfs_read_raw('nth/fw_dump_data'))

    def check_normal_dump(self, spec, dump_level, expected_error_tlvs={}):
        self.load_spec(spec)
        self.set_dump_level(dump_level)
        level_x_spec = spec.get_for_level(dump_level)
        self.trigger_dump()
        dump = self.get_dump()
        dump.assert_dump_level(dump_level)
        for (index, err_code) in expected_error_tlvs.iteritems():
            assert_equal(TYPE_ERROR, dump[index].the_type, 'Bad TLV type')
            assert_equal(err_code, dump[index].value.error_code,
                         'Bad error code')
        errs = [tlv.the_type for tlv in dump.tlvs if tlv.the_type == TYPE_ERROR]
        assert_equal(len(expected_error_tlvs), len(errs),
                     'Incorrect number of error TLVs')
        level_x_spec.assert_dump_value(dump.tlvs_without_prolog())
        return dump

    def test_well_formed(self):
        spec = define_spec(
            spec_level(1, spec_fw_name(), spec_hwinfo_field('assembly.partno'),
                       spec_rtsym('_o')),
            spec_level(2, spec_hwinfo()),
            spec_level(3, spec_rtsym('does_not_exist'),
                       spec_hwinfo_field('does_not_exist')),
            # The CSR specs are samples from FW, and should work on
            # nfp-6xxxc-b0. In future, it may be necessary to
            # externalize these with config, when running on different
            # hardware.
            spec_level(
                4,
                spec_csr(TYPE_XPB_CSR, CppParams(14,0,0,8), 0x8100020, 32, 32),
                spec_csr(TYPE_XPB_CSR, CppParams(14,0,0,8), 0x810000c, 4, 32),
                spec_csr(TYPE_ME_CSR, CppParams(14,2,1,32), 0x20011170,
                         16, 32),
                spec_csr(TYPE_IND_ME_CSR, CppParams(14,2,1,32), 0x20011040,
                         4, 32),
                spec_csr(TYPE_CPP_CSR, CppParams(9,2,0,4), 0x400c0, 52, 32),
                spec_csr(TYPE_CPP_CSR, CppParams(1,0,0,8), 0x8000, 32, 64)
                ),
            )
        self.check_normal_dump(spec, 1)
        self.check_normal_dump(spec, 2)
        self.check_normal_dump(spec, 10)
        self.check_normal_dump(spec, 3, expected_error_tlvs={1:-errno.ENOENT,
                                                             2:-errno.ENOENT})
        self.check_normal_dump(spec, 4)

    def test_arm_island_xpb_read(self):
        spec = define_spec(spec_level(1, spec_csr(TYPE_XPB_CSR,
                                                  CppParams(14,0,0,1),
                                                  0x41090000, 4, 32)))
        dump = self.check_normal_dump(spec, 1)
        (reg_value,) = unpack_from('< I', dump[1].value.reg_data)
        assert reg_value != 0xffffffff, 'Bad XPB register read'

    def test_fwname(self):
        spec = define_spec(spec_level(1, spec_fw_name()))
        dump = self.check_normal_dump(spec, 1)
        assert_equal("TEST_FW_1234567", dump[1].value[0], "FW name")

    def test_multiple_of_same_level(self):
        spec = define_spec(
            spec_level(1, spec_fw_name()),
            spec_level(2, spec_rtsym('_o')),
            spec_level(1, spec_hwinfo_field('assembly.partno'),
                       spec_rtsym('_o')),
            spec_level(3, spec_rtsym('does_not_exist')),
            )
        dump = self.check_normal_dump(spec, 1)
        assert_equal(4, len(dump), 'Number of tlvs')
        self.check_normal_dump(spec, 2)
        self.check_normal_dump(spec, 3, expected_error_tlvs={1:-errno.ENOENT})

    def test_unknown_spec_tlv_handling(self):
        spec = define_spec(spec_level(1, spec_fw_name(),
                                      spec_blob(9999, b'somedata'),
                                      spec_rtsym('_o')))
        self.check_normal_dump(spec, 1,
                               expected_error_tlvs={2:-errno.EOPNOTSUPP})

    def test_bad_spec_alignment(self):
        spec = define_spec(spec_level(1, spec_blob(9999, b'abcde')))
        self.load_spec(spec)
        self.set_dump_level(1)
        self.trigger_dump(expected_ret=-errno.EINVAL)

    def test_bad_tlv_length(self):
        spec = define_spec(spec_level(1, spec_blob(9999, b'somedata',
                                                   length_override=100)))
        self.load_spec(spec)
        self.set_dump_level(1)
        self.trigger_dump(expected_ret=-errno.EINVAL)

    def test_8_trailing_zeros(self):
        spec = define_spec(spec_level(1, spec_fw_name(), TLV(0, EmptyValue())))
        self.load_spec(spec)
        self.set_dump_level(1)
        self.trigger_dump()
        dump = self.get_dump()
        assert_equal(2, len(dump), 'Number of tlvs')
        dump.assert_dump_level(1)
        assert_equal(TYPE_FWNAME, dump[1].the_type, 'Dump TLV type')

    def test_4_trailing_zeros(self):
        spec = define_spec(spec_level(1, spec_fw_name()))
        spec_bytearray = bytearray()
        spec_bytearray.extend(spec.to_bytes())
        spec_bytearray.extend(b'\0\0\0\0')
        self.load_spec_bytes(bytes(spec_bytearray))
        self.set_dump_level(1)
        self.trigger_dump()
        dump = self.get_dump()
        assert_equal(2, len(dump), 'Number of tlvs')
        dump.assert_dump_level(1)
        assert_equal(TYPE_FWNAME, dump[1].the_type, 'Dump TLV type')

    def test_huge_tlv_length(self):
        spec = define_spec(TLV(1, TlvSequence([spec_fw_name()]), 0xFFFFFFF8))
        self.load_spec(spec)
        self.set_dump_level(1)
        self.trigger_dump(expected_ret=-errno.EINVAL)

    def test_near_empty_spec(self):
        spec_bytearray = bytearray()
        spec_bytearray.extend(b'\0')
        self.load_spec_bytes(bytes(spec_bytearray))
        self.set_dump_level(1)
        self.trigger_dump()
        dump = self.get_dump()
        assert_equal(1, len(dump), 'Missing prolog')
        dump.assert_dump_level(1)

    def test_abs_rtsym(self):
        spec = define_spec(spec_level(1,  spec_rtsym('sample_abs_sym')))
        dump = self.check_normal_dump(spec, 1)
        (symval1, symval2) = unpack_from('< I I', dump[1].value.reg_data)
        assert_equal(0x67, symval2, 'abs rtsym value high byte')
        assert_equal(0x89abcdef, symval1, 'abs rtsym value low bytes')

    def prepare(self):
        if self.group.upstream_drv:
            return NrtResult(name=self.name, testtype=self.__class__.__name__,
                             passed=None, comment="FW dump test needs NTH")

    def execute(self):
        self.prep()
        self.test_well_formed()
        self.test_arm_island_xpb_read()
        self.test_fwname()
        self.test_multiple_of_same_level()
        self.test_unknown_spec_tlv_handling()
        self.test_bad_spec_alignment()
        self.test_bad_tlv_length()
        self.test_8_trailing_zeros()
        self.test_4_trailing_zeros()
        self.test_huge_tlv_length()
        self.test_near_empty_spec()
        self.test_abs_rtsym()

    def cleanup(self):
        self.dut.nffw_unload()
        self.dut.cmd('rm -rf /lib/firmware/netronome')
        self.dut.reset_mods()
