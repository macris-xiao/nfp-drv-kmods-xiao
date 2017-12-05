##
## Copyright (C) 2017,  Netronome Systems, Inc.  All rights reserved.
##
import abc
import itertools

from netro.testinfra.nti_exceptions import NtiGeneralError
from struct import pack, unpack_from
from tests.common_test import assert_equal, assert_geq

TYPE_CPP_CSR = 0
TYPE_XPB_CSR = 1
TYPE_ME_CSR = 2
TYPE_IND_ME_CSR = 3
TYPE_RTSYM = 4
TYPE_HWINFO = 5
TYPE_FWNAME = 6
TYPE_HWINFO_FIELD = 7
TYPE_PROLOG = 10000
TYPE_ERROR = 10001

CONTEXTS_PER_IND_REG = 8

SEC_PER_HR = 3600

SPEC_ALIGN = 4
DUMP_ALIGN = 8

# DSL functions to define dump specs
def define_spec(*args):
    ''' Create a DumpSpec from provided TLVs.

    args -- TLVs corresponding to dump levels, each containing a
            TlvSequence as value.
    '''
    return DumpSpec(list(args))

def spec_level(level_id, *args):
    ''' Create a "dump level" TLV with TlvSequence value, for inclusion
    in a spec.

    level_id -- the dump level to use as type
    args -- TLVs with spec types and values, in the order they should
            appear in the dump level being created.
    '''
    return TLV(level_id, TlvSequence(list(args)))

def spec_blob(the_type, data, length_override=None):
    ''' Create a blob TLV, with any type and and arbitrary bytes data.

    the_type -- TLV type number
    data -- bytes to use as value
    length_override -- integer to serialize out as the TLV length
    '''
    return TLV(the_type, BlobSpec(data), length_override)

def spec_csr(the_type, cpp, offset, dump_addr_len, register_width):
    ''' Create a TLV with a CsrSpec value.

    the_type -- one of the TYPE_*_CSR values
    cpp -- a CppParams instance with target, action, token, island
    offset -- address where to start the dump
    dump_addr_len -- address space to cover in the dump
    register_width -- bit width of each register to dump
    '''
    return TLV(the_type, CsrSpec(the_type, cpp, offset, dump_addr_len,
                                 register_width))

def spec_hwinfo():
    return TLV(TYPE_HWINFO, HwInfoSpec())

def spec_hwinfo_field(field_name):
    return TLV(TYPE_HWINFO_FIELD, HwInfoFieldSpec(field_name))

def spec_fw_name():
    return TLV(TYPE_FWNAME, FwNameSpec())

def spec_rtsym(name):
    return TLV(TYPE_RTSYM, RtSymSpec(name))

def align_to(num, align):
    ''' Return the next highest integer multiple of "align" that is on
    or after "num".
    '''
    aligned = num
    num_mod = aligned % align
    aligned += 0 if num_mod == 0 else (align - num_mod)
    return aligned

class CppParams(object):
    def __init__(self, target, action, token, island):
        self.target = target
        self.action = action
        self.token = token
        self.island = island

    def to_be_num(self):
        ''' Return a big-endian integer containing the member fields in
        order.
        '''
        value = self.target << 24
        value |= self.action << 16
        value |= self.token << 8
        value |= self.island
        return value

class TlvNode(object):
    ''' A node (TLV wrapper or value) that forms part of a TLV-based
    data structure.
    '''
    __metaclass__ = abc.ABCMeta

    @abc.abstractmethod
    def get_length(self):
        ''' Total serialized length in bytes of this node. '''
        pass

    @abc.abstractmethod
    def write_to(self, dest):
        ''' Serialize and add this node to the dest bytearray. '''
        pass

    def to_bytes(self):
        ''' Serialize this node to a bytes object. '''
        buf = bytearray()
        self.write_to(buf)
        return bytes(buf)

class SpecNode(TlvNode):
    ''' A node that forms part of a dump specification. '''
    __metaclass__ = abc.ABCMeta

    def get_minimum_dump_length(self):
        ''' The minimum byte size that the dump matching this spec can
        have.
        '''
        return 0

    def assert_dump_value(self, dump, dump_type=None):
        ''' Check that the provided node from the dump matches this
        spec node.
        '''
        pass

class TLV(SpecNode):
    ''' Node with the type, length and a value TlvNode.

    Length can be overridden, to create a test dumpspec with a bad
    length. This is only used when serializing, not when computing
    the length to propagate to higher level nodes.

    If part of a dump spec, the SpecNode methods delegate to the value
    nodes as appropriate, which will also be SpecNode subtypes.
    '''

    def __init__(self, the_type, value, length_override=None):
        self.the_type = the_type
        self.value = value
        self.value_length = self.value.get_length()
        if length_override is not None:
            self.written_length = length_override
        else:
            self.written_length = self.value_length

    def write_to(self, dest):
        dest.extend(pack('> I I', self.the_type, self.written_length))
        if self.value is not None:
            self.value.write_to(dest)

    def get_length(self):
        return 8 + self.value_length

    def get_minimum_dump_length(self):
        return 8 + self.value.get_minimum_dump_length()

    def assert_dump_value(self, dump, dump_type=None):
        if dump.the_type == TYPE_ERROR:
            # Check that the error TLV wrapped th is spec
            assert_equal(self.to_bytes(), dump.value.wrapped_tlv,
                         'Dump error does not wrap spec')
        else:
            assert_equal(self.the_type, dump.the_type,
                         'Spec and dump TLV types')
            assert_geq(dump.value.get_length(),
                       self.value.get_minimum_dump_length(),
                       'TLV %d, length' % self.the_type)
            self.value.assert_dump_value(dump.value, dump.the_type)

class EmptyValue(SpecNode):
    ''' TLV value type with no content. '''

    def get_length(self):
        return 0

    def get_minimum_dump_length(self):
        return DUMP_ALIGN

    def write_to(self, dest):
        pass

class FwNameSpec(EmptyValue):
    def assert_dump_value(self, dump, dump_type=None):
        assert isinstance(dump, PackedStrings), 'fwname dumped incorrectly'

class HwInfoSpec(EmptyValue):
    def assert_dump_value(self, dump, dump_type=None):
        assert isinstance(dump, PackedStrings), 'hwinfo dumped incorrectly'
        assert len(dump) > 0 and len(dump) % 2 == 0, \
            'hwinfo has no or odd number of elements'

class StringValue(SpecNode):
    ''' Serializes to a zero-terminated string with padding to provided
    alignment. '''

    def __init__(self, name, align=SPEC_ALIGN):
        self.name = name
        self.align = align
        self.name_length = self.calc_name_length()

    def write_to(self, dest):
        dest.extend(pack('%ds' % self.name_length, self.name))

    def get_length(self):
        return self.name_length

    def calc_name_length(self):
        return align_to(len(self.name) + 1, self.align)

class RtSymSpec(StringValue):
    def get_minimum_dump_length(self):
        return align_to(17 + len(self.name) + 1, DUMP_ALIGN) + DUMP_ALIGN

    def assert_dump_value(self, dump, dump_type=None):
        assert_equal(self.name, dump.sym_name, 'Bad rtsym name')

class HwInfoFieldSpec(StringValue):
    def get_minimum_dump_length(self):
        return align_to(len(self.name) + 2, DUMP_ALIGN)

    def assert_dump_value(self, dump, dump_type=None):
        assert_equal(self.name, dump[0], 'Bad hwinfo field name')
        assert_equal(2, len(dump), 'hwinfo field needs a key and value')

class CsrSpec(SpecNode):
    def __init__(self, the_type, cpp, offset, dump_addr_len, register_width):
        self.the_type = the_type
        self.cpp = cpp
        self.offset = offset
        self.dump_addr_len = dump_addr_len
        self.register_width = register_width

    def get_length(self):
        return 16

    def get_minimum_dump_length(self):
        ''' The dump adds and error code and error offset. '''
        dump_len = self.dump_addr_len
        if self.the_type == TYPE_IND_ME_CSR:
            dump_len *= CONTEXTS_PER_IND_REG
        return align_to(self.get_length() + 8 + dump_len, DUMP_ALIGN)

    def write_to(self, dest):
        dest.extend(pack('> I I I I',
                         self.cpp.to_be_num(),
                         self.offset,
                         self.dump_addr_len,
                         self.register_width))

    def assert_dump_value(self, dump, dump_type=None):
        assert_equal(self.cpp.target, dump.cpp.target, 'cpp')
        assert_equal(self.cpp.action, dump.cpp.action, 'action')
        assert_equal(self.cpp.token, dump.cpp.token, 'token')
        assert_equal(self.cpp.island, dump.cpp.island, 'island')
        assert_equal(self.offset, dump.offset, 'offset')
        assert_equal(self.dump_addr_len, dump.dump_addr_len, 'dump_addr_len')
        assert_equal(self.register_width, dump.register_width,
                     'register_width')
        expected_len = self.dump_addr_len
        if dump_type == TYPE_IND_ME_CSR:
            expected_len *= CONTEXTS_PER_IND_REG
        assert_equal(align_to(expected_len, DUMP_ALIGN), len(dump.reg_data),
                     'register data length')

class BlobSpec(SpecNode):
    ''' Any arbitrary spec value. '''

    def __init__(self, buf):
        self.buf = buf

    def get_length(self):
        return len(self.buf)

    def write_to(self, dest):
        dest.extend(self.buf)

class TlvSequence(SpecNode):
    def __init__(self, tlvs):
        ''' tlvs -- the list of TLVs to include in the sequence '''
        self.tlvs = list(tlvs)
        self.length = sum([tlv.get_length() for tlv in self.tlvs])
        self.min_dump_length = \
            sum([tlv.get_minimum_dump_length() for tlv in self.tlvs])

    def __getitem__(self, key):
        return self.tlvs[key]

    def __len__(self):
        return len(self.tlvs)

    def get_length(self):
        return self.length

    def get_minimum_dump_length(self):
        return self.min_dump_length

    def write_to(self, dest):
        for tlv in self.tlvs:
            tlv.write_to(dest)

    def assert_dump_value(self, dump, dump_type=None):
        assert_equal(len(self.tlvs), len(dump.tlvs),
                     'Spec and dump have different numbers of TLVs')
        for spec_tlv, dump_tlv in zip(self.tlvs, dump.tlvs):
            spec_tlv.assert_dump_value(dump_tlv)

class DumpSpec(TlvSequence):
    ''' Top level dump spec type. '''

    def get_for_level(self, level):
        ''' Get one aggregate spec sequence over all levels that match
        the provided parameter (more than one level could match).
        '''
        lists = [tlv.value.tlvs for tlv in self.tlvs
                 if tlv.the_type == level]
        return TlvSequence(itertools.chain(*lists))

class PackedStrings(BlobSpec):
    ''' A dump value type that contains zero-terminated strings,
    packed next to each other.
    '''
    def __init__(self, buf):
        super(PackedStrings, self).__init__(buf)
        i = 0
        self.elem = []
        while len(buf) > 0:
            end_idx = buf.index(b'\0')
            decoded = '' if end_idx == 0 else buf[:end_idx].decode('utf-8')
            if i > 0 and i % 2 == 0 and decoded == '':
                # stopping after finding empty key
                break
            self.elem.append(decoded)
            buf = buf[end_idx+1:]
            i += 1

    def __getitem__(self, key):
        return self.elem[key]

    def __len__(self):
        return len(self.elem)

class CsrDump(BlobSpec):
    def __init__(self, buf):
        super(CsrDump, self).__init__(buf)
        (target, action, token, island,
         self.offset, self.dump_addr_len, self.register_width,
         self.error, self.error_offset) = \
            unpack_from('> B B B B I I I i I', buf)
        self.cpp = CppParams(target, action, token, island)
        self.reg_data = buf[24:]

class RtsymDump(BlobSpec):
    def __init__(self, buf):
        super(RtsymDump, self).__init__(buf)
        (target, action, token, island,
         self.offset, self.dump_addr_len,
         self.error, self.padded_name_len) = \
            unpack_from('> B B B B I I i B', buf)
        name_buf = buf[17:]
        assert_equal(len(name_buf)-self.dump_addr_len, self.padded_name_len,
                     'Dump rtsym padded name length')
        end_idx = name_buf.index(b'\0')
        self.sym_name = \
            '' if end_idx == 0 else name_buf[:end_idx].decode('utf-8')
        self.cpp = CppParams(target, action, token, island)
        self.reg_data = buf[17+self.padded_name_len:]

class Prolog(BlobSpec):
    def __init__(self, buf):
        super(Prolog, self).__init__(buf)
        (self.dump_level,) = unpack_from('> I', buf)

class ErrorValue(BlobSpec):
    def __init__(self, buf):
        super(ErrorValue, self).__init__(buf)
        (self.error_code,) = unpack_from('> i', buf)
        self.wrapped_tlv = buf[8:]

class FwDump:
    ''' Top level object representing a firmware dump. Can be indexed
    to get TLVs in the dump.
    '''
    def __init__(self, data):
        ''' Deserialize the data to TLV objects with value types
        dictated by the TLV types.
        '''
        self.tlvs = []
        while len(data) > 0:
            (the_type, length) = unpack_from('> I I', data)
            value = self.create_value(the_type, data[8:8+length])
            self.tlvs.append(TLV(the_type, value, length))
            data = data[8+length:]

    def __getitem__(self, key):
        return self.tlvs[key]

    def __len__(self):
        return len(self.tlvs)

    def create_value(self, the_type, value_bytes):
        if the_type in (TYPE_FWNAME, TYPE_HWINFO, TYPE_HWINFO_FIELD):
            return PackedStrings(value_bytes)
        elif the_type in (TYPE_CPP_CSR, TYPE_XPB_CSR, TYPE_ME_CSR,
                          TYPE_IND_ME_CSR):
            return CsrDump(value_bytes)
        elif the_type == TYPE_RTSYM:
            return RtsymDump(value_bytes)
        elif the_type == TYPE_PROLOG:
            return Prolog(value_bytes)
        elif the_type == TYPE_ERROR:
            return ErrorValue(value_bytes)
        raise NtiGeneralError('Unknown dump tlv type %d' % the_type)

    def assert_dump_level(self, expected_level):
        ''' Check that the first TLV is a prolog with the correct
        dump level
        '''
        assert_equal(TYPE_PROLOG, self.tlvs[0].the_type,
                     'Prolog type expected as first TLV in dump')
        assert_equal(expected_level, self.tlvs[0].value.dump_level,
                     'Bad dump level')

    def tlvs_without_prolog(self):
        ''' Return a tuple with all dump TLVs except the prolog. '''
        return TlvSequence([tlv for tlv in self.tlvs
                            if tlv.the_type != TYPE_PROLOG])
