import enum
from construct import (BitsInteger, BitStruct, Byte, Const, CString, Enum,
                       Int16ul, Int32ul, Padding, Seek, Struct, Tell, this)

TDINFO_MAGIC_LITTLE_ENDIAN = 0x52FB
PAGE_SIZE_IN_BYTES = 512
CONSTRUCT_SEEK_EOF = 2


def calculate_extra_information_offset(ctx):
    if ctx.used_bytes_in_last_page == 0:
        used_bytes_in_last_page = PAGE_SIZE_IN_BYTES
    else:
        used_bytes_in_last_page = ctx.used_bytes_in_last_page

    file_size_in_bytes = ctx.file_size_in_pages * PAGE_SIZE_IN_BYTES

    return file_size_in_bytes - (PAGE_SIZE_IN_BYTES - used_bytes_in_last_page)


class SymbolClass(enum.IntEnum):
    STATIC = 0
    ABSOLUTE = 1
    AUTO = 2
    PASCAL_VAR = 3
    REGISTER = 4
    CONSTANT = 5
    TYPEDEF = 6
    STRUCT_UNION_OR_ENUM = 7


class TypeId(enum.IntEnum):
    VOID = 0
    LSTR = 1
    DSTR = 2
    PSTR = 3
    SCHAR = 4
    SINT = 5
    SLONG = 6
    UCHAR = 8
    UINT = 9
    ULONG = 10
    PCHAR = 12
    FLOAT = 13
    TPREAL = 14
    DOUBLE = 15
    LDOUBLE = 16
    BCD4 = 17
    BCD8 = 18
    BCD10 = 19
    BCDCOB = 20
    NEAR = 21
    FAR = 22
    SEG = 23
    NEAR386 = 24
    FAR386 = 25
    ARRAY = 26
    PARRAY = 28
    STRUCT = 30
    UNION = 31
    ENUM = 34
    FUNCTION = 35
    LABEL = 36
    SET = 37
    TFILE = 38
    BFILE = 39
    BOOL = 40
    PENUM = 41
    FUNCPROTOTYPE = 44
    SPECIALFUNC = 45
    OBJECT = 46
    NREF = 52
    FREF = 53
    WORDBOOL = 54
    LONGBOOL = 55
    GLOBALHANDLE = 62
    LOCALHANDLE = 63


SYMBOL_RECORD_STRUCT = Struct(
    'index' / Int16ul,  # 1-based
    'type' / Int16ul,
    'offset' / Int16ul,
    'segment' / Int16ul,
    'bitfield' / BitStruct(
        Padding(5),
        'symbol_class' / Enum(BitsInteger(3), SymbolClass))
)

TYPE_RECORD_STRUCT = Struct(
    'id' / Enum(Byte, TypeId),
    'name' / Int16ul,
    'size' / Int16ul,
    'class_type' / Byte,
    'member_type' / Int16ul
)

MEMBER_RECORD_STRUCT = Struct(
    'info' / Byte,
    'name' / Int16ul,
    'type' / Int16ul
)

MODULE_RECORD_STRUCT = Struct(
    'name' / Int16ul,
    Padding(14)
)

SEGMENT_RECORD_STRUCT = Struct(
    'module' / Int16ul,
    'code_segment' / Int16ul,
    'code_offset' / Int16ul,
    'code_length' / Int16ul,
    'scope_index' / Int16ul,
    'scope_count' / Int16ul,
    Padding(4)
)

SCOPE_RECORD_STRUCT = Struct(
    'symbol_index' / Int16ul,
    'symbol_count' / Int16ul,
    'parent' / Int16ul,
    'function' / Int16ul,
    'offset' / Int16ul,
    'length' / Int16ul
)

TDINFO_HEADER_STRUCT = Struct(
    'magic_number' / Const(TDINFO_MAGIC_LITTLE_ENDIAN, Int16ul),
    'minor_version' / Byte,
    'major_version' / Byte,
    'names_pool_size_in_bytes' / Int32ul,
    'names_count' / Int16ul,
    'types_count' / Int16ul,
    'members_count' / Int16ul,
    'symbols_count' / Int16ul,
    'globals_count' / Int16ul,
    'modules_count' / Int16ul,
    'locals_count' / Int16ul,
    'scopes_count' / Int16ul,
    'line_numbers_count' / Int16ul,
    'source_files_count' / Int16ul,
    'segments_count' / Int16ul,
    'correlations_count' / Int16ul,
    Padding(14),
    'extension_size' / Int16ul,
    Padding(this.extension_size)
)

DOS_MZ_EXE_STRUCT = Struct(
    'signature' / Const(b'MZ'),
    'used_bytes_in_last_page' / Int16ul,
    'file_size_in_pages' / Int16ul,
    'offset_of_unused_bytes' / Tell,
    Padding(lambda ctx: calculate_extra_information_offset(ctx) - ctx.offset_of_unused_bytes),
    'tdinfo_header' / TDINFO_HEADER_STRUCT,
    'symbol_records' / SYMBOL_RECORD_STRUCT[this.tdinfo_header.symbols_count],
    'module_records' / MODULE_RECORD_STRUCT[this.tdinfo_header.modules_count],
    Padding(this.tdinfo_header.source_files_count * 6),
    Padding(this.tdinfo_header.line_numbers_count * 4),
    'scope_records' / SCOPE_RECORD_STRUCT[this.tdinfo_header.scopes_count],
    'segment_records' / SEGMENT_RECORD_STRUCT[this.tdinfo_header.segments_count],
    Padding(this.tdinfo_header.correlations_count * 8),
    'type_records' / TYPE_RECORD_STRUCT[this.tdinfo_header.types_count],
    'member_records' / MEMBER_RECORD_STRUCT[this.tdinfo_header.members_count],
    Seek(-this.tdinfo_header.names_pool_size_in_bytes, whence=CONSTRUCT_SEEK_EOF),
    'name_pool' / CString('ascii')[this.tdinfo_header.names_count],
)
