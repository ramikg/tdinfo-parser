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


SYMBOL_RECORD_STRUCT = Struct(
    'index' / Int16ul,  # 1-based
    'type' / Int16ul,
    'offset' / Int16ul,
    'segment' / Int16ul,
    'bitfield' / BitStruct(
        Padding(5),
        'symbol_class' / Enum(BitsInteger(3), SymbolClass))
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
    Padding(28),
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
    Seek(-this.tdinfo_header.names_pool_size_in_bytes, whence=CONSTRUCT_SEEK_EOF),
    'name_pool' / CString('ascii')[this.tdinfo_header.names_count],
)
