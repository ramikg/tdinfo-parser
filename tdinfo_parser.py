import ida_idaapi
import ida_kernwin
import ida_nalt
import ida_name
import ida_segment
import idc

ida_idaapi.require('tdinfo_structs')


class TdinfoParserException(Exception):
    pass


class TdinfoParserSymbolAlreadyAppliedException(TdinfoParserException):
    pass


class TdinfoParserIdaSetNameFailedException(TdinfoParserException):
    pass


class TdinfoParserUnsupportedSymbolClassException(TdinfoParserException):
    pass


def _parse_exe_file():
    input_file_path = ida_kernwin.ask_file(False, ida_nalt.get_input_file_path(), 'Input file')
    parsed_file = tdinfo_structs.DOS_MZ_EXE_STRUCT.parse_file(input_file_path)

    print('Borland TLink symbolic information version: {}.{}'.format(
        parsed_file.tdinfo_header.major_version,
        parsed_file.tdinfo_header.minor_version))

    return parsed_file


def _apply_tdinfo_symbol(image_base, name_pool, symbol):
    if symbol.bitfield.symbol_class != tdinfo_structs.SymbolClass.STATIC.name:
        raise TdinfoParserUnsupportedSymbolClassException()

    symbol_ea = image_base + symbol.segment * 0x10 + symbol.offset
    symbol_name = str(name_pool[symbol.index - 1])

    if ida_name.get_name(symbol_ea) == symbol_name:
        raise TdinfoParserSymbolAlreadyAppliedException()

    if ida_name.set_name(symbol_ea, symbol_name):
        print('Applied name {} to address {:04X}:{:04X}'.format(
            symbol_name,
            image_base // 0x10 + symbol.segment,
            symbol.offset))
    else:
        raise TdinfoParserIdaSetNameFailedException()


def apply_tdinfo_symbols():
    # A heuristic, since get_imagebase returns wrong result
    image_base = ida_segment.get_first_seg().start_ea

    parsed_exe_file = _parse_exe_file()

    applied_symbols_count = 0
    already_existing_symbols_count = 0
    for symbol in parsed_exe_file.symbol_records:
        try:
            _apply_tdinfo_symbol(image_base, parsed_exe_file.name_pool, symbol)
            _apply_tdinfo_type(image_base, parsed_exe_file, symbol)
            applied_symbols_count += 1
        except TdinfoParserSymbolAlreadyAppliedException:
            already_existing_symbols_count += 1
        except TdinfoParserException:
            pass

    print('Detected {} global symbols.'.format(
        parsed_exe_file.tdinfo_header.globals_count)),
    print('{} identical symbols already existed, {} new symbols were applied.'.format(
        already_existing_symbols_count,
        applied_symbols_count))

    for segment in parsed_exe_file.segment_records:
        _apply_tdinfo_segment(image_base, parsed_exe_file, segment)
        _apply_tdinfo_scopes(image_base, parsed_exe_file, segment)


def _apply_tdinfo_type(image_base, parsed_exe_file, symbol):
    if (symbol.bitfield.symbol_class != tdinfo_structs.SymbolClass.STATIC.name or
        symbol.type == 0):
        return

    symbol_ea = image_base + symbol.segment * 0x10 + symbol.offset
    symbol_name = str(parsed_exe_file.name_pool[symbol.index - 1])

    type = parsed_exe_file.type_records[symbol.type - 1]
    _apply_tdinfo_type_rec(symbol_ea, symbol_name, parsed_exe_file, type)


def _apply_tdinfo_type_rec(symbol_ea, symbol_name, parsed_exe_file, type):
    if (type.id == tdinfo_structs.TypeId.SCHAR.name or
        type.id == tdinfo_structs.TypeId.UCHAR.name):
        idc.create_byte(symbol_ea)
    elif (type.id == tdinfo_structs.TypeId.SINT.name or
          type.id == tdinfo_structs.TypeId.UINT.name):
        idc.create_word(symbol_ea)
    elif (type.id == tdinfo_structs.TypeId.SLONG.name or
          type.id == tdinfo_structs.TypeId.ULONG.name or
          type.id == tdinfo_structs.TypeId.FAR.name):
        idc.create_dword(symbol_ea)
    elif type.id == tdinfo_structs.TypeId.ARRAY.name:
        member = parsed_exe_file.type_records[type.member_type - 1]
        if member.id == tdinfo_structs.TypeId.ARRAY.name: # array of arrays
            idc.make_array(symbol_ea, type.size)
        else:
            _apply_tdinfo_type_rec(symbol_ea, symbol_name, parsed_exe_file, member)
            idc.make_array(symbol_ea, type.size // member.size)
    elif type.id == tdinfo_structs.TypeId.STRUCT.name:
        struct_name = 'struct' + symbol_name
        if get_struc_id(struct_name) == BADADDR: #check if struct already exists
            _apply_tdinfo_struct(struct_name, parsed_exe_file, type)
        idc.create_struct(symbol_ea, -1, struct_name)


def _apply_tdinfo_struct(struct_name, parsed_exe_file, type): #create struct + members
    id = idc.add_struc(-1, struct_name, 0)

    memberIndex = type.member_type - 1
    member = parsed_exe_file.member_records[memberIndex]
    while True: # loop on struct members
        member_name = str(parsed_exe_file.name_pool[member.name - 1])
        member_type = parsed_exe_file.type_records[member.type - 1]

        if (member_type.id == tdinfo_structs.TypeId.SINT.name or
            member_type.id == tdinfo_structs.TypeId.UINT.name):
            flag = FF_WORD
        elif (member_type.id == tdinfo_structs.TypeId.SLONG.name or
              member_type.id == tdinfo_structs.TypeId.ULONG.name or
              member_type.id == tdinfo_structs.TypeId.FAR.name):
            flag = FF_DWORD
        else:
            flag = FF_BYTE

        idc.add_struc_member(id, member_name, -1, flag, -1, member_type.size)

        memberIndex += 1
        member = parsed_exe_file.member_records[memberIndex]
        if member.info == 0xC0: #end marker
            break


def _apply_tdinfo_segment(image_base, parsed_exe_file, segment):
    segment_ea = image_base + segment.code_segment * 0x10 + segment.code_offset
    module = parsed_exe_file.module_records[segment.module - 1]
    module_name = str(parsed_exe_file.name_pool[module.name - 1])

    if set_segm_name(segment_ea, module_name):
        print('Applied name {} to segment {:04X}:{:04X}'.format(
            module_name,
            image_base // 0x10 + segment.code_segment, segment.code_offset))


def _apply_tdinfo_scopes(image_base, parsed_exe_file, segment):
    for i in range(segment.scope_count):
        scope = parsed_exe_file.scope_records[segment.scope_index - 1 + i]
        _apply_tdinfo_scope(image_base, parsed_exe_file, segment, scope)


def _apply_tdinfo_scope(image_base, parsed_exe_file, segment, scope):
    scope_offset = scope.offset if scope.parent == 0 else parsed_exe_file.scope_records[scope.parent - 1].offset
    scope_ea = image_base + segment.code_segment * 0x10 + scope_offset

    for i in range(scope.symbol_count):
        symbol = parsed_exe_file.symbol_records[scope.symbol_index - 1 + i]
        _apply_tdinfo_localvar(image_base, parsed_exe_file, symbol, segment, scope_ea, scope_offset)


def _apply_tdinfo_localvar(image_base, parsed_exe_file, symbol, segment, scope_ea, scope_offset):
    if symbol.bitfield.symbol_class != tdinfo_structs.SymbolClass.AUTO.name:
        return

    symbol_name = str(parsed_exe_file.name_pool[symbol.index - 1])
    offset = symbol.offset - 0x10000 if symbol.offset > 0x7fff else symbol.offset
    operator = '+' if offset >= 0 else '-'

    idc.add_func(scope_ea, BADADDR) # create function if needed
    if (idc.define_local_var(scope_ea, scope_ea, '[bp{}{}]'.format(operator, abs(offset)), symbol_name)):
        print('Applied name {} to [bp{}{}] at address {:04X}:{:04X}'.format(
            symbol_name,
            operator, abs(offset),
            image_base // 0x10 + segment.code_segment, scope_offset))