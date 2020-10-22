import ida_kernwin
import ida_name
import idc

from tdinfo_structs import DOS_MZ_EXE_STRUCT, SymbolClass


class TdinfoParserException(Exception):
    pass


class TdinfoParserSymbolAlreadyAppliedException(TdinfoParserException):
    pass


class TdinfoParserIdaSetNameFailedException(TdinfoParserException):
    pass


class TdinfoParserUnsupportedSymbolClassException(TdinfoParserException):
    pass


def _parse_exe_file():
    input_file_path = ida_kernwin.ask_file(False, idc.get_input_file_path(), 'Input file')
    parsed_file = DOS_MZ_EXE_STRUCT.parse_file(input_file_path)

    print('Borland TLink symbolic information version: {}.{}'.format(
        parsed_file.tdinfo_header.major_version,
        parsed_file.tdinfo_header.minor_version))

    return parsed_file


def _apply_tdinfo_symbol(image_base, name_pool, symbol):
    if symbol.bitfield.symbol_class != SymbolClass.STATIC.name:
        raise TdinfoParserUnsupportedSymbolClassException()

    symbol_ea = image_base + symbol.segment * 0x10 + symbol.offset
    symbol_name = name_pool[symbol.index - 1].encode('ascii')

    if ida_name.get_name(symbol_ea) == symbol_name:
        raise TdinfoParserSymbolAlreadyAppliedException()

    if (ida_name.set_name(symbol_ea, symbol_name)):
        print('Applied name {} to address {:04X}:{:04X}'.format(
            symbol_name,
            image_base / 0x10 + symbol.segment,
            symbol.offset))
    else:
        raise TdinfoParserIdaSetNameFailedException()


def apply_tdinfo_symbols():
    # A heuristic, since get_imagebase returns wrong result
    image_base = idc.get_first_seg()

    parsed_exe_file = _parse_exe_file()

    applied_symbols_count = 0
    already_existing_symbols_count = 0
    for symbol in parsed_exe_file.symbol_records:
        try:
            _apply_tdinfo_symbol(image_base, parsed_exe_file.name_pool, symbol)
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
