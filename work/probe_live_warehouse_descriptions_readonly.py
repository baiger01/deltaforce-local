"""Read only warehouse description config rows and bounded linked text candidates.

Uses the existing verified shadow-only process reader and DataTable accessors.
FString candidates retain pointer paths; they are not asserted to be the result
of executing FText::ToString. No code executes inside the client process.
"""

import ast
import argparse
import os
from pathlib import Path
import struct
import sys

import probe_live_keybox_registration as probe
from local_game_paths import game_paths


TARGET_IDS = {10100102, 10100104, 10100106, 10100108, 10100110,
              *range(10100202, 10100211)}


def exact_link_candidates(read, root):
    """Capture the observed reference/entry chain without traversing neighbors."""
    result = {'status': 'unverified_reference_entry_chain'}
    try:
        root_header = read(root, 48, module_only=False)
        reference = struct.unpack_from('<Q', root_header, 24)[0]
        reference_header = read(reference, 64, module_only=False)
        entry = struct.unpack_from('<Q', reference_header, 40)[0]
        result.update(reference_address=reference, reference_64_bytes_hex=reference_header.hex(),
                      entry_address=entry)
        if entry:
            entry_header = read(entry, 64, module_only=False)
            result['entry_64_bytes_hex'] = entry_header.hex()
            pointer, count, capacity = struct.unpack_from('<Qii', entry_header, 16)
            if pointer and 1 <= count <= capacity <= 2048:
                value = read(pointer, count * 2, module_only=False)
                if value[-2:] == b'\0\0':
                    result.update(entry_plus_16_fstring=value[:-2].decode('utf-16-le'),
                                  entry_plus_16_fstring_address=entry + 16)
            shared_string = struct.unpack_from('<Q', entry_header, 32)[0]
            if shared_string:
                shared_header = read(shared_string, 16, module_only=False)
                result.update(entry_plus_32_shared_string_address=shared_string,
                              shared_string_16_bytes_hex=shared_header.hex())
                pointer, count, capacity = struct.unpack('<Qii', shared_header)
                if pointer and 1 <= count <= capacity <= 2048:
                    value = read(pointer, count * 2, module_only=False)
                    if value[-2:] == b'\0\0':
                        result['entry_plus_32_shared_string'] = value[:-2].decode('utf-16-le')
                if read(shared_string, 16, module_only=False) != shared_header:
                    raise ValueError('Shared string changed during read')
            if read(entry, 64, module_only=False) != entry_header:
                raise ValueError('Linked entry changed during read')
        if read(reference, 64, module_only=False) != reference_header:
            raise ValueError('Linked reference changed during read')
    except (OSError, ValueError, UnicodeError, struct.error) as error:
        result['read_error'] = str(error)
    return result


def accessor_code(read, root):
    """Read only code reached by the observed ITextData virtual slot 2 call."""
    capstone = probe.capstone_module()
    decoder = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
    decoder.detail = True
    vtable = struct.unpack('<Q', read(root, 8, module_only=False))[0]
    target = struct.unpack('<Q', read(vtable + 16, 8))[0]
    virtual_code = read(target, 128)
    calls = [ins.operands[0].imm for ins in decoder.disasm(virtual_code, target)
             if ins.mnemonic == 'call' and len(ins.operands) == 1
             and ins.operands[0].type == capstone.x86.X86_OP_IMM]
    if len(calls) != 1:
        raise ValueError('Expected the single observed ITextData slot 2 direct call')
    helper = calls[0]
    helper_code = read(helper, 1024)
    instructions = list(decoder.disasm(helper_code, helper))
    direct_targets = list(dict.fromkeys(ins.operands[0].imm for ins in instructions
        if ins.mnemonic in ('call', 'jmp') and len(ins.operands) == 1
        and ins.operands[0].type == capstone.x86.X86_OP_IMM))[:12]
    return {'virtual_slot': 2, 'virtual_target': target, 'virtual_code_hex': virtual_code.hex(),
            'helper_address': helper, 'helper_1024_bytes_hex': helper_code.hex(),
            'helper_instructions': [{'address': ins.address, 'op': ins.mnemonic, 'args': ins.op_str}
                                    for ins in instructions],
            'direct_targets': [{'address': address, 'first_512_code_bytes': read(address, 512).hex(),
                                **({'first_2304_code_bytes': read(address, 2304).hex()}
                                   if index == 0 else {})}
                               for index, address in enumerate(direct_targets)]}


def string_candidates(read, root):
    result, seen, pending = [], set(), [(root, [])]
    interface = None
    root_hex = None
    while pending and len(seen) < 40:
        address, chain = pending.pop(0)
        if address in seen or not 0x10000 <= address < 0x800000000000 - 80 or address % 8:
            continue
        seen.add(address)
        try:
            raw = read(address, 80, module_only=False)
        except (OSError, ValueError):
            continue
        if address == root:
            root_hex = raw.hex()
            vtable = struct.unpack_from('<Q', raw)[0]
            try:
                targets = struct.unpack('<8Q', read(vtable, 64))
                interface = {'vtable_address': vtable, 'candidate_virtual_targets': []}
                for slot, target in enumerate(targets):
                    try:
                        interface['candidate_virtual_targets'].append({'slot': slot,
                            'address': target, 'first_96_code_bytes': read(target, 96).hex()})
                    except (OSError, ValueError):
                        pass
            except (OSError, ValueError):
                pass
        for offset in range(0, 65, 8):
            pointer, count, capacity = struct.unpack_from('<Qii', raw, offset)
            if (0x10000 <= pointer < 0x800000000000 - 1024 and pointer % 2 == 0
                    and 1 <= count <= 256 and count <= capacity <= 2048):
                try:
                    text = read(pointer, count * 2, module_only=False)
                    if text[-2:] != b'\0\0':
                        continue
                    value = text[:-2].decode('utf-16-le')
                    if value and all(ord(char) >= 32 or char in '\r\n\t' for char in value):
                        result.append({'fstring_address': address + offset,
                            'pointer_path': chain + [offset], 'text': value,
                            'utf16_code_units_including_terminator': count})
                except (OSError, ValueError, UnicodeError):
                    pass
            if len(chain) < 3 and 0x200000000 <= pointer < 0x800000000000:
                pending.append((pointer, chain + [offset]))
        if read(address, 80, module_only=False) != raw:
            raise ValueError('Configuration-linked text changed during read')
    return {'root_address': root, 'nodes_read': len(seen), 'candidates': result,
            'root_80_bytes_hex': root_hex, 'text_data_interface_candidates': interface,
            'exact_link_candidates': exact_link_candidates(read, root)}


def capture_description_rows(read, result):
    if not result['rowmap_accessor_code_hex'].startswith('488d4130c3'):
        result.update(rowmap_status='skipped', rowmap_reason='unsupported_rowmap_accessor')
        return
    address = result['source_table_address'] + 0x30
    header = read(address, 56, module_only=False)
    slots, count, capacity = struct.unpack_from('<Qii', header)
    bits, bit_count, bit_capacity = struct.unpack_from('<Qii', header, 0x20)
    free = struct.unpack_from('<i', header, 0x34)[0]
    if not slots or not 0 <= free <= count <= capacity <= 512 or bit_count != count or bit_capacity < count:
        raise ValueError('Invalid description RowMap bounds')
    bit_bytes = ((bit_count + 31) // 32) * 4
    if bits:
        bit_data = read(bits, bit_bytes, module_only=False)
    elif bit_bytes <= 16:
        bit_data = header[0x10:0x10 + bit_bytes]
    else:
        raise ValueError('Unsupported inline description allocation bits')
    allocated = [index for index in range(count) if bit_data[index // 8] & (1 << (index % 8))]
    if len(allocated) != count - free:
        raise ValueError('Description RowMap allocation count differs')
    rows = []
    for index in allocated:
        slot = read(slots + index * 24, 24, module_only=False)
        pointer = struct.unpack_from('<Q', slot, 8)[0]
        if not 0x10000 <= pointer < 0x800000000000 - 112:
            raise ValueError('Invalid description row pointer')
        row_id = struct.unpack('<i', read(pointer + 16, 4, module_only=False))[0]
        if row_id not in TARGET_IDS:
            continue
        raw = read(pointer, 112, module_only=False)
        row = {'id': row_id, 'row_address': pointer, 'row_hex': raw.hex(), 'text_fields': {}}
        for name, offset in (('Description', 24), ('StartValue', 48), ('EndValue', 72)):
            text_data = struct.unpack_from('<Q', raw, offset)[0]
            row['text_fields'][name] = string_candidates(read, text_data) if text_data else None
        if read(pointer, 112, module_only=False) != raw:
            raise ValueError('Description row changed during read')
        rows.append(row)
    if read(address, 56, module_only=False) != header:
        raise ValueError('Description RowMap changed during read')
    result.update(rowmap_status='captured_warehouse_description_rows', row_slot_count=count,
                  row_free_count=free, rows=rows,
                  field_binding='SafeHouseDescription native registration489440976: Id16, Description24, StartValue48, EndValue72, size112',
                  text_status='bounded_linked_fstring_candidates_not_executed_FText_ToString')
    if rows:
        result['text_accessor_code'] = accessor_code(read, rows[0]['text_fields']['Description']['root_address'])


def warehouse_capture():
    source = Path(__file__).with_name('read_keybox_rowmap.py')

    class DescriptionScope(ast.NodeTransformer):
        def visit_Constant(self, node):
            replacement = {'KeyBox': 'SafeHouseDescription',
                           'Key/KeyBox': 'SafeHouse/SafeHouseDescription'}.get(node.value) if isinstance(node.value, str) else None
            return ast.copy_location(ast.Constant(replacement), node) if replacement else node

    tree = DescriptionScope().visit(ast.parse(source.read_text(encoding='utf-8')))
    ast.fix_missing_locations(tree)
    namespace = {'__file__': str(source), '__name__': 'warehouse_description_source_scope'}
    exec(compile(tree, str(source), 'exec'), namespace)
    namespace['capture_rows'] = capture_description_rows
    return namespace['capture']


def main():
    parser = argparse.ArgumentParser(add_help=False)
    parser.add_argument('--source-game', required=True)
    parser.add_argument('--shadow-game', required=True)
    args, forwarded = parser.parse_known_args()
    source, shadow = game_paths(args.source_game, args.shadow_game)
    os.environ['DF_LOCAL_SOURCE_GAME'] = str(source)
    os.environ['DF_LOCAL_SHADOW_GAME'] = str(shadow)
    sys.argv = [sys.argv[0], *forwarded]
    capture = warehouse_capture()

    def descriptions(read, base, config_map):
        results = [capture(read, base, config_map, table_name=name)
                   for name in ('SafeHouseDescription', 'SafeHouse/SafeHouseDescription')]
        return {'status': 'warehouse_description_probe', 'warehouse_descriptions': results,
                'read_policy': 'verified configuration rows only; bounded linked text; no account objects, writes or code execution'}

    probe.capture_keybox_rows = descriptions
    probe.capture_keybox_rowmap = lambda *args, **kwargs: {'status': 'skipped', 'reason': 'warehouse_scope_only'}
    probe.main()


if __name__ == '__main__':
    main()
