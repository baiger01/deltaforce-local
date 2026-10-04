"""Cross-check original PE property registrations against every original BP row.

Read-only inputs. The report is evidence under work/evidence; production
catalogs and mutation gates are never written by this verifier.
"""

import hashlib
import json
import mmap
from pathlib import Path
import re
import struct

import pefile

from explore_tagged_export import read_row
from local_game_paths import game_paths
from scan_weapon_tables import decode_content, parse_entry


ROOT = Path(__file__).resolve().parent.parent
EXPECTED_PE = '4254fbe66585f260f1f9dbfc5e302887842552e7baed8939e023160a5e250be0'
GROUPS = {
    'archives': (6358, 'BattlePassArchive', 413541064, 'ArchiveName'),
    'bonuses': (6360, 'BattlePassBonus', 413477528, 'BonusRate'),
    'clues': (6362, 'BattlePassClue', 413570376, 'ClueBrief'),
    'expr_cards': (6364, 'BattlePassExprCard', 413635048, 'Expr'),
    'levels': (6368, 'BattlePassLevel', 413502216, 'FreeReward1'),
    'packs': (6370, 'BattlePassPack', 413605080, 'OriginalPrice'),
    'seasons': (6372, 'BattlePassSeason', 413437720, 'LevelExpr'),
}
SIZES = {'int32': 4, 'int64': 8, 'float': 4, 'FString': None, 'FText': None}


def sha256(path):
    digest = hashlib.sha256()
    with path.open('rb') as handle:
        for block in iter(lambda: handle.read(8 * 1024 * 1024), b''):
            digest.update(block)
    return digest.hexdigest()


def original_exports(source):
    path = source / 'DeltaForce/Content/Paks/pak-0-0-pakchunk2-WindowsClient.pak'
    wanted = {group[0] for group in GROUPS.values()}
    results = {}
    with path.open('rb') as handle:
        handle.seek(-512, 2)
        tail = handle.read(512)
        marker = tail.rfind(struct.pack('<I', 0x5a6f12e1))
        _, limit = struct.unpack_from('<IQ', tail, marker + 4)
        methods = [match[:-1].decode('ascii') for match in re.findall(
            rb'(?:Oodle|Zlib|Gzip|LZ4|Zstd)\x00', tail)]
        position = number = 0
        while position < limit and number < max(wanted):
            try:
                try:
                    entry = parse_entry(handle, position, limit)
                except (ValueError, struct.error):
                    entry = parse_entry(handle, position, limit, variant='observed_permutation')
            except (ValueError, struct.error):
                aligned = (position + 2047) // 2048 * 2048
                handle.seek(position)
                if aligned >= limit or handle.read(aligned - position) != bytes(aligned - position):
                    raise ValueError(f'Invalid PAK boundary at {position}')
                position = aligned
                entry = parse_entry(handle, position, limit, variant='observed_permutation')
            number += 1
            if number in wanted:
                data = decode_content(handle, position, entry, methods)
                if data is None:
                    raise ValueError(f'Expected readable table export {number}')
                results[number] = {'data': data, 'pak_offset': position,
                                   'sha256': hashlib.sha256(data).hexdigest()}
            position = entry['next_pos']
    if set(results) != wanted:
        raise ValueError('Missing original table exports')
    return results


def verify_bindings():
    source = game_paths()[0]
    path = source / 'DeltaForce/Binaries/Win64/DeltaForceClient-Win64-Shipping.exe'
    if sha256(path) != EXPECTED_PE:
        raise ValueError('PE version differs from the inspected original')
    exports = original_exports(source)
    pe = pefile.PE(str(path), fast_load=True)
    sections = [(section.PointerToRawData, min(section.SizeOfRawData, section.Misc_VirtualSize),
                 pe.OPTIONAL_HEADER.ImageBase + section.VirtualAddress)
                for section in pe.sections]
    report = {'pe_sha256': EXPECTED_PE, 'source_game': str(source), 'tables': {},
        'native_executable': {'path': str(path), 'size': path.stat().st_size,
            'image_base': pe.OPTIONAL_HEADER.ImageBase,
            'overlay_start': pe.get_overlay_data_start_offset(),
            'va_mapping': 'ImageBase + section.VirtualAddress + raw_offset - section.PointerToRawData',
            'sections': [{'name': section.Name.rstrip(b'\0').decode('ascii'),
                'raw_start': section.PointerToRawData, 'raw_size': section.SizeOfRawData,
                'rva_start': section.VirtualAddress, 'virtual_size': section.Misc_VirtualSize,
                'characteristics': section.Characteristics} for section in pe.sections]}}
    with path.open('rb') as handle, mmap.mmap(handle.fileno(), 0, access=mmap.ACCESS_READ) as data:
        def offset_va(offset):
            return next((base + offset - raw for raw, size, base in sections
                         if raw <= offset < raw + size), None)

        def va_offset(address):
            return next((raw + address - base for raw, size, base in sections
                         if base <= address < base + size), None)

        def text_at(address):
            offset = va_offset(address)
            if offset is None:
                return None
            value = data[offset:offset + 128].split(b'\0')[0]
            return value.decode('ascii') if value and all(32 <= byte < 127 for byte in value) else None

        def qwords(offset, count):
            return struct.unpack_from('<' + 'Q' * count, data, offset)

        def occurrences(needle):
            offset = data.find(needle)
            while offset >= 0:
                if offset % 8 == 0:
                    yield offset
                offset = data.find(needle, offset + 1)

        def descriptor(offset):
            if offset_va(offset) is None:
                return None
            name_pointer, kind_pointer, member_offset = qwords(offset, 3)
            name, kind = text_at(name_pointer), text_at(kind_pointer)
            if (name and re.fullmatch(r'[A-Za-z][A-Za-z0-9_]*', name)
                    and kind in SIZES and member_offset < 4096):
                return {'descriptor_offset': offset, 'descriptor_va': offset_va(offset),
                        'name': name, 'kind': kind, 'member_offset': member_offset,
                        'name_va': name_pointer, 'type_name_va': kind_pointer}
            return None

        def property_record(offset):
            if offset_va(offset) is None:
                return None
            name_pointer, rep_notify, flags, kind_flags, array_offset = qwords(offset, 5)
            name = text_at(name_pointer)
            if (name and re.fullmatch(r'[A-Za-z][A-Za-z0-9_]*', name) and not rep_notify
                    and kind_flags >> 32 == 0x45 and array_offset & 0xffffffff == 1
                    and array_offset >> 32 < 4096):
                return {'name': name, 'member_offset': array_offset >> 32,
                        'gen_flags': kind_flags & 0xffffffff, 'property_flags': flags,
                        'property_record_offset': offset, 'property_record_va': offset_va(offset)}
            return None

        for group, (entry, struct_name, anchor, pivot_name) in GROUPS.items():
            first = last = anchor
            while descriptor(first - 24):
                first -= 24
            while descriptor(last):
                last += 24
            fields = [descriptor(offset) for offset in range(first, last, 24)]
            if any(field['member_offset'] >= fields[index + 1]['member_offset']
                   for index, field in enumerate(fields[:-1])):
                raise ValueError(f'{group}: native descriptor offsets are not strictly ascending')
            pivot_index = next(i for i, field in enumerate(fields) if field['name'] == pivot_name)
            pivot = fields[pivot_index]
            registrations = []
            for record_offset in occurrences(struct.pack('<Q', pivot['name_va'])):
                record = property_record(record_offset)
                if record is None or record['member_offset'] != pivot['member_offset']:
                    continue
                for pointer_offset in occurrences(struct.pack('<Q', offset_va(record_offset))):
                    pointer_start = pointer_offset - (len(fields) - 1 - pivot_index) * 8
                    pointers = qwords(pointer_start, len(fields))
                    offsets = [va_offset(pointer) for pointer in pointers]
                    if None in offsets:
                        continue
                    records = [property_record(offset) for offset in offsets]
                    if any(record is None for record in records):
                        continue
                    records.reverse()
                    if [(record['name'], record['member_offset']) for record in records] != [
                            (field['name'], field['member_offset']) for field in fields]:
                        continue
                    for reference in occurrences(struct.pack('<Q', offset_va(pointer_start))):
                        params_start = reference - 48
                        params = qwords(params_start, 9)
                        if (offset_va(params_start) is not None and text_at(params[3]) == struct_name
                                and params[7] & 0xffffffff == len(fields)
                                and params[7] >> 32 == 0x45 and params[5] in (4, 8, 16)):
                            registrations.append({'struct_params_offset': params_start,
                                'struct_params_va': offset_va(params_start),
                                'struct_name': struct_name, 'size': params[4], 'alignment': params[5],
                                'super_constructor_va': params[1], 'property_count': len(fields),
                                'property_pointer_array_offset': pointer_start,
                                'property_pointer_array_va': offset_va(pointer_start),
                                'property_pointer_order': 'descending_member_offset',
                                'records_in_serialization_order': records})
            if len(registrations) != 1:
                raise ValueError(f'{group}: expected one complete named native registration, got {len(registrations)}')
            registration = registrations[0]
            if any(field['member_offset'] + (SIZES[field['kind']] or 1) > registration['size']
                   for field in fields):
                raise ValueError(f'{group}: field lies outside the registered structure size')
            raw = exports[entry]['data']
            cached = ROOT / 'work/evidence/matched_assets' / (
                f'pak-0-0-pakchunk2-WindowsClient.pak.entry-{entry}.bin')
            if hashlib.sha256(cached.read_bytes()).hexdigest() != exports[entry]['sha256']:
                raise ValueError(f'{group}: cached export does not match the current original')
            none_offset = 29 if struct.unpack_from('<i', raw, 37)[0] == 0 else 55
            none, instance, prefix, count = struct.unpack_from('<iiii', raw, none_offset)
            if instance or prefix:
                raise ValueError(f'{group}: unexpected table prefix')
            row_struct_reference = struct.unpack_from('<i', raw, 25)[0]
            kind_indices, gen_flags, mappings, rows = {}, {}, [], []
            tag_sequence = None
            offset, type_layout = none_offset + 16, {}
            for index in range(count):
                row_offset = offset
                tags, offset, layout = read_row(raw, offset + 8, none, known_types=type_layout)
                type_layout = dict(layout)
                if len(tags) != len(fields) + 1:
                    raise ValueError(f'{group}: row {index} native column count differs')
                signature = [(tag['field'], tag['kind'], tag['metadata_bytes']) for tag in tags]
                if tag_sequence is not None and signature != tag_sequence:
                    raise ValueError(f'{group}: row {index} field/type sequence differs')
                tag_sequence = signature
                if (raw[tags[-1]['value_start']:tags[-1]['end']] != struct.pack('<ii', none, 0)
                        or tags[-1]['size'] != 8 or tags[-1]['metadata_bytes'] != 0):
                    raise ValueError(f'{group}: terminal inherited FName is not the constant None default')
                if len({tag['field'] for tag in tags}) != len(tags):
                    raise ValueError(f'{group}: repeated serialized field index')
                for field, prop, tag in zip(fields, registration['records_in_serialization_order'], tags):
                    kind, size = field['kind'], SIZES[field['kind']]
                    if size is not None and tag['size'] != size:
                        raise ValueError(f'{group}: row {index} scalar width differs for {field["name"]}')
                    if tag['metadata_bytes'] != 0:
                        raise ValueError(f'{group}: unexpected scalar metadata')
                    if kind_indices.setdefault(kind, tag['kind']) != tag['kind']:
                        raise ValueError(f'{group}: property type FName index changed')
                    if gen_flags.setdefault(kind, prop['gen_flags']) != prop['gen_flags']:
                        raise ValueError(f'{group}: native property gen type changed')
                    if index == 0:
                        mappings.append({**field, **prop, 'field_index': tag['field'],
                            'type_index': tag['kind'], 'first_tag_offset': tag['offset'],
                            'first_value_offset': tag['value_start']})
                rows.append({'row': index, 'offset': row_offset, 'end': offset})
            if len(set(kind_indices.values())) != len(kind_indices):
                raise ValueError(f'{group}: native types cannot be uniquely distinguished by serialized type indices')
            if len(set(gen_flags.values())) != len(gen_flags):
                raise ValueError(f'{group}: native property registration types are ambiguous')
            if raw[offset:] != b'\xc1\x83\x2a\x9e':
                raise ValueError(f'{group}: trailing unparsed data')
            report['tables'][group] = {'entry': entry, 'pak_offset': exports[entry]['pak_offset'],
                'export_sha256': exports[entry]['sha256'], 'row_count': count,
                'row_struct_import_reference': row_struct_reference, 'none_index': none,
                'native_registration': registration, 'descriptor_start': first, 'descriptor_end': last,
                'bindings': mappings, 'kind_indices': kind_indices, 'native_gen_flags': gen_flags,
                'all_rows': rows, 'all_rows_have_identical_field_and_type_order': True,
                'terminal_inherited_name_field_index': tags[-1]['field'],
                'terminal_inherited_name_is_constant_none': True}
    report['binding_status'] = 'verified_by_native_reflection_and_serialization'
    report['scope'] = 'Complete derived row columns, not the encrypted package-wide name map'
    report['limitations'] = [
        'The terminal inherited FName field is checked as the constant None default but is not named by this verifier.',
        'RowStruct import names are in encrypted companions; structure identity is established by the unique complete native typed registration and serialization order.',
        'The latest installed season does not establish an official current season or dates.',
        'Client-specific price discounts and eligibility checks must still be handled separately.',
        'This verifier never enables mutations or changes production catalogs.']
    return report


def main():
    report = verify_bindings()
    output = ROOT / 'work/evidence/battlepass-reflection-bindings-20261001.json'
    output.write_text(json.dumps(report, indent=2, ensure_ascii=True) + '\n', encoding='utf-8')
    for group, table in report['tables'].items():
        print(group, table['native_registration']['struct_name'], table['row_count'],
              'rows', len(table['bindings']), 'native columns')
    print(output)


if __name__ == '__main__':
    main()
