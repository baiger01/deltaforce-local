"""Bind installed safehouse exports to complete native reflected field records."""

import hashlib
import json
import mmap
from pathlib import Path
import re
import struct

import pefile

from explore_tagged_export import read_row
from local_game_paths import game_paths
from lua53_reader import Reader, walk
from scan_weapon_tables import decode_content, parse_entry


ROOT = Path(__file__).resolve().parent.parent
PROTOCOL = ROOT / 'outputs/df-local-server/protocol'
PAK = 'pak-0-0-pakchunk2-WindowsClient.pak'
EXPECTED_PE = '4254fbe66585f260f1f9dbfc5e302887842552e7baed8939e023160a5e250be0'
TABLES = {
    'formulas': (7068, 50337145, 'SafeHouseFormula', 489441296, 413672064, 19),
    'upgrades': (7072, 50353481, 'SafeHouseUpgrade', 489441376, 413654576, 14),
}
LUA_PAK = 'pak-0-0-pakchunk1-WindowsClient.pak'
LUA_SOURCES = {
    'BlackSiteProductionLine.lua': (1727, 8169472, 'dc4f8039ff5c721d1cf95c30bd631e71eae48f8711f7b27d1f07cf0f93999f77'),
    'QuestLineStruct.lua': (1833, 8540160, '71410bc0a0e0d9cc65c0f99e98ba2192af9fd5bfbef7438efeaaab61f7213f28'),
    'QuestStruct.lua': (1838, 8568832, '4a66e646387aa90a95ecb6e4a786722093ca6590ae571ffe88ecd03c733fb821'),
    'common_pb.lua': (6645, 31748096, '81e071e35f33f0e5704d5098ac2a182c794bbe5b1e5a7e24f415a0473b40350b'),
    'BlackSiteServer.lua': (6854, 34129920, '69389419f7b0fb5e3b993c2e65fa2b46f659e3e50c3cf2f375d94d519f6ae890'),
    'QuestServer.lua': (6919, 34859008, '66923c74fb9516e33c5e50676b422bfc4183b3604b4b0d4947cb38dc9f97881c'),
}
SCALAR_TYPES = {'int': ('<i', 3), 'int32': ('<i', 3), 'int64': ('<q', 4),
                'uint64': ('<Q', 7), 'float': ('<f', 10)}


def source_structs(tables):
    path = game_paths()[0] / 'DeltaForce/Binaries/Win64/DeltaForceClient-Win64-Shipping.exe'
    with path.open('rb') as handle:
        header = handle.read(65536)
    pe = pefile.PE(data=header, fast_load=True)
    start = pe.DOS_HEADER.e_lfanew + 24 + pe.FILE_HEADER.SizeOfOptionalHeader
    sections = []
    for index in range(pe.FILE_HEADER.NumberOfSections):
        _, va, size, raw = struct.unpack_from('<4I', header, start + index * 40 + 8)
        sections.append((raw, size, pe.OPTIONAL_HEADER.ImageBase + va))
    with path.open('rb') as handle, mmap.mmap(handle.fileno(), 0, access=mmap.ACCESS_READ) as data:
        if hashlib.sha256(data).hexdigest() != EXPECTED_PE:
            raise ValueError('Installed native executable changed')

        def raw_offset(address):
            offsets = [raw + address - va for raw, size, va in sections if va <= address < va + size]
            if len(offsets) != 1:
                raise ValueError('Native pointer does not map to one source section')
            return offsets[0]

        def text(address):
            offset = raw_offset(address)
            return data[offset:offset + 128].split(b'\0')[0].decode('ascii')

        result = {}
        for group, (_, _, name, params_offset, descriptor_offset, count) in tables.items():
            params = struct.unpack_from('<9Q', data, params_offset)
            if text(params[3]) != name or params[7] >> 32 != 0x45:
                raise ValueError('Native struct registration changed')
            records = []
            array_offset = raw_offset(params[6])
            for pointer in struct.unpack_from('<' + 'Q' * (params[7] & 0xffffffff), data, array_offset):
                offset = raw_offset(pointer)
                values = struct.unpack_from('<5Q', data, offset)
                flags, member = values[3] & 0xffffffff, values[4] >> 32
                if member == 0:
                    continue
                records.append({'name': text(values[0]), 'gen_flags': flags,
                                'property_record_offset': offset, 'member_offset': member})
            records.reverse()
            if len(records) != count:
                raise ValueError('Native reflected property count changed')
            columns = []
            for index, record in enumerate(records):
                offset = descriptor_offset + index * 24
                name_pointer, kind_pointer, member = struct.unpack_from('<3Q', data, offset)
                kind = text(kind_pointer)
                if text(name_pointer) != record['name']:
                    raise ValueError('Native descriptor and reflected field order differ')
                expected_flags = (SCALAR_TYPES[kind][1] if kind in SCALAR_TYPES else
                                  21 if kind == 'FString' else 29 if kind == 'FText' else
                                  76 if kind == 'bool' else 22 if kind.startswith('TArray<') else None)
                if record['gen_flags'] != expected_flags or (kind != 'bool' and member != record['member_offset']):
                    raise ValueError('Native descriptor type/member differs from reflection')
                columns.append({**record, 'kind': kind, 'member_offset': member,
                                'descriptor_offset': offset})
            result[group] = {'struct': name, 'struct_params_offset': params_offset,
                             'size': params[4], 'columns': columns}
        return result


def installed_export(entry, offset, *, pak=PAK):
    path = game_paths()[0] / 'DeltaForce/Content/Paks' / pak
    with path.open('rb') as handle:
        handle.seek(-512, 2)
        tail = handle.read(512)
        marker = tail.rfind(struct.pack('<I', 0x5a6f12e1))
        if marker < 0:
            raise ValueError('Installed source PAK footer is missing')
        _, limit = struct.unpack_from('<IQ', tail, marker + 4)
        methods = [match[:-1].decode('ascii') for match in re.findall(
            rb'(?:Oodle|Zlib|Gzip|LZ4|Zstd)\x00', tail)]
        record = parse_entry(handle, offset, limit, variant='observed_permutation')
        raw = decode_content(handle, offset, record, methods)
    if raw is None:
        raise ValueError('Native table export is not readable')
    return raw, {'pak': pak, 'entry': entry, 'pak_offset': offset,
                 'sha256': hashlib.sha256(raw).hexdigest(), 'size': len(raw)}


def string_value(raw):
    length, = struct.unpack_from('<i', raw)
    if length == 0 and len(raw) == 4:
        return ''
    width = 1 if length > 0 else 2
    count = abs(length)
    if count < 1 or len(raw) != 4 + count * width or raw[-width:] != b'\0' * width:
        raise ValueError('Native FString length/terminator differs')
    return raw[4:-width].decode('utf-8' if width == 1 else 'utf-16-le')


def field_value(raw, tag, kind):
    value = raw[tag['value_start']:tag['end']]
    if kind in SCALAR_TYPES:
        fmt = SCALAR_TYPES[kind][0]
        if tag['metadata_bytes'] or len(value) != struct.calcsize(fmt):
            raise ValueError('Native scalar serialization differs')
        return struct.unpack(fmt, value)[0]
    if kind == 'FString':
        if tag['metadata_bytes']:
            raise ValueError('Native string serialization differs')
        return string_value(value)
    if kind == 'bool':
        if tag['metadata_bytes'] != 1 or value:
            raise ValueError('Native bool serialization differs')
        return bool(raw[tag['offset'] + 24])
    if kind.startswith('TArray<'):
        if tag['metadata_bytes'] != 8:
            raise ValueError('Native array serialization differs')
        element = kind[7:-1]
        if element == 'EQuestGoalForbiddenType':
            count, = struct.unpack_from('<i', value)
            if count < 0 or len(value) != 4 + count * 8:
                raise ValueError('Native enum-name array serialization differs')
            return [{'fname_hex': value[4 + index * 8:12 + index * 8].hex()}
                    for index in range(count)]
        fmt = '<q' if element == 'int64' else '<I' if element == 'uint32' else '<i'
        count, = struct.unpack_from('<i', value)
        if count < 0 or len(value) != 4 + count * struct.calcsize(fmt):
            raise ValueError('Native array element size/count differs')
        return [item[0] for item in struct.iter_unpack(fmt, value[4:])]
    if kind == 'FText':
        if tag['metadata_bytes']:
            raise ValueError('Native text serialization differs')
        return {'serialized_hex': value.hex()}
    raise ValueError('Unsupported verified native field type: ' + kind)


def extract_tables(tables):
    reflected = source_structs(tables)
    sources, recovered = {}, {}
    for group, (entry, pak_offset, *_) in tables.items():
        raw, source = installed_export(entry, pak_offset)
        root = 29 if struct.unpack_from('<i', raw, 37)[0] == 0 else 55
        none, instance, prefix, count = struct.unpack_from('<iiii', raw, root)
        if instance or prefix:
            raise ValueError('Unexpected native table prefix')
        columns = reflected[group]['columns']
        offset, layout, signature, rows, mapping = root + 16, {}, None, [], {}
        for row_index in range(count):
            start = offset
            tags, offset, current_layout = read_row(raw, offset + 8, none, known_types=layout)
            layout = dict(current_layout)
            if len(tags) != len(columns) + 1:
                raise ValueError('Native table has different complete reflected property count')
            current_signature = [(tag['field'], tag['kind'], tag['metadata_bytes']) for tag in tags]
            if signature is not None and signature != current_signature:
                raise ValueError('Native serialized property order changes across rows')
            signature = current_signature
            row = {'source_row': row_index, 'serialized_offset': start}
            for tag, column in zip(tags, columns):
                row[column['name']] = field_value(raw, tag, column['kind'])
                mapping[column['name']] = tag['field']
            inherited = tags[-1]
            if inherited['size'] != 8 or inherited['metadata_bytes']:
                raise ValueError('Inherited native row-key FName differs')
            row['row_key_fname_hex'] = raw[inherited['value_start']:inherited['end']].hex()
            rows.append(row)
        if raw[offset:] != b'\xc1\x83\x2a\x9e':
            raise ValueError('Native table has an unparsed trailer')
        sources[group] = {**source, **reflected[group], 'row_count': count,
                          'serialized_field_indices': mapping, 'name_map_available': False}
        recovered[group] = rows
    return sources, recovered


def lua_source(name):
    entry, offset, expected = LUA_SOURCES[name]
    raw, source = installed_export(entry, offset, pak=LUA_PAK)
    if source['sha256'] != expected:
        raise ValueError('Installed client Lua hash changed: ' + name)
    root = Reader(raw, allow_client_format1=True).function()
    if root['source'] != '@' + name:
        raise ValueError('Client Lua source identity changed')
    return root, {'source': root['source'], **source}


def consumer(name, required):
    root, source = lua_source(name)
    functions = {function['id']: function for function in walk(root)}
    for function_id, constants in required.items():
        if not all(value in functions[function_id]['constants'] for value in constants):
            raise ValueError('Native consumer changed: ' + name)
    return {**source, 'functions': list(required)}


def main():
    sources, rows = extract_tables(TABLES)
    formulas = rows['formulas']
    ids = [row['Id'] for row in formulas]
    if len(ids) != len(set(ids)) or any(row['Id'] <= 0 or row['DeviceId'] <= 0 for row in formulas):
        raise ValueError('Invalid or duplicate source formula ID')
    report = {'native_pe_sha256': EXPECTED_PE,
        'mapping_status': 'verified_by_native_reflection_and_serialization',
        'sources': sources, **rows,
        'client_consumers': {
            'server': consumer('BlackSiteServer.lua', {'0.3': ['SafeHouse/SafeHouseUpgrade'],
                '0.13': ['CSSafehouseProduceReq', 'device_id', 'formula_id'],
                '0.13.0': ['produce_info', 'StartProduce']}),
            'production': consumer('BlackSiteProductionLine.lua', {'0.1': ['MaterialList', 'ProductList', 'Time'],
                '0.2': ['start_time', 'end_time', 'products'], '0.31': ['startTimeLimit', 'endTimeLimit']})},
        'limitations': ['Source dates are retained exactly; expired recipes are not silently re-dated.',
                       'Weighted products and blueprint/leader unlocks require separate verified handlers.',
                       'Prefab weapon products with no source physical layout require verified receiver/component grants; they are rejected before consuming materials.'],
        'local_policy': ['Production uses the original unmodified duration and deterministic ProductList.',
                         'Source date strings use UTC+08:00 for this Chinese client installation, independently of the server host timezone.',
                         'Loose player inventory props are eligible materials; loaded weapon ammunition is not consumed.']}
    output = PROTOCOL / 'native_safehouse_catalog.json'
    output.write_text(json.dumps(report, ensure_ascii=True, indent=2) + '\n', encoding='utf-8')
    print({'formulas': len(formulas), 'upgrades': len(rows['upgrades'])})


if __name__ == '__main__':
    main()
