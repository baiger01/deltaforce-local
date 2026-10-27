"""Read original warehouse fields and consumers; never change service/account data."""

import argparse
import hashlib
import json
import mmap
from pathlib import Path
import re
import struct

import pefile

from explore_tagged_export import read_row
from extract_native_safehouse_catalog import (
    EXPECTED_PE, extract_tables, field_value, installed_export, TABLES,
)
from local_game_paths import game_paths
from lua53_reader import Reader, listing, walk
from scan_weapon_tables import decode_content, parse_entry


ROOT = Path(__file__).resolve().parent.parent
BOX_PARAMS = 489395040
BOX_DESCRIPTORS = 413118432
BOX_SHA = 'e20998feb112b48fbefebdae9f4ee185c04aea9a4c92a2b67dec32d6d1d05876'


def box_schema():
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
            raise ValueError('Original native executable changed')

        def raw_offset(address):
            offsets = [raw + address - va for raw, size, va in sections if va <= address < va + size]
            if len(offsets) != 1:
                raise ValueError('Native pointer does not map to one section')
            return offsets[0]

        def text(address):
            offset = raw_offset(address)
            return data[offset:offset + 128].split(b'\0')[0].decode('ascii')

        params = struct.unpack_from('<9Q', data, BOX_PARAMS)
        if text(params[3]) != 'ExtensionBoxDesc' or params[7] >> 32 != 0x45:
            raise ValueError('Original box struct registration differs')
        records = []
        count = params[7] & 0xffffffff
        for pointer in struct.unpack_from('<' + 'Q' * count, data, raw_offset(params[6])):
            offset = raw_offset(pointer)
            values = struct.unpack_from('<5Q', data, offset)
            member = values[4] >> 32
            if member:
                records.append({'name': text(values[0]), 'member_offset': member,
                    'gen_flags': values[3] & 0xffffffff, 'property_record_offset': offset})
        records.reverse()
        if len(records) != 20:
            raise ValueError('Complete original box property count differs')
        for index, record in enumerate(records):
            offset = BOX_DESCRIPTORS + index * 24
            name, kind, member = struct.unpack_from('<3Q', data, offset)
            kind = text(kind)
            flags = (7 if kind == 'uint64' else 0 if kind == 'uint8' else
                21 if kind == 'FString' else 22 if kind.startswith('TArray<') else
                16 if kind.startswith('TSoftObjectPtr<') else None)
            if (text(name) != record['name'] or member != record['member_offset']
                    or flags != record['gen_flags']):
                raise ValueError('Native box descriptor/reflection differs')
            record.update(kind=kind, descriptor_offset=offset)
    return {'struct': 'ExtensionBoxDesc', 'struct_params_offset': BOX_PARAMS,
            'native_pe_sha256': EXPECTED_PE, 'columns': records}


def box_rows(raw, columns):
    root = 29 if struct.unpack_from('<i', raw, 37)[0] == 0 else 55
    none, instance, prefix, count = struct.unpack_from('<4i', raw, root)
    if instance or prefix or count != 30:
        raise ValueError('Original box row prefix/count differs')
    offset, layout, signature, result, mapping = root + 16, {}, None, [], {}
    for index in range(count):
        start = offset
        tags, offset, layout = read_row(raw, offset + 8, none, known_types=layout)
        layout = dict(layout)
        if len(tags) != len(columns) + 1:
            raise ValueError('Complete box column count differs')
        current = [(tag['field'], tag['kind'], tag['metadata_bytes']) for tag in tags]
        if signature is not None and signature != current:
            raise ValueError('Box field order differs across original rows')
        signature = current
        row = {'source_row': index, 'serialized_offset': start}
        native_kinds, serialized_kinds = {}, {}
        for tag, column in zip(tags, columns):
            kind = column['kind']
            normalized = 'array' if kind.startswith('TArray<') else kind
            if (native_kinds.setdefault(normalized, tag['kind']) != tag['kind'] or
                    serialized_kinds.setdefault(tag['kind'], normalized) != normalized):
                raise ValueError('Native box property kinds do not bind one-to-one')
            if kind == 'uint8':
                if tag['size'] != 1 or tag['metadata_bytes'] != 8:
                    raise ValueError('Original uint8 ByteProperty differs')
                value = raw[tag['value_start']]
            elif kind in ('uint64', 'FString'):
                value = field_value(raw, tag, kind)
            else:
                value = {'opaque_serialized_hex': raw[tag['value_start']:tag['end']].hex(),
                         'metadata_bytes': tag['metadata_bytes']}
            row[column['name']] = value
            mapping[column['name']] = {'field': tag['field'], 'kind': tag['kind'],
                'metadata_bytes': tag['metadata_bytes'], 'value_offset_first_row':
                    mapping.get(column['name'], {}).get('value_offset_first_row', tag['value_start'])}
        inherited = tags[-1]
        if inherited['size'] != 8 or inherited['metadata_bytes']:
            raise ValueError('Box inherited row key differs')
        row['row_key_fname_hex'] = raw[inherited['value_start']:inherited['end']].hex()
        result.append(row)
    if raw[offset:] != b'\xc1\x83\x2a\x9e':
        raise ValueError('Original box table has an unparsed tail')
    return result, mapping


def consumer(name, entry, offset, expected, ids):
    raw, source = installed_export(entry, offset, pak='pak-0-0-pakchunk1-WindowsClient.pak')
    if source['sha256'] != expected:
        raise ValueError('Original Lua changed: ' + name)
    root = Reader(raw, allow_client_format1=True).function()
    if root['source'] != '@' + name:
        raise ValueError('Original Lua identity differs')
    functions = {fn['id']: fn for fn in walk(root)}
    return {**source, 'source': root['source'], 'functions': {ident: {
        'serialized_offset': functions[ident]['offset'],
        'instructions': listing(functions[ident]).splitlines()} for ident in ids}}


def scan_localization():
    names = ('10100102_Description', '10100102_EndValue', '10100110_EndValue',
             '10100202_Description', '10100202_EndValue', '20150010001_Name')
    needles = [(name, encoding, name.encode(encoding)) for name in names
               for encoding in ('utf-8', 'utf-16-le')]
    base = game_paths()[0] / 'DeltaForce/Content/Paks'
    paths = sorted((path for path in base.glob('*.pak')
                    if 'optional' not in path.name and 'uhd' not in path.name),
                   key=lambda path: path.stat().st_size)
    target = ROOT / 'work/evidence/native-warehouse-localization-search-20261020.json'
    report = {'scope': 'Read-only clear payload search; encrypted payloads and optional/UHD archives excluded.',
              'maximum_decoded_export_bytes': 100000000, 'needles': list(names),
              'archives': [], 'hits': []}
    if target.exists():
        report = json.loads(target.read_text(encoding='utf-8'))
    completed = {row['pak'] for row in report['archives'] if row['complete']}
    for path in paths:
        if path.name in completed:
            continue
        with path.open('rb') as handle:
            handle.seek(-512, 2)
            tail = handle.read(512)
            marker = tail.rfind(struct.pack('<I', 0x5a6f12e1))
            _, limit = struct.unpack_from('<IQ', tail, marker + 4)
            methods = [value[:-1].decode('ascii') for value in re.findall(
                rb'(?:Oodle|Zlib|Gzip|LZ4|Zstd)\x00', tail)]
            position = number = decoded = 0
            errors = {}
            while position < limit:
                try:
                    try:
                        entry = parse_entry(handle, position, limit)
                    except (ValueError, struct.error):
                        entry = parse_entry(handle, position, limit, variant='observed_permutation')
                except (ValueError, struct.error):
                    aligned = (position + 2047) // 2048 * 2048
                    handle.seek(position)
                    if aligned >= limit or handle.read(aligned - position) != bytes(aligned - position):
                        errors['invalid_boundary'] = position
                        break
                    position = aligned
                    entry = parse_entry(handle, position, limit, variant='observed_permutation')
                number += 1
                try:
                    raw = decode_content(handle, position, entry, methods, 100000000)
                    if raw:
                        decoded += 1
                        matches = [{'key': name, 'encoding': encoding, 'offset': raw.find(needle)}
                                   for name, encoding, needle in needles if needle in raw]
                        if matches:
                            record = {'pak': path.name, 'entry': number, 'pak_offset': position,
                                'sha256': hashlib.sha256(raw).hexdigest(), 'size': len(raw),
                                'matches': matches}
                            report['hits'].append(record)
                            print('HIT', record, flush=True)
                except (ValueError, struct.error, RuntimeError) as error:
                    kind = type(error).__name__
                    errors[kind] = errors.get(kind, 0) + 1
                position = entry['next_pos']
            record = {'pak': path.name, 'entries': number, 'decoded_exports': decoded,
                      'complete': position == limit, 'position': position, 'limit': limit,
                      'errors': errors}
            report['archives'] = [row for row in report['archives'] if row['pak'] != path.name]
            report['archives'].append(record)
            report['complete'] = {row['pak'] for row in report['archives'] if row['complete']} == {
                path.name for path in paths}
            target.write_text(json.dumps(report, ensure_ascii=True, indent=2) + '\n', encoding='utf-8')
            print('ARCHIVE', path.name, number, 'complete', record['complete'], flush=True)
    print('evidence', target, flush=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--localization-search', action='store_true')
    args = parser.parse_args()
    if args.localization_search:
        scan_localization()
        return
    schema = box_schema()
    raw, source = installed_export(6520, 48506569)
    if source['sha256'] != BOX_SHA:
        raise ValueError('Original box export changed')
    boxes, fields = box_rows(raw, schema['columns'])
    sources, tables = extract_tables({'upgrades': TABLES['upgrades']})
    upgrades = [row for row in tables['upgrades'] if row['DeviceId'] == 1010]
    if [row['Level'] for row in upgrades] != list(range(1, 11)):
        raise ValueError('Original warehouse sequence differs')
    report = {'scope': 'Original installation read only. No client launch, runtime edits or account writes.',
        'boxes': {'source': source, 'native': schema, 'serialized_fields': fields, 'rows': boxes},
        'warehouse_upgrades': {'source': sources['upgrades'], 'rows': upgrades},
        'consumers': {}, 'limitations': [
            'Localized item/upgrade labels are not inferred from identifiers.',
            'Type2 main-grid expansion units/aggregation still require a source or live-client witness.',
            'Opaque icon/text payloads are retained without invented decoding.']}
    for name, entry, offset, expected, ids in (
        ('InventoryServer_Network.lua', 6887, 34572288,
         'd7f83db2ae2cf4902b440131c15648c7b7d4b8b8f5e459231b9eb6ec17dcb0dc',
         ('0.5.0', '0.6', '0.6.0', '0.17', '0.18', '0.21', '0.21.0', '0.40', '0.50')),
        ('InventoryServer_DepositLogic.lua', 6884, 34549760,
         '594f6ef7896cae11051fd67d365160af4afb699b51c0febb794e7c9dc588bb84',
         ('0.11', '0.12', '0.13', '0.14', '0.15', '0.16', '0.17', '0.18', '0.20', '0.27')),
        ('ItemConfigTool.lua', 6989, 35528704,
         '85faf275693d6ee768653025895528252965347a14f387d6fd66e099ba4f016c', ('0.32',)),
        ('InventoryLogic.lua', 4264, 20758528,
         '6ea07fc739cd6e4898d37204e3cd2acf623e3b1661bf0daae90cbc7834cbd5d1', ('0.38.0',))):
        report['consumers'][name] = consumer(name, entry, offset, expected, ids)
    target = ROOT / 'work/evidence/native-warehouse-box-contract-20261020.json'
    target.write_text(json.dumps(report, ensure_ascii=True, indent=2) + '\n', encoding='utf-8')
    print('evidence', target)
    for row in boxes:
        print(row['ItemID'], row['GainPosLength'], row['GainPosWidth'],
              row['StorableItemTypeList'], row['ExcludeTypeList'], row['ExcludeQualityList'])


if __name__ == '__main__':
    main()
