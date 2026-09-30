"""Extract explicit container layout strings from clear installed UE exports."""

import hashlib
import json
from pathlib import Path
import re
import struct

from extract_operator_avatar_catalog import tags


ROOT = Path(__file__).resolve().parent.parent
PAK = 'pak-0-0-pakchunk2-WindowsClient.pak'
TARGET = ROOT / 'outputs/df-local-server/protocol/container_layout_catalog.json'
# Property type indices are serialized in these exports. The corresponding
# encrypted name maps are unavailable; retain field indices and offsets.
SOURCES = {
    'backpack': (6354, 52, 50, 42, 60, {53: 'ObjectProperty', 39: 'BoolProperty',
        49: 'IntProperty', 33: 'ArrayProperty', 58: 'StrProperty',
        62: 'UInt64Property'}),
    'chest_rig': (6434, 45, 43, 35, 53, {46: 'ObjectProperty', 42: 'IntProperty',
        28: 'ArrayProperty', 51: 'StrProperty', 55: 'UInt64Property'}),
}
LAYOUT = re.compile(r'\((\d+),(\d+)\)\((-?\d+),(-?\d+)\)')


def extract(kind, config):
    entry, none_index, id_index, layout_index, capacity_index, types = config
    source = ROOT / 'work/evidence/matched_assets' / f'{PAK}.entry-{entry}.uexp'
    data = source.read_bytes()
    names = [f'field_{index}' for index in range(128)]
    names[none_index] = 'None'
    for index, type_name in types.items():
        names[index] = type_name
    _, offset = tags(data, 0, names, len(data))
    prefix, count = struct.unpack_from('<ii', data, offset)
    if prefix != 0 or not 1 <= count <= 1000:
        raise ValueError('Invalid container table prefix')
    offset += 8
    rows, unavailable = {}, {}
    for _ in range(count):
        row_offset = offset
        offset += 8  # Serialized row FName; the ID is also in the UInt64 field.
        properties, offset = tags(data, offset, names, len(data))
        fields = {tag['name']: tag for tag in properties}
        id_tag = fields[f'field_{id_index}']
        text_tag = fields[f'field_{layout_index}']
        capacity_tag = fields[f'field_{capacity_index}']
        if (id_tag['kind'], id_tag['size']) != ('UInt64Property', 8):
            raise ValueError('Invalid container ID property')
        item_id = struct.unpack_from('<Q', data, id_tag['value_start'])[0]
        if text_tag['kind'] != 'StrProperty':
            raise ValueError('Invalid layout property')
        length = struct.unpack_from('<i', data, text_tag['value_start'])[0]
        if length < 0:
            text = data[text_tag['value_start'] + 4:text_tag['end']].decode('utf-16le').rstrip('\0')
            unavailable[str(item_id)] = {'raw_layout': text, 'reason': 'non-layout text',
                                        'serialized_row_offset': row_offset}
            continue
        if length == 0 and text_tag['size'] == 4:
            unavailable[str(item_id)] = {'raw_layout': '', 'reason': 'empty layout',
                                        'serialized_row_offset': row_offset}
            continue
        if length != text_tag['size'] - 4 or length <= 1:
            raise ValueError('Invalid layout string size')
        text = data[text_tag['value_start'] + 4:text_tag['end']].rstrip(b'\0').decode('ascii')
        segments = text.split('|')
        matches = [LAYOUT.fullmatch(segment) for segment in segments]
        if not all(matches):
            raise ValueError(f'Unrecognized explicit layout: {text!r}')
        spaces = [list(map(int, match.groups())) for match in matches]
        if any(not 1 <= width <= 20 or not 1 <= height <= 20
               for width, height, _, _ in spaces):
            raise ValueError('Invalid container dimensions')
        capacity = struct.unpack_from('<i', data, capacity_tag['value_start'])[0]
        if capacity != sum(width * height for width, height, _, _ in spaces):
            unavailable[str(item_id)] = {'raw_layout': text,
                'reason': 'declared capacity differs from explicit layout',
                'declared_capacity': capacity, 'serialized_row_offset': row_offset}
            continue
        if str(item_id) in rows:
            raise ValueError('Duplicate container ID')
        rows[str(item_id)] = {'kind': kind, 'capacity': capacity,
            'layout': [space[:2] for space in spaces], 'raw_layout': text,
            'serialized_row_offset': row_offset,
            'serialized_id_offset': id_tag['value_start'],
            'serialized_layout_offset': text_tag['value_start']}
    if data[offset:] != b'\xc1\x83\x2a\x9e':
        raise ValueError('Unexpected container table trailer')
    return rows, {'source_pak': PAK, 'source_entry': entry,
        'source_uexp_sha256': hashlib.sha256(data).hexdigest(),
        'row_count': count, 'id_property_index': id_index,
        'layout_property_index': layout_index, 'capacity_property_index': capacity_index,
        'unavailable_rows': unavailable}


def main():
    rows, sources = {}, {}
    for kind, config in SOURCES.items():
        extracted, source = extract(kind, config)
        rows.update(extracted)
        sources[kind] = source
    for item_id in ('11070004001', '11080004006', '11070002001', '11080006004'):
        print(item_id, rows[item_id])
    TARGET.write_text(json.dumps({'sources': sources, 'rows': rows}, indent=2) + '\n',
                      encoding='utf-8')
    print('container rows', len(rows))


if __name__ == '__main__':
    main()
