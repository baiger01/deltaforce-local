"""Extract numeric safety-box layouts without guessing encrypted field names."""

import hashlib
import json
from pathlib import Path
import struct

from extract_operator_avatar_catalog import tags
from extract_prop_slot_catalog import name_map


ROOT = Path(__file__).resolve().parent.parent
PAK = 'pak-0-0-pakchunk2-WindowsClient.pak'
SOURCE = ROOT / 'work/evidence/matched_assets' / f'{PAK}.entry-7056.uexp'
EXPECTED = '67e8779e53eba3eaaad941d177ad9baf4e49e06a83d3384438132d5ad9154480'
TARGET = ROOT / 'outputs/df-local-server/protocol/safe_box_layout_catalog.json'


def main():
    data = SOURCE.read_bytes()
    if hashlib.sha256(data).hexdigest() != EXPECTED:
        raise ValueError('Unverified safety-box export')
    names = [f'field_{index}' for index in range(128)]
    for index, name in {53: 'None', 43: 'BoolProperty', 50: 'IntProperty',
                        54: 'ObjectProperty', 63: 'UInt64Property'}.items():
        names[index] = name
    _, offset = tags(data, 0, names, len(data))
    prefix, count = struct.unpack_from('<ii', data, offset)
    if (prefix, count) != (0, 38):
        raise ValueError('Unexpected safety-box table prefix')
    offset += 8
    game_items = ROOT / 'outputs/df-local-server/protocol/game_item_catalog.json'
    metadata = json.loads(game_items.read_text(encoding='utf-8'))['rows']
    rows = {}
    for index in range(count):
        row_offset = offset
        properties, offset = tags(data, offset + 8, names, len(data))
        fields = {tag['name']: tag for tag in properties}
        values = {}
        for field, name, kind, fmt in ((51, 'template_id', 'UInt64Property', '<Q'),
                                     (48, 'dimension_a', 'IntProperty', '<i'),
                                     (49, 'dimension_b', 'IntProperty', '<i'),
                                     (62, 'capacity', 'IntProperty', '<i')):
            tag = fields[f'field_{field}']
            if tag['kind'] != kind or tag['size'] != struct.calcsize(fmt):
                raise ValueError('Unexpected safety-box numeric property')
            values[name] = struct.unpack_from(fmt, data, tag['value_start'])[0]
        item_id = str(values.pop('template_id'))
        if item_id not in metadata or not item_id.startswith('1109') or item_id in rows:
            raise ValueError('Invalid safety-box template ID')
        if not 1 <= values['dimension_a'] <= 20 or not 1 <= values['dimension_b'] <= 20:
            raise ValueError('Invalid safety-box dimensions')
        if values['capacity'] != values['dimension_a'] * values['dimension_b']:
            raise ValueError('Safety-box capacity does not match dimensions')
        rows[item_id] = {**values, 'serialized_row_offset': row_offset,
                        'source_row_index': index}
    if data[offset:] != b'\xc1\x83\x2a\x9e':
        raise ValueError('Unexpected safety-box table trailer')
    slot_source = ROOT / 'work/evidence/prop_slot_config'
    uasset = (slot_source / 'PropSlotConfig.uasset').read_bytes()
    uexp = (slot_source / 'PropSlotConfig.uexp').read_bytes()
    slot_names = name_map(uasset)
    needle = struct.pack('<iiii', slot_names.index('109001'), 0, slot_names.index('PageId'), 0)
    slot_offset = uexp.index(needle)
    properties, _ = tags(uexp, slot_offset + 8, slot_names, len(uexp))
    ignored = next(tag for tag in properties if tag['name'] == 'IgnorePropTypes')
    if ignored['kind'] != 'StrProperty':
        raise ValueError('Unexpected safety-box exclusion list')
    length = struct.unpack_from('<i', uexp, ignored['value_start'])[0]
    raw = uexp[ignored['value_start'] + 4:ignored['end']]
    text = raw.decode('utf-16le').rstrip('\0') if length < 0 else raw.rstrip(b'\0').decode('utf-8')
    ignored_types = text.split(',')
    if not all(value.isdecimal() for value in ignored_types):
        raise ValueError('Invalid safety-box exclusion prefix')
    report = {'source_pak': PAK, 'source_entry': 7056, 'source_uexp_sha256': EXPECTED,
              'row_count': count, 'dimension_direction_verified': False,
              'numeric_field_indices': {'template_id': 51, 'dimension_a': 48,
                                        'dimension_b': 49, 'capacity': 62},
              'game_item_catalog_sha256': hashlib.sha256(game_items.read_bytes()).hexdigest(),
              'contents_ignore_types': ignored_types,
              'contents_ignore_source': {'table': 'PropSlotConfig', 'row': '109001',
                                        'row_offset': slot_offset,
                                        'uexp_sha256': hashlib.sha256(uexp).hexdigest()},
              'rows': rows}
    TARGET.write_text(json.dumps(report, indent=2) + '\n', encoding='utf-8')
    print('verified safety-box layouts', len(rows))


if __name__ == '__main__':
    main()
