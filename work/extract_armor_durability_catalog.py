"""Read exact armor durability from the installed BodyArmorFunction table."""

import json
from pathlib import Path
import struct

from extract_game_item_catalog import scalar
from extract_operator_avatar_catalog import fname, tags
from extract_prop_slot_catalog import name_map


ROOT = Path(__file__).resolve().parent.parent
SOURCE = ROOT / 'work/evidence/armor_tables/BodyArmorFunction'
TARGET = ROOT / 'outputs/df-local-server/protocol/armor_durability_catalog.json'


def main():
    names = name_map(Path(str(SOURCE) + '.entry-48.bin').read_bytes())
    data = Path(str(SOURCE) + '.entry-49.bin').read_bytes()
    _, offset = tags(data, 0, names, len(data))
    if struct.unpack_from('<i', data, offset)[0] != 0:
        raise ValueError('Unexpected armor table prefix')
    count = struct.unpack_from('<i', data, offset + 4)[0]
    if not 1 <= count <= 1000:
        raise ValueError('Unexpected armor row count')
    offset += 8
    rows = {}
    for _ in range(count):
        item_id = fname(data, offset, names)
        offset += 8
        properties, offset = tags(data, offset, names, len(data))
        fields = {tag['name']: tag for tag in properties}
        if int(item_id) != scalar(data, fields['ItemId'], names):
            raise ValueError('Armor row ID mismatch')
        maximum = scalar(data, fields['MaxDurability'], names)
        if not isinstance(maximum, int) or not 0 < maximum <= 100000:
            raise ValueError('Invalid armor durability')
        rows[item_id] = maximum
    if offset + 4 != len(data) or data[offset:] != b'\xc1\x83\x2a\x9e':
        raise ValueError('Unexpected armor table trailer')
    TARGET.write_text(json.dumps({'source_table': '/Game/DataTables/Armor/BodyArmorFunction',
                                  'rows': rows}, separators=(',', ':')) + '\n',
                      encoding='utf-8')
    print('armor rows', len(rows), 'durability values', rows)


if __name__ == '__main__':
    main()
