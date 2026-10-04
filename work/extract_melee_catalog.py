"""Extract client melee pairs without guessing encrypted property names."""

import hashlib
import json
from pathlib import Path
import re
import struct

from explore_tagged_export import read_row


ROOT = Path(__file__).resolve().parent.parent
SOURCE = ROOT / 'work/evidence/matched_assets/pak-0-0-pakchunk2-WindowsClient.pak.entry-7276.bin'
OUTPUT = ROOT / 'outputs/df-local-server/protocol/melee_weapon_catalog.json'
NATIVE = ROOT / 'work/evidence/native-trial-melee-fixed-20260930.log'


def main():
    data = SOURCE.read_bytes()
    none, instance, prefix, count = struct.unpack_from('<iiii', data, 29)
    if (none, instance, prefix, count) != (45, 0, 0, 18):
        raise ValueError('Unexpected melee export root')
    items = json.loads((OUTPUT.parent / 'game_item_catalog.json').read_text(encoding='utf-8'))['rows']
    native = NATIVE.read_bytes()
    observed = {(int(skin), int(weapon)) for skin, weapon in re.findall(
        r'皮肤id:,\s*,?\s*(\d+),\s*武器id:,\s*(\d+),\s*是否已解锁:,\s*true',
        native.decode('utf-8'))}
    if len(observed) != 15:
        raise ValueError('Expected the 15 native-confirmed unlocked melee pairs')
    rows, offset, kinds = [], 45, {}
    for index in range(count):
        start = offset
        fields, offset, layout = read_row(data, offset + 8, none, known_types=kinds)
        kinds = dict(layout)
        tags = {tag['field']: tag for tag in fields}
        values = []
        for field in (40, 41):
            tag = tags[field]
            if (tag['kind'], tag['size']) != (35, 8):
                raise ValueError('Unexpected melee ID scalar')
            values.append(struct.unpack_from('<Q', data, tag['value_start'])[0])
        skin, weapon = values
        if not str(skin).startswith('2810') or not str(weapon).startswith('1810'):
            raise ValueError('Unexpected melee item family')
        if str(skin) not in items or str(weapon) not in items:
            raise ValueError('Melee pair missing from recovered GameItem')
        rows.append({'skin_id': skin, 'weapon_id': weapon,
                     'serialized_row_index': index, 'serialized_uexp_offset': start,
                     'skin_name_key': items[str(skin)]['name_key'],
                     'weapon_name_key': items[str(weapon)]['name_key'],
                     'native_collection_unlock_confirmed': (skin, weapon) in observed,
                     'length': items[str(weapon)]['length'],
                     'width': items[str(weapon)]['width']})
    if data[offset:] != b'\xc1\x83\x2a\x9e':
        raise ValueError('Unparsed melee export suffix')
    if len({row['skin_id'] for row in rows}) != count or len({row['weapon_id'] for row in rows}) != count:
        raise ValueError('Duplicate melee pair')
    report = {
        'source_pak': 'pak-0-0-pakchunk2-WindowsClient.pak',
        'source_entry': 7276,
        'source_uexp_sha256': hashlib.sha256(data).hexdigest(),
        'source_table_identification': '15 pairs corroborated by native MeleeWeaponSkinDataTable logs; encrypted name map unavailable',
        'serialized_skin_field_index': 40, 'serialized_weapon_field_index': 41,
        'client_consumers': ['CollectionServer.lua 0.11.4, 0.13, 0.44',
                             'ItemBase.lua 0.22', 'ItemOperaTool.lua 0.28',
                             'InventoryServer_Network.lua 0.12'],
        'client_lua_sha256': {name: hashlib.sha256(
            (ROOT / 'work/evidence/weapon_lua' / name).read_bytes()).hexdigest()
            for name in ('CollectionServer.lua', 'ItemBase.lua', 'ItemOperaTool.lua',
                         'InventoryServer_Network.lua', 'WeaponHelperTool.lua')},
        'local_default_skin_id': rows[0]['skin_id'],
        'local_default_policy': 'Use the first client base pair for the local test account; not an official ownership claim',
        'row_count': count, 'rows': rows,
        'local_provisioning_validation': {
            'source': NATIVE.name, 'source_sha256': hashlib.sha256(native).hexdigest(),
            'unlocked_pair_count': len(observed),
            'policy': 'Provision only native-confirmed unlocked pairs; retain other series variants as catalog evidence'},
    }
    OUTPUT.write_text(json.dumps(report, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')
    print('melee_pairs', count, 'source_sha256', report['source_uexp_sha256'])


if __name__ == '__main__':
    main()
