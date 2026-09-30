"""Extract local ammunition classes, magazine functions, and protocol enums."""

import hashlib
import json
from pathlib import Path
import struct

from explore_tagged_export import read_row
from extract_game_item_catalog import scalar
from extract_operator_avatar_catalog import fname, name_map, tags
from lua53_reader import Reader, listing


ROOT = Path(__file__).resolve().parent.parent
EVIDENCE = ROOT / 'work/evidence/matched_assets'
OUTPUT = ROOT / 'outputs/df-local-server/protocol/weapon_ammo_catalog.json'


def clear_rows(stem):
    header = (EVIDENCE / (stem + '.uasset')).read_bytes()
    data = (EVIDENCE / (stem + '.uexp')).read_bytes()
    names = name_map(header)
    _, offset = tags(data, 0, names, len(data))
    prefix, count = struct.unpack_from('<ii', data, offset)
    if prefix:
        raise ValueError('Unexpected table prefix')
    offset += 8
    rows = []
    for _ in range(count):
        start = offset
        row_name = fname(data, offset, names)
        fields, offset = tags(data, offset + 8, names, len(data))
        rows.append((row_name, start, {field['name']: scalar(data, field, names) for field in fields}))
    if data[offset:] != bytes.fromhex('c1832a9e'):
        raise ValueError('Unparsed table trailer')
    return rows, {'file': stem, 'row_count': count,
                 'uasset_sha256': hashlib.sha256(header).hexdigest(),
                 'uexp_sha256': hashlib.sha256(data).hexdigest()}


def indexed_rows(entry, id_index, class_index, capacity_index=None):
    path = EVIDENCE / f'pak-0-0-pakchunk2-WindowsClient.pak.entry-{entry}.bin'
    data = path.read_bytes()
    none_index = struct.unpack_from('<i', data, 29)[0]
    prefix, count = struct.unpack_from('<ii', data, 37)
    if prefix:
        raise ValueError('Unexpected indexed table prefix')
    offset, types, rows = 45, {}, {}
    for _ in range(count):
        row_offset = offset
        fields, offset, inferred = read_row(data, offset + 8, none_index, known_types=types)
        types = dict(inferred)
        fields = {field['field']: field for field in fields}
        id_tag, class_tag = fields[id_index], fields[class_index]
        if id_tag['size'] != 8 or class_tag['size'] != 1 or class_tag['metadata_bytes'] != 8:
            raise ValueError('Unexpected ID or ammo enum serialization')
        item_id = struct.unpack_from('<Q', data, id_tag['value_start'])[0]
        if str(item_id) in rows:
            raise ValueError('Duplicate item ID')
        rows[str(item_id)] = {'ammo_type': data[class_tag['value_start']],
            'serialized_row_offset': row_offset, 'serialized_class_offset': class_tag['value_start']}
        if capacity_index is not None:
            capacity_tag = fields[capacity_index]
            if capacity_tag['size'] != 2 or capacity_tag['metadata_bytes'] != 0:
                raise ValueError('Unexpected base clip capacity serialization')
            rows[str(item_id)]['base_capacity'] = struct.unpack_from('<H', data, capacity_tag['value_start'])[0]
            rows[str(item_id)]['serialized_capacity_offset'] = capacity_tag['value_start']
    if data[offset:] != bytes.fromhex('c1832a9e'):
        raise ValueError('Unparsed indexed table trailer')
    return rows, {'file': path.name, 'row_count': count,
        'sha256': hashlib.sha256(data).hexdigest(), 'id_property_index': id_index,
        'ammo_class_property_index': class_index, 'base_capacity_property_index': capacity_index,
        'property_metadata_lengths': types}


def main():
    parts, part_source = clear_rows('1.101.37117.36.10_WindowsNoEditor_37127_P.pak.entry-233')
    functions, function_source = clear_rows('1.101.37117.36.537_WindowsNoEditor_37654_P.pak.entry-314')
    capacities = {}
    for row_name, offset, row in functions:
        if row['Param1'] != 'GMagCapacity':
            continue
        if (row['PartFunctionType'] != 'EWeaponPartFunctionType::StaticAttributeReplace'
                or row['Param2'] != 'Initial' or not str(row['Param3']).isdigit()):
            continue
        function_id = row['FunctionId']
        capacity = int(row['Param3'])
        if function_id in capacities and capacities[function_id]['capacity'] != capacity:
            raise ValueError('Ambiguous magazine function')
        capacities[function_id] = {'capacity': capacity, 'function_row': row_name,
                                  'serialized_function_offset': offset}
    magazines = {}
    for item_id, offset, row in parts:
        function_id = row['FunctionId_SOL']
        if function_id in capacities:
            magazines[item_id] = {**capacities[function_id], 'function_id': function_id,
                'serialized_part_offset': offset, 'dual_clip': row['bDualClipMag'],
                'sub_clip_capacity': row['SubClipCapacity']}
    weapons, weapon_source = indexed_rows(4489, 331, 177, 373)
    bullets, bullet_source = indexed_rows(4555, 595, 643)
    enum_path = EVIDENCE / 'pak-0-0-pakchunk1-WindowsClient.pak.entry-6681.bin'
    enum_data = enum_path.read_bytes()
    lua = Reader(enum_data, allow_client_format1=True).function()
    enum_listing = listing(lua).splitlines()[46:51]
    if (lua['source'] != '@cs_deposit_pb.lua'
            or not any("'eBulletOperate_Load' K13=1" in line for line in enum_listing)
            or not any("'eBulletOperate_UnLoad' K15=2" in line for line in enum_listing)):
        raise ValueError('Client bullet enum definitions changed')
    report = {'sources': {'parts': part_source, 'functions': function_source,
        'weapon_attributes': weapon_source, 'ammo': bullet_source,
        'bullet_enum': {'file': enum_path.name, 'sha256': hashlib.sha256(enum_data).hexdigest(),
                        'function': '0', 'instructions': enum_listing}},
        'client_compatibility': 'WeaponHelperTool.lua 0.111: WeaponAttributeTable.AmmoType == GetAmmoConfig(id).Type',
        'client_capacity': 'WeaponAssemblyTool.lua 0.68/0.71/0.72: installed magazine overrides base capacity',
        'operate_types': {'load': 1, 'unload': 2}, 'magazines': magazines,
        'magazine_item_ids': [int(item_id) for item_id, _, row in parts if row['MagazineTypeId']],
        'weapons': weapons, 'bullets': bullets}
    OUTPUT.write_text(json.dumps(report, indent=2) + '\n', encoding='utf-8')
    print('weapons', len(weapons), 'bullets', len(bullets), 'magazines', len(magazines))


if __name__ == '__main__':
    main()
