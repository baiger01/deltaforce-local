"""Verify native keycard columns and retain unresolved key-box FNames."""

import hashlib
import json
import mmap
from pathlib import Path
import re
import struct

from explore_tagged_export import read_row
from extract_game_item_catalog import scalar
from extract_operator_avatar_catalog import tags
from extract_prop_slot_catalog import name_map
from local_game_paths import game_paths
from lua53_reader import Reader, listing, walk
from scan_weapon_tables import decode_content, parse_entry


ROOT = Path(__file__).resolve().parent.parent
PROTOCOL = ROOT / 'outputs/df-local-server/protocol'
PAK = 'pak-0-0-pakchunk2-WindowsClient.pak'
EXPECTED_PE = '4254fbe66585f260f1f9dbfc5e302887842552e7baed8939e023160a5e250be0'
TABLES = {
    'key_boxes': (6726, 'KeyBoxRow', 413513424,
        [('Index', 'int', 16), ('ItemID', 'FName', 20), ('MapID', 'int', 28),
         ('DefaultSlotNum', 'int', 32), ('LevelSlotNums1', 'int', 36),
         ('LevelSlotNums2', 'int', 40), ('LevelSlotNums3', 'int', 44),
         ('LevelSlotNums4', 'int', 48), ('BoxLength', 'int', 52)]),
    'key_box_unlocks': (6728, 'KeyBoxUnlockRow', 413542944,
        [('ItemID', 'FName', 16), ('KeyBoxID', 'FName', 24), ('MapID', 'int', 32),
         ('SlotLevel', 'int', 36), ('UnlockSlotNum', 'int', 40)]),
    'keycards': (6730, 'DFMKeyInfoRow', 413572464,
        [('ID', 'uint64', 8), ('Name', 'FText', 16), ('MapLevelStr', 'FString', 40),
         ('MapName', 'FText', 56), ('MapID', 'uint16', 80), ('Area', 'FText', 88),
         ('LockLocation', 'FText', 112), ('LockCoord', 'FVector', 136),
         ('Durability', 'int', 148), ('Description', 'FText', 152),
         ('BehindTheDoor', 'FText', 176), ('Mechanic', 'uint8', 200),
         ('Rank', 'uint8', 201), ('KeySpawnLocation', 'TArray<FText>', 208),
         ('ConnectionRelation', 'TArray<uint64>', 224)]),
}
TYPE_LAYOUT = {'int': (4, 0, 3), 'uint64': (8, 0, 7), 'uint16': (2, 0, 5),
    'uint8': (1, 8, 0), 'FName': (8, 0, 20), 'FString': (None, 0, 21),
    'FText': (None, 0, 29), 'FVector': (12, 24, 25),
    'TArray<FText>': (None, 8, 22), 'TArray<uint64>': (None, 8, 22)}


def current_export(entry, cached):
    index_path = ROOT / 'work/evidence/hero-custom-medicine-filter-table-index-20261001.jsonl'
    records = [json.loads(line) for line in index_path.read_text(encoding='utf-8').splitlines()]
    record = next(row for row in records if row['entry'] == entry)
    path = game_paths()[0] / 'DeltaForce/Content/Paks' / PAK
    with path.open('rb') as handle:
        handle.seek(-512, 2)
        tail = handle.read(512)
        marker = tail.rfind(struct.pack('<I', 0x5a6f12e1))
        _, limit = struct.unpack_from('<IQ', tail, marker + 4)
        methods = [match[:-1].decode('ascii') for match in re.findall(
            rb'(?:Oodle|Zlib|Gzip|LZ4|Zstd)\x00', tail)]
        position = record['offset']
        raw_entry = parse_entry(handle, position, limit, variant='observed_permutation')
        data = decode_content(handle, position, raw_entry, methods)
    if data is None or data != cached:
        raise ValueError(f'Cached export {entry} differs from the installed source')
    return {'pak': PAK, 'entry': entry, 'pak_offset': position,
            'sha256': hashlib.sha256(data).hexdigest(), 'size': len(data)}


def lua(name, required):
    path = ROOT / 'work/evidence/weapon_lua' / name
    raw = path.read_bytes()
    root = Reader(raw, allow_client_format1=True).function()
    if root['source'] != '@' + name:
        raise ValueError('Unexpected native Lua source')
    functions = {function['id']: function for function in walk(root)}
    for function_id, constants in required.items():
        if not all(value in functions[function_id]['constants'] for value in constants):
            raise ValueError(f'Native {name} consumer changed')
    return {'sha256': hashlib.sha256(raw).hexdigest(), 'functions': list(required)}, functions


def main():
    proof = json.loads((ROOT / 'work/evidence/native-keycard-reflection-probe.json').read_text())
    exe = game_paths()[0] / 'DeltaForce/Binaries/Win64/DeltaForceClient-Win64-Shipping.exe'
    with exe.open('rb') as handle, mmap.mmap(handle.fileno(), 0, access=mmap.ACCESS_READ) as data:
        if hashlib.sha256(data).hexdigest() != EXPECTED_PE or proof['_source']['pe_sha256'] != EXPECTED_PE:
            raise ValueError('Native executable version changed')
        sections = proof['_source']['sections']

        def text_at(address):
            matches = [section['raw_offset'] + address - section['virtual_base'] for section in sections
                       if section['virtual_base'] <= address < section['virtual_base'] + section['raw_size']]
            if len(matches) != 1:
                raise ValueError('Native descriptor pointer is outside one section')
            return data[matches[0]:matches[0] + 128].split(b'\0')[0].decode('ascii')

        sources, recovered = {}, {}
        for group, (entry, struct_name, anchor, expected) in TABLES.items():
            registered = proof[struct_name]
            if len(registered) != 1:
                raise ValueError('Expected one complete native struct registration')
            properties = [field for field in registered[0]['properties'] if field['member_offset']]
            if [(field['name'], field['member_offset']) for field in properties] != [
                    (name, offset) for name, _, offset in expected]:
                raise ValueError(f'Native {struct_name} property registration changed')
            for index, ((name, kind, offset), field) in enumerate(zip(expected, properties)):
                name_va, kind_va, member = struct.unpack_from('<3Q', data, anchor + index * 24)
                if (text_at(name_va), text_at(kind_va), member) != (name, kind, offset):
                    raise ValueError('Native named/type/member descriptors changed')
                if field['gen_flags'] != TYPE_LAYOUT[kind][2]:
                    raise ValueError('Native property kind differs from its typed descriptor')
            path = ROOT / 'work/evidence/matched_assets' / f'{PAK}.entry-{entry}.uexp'
            raw = path.read_bytes()
            source = current_export(entry, raw)
            none_offset = 29 if struct.unpack_from('<i', raw, 37)[0] == 0 else 55
            none, instance, prefix, count = struct.unpack_from('<iiii', raw, none_offset)
            if instance or prefix:
                raise ValueError('Unexpected native table prefix')
            offset, kinds, rows, mapping, signature = none_offset + 16, {}, [], {}, None
            for row_index in range(count):
                start = offset
                fields, offset, layout = read_row(raw, offset + 8, none, known_types=kinds)
                kinds = dict(layout)
                inherited = group != 'keycards'
                if len(fields) != len(expected) + inherited:
                    raise ValueError('Native table property count differs from the registered struct')
                current_signature = [(field['field'], field['kind'], field['metadata_bytes']) for field in fields]
                if signature is None:
                    signature = current_signature
                elif signature != current_signature:
                    raise ValueError('Native table changes property order across rows')
                row = {'source_row': row_index, 'serialized_offset': start}
                for field, (name, kind, _) in zip(fields, expected):
                    size, metadata, _ = TYPE_LAYOUT[kind]
                    if (size is not None and field['size'] != size) or field['metadata_bytes'] != metadata:
                        raise ValueError('Native serialized column type/size differs from its named registration')
                    value = raw[field['value_start']:field['end']]
                    mapping[name] = field['field']
                    if kind == 'FName':
                        index, number = struct.unpack('<ii', value)
                        row[name + '_fname'] = {'index': index, 'number': number}
                    elif kind in ('int', 'uint64', 'uint16', 'uint8'):
                        row[name] = int.from_bytes(value, 'little', signed=kind == 'int')
                    elif kind == 'FString':
                        length = struct.unpack_from('<i', value)[0]
                        if length == 0 and len(value) == 4:
                            row[name] = ''
                            continue
                        if length <= 0 or length != len(value) - 4 or value[-1:] != b'\0':
                            raise ValueError('Unexpected native map level string')
                        row[name] = value[4:-1].decode('ascii')
                rows.append(row)
            if raw[offset:] != b'\xc1\x83\x2a\x9e':
                raise ValueError('Unparsed native table trailer')
            sources[group] = {**source, 'row_count': count, 'struct': struct_name,
                'struct_params_offset': registered[0]['struct_params_offset'],
                'native_registration': registered[0],
                'typed_descriptor_offset': anchor, 'serialized_field_indices': mapping,
                'name_map_available': False}
            recovered[group] = rows
    item_path = PROTOCOL / 'game_item_catalog.json'
    items = json.loads(item_path.read_text(encoding='utf-8'))['rows']
    cards = {}
    for row in recovered['keycards']:
        item_id = str(row['ID'])
        if item_id in cards or item_id not in items or not item_id.startswith('1505'):
            raise ValueError('Invalid/duplicate native keycard ID')
        if row['Durability'] <= 0 or (items[item_id]['length'], items[item_id]['width']) != (1, 1):
            raise ValueError('Unexpected native keycard dimensions/durability')
        cards[item_id] = {'map_id': row['MapID'], 'durability': row['Durability'],
            'map_level': row['MapLevelStr'], 'name_key': items[item_id]['name_key'],
            'source_row': row['source_row'], 'serialized_offset': row['serialized_offset']}
    slot_dir = ROOT / 'work/evidence/prop_slot_config'
    asset, raw = (slot_dir / 'PropSlotConfig.uasset').read_bytes(), (slot_dir / 'PropSlotConfig.uexp').read_bytes()
    names, slots = name_map(asset), {}
    for slot in ('116', '116001'):
        offset = raw.index(struct.pack('<iiii', names.index(slot), 0, names.index('PageId'), 0))
        fields, _ = tags(raw, offset + 8, names, len(raw))
        slots[slot] = {field['name']: scalar(raw, field, names) for field in fields
                      if field['name'] in ('PagePropTypes', 'IgnorePropTypes', 'bIsContainerByItem')}
    if slots['116']['PagePropTypes'] != '1112' or slots['116001']['PagePropTypes'] != '1505':
        raise ValueError('Native keychain slot restrictions changed')
    consumers = {}
    for name, checks in {
        'KeyFeature.lua': {'0.3': ['Durability'], '0.4': ['health', 'health_max']},
        'ItemConfigTool.lua': {'0.31': ['Key/KeyBox', 'ItemID', 'MapID', 'Index']},
        'ItemOperaTool.lua': {'0.15': ['KeyInfo', 'MapID']},
        'ItemSlotSpace.lua': {'0.3': ['base_cnt', 'total_locked', 'unlocked', 'is_map_unlocked'],
                              '0.10': ['validNum', 'baseCnt', 'length', 'ceil']},
        'KeyChainManagerMain.lua': {'0.14': ['GetSpaceByIndex'],
                                   '0.14.0': ['GetKeyBoxSpaceOrder']},
    }.items():
        consumers[name], _ = lua(name, checks)
    enum_source, enum_functions = lua('common_pb.lua', {'0': ['KeyChain', 116, 'Box_InKeyChain', 116001]})
    enum_listing = listing(enum_functions['0']).splitlines()
    enum_witnesses = {}
    for name, value in (('KeyChain', 116), ('Box_InKeyChain', 116001)):
        index = next(index for index, line in enumerate(enum_listing) if f"'{name}'" in line)
        witness = enum_listing[index:index + 3]
        if not (f'={value}' in witness[1] and 'SETTABLE' in witness[2]):
            raise ValueError('Native keychain position enum assignment changed')
        enum_witnesses[name] = witness
    message_names = {'CSDepositGetExtensionPropsReq', 'CSDepositGetExtensionPropsRes',
                     'CSDepositEquipPropReq', 'CSDepositEquipPropRes', 'EquipPosition',
                     'GridSize', 'PropLocation', 'PropInfo', 'PositionChange'}
    definitions = json.loads((PROTOCOL / 'generated_codec_fields.json').read_text(encoding='utf-8'))['messages']
    wire_messages = [message for message in definitions if message['name'] in message_names]
    if ({message['name'] for message in wire_messages} != message_names or
            any(not message['all_observed_field_calls_matched'] for message in wire_messages)):
        raise ValueError('Native keycard wire definitions are incomplete')
    report = {'native_pe_sha256': EXPECTED_PE, 'sources': sources,
        'game_item_catalog_sha256': hashlib.sha256(item_path.read_bytes()).hexdigest(),
        'slot_source': {'uasset_sha256': hashlib.sha256(asset).hexdigest(),
            'uexp_sha256': hashlib.sha256(raw).hexdigest(), 'rows': slots},
        'client_consumers': consumers, 'equipment_position': 116, 'contents_position': 116001,
        'position_enum_source': {**enum_source, 'assignments': enum_witnesses},
        'wire_messages': wire_messages,
        'contents_ignore_prefixes': slots['116001']['IgnorePropTypes'].split(','),
        'keycards': cards,
        'keychain_template_ids': sorted(int(item_id) for item_id in items if item_id.startswith('1112')),
        'resolved_key_boxes': [], 'raw_key_boxes': recovered['key_boxes'],
        'raw_key_box_unlocks': recovered['key_box_unlocks'],
        'limitations': ['KeyBox.ItemID and KeyBoxUnlock ItemID/KeyBoxID are local FName pairs.',
            'Encrypted package name maps are unavailable; their numeric indices are not item IDs.',
            'Keychain layout selection and slot unlock mutations remain disabled until ID bindings are verified.',
            'The local service does not simulate door interaction or claim online permissions.'],
        'local_policy': ['Fresh physical cards use the original maximum durability; saved per-GID health is preserved.',
                         'After verified ID bindings are recovered, configured map spaces use default base cells; level unlocks remain zero.',
                         'Map spaces exposed by this local diagnostic policy are marked available; no official entitlement is asserted.']}
    (PROTOCOL / 'native_keycard_catalog.json').write_text(json.dumps(report, indent=2) + '\n', encoding='utf-8')
    print({'keycards': len(cards), 'keychain_templates': len(report['keychain_template_ids']),
           'key_box_rows': len(recovered['key_boxes']), 'resolved_key_box_rows': 0})


if __name__ == '__main__':
    main()
