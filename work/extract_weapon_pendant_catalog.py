"""Recover pendant IDs and conservative local visibility from installed exports.

The PendantDataTable's encrypted name map remains unavailable. Its two bool
property indices are retained without assigning invented original names.
Requiring both is invariant under the unresolved OpenCollection/DisplayResources
ordering. The local test grant is explicitly separate from official ownership.
"""

import hashlib
import json
from pathlib import Path
import struct

from extract_hero_customization_catalog import export
from extract_operator_avatar_catalog import fname, name_map, tags


ROOT = Path(__file__).resolve().parent.parent
PROTOCOL = ROOT / 'outputs/df-local-server/protocol'
CAPTURE = ROOT / 'work/hero_custom_scan/evidence/matched_assets'
STEM = '1.101.37117.36.10_WindowsNoEditor_37127_P.pak'
EXPECTED_TABLE = 'fcd134d66408f3a730b83507b8c4e93c74da9d32e2e7d0aad5a00b8f7b39e27b'
EXPECTED_HEADER = 'd1e42b4f0493ff6fdcb08ee901bed3fb93f9c833f60dff6e0dcf92df9dc19fa5'
EXPECTED_PARTS = '84d144362d87ea7c23dd879740f5826b3222b0bbf5369dfa048c5159fa38261a'


def parts():
    header = (CAPTURE / f'{STEM}.entry-233.uasset').read_bytes()
    data = (CAPTURE / f'{STEM}.entry-234.uexp').read_bytes()
    if hashlib.sha256(header).hexdigest() != EXPECTED_HEADER or hashlib.sha256(data).hexdigest() != EXPECTED_PARTS:
        raise ValueError('Unverified PartsDataTable source')
    names = name_map(header)
    _, offset = tags(data, 0, names, len(data))
    prefix, count = struct.unpack_from('<ii', data, offset)
    if (prefix, count) != (0, 2590):
        raise ValueError('Unexpected PartsDataTable root')
    offset += 8
    result = {}
    for index in range(count):
        start = offset
        row_name = fname(data, offset, names)
        fields, offset = tags(data, offset + 8, names, len(data))
        if not row_name.startswith('1346'):
            continue
        decoded = {}
        for field in fields:
            if field['name'] in ('ItemId', 'RuleId', 'PartsTypeId', 'WeaponAssemblyPoint'):
                fmt = '<Q' if field['kind'] == 'UInt64Property' else '<i'
                decoded[field['name']] = struct.unpack_from(fmt, data, field['value_start'])[0]
            elif field['name'] in ('IsHiddenInGunsmith', 'bRelease'):
                decoded[field['name']] = bool(data[field['start'] + 24])
            elif field['name'] == 'SocketOffsets':
                raw = data[field['value_start']:field['end']]
                decoded['SocketOffsets'] = [fname(raw, pos, names) for pos in range(4, len(raw), 8)]
        if decoded['ItemId'] != int(row_name):
            raise ValueError('PartsDataTable row ID mismatch')
        result[int(row_name)] = {'row_index': index, 'row_offset': start, **decoded}
    if data[offset:] != b'\xc1\x83\x2a\x9e':
        raise ValueError('Unexpected PartsDataTable trailer')
    return result


def main():
    table, table_source = export(6886)
    if table_source['sha256'] != EXPECTED_TABLE or len(table) != 283:
        raise ValueError('Unverified PendantDataTable export')
    item_path = PROTOCOL / 'game_item_catalog.json'
    items = json.loads(item_path.read_text(encoding='utf-8'))['rows']
    named_parts = parts()
    rows = []
    for row in table:
        item_id = struct.unpack('<Q', row['fields'][305]['raw'])[0]
        if str(item_id) not in items or not str(item_id).startswith('1346') or item_id not in named_parts:
            raise ValueError('Unverified pendant item or part ID')
        visibility = {str(index): row['fields'][index]['bool'] for index in (294, 301)}
        if any(value is None for value in visibility.values()):
            raise ValueError('Expected two serialized bool properties')
        is_mystical = str(item_id)[4:6] == '64'
        rows.append({'pendant_id': item_id, 'is_mystical': is_mystical,
                     'name_key': items[str(item_id)]['name_key'],
                     'raw_visibility_booleans': visibility,
                     'local_test_grant': not is_mystical and all(visibility.values()),
                     'row_index': row['row'], 'row_offset': row['offset'],
                     'parts_data': named_parts[item_id]})
    missing = sorted(int(item) for item in items if item.startswith('1346') and int(item) not in {row['pendant_id'] for row in rows})
    report = {
        'sources': {'PendantDataTable': table_source,
                    'PartsDataTable': {'pak': STEM, 'header_entry': 233, 'export_entry': 234,
                                       'header_sha256': EXPECTED_HEADER, 'export_sha256': EXPECTED_PARTS},
                    'GameItem': {'catalog_sha256': hashlib.sha256(item_path.read_bytes()).hexdigest()},
                    'GunsmithPendantLogic': {'sha256': '27d54d03279644786f5fcbaba6f916e8ca68b21354f8884f016d3726fb196ee4',
                                             'functions': {'list': '0.5@3466', 'visibility_ownership': '0.8@5822',
                                                           'command': '0.16@12305', 'normalize_guid': '0.22@15147'}},
                    'ItemHelperTool': {'sha256': 'f31339b9c5a75d2c52c2e7eb36732c26e03c5f58c12c3dbbb31c57a8bf8a095c',
                                       'classification_function': '0.62@24562', 'third_type_function': '0.40@15278'}},
        'client_item_types': {'main_adapter': 13, 'sub_pendant': 46, 'mystical_third_type': 64},
        'raw_field_indices': {'pendant_id': 305, 'visibility_boolean_pair': [294, 301]},
        'table_identification_status': 'Candidate PendantDataTable identified by native consumers, 283 exact GameItem/PartsDataTable pendant IDs and compatible property shapes; its encrypted original header name map is unavailable.',
        'visibility_provenance': 'Native visibility consumers require OpenCollection and DisplayResources. The captured export has exactly two serialized bool property indices, so their semantic pairing is inferred from the consumer and property shapes; individual original names remain unresolved. Only their conjunction is used for the conservative local test grant.',
        'local_policy': 'The user authorized open ordinary pendants for local test accounts. Provision persists actual collection ownership; this is not an official default entitlement. Mystical instances are never synthesized.',
        'weapon_relation_provenance': 'Native GetAllPendantPartIDs() takes no weapon argument. Captured PartsDataTable pendant RuleId, PartsTypeId and WeaponAssemblyPoint are zero, SocketOffsets empty. Client assets determine attachment; no invented weapon/socket mapping is emitted.',
        'unrecovered_game_item_ids': missing, 'rows': rows}
    (PROTOCOL / 'weapon_pendant_catalog.json').write_text(json.dumps(report, indent=2) + '\n', encoding='utf-8')
    print('verified pendant rows', len(rows), 'ordinary local grants', sum(row['local_test_grant'] for row in rows))


if __name__ == '__main__':
    main()
