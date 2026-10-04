"""Bind KeyBox ItemID FNames through complete runtime/source row fingerprints."""

import argparse
import copy
import hashlib
import json
import os
from pathlib import Path
import re
import struct
import tempfile

ROOT = Path(__file__).resolve().parent.parent
EXPECTED_PE = '4254fbe66585f260f1f9dbfc5e302887842552e7baed8939e023160a5e250be0'
EXPECTED_KEYBOX = 'c56af28577c9bd35e5320870ef5aeaa1ae7e66ef0736302b33cb00746cc5e1d5'
BINDING_STATUS = 'verified_by_native_runtime_fname_and_complete_row_fingerprint'
SCALAR_FIELDS = ('Index', 'MapID', 'DefaultSlotNum', 'LevelSlotNums1',
                 'LevelSlotNums2', 'LevelSlotNums3', 'LevelSlotNums4', 'BoxLength')
SCALAR_OFFSETS = (16, 28, 32, 36, 40, 44, 48, 52)


def _bind_rows(catalog, captured, namespace):
    if (captured.get('status') != 'captured' or captured.get('rowmap_status') != 'captured_rows'
            or captured.get('table_name') != namespace):
        raise ValueError('Complete captured rows are required for ' + namespace)
    source = catalog['raw_key_boxes']
    actual = captured['rows']
    if len(actual) != len(source) or len(source) != catalog['sources']['key_boxes']['row_count']:
        raise ValueError('Runtime rows do not cover the complete source table')
    fingerprints = {}
    for row in source:
        fingerprint = tuple(row[field] for field in SCALAR_FIELDS)
        if any(type(value) is not int for value in fingerprint) or fingerprint in fingerprints:
            raise ValueError('Source scalar fingerprint is not unique/integer')
        fingerprints[fingerprint] = row
    if len({row['Index'] for row in source}) != len(source):
        raise ValueError('Source Index is not unique')
    matched, groups, reverse, runtime_groups = {}, {}, {}, {}
    for row in actual:
        raw = bytes.fromhex(row['row_hex'])
        if len(raw) != 56:
            raise ValueError('Runtime KeyBoxRow size differs from native reflection')
        fingerprint = tuple(struct.unpack_from('<i', raw, offset)[0] for offset in SCALAR_OFFSETS)
        if list(fingerprint) != row['scalar_fingerprint'] or raw[20:28].hex() != row['item_id_fname_hex']:
            raise ValueError('Runtime row fields disagree with captured native bytes')
        if fingerprint not in fingerprints or fingerprint in matched:
            raise ValueError('Runtime scalar fingerprint is missing, duplicate or changed')
        name = row.get('item_name')
        if type(name) is not str or re.fullmatch(r'[1-9][0-9]*', name) is None:
            raise ValueError('Decoded ItemID FName is not a canonical integer name')
        item = int(name)
        original = fingerprints[fingerprint]
        group = (original['ItemID_fname']['index'], original['ItemID_fname']['number'])
        runtime_group = raw[20:28].hex()
        if group in groups and groups[group] != (item, runtime_group):
            raise ValueError('One serialized FName group has inconsistent runtime item names')
        if item in reverse and reverse[item] != group:
            raise ValueError('Distinct serialized FName groups collapse onto one item ID')
        if runtime_group in runtime_groups and runtime_groups[runtime_group] != item:
            raise ValueError('One runtime FName has inconsistent decoded names')
        groups[group] = (item, runtime_group)
        reverse[item] = group
        runtime_groups[runtime_group] = item
        matched[fingerprint] = item
    if len(matched) != len(source):
        raise ValueError('Source table coverage is incomplete')
    resolved = [{**copy.deepcopy(row), 'item_id': matched[tuple(row[field] for field in SCALAR_FIELDS)]}
                for row in source]
    item_maps = [(row['item_id'], row['MapID']) for row in resolved]
    if len(set(item_maps)) != len(item_maps):
        raise ValueError('Resolved keychain contains duplicate map spaces')
    return resolved, groups


def bind_catalog(catalog, capture_data, capture_sha256):
    """Return a copy only after all source rows and identity groups verify."""
    if (catalog.get('native_pe_sha256') != EXPECTED_PE or
            capture_data.get('native_pe_sha256') != EXPECTED_PE or
            catalog['sources']['key_boxes'].get('sha256') != EXPECTED_KEYBOX):
        raise ValueError('Source executable or KeyBox table hash differs')
    if re.fullmatch(r'[0-9a-f]{64}', capture_sha256) is None:
        raise ValueError('Expected the exact runtime capture SHA256')
    if capture_data.get('registrations', {}).get('KeyBoxRow', {}).get('property_names_and_offsets_verified') is not True:
        raise ValueError('Runtime native KeyBoxRow named fields were not verified')
    primary, groups = _bind_rows(catalog, capture_data.get('keybox_rowmap', {}), 'Key/KeyBox')
    comparison = capture_data.get('keybox_rowmap_short')
    compared = False
    if comparison is not None:
        short, short_groups = _bind_rows(catalog, comparison, 'KeyBox')
        if primary != short or groups != short_groups:
            raise ValueError('Consumer namespace and short-name configuration disagree')
        compared = True
    result = copy.deepcopy(catalog)
    known = set(catalog['keychain_template_ids'])
    result['resolved_key_boxes'] = [row for row in primary if row['item_id'] in known]
    result['missing_game_item_key_box_bindings'] = [row for row in primary if row['item_id'] not in known]
    result['unresolved_keychain_template_ids'] = sorted(set(catalog['keychain_template_ids']) -
                                                     {row['item_id'] for row in result['resolved_key_boxes']})
    result['sources']['key_boxes']['item_id_binding'] = {
        'status': BINDING_STATUS, 'native_pe_sha256': EXPECTED_PE,
        'runtime_capture_sha256': capture_sha256, 'consumer_table_namespace': 'Key/KeyBox',
        'short_namespace_cross_checked': compared, 'source_row_count': len(primary),
        'available_row_count': len(result['resolved_key_boxes']),
        'available_template_count': len({row['item_id'] for row in result['resolved_key_boxes']}),
        'missing_game_item_row_count': len(result['missing_game_item_key_box_bindings']),
        'scalar_fields': list(SCALAR_FIELDS), 'scalar_match': 'unique_exact_complete_table',
        'verified_group_count': len(groups), 'serialized_fname_groups': [
            {'index': group[0], 'number': group[1], 'item_id': item}
            for group, (item, _runtime_id) in sorted(groups.items())],
        'runtime_chain': ['DataTableSystemManagerLite verified weak reference',
                          'GetDataTable interface vtable+0x68', 'configuration cache native hash chains',
                          'native decoded Key/KeyBox FName', 'GetFirstDataTable configuration pointer',
                          'UDataTable vtable+0x270 actual LEA+0x30',
                          'GetAllRows allocation bits and native KeyBoxRow fields']}
    result['limitations'] = [
        'KeyBoxUnlock ItemID/KeyBoxID FName bindings and slot unlock mutations remain unverified.',
        'Encrypted package name maps remain unavailable; KeyBox ItemID binding uses verified runtime names.',
        'Templates absent from the verified KeyBox rows do not expose a guessed keychain layout.',
        'Verified runtime ItemIDs missing from GameItem are retained as evidence and do not publish layouts.',
        'The local service does not simulate door interaction or claim online permissions.']
    return result


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--capture', type=Path, required=True)
    parser.add_argument('--catalog', type=Path,
                        default=ROOT / 'outputs/df-local-server/protocol/native_keycard_catalog.json')
    parser.add_argument('--check-only', action='store_true')
    args = parser.parse_args()
    capture_bytes = args.capture.read_bytes()
    catalog_bytes = args.catalog.read_bytes()
    catalog = json.loads(catalog_bytes)
    result = bind_catalog(catalog, json.loads(capture_bytes), hashlib.sha256(capture_bytes).hexdigest())
    if not args.check_only:
        payload = json.dumps(result, indent=2) + '\n'
        with tempfile.NamedTemporaryFile(mode='w', encoding='utf-8', newline='\n',
                                         dir=args.catalog.parent, delete=False) as target:
            target.write(payload)
            temporary = Path(target.name)
        try:
            if args.catalog.read_bytes() != catalog_bytes:
                raise ValueError('Catalog changed during binding; no shared edits overwritten')
            os.replace(temporary, args.catalog)
        finally:
            if temporary.exists():
                temporary.unlink()
    print(json.dumps({'resolved_rows': len(result['resolved_key_boxes']),
                      'verified_source_rows': result['sources']['key_boxes']['item_id_binding']['source_row_count'],
                      'missing_game_item_rows': len(result['missing_game_item_key_box_bindings']),
                      'item_ids': len({row['item_id'] for row in result['resolved_key_boxes']}),
                      'unresolved_template_ids': result['unresolved_keychain_template_ids'],
                      'binding_status': BINDING_STATUS}))


if __name__ == '__main__':
    main()
