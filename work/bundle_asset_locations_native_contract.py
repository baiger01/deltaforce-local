"""Export safe source witnesses for bundle CDN planning from pinned captures."""

import argparse
import hashlib
import json
from pathlib import Path
import struct


EXPECTED_PE = '4254fbe66585f260f1f9dbfc5e302887842552e7baed8939e023160a5e250be0'
CODE_CAPTURE_SHA = '6b24a730c4b74fb5f0833022cc3f1c67318dd4846c99db7528be8c12ca83a9f9'
SETTINGS_CAPTURE_SHA = 'a74b1307d96b683577bf3d62f555235d08ef6954984b0d272b1c9c381dd09e46'
CRC_TABLE_SHA = '0053f121cdcaf9f510a940ba891fb2bccd41487953c5a4c0048c4a3ccdec782e'
QUALITY_TABLE_SHA = '31122defde8e19d5a41d7dc8d5aacd31626d6e6de487a7eca03a1b44132fe4b4'
EXPECTED_FIELDS = {
    'AppSettingRow.MapleInfo.DefaultCDNUrl': 'https://cdn.df.qq.com',
    'AppSettingRow.MapleInfo.CDNUrl_PC': 'https://repo.df.qq.com',
    'AppSettingRow.CDNRoot': 'G/CN',
}


def pinned_report(path, expected):
    if not path.is_file():
        raise ValueError('Required saved capture is missing; pass an existing --code-capture or --settings-capture')
    if path.stat().st_size > 4 * 1024 * 1024:
        raise ValueError('Saved capture exceeds the fixed report size limit')
    data = path.read_bytes()
    if hashlib.sha256(data).hexdigest() != expected:
        raise ValueError('Saved capture differs from this source-proven contract snapshot')
    return json.loads(data)


def block_metadata(label, block):
    data = bytes.fromhex(block['bytes'])
    if len(data) != block['size'] or hashlib.sha256(data).hexdigest() != block['sha256']:
        raise ValueError('Saved code/data span hash or length differs')
    return {'role': label, 'rva': block['rva'], 'size': block['size'], 'sha256': block['sha256']}


def export_contract(code, settings):
    if (code.get('native_pe_sha256') != EXPECTED_PE
            or settings.get('source_schema', {}).get('source_pe_sha256') != EXPECTED_PE
            or settings.get('status') != 'captured_configuration_fields'
            or settings.get('source_schema', {}).get('status') != 'verified_source_types'
            or settings.get('weak_reference_and_headers_rechecked') is not True
            or not isinstance(code.get('pid'), int) or code['pid'] <= 0
            or code['pid'] != settings.get('pid')):
        raise ValueError('Expected same-process, same-version source and rechecked typed fields')
    fields = settings.get('fields', [])
    if (len(fields) != 3 or {row.get('field') for row in fields} != set(EXPECTED_FIELDS)
            or any(row.get('public_value_output_verified') is not True
                   or row.get('status') != 'observed_public_configuration_value'
                   or row.get('value') != EXPECTED_FIELDS[row['field']] for row in fields)):
        raise ValueError('Expected exactly the three pinned public CDN configuration values')
    composition = code['composition_scalars']
    if (len(composition) != 10 or any(row.get('stable') is not True
            or row['value'] != row['value_recheck'] for row in composition.values())
            or composition['pc_url_selector']['value'] != 1
            or any(row['value'] != 0 for name, row in composition.items() if name != 'pc_url_selector')):
        raise ValueError('Composition selector or override snapshot differs')
    request = code['image_request_scalars']
    expected = {'request_extension_gate': 0, 'request_quality_gate': 0,
                'request_quality_enum': 3, 'request_quality_alternate_enum': 1}
    if set(request) != set(expected) or any(row.get('stable') is not True
            or row['value'] != value or row['value_recheck'] != value
            for name, value in expected.items() for row in [request[name]]):
        raise ValueError('Request quality/extension scalar snapshot differs')
    crc = code['image_crc_table']
    quality = code['image_request_quality_table']
    if crc['sha256'] != CRC_TABLE_SHA or quality['sha256'] != QUALITY_TABLE_SHA:
        raise ValueError('Native CRC or quality table differs')
    table = struct.unpack('<8i', bytes.fromhex(quality['bytes']))
    if table != (0, 5, 6, 7, 23, 39, 55, 56):
        raise ValueError('Native quality table entries differ')
    for key, value in [('disk_hash_branch_byte', 1), ('disk_manager_override_byte', 0)]:
        row = code[key]
        if row.get('stable') is not True or row['value'] != value or row['value_recheck'] != value:
            raise ValueError('Native disk selector snapshot differs')
    blocks = []
    for group, names in [
        ('implementations', ['AppRow_GetCDNUrl', 'IconManager_GetCDNUrl']),
        ('composition_helpers', ['URL_StringProcess', 'URL_StringConstruct', 'URL_StringAppend']),
        ('image_processing_tails', ['SetCDNImage', 'Disk_ImagePath']),
        ('image_request_tails', ['Req_Worker']),
        ('image_request_helpers', ['Request_PathComponent', 'Request_SplitPath']),
        ('image_component_helpers', ['Request_CleanComponent', 'Request_BaseComponent']),
        ('image_component_tails', ['Request_Dispatch', 'Disk_SplitEquals']),
        ('image_processing_helpers', ['Disk_BasenameHash', 'Disk_IntegerString']),
    ]:
        blocks.extend(block_metadata(name, code[group][name]) for name in names)
    blocks.extend([block_metadata('CRC_Table', crc), block_metadata('Quality_Table', quality)])
    blocks.extend(block_metadata(name, block) for name, block in code['image_component_data'].items())
    return {
        'schema_version': 1,
        'status': 'source_and_rechecked_configuration_witnesses_verified',
        'source_pe_sha256': EXPECTED_PE,
        'capture_provenance': {
            'code_capture_sha256': CODE_CAPTURE_SHA, 'settings_capture_sha256': SETTINGS_CAPTURE_SHA,
            'same_capture_process_verified': True,
            'configuration_and_module_scalars_rechecked': True,
            'atomic_with_resource_request_verified': False,
        },
        'configuration': {'default_base': 'https://cdn.df.qq.com', 'pc_base': 'https://repo.df.qq.com',
                          'root': 'G/CN', 'selected_base_role': 'pc'},
        'request_processing': {
            'extension_gate': 0, 'quality_gate': 0, 'quality_enum': 3,
            'quality_alternate_enum': 1, 'quality_integer': table[3],
            'quality_table': list(table),
            'scope': 'Observed Resource/.../C= inputs with one filename component and no query or fragment',
            'initial_composition': 'base + "/G/CN/" + exact_source_resource_value',
            'literal_extension_rule': 'preserve_input',
            'extensionless_rule': 'insert_quality_directory_before_original_basename',
            'extensionless_composition': 'base + "/G/CN/" + exact_source_directory + "/7/" + exact_original_basename',
            'original_extension_case_preserved': True,
            'cache_key_uses_original_source': True,
            'proven_through': 'Request_Dispatch copies processed URL to its download queue record',
        },
        'cache_filename': {
            'scope': 'Observed logical disk paths containing one literal equals sign',
            'hash_input': 'Original filename suffix after C=, including literal extension when present',
            'case_fold': 'ASCII a-z to A-Z only', 'encoding': 'UTF-16LE excluding trailing NUL',
            'initial_crc': 0, 'final_xor': 0, 'table_polynomial': '0x04c11db7',
            'byte_step': 'crc = (crc >> 8) ^ table[(crc ^ byte) & 255]',
            'filename': 'C= plus signed 32-bit decimal CRC',
            'table_sha256': CRC_TABLE_SHA,
            'logical_relative_parent': 'DeltaForce/Saved/Cdn/G/CN plus exact original source directory',
        },
        'proof_flags': {
            'source_url_processing_verified': True,
            'cache_read_filename_transform_verified': True,
            'native_http_request_execution_verified': False,
            'download_body_direct_cache_bytes_verified': False,
            'cache_write_name_binding_verified': False,
            'native_resource_binding_and_rendering_verified': False,
            'reward_bare_filename_prefix_verified': False,
            'unclassified_source_field_304_consumer_binding_verified': False,
        },
        'source_spans': blocks,
        'limits': [
            'Code interpretation and observed scalar/field snapshots are not an executed native URL getter result.',
            'A source-proven queue URL does not prove final HTTP redirect handling or download success.',
            'Cache read naming does not prove arbitrary downloaded bodies can be written directly to every native cache format.',
            'No image payload, absolute machine path, instance address, process identifier or raw code is exported.',
        ],
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--code-capture', type=Path, required=True)
    parser.add_argument('--settings-capture', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    try:
        result = export_contract(pinned_report(args.code_capture, CODE_CAPTURE_SHA),
                                 pinned_report(args.settings_capture, SETTINGS_CAPTURE_SHA))
    except (ValueError, KeyError, TypeError, OSError) as exc:
        parser.error(str(exc) if isinstance(exc, ValueError) else 'Saved source evidence is incomplete or unreadable')
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, indent=2, sort_keys=True) + '\n', encoding='utf-8')
    print(json.dumps({'status': result['status'], 'source_spans': len(result['source_spans']),
                      'output': str(args.output)}))


if __name__ == '__main__':
    main()
