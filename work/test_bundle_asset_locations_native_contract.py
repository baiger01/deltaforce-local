"""Focused checks for the exported public CDN source contract."""

import copy
import hashlib
import json
from pathlib import Path
import tempfile
import unittest

import bundle_asset_locations_native_contract as contract


class ContractTests(unittest.TestCase):
    def fixture(self):
        blocks = {'rva': 1, 'size': 8, 'bytes': '00' * 8,
                  'sha256': hashlib.sha256(bytes(8)).hexdigest()}
        code = {'native_pe_sha256': contract.EXPECTED_PE, 'pid': 99,
                'composition_scalars': {}, 'image_request_scalars': {},
                'image_component_data': {}}
        scalar = lambda value: {'stable': True, 'value': value, 'value_recheck': value}
        code['composition_scalars'] = {'pc_url_selector': scalar(1),
                                      **{f'override{i}': scalar(0) for i in range(9)}}
        code['image_request_scalars'] = {name: scalar(value) for name, value in
            [('request_extension_gate', 0), ('request_quality_gate', 0),
             ('request_quality_enum', 3), ('request_quality_alternate_enum', 1)]}
        code['disk_hash_branch_byte'] = scalar(1)
        code['disk_manager_override_byte'] = scalar(0)
        import struct
        from bundle_asset_locations import CRC_TABLE
        code['image_crc_table'] = copy.deepcopy(blocks)
        code['image_crc_table'].update(size=1024, bytes=struct.pack('<256I', *CRC_TABLE).hex(),
                                       sha256=contract.CRC_TABLE_SHA)
        quality = struct.pack('<8i', 0, 5, 6, 7, 23, 39, 55, 56)
        code['image_request_quality_table'] = {'rva': 1, 'size': 32, 'bytes': quality.hex(),
                                             'sha256': contract.QUALITY_TABLE_SHA}
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
            code[group] = {name: copy.deepcopy(blocks) for name in names}
        settings = {'pid': 99, 'status': 'captured_configuration_fields',
            'source_schema': {'source_pe_sha256': contract.EXPECTED_PE, 'status': 'verified_source_types'},
            'weak_reference_and_headers_rechecked': True,
            'fields': [{'field': key, 'value': value, 'public_value_output_verified': True,
                        'status': 'observed_public_configuration_value'}
                       for key, value in contract.EXPECTED_FIELDS.items()]}
        return code, settings

    def test_pinned_source_requires_exact_file_hash(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'report.json'
            path.write_text('{"private": "do-not-export"}', encoding='utf-8')
            with self.assertRaisesRegex(ValueError, 'differs'):
                contract.pinned_report(path, contract.CODE_CAPTURE_SHA)

    def test_missing_capture_is_actionable(self):
        with tempfile.TemporaryDirectory() as directory:
            with self.assertRaisesRegex(ValueError, 'pass an existing'):
                contract.pinned_report(Path(directory) / 'missing.json', contract.CODE_CAPTURE_SHA)

    def test_same_process_source_rechecked_gates(self):
        for field, value in [('pid', 100), ('weak_reference_and_headers_rechecked', False),
                             ('status', 'skipped')]:
            code, settings = self.fixture()
            settings[field] = value
            with self.subTest(field=field), self.assertRaises(ValueError):
                contract.export_contract(code, settings)

    def test_private_or_duplicate_configuration_rejected(self):
        for change in ['private', 'duplicate', 'not_public']:
            code, settings = self.fixture()
            if change == 'private':
                settings['fields'][0]['value'] = 'https://cdn.df.qq.com/?secret=test'
            elif change == 'duplicate':
                settings['fields'][1] = copy.deepcopy(settings['fields'][0])
            else:
                settings['fields'][0]['public_value_output_verified'] = False
            with self.subTest(change=change), self.assertRaises(ValueError):
                contract.export_contract(code, settings)

    def test_unstable_or_different_quality_rejected(self):
        for group, name in [('composition_scalars', 'pc_url_selector'),
                            ('image_request_scalars', 'request_quality_enum')]:
            code, settings = self.fixture()
            code[group][name]['value_recheck'] ^= 1
            with self.subTest(group=group), self.assertRaises(ValueError):
                contract.export_contract(code, settings)

    def test_modified_span_rejected(self):
        code, settings = self.fixture()
        code['image_processing_tails']['SetCDNImage']['bytes'] = 'ff' * 8
        with self.assertRaisesRegex(ValueError, 'span hash'):
            contract.export_contract(code, settings)

    def test_safe_output_contains_only_public_metadata(self):
        code, settings = self.fixture()
        code['module_base'] = 0x140000000
        settings['configuration_object_address'] = 0x40000000
        settings['private'] = 'do-not-export'
        result = contract.export_contract(code, settings)
        serialized = json.dumps(result)
        for marker in ['module_base', 'configuration_object_address', 'do-not-export',
                       '"pid"', '"bytes"', '"instructions"']:
            self.assertNotIn(marker, serialized)
        self.assertEqual(result['request_processing']['quality_integer'], 7)
        self.assertTrue(result['proof_flags']['cache_read_filename_transform_verified'])
        self.assertFalse(result['proof_flags']['download_body_direct_cache_bytes_verified'])

    def test_modified_crc_table_bytes_rejected(self):
        code, settings = self.fixture()
        code['image_crc_table']['bytes'] = bytes(1024).hex()
        with self.assertRaisesRegex(ValueError, 'span hash'):
            contract.export_contract(code, settings)


if __name__ == '__main__':
    unittest.main()
