import importlib.util
from pathlib import Path
import struct
import unittest

WORK = Path(__file__).resolve().parents[3] / 'work'
spec = importlib.util.spec_from_file_location('bind_native_keybox_catalog', WORK / 'bind_native_keybox_catalog.py')
native = importlib.util.module_from_spec(spec)
spec.loader.exec_module(native)


class KeyBoxBindingTests(unittest.TestCase):
    def fixture(self):
        source = []
        runtime = []
        for index, map_id, group, item_id, base in (
                (1, 19, 19, 11120000001, 4), (2, 22, 19, 11120000001, 4),
                (3, 19, 20, 11120000002, 6)):
            values = [index, map_id, base, 0, 0, 0, 0, 4]
            row = dict(zip(native.SCALAR_FIELDS, values))
            row.update(source_row=index - 1, serialized_offset=71 + (index - 1) * 314,
                       ItemID_fname={'index': group, 'number': 0})
            source.append(row)
            raw = bytearray(56)
            struct.pack_into('<i', raw, 16, index)
            raw[20:28] = struct.pack('<II', 0x100 + group, 0)
            struct.pack_into('<7i', raw, 28, *values[1:])
            runtime.append({'row_hex': raw.hex(), 'item_id_fname_hex': raw[20:28].hex(),
                            'scalar_fingerprint': values, 'item_name': str(item_id)})
        catalog = {'native_pe_sha256': native.EXPECTED_PE,
                   'sources': {'key_boxes': {'row_count': 3, 'sha256': native.EXPECTED_KEYBOX}},
                   'keychain_template_ids': [11120000001, 11120000002, 11120000003],
                   'raw_key_boxes': source, 'resolved_key_boxes': [], 'limitations': []}
        capture = {'native_pe_sha256': native.EXPECTED_PE,
                   'registrations': {'KeyBoxRow': {'property_names_and_offsets_verified': True}},
                   'keybox_rowmap': {'status': 'captured', 'rowmap_status': 'captured_rows',
                                     'table_name': 'Key/KeyBox', 'rows': list(reversed(runtime))}}
        return catalog, capture

    def test_complete_binding_uses_scalars_and_not_runtime_order(self):
        catalog, capture = self.fixture()
        result = native.bind_catalog(catalog, capture, 'a' * 64)
        self.assertEqual([row['item_id'] for row in result['resolved_key_boxes']],
                         [11120000001, 11120000001, 11120000002])
        self.assertEqual(result['unresolved_keychain_template_ids'], [11120000003])
        self.assertEqual(catalog['resolved_key_boxes'], [])
        self.assertNotIn('row_address', str(result['resolved_key_boxes']))

    def test_partial_or_changed_scalar_rows_rejected(self):
        catalog, capture = self.fixture()
        capture['keybox_rowmap']['rows'].pop()
        with self.assertRaises(ValueError):
            native.bind_catalog(catalog, capture, 'a' * 64)

    def test_unknown_item_and_inconsistent_fname_group_rejected(self):
        for name in ('11120000999', '11120000002'):
            with self.subTest(name=name):
                catalog, capture = self.fixture()
                capture['keybox_rowmap']['rows'][1]['item_name'] = name
                with self.assertRaises(ValueError):
                    native.bind_catalog(catalog, capture, 'a' * 64)

    def test_primary_and_short_namespace_must_agree(self):
        catalog, capture = self.fixture()
        short = dict(capture['keybox_rowmap'], table_name='KeyBox')
        short['rows'] = [dict(row) for row in short['rows']]
        short['rows'][0]['item_name'] = '11120000001'
        capture['keybox_rowmap_short'] = short
        with self.assertRaises(ValueError):
            native.bind_catalog(catalog, capture, 'a' * 64)

    def test_five_missing_game_item_rows_are_evidence_only(self):
        catalog, capture = self.fixture()
        capture['keybox_rowmap']['rows'][0]['item_name'] = '11120000011'
        for index, map_id in enumerate((22, 39, 81, 88), 4):
            source = dict(catalog['raw_key_boxes'][2], Index=index, MapID=map_id,
                          source_row=index - 1, serialized_offset=71 + (index - 1) * 314)
            catalog['raw_key_boxes'].append(source)
            values = [source[field] for field in native.SCALAR_FIELDS]
            raw = bytearray.fromhex(capture['keybox_rowmap']['rows'][0]['row_hex'])
            struct.pack_into('<i', raw, 16, index)
            struct.pack_into('<7i', raw, 28, *values[1:])
            capture['keybox_rowmap']['rows'].append({'row_hex': raw.hex(),
                'scalar_fingerprint': values, 'item_id_fname_hex': raw[20:28].hex(),
                'item_name': '11120000011'})
        catalog['sources']['key_boxes']['row_count'] = 7
        result = native.bind_catalog(catalog, capture, 'a' * 64)
        self.assertEqual(len(result['missing_game_item_key_box_bindings']), 5)
        self.assertEqual(len(result['resolved_key_boxes']), 2)
        self.assertTrue(all(row['item_id'] == 11120000001 for row in result['resolved_key_boxes']))
        self.assertEqual(result['sources']['key_boxes']['item_id_binding']['source_row_count'], 7)


if __name__ == '__main__':
    unittest.main()
