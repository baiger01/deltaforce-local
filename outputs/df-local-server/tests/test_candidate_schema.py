import json
from pathlib import Path
import tempfile
import unittest

from dfserver.candidate_schema import CandidateProtobufCodec, compile_candidate_descriptors, validate_class_metadata
from dfserver.core import DomainError

PROJECT = Path(__file__).resolve().parent.parent


class CandidateSchemaTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temporary = tempfile.TemporaryDirectory()
        metadata = json.loads((PROJECT / 'protocol/generated_codec_fields.json').read_text(encoding='utf-8'))
        cls.classes = json.loads((PROJECT / 'protocol/generated_class_metadata.json').read_text(encoding='utf-8'))
        cls.descriptor, cls.report = compile_candidate_descriptors(metadata, class_metadata=cls.classes)
        path = Path(cls.temporary.name) / 'candidate.pb'
        path.write_bytes(cls.descriptor)
        cls.codec = CandidateProtobufCodec(path)

    @classmethod
    def tearDownClass(cls):
        cls.temporary.cleanup()

    def test_deposit_request_matches_manual_field_tag_vector(self):
        fields = {'grid_page_id': 1, 'get_prop_type': 2, 'invoke_event': 3}
        self.assertEqual(self.codec.encode('pb.CSDepositGetPropsReq', fields), bytes.fromhex('080110021803'))
        self.assertEqual(self.codec.decode('pb.CSDepositGetPropsReq', bytes.fromhex('080110021803')), fields)

    def test_nested_warehouse_message_matches_manual_wire_vector(self):
        # result=0, one page(id=1, length=10, width=12).
        wire = bytes.fromhex('0a060801100a180c1800')
        fields = {'grid_pages': [{'grid_page_id': 1, 'grid_length': 10, 'grid_width': 12}], 'result': 0}
        self.assertEqual(self.codec.encode('pb.CSDepositGetPropsRes', fields), wire)
        self.assertEqual(self.codec.decode('pb.CSDepositGetPropsRes', wire), fields)

    def test_generated_package_keeps_raw_binary_body(self):
        # CSPkg body is buffer/getstr, not UTF-8 text.
        fields = {'head': {'client_sequence_id': 42}, 'body': 'AP+A'}
        wire = bytes.fromhex('0a02182a120300ff80')
        self.assertEqual(self.codec.encode('pb.CSPkg', fields), wire)
        self.assertEqual(self.codec.decode('pb.CSPkg', wire), fields)

    def test_scalar_unknown_fields_and_ranges_are_rejected_when_encoding(self):
        for fields in ({'unknown': 1}, {'grid_page_id': 1 << 31}, {'grid_page_id': 'oops'}):
            with self.subTest(fields=fields), self.assertRaises(DomainError):
                self.codec.encode('pb.CSDepositGetPropsReq', fields)
        with self.assertRaises(DomainError):
            self.codec.decode('pb.CSDepositGetPropsReq', b'\x08\x80')

    def test_repeated_buffers_preserve_each_raw_binary_value(self):
        # TDMNumeralProp tags 3 and 4 are repeated buffers. getstrary does not
        # make addbuffer input UTF-8 text; protobuf JSON uses base64 for bytes.
        fields = {'weapon_store_bytes': ['AP+A', 'AQI='], 'weapon_designs_bytes': ['/wA=']}
        wire = bytes.fromhex('1a0300ff801a0201022202ff00')
        self.assertEqual(self.codec.encode('pb.TDMNumeralProp', fields), wire)
        self.assertEqual(self.codec.decode('pb.TDMNumeralProp', wire), fields)

    def test_unrecovered_messages_and_transitive_dependencies_are_excluded(self):
        field = {'name': 'nested', 'number': 1, 'codec_category': 'submsg',
                 'repeated': False, 'nested_type': 'Missing'}
        metadata = {'messages': [
            {'name': 'Missing', 'fields': [], 'all_observed_field_calls_matched': False},
            {'name': 'Parent', 'fields': [field], 'all_observed_field_calls_matched': True},
            {'name': 'Grandparent', 'fields': [dict(field, nested_type='Parent')], 'all_observed_field_calls_matched': True},
            {'name': 'Empty', 'fields': [], 'all_observed_field_calls_matched': True},
        ]}
        descriptor, report = compile_candidate_descriptors(metadata)
        self.assertEqual(report['messages_compiled'], 1)
        self.assertEqual(set(report['excluded_messages']), {'Missing', 'Parent', 'Grandparent'})
        self.assertTrue(descriptor)

    def test_recursive_complete_types_are_retained(self):
        metadata = {'messages': [{'name': 'Node', 'all_observed_field_calls_matched': True,
                                 'fields': [{'name': 'children', 'number': 1, 'codec_category': 'submsg',
                                             'repeated': True, 'nested_type': 'Node'}]}]}
        _, report = compile_candidate_descriptors(metadata)
        self.assertEqual(report['messages_compiled'], 1)

    def test_invalid_duplicate_fields_or_names_are_not_silently_accepted(self):
        field = {'name': 'value', 'number': 1, 'codec_category': 'i32', 'repeated': False, 'nested_type': None}
        for fields in ([field, field], [dict(field, number=True)], [dict(field, number=19000)]):
            with self.subTest(fields=fields), self.assertRaises(ValueError):
                compile_candidate_descriptors({'messages': [{'name': 'Msg', 'fields': fields,
                                                             'all_observed_field_calls_matched': True}]})
        with self.assertRaises(ValueError):
            compile_candidate_descriptors({'messages': [{'name': 'Msg', 'all_observed_field_calls_matched': False},
                                                       {'name': 'Msg', 'all_observed_field_calls_matched': False}]})

    def test_compilation_is_deterministic_and_never_enables_gateway(self):
        metadata = json.loads((PROJECT / 'protocol/generated_codec_fields.json').read_text(encoding='utf-8'))
        again, report = compile_candidate_descriptors(metadata, class_metadata=self.classes)
        self.assertEqual(again, self.descriptor)
        self.assertEqual(report, self.report)
        self.assertFalse(self.codec.status()['business_gateway_ready'])
        self.assertFalse(self.codec.status()['original_client_wire_compatibility_verified'])

    def test_independent_storage_declarations_corroborate_every_observed_field(self):
        crosscheck = self.report['class_declaration_crosscheck']
        metadata = json.loads((PROJECT / 'protocol/generated_codec_fields.json').read_text(encoding='utf-8'))
        self.assertEqual(crosscheck['observed_codec_fields_corroborated'], sum(len(m['fields']) for m in metadata['messages']))
        self.assertFalse(crosscheck['wire_signedness_or_encoding_verified'])
        field = {'name': 'count', 'number': 1, 'codec_category': 'u32', 'repeated': False, 'nested_type': None}
        sample = {'messages': [{'name': 'Message', 'fields': [field], 'all_observed_field_calls_matched': True}]}
        classes = {'messages': [{'name': 'Message', 'dynamic_fields': [{'name': 'count', 'declared_type': 'Int32'}]}]}
        self.assertEqual(validate_class_metadata(sample, classes)['observed_codec_fields_corroborated'], 1)
        classes['messages'][0]['dynamic_fields'][0]['declared_type'] = 'String'
        with self.assertRaises(ValueError):
            compile_candidate_descriptors(sample, class_metadata=classes)
        classes['messages'][0]['dynamic_fields'] = []
        with self.assertRaises(ValueError):
            compile_candidate_descriptors(sample, class_metadata=classes)


if __name__ == '__main__':
    unittest.main()
