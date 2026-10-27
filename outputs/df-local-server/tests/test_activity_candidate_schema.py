from copy import deepcopy
import json
from pathlib import Path
import tempfile
import unittest

from dfserver.app.core import DomainError
from dfserver.gateway.candidate_schema import CandidateProtobufCodec, compile_candidate_descriptors


PROJECT = Path(__file__).resolve().parent.parent
ENTRY = 'ActivityObjectiveConditions_ExtConditionsEntry'


class ActivityCandidateSchemaTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.metadata = json.loads((PROJECT / 'protocol/generated_codec_fields.json').read_text(encoding='utf-8'))
        cls.classes = json.loads((PROJECT / 'protocol/generated_class_metadata.json').read_text(encoding='utf-8'))
        descriptor, cls.report = compile_candidate_descriptors(cls.metadata, class_metadata=cls.classes)
        cls.temporary = tempfile.TemporaryDirectory()
        path = Path(cls.temporary.name) / 'activity.pb'
        path.write_bytes(descriptor)
        cls.codec = CandidateProtobufCodec(path)

    @classmethod
    def tearDownClass(cls):
        cls.temporary.cleanup()

    def test_observed_activity_response_schemas_compile(self):
        required = {'pb.ActivityInfo', 'pb.CSActivityGetRes', 'pb.CSActivityExchangeRes',
                    'pb.CSActivityPropExchangeRes', 'pb.' + ENTRY}
        self.assertTrue(required.issubset(self.codec.names), required - set(self.codec.names))
        self.assertIn(ENTRY, self.report['opaque_empty_only_types'])
        fields = {'result': 0, 'actv_infos': [{'actv_id': '1'}]}
        wire = bytes.fromhex('080012020801')
        self.assertEqual(self.codec.encode('pb.CSActivityGetRes', fields), wire)
        self.assertEqual(self.codec.decode('pb.CSActivityGetRes', wire), fields)
        for name in ('CSActivityExchangeRes', 'CSActivityPropExchangeRes'):
            self.assertEqual(self.codec.decode('pb.' + name,
                self.codec.encode('pb.' + name, {'result': 0})), {'result': 0})

    def test_empty_opaque_type_and_empty_parent_list_are_supported(self):
        self.assertTrue('pb.' + ENTRY in self.codec.names, ENTRY + ' schema missing')
        self.assertEqual(self.codec.encode('pb.' + ENTRY, {}), b'')
        self.assertEqual(self.codec.decode('pb.' + ENTRY, b''), {})
        self.assertEqual(self.codec.encode('pb.ActivityObjectiveConditions', {'ext_conditions': []}), b'')
        self.assertEqual(self.codec.decode('pb.ActivityObjectiveConditions', b''), {})

    def test_every_opaque_nested_occurrence_is_rejected(self):
        self.assertTrue('pb.ActivityObjectiveConditions' in self.codec.names, 'ActivityObjectiveConditions schema missing')
        with self.assertRaises(DomainError):
            self.codec.encode('pb.ActivityObjectiveConditions', {'ext_conditions': [{}]})
        for payload in (bytes.fromhex('5200'), bytes.fromhex('52020801')):
            with self.subTest(payload=payload.hex()), self.assertRaises(DomainError):
                self.codec.decode('pb.ActivityObjectiveConditions', payload)
        with self.assertRaises(DomainError):
            self.codec.encode('pb.' + ENTRY, {'unknown': 1})
        with self.assertRaises(DomainError):
            self.codec.decode('pb.' + ENTRY, bytes.fromhex('0801'))

    def test_source_pin_or_reference_changes_do_not_enable_opaque_type(self):
        original = next(m for m in self.metadata['messages'] if m['name'] == 'ActivityObjectiveConditions')
        mutations = []
        for key, value in (('source', '@other.lua'), ('source_sha256', '0' * 64),
                           ('encode_function_id', '0.99'), ('decode_function_id', '0.98'),
                           ('encode_field_calls', 8)):
            row = deepcopy(original)
            row[key] = value
            mutations.append(row)
        for key, value in (('number', 11), ('repeated', False), ('encode_instruction', 58)):
            row = deepcopy(original)
            row['fields'][-1][key] = value
            mutations.append(row)
        for row in mutations:
            with self.subTest(row=row):
                metadata = {'messages': [row if m['name'] == row['name'] else m
                    for m in self.metadata['messages']]}
                _, report = compile_candidate_descriptors(metadata)
                self.assertNotIn(ENTRY, report['opaque_empty_only_types'])
                self.assertIn('ActivityObjectiveConditions', report['excluded_messages'])
                self.assertIn('CSActivityGetRes', report['excluded_messages'])


if __name__ == '__main__':
    unittest.main()
