import json
from pathlib import Path
import tempfile
import unittest

from dfserver.business_envelope import BusinessEnvelope
from dfserver.candidate_business import CandidateBusinessCodec
from dfserver.candidate_schema import CandidateProtobufCodec, compile_candidate_descriptors
from dfserver.core import DomainError


ROOT = Path(__file__).resolve().parent.parent


class BattlePassCodecTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.directory = tempfile.TemporaryDirectory()
        recovery = json.loads((ROOT / 'protocol/generated_codec_fields.json').read_text())
        classes = json.loads((ROOT / 'protocol/generated_class_metadata.json').read_text())
        descriptor, cls.report = compile_candidate_descriptors(recovery, class_metadata=classes)
        path = Path(cls.directory.name) / 'candidate.pb'
        path.write_bytes(descriptor)
        cls.codec = CandidateProtobufCodec(path)
        cls.business = CandidateBusinessCodec(path, ROOT / 'protocol/generated_class_metadata.json')

    @classmethod
    def tearDownClass(cls):
        cls.directory.cleanup()

    def test_known_battle_pass_info_and_purchase_responses_roundtrip(self):
        info = {'has_bought': False, 'season_info': {'season_id': 202604},
                'main_line': {'level_info': {'curr_level': 1, 'curr_expr': 0}},
                'archives': [], 'pack': {'valid_time': True, 'pack_id': 11,
                    'bought_packs': [], 'bought_pack_list': []}, 'type': 0}
        for name in ('CSBattlePassGetInfoRes', 'CSBattlePassBuyRes', 'CSBattlePassBuyLevelRes'):
            with self.subTest(name=name):
                message = self.business.decode(self.business.encode(name,
                    {'result': 0, 'info': info}, sequence=29))
                self.assertEqual(message.fields['info']['season_info']['season_id'], 202604)
                self.assertEqual(message.fields['info']['pack']['pack_id'], 11)
                self.assertEqual(message.sequence, 29)

    def test_opaque_entry_rejects_nonempty_outgoing_list(self):
        for entries in ([{}], [{'key': 11, 'value': 1}]):
            with self.subTest(entries=entries), self.assertRaises(DomainError):
                self.codec.encode('pb.BattlePassPackInfo', {'bought_packs': entries})

    def test_opaque_entry_rejects_received_wire_content(self):
        for payload in (bytes.fromhex('3a00'), bytes.fromhex('3a04080b1001')):
            with self.subTest(payload=payload), self.assertRaises(DomainError):
                self.codec.decode('pb.BattlePassPackInfo', payload)
            # result=0; info.pack contains the original field-7 payload.
            info = b'\x2a' + bytes([len(payload)]) + payload
            body = b'\x08\x00\x12' + bytes([len(info)]) + info
            envelope = BusinessEnvelope(body, {'name': 'CSBattlePassGetInfoRes',
                'service': 'battlepass', 'client_sequence_id': 29}).encode()
            with self.assertRaises(DomainError):
                self.business.decode(envelope)

    def test_only_observed_battle_pass_reference_receives_opaque_compatibility(self):
        field = {'name': 'value', 'number': 1, 'codec_category': 'submsg',
                 'repeated': True, 'nested_type': 'BattlePassPackInfo_BoughtPacksEntry'}
        _, report = compile_candidate_descriptors({'messages': [
            {'name': 'Unverified', 'all_observed_field_calls_matched': True, 'fields': [field]}]})
        self.assertIn('Unverified', report['excluded_messages'])
        self.assertEqual(report['messages_compiled'], 0)
        self.assertIn('BattlePassPackInfo_BoughtPacksEntry', self.report['opaque_empty_only_types'])


if __name__ == '__main__':
    unittest.main()
