from pathlib import Path
import unittest

from dfserver.business_envelope import BusinessEnvelope, parse_business_envelope
from dfserver.candidate_business import CandidateBusinessCodec
from dfserver.core import DomainError

PROJECT = Path(__file__).resolve().parent.parent


class CandidateBusinessTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.codec = CandidateBusinessCodec(PROJECT / 'protocol/candidate_business.pb',
                                           PROJECT / 'protocol/generated_class_metadata.json')

    def test_explicit_service_and_manual_request_tags(self):
        fields = {'grid_page_id': 1, 'get_prop_type': 2, 'invoke_event': 3}
        expected = BusinessEnvelope(bytes.fromhex('080110021803'),
                                    {'client_sequence_id': 42, 'name': 'CSDepositGetPropsReq', 'service': 'deposit'})
        wire = self.codec.encode('CSDepositGetPropsReq', fields, sequence=42)
        self.assertEqual(parse_business_envelope(wire), expected)
        decoded = self.codec.decode(wire)
        self.assertEqual((decoded.name, decoded.service, decoded.sequence, decoded.fields),
                         ('CSDepositGetPropsReq', 'deposit', 42, fields))

    def test_response_has_declared_name_service_and_request_sequence(self):
        request = self.codec.decode(self.codec.encode('CSDepositGetPropsReq', {}, sequence=81))
        fields = {'grid_pages': [{'grid_page_id': 1, 'grid_length': 10, 'grid_width': 12}], 'result': 0}
        response = self.codec.decode(self.codec.response(request, fields))
        self.assertEqual((response.name, response.service, response.sequence, response.fields),
                         ('CSDepositGetPropsRes', 'deposit', 81, fields))
        with self.assertRaises(DomainError):
            self.codec.response(response, {})

    def test_state_message_uses_online_service_not_a_name_guess(self):
        message = self.codec.decode(self.codec.encode('CSStateGetInfoReq', {}, sequence=1))
        self.assertEqual(message.service, 'online')
        self.assertEqual(self.codec.decode(self.codec.encode('CSQuestGetPlayerDataReq', {}, sequence=2)).service, 'quest')

    def test_unknown_outer_type_wrong_service_and_missing_sequence_fail(self):
        for header in ({'name': 'PropInfo', 'service': 'deposit', 'client_sequence_id': 1},
                       {'name': 'UnknownReq', 'service': 'deposit', 'client_sequence_id': 1},
                       {'name': 'CSDepositGetPropsReq', 'service': 'account', 'client_sequence_id': 1},
                       {'name': 'CSDepositGetPropsReq', 'service': 'deposit'}):
            with self.subTest(header=header), self.assertRaises(DomainError):
                self.codec.decode(BusinessEnvelope(b'', header).encode())
        for sequence in (True, 1 << 31, None):
            with self.subTest(sequence=sequence), self.assertRaises(DomainError):
                self.codec.encode('CSDepositGetPropsReq', {}, sequence=sequence)

    def test_unknown_body_and_nested_fields_or_truncation_are_rejected(self):
        request_header = {'name': 'CSDepositGetPropsReq', 'service': 'deposit', 'client_sequence_id': 1}
        response_header = dict(request_header, name='CSDepositGetPropsRes')
        for body, header in ((b'\xf8\x03\x01', request_header), (b'\x08\x80', request_header),
                             (b'\x0a\x03\xf8\x03\x01', response_header)):
            with self.subTest(body=body), self.assertRaises(DomainError):
                self.codec.decode(BusinessEnvelope(body, header).encode())
        with self.assertRaises(DomainError):
            self.codec.decode(b'\x0a\x80')

    def test_candidate_status_does_not_claim_gateway_or_authorization(self):
        status = self.codec.status()
        self.assertGreater(status['declared_service_message_count'], 2000)
        self.assertEqual(status['schema_selection'], 'explicit candidate business descriptor set')
        self.assertFalse(status['business_gateway_ready'])
        self.assertFalse(status['original_client_wire_compatibility_verified'])
        self.assertFalse(status['account_authorization_implemented'])
        message = self.codec.decode(self.codec.encode('CSAccountLoginReq', {'session_id': 'own secret'}, sequence=1))
        self.assertNotIn('own secret', repr(message))


if __name__ == '__main__':
    unittest.main()
