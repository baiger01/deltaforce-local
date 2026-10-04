import base64
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from dfserver import native_session_auxiliary as auxiliary
from dfserver.candidate_business import CandidateMessage
from dfserver.core import Backend, DomainError
from dfserver.handshake_diagnostic import _candidate_codec


ROOT = Path(__file__).resolve().parent.parent


class NativeSessionAuxiliaryTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.backend = Backend(Path(self.directory.name) / 'save.sqlite3', ROOT / 'definitions.json')
        self.token = self.backend.register('auxiliary-a', 'local-password-123')['session']
        self.other = self.backend.register('auxiliary-b', 'local-password-123')['session']
        with self.backend.connection() as connection:
            connection.executescript(auxiliary.SCHEMA)
        self.codec = _candidate_codec()

    def decoded(self, name, fields=None):
        return self.codec.decode(self.codec.encode(name, fields or {}, sequence=23))

    def response(self, name, fields=None, token=None):
        request = self.decoded(name, fields)
        result = auxiliary.response_fields(request, self.backend, token or self.token)
        response = self.codec.decode(self.codec.response(request, result))
        self.assertEqual(response.sequence, 23)
        self.assertEqual(response.service, request.service)
        return result, response.fields

    def test_real_empty_queries_have_native_success_and_no_invented_objects(self):
        for name, expected in (
            ('CSFriendRecommendReq', {'result': 0, 'player_list': []}),
            ('CSPatchQuickPatchReq', {'result': 0, 'patches': []}),
            ('CSRoundtripDirReq', {'result': 0, 'idc_list': []}),
            ('CSPlayerInfoAddButtonHasBeenClickedReq', {'result': 0, 'button_status_list': []}),
        ):
            with self.subTest(name=name):
                result, decoded = self.response(name)
                self.assertEqual(result, expected)
                self.assertEqual(decoded, {'result': 0})
        self.assertEqual(self.response('CSPatchQuickPatchReq', {'curr_patch_id': 2**63})[0],
                         {'result': 0, 'patches': []})

    def test_button_status_query_does_not_record_a_click(self):
        fields = {'situation_id_list': ['176_42', '176_99', '176_42']}
        expected = {'result': 0, 'button_status_list': [
            {'situation_id': '176_42', 'has_been_clicked': False},
            {'situation_id': '176_99', 'has_been_clicked': False}]}
        for token in (self.token, self.other, self.token):
            result, decoded = self.response('CSPlayerInfoAddButtonHasBeenClickedReq', fields, token)
            self.assertEqual(result, expected)
            self.assertEqual(decoded, expected)

    def test_distribution_without_recovered_entitlement_is_explicitly_refused(self):
        with self.backend.connection() as connection:
            before = list(connection.execute('SELECT * FROM native_lobby_collection_props'))
        result, decoded = self.response('CSCollectionAutoDistributionReq')
        self.assertEqual(result, {'result': 157012})
        self.assertEqual(decoded, result)
        with self.backend.connection() as connection:
            self.assertEqual(list(connection.execute('SELECT * FROM native_lobby_collection_props')), before)

    def test_queries_require_local_authorization_and_original_error_codes(self):
        for name, code in (
            ('CSFriendRecommendReq', 24011),
            ('CSPlayerInfoAddButtonHasBeenClickedReq', 28008),
            ('CSCollectionAutoDistributionReq', 157000),
            ('CSPatchQuickPatchReq', 10010),
            ('CSRoundtripDirReq', 10010),
        ):
            with self.subTest(name=name):
                self.assertEqual(self.response(name, token='invalid-local-session')[0], {'result': code})

    def test_invalid_button_parameters_are_rejected_without_querying_records(self):
        for fields in ({'situation_id_list': ['']}, {'situation_id_list': ['x' * 1025]},
                       {'situation_id_list': ['1'] * 257}):
            self.assertEqual(self.response('CSPlayerInfoAddButtonHasBeenClickedReq', fields)[0],
                             {'result': 28001})

    def tlog(self, body=b'local-client-event', player_id=0):
        return self.decoded('CSTlogAgentTglogReq', {'player_id': player_id, 'entry_array': [
            {'name': 'NativeEvent', 'pbtlog': base64.b64encode(body).decode('ascii'),
             'no_autofill': True}]})

    def test_one_way_messages_have_no_response_type_or_fake_response_fields(self):
        for name in auxiliary.ONE_WAY_REQUESTS:
            request = self.decoded(name)
            self.assertIsNone(auxiliary.response_fields(request, self.backend, self.token))
            with self.assertRaises(DomainError):
                self.codec.response(request, {'result': 0})
            entry = {}
            self.assertTrue(auxiliary.handle_one_way(request, self.backend, self.token, diagnostic_entry=entry))
            self.assertTrue(entry['local_auxiliary_one_way'])
            self.assertFalse(entry['local_auxiliary_response_expected'])
        with self.backend.connection() as connection:
            self.assertEqual(connection.execute('SELECT COUNT(*) FROM native_lobby_shop_records').fetchone()[0], 0)

    def test_telemetry_receipts_persist_are_bounded_and_do_not_store_payloads(self):
        request = self.tlog()
        for _ in range(2):
            self.assertTrue(auxiliary.handle_one_way(request, self.backend, self.token))
        self.backend = Backend(self.backend.database, ROOT / 'definitions.json')
        with self.backend.connection() as connection:
            receipt = dict(connection.execute('SELECT * FROM native_session_telemetry_receipts').fetchone())
            self.assertEqual(receipt['occurrences'], 2)
            self.assertEqual(receipt['entry_count'], 1)
            self.assertEqual(receipt['payload_bytes'], len(b'local-client-event'))
            self.assertNotIn('local-client-event', json.dumps(receipt))
        self.assertTrue(auxiliary.handle_one_way(request, self.backend, self.other))
        with patch.object(auxiliary, 'MAX_TELEMETRY_RECEIPTS', 2):
            for value in (b'two', b'three', b'four'):
                self.assertTrue(auxiliary.handle_one_way(self.tlog(value), self.backend, self.token))
        with self.backend.connection() as connection:
            counts = list(connection.execute('SELECT COUNT(*) FROM native_session_telemetry_receipts GROUP BY player_id'))
            self.assertEqual(sorted(row[0] for row in counts), [1, 2])

    def test_one_way_invalid_identity_payload_and_write_failure_have_no_success_receipt(self):
        with self.assertRaises(DomainError):
            auxiliary.handle_one_way(self.tlog(player_id=2**63), self.backend, self.token)
        with self.assertRaises(DomainError):
            auxiliary.handle_one_way(self.tlog(), self.backend, 'invalid-local-session')
        request = CandidateMessage('CSTlogAgentTglogReq', 'tlogagent', 1,
            {'entry_array': [{'name': 'NativeEvent', 'pbtlog': 'invalid-base64'}]})
        with self.assertRaises(DomainError):
            auxiliary.handle_one_way(request, self.backend, self.token)
        with patch.object(auxiliary, 'MAX_TELEMETRY_BYTES', 1), self.assertRaises(DomainError):
            auxiliary.handle_one_way(self.tlog(), self.backend, self.token)
        with self.backend.connection() as connection:
            connection.execute("CREATE TRIGGER fail_tlog BEFORE INSERT ON native_session_telemetry_receipts "
                               "BEGIN SELECT RAISE(ABORT,'test failure'); END")
            connection.commit()
        with self.assertRaises(DomainError):
            auxiliary.handle_one_way(self.tlog(), self.backend, self.token)
        with self.backend.connection() as connection:
            self.assertEqual(connection.execute('SELECT COUNT(*) FROM native_session_telemetry_receipts').fetchone()[0], 0)

    def test_source_metadata_matches_recovered_wire_contract_hashes(self):
        metadata = json.loads((ROOT / 'protocol/generated_codec_fields.json').read_text(encoding='utf-8'))
        recovered = {row['name']: row for row in metadata['messages']}
        for name, contract in auxiliary.WIRE_CONTRACTS.items():
            row = recovered[name]
            self.assertEqual(row['source_sha256'], contract['sha256'])
            self.assertEqual(row['encode_function_id'], contract['encode'])
            self.assertEqual(row['decode_function_id'], contract['decode'])
            self.assertTrue(row['all_observed_field_calls_matched'])


if __name__ == '__main__':
    unittest.main()
