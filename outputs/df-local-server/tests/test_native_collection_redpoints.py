"""Exercise collection read receipts through the native lobby wire route."""

from collections import deque
from contextlib import redirect_stdout
import io
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest

from dfserver.core import Backend
from dfserver.gcp_data import decode_data_frame, encode_data_frame
from dfserver.gcp_framing import StreamDecoder
from dfserver.handshake_diagnostic import (
    _candidate_codec, _candidate_local_collection_response, _continue_local_lobby)
from dfserver.local_commerce import response_fields


ROOT = Path(__file__).resolve().parent.parent
BRICK = 16110000020
KEY = 32320000001


class ClosedTransport:
    def __init__(self):
        self.sent = []

    def sendall(self, data):
        self.sent.append(data)

    def recv(self, size):
        return b''


class NativeCollectionRedPointTests(unittest.TestCase):
    def setUp(self):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.backend = Backend(Path(directory.name) / 'save.sqlite3', ROOT / 'definitions.json')
        self.token = self.backend.register('collection-read', 'local-password-123')['session']
        with self.backend.connection() as connection:
            player_id = self.backend._authorize(connection, self.token)
            connection.execute('INSERT INTO native_lobby_collection_props VALUES (?,?,?)',
                               (player_id, BRICK, 10))
            connection.commit()
        self.codec = _candidate_codec()
        self.key = b'0123456789abcdef'

    def load(self):
        message = b'ABCD' + self.codec.encode('CSCollectionLoadPropsReq', {}, sequence=20)
        frame = _candidate_local_collection_response(message, self.backend, self.token,
            self.key, header_word4=12, header_word9=20)
        return self.codec.decode(decode_data_frame(frame, self.key,
            direction='server_to_client', compression_method=1).messages[0]).fields

    def update(self, fields, *, token=None, expected_result=0):
        sequence = 483
        message = sequence.to_bytes(4, 'big') + self.codec.encode(
            'CSCollectionUpdateRedPointReq', fields, sequence=sequence)
        current = encode_data_frame((message,), self.key, direction='client_to_server',
                                    header_word4=12, header_word9=sequence)
        transport, result = ClosedTransport(), {}
        with redirect_stdout(io.StringIO()):
            _continue_local_lobby(transport, StreamDecoder(), deque(), current,
                SimpleNamespace(session_key=self.key), {}, self.backend,
                token or self.token, 900, result, continuation_seconds=1)
        entry = result['bounded_business_continuation'][0]
        self.assertNotIn('request_not_answered', entry)
        self.assertTrue(entry['response_sent'])
        self.assertEqual(len(transport.sent), 1)
        frames = StreamDecoder().feed(transport.sent[0])
        response = self.codec.decode(decode_data_frame(frames[0], self.key,
            direction='server_to_client', compression_method=1).messages[0])
        self.assertEqual((response.name, response.sequence),
                         ('CSCollectionUpdateRedPointRes', sequence))
        self.assertEqual(response.fields, {'result': expected_result})
        return entry

    def identities(self, fields):
        return {(int(row.get('prop_id') or 0), int(row.get('prop_gid') or 0))
                for row in fields.get('redpoint_list', []) if row.get('prop_id')}

    def page(self, name, fields=None):
        request = self.codec.decode(self.codec.encode(name, fields or {}, sequence=20))
        result = response_fields(request, self.backend, self.token)
        return self.codec.decode(self.codec.response(request, result)).fields

    def test_wire_update_replies_and_clears_read_after_reload_and_backend_restart(self):
        first = self.load()
        self.assertIn((BRICK, 0), self.identities(first))
        entry = self.update({'props': [{'id': BRICK}]})
        self.assertEqual(entry['local_commerce_result'], 0)
        self.assertEqual(entry['local_collection_read_request']['props'], [{'id': str(BRICK)}])
        self.assertNotIn((BRICK, 0), self.identities(self.load()))
        self.backend = Backend(self.backend.database, ROOT / 'definitions.json')
        self.token = self.backend.login('collection-read', 'local-password-123')['session']
        self.assertNotIn((BRICK, 0), self.identities(self.load()))
        self.update({'props': [{'id': BRICK}]})
        owned = self.backend.native_lobby_profile(self.token)['collection_props']
        self.assertEqual(next(row['quantity'] for row in owned if row['template_id'] == BRICK), 10)

    def test_read_instance_is_exact_and_does_not_clear_another_owned_instance(self):
        from dfserver.gun_skins import SKINS
        skin_id = next(skin_id for skin_id, row in SKINS.items() if row['is_mystical'])
        with self.backend.connection() as connection:
            player_id = self.backend._authorize(connection, self.token)
            connection.executemany('INSERT INTO native_lobby_gun_skins VALUES (?,?,?,NULL)',
                [(player_id, skin_id, 2001), (player_id, skin_id, 2002)])
            connection.commit()
        self.assertTrue({(skin_id, 2001), (skin_id, 2002)} <= self.identities(self.load()))
        self.update({'props': [{'id': skin_id, 'gid': 2001}]})
        after = self.identities(self.load())
        self.assertNotIn((skin_id, 2001), after)
        self.assertIn((skin_id, 2002), after)

    def test_foreign_or_unknown_prop_cannot_clear_reads_or_change_ownership(self):
        from dfserver.client_errors import error_code
        other = self.backend.register('collection-other', 'local-password-123')['session']
        self.load()
        before = self.backend.native_lobby_profile(self.token)
        self.update({'props': [{'id': BRICK}]}, token=other,
                    expected_result=error_code('CollectionPropNotFound'))
        self.update({'props': [{'id': BRICK}, {'id': KEY}]},
                    expected_result=error_code('CollectionPropNotFound'))
        self.assertIn((BRICK, 0), self.identities(self.load()))
        self.assertEqual(self.backend.native_lobby_profile(self.token)['collection_props'],
                         before['collection_props'])
        self.assertEqual(self.backend.native_lobby_profile(other)['collection_props'], [])

    def test_legacy_id_read_clears_only_that_owned_template(self):
        self.load()
        self.update({'prop_ids': [BRICK]})
        self.assertNotIn((BRICK, 0), self.identities(self.load()))

    def test_skin_pendant_and_social_loads_share_exact_read_receipts(self):
        from dfserver.gun_skins import SKINS
        from dfserver.weapon_pendants import PENDANTS
        skin_id = next(item for item, row in SKINS.items() if row['is_mystical'])
        pendant_id = next(item for item, row in PENDANTS.items() if row['is_mystical'])
        social_id = 42010030001
        with self.backend.connection() as connection:
            player_id = self.backend._authorize(connection, self.token)
            connection.execute('INSERT INTO native_lobby_gun_skins VALUES (?,?,?,NULL)',
                               (player_id, skin_id, 2001))
            connection.execute('INSERT INTO native_lobby_pendant_instances VALUES (?,?,?,?)',
                               (player_id, pendant_id, 2002, '{}'))
            connection.execute('INSERT INTO native_lobby_collection_props VALUES (?,?,1)',
                               (player_id, social_id))
            connection.commit()
        pages = [('CSCollectionLoadMysticalSkinPropsReq', (skin_id, 2001)),
                 ('CSCollectionLoadMysticalPendantPropsReq', (pendant_id, 2002)),
                 ('CSCollectionUnlockAvatarsReq', (social_id, 0))]
        for name, pair in pages:
            with self.subTest(name=name):
                before = self.page(name)
                self.assertIn(pair, self.identities(before))
                self.update({'props': [{'id': pair[0], 'gid': pair[1]}]})
                after = self.page(name)
                self.assertNotIn(pair, self.identities(after))
                self.assertEqual({key: value for key, value in after.items() if key != 'redpoint_list'},
                                 {key: value for key, value in before.items() if key != 'redpoint_list'})
        for _, pair in pages:
            self.assertNotIn(pair, self.identities(self.load()))

    def test_pattern_receipt_persists_independently_without_granting_any_prop(self):
        from dfserver.native_collection import with_redpoints
        # Exercise the wire's uint64 range; this is not a runtime pattern mapping.
        pattern_id = 2**64 - 1
        other = self.backend.register('collection-other', 'local-password-123')['session']
        self.load()
        before = self.backend.native_lobby_profile(self.token)['collection_props']
        self.update({'gun_skin_pattern_id': [pattern_id]})
        self.backend = Backend(self.backend.database, ROOT / 'definitions.json')
        self.assertEqual(self.backend.native_lobby_profile(self.token)['collection_props'], before)
        payload = {'result': 0, 'redpoint_list': [{'prop_id': '0',
                                                'gun_skin_pattern_id': str(pattern_id)}]}
        self.assertEqual(with_redpoints('CSCollectionLoadPropsReq', payload,
                                      self.backend, self.token)['redpoint_list'], [])
        self.assertEqual(with_redpoints('CSCollectionLoadPropsReq', payload,
                                      self.backend, other)['redpoint_list'], payload['redpoint_list'])
        self.assertFalse(any(row.get('gun_skin_pattern_id') for row in self.load().get('redpoint_list', [])))
        with self.backend.connection() as connection:
            rows = [dict(row) for row in connection.execute(
                'SELECT kind,item_id,item_gid FROM native_lobby_collection_reads')]
        self.assertEqual(rows, [{'kind': 'pattern', 'item_id': str(pattern_id), 'item_gid': '0'}])

    def test_invalid_prop_identity_replies_without_committing_a_partial_read(self):
        from dfserver.client_errors import error_code
        self.load()
        self.update({'props': [{'id': BRICK}, {'id': 0, 'gid': 1}]},
                    expected_result=error_code('CollectionParamWorng'))
        self.assertIn((BRICK, 0), self.identities(self.load()))

    def test_native_empty_read_entries_are_noops_without_granting_or_marking_reads(self):
        self.load()
        before = self.backend.native_lobby_profile(self.token)['collection_props']
        for entry in ({}, {'id': 0}, {'gid': 0}, {'id': 0, 'gid': 0}):
            with self.subTest(entry=entry):
                self.update({'props': [entry]})
                self.assertIn((BRICK, 0), self.identities(self.load()))
        self.assertEqual(self.backend.native_lobby_profile(self.token)['collection_props'], before)
        with self.backend.connection() as connection:
            self.assertEqual(connection.execute(
                'SELECT COUNT(*) FROM native_lobby_collection_reads').fetchone()[0], 0)

    def test_empty_read_entry_does_not_block_real_receipt_or_bypass_unknown_identity(self):
        from dfserver.client_errors import error_code
        self.load()
        self.update({'props': [{}, {'id': BRICK}, {'id': KEY}]},
                    expected_result=error_code('CollectionPropNotFound'))
        self.assertIn((BRICK, 0), self.identities(self.load()))
        self.update({'props': [{}, {'id': BRICK}, {'id': 0, 'gid': 0}]})
        self.assertNotIn((BRICK, 0), self.identities(self.load()))

    def test_new_collection_grant_and_reacquisition_are_unread(self):
        from dfserver.premium_shop import collection_change
        self.load()
        self.update({'props': [{'id': BRICK}]})
        with self.backend.connection() as connection:
            player_id = self.backend._authorize(connection, self.token)
            collection_change(connection, player_id, BRICK, 1)
            connection.commit()
        self.assertTrue((BRICK, 0) in self.identities(self.load()))
        self.update({'props': [{'id': BRICK}]})
        with self.backend.connection() as connection:
            player_id = self.backend._authorize(connection, self.token)
            collection_change(connection, player_id, BRICK, -11)
            collection_change(connection, player_id, BRICK, 1)
            connection.commit()
        self.assertTrue((BRICK, 0) in self.identities(self.load()))

    def test_save_failure_replies_and_rolls_back_the_prior_prop_receipt(self):
        from dfserver.client_errors import error_code
        self.load()
        with self.backend.connection() as connection:
            connection.executescript("""
                CREATE TRIGGER reject_test_pattern_receipt
                BEFORE INSERT ON native_lobby_collection_reads WHEN NEW.kind='pattern'
                BEGIN SELECT RAISE(ABORT, 'test receipt save failure'); END;
            """)
        self.update({'props': [{'id': BRICK}], 'gun_skin_pattern_id': [1]},
                    expected_result=error_code('CollectionSaveDBFailed'))
        self.assertTrue((BRICK, 0) in self.identities(self.load()))
        with self.backend.connection() as connection:
            self.assertEqual(connection.execute(
                'SELECT COUNT(*) FROM native_lobby_collection_reads').fetchone()[0], 0)


if __name__ == '__main__':
    unittest.main()
