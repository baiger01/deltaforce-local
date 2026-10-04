import importlib
import importlib.util
from pathlib import Path
import tempfile
import unittest

from dfserver.core import Backend
from dfserver.client_errors import error_code
from dfserver.handshake_diagnostic import _candidate_codec
from dfserver.handshake_diagnostic import _candidate_local_account_state_response
from dfserver.gcp_data import decode_data_frame
from dfserver.local_commerce import response_fields


ROOT = Path(__file__).resolve().parent.parent
SELECTIONS = (
    ('CSAccountUpdateAvatarReq', 'avatar_id', 42010030001, 'AccountAvatarNotUnlock'),
    ('CSPlayerUpdateMilitaryTagReq', 'military_tag', 42020030001, 'PlayerInfoMilitaryTagNotUnlock'),
    ('CSPlayerUpdateTitleReq', 'title', 42030050001, 'PlayerInfoTitleNotUnlock'),
    ('CSPlayerUpdateHonorMarkReq', 'honor_mark', 42040010001, 'PlayerInfoHonorMarkNotUnlock'),
)


class ProfileCosmeticsTests(unittest.TestCase):
    def setUp(self):
        self.assertIsNotNone(importlib.util.find_spec('dfserver.profile_cosmetics'),
                             'Native profile cosmetic contracts are missing')
        self.cosmetics = importlib.import_module('dfserver.profile_cosmetics')
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.backend = Backend(Path(self.directory.name) / 'save.sqlite3', ROOT / 'definitions.json')
        self.token = self.backend.register('cosmetic', 'local-password-123')['session']
        self.other_token = self.backend.register('other-cosmetic', 'local-password-123')['session']
        with self.backend.connection() as connection:
            connection.executescript(self.cosmetics.SCHEMA)
        self.codec = _candidate_codec()

    def request(self, name, fields=None, token=None):
        request = self.codec.decode(self.codec.encode(name, fields or {}, sequence=23))
        result = response_fields(request, self.backend, token or self.token)
        self.assertIsNotNone(result, name)
        self.codec.response(request, result)
        return result

    def grant(self, item_id, quantity=1, token=None):
        with self.backend.connection() as connection:
            player_id = self.backend._authorize(connection, token or self.token)
            connection.execute('INSERT INTO native_lobby_collection_props VALUES (?,?,?)',
                               (player_id, item_id, quantity))
            connection.commit()

    def test_catalog_uses_recovered_social_avatar_rows(self):
        catalog = self.cosmetics.CATALOG
        self.assertEqual(catalog['row_count'], 2098)
        self.assertEqual(catalog['source_entry'], 7110)
        self.assertEqual(catalog['source_sha256'],
                         '50fe5c89e0ae53540ebf1a3df8cfca572b2c7558513516601f321fb12a7e8cbe')
        for _, _, item_id, _ in SELECTIONS:
            self.assertIn(item_id, self.cosmetics.SOCIAL_ITEMS)

    def test_unlock_list_contains_only_own_account_social_props(self):
        self.grant(42010030001, 2)
        self.grant(38050050066)
        self.grant(42020030001, token=self.other_token)
        result = self.request('CSCollectionUnlockAvatarsReq')
        self.assertEqual(result['result'], 0)
        self.assertEqual(result['props'], [{'id': 42010030001, 'gid': 0, 'num': 2}])
        self.assertEqual(self.request('CSCollectionUnlockAvatarsReq', token=self.other_token)['props'],
                         [{'id': 42020030001, 'gid': 0, 'num': 1}])

    def test_empty_account_does_not_unlock_any_catalog_items(self):
        self.assertEqual(self.request('CSCollectionUnlockAvatarsReq')['props'], [])
        self.assertEqual(self.backend.native_lobby_profile(self.token)['collection_props'], [])

    def test_unowned_social_items_cannot_be_equipped(self):
        before = self.cosmetics.profile_fields(self.backend, self.token)
        for name, field, item_id, failure in SELECTIONS:
            with self.subTest(name=name):
                self.assertEqual(self.request(name, {field: item_id})['result'], error_code(failure))
        self.assertEqual(self.cosmetics.profile_fields(self.backend, self.token), before)

    def test_other_accounts_ownership_does_not_allow_equipping(self):
        self.grant(42010030001, token=self.other_token)
        result = self.request('CSAccountUpdateAvatarReq', {'avatar_id': 42010030001})
        self.assertEqual(result['result'], error_code('AccountAvatarNotUnlock'))

    def test_owned_items_cannot_be_equipped_in_another_social_category(self):
        self.grant(42020030001)
        result = self.request('CSAccountUpdateAvatarReq', {'avatar_id': 42020030001})
        self.assertEqual(result['result'], error_code('AccountAvatarNotUnlock'))
        self.assertEqual(self.cosmetics.profile_fields(self.backend, self.token)['pic_url'], '')

    def test_owned_profile_selections_survive_backend_reopen(self):
        for name, field, item_id, _ in SELECTIONS:
            self.grant(item_id)
            self.assertEqual(self.request(name, {field: item_id})['result'], 0)
        self.backend = Backend(self.backend.database, ROOT / 'definitions.json')
        self.assertEqual(self.cosmetics.profile_fields(self.backend, self.token), {
            'pic_url': '42010030001', 'military_tag': 42020030001,
            'title': 42030050001, 'honor_mark': 42040010001})
        self.assertEqual(self.cosmetics.basic_info_fields(self.backend, self.token), {
            'pic_url': '42010030001', 'military_tag': 42020030001, 'title': 42030050001})
        self.assertEqual(self.cosmetics.profile_fields(self.backend, self.other_token), {
            'pic_url': '', 'military_tag': 0, 'title': 0, 'honor_mark': 0})

    def test_encrypted_profile_replies_restore_selected_social_items(self):
        for name, field, item_id, _ in SELECTIONS:
            self.grant(item_id)
            self.assertEqual(self.request(name, {field: item_id})['result'], 0)
        self.backend = Backend(self.backend.database, ROOT / 'definitions.json')
        key = b'0123456789abcdef'
        identity = {'native_id': 6388495194730612943, 'username': 'cosmetic'}
        for name in ('CSAccountGetPlayerProfileReq', 'CSPlayerGetBasicInfoReq'):
            with self.subTest(name=name):
                request = b'ABCD' + self.codec.encode(name, {}, sequence=35)
                frame = _candidate_local_account_state_response(request, self.backend,
                    self.token, identity, key, header_word4=12, header_word9=35)
                response = self.codec.decode(decode_data_frame(frame, key,
                    direction='server_to_client', compression_method=1).messages[0])
                fields = response.fields.get('info', response.fields)
                self.assertEqual(fields['pic_url'], '42010030001')
                self.assertEqual(int(fields['military_tag']), 42020030001)
                self.assertEqual(int(fields['title']), 42030050001)
                if name == 'CSAccountGetPlayerProfileReq':
                    self.assertEqual(int(fields['honor_mark']), 42040010001)

    def test_default_avatar_and_military_can_be_restored(self):
        for name, field, item_id, _ in SELECTIONS[:2]:
            self.grant(item_id)
            self.assertEqual(self.request(name, {field: item_id})['result'], 0)
            self.assertEqual(self.request(name, {field: 0})['result'], 0)
        self.assertEqual(self.cosmetics.profile_fields(self.backend, self.token), {
            'pic_url': '', 'military_tag': 0, 'title': 0, 'honor_mark': 0})

    def test_foreign_profile_request_does_not_return_this_accounts_cosmetics(self):
        self.grant(42010030001)
        self.request('CSAccountUpdateAvatarReq', {'avatar_id': 42010030001})
        key = b'0123456789abcdef'
        request = b'ABCD' + self.codec.encode('CSPlayerGetBasicInfoReq',
            {'player_id': 999}, sequence=36)
        frame = _candidate_local_account_state_response(request, self.backend, self.token,
            {'native_id': 6388495194730612943, 'username': 'cosmetic'}, key,
            header_word4=12, header_word9=36)
        response = self.codec.decode(decode_data_frame(frame, key,
            direction='server_to_client', compression_method=1).messages[0])
        self.assertEqual(response.fields['result'], error_code('PlayerInfoGetProfileFailed'))
        self.assertFalse(response.fields.get('info'))

    def test_unknown_config_id_cannot_be_unlocked_by_a_saved_collection_row(self):
        self.grant(42010039999)
        self.assertEqual(self.request('CSCollectionUnlockAvatarsReq')['props'], [])
        self.assertEqual(self.request('CSAccountUpdateAvatarReq', {'avatar_id': 42010039999})['result'],
                         error_code('AccountAvatarNotUnlock'))


if __name__ == '__main__':
    unittest.main()
