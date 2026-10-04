import base64
from pathlib import Path
import tempfile
import unittest

from dfserver import native_settings
from dfserver.core import Backend
from dfserver.handshake_diagnostic import _candidate_codec


ROOT = Path(__file__).resolve().parent.parent


class NativeSettingsTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.backend = Backend(Path(self.directory.name) / 'save.sqlite3', ROOT / 'definitions.json')
        self.token = self.backend.register('settings-a', 'local-password-123')['session']
        self.other = self.backend.register('settings-b', 'local-password-123')['session']
        with self.backend.connection() as connection:
            connection.executescript(native_settings.SCHEMA)
        self.codec = _candidate_codec()

    def request(self, name, fields=None, token=None):
        request = self.codec.decode(self.codec.encode(name, fields or {}, sequence=17))
        result = native_settings.response_fields(request, self.backend, token or self.token)
        response = self.codec.decode(self.codec.response(request, result))
        self.assertEqual(response.sequence, 17)
        self.assertEqual(response.service, 'setting')
        return result, response.fields

    def test_opaque_values_and_all_seven_fields_roundtrip_after_restart(self):
        kv = {'key': 'layout-01', 'type': 'CustomLayout', 'value': '{"x":1}',
              'share_code': '', 'title': 'local-layout',
              'value_byte': base64.b64encode(bytes(range(256))).decode('ascii'),
              'cloud_keys': '["x"]'}
        self.assertEqual(self.request('CSSettingPutKeyValueReq', {'kv': kv})[0]['result'], 0)
        self.backend = Backend(self.backend.database, ROOT / 'definitions.json')
        result, decoded = self.request('CSSettingGetValueByKeyReq', {'key': kv['key']})
        self.assertEqual(result['kv'], kv)
        self.assertEqual(decoded['kv'], kv)

    def test_account_isolation_and_overwrite_move_between_type_queries(self):
        first = {'key': 'shared-key', 'type': 'first', 'value': 'one'}
        second = {'key': 'shared-key', 'type': 'second', 'value': 'two'}
        self.request('CSSettingPutKeyValueReq', {'kv': first})
        self.request('CSSettingPutKeyValueReq', {'kv': second}, self.other)
        self.assertEqual(self.request('CSSettingGetValueByKeyReq', {'key': first['key']})[0]['kv']['value'], 'one')
        self.request('CSSettingPutKeyValueReq', {'kv': second})
        self.assertEqual(self.request('CSSettingGetValuesByTypeReq', {'type': 'first'})[0]['kv_array'], [])
        self.assertEqual(self.request('CSSettingGetValuesByTypeReq', {'type': 'second'})[0]['kv_array'], [second])
        self.assertEqual(self.request('CSSettingGetValueByKeyReq', {'key': first['key']}, self.other)[0]['kv'], second)
        with self.backend.connection() as connection:
            self.assertEqual(connection.execute('SELECT COUNT(*) FROM native_lobby_settings').fetchone()[0], 2)

    def test_native_missing_record_and_empty_parameter_errors(self):
        for name, fields, code in (
            ('CSSettingPutKeyValueReq', {}, 152005),
            ('CSSettingPutKeyValueReq', {'kv': {'type': 'local'}}, 152003),
            ('CSSettingPutKeyValueReq', {'kv': {'key': 'key'}}, 152004),
            ('CSSettingGetValueByKeyReq', {}, 152003),
            ('CSSettingGetValueByKeyReq', {'key': 'absent'}, 152006),
            ('CSSettingGetValuesByTypeReq', {}, 152004),
        ):
            with self.subTest(name=name, fields=fields):
                result, decoded = self.request(name, fields)
                self.assertEqual(result['result'], code)
                self.assertEqual(decoded['result'], code)
                self.assertNotIn('kv', decoded)
        self.assertEqual(self.request('CSSettingGetValuesByTypeReq', {'type': 'absent'})[0],
                         {'result': 0, 'kv_array': []})

    def test_missing_optional_native_settings_preserve_client_defaults(self):
        for key in ('SaveBaseSetting', 'SaveSensititySetting', 'InventoryAutoLine',
                    'SaveSOLMarkingItems', 'PlayerSensitity', 'PlayerBase', 'SAFEHOUSE_LOC_KEY',
                    'FriendDynamic'):
            with self.subTest(key=key):
                result, decoded = self.request('CSSettingGetValueByKeyReq', {'key': key})
                self.assertEqual(result, {'result': 0, 'kv': {'key': key, 'value': ''}})
                self.assertEqual(decoded, result)
        with self.backend.connection() as connection:
            self.assertEqual(connection.execute('SELECT COUNT(*) FROM native_lobby_settings').fetchone()[0], 0)

    def test_saved_optional_setting_overrides_empty_fallback_only_for_its_owner(self):
        kv = {'key': 'SaveBaseSetting', 'type': 'SaveSystemSetting', 'value': 'opaque-client-setting'}
        self.assertEqual(self.request('CSSettingPutKeyValueReq', {'kv': kv})[0]['result'], 0)
        self.backend = Backend(self.backend.database, ROOT / 'definitions.json')
        self.assertEqual(self.request('CSSettingGetValueByKeyReq', {'key': kv['key']})[0]['kv'], kv)
        self.assertEqual(self.request('CSSettingGetValueByKeyReq', {'key': kv['key']}, self.other)[0],
                         {'result': 0, 'kv': {'key': kv['key'], 'value': ''}})

    def test_empty_values_are_stored_and_repeated_put_is_idempotent(self):
        kv = {'key': 'empty', 'type': 'local', 'value': '', 'value_byte': ''}
        for _ in range(3):
            self.assertEqual(self.request('CSSettingPutKeyValueReq', {'kv': kv})[0], {'result': 0})
        self.assertEqual(self.request('CSSettingGetValueByKeyReq', {'key': 'empty'})[0]['kv'], kv)
        with self.backend.connection() as connection:
            self.assertEqual(connection.execute('SELECT COUNT(*) FROM native_lobby_settings').fetchone()[0], 1)

    def test_local_response_capacity_and_unauthorized_writes_preserve_existing_values(self):
        initial = {'key': 'bounded', 'type': 'local', 'value': 'original'}
        self.request('CSSettingPutKeyValueReq', {'kv': initial})
        oversized = {**initial, 'value': 'x' * native_settings.MAX_STORED_JSON_BYTES}
        self.assertEqual(self.request('CSSettingPutKeyValueReq', {'kv': oversized})[0]['result'], 152001)
        self.assertEqual(self.request('CSSettingPutKeyValueReq', {'kv': initial},
            token='invalid-local-session')[0]['result'], 152001)
        self.assertEqual(self.request('CSSettingGetValueByKeyReq', {'key': initial['key']},
            token='invalid-local-session')[0]['result'], 152000)
        self.assertEqual(self.request('CSSettingGetValueByKeyReq', {'key': initial['key']})[0]['kv'], initial)

    def test_sql_write_failure_rolls_back_and_returns_original_save_error(self):
        initial = {'key': 'rollback', 'type': 'local', 'value': 'original'}
        self.request('CSSettingPutKeyValueReq', {'kv': initial})
        with self.backend.connection() as connection:
            connection.execute("CREATE TRIGGER setting_write_failure BEFORE UPDATE ON native_lobby_settings "
                               "BEGIN SELECT RAISE(ABORT,'test failure'); END")
            connection.commit()
        self.assertEqual(self.request('CSSettingPutKeyValueReq',
            {'kv': {**initial, 'value': 'replacement'}})[0]['result'], 152001)
        self.assertEqual(self.request('CSSettingGetValueByKeyReq', {'key': initial['key']})[0]['kv'], initial)


if __name__ == '__main__':
    unittest.main()
