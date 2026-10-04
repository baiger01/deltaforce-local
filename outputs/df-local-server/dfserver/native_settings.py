"""Opaque local settings using installed cs_setting_editor_pb.lua fields.

PAK1 entries 6766/6767 define all seven SettingKeyValue fields. Consumers in
SystemSettingServer.lua entry 6945 read value/title/cloud_keys verbatim. Its
optional initialization keys accept an explicit empty value and retain the
client's own defaults. Unknown missing keys use SettingEmptyRecord. No share
codes or default configuration contents are generated locally.
"""

import json
import sqlite3

from .business_envelope import MAX_ENVELOPE_BYTES
from .client_errors import error_code
from .core import DomainError, fail


SUPPORTED_REQUESTS = frozenset({'CSSettingPutKeyValueReq', 'CSSettingGetValueByKeyReq',
                                'CSSettingGetValuesByTypeReq'})
KV_FIELDS = frozenset({'key', 'type', 'value', 'share_code', 'title', 'value_byte', 'cloud_keys'})
# SystemSettingServer.lua entry 6945: 0.28/0.35/0.37/0.39/0.46/0.49
# and their callbacks explicitly skip an empty kv.value.
# IrisSafeHouseServer.lua entry 6894: root SAFEHOUSE_LOC_KEY, 0.1/0.1.0;
# SHA-256 6f2fbc7857eab2ee033ebd67ea3e7036c556b5c349f7345b5e258a8807e0f367.
# FriendServer.lua entry 6871: 0.2 sets FriendDynamic, 0.99/0.99.0 read it;
# SHA-256 ec54b7529b3e50a6f5361682237113cc4e05f577d6272780ee6306f061e469fd.
OPTIONAL_SETTING_KEYS = frozenset({'PlayerSensitity', 'SaveBaseSetting', 'SaveSensititySetting',
                                  'PlayerBase', 'InventoryAutoLine', 'SaveSOLMarkingItems',
                                  'SAFEHOUSE_LOC_KEY', 'FriendDynamic'})
# Local save bound: leave enough envelope space to return every setting of a type.
MAX_STORED_JSON_BYTES = MAX_ENVELOPE_BYTES // 2
SCHEMA = """
CREATE TABLE IF NOT EXISTS native_lobby_settings (
 player_id TEXT NOT NULL REFERENCES players(id), key TEXT NOT NULL,
 type TEXT NOT NULL, kv_json TEXT NOT NULL, PRIMARY KEY(player_id,key));
CREATE INDEX IF NOT EXISTS native_lobby_settings_by_type
 ON native_lobby_settings(player_id,type);
"""


def _required(value, name):
    if not isinstance(value, str) or not value:
        fail('SettingEmpty' + name.capitalize(), 'Required native setting parameter is empty')
    return value


def _put(connection, player_id, fields):
    kv = fields.get('kv')
    if not isinstance(kv, dict) or not kv:
        fail('SettingEmptyPutReq', 'Native settings request has no key/value record')
    key, category = _required(kv.get('key'), 'key'), _required(kv.get('type'), 'type')
    if set(kv) - KV_FIELDS or any(not isinstance(value, str) for value in kv.values()):
        fail('SettingEmptyPutReq', 'Key/value record does not match the recovered wire fields')
    payload = json.dumps(kv, ensure_ascii=True, separators=(',', ':'))
    used = connection.execute('SELECT COALESCE(SUM(LENGTH(kv_json)),0) FROM native_lobby_settings '
        'WHERE player_id=? AND key<>?', (player_id, key)).fetchone()[0]
    if used + len(payload) > MAX_STORED_JSON_BYTES:
        fail('SettingSaveDBFailed', 'Local settings would exceed the bounded native query response')
    connection.execute('INSERT INTO native_lobby_settings(player_id,key,type,kv_json) VALUES (?,?,?,?) '
        'ON CONFLICT(player_id,key) DO UPDATE SET type=excluded.type,kv_json=excluded.kv_json',
        (player_id, key, category, payload))
    return {'result': 0}


def response_fields(request, backend, token):
    """Return native response fields; persist opaque values only to the local save."""
    name, fields = request.name, request.fields
    if name not in SUPPORTED_REQUESTS:
        return None
    writing = name == 'CSSettingPutKeyValueReq'
    try:
        with backend.connection() as connection:
            if writing:
                connection.execute('BEGIN IMMEDIATE')
            player_id = backend._authorize(connection, token)
            if writing:
                result = _put(connection, player_id, fields)
                connection.commit()
                return result
            if name == 'CSSettingGetValueByKeyReq':
                key = _required(fields.get('key'), 'key')
                row = connection.execute('SELECT kv_json FROM native_lobby_settings '
                    'WHERE player_id=? AND key=?', (player_id, key)).fetchone()
                if row is None:
                    if key in OPTIONAL_SETTING_KEYS:
                        return {'result': 0, 'kv': {'key': key, 'value': ''}}
                    fail('SettingEmptyRecord', 'Local account has no setting for this key')
                return {'result': 0, 'kv': json.loads(row['kv_json'])}
            category = _required(fields.get('type'), 'type')
            rows = connection.execute('SELECT kv_json FROM native_lobby_settings '
                'WHERE player_id=? AND type=? ORDER BY key', (player_id, category)).fetchall()
            return {'result': 0, 'kv_array': [json.loads(row['kv_json']) for row in rows]}
    except DomainError as error:
        code = error.code if error.code.startswith('Setting') else (
            'SettingSaveDBFailed' if writing else 'SettingLoadDBFailed')
        return {'result': error_code(code)}
    except (sqlite3.Error, ValueError, TypeError):
        return {'result': error_code('SettingSaveDBFailed' if writing else 'SettingLoadDBFailed')}
