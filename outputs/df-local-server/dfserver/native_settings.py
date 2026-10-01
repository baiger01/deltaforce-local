"""Opaque local settings using installed cs_setting_editor_pb.lua fields.

PAK1 entries 6766/6767 define all seven SettingKeyValue fields. Consumers in
SystemSettingServer.lua entry 6945 read value/title/cloud_keys verbatim. A
successful missing-key response is invalid for those consumers, so use the
installed SettingEmptyRecord result. No share codes are generated locally.
"""

import json
import sqlite3

from .business_envelope import MAX_ENVELOPE_BYTES
from .client_errors import error_code
from .core import DomainError, fail


SUPPORTED_REQUESTS = frozenset({'CSSettingPutKeyValueReq', 'CSSettingGetValueByKeyReq',
                                'CSSettingGetValuesByTypeReq'})
KV_FIELDS = frozenset({'key', 'type', 'value', 'share_code', 'title', 'value_byte', 'cloud_keys'})
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
