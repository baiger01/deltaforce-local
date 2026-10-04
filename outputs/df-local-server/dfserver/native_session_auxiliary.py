"""Installed auxiliary query contracts and authenticated local one-way receipts.

All source entries below belong to pak-0-0-pakchunk1-WindowsClient.pak.
FriendServer 6871 0.41.0 accepts an empty recommendation list; QuickPatchServer
6920 0.4.0 explicitly accepts no patches. InventoryServer_LabelLogic 6885 0.8
queries button state, while 0.6 and 0.11 handle actual changes. IDCSpeedLogic
4938 0.0.0 accepts an empty IDC directory and 0.15 disables DS polling when
client_ping_switch is absent. CollectionServer 6860 0.214 triggers low-rental
voucher distribution; its entitlement rules are unavailable and are refused.

ShopAutoRetroReward and TlogAgentTglog have no declared Res message. Local shop
purchases commit debit, grants, and purchase records atomically, so this save has
no asynchronous reward backlog. Telemetry is consumed locally as bounded digest
receipts; opaque event contents are neither persisted nor sent elsewhere.
"""

import base64
import binascii
import hashlib
import json
import sqlite3
import time

from .client_errors import error_code
from .core import DomainError, fail


SUPPORTED_REQUESTS = frozenset({
    'CSCollectionAutoDistributionReq', 'CSFriendRecommendReq', 'CSPatchQuickPatchReq',
    'CSPlayerInfoAddButtonHasBeenClickedReq', 'CSRoundtripDirReq',
})
ONE_WAY_REQUESTS = frozenset({'CSShopAutoRetroRewardReq', 'CSTlogAgentTglogReq'})
MAX_SITUATIONS = 256
MAX_SITUATION_BYTES = 1024
MAX_TELEMETRY_ENTRIES = 256
MAX_TELEMETRY_BYTES = 256 * 1024
MAX_TELEMETRY_RECEIPTS = 128
SCHEMA = """
CREATE TABLE IF NOT EXISTS native_session_telemetry_receipts (
 player_id TEXT NOT NULL REFERENCES players(id), digest TEXT NOT NULL,
 entry_count INTEGER NOT NULL, payload_bytes INTEGER NOT NULL,
 first_received INTEGER NOT NULL, last_received INTEGER NOT NULL,
 occurrences INTEGER NOT NULL DEFAULT 1, PRIMARY KEY(player_id,digest));
"""

# PAK entry, SHA-256, and matched encode/decode function IDs. These contain no
# original instructions or event payloads and are checked against codec metadata.
WIRE_CONTRACTS = {
    'CSCollectionAutoDistributionReq': {'entry': 6674,
        'sha256': 'bc6ea0f3b16b372eadcf331e16b189b6d1bed5ce4a083eb5fb875ce3c13974f6', 'encode': '0.99', 'decode': '0.98'},
    'CSFriendRecommendReq': {'entry': 6686,
        'sha256': '2617f8b640a33901fac97aec9e3aaf5ff867dc8226766fcff02364bca983eca9', 'encode': '0.63', 'decode': '0.62'},
    'CSRoundtripDirReq': {'entry': 6702,
        'sha256': '6c6b54ac25062f583505681cb1a85b7bb7380dc771597634da6e9cced2942c56', 'encode': '0.1', 'decode': '0.0'},
    'CSPatchQuickPatchReq': {'entry': 6728,
        'sha256': '490d815908af15c6d1717396a3662926b00a4735ada63479cda0e1ce0d3ba9d6', 'encode': '0.1', 'decode': '0.0'},
    'CSPlayerInfoAddButtonHasBeenClickedReq': {'entry': 6736,
        'sha256': 'aef9c0a315e377dd4f49ba78b26f36ef55d7f52657326d4eb977786eea7f1278', 'encode': '0.19', 'decode': '0.18'},
    'CSShopAutoRetroRewardReq': {'entry': 6770,
        'sha256': '78d12903fcf1cfdf1fbc9749060eeb5cdac2b84b2cf58201b31aad5483b7edb2', 'encode': '0.277', 'decode': '0.276'},
    'CSTlogAgentTglogReq': {'entry': 6796,
        'sha256': '77d1530ca0c1c8fa96e3f29bb5890b85cd607b6e115d0e526819bcb1448e439f', 'encode': '0.1', 'decode': '0.0'},
}
CONSUMER_SOURCES = {
    'CollectionServer.lua': {'entry': 6860,
        'sha256': '30fd97e50c22998e987b1fdcf8ee7a0e4edfe1ae51b93dc1d6e11ff5e7bf37f2', 'functions': ['0.214', '0.214.0']},
    'FriendServer.lua': {'entry': 6871,
        'sha256': 'ec54b7529b3e50a6f5361682237113cc4e05f577d6272780ee6306f061e469fd', 'functions': ['0.41', '0.41.0']},
    'InventoryServer_LabelLogic.lua': {'entry': 6885,
        'sha256': 'cfa633fd345e05d21a417691a84d0b440df6e4aa41464e0bbd5c70b524acd1c0', 'functions': ['0.8', '0.8.0', '0.6', '0.11']},
    'QuickPatchServer.lua': {'entry': 6920,
        'sha256': 'b6b9a05fc9098982f5e6436730bb4d8c9f4a6a7a1b4013363478904e2d703e1a', 'functions': ['0.4', '0.4.0']},
    'IDCSpeedLogic.lua': {'entry': 4938,
        'sha256': 'b050b75ba02dae85f8d67a3c1a3973a8b8dd562d73b9c3ccc1c20d2859565ff8', 'functions': ['0.0.0', '0.15']},
}


def _button_status(fields):
    situations = fields.get('situation_id_list', [])
    if not isinstance(situations, list) or len(situations) > MAX_SITUATIONS or any(
            not isinstance(value, str) or not value or len(value.encode('utf-8')) > MAX_SITUATION_BYTES
            for value in situations):
        fail('PlayerInfoInvaildParam', 'Button situation query is outside the local request bounds')
    # No native MarkChange writer is implemented in this save. Reading this query
    # must never create a click; absent local records are explicitly false.
    return {'result': 0, 'button_status_list': [
        {'situation_id': value, 'has_been_clicked': False}
        for value in dict.fromkeys(situations)]}


def response_fields(request, backend, token):
    if request.name not in SUPPORTED_REQUESTS:
        return None
    errors = {'CSCollectionAutoDistributionReq': 'CollectionLoadDBFailed',
              'CSFriendRecommendReq': 'FriendGetDBFailed',
              'CSPlayerInfoAddButtonHasBeenClickedReq': 'PlayerInfoGetDBFailed'}
    try:
        with backend.connection() as connection:
            backend._authorize(connection, token)
            if request.name == 'CSCollectionAutoDistributionReq':
                return {'result': error_code('CollectionPropDescNotFound')}
            if request.name == 'CSFriendRecommendReq':
                return {'result': 0, 'player_list': []}
            if request.name == 'CSPatchQuickPatchReq':
                return {'result': 0, 'patches': []}
            if request.name == 'CSPlayerInfoAddButtonHasBeenClickedReq':
                return _button_status(request.fields)
            return {'result': 0, 'idc_list': []}
    except DomainError as error:
        name = error.code if error.code == 'PlayerInfoInvaildParam' else errors.get(request.name, 'ServerDisabled')
        return {'result': error_code(name)}
    except (sqlite3.Error, ValueError, TypeError):
        return {'result': error_code(errors.get(request.name, 'ServerDisabled'))}


def _telemetry_receipt(connection, player_id, fields):
    supplied = fields.get('player_id', 0)
    if isinstance(supplied, bool) or not isinstance(supplied, (int, str)):
        fail('INVALID_ARGUMENT', 'Native telemetry identity is not an integer')
    try:
        supplied = int(supplied)
    except ValueError:
        fail('INVALID_ARGUMENT', 'Native telemetry identity is not an integer')
    identity = connection.execute('SELECT native_id FROM native_identities WHERE player_id=?', (player_id,)).fetchone()
    if supplied < 0 or supplied and (identity is None or supplied != identity['native_id']):
        fail('INVALID_ARGUMENT', 'Native telemetry identity does not belong to this local session')
    entries = fields.get('entry_array', [])
    if not isinstance(entries, list) or len(entries) > MAX_TELEMETRY_ENTRIES:
        fail('INVALID_ARGUMENT', 'Native telemetry entry count exceeds the local bound')
    digest, size = hashlib.sha256(), 0
    for entry in entries:
        if (not isinstance(entry, dict) or set(entry) - {'name', 'pbtlog', 'no_autofill'}
                or not isinstance(entry.get('name', ''), str)
                or not isinstance(entry.get('pbtlog', ''), str)
                or type(entry.get('no_autofill', False)) is not bool):
            fail('INVALID_ARGUMENT', 'Native telemetry entry differs from the recovered wire fields')
        try:
            payload = base64.b64decode(entry.get('pbtlog', ''), validate=True)
        except (binascii.Error, ValueError):
            fail('INVALID_ARGUMENT', 'Native telemetry bytes are not valid protobuf JSON bytes')
        size += len(payload)
        if size > MAX_TELEMETRY_BYTES or len(entry.get('name', '').encode('utf-8')) > 1024:
            fail('INVALID_ARGUMENT', 'Native telemetry exceeds the local byte bound')
        encoded = json.dumps(entry, sort_keys=True, separators=(',', ':'), ensure_ascii=True).encode('ascii')
        digest.update(len(encoded).to_bytes(4, 'big'))
        digest.update(encoded)
    value, now = digest.hexdigest(), int(time.time())
    connection.execute('INSERT INTO native_session_telemetry_receipts '
        '(player_id,digest,entry_count,payload_bytes,first_received,last_received) VALUES (?,?,?,?,?,?) '
        'ON CONFLICT(player_id,digest) DO UPDATE SET occurrences=occurrences+1,last_received=excluded.last_received',
        (player_id, value, len(entries), size, now, now))
    connection.execute('DELETE FROM native_session_telemetry_receipts WHERE player_id=? AND digest NOT IN '
        '(SELECT digest FROM native_session_telemetry_receipts WHERE player_id=? '
        'ORDER BY last_received DESC,rowid DESC LIMIT ?)', (player_id, player_id, MAX_TELEMETRY_RECEIPTS))
    return len(entries), size


def handle_one_way(request, backend, token, *, diagnostic_entry=None):
    """Consume declared one-way requests; errors propagate without a made-up Res."""
    if request.name not in ONE_WAY_REQUESTS:
        return False
    try:
        with backend.connection() as connection:
            connection.execute('BEGIN IMMEDIATE')
            player_id = backend._authorize(connection, token)
            if request.name == 'CSTlogAgentTglogReq':
                count, size = _telemetry_receipt(connection, player_id, request.fields)
            elif request.fields:
                fail('INVALID_ARGUMENT', 'Native automatic retro-reward request declares no fields')
            connection.commit()
        if diagnostic_entry is not None:
            diagnostic_entry['local_auxiliary_one_way'] = True
            diagnostic_entry['local_auxiliary_response_expected'] = False
            if request.name == 'CSTlogAgentTglogReq':
                diagnostic_entry['local_telemetry_entry_count'] = count
                diagnostic_entry['local_telemetry_payload_bytes'] = size
            else:
                diagnostic_entry['local_retro_reward_pending_count'] = 0
        return True
    except sqlite3.Error as error:
        raise DomainError('LOCAL_AUXILIARY_SAVE_FAILED', 'Local auxiliary receipt could not be saved') from error
