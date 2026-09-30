"""Bounded loopback GCP handshake diagnostic.

This listener supports a bounded, locally authenticated compatibility trial
against the original client. Diagnostic exponent-one mode is restricted to
loopback: the resulting session key is public and must never protect an
Internet account session. Reports contain only framing and field lengths.
"""
import argparse
from collections import deque
from datetime import datetime, timezone
from functools import lru_cache
import hashlib
import json
import os
from pathlib import Path
import secrets
import socket
import socketserver
import threading
import time

from .gcp_control import AuthResponse, CommonAuthResponse, ReadyResponse, parse_auth_request
from .business_probe import summarize_message_shape, summarize_prefixed_envelope
from .business_envelope import BusinessEnvelope, parse_business_envelope
from .candidate_business import CandidateBusinessCodec
from .client_errors import inventory_error
from .container_layouts import capacity as container_capacity
from .core import (POCKET_LAYOUT, POCKET_POSITION,
                   BACKPACK_LAYOUT, BACKPACK_POSITION, CHEST_RIG_LAYOUT,
                   CHEST_RIG_POSITION, DomainError)
from .gcp_crypto import decode_received_body, encrypt_body
from .gcp_data import decode_data_frame, encode_data_frame
from .gcp_framing import Frame, StreamDecoder
from .gcp_handshake import DhAckBody, DhAckHeader, ServerDhAcknowledgement, create_server_ack, parse_hello
from .local_commerce import (SUPPORTED_REQUESTS as LOCAL_COMMERCE_REQUESTS,
                             response_fields as local_commerce_response_fields,
                             installed_items, item_condition_fields, inventory_location)


LOCAL_FINISHED_GUIDE_STAGES = (6, 7, 1, 2, 3, 5, 34)


def _time():
    return datetime.now(timezone.utc).isoformat()


@lru_cache(maxsize=1)
def _candidate_codec():
    """Share immutable descriptors; per-message protobuf instances stay local."""
    root = Path(__file__).resolve().parent.parent
    return CandidateBusinessCodec(root / 'protocol/candidate_business.pb',
                                  root / 'protocol/generated_class_metadata.json')


def _read_modulus(path):
    raw = Path(path).read_text(encoding='ascii').strip()
    if len(raw) != 128 or any(char not in '0123456789abcdefABCDEF' for char in raw):
        raise ValueError('DH modulus file must contain exactly 128 hex digits')
    value = bytes.fromhex(raw)
    if int.from_bytes(value, 'big') <= 5 or not value[-1] & 1:
        raise ValueError('DH modulus must be an odd nontrivial value')
    return value


class State:
    def __init__(self, report):
        self.path = Path(report)
        self.lock = threading.Lock()
        self.data = {'kind': 'loopback_dh_handshake_diagnostic',
                     'started_at_utc': _time(), 'listening': False,
                     'connections_received': 0, 'records': [],
                     'game_account_authorization_implemented': False,
                     'game_login_response_sent': False,
                     'original_client_compatibility_verified': False,
                     'raw_frames_credentials_dh_keys_or_modulus_in_report': False}

    def update(self, **values):
        with self.lock:
            self.data.update(values)
            self._write()

    def record(self, result):
        with self.lock:
            self.data['connections_received'] += 1
            self.data['records'] = (self.data['records'] + [result])[-32:]
            self._write()

    def _write(self):
        self.path.parent.mkdir(parents=True, exist_ok=True)
        temporary = self.path.with_suffix(self.path.suffix + '.tmp')
        temporary.write_text(json.dumps(self.data, indent=2) + '\n', encoding='utf-8')
        temporary.replace(self.path)


def _log_request_progress(entry, phase):
    fields = ('request_name', 'service', 'prefix_sequence', 'elapsed_ms',
              'response_sent', 'response_elapsed_ms', 'local_commerce_result',
              'request_not_answered', 'failure_code', 'local_bullet_commands',
              'local_body_container_snapshots', 'local_serial_buy_items',
              'local_inventory_change_notification_sent')
    event = {'event': 'business_request', 'phase': phase, 'observed_at_utc': _time()}
    event.update({name: entry[name] for name in fields if name in entry})
    print(json.dumps(event), flush=True)


def _receive_one(connection, decoder, queue):
    while not queue:
        chunk = connection.recv(65536)
        if not chunk:
            return None
        queue.extend(decoder.feed(chunk))
    return queue.popleft()


def _diagnostic_ack(hello_frame, hello):
    """Use g=2, exponent 1 so the shared value equals the hello public value.

    This is a protocol diagnostic only. Anyone seeing the hello can compute the
    key, so it must never authorize accounts or carry private application data.
    """
    public = int.from_bytes(hello.client_public_key, 'big')
    if public <= 2:
        raise ValueError('Invalid diagnostic DH peer public value')
    shared = public.to_bytes((public.bit_length() + 7) // 8, 'big')
    key = hashlib.md5(shared, usedforsecurity=False).digest()
    header = DhAckHeader((2).to_bytes(64, 'big'), 1, 500, 0)
    frame = Frame(11, hello_frame.header_word4, 0x1002, 1,
                  hello_frame.header_word9, header.encode(),
                  encrypt_body(DhAckBody(b'').encode(), key))
    frame.encode()
    return ServerDhAcknowledgement(frame, key)


def _identity_correlations(request, expected):
    """Report only whether a local test identity appears on this one exchange."""
    if not isinstance(expected, dict):
        raise ValueError('Expected a private local identity description')
    token, native_id, username = expected['token'], expected['native_id'], expected['username']
    if (not isinstance(token, str) or not token.isascii() or not token or len(token) > 128
            or type(native_id) is not int or not 0 < native_id < 2**63
            or not isinstance(username, str) or not username):
        raise ValueError('Invalid private local identity description')
    fields = (request.opaque_credential, request.opaque_auth_data, request.opaque_context)
    token_bytes = token.encode('ascii')
    native_decimal = str(native_id).encode('ascii')
    native_binary = (native_id.to_bytes(8, 'big'), native_id.to_bytes(8, 'little'))
    name_bytes = username.encode('utf-8')
    return {
        'local_token_exact_field': any(field == token_bytes for field in fields),
        'local_token_contained_in_field': any(token_bytes in field for field in fields),
        'local_token_contained_in_auth_data': token_bytes in request.opaque_auth_data,
        'local_token_sha256_contained': any(hashlib.sha256(token_bytes).digest() in field for field in fields),
        'native_id_decimal_contained': any(native_decimal in field for field in fields),
        'native_id_binary_contained': any(any(value in field for value in native_binary) for field in fields),
        'local_username_contained': any(name_bytes in field for field in fields),
    }


def _parser_probe_control_body(command):
    """Use the 0x3366 control readers, not the unrelated 0x4366 codec.

    These are schema-shaped, zero-valued parser probes. They deliberately do
    not assert authentication success or populate an account identity.
    """
    if command == 0x2002:
        return AuthResponse(CommonAuthResponse(0, 0, None, 0), 0, b'', 0,
                            b'', 0, 0, b'').encode()
    if command == 0x6002:
        # The native reader receives frame.header_word4 (12), not the preceding
        # frame.version (11). Version 12 adds four 32-bit extension words.
        return ReadyResponse(0, bytes(16), 0).encode(version=12)
    raise ValueError('Unsupported parser-probe control command')


def _derived_ready_body(expected_identity):
    """Make a distinct, local-only relay tuple from an authorized test session.

    This tests whether a zero relay tuple caused the 0x6002 rejection. It is not
    evidence that these values implement the original server's relay policy.
    """
    token = expected_identity['token'].encode('ascii')
    relay_identity = hashlib.sha256(b'df-local-relay-v1\0' + token).digest()[:16]
    return ReadyResponse(1, relay_identity, 1, 0, 0).encode()


def _session_bound_auth_body(request, expected_identity):
    """Probe the SDK account response with our authenticated local identity.

    The 0x2002 reader's common prefix carries account type, format, value and
    UID; its next word and blob carry auth type and ticket in the older SDK
    formatter. Remaining extension fields are still unknown, so this is only a
    scoped compatibility probe, never a production authorization response.
    """
    native_id = expected_identity['native_id']
    token = expected_identity['token'].encode('ascii')
    return AuthResponse(CommonAuthResponse(1, 2, native_id, native_id),
                        request.auth_type, token, 0, b'', 0, 0, b'').encode()


def _candidate_local_login_response(message, expected_identity, key, *, header_word4, header_word9):
    """One bounded, locally authenticated login-response compatibility probe.

    Client requests contain a four-byte prefix. The original client's receive
    log reports "parse cspkg failed" for prefixed server responses, indicating
    the downstream CSPkg parser receives the payload directly on this path.
    """
    if len(message) < 5:
        raise ValueError('Truncated login package')
    codec = _candidate_codec()
    request = codec.decode(message[4:])
    if request.name != 'CSAccountLoginReq' or request.service != 'account':
        raise ValueError('Unexpected first business request')
    native_id = expected_identity['native_id']
    registered = expected_identity.get('game_registered', True)
    fields = {
        # The standalone auto-login path opens its in-lobby name editor after a
        # successful login with is_register unset. Error 15024 leaves it on the
        # loading view because LoginInterface has no active register listener.
        'result': 0,
        'player_id': native_id,
        'player_id_str': str(native_id),
        'area_id': 1,
        'zone_id': 1,
    }
    if registered:
        fields['game_nick'] = expected_identity.get('game_nick') or expected_identity['username']
        fields['is_register'] = True
    response = codec.response(request, fields)
    frame = encode_data_frame((response,), key,
                              direction='server_to_client',
                              opaque_flag=64,
                              header_word4=header_word4,
                              header_word9=header_word9)
    return frame


def _candidate_local_state_response(message, expected_identity, key, *, header_word4, header_word9):
    if len(message) < 5:
        raise ValueError('Truncated state package')
    codec = _candidate_codec()
    request = codec.decode(message[4:])
    if request.name != 'CSStateGetInfoReq' or request.service != 'online':
        raise ValueError('Unexpected post-login state request')
    response = codec.response(request, {
        'PlayerID': expected_identity['native_id'],
        'State': 0,
        'result': 0,
    })
    return encode_data_frame((response,), key,
                             direction='server_to_client',
                             opaque_flag=64,
                             header_word4=header_word4,
                             header_word9=header_word9)


def _candidate_local_heartbeat_response(message, key, *, header_word4, header_word9):
    if len(message) < 5:
        raise ValueError('Truncated heartbeat package')
    codec = _candidate_codec()
    request = codec.decode(message[4:])
    if request.name != 'CSOnlineHeartbeatReq' or request.service != 'online':
        raise ValueError('Unexpected heartbeat request')
    padding = request.fields.get('padding', 0)
    response = codec.response(request, {
        'padding': padding,
        'tick_count': int(time.monotonic() * 1000),
    })
    return encode_data_frame((response,), key, direction='server_to_client',
                             opaque_flag=64, header_word4=header_word4,
                             header_word9=header_word9)


def _transport_ping_reply(request, *, header_word9):
    """Echo a 0x9001 ping, as seen in both directions of the official capture."""
    if request.command != 0x9001 or len(request.extra_header) != 24 or request.body:
        raise ValueError('Unexpected transport ping layout')
    # Official gateway capture: client ping frames use flag 0, server ping
    # frames use flag 1 even though both have an empty body.
    return Frame(request.version, request.header_word4, 0x9001, 1,
                 header_word9, request.extra_header, b'')


def _suggest_local_game_nick(native_id):
    """Generate a new account-scoped ASCII suggestion under 16 characters."""
    if type(native_id) is not int or not 0 < native_id < 1 << 63:
        raise ValueError('Invalid local native ID')
    alphabet = '0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ'
    digits = []
    while native_id:
        native_id, digit = divmod(native_id, len(alphabet))
        digits.append(alphabet[digit])
    prefix = 'DL' + ''.join(reversed(digits))
    suffix_length = min(5, 16 - len(prefix))
    return prefix + ''.join(secrets.choice(alphabet) for _ in range(suffix_length))


def _candidate_local_nick_response(message, backend, local_session, key, *,
                                   header_word4, header_word9):
    """Handle name validation and creation for the authenticated local account."""
    if len(message) < 5 or backend is None or not local_session:
        raise ValueError('A local account session is required for character creation')
    codec = _candidate_codec()
    request = codec.decode(message[4:])
    if request.name == 'CSAccountValidateNickReq' and request.service == 'account':
        try:
            state = backend.validate_game_nick(local_session, request.fields.get('nick'))
            result = 0 if state['available'] else 1
        except DomainError:
            result = 1
        fields = {'result': result}
    elif request.name == 'CSAccountRegisterReq' and request.service == 'account':
        try:
            profile = backend.register_game_nick(local_session, request.fields.get('game_nick'))
            fields = {'result': 0, 'game_nick': profile['game_nick']}
        except DomainError:
            fields = {'result': 1, 'err_msg': 'Local character name is unavailable'}
    elif request.name == 'CSAccountRandNickReq' and request.service == 'account':
        native_id = backend.native_identity(local_session)['native_id']
        for _ in range(8):
            suggestion = _suggest_local_game_nick(native_id)
            if backend.validate_game_nick(local_session, suggestion)['available']:
                fields = {'result': 0, 'nick': suggestion}
                break
        else:
            fields = {'result': 1}
    else:
        raise ValueError('Unexpected character-name request')
    response = codec.response(request, fields)
    return encode_data_frame((response,), key, direction='server_to_client',
                             opaque_flag=64, header_word4=header_word4,
                             header_word9=header_word9)


def _candidate_local_unicode_conf_response(message, key, *, header_word4, header_word9):
    """Give the character-name editor bounded Unicode validation rules."""
    if len(message) < 5:
        raise ValueError('Truncated Unicode configuration request')
    codec = _candidate_codec()
    request = codec.decode(message[4:])
    if request.name != 'CSAccountGetUnicodeConfReq' or request.service != 'account':
        raise ValueError('Unexpected Unicode configuration request')
    ranges = [(0x20, 0x7e), (0x3400, 0x9fff)]
    response = codec.response(request, {
        'result': 0,
        'white_list': [{'minRune': start, 'maxRune': end} for start, end in ranges],
        'black_list': [],
        'count_chars': [{'minRune': start, 'maxRune': end, 'charNum': 1}
                        for start, end in ranges],
        'default_char_num': 1,
        'max_char_num': 16,
    })
    return encode_data_frame((response,), key, direction='server_to_client',
                             opaque_flag=64, header_word4=header_word4,
                             header_word9=header_word9)


def _candidate_local_hall_mode_response(message, key, *, header_word4, header_word9):
    """Acknowledge the client's transition into a local lobby mode."""
    if len(message) < 5:
        raise ValueError('Truncated hall-mode request')
    codec = _candidate_codec()
    request = codec.decode(message[4:])
    if request.name != 'CSClientEnterHallModeReq' or request.service != 'playerinfo':
        raise ValueError('Unexpected hall-mode request')
    mode_id = request.fields.get('enter_mode_id', 0)
    if type(mode_id) is not int or not 0 <= mode_id < (1 << 31):
        raise ValueError('Invalid hall mode')
    response = codec.response(request, {'result': 0})
    return encode_data_frame((response,), key, direction='server_to_client',
                             opaque_flag=64, header_word4=header_word4,
                             header_word9=header_word9)


@lru_cache(maxsize=1)
def _candidate_known_operator_ids():
    """Select installed operator avatars with distinct matching base outfits."""
    root = Path(__file__).resolve().parent.parent
    catalog = json.loads((root / 'protocol/operator_asset_catalog.json').read_text(encoding='utf-8'))
    rows = catalog['rows']
    # The earlier thirteen-operator subset stopped at 41. The installed table
    # also has four distinct avatar/base-outfit pairs at 45, 46, 47 and 51.
    # Other C-series rows are not included merely because they are tagged Hero.
    extra_base = {
        88000000038: 'M_Elio', 88000000039: 'F_Claire',
        88000000040: 'M_Landon', 88000000041: 'M_Rashid',
        88000000045: 'F_C103', 88000000046: 'M_C204',
        88000000047: 'M_C405', 88000000051: 'M_C104',
    }
    ids = []
    for raw_id, row in rows.items():
        avatar_id = int(raw_id)
        if not (row.get('known_name') or avatar_id in extra_base):
            continue
        parts = row.get('views', {}).get('UI', {}).get('core_parts', [])
        if row.get('character_tag') != 'ECharacterTag::Hero' or not parts:
            raise ValueError(f'Operator avatar {avatar_id} has no installed UI model')
        if avatar_id in extra_base and not any(
                extra_base[avatar_id] in part['mesh_path'] for part in parts):
            raise ValueError(f'Unverified operator avatar {avatar_id}')
        ids.append(avatar_id)
    ids = tuple(sorted(ids))
    if not {88000000025, 88000000027, *extra_base}.issubset(ids):
        raise ValueError('Expected operator avatars are absent from the installed catalog')
    return ids


@lru_cache(maxsize=1)
def _candidate_operator_base_fashions():
    """Map operator IDs to installed base outfits with matching UI model families."""
    root = Path(__file__).resolve().parent.parent
    rows = json.loads((root / 'protocol/operator_asset_catalog.json').read_text(
        encoding='utf-8'))['rows']
    suffixes = {
        25: (6, 'M_Dragon'), 26: (7, 'F_Hack'), 27: (2, 'M_Roy'),
        28: (3, 'F_Luna'), 29: (4, 'M_Terry'), 30: (5, 'M_Kai'),
        35: (8, 'M_David'), 36: (9, 'F_Zoya'), 37: (10, 'M_Sineva'),
        38: (11, 'M_Elio'), 39: (12, 'F_Claire'),
        40: (13, 'M_Landon'), 41: (14, 'M_Rashid'),
        45: (18, 'F_C103'), 46: (19, 'M_C204'),
        47: (20, 'M_C405'), 51: (24, 'M_C104'),
    }
    mapping = {}
    for hero_suffix, (fashion_suffix, family) in suffixes.items():
        hero_id = 88000000000 + hero_suffix
        fashion_id = 30000020000 + fashion_suffix
        for item_id in (hero_id, fashion_id):
            row = rows.get(str(item_id), {})
            parts = row.get('views', {}).get('UI', {}).get('core_parts', [])
            if row.get('character_tag') != 'ECharacterTag::Hero' or not any(
                    family in part['mesh_path'] for part in parts):
                raise ValueError(f'Unverified base outfit {fashion_id} for hero {hero_id}')
        mapping[hero_id] = fashion_id
    if set(mapping) != set(_candidate_known_operator_ids()):
        raise ValueError('Operator catalogue and base-outfit mapping differ')
    return mapping


def _candidate_local_hero_response(message, backend, local_session, key, *, header_word4, header_word9):
    """Probe hero catalogue fields using installed base-avatar IDs.

    Hero IDs and base-outfit IDs are separate installed asset rows. The mapping
    is checked against their matching UI model families, then trialled in game.
    """
    if len(message) < 5:
        raise ValueError('Truncated hero package')
    codec = _candidate_codec()
    request = codec.decode(message[4:])
    ids = _candidate_known_operator_ids()
    fashions = _candidate_operator_base_fashions()
    if request.name == 'CSHeroGetHeroIDListReq':
        fields = {'result': 0, 'hero_ids': list(ids)}
    elif request.name == 'CSHeroLoadHeroListReq':
        selected = backend.native_lobby_profile(local_session)['selected_hero_id'] or 88000000025
        if selected not in ids:
            selected = 88000000025
        fields = {
            'result': 0,
            'hero_ids': list(ids),
            'mp_hero_selected': selected,
            'sol_hero_selected': selected,
            'heros': [{
                'hero_id': hero_id,
                'is_unlock': True,
                'can_use': True,
                'is_blast_unlock': True,
                'fashion_list': [{'fashion': {'slot': 0, 'id': fashions[hero_id]},
                                  'is_unlock': True, 'is_def': True, 'is_read': True}],
                'fashion_equipped': [{'slot': 0, 'id': fashions[hero_id]}],
            } for hero_id in ids],
        }
    else:
        raise ValueError('Not a supported hero catalogue request')
    response = codec.response(request, fields)
    return encode_data_frame((response,), key, direction='server_to_client',
                             opaque_flag=64, header_word4=header_word4,
                             header_word9=header_word9)


def _candidate_local_hero_select_response(message, backend, local_session, key,
                                          *, header_word4, header_word9):
    """Acknowledge a client-selected installed operator and save it locally."""
    if len(message) < 5:
        raise ValueError('Truncated hero selection package')
    codec = _candidate_codec()
    request = codec.decode(message[4:])
    if request.name != 'CSHeroSelectHeroReq':
        raise ValueError('Not a hero selection request')
    hero_id = int(request.fields.get('hero_id', 0))
    if hero_id not in _candidate_known_operator_ids():
        raise ValueError('Operator ID is absent from the installed SOL catalogue')
    mode = int(request.fields.get('mode', 0))
    if not -(1 << 31) <= mode < (1 << 31):
        raise ValueError('Unsupported hero selection mode')
    backend.set_native_selected_hero(local_session, hero_id)
    response = codec.response(request, {
        'result': 0, 'mode': mode, 'hero_id': hero_id,
        'reborn_boss_type': int(request.fields.get('reborn_boss_type', 0)),
    })
    return encode_data_frame((response,), key, direction='server_to_client',
                             opaque_flag=64, header_word4=header_word4,
                             header_word9=header_word9)


@lru_cache(maxsize=1)
def _candidate_local_map_board_catalog():
    probe = os.environ.get('DF_LOCAL_MAP_ID_PROBE')
    if probe:
        try:
            first, last = (int(value) for value in probe.split(':'))
        except ValueError as error:
            raise ValueError('Invalid bounded map ID probe range') from error
        if not 1 <= first <= last <= 10000 or last - first > 499:
            raise ValueError('Map ID probe must contain at most 500 IDs in 1..10000')
        return [{'map_id': map_id, 'point_id': map_id,
                 'match_mode_id': map_id, 'min_level': 1}
                for map_id in range(first, last + 1)]
    root = Path(__file__).resolve().parent.parent
    rows = json.loads((root / 'protocol/local_map_board_candidates.json').read_text(
        encoding='utf-8'))['operations']
    if len({(row['point_id'], row.get('match_mode_type', 1)) for row in rows}) != len(rows):
        raise ValueError('Invalid bounded local map board candidates')
    for row in rows:
        if any(type(row[field]) is not int or row[field] <= 0 for field in
               ('map_id', 'point_id', 'match_mode_id', 'min_level')):
            raise ValueError('Invalid local map board candidate field')
        if type(row.get('match_mode_type', 1)) is not int or row.get('match_mode_type', 1) <= 0:
            raise ValueError('Invalid local map board match mode type')
    return rows


def _candidate_local_prepare_map_response(message, backend, local_session, key,
                                          *, header_word4, header_word9):
    """Answer preparation boards with locally observed map candidates.

    This only populates the operations board for a bounded client trial. The
    actual entrance and matchmaking mappings still require native validation.
    """
    if len(message) < 5:
        raise ValueError('Truncated preparation board package')
    codec = _candidate_codec()
    request = codec.decode(message[4:])
    if request.name not in ('CSPrepareMapBoardReq', 'CSPrepareTDMMapBoardReq',
                            'CSPrepareBombMapBoardReq'):
        raise ValueError('Not a preparation board request')
    fields = {'result': 0}
    if request.name == 'CSPrepareMapBoardReq':
        level = backend.native_lobby_profile(local_session)['level']
        fields['board_info_array'] = [
            {'point_id': row['point_id'], 'mode': {
                'game_mode': 1, 'game_rule': 4, 'sub_mode': 10, 'team_mode': 3,
                'map_id': row['map_id'], 'match_mode_id': row['match_mode_id']},
             'need_level': row['min_level'], 'is_open': int(level >= row['min_level']),
             'is_show': 1, 'lock_reason': 0 if level >= row['min_level'] else 1,
             'match_mode_type': row.get('match_mode_type', 1)}
            for row in _candidate_local_map_board_catalog()]
    response = codec.response(request, fields)
    return encode_data_frame((response,), key, direction='server_to_client',
                             opaque_flag=64, header_word4=header_word4,
                             header_word9=header_word9)


def _candidate_local_commerce_response(message, backend, local_session, key,
                                       *, header_word4, header_word9):
    if len(message) < 5:
        raise ValueError('Truncated commerce package')
    codec = _candidate_codec()
    request = codec.decode(message[4:])
    fields = local_commerce_response_fields(request, backend, local_session)
    if fields is None:
        raise ValueError('Not a supported local commerce request')
    response = codec.response(request, fields)
    return encode_data_frame((response,), key, direction='server_to_client',
                             opaque_flag=64, header_word4=header_word4,
                             header_word9=header_word9, max_output=1024 * 1024)


def _candidate_local_commerce_item_ids(message):
    """Keep only requested item IDs in the diagnostic, never account payloads."""
    fields = _candidate_codec().decode(message[4:]).fields
    ids = [int(value) for value in fields.get('prop_ids', [])]
    ids.extend(int(info.get('prop_id') or 0) for info in fields.get('infos', []))
    info = fields.get('info') or {}
    ids.extend((int(info.get('prop_id') or 0), int(fields.get('prop_id') or 0),
                int((fields.get('mall_prop') or {}).get('prop_info', {}).get('id') or 0)))
    return list(dict.fromkeys(item_id for item_id in ids if item_id))[:64]


def _candidate_local_commerce_type_filters(message):
    """Record the bounded type-list filters using the client's declared field types."""
    fields = _candidate_codec().decode(message[4:]).fields
    return {
        'prop_ids': [int(value) for value in fields.get('prop_ids', [])[:100]],
        'prop_prefixes': [int(value) for value in fields.get('prop_prefixes', [])[:100]],
        'with_nums': fields.get('with_nums', False),
    }


def _candidate_local_module_status_response(message, key, *, header_word4, header_word9):
    """Return the installed client's module IDs as unlocked for the local save."""
    if len(message) < 5:
        raise ValueError('Truncated module status package')
    codec = _candidate_codec()
    request = codec.decode(message[4:])
    if request.name != 'CSSwitchLoadModuleStatusReq':
        raise ValueError('Not a module status request')
    module_ids = (
        1000, 1001, 1002, 1003, 2000, 2001, 3000, 3001, 3002, 3003,
        4000, 4001, 5000, 5001, 5002, 5003, 5004, 5104, 6000, 6001,
        7000, 7001, 7002, 8000, 9000, 9001, 10000, 11000, 11001,
        11002, 11003, 12000, 12001, 12002, 14000, 15000, 16000,
        20001, 20002, 20003, 20004, 20005, 20006,
    )
    response = codec.response(request, {
        'result': 0,
        'status': [{'module_id': module_id, 'is_unlocked': True,
                    'is_init_unlock': True, 'is_need_popup': False,
                    'unlock_timestamp': 1}
                   for module_id in module_ids],
    })
    return encode_data_frame((response,), key, direction='server_to_client',
                             opaque_flag=64, header_word4=header_word4,
                             header_word9=header_word9)


def _candidate_local_lottery_purchase_summary(message):
    """Record only shop item IDs and prices needed to debug a failed purchase."""
    request = _candidate_codec().decode(message[4:])
    if request.name != 'CSShopBuyLotteryItemReq':
        raise ValueError('Not a lottery purchase request')
    return [{'item_id': int(row.get('item_id') or 0),
             'num': int(row.get('num') or 0),
             'currency_type': int(row.get('currency_type') or 0),
             'price': int(row.get('price') or 0),
             'slippage': int(row.get('slippage') or 0),
             'currency_type_substitute': int(row.get('currency_type_substitute') or 0),
             'price_substitute': int(row.get('price_substitute') or 0)}
            for row in request.fields.get('buy_props', [])][:16]


def _candidate_local_serial_buy_summary(message):
    """Record non-secret purchase routing and equipment fields for diagnosis."""
    request = _candidate_codec().decode(message[4:])
    if request.name != 'CSSerialCheapBuyReq':
        raise ValueError('Not a serial purchase request')
    rows = []
    for entry in request.fields.get('buy_list', [])[:32]:
        mall = entry.get('mall_prop') or {}
        mall_prop = mall.get('prop_info') or {}
        auction = entry.get('auction_prop') or {}
        single = entry.get('single_auction_prop') or {}
        prices = entry.get('mall_prices') or mall.get('prices') or []
        rows.append({
            'channel': int(entry.get('channel') or 0),
            'item_id': int(mall_prop.get('id') or auction.get('prop_id')
                           or single.get('prop_id') or 0),
            'num': int(mall_prop.get('num') or auction.get('total_num')
                       or single.get('buy_num') or 0),
            'exchange_id': int(mall.get('exchange_id') or 0),
            'auction_currency': int(auction.get('currency')
                                    or single.get('currency') or 0),
            'auction_price': int(auction.get('price') or single.get('price') or 0),
            'mall_prices': [{'money_type': int(price.get('money_type') or 0),
                             'price': int(price.get('price') or 0)}
                            for price in prices[:8]],
            'target_position': int(mall_prop.get('position') or 0),
            'target_location': mall_prop.get('loc') or {},
            'auction_assemble_info': auction.get('assemble_info') or {},
            'single_auction_to_pos': int(single.get('to_pos') or 0),
            'single_auction_assemble_info': single.get('assemble_info') or {},
        })
    return {'scene': int(request.fields.get('scene') or 0),
            'buy_plan_type': int(request.fields.get('buy_plan_type') or 0),
            'outfit_index': int(request.fields.get('outfit_index') or 0),
            'rows': rows}


def _candidate_local_sell_summary(message):
    request = _candidate_codec().decode(message[4:])
    if request.name != 'CSMallSellReq':
        raise ValueError('Not a mall sale request')
    return {'props': [{'id': int(prop.get('id') or 0),
                       'gid': int(prop.get('gid') or 0),
                       'num': int(prop.get('num') or 0)}
                      for prop in request.fields.get('sell_props', [])[:32]],
            'prices': [{'money_type': int(price.get('money_type') or 0),
                        'price': int(price.get('price') or 0)}
                       for price in request.fields.get('prices', [])[:32]]}


def _candidate_local_commerce_result(response_frame, key):
    decoded = decode_data_frame(response_frame, key, direction='server_to_client',
                                compression_method=1, max_output=1024 * 1024)
    result = _candidate_codec().decode(decoded.messages[0]).fields.get('result')
    return None if result is None else int(result)


def _candidate_local_inventory_change_notification(response_frame, key, *,
                                                   header_word4, header_word9):
    """Push a committed commerce change through the client's inventory listener."""
    codec = _candidate_codec()
    decoded = decode_data_frame(response_frame, key, direction='server_to_client',
                                compression_method=1)
    if len(decoded.messages) != 1:
        raise ValueError('Expected one local purchase response')
    response = codec.decode(decoded.messages[0])
    if int(response.fields.get('result', 1)) != 0:
        return None
    change = (response.fields.get('change') or response.fields.get('changes')
              or response.fields.get('deposit_change')
              or response.fields.get('prop_changes')
              or response.fields.get('mall_changes')
              or response.fields.get('auction_changes'))
    if not change:
        return None
    if response.name == 'CSShopBuyLotteryItemRes':
        # Its prop changes are consumed by CollectionServer, never DepositServer.
        change = {'currency_changes': change.get('currency_changes', [])}
    notification = codec.encode('CSDepositChangeNtf',
                                {'deposit_change': change}, sequence=0)
    return encode_data_frame((notification,), key, direction='server_to_client',
                             opaque_flag=64, header_word4=header_word4,
                             header_word9=header_word9)


def _candidate_local_collection_change_notification(response_frame, key, *,
                                                    header_word4, header_word9):
    """Push purchased Mandel bricks through the collection listener."""
    codec = _candidate_codec()
    decoded = decode_data_frame(response_frame, key, direction='server_to_client',
                                compression_method=1)
    if len(decoded.messages) != 1:
        raise ValueError('Expected one local purchase response')
    response = codec.decode(decoded.messages[0])
    if response.name != 'CSShopBuyLotteryItemRes' or int(response.fields.get('result', 1)) != 0:
        return None
    changes = []
    for entry in response.fields.get('change', {}).get('prop_changes', []):
        prop = entry.get('prop') or {}
        changes.append({'change_type': 1,
                        'prop': {'id': int(prop['id']), 'gid': 0,
                                 'num': int(prop['num'])},
                        'delta_num': int(prop['num'])})
    if not changes:
        return None
    notification = codec.encode('CSCollectionPropChangeNtf',
                                {'data_change': changes}, sequence=0)
    return encode_data_frame((notification,), key, direction='server_to_client',
                             opaque_flag=64, header_word4=header_word4,
                             header_word9=header_word9)


def _candidate_local_hero_unlock_response(message, key, *, header_word4, header_word9):
    """Describe the owned local operators to the selection panel."""
    if len(message) < 5:
        raise ValueError('Truncated hero unlock package')
    codec = _candidate_codec()
    request = codec.decode(message[4:])
    if request.name != 'CSHeroGetUnlockInfoReq':
        raise ValueError('Not a hero unlock catalogue request')
    root = Path(__file__).resolve().parent.parent
    rows = json.loads((root / 'protocol/operator_asset_catalog.json').read_text(
        encoding='utf-8'))['rows']
    response = codec.response(request, {
        'result': 0,
        'unlock_info': [dict({'hero_id': hero_id, 'get_type': 0},
                             **({'name': rows[str(hero_id)]['known_name']}
                                if rows[str(hero_id)].get('known_name') else {}))
                        for hero_id in _candidate_known_operator_ids()],
    })
    return encode_data_frame((response,), key, direction='server_to_client',
                             opaque_flag=64, header_word4=header_word4,
                             header_word9=header_word9)


@lru_cache(maxsize=1)
def _candidate_main_deposit_grid():
    """Read the installed version's main warehouse dimensions, never fixtures."""
    root = Path(__file__).resolve().parent.parent
    catalog = json.loads((root / 'protocol/deposit_slot_catalog.json').read_text(encoding='utf-8'))
    slot_id = catalog['main_container_slot_id']
    row = catalog['rows'][str(slot_id)]
    length, width = row['grid_length'], row['grid_width']
    if slot_id != 2 or (length, width) != (9, 40):
        raise ValueError('Unverified main warehouse slot configuration')
    return {'grid_page_id': slot_id, 'grid_length': length,
            'grid_width': width, 'props': []}


@lru_cache(maxsize=1)
def _candidate_body_equipment_positions():
    """Initialize the installed client's equipment slots before item moves."""
    root = Path(__file__).resolve().parent.parent
    catalog = json.loads((root / 'protocol/deposit_slot_catalog.json').read_text(encoding='utf-8'))
    positions = []
    for slot_id, row in catalog['rows'].items():
        position = int(slot_id)
        if not 100 < position < 139:
            continue
        length, width = int(row['grid_length']), int(row['grid_width'])
        if length < 1 or width < 1:
            continue
        positions.append({'position': position, 'capacity': int(row['capacity']),
                          'grid_space': [{'id': 0, 'length': length, 'width': width}]})
    positions.sort(key=lambda row: row['position'])
    for required in (101, 105, 107, 108, 111, 112, 114):
        if required not in {row['position'] for row in positions}:
            raise ValueError(f'Missing installed equipment slot {required}')
    return positions


def _candidate_equipped_container_capacity(template_id):
    return container_capacity(template_id)


def _candidate_local_account_state_response(message, backend, local_session,
                                            expected_identity, key, *, header_word4, header_word9):
    """Return this local account's persisted level and currency balances."""
    if len(message) < 5:
        raise ValueError('Truncated account-state package')
    codec = _candidate_codec()
    request = codec.decode(message[4:])
    state = backend.native_lobby_profile(local_session)
    level = state['level']
    if request.name == 'CSAccountGetPlayerProfileReq':
        fields = {'result': 0, 'level': level, 'account_level': level,
                  'blast_level': level, 'exp': 0, 'account_exp': 0,
                  'nick_name': expected_identity.get('game_nick') or expected_identity['username']}
    elif request.name == 'CSPlayerGetBasicInfoReq':
        fields = {'result': 0, 'info': {
            'player_id': expected_identity['native_id'],
            'nick_name': expected_identity.get('game_nick') or expected_identity['username'],
            'sol_level': level, 'mp_level': level}}
    elif request.name == 'CSGetCurrencyReq':
        fields = {'result': 0, 'currencys': [
            {'id': row['currency_id'], 'num': row['amount']}
            for row in state['currencies']]}
    else:
        raise ValueError('Not a supported account-state request')
    response = codec.response(request, fields)
    return encode_data_frame((response,), key, direction='server_to_client',
                             opaque_flag=64, header_word4=header_word4,
                             header_word9=header_word9)


def _candidate_local_collection_response(message, backend, local_session, key, *,
                                         header_word4, header_word9):
    """Load the account's collection props, including non-warehouse bricks."""
    if len(message) < 5:
        raise ValueError('Truncated collection package')
    codec = _candidate_codec()
    request = codec.decode(message[4:])
    if request.name != 'CSCollectionLoadPropsReq':
        raise ValueError('Not a collection load request')
    state = backend.native_lobby_profile(local_session)
    response = codec.response(request, {
        'result': 0,
        'common_props': [
            {'id': row['template_id'], 'gid': 0, 'num': row['quantity']}
            for row in state['collection_props']],
    })
    return encode_data_frame((response,), key, direction='server_to_client',
                             opaque_flag=64, header_word4=header_word4,
                             header_word9=header_word9)


def _candidate_local_deposit_response(message, backend, local_session, key, *, header_word4, header_word9):
    """Provide the local account's warehouse grid and its persisted props."""
    if len(message) < 5:
        raise ValueError('Truncated deposit package')
    codec = _candidate_codec()
    request = codec.decode(message[4:])
    if request.name != 'CSDepositGetPropsReq':
        raise ValueError('Not the main warehouse fetch')
    # GameItem row 18100000001 is a melee receiver; InventoryServer_Network
    # function 0.12 rejects preset IDs in melee_weapons.
    backend.ensure_native_lobby_default_melee(local_session, 18100000001)
    state = backend.native_lobby_profile(local_session)
    grid = _candidate_main_deposit_grid()
    grid['props'] = []
    equipment = {row['position']: {**row,
                                  'grid_space': [dict(space) for space in row['grid_space']],
                                  'load_props': []}
                 for row in _candidate_body_equipment_positions()}
    equipment[POCKET_POSITION] = {
        'position': POCKET_POSITION, 'capacity': len(POCKET_LAYOUT),
        'src_prop_id': 0,
        'grid_space': [{'id': space_id, 'length': width, 'width': height}
                       for space_id, (width, height) in enumerate(POCKET_LAYOUT, 1)],
        'load_props': [],
    }
    rig = next((prop for prop in state['props'] if prop['grid_page_id'] == 107), None)
    rig_layout = CHEST_RIG_LAYOUT.get(rig['template_id'] if rig else None)
    if rig:
        rig_spaces = [{'id': space_id, 'length': width, 'width': height}
                      for space_id, (width, height) in enumerate(rig_layout or (), 1)]
        equipment[CHEST_RIG_POSITION] = {
            'position': CHEST_RIG_POSITION,
            'capacity': container_capacity(rig['template_id']),
            'src_prop_id': rig['template_id'],
            'grid_space': rig_spaces,
            'load_props': [],
        }
    backpack = next((prop for prop in state['props'] if prop['grid_page_id'] == 108), None)
    backpack_layout = BACKPACK_LAYOUT.get(backpack['template_id'] if backpack else None)
    if backpack:
        backpack_spaces = [
            {'id': space_id, 'length': width, 'width': height}
            for space_id, (width, height) in enumerate(backpack_layout or (), 1)]
        equipment[BACKPACK_POSITION] = {
            'position': BACKPACK_POSITION,
            'capacity': container_capacity(backpack['template_id']),
            'src_prop_id': backpack['template_id'],
            'grid_space': backpack_spaces,
            'load_props': [],
        }
    occupied = set()
    pocket_slots = set()
    for prop in state['props']:
        position = prop['grid_page_id']
        if position == grid['grid_page_id']:
            if prop['x'] + prop['length'] > grid['grid_length'] or prop['y'] + prop['width'] > grid['grid_width']:
                raise ValueError('Warehouse prop exceeds the installed grid')
            cells = {(x, y) for x in range(prop['x'], prop['x'] + prop['length'])
                     for y in range(prop['y'], prop['y'] + prop['width'])}
            if occupied & cells:
                raise ValueError('Overlapping warehouse props in the local save')
            occupied.update(cells)
            destination = grid['props']
        elif position == CHEST_RIG_POSITION:
            if not rig or (rig_layout and prop['x'] not in {space['id'] for space in rig_spaces}):
                raise ValueError('Unsupported chest-rig placement')
            destination = equipment[position]['load_props']
        elif position == BACKPACK_POSITION:
            if not backpack or (backpack_layout and prop['x'] not in {space['id'] for space in backpack_spaces}):
                raise ValueError('Unsupported backpack placement')
            destination = equipment[position]['load_props']
        elif position == POCKET_POSITION:
            if not 1 <= prop['x'] <= len(POCKET_LAYOUT) or prop['x'] in pocket_slots:
                raise ValueError('Invalid pocket slot')
            if (prop['y'], prop['length'], prop['width']) != (0, 1, 1):
                raise ValueError('Invalid pocket item placement')
            pocket_slots.add(prop['x'])
            destination = equipment[position]['load_props']
        elif position in equipment:
            destination = equipment[position]['load_props']
            if destination:
                raise ValueError('Multiple items occupy one equipment slot')
            # InventoryServer uses the equipped item ID to resolve this slot's
            # own space configuration, including weapon and container slots.
            equipment[position]['src_prop_id'] = prop['template_id']
            if position in (107, 108):
                equipment[position]['capacity'] = _candidate_equipped_container_capacity(
                    prop['template_id'])
        else:
            raise ValueError('Unsupported inventory position')
        destination.append({
            'id': prop['template_id'], 'gid': prop['gid'], 'num': prop['quantity'],
            'position': position, 'length': prop['length'], 'width': prop['width'],
            **item_condition_fields(prop['template_id'], components=prop.get('components'), weapon=prop.get('weapon')),
            'loc': inventory_location(prop),
        })
    if state['melee_props'] and not equipment[113]['load_props']:
        melee = state['melee_props'][0]
        metadata = installed_items()[str(melee['template_id'])]
        equipment[113]['src_prop_id'] = melee['template_id']
        equipment[113]['load_props'] = [{
            'id': melee['template_id'], 'gid': melee['gid'], 'num': 1, 'position': 113,
            'length': metadata['length'], 'width': metadata['width'],
            'loc': {'pos': 113, 'start_x': 0, 'start_y': 0, 'x': 1, 'y': 1,
                    'space_id': 0, 'rotate': False},
        }]
    response = codec.response(request, {
        'result': 0,
        'grid_pages': [grid],
        'equiped_props': list(equipment.values()),
        'melee_weapons': [{'id': row['template_id'], 'gid': row['gid'], 'num': 1,
                           'position': 113} for row in state['melee_props']],
        'currency': [{'id': row['currency_id'], 'num': row['amount']}
                     for row in state['currencies']],
        'sort_config': state['sort_config'],
        'cur_extension_num': 0,
        'max_extension_num': 0,
        'upperlimit_extension_num': 0,
    })
    return encode_data_frame((response,), key, direction='server_to_client',
                             opaque_flag=64, header_word4=header_word4,
                             header_word9=header_word9)


def _candidate_local_equip_summary(message):
    """Retain only item IDs and slots needed to diagnose an equipment move."""
    request = _candidate_codec().decode(message[4:])
    if request.name != 'CSDepositEquipPropReq':
        raise ValueError('Not an equipment move request')
    return [{'prop_id': int(cmd.get('prop_id') or 0),
             'prop_gid': int(cmd.get('prop_gid') or 0),
             'src_pos': int(cmd.get('src_pos') or 0),
             'target_pos': int(cmd.get('target_pos') or 0),
             'target_prop_gid': int(cmd.get('target_prop_gid') or 0),
             'num': int(cmd.get('num') or 0),
             'spec_loc': cmd.get('spec_loc') or {}}
            for cmd in request.fields.get('cmds', [])]


def _candidate_local_body_container_summary(message):
    request = _candidate_codec().decode(message[4:])
    if request.name != 'CSDepositAssemblySyncBodyContainerReq':
        raise ValueError('Not a body-container sync request')
    return [{'pos': int(snapshot.get('pos') or 0),
             'space': int(snapshot.get('space') or 0),
             'props': [{'id': int(prop.get('id') or 0),
                        'gid': int(prop.get('gid') or 0),
                        'num': int(prop.get('num') or 0),
                        'position': int(prop.get('position') or 0),
                        'loc': {name: prop.get('loc', {}).get(name)
                                for name in ('pos', 'space_id', 'start_x', 'start_y',
                                             'x', 'y', 'rotate')
                                if name in prop.get('loc', {})}}
                       for prop in snapshot.get('props', [])[:100]]}
            for snapshot in request.fields.get('snapshots', [])[:32]]


def _candidate_local_equip_response(message, backend, local_session, key, *,
                                    header_word4, header_word9):
    """Confirm an equipment move and return its authoritative item changes."""
    if len(message) < 5:
        raise ValueError('Truncated equipment move package')
    codec = _candidate_codec()
    request = codec.decode(message[4:])
    if request.name != 'CSDepositEquipPropReq':
        raise ValueError('Not an equipment move request')
    commands = []
    for command in request.fields.get('cmds', []):
        normalized = dict(command)
        for name in ('prop_id', 'prop_gid', 'target_pos', 'src_pos',
                     'target_prop_id', 'target_prop_gid', 'num'):
            if name in normalized:
                normalized[name] = int(normalized[name])
        commands.append(normalized)
    try:
        moves = backend.native_lobby_move_props(local_session, commands)
    except DomainError as error:
        fields = {'result': inventory_error(error), 'cmds': request.fields.get('cmds', [])}
    else:
        changes = []
        for move in moves:
            before, after = move['before'], move['after']

            changes.append({'change_type': 5,
                            'prop': {'id': after['template_id'], 'gid': after['gid'],
                                     'num': after['quantity'],
                                     'position': after['grid_page_id'],
                                     'length': after['length'], 'width': after['width'],
                                     **item_condition_fields(after['template_id'], components=after.get('components'), weapon=after.get('weapon')),
                                     'loc': inventory_location(after)},
                            'src': inventory_location(before),
                            'dest': inventory_location(after),
                            'delta': after['quantity']})
        fields = {'result': 0, 'deposit_change': {'prop_changes': changes},
                  'cmds': request.fields.get('cmds', [])}
    response = codec.response(request, fields)
    return encode_data_frame((response,), key, direction='server_to_client',
                             opaque_flag=64, header_word4=header_word4,
                             header_word9=header_word9)


def _native_inventory_changes(moves):
    changes = []
    for move in moves:
        before, after = move['before'], move['after']
        row = after or before
        destination = inventory_location(after) if after else {'pos': 0}
        source = inventory_location(before) if before else {'pos': 0}
        # common_pb.lua 0, instructions 618-642: Modify=3, ModifyWithMove=4, Move=5.
        change_type = (2 if after is None else 1 if before is None
                       else 3 if source == destination
                       else 4 if before['quantity'] != after['quantity'] else 5)
        changes.append({'change_type': change_type, 'src': source, 'dest': destination,
            'delta': (after['quantity'] if after else 0) - (before['quantity'] if before else 0),
            'prop': {'id': row['template_id'], 'gid': row['gid'], 'num': row['quantity'],
                'position': row['grid_page_id'], 'length': row['length'], 'width': row['width'],
                **item_condition_fields(row['template_id'], components=row.get('components'), weapon=row.get('weapon')),
                'loc': inventory_location(row)}})
    return {'prop_changes': changes}


def _candidate_local_bullet_summary(message):
    fields = _candidate_codec().decode(message[4:]).fields
    return [{name: int(command.get(name) or 0) for name in
             ('op_type', 'bullet_id', 'bullet_gid', 'bullet_op_num',
              'target_gun_rec_id', 'target_gun_rec_gid')}
            for command in fields.get('cmds', [])[:32]]


def _candidate_local_bullet_response(message, backend, local_session, key, *, header_word4, header_word9):
    codec = _candidate_codec()
    request = codec.decode(message[4:])
    if request.name != 'CSDepositOperateBulletReq':
        raise ValueError('Not a bullet operation request')
    commands = [{name: int(command.get(name) or 0) for name in
                 ('op_type', 'bullet_id', 'bullet_gid', 'bullet_op_num',
                  'target_gun_rec_id', 'target_gun_rec_gid')}
                for command in request.fields.get('cmds', [])]
    try:
        moves = backend.native_lobby_operate_bullets(local_session, commands)
    except DomainError as error:
        fields = {'result': inventory_error(error)}
    else:
        fields = {'result': 0, 'changes': _native_inventory_changes(moves)}
    response = codec.response(request, fields)
    return encode_data_frame((response,), key, direction='server_to_client',
                             opaque_flag=64, header_word4=header_word4, header_word9=header_word9)


def _candidate_local_body_container_response(message, backend, local_session, key, *, header_word4, header_word9):
    """Commit the client's container snapshot and return authoritative changes."""
    if len(message) < 5:
        raise ValueError('Truncated body-container sync package')
    codec = _candidate_codec()
    request = codec.decode(message[4:])
    if request.name != 'CSDepositAssemblySyncBodyContainerReq':
        raise ValueError('Not a body-container sync request')
    try:
        moves = backend.native_lobby_sync_body_containers(
            local_session, request.fields.get('snapshots', []))
    except DomainError as error:
        fields = {'result': inventory_error(error)}
    else:
        fields = {'result': 0, 'deposit_change': _native_inventory_changes(moves)}
    response = codec.response(request, fields)
    return encode_data_frame((response,), key, direction='server_to_client',
                             opaque_flag=64, header_word4=header_word4,
                             header_word9=header_word9)


def _candidate_local_guide_progress_response(message, key, *, header_word4, header_word9):
    """Acknowledge bounded guide progress so the client can release its guide input layer."""
    if len(message) < 5:
        raise ValueError('Truncated guide progress package')
    codec = _candidate_codec()
    request = codec.decode(message[4:])
    if request.name != 'CSGuideSetDataReq':
        raise ValueError('Not a guide progress request')
    if len(request.fields.get('data', [])) > 256:
        raise ValueError('Too many guide progress entries')
    response = codec.response(request, {'result': 0})
    return encode_data_frame((response,), key, direction='server_to_client',
                             opaque_flag=64, header_word4=header_word4,
                             header_word9=header_word9)


def _candidate_local_guide_stage_response(message, key, *, header_word4, header_word9):
    """Complete the client's guide skip and stage requests for the local account."""
    if len(message) < 5:
        raise ValueError('Truncated guide stage package')
    codec = _candidate_codec()
    request = codec.decode(message[4:])
    if request.name == 'CSGuidePassedReq':
        fields = {'result': 0, 'guide_stage_id': list(LOCAL_FINISHED_GUIDE_STAGES)}
    elif request.name == 'CSGuideSkipReq':
        fields = {'result': 0}
    else:
        raise ValueError('Not a guide stage request')
    response = codec.response(request, fields)
    return encode_data_frame((response,), key, direction='server_to_client',
                             opaque_flag=64, header_word4=header_word4,
                             header_word9=header_word9)


def _candidate_local_deposit_sort_response(message, backend, local_session, key,
                                           *, header_word4, header_word9):
    """Acknowledge sorting an already packed local grid and retain UI options."""
    if len(message) < 5:
        raise ValueError('Truncated warehouse sorting package')
    codec = _candidate_codec()
    request = codec.decode(message[4:])
    if request.name == 'CSDepositSortPositionReq':
        position = int(request.fields.get('pos_id', 0))
        if position != 2:
            raise ValueError('Unsupported warehouse sorting position')
        fields = {'result': 0, 'pos_id': position, 'changes': {}}
    elif request.name == 'CSDepositSortMultiplePosReq':
        positions = [int(value) for value in request.fields.get('pos_id', [])]
        if any(value != 2 for value in positions):
            raise ValueError('Unsupported warehouse sorting position')
        fields = {'result': 0, 'changes': {}}
    elif request.name == 'CSDepositSetSortConfigReq':
        config = backend.set_native_lobby_sort_config(
            local_session, request.fields.get('sort_config', {}))
        fields = {'result': 0, 'cur_sort_config': config}
    else:
        raise ValueError('Not a warehouse sorting request')
    response = codec.response(request, fields)
    return encode_data_frame((response,), key, direction='server_to_client',
                             opaque_flag=64, header_word4=header_word4,
                             header_word9=header_word9)


def _candidate_local_safehouse_response(message, backend, local_session, key,
                                        *, header_word4, header_word9):
    """Expose the authenticated account's persisted safehouse device levels."""
    if len(message) < 5:
        raise ValueError('Truncated safehouse package')
    codec = _candidate_codec()
    request = codec.decode(message[4:])
    devices = [{'device_id': row['device_id'], 'level': row['level']}
               for row in backend.native_lobby_profile(local_session)['devices']]
    if request.name == 'CSSafehouseGetInfoReq':
        fields = {'result': 0, 'devices': devices,
                  'upgraded_device_list': [device['device_id'] for device in devices],
                  'is_safehouse_unlocked': bool(devices)}
    elif request.name == 'CSSafehouseGetPlayerDeviceReq':
        fields = {'result': 0, 'device_infos': devices}
    else:
        raise ValueError('Not a safehouse device request')
    response = codec.response(request, fields)
    return encode_data_frame((response,), key, direction='server_to_client',
                             opaque_flag=64, header_word4=header_word4,
                             header_word9=header_word9)


def _candidate_local_safehouse_unlock_response(message, key, *, header_word4, header_word9):
    """Complete the client's safehouse feature check for an offline account."""
    if len(message) < 5:
        raise ValueError('Truncated safehouse unlock package')
    codec = _candidate_codec()
    request = codec.decode(message[4:])
    if request.name != 'CSSafehouseFuncIsUnlockReq':
        raise ValueError('Not a safehouse feature check')
    unlock_id = int(request.fields.get('unlock_id', 0))
    if unlock_id <= 0:
        raise ValueError('Invalid safehouse unlock ID')
    response = codec.response(request, {
        'result': 0,
        'params': [{'unlock_id': unlock_id, 'params': []}],
    })
    return encode_data_frame((response,), key, direction='server_to_client',
                             opaque_flag=64, header_word4=header_word4,
                             header_word9=header_word9)


def _candidate_local_safehouse_config_response(message, key, *, header_word4, header_word9):
    """Confirm the client's installed upgrade/formula tables are current."""
    if len(message) < 5:
        raise ValueError('Truncated safehouse config package')
    codec = _candidate_codec()
    request = codec.decode(message[4:])
    if request.name != 'CSSafehouseGetConfigReq':
        raise ValueError('Not a safehouse config request')
    formula_sign = request.fields.get('formula_sign')
    upgrade_sign = request.fields.get('upgrade_sign')
    if not (isinstance(formula_sign, str) and formula_sign
            and isinstance(upgrade_sign, str) and upgrade_sign):
        raise ValueError('Missing installed safehouse table signatures')
    response = codec.response(request, {
        'result': 0,
        'formula_cfg': [], 'upgrade_cfg': [],
        'new_formula_sign': formula_sign,
        'new_upgrade_sign': upgrade_sign,
    })
    return encode_data_frame((response,), key, direction='server_to_client',
                             opaque_flag=64, header_word4=header_word4,
                             header_word9=header_word9)


def _continue_character_creation(connection, decoder, queue, current, ack,
                                 expected_identity, backend, local_session,
                                 outbound_sequence, result, continuation_seconds=360):
    """Handle the original client's lobby and name-creation requests."""
    result['registration_continuation'] = []
    began = time.monotonic()
    deadline = time.monotonic() + continuation_seconds
    for _ in range(8192):
        if time.monotonic() >= deadline:
            result['registration_stop'] = 'deadline'
            return
        if current.command == 0x9001:
            outbound_sequence += 1
            connection.sendall(_transport_ping_reply(
                current, header_word9=outbound_sequence).encode())
            result['registration_continuation'].append(
                {'transport_command': '0x9001', 'reply_sent': True,
                 'elapsed_ms': round((time.monotonic() - began) * 1000)})
        elif current.command == 0x4013:
            data = decode_data_frame(current, ack.session_key,
                                     direction='client_to_server', compression_method=1)
            if len(data.messages) != 1:
                result['registration_stop'] = 'merged_messages'
                result['registration_merged_message_count'] = len(data.messages)
                return
            message = data.messages[0]
            shape = summarize_prefixed_envelope(message)
            name = shape.get('message_name')
            entry = {'request_name': name, 'service': shape.get('service'),
                     'prefix_sequence': shape.get('prefix_word_be'),
                     'elapsed_ms': round((time.monotonic() - began) * 1000)}
            result['registration_continuation'].append(entry)
            _log_request_progress(entry, 'received')
            try:
                outbound_sequence += 1
                if name == 'CSAccountLoginReq':
                    response = _candidate_local_login_response(
                        message, expected_identity, ack.session_key,
                        header_word4=current.header_word4, header_word9=outbound_sequence)
                elif name == 'CSStateGetInfoReq':
                    response = _candidate_local_state_response(
                        message, expected_identity, ack.session_key,
                        header_word4=current.header_word4, header_word9=outbound_sequence)
                elif name == 'CSOnlineHeartbeatReq':
                    response = _candidate_local_heartbeat_response(
                        message, ack.session_key,
                        header_word4=current.header_word4, header_word9=outbound_sequence)
                elif name in ('CSAccountRandNickReq', 'CSAccountValidateNickReq',
                              'CSAccountRegisterReq'):
                    response = _candidate_local_nick_response(
                        message, backend, local_session, ack.session_key,
                        header_word4=current.header_word4, header_word9=outbound_sequence)
                    entry['local_name_operation'] = True
                    if name == 'CSAccountRegisterReq':
                        game_profile = backend.native_identity(local_session)
                        expected_identity['game_nick'] = game_profile['game_nick']
                        expected_identity['game_registered'] = game_profile['game_registered']
                        result['character_registration_observed'] = game_profile['game_registered']
                elif name == 'CSAccountGetUnicodeConfReq':
                    response = _candidate_local_unicode_conf_response(
                        message, ack.session_key,
                        header_word4=current.header_word4, header_word9=outbound_sequence)
                elif name == 'CSClientEnterHallModeReq':
                    response = _candidate_local_hall_mode_response(
                        message, ack.session_key,
                        header_word4=current.header_word4, header_word9=outbound_sequence)
                elif name in ('CSHeroGetHeroIDListReq', 'CSHeroLoadHeroListReq'):
                    response = _candidate_local_hero_response(
                        message, backend, local_session, ack.session_key,
                        header_word4=current.header_word4, header_word9=outbound_sequence)
                    entry['base_avatar_catalogue_probe'] = True
                elif name == 'CSHeroSelectHeroReq':
                    response = _candidate_local_hero_select_response(
                        message, backend, local_session, ack.session_key,
                        header_word4=current.header_word4, header_word9=outbound_sequence)
                    entry['local_hero_selection_response'] = True
                elif name == 'CSHeroGetUnlockInfoReq':
                    response = _candidate_local_hero_unlock_response(
                        message, ack.session_key,
                        header_word4=current.header_word4, header_word9=outbound_sequence)
                    entry['local_hero_unlock_response'] = True
                elif name in ('CSAccountGetPlayerProfileReq', 'CSPlayerGetBasicInfoReq',
                              'CSGetCurrencyReq'):
                    response = _candidate_local_account_state_response(
                        message, backend, local_session, expected_identity, ack.session_key,
                        header_word4=current.header_word4, header_word9=outbound_sequence)
                    entry['local_account_state_response'] = True
                elif name == 'CSDepositGetPropsReq':
                    response = _candidate_local_deposit_response(
                        message, backend, local_session, ack.session_key,
                        header_word4=current.header_word4, header_word9=outbound_sequence)
                    entry['main_warehouse_grid_probe'] = True
                elif name == 'CSDepositEquipPropReq':
                    entry['local_equip_commands'] = _candidate_local_equip_summary(message)
                    response = _candidate_local_equip_response(
                        message, backend, local_session, ack.session_key,
                        header_word4=current.header_word4, header_word9=outbound_sequence)
                    entry['local_equip_response'] = True
                elif name == 'CSDepositAssemblySyncBodyContainerReq':
                    entry['local_body_container_snapshots'] = _candidate_local_body_container_summary(message)
                    response = _candidate_local_body_container_response(
                        message, backend, local_session, ack.session_key,
                        header_word4=current.header_word4, header_word9=outbound_sequence)
                    entry['local_body_container_response'] = True
                    entry['local_commerce_result'] = _candidate_local_commerce_result(response, ack.session_key)
                elif name == 'CSDepositOperateBulletReq':
                    entry['local_bullet_commands'] = _candidate_local_bullet_summary(message)
                    response = _candidate_local_bullet_response(
                        message, backend, local_session, ack.session_key,
                        header_word4=current.header_word4, header_word9=outbound_sequence)
                    entry['local_bullet_response'] = True
                    entry['local_commerce_result'] = _candidate_local_commerce_result(response, ack.session_key)
                elif name == 'CSGuideSetDataReq':
                    response = _candidate_local_guide_progress_response(
                        message, ack.session_key,
                        header_word4=current.header_word4, header_word9=outbound_sequence)
                    entry['local_guide_progress_response'] = True
                elif name in ('CSGuideSkipReq', 'CSGuidePassedReq'):
                    response = _candidate_local_guide_stage_response(
                        message, ack.session_key,
                        header_word4=current.header_word4, header_word9=outbound_sequence)
                    entry['local_guide_stage_response'] = True
                elif name == 'CSCollectionLoadPropsReq':
                    response = _candidate_local_collection_response(
                        message, backend, local_session, ack.session_key,
                        header_word4=current.header_word4, header_word9=outbound_sequence)
                    entry['local_collection_response'] = True
                elif name in ('CSDepositSortPositionReq', 'CSDepositSortMultiplePosReq',
                              'CSDepositSetSortConfigReq'):
                    response = _candidate_local_deposit_sort_response(
                        message, backend, local_session, ack.session_key,
                        header_word4=current.header_word4, header_word9=outbound_sequence)
                    entry['local_warehouse_sort_response'] = True
                elif name in ('CSSafehouseGetInfoReq', 'CSSafehouseGetPlayerDeviceReq'):
                    response = _candidate_local_safehouse_response(
                        message, backend, local_session, ack.session_key,
                        header_word4=current.header_word4, header_word9=outbound_sequence)
                    entry['local_safehouse_device_response'] = True
                elif name == 'CSSafehouseGetConfigReq':
                    response = _candidate_local_safehouse_config_response(
                        message, ack.session_key,
                        header_word4=current.header_word4, header_word9=outbound_sequence)
                    entry['local_safehouse_config_response'] = True
                elif name == 'CSSafehouseFuncIsUnlockReq':
                    response = _candidate_local_safehouse_unlock_response(
                        message, ack.session_key,
                        header_word4=current.header_word4, header_word9=outbound_sequence)
                    entry['local_safehouse_unlock_response'] = True
                elif name == 'CSSwitchLoadModuleStatusReq':
                    response = _candidate_local_module_status_response(
                        message, ack.session_key,
                        header_word4=current.header_word4, header_word9=outbound_sequence)
                    entry['local_module_status_response'] = True
                elif name in ('CSActivityGetReq', 'CSAuctionWithdrawReq',
                              'CSMarketWithdrawReq'):
                    response = _candidate_local_lobby_critical_response(
                        message, ack.session_key,
                        header_word4=current.header_word4, header_word9=outbound_sequence)
                    entry['local_lobby_critical_response'] = True
                elif name in ('CSPrepareMapBoardReq', 'CSPrepareTDMMapBoardReq',
                              'CSPrepareBombMapBoardReq'):
                    response = _candidate_local_prepare_map_response(
                        message, backend, local_session, ack.session_key,
                        header_word4=current.header_word4, header_word9=outbound_sequence)
                    entry['local_prepare_board_response'] = True
                elif name in LOCAL_COMMERCE_REQUESTS:
                    if name in ('CSAuctionGetSaleListBatchReq', 'CSAuctionGetSaleListReq',
                                'CSMarketGetSaleListReq', 'CSAuctionBuyTReq',
                                'CSMarketBuyTReq', 'CSMallBuyReq'):
                        entry['local_commerce_item_ids'] = _candidate_local_commerce_item_ids(message)
                    if name == 'CSShopBuyLotteryItemReq':
                        entry['local_lottery_purchase_items'] = _candidate_local_lottery_purchase_summary(message)
                    if name == 'CSSerialCheapBuyReq':
                        entry['local_serial_buy_items'] = _candidate_local_serial_buy_summary(message)
                    if name == 'CSMallSellReq':
                        entry['local_sell_items'] = _candidate_local_sell_summary(message)
                    response = _candidate_local_commerce_response(
                        message, backend, local_session, ack.session_key,
                        header_word4=current.header_word4, header_word9=outbound_sequence)
                    entry['local_commerce_response'] = True
                    entry['local_commerce_result'] = _candidate_local_commerce_result(
                        response, ack.session_key)
                elif name and name.endswith('Ntf'):
                    entry['notification_observed'] = True
                    response = None
                else:
                    response = _candidate_read_only_empty_response(
                        message, ack.session_key,
                        header_word4=current.header_word4, header_word9=outbound_sequence)
                    entry['empty_read_only_response_probe'] = True
            except (ValueError, DomainError) as error:
                entry['request_not_answered'] = True
                entry['failure_code'] = (error.code if isinstance(error, DomainError)
                                         else type(error).__name__)
                response = None
            if response is not None:
                connection.sendall(response.encode())
                entry['response_sent'] = True
                entry['response_elapsed_ms'] = round((time.monotonic() - began) * 1000)
                if name in ('CSDepositOperateBulletReq', 'CSDepositAssemblySyncBodyContainerReq',
                            'CSShopBuyLotteryItemReq', 'CSMarketBuyTReq', 'CSAuctionBuyTReq',
                            'CSMallBuyReq', 'CSSerialCheapBuyReq', 'CSMallSellReq'):
                    outbound_sequence += 1
                    notification = _candidate_local_inventory_change_notification(
                        response, ack.session_key, header_word4=current.header_word4,
                        header_word9=outbound_sequence)
                    if notification is not None:
                        connection.sendall(notification.encode())
                        entry['local_inventory_change_notification_sent'] = True
            _log_request_progress(entry, 'processed')
        else:
            result['registration_stop'] = f'non_data_0x{current.command:04x}'
            return
        try:
            current = _receive_one(connection, decoder, queue)
        except (TimeoutError, socket.timeout):
            result['registration_stop'] = 'receive_timeout'
            return
        if current is None:
            result['registration_stop'] = 'client_closed'
            return
    result['registration_stop'] = 'response_limit'


def _candidate_read_only_empty_response(message, key, *, header_word4, header_word9):
    """Probe bounded read-only requests with a declared empty response schema.

    This is a bounded lobby-bootstrap diagnostic; it does not provide actual
    inventory, task or commerce state and must not handle mutating requests.
    """
    if len(message) < 5:
        raise ValueError('Truncated read-only package')
    codec = _candidate_codec()
    envelope = parse_business_envelope(message[4:])
    name = envelope.header.get('name')
    service = envelope.header.get('service')
    sequence = envelope.header.get('client_sequence_id')
    if (not isinstance(name, str) or not name.startswith('CS') or not name.endswith('Req')
            or not (any(verb in name[2:-3] for verb in ('Get', 'Query', 'List', 'Fetch', 'Status'))
                    or name in {'CSCollectionLoadPropsReq', 'CSSwitchLoadSystemUnlockInfoReq',
                                'CSMossaiChatFuncInfoReq', 'CSTssLoadReportConfigReq',
                                'CSBattlePassBpCountryPriceReq',
                                'CSAuctionAutoLoadGuidePriceReq',
                                'CSCollectionLoadMysticalSkinPropsReq',
                                'CSCollectionLoadMysticalPendantPropsReq',
                                'CSArmedforceLoadOutfitReq'})
            or type(sequence) is not int or not -(1 << 31) <= sequence < (1 << 31)):
        raise ValueError('Not a declared read-only request')
    response_name = name[:-3] + 'Res'
    if codec.services.get(response_name) != service:
        raise ValueError('No matching declared read-only response service')
    descriptor = codec.codec._class('pb.' + response_name).DESCRIPTOR
    fields = {'result': 0} if 'result' in descriptor.fields_by_name else {}
    if name == 'CSGuideGetPlayerGuideReq':
        # GuideServer.lua treats an absent stage list as an unfinished account
        # and leaves its weak-click input layer active during equipment pages.
        fields.update({'guide_stage_id': list(LOCAL_FINISHED_GUIDE_STAGES),
                       'skip_all': True, 'player_account_batch': 999})
    elif name == 'CSMallGetLabelNo1ConfigReq':
        # Zero makes ShopServer immediately retry this read every five seconds.
        fields.update({'cfg_list': [], 'next_get_time': int(time.time()) + 3600})
    elif name == 'CSMallGetCfgVersionReq':
        fields['version_info'] = {'ver': 'local-empty-v1', 'load_time': 1}
    elif name == 'CSMallGetMerchantsReq':
        fields.update({'merchants': [], 'version_info': {
            'ver': 'local-empty-v1', 'load_time': 1}})
    elif name == 'CSAuctionAutoLoadGuidePriceReq':
        # This request is a paged catalogue read. Explicitly finish the empty
        # local catalogue so the client does not wait for another page.
        fields.update({'finish': True, 'new_sync_digest': 'local-empty-v1',
                       'price_list': []})
    elif name in ('CSMallGetBuyGoodsReq', 'CSMallGetRecycleGoodsReq'):
        # Both mall reads are paged. An empty result without the completion
        # marker causes the client to request the same page continuously,
        # delaying character creation and eventually exhausting the bounded
        # connection's response budget.
        fields['is_finish'] = True
        fields['version_info'] = {'ver': 'local-empty-v1', 'load_time': 1}
    response = codec.encode(response_name, fields, sequence=sequence)
    return encode_data_frame((response,), key, direction='server_to_client',
                             opaque_flag=64, header_word4=header_word4,
                             header_word9=header_word9)


def _candidate_local_lobby_critical_response(message, key, *, header_word4, header_word9):
    """Finish the three empty bootstrap reads required by the client's loading flow."""
    if len(message) < 5:
        raise ValueError('Truncated lobby-critical package')
    codec = _candidate_codec()
    request = codec.decode(message[4:])
    if request.name == 'CSActivityGetReq':
        # The installed client declares CSActivityGetRes.result as int32 field 1,
        # but its remaining response fields have not been recovered completely.
        # An empty activity list needs only the explicit successful result.
        response = BusinessEnvelope(
            b'\x08\x00',
            {'client_sequence_id': request.sequence, 'name': 'CSActivityGetRes',
             'service': 'activity'},
        ).encode()
    elif request.name in ('CSAuctionWithdrawReq', 'CSMarketWithdrawReq'):
        # These empty requests are issued by the client's main-hall bootstrap
        # to read pending withdrawals; there are none on a fresh local account.
        response = codec.response(request, {'result': 0})
    elif request.name == 'CSArmedForceReportOutfitReq':
        response = codec.response(request, {'result': 0})
    else:
        raise ValueError('Not a supported lobby-critical request')
    return encode_data_frame((response,), key, direction='server_to_client',
                             opaque_flag=64, header_word4=header_word4,
                             header_word9=header_word9)


def inspect_exchange(connection, modulus=None, *, timeout=12, diagnostic_exponent_one=False,
                     expected_identity=None, response_probe=False, ready_probe=False,
                     ready_identity_probe=False, auth_identity_probe=False,
                     business_login_probe=False, business_bootstrap_probe=False,
                     backend=None, local_session=None, continuation_seconds=360):
    """Perform only the transport DH step; return credential-free metadata."""
    if ready_probe and not response_probe:
        raise ValueError('Ready parser probe requires the auth parser probe')
    if ready_identity_probe and not ready_probe:
        raise ValueError('Derived ready probe requires the ready parser probe')
    if auth_identity_probe and not response_probe:
        raise ValueError('Session-bound auth probe requires the auth parser probe')
    if response_probe and (not diagnostic_exponent_one or expected_identity is None):
        raise ValueError('Response parser probe requires a scoped local identity trial')
    if business_login_probe and not (response_probe and ready_probe and auth_identity_probe):
        raise ValueError('Business login probe requires locally bound auth and ready probes')
    if business_bootstrap_probe and not business_login_probe:
        raise ValueError('Bootstrap probe requires the business login probe')
    result = {'observed_at_utc': _time(), 'ack_sent': False,
              'auth_response_sent': False, 'business_response_sent': False}
    decoder, queue = StreamDecoder(), deque()
    if not 30 <= continuation_seconds <= 3600:
        raise ValueError('Invalid bounded continuation duration')
    connection.settimeout(max(timeout, continuation_seconds) if business_bootstrap_probe else timeout)
    try:
        first = _receive_one(connection, decoder, queue)
        if first is None:
            result['outcome'] = 'closed_before_hello'
            return result
        hello = parse_hello(first)
        result.update({'hello_version': first.version, 'hello_command': first.command,
                       'hello_header_word4': first.header_word4,
                       'hello_header_word9': first.header_word9,
                       'client_public_key_length': len(hello.client_public_key)})
        # Empty ACK context was accepted in two bounded original-client trials.
        if diagnostic_exponent_one:
            if modulus is not None:
                raise ValueError('Diagnostic exponent-one mode does not accept a modulus')
            ack = _diagnostic_ack(first, hello)
        else:
            ack = create_server_ack(first, modulus, body=DhAckBody(b''),
                                    header_word4=first.header_word4,
                                    header_word9=first.header_word9,
                                    compression_method=1,
                                    compression_threshold=500,
                                    compression_maximum=0)
        connection.sendall(ack.frame.encode())
        result.update({'ack_sent': True, 'ack_command': ack.frame.command,
                       'ack_sent_at_utc': _time(),
                       'ack_wire_bytes': ack.frame.wire_size,
                       'ack_context_bytes': 0,
                       'diagnostic_exponent_one': diagnostic_exponent_one,
                       'session_key_public': diagnostic_exponent_one,
                       'ack_context_accepted_by_original_client_verified': False})
        second = _receive_one(connection, decoder, queue)
        if second is None:
            result['outcome'] = 'closed_after_ack'
            return result
        result.update({'next_command': second.command,
                       'auth_request_received_at_utc': _time() if second.command == 0x2001 else None,
                       'next_header_word9': second.header_word9,
                       'next_wire_bytes': second.wire_size})
        if second.command == 0x2001:
            request = parse_auth_request(decode_received_body(
                second, ack.session_key, direction='client_to_server'),
                version=second.header_word4)
            result.update({'outcome': 'transport_auth_request_decoded',
                           'ack_context_accepted_by_original_client_verified': True,
                           'auth_type': request.auth_type,
                           'credential_bytes': len(request.opaque_credential),
                           'auth_data_bytes': len(request.opaque_auth_data),
                           'context_bytes': len(request.opaque_context)})
            if expected_identity is not None:
                result['local_identity_correlations'] = _identity_correlations(request, expected_identity)
            if response_probe:
                if not result['local_identity_correlations']['local_token_contained_in_auth_data']:
                    result['outcome'] = 'local_token_not_in_auth_data'
                    return result
                probe_body = (_session_bound_auth_body(request, expected_identity)
                              if auth_identity_probe else _parser_probe_control_body(0x2002))
                response = Frame(11, second.header_word4, 0x2002, 1,
                                 second.header_word9, b'', encrypt_body(probe_body, ack.session_key))
                connection.sendall(response.encode())
                result.update({'auth_response_sent': True,
                               'auth_response_sent_at_utc': _time(),
                               'auth_response_header_word9': response.header_word9,
                               'auth_response_is_empty_parser_probe': False,
                               'auth_response_probe_layout': ('0x3366_local_session_bound_account'
                                                               if auth_identity_probe else
                                                               '0x3366_fixed_schema_zero_values'),
                               'auth_response_wire_bytes': response.wire_size})
                if ready_probe:
                    if second.header_word9 == 0xffffffff:
                        raise ValueError('Control sequence exhausted')
                    # The captured official connection placed 0x6002 about
                    # 81 ms after 0x2002. Keep the frames in separate writes.
                    time.sleep(0.08)
                    ready_body = (_derived_ready_body(expected_identity) if ready_identity_probe
                                  else _parser_probe_control_body(0x6002))
                    ready = Frame(11, second.header_word4, 0x6002, 1,
                                  second.header_word9 + 1, b'', encrypt_body(ready_body, ack.session_key))
                    connection.sendall(ready.encode())
                    outbound_sequence = ready.header_word9
                    result.update({'ready_response_sent': True,
                                   'ready_response_sent_at_utc': _time(),
                                   'ready_response_header_word9': ready.header_word9,
                                   'ready_response_is_empty_parser_probe': False,
                                   'ready_response_probe_layout': ('0x3366_v12_local_session_derived_relay'
                                                                    if ready_identity_probe else
                                                                    '0x3366_v12_fixed_schema_zero_values'),
                                   'ready_response_delay_ms': 80,
                                   'ready_response_wire_bytes': ready.wire_size})
                third = _receive_one(connection, decoder, queue)
                if third is None:
                    result['outcome'] = 'closed_after_control_parser_probe'
                else:
                    result.update({'outcome': 'next_command_after_control_parser_probe',
                                   'post_response_received_at_utc': _time(),
                                   'post_response_command': third.command,
                                   'post_response_wire_bytes': third.wire_size,
                                   'post_response_header_word4': third.header_word4,
                                   'post_response_header_word9': third.header_word9})
                    if third.command == 0x4013:
                        try:
                            decoded = decode_data_frame(third, ack.session_key,
                                                        direction='client_to_server',
                                                        compression_method=1)
                            result.update({'post_response_data_decoded': True,
                                           'post_response_data_compression_flag': decoded.header.compression_flag,
                                           'post_response_data_opaque_flag': decoded.header.opaque_flag,
                                           'post_response_data_message_lengths': [len(item) for item in decoded.messages],
                                           'post_response_message_shapes': [summarize_message_shape(item)
                                                                            for item in decoded.messages],
                                           'post_response_prefixed_envelopes': [summarize_prefixed_envelope(item)
                                                                                for item in decoded.messages]})
                            if (business_bootstrap_probe and len(decoded.messages) == 1
                                    and result['post_response_prefixed_envelopes'][0].get('message_name')
                                    != 'CSAccountLoginReq'):
                                # The client opens additional authenticated GCP
                                # connections and may start with a pending lobby or
                                # character request. Requiring LoginReq here caused
                                # nickname requests to fail with -1 on reconnect.
                                result['business_login_probe_result'] = 'authenticated_followup_without_login'
                                _continue_character_creation(
                                    connection, decoder, queue, third, ack,
                                    expected_identity, backend, local_session,
                                    outbound_sequence, result, continuation_seconds)
                                return result
                            if business_login_probe and len(decoded.messages) == 1:
                                try:
                                    outbound_sequence += 1
                                    login_response = _candidate_local_login_response(
                                        decoded.messages[0], expected_identity, ack.session_key,
                                        header_word4=third.header_word4,
                                        header_word9=outbound_sequence)
                                except (ValueError, DomainError):
                                    result['business_login_probe_result'] = 'candidate_request_not_accepted'
                                else:
                                    connection.sendall(login_response.encode())
                                    result.update({'business_response_sent': True,
                                                   'business_response_name': 'CSAccountLoginRes',
                                                   'business_response_wire_bytes': login_response.wire_size,
                                                   'business_response_header_word9': login_response.header_word9,
                                                   'business_response_prefix_strategy': 'unprefixed_downlink_cspkg'})
                                    fourth = _receive_one(connection, decoder, queue)
                                    if fourth is None:
                                        result['business_login_probe_result'] = 'client_closed_after_response'
                                    else:
                                        result.update({'business_login_probe_result': 'next_frame_received',
                                                       'followup_command': fourth.command,
                                                       'followup_wire_bytes': fourth.wire_size})
                                        if fourth.command == 0x4013:
                                            followup = decode_data_frame(fourth, ack.session_key,
                                                                         direction='client_to_server',
                                                                         compression_method=1)
                                            result['followup_business_shapes'] = [
                                                summarize_prefixed_envelope(item) for item in followup.messages]
                                            if (business_bootstrap_probe
                                                    and expected_identity.get('game_registered') is False):
                                                _continue_character_creation(
                                                    connection, decoder, queue, fourth, ack,
                                                    expected_identity, backend, local_session,
                                                    outbound_sequence, result, continuation_seconds)
                                            elif business_bootstrap_probe and len(followup.messages) == 1:
                                                try:
                                                    outbound_sequence += 1
                                                    followup_name = result['followup_business_shapes'][0].get('message_name')
                                                    if followup_name == 'CSStateGetInfoReq':
                                                        state_response = _candidate_local_state_response(
                                                            followup.messages[0], expected_identity,
                                                            ack.session_key,
                                                            header_word4=fourth.header_word4,
                                                            header_word9=outbound_sequence)
                                                    else:
                                                        state_response = _candidate_read_only_empty_response(
                                                            followup.messages[0], ack.session_key,
                                                            header_word4=fourth.header_word4,
                                                            header_word9=outbound_sequence)
                                                except (ValueError, DomainError):
                                                    result['business_state_probe_result'] = 'candidate_request_not_accepted'
                                                else:
                                                    connection.sendall(state_response.encode())
                                                    result.update({'business_state_response_sent': followup_name == 'CSStateGetInfoReq',
                                                                   'business_bootstrap_response_name': followup_name,
                                                                   'business_state_response_wire_bytes': state_response.wire_size,
                                                                   'business_state_response_header_word9': state_response.header_word9})
                                                    fifth = _receive_one(connection, decoder, queue)
                                                    if fifth is None:
                                                        result['business_state_probe_result'] = 'client_closed_after_response'
                                                    else:
                                                        result.update({'business_state_probe_result': 'next_frame_received',
                                                                       'post_state_command': fifth.command,
                                                                       'post_state_wire_bytes': fifth.wire_size})
                                                        if fifth.command == 0x4013:
                                                            later = decode_data_frame(fifth, ack.session_key,
                                                                                      direction='client_to_server',
                                                                                      compression_method=1)
                                                            result['post_state_business_shapes'] = [
                                                                summarize_prefixed_envelope(item) for item in later.messages]
                                                            result['bounded_business_continuation'] = []
                                                            current = fifth
                                                            continuation_began = time.monotonic()
                                                            continuation_deadline = time.monotonic() + continuation_seconds
                                                            for _ in range(8192):
                                                                if time.monotonic() >= continuation_deadline:
                                                                    result['bounded_business_stop'] = 'continuation_deadline'
                                                                    break
                                                                if current.command == 0x9001:
                                                                    outbound_sequence += 1
                                                                    connection.sendall(_transport_ping_reply(
                                                                        current, header_word9=outbound_sequence).encode())
                                                                    result['bounded_business_continuation'].append(
                                                                        {'transport_command': '0x9001',
                                                                         'wire_bytes': current.wire_size,
                                                                         'reply_sent': True})
                                                                    try:
                                                                        current = _receive_one(connection, decoder, queue)
                                                                    except (TimeoutError, socket.timeout):
                                                                        result['bounded_business_stop'] = 'receive_timeout_after_transport_heartbeat'
                                                                        break
                                                                    if current is None:
                                                                        result['bounded_business_stop'] = 'client_closed_after_transport_heartbeat'
                                                                        break
                                                                    continue
                                                                if current.command != 0x4013:
                                                                    result['bounded_business_stop'] = 'non_data_command'
                                                                    result['bounded_business_non_data_command'] = f'0x{current.command:04x}'
                                                                    break
                                                                current_data = decode_data_frame(
                                                                    current, ack.session_key,
                                                                    direction='client_to_server', compression_method=1)
                                                                if len(current_data.messages) != 1:
                                                                    result['bounded_business_stop'] = 'merged_messages'
                                                                    break
                                                                message = current_data.messages[0]
                                                                shape = summarize_prefixed_envelope(message)
                                                                name = shape.get('message_name')
                                                                entry = {'request_name': name,
                                                                         'service': shape.get('service'),
                                                                         'prefix_sequence': shape.get('prefix_word_be'),
                                                                         'wire_bytes': current.wire_size,
                                                                         'elapsed_ms': round((time.monotonic() - continuation_began) * 1000)}
                                                                result['bounded_business_continuation'].append(entry)
                                                                _log_request_progress(entry, 'received')
                                                                if name and name.startswith('CS') and name.endswith('Ntf'):
                                                                    entry['notification_observed'] = True
                                                                    try:
                                                                        current = _receive_one(connection, decoder, queue)
                                                                    except (TimeoutError, socket.timeout):
                                                                        result['bounded_business_stop'] = 'receive_timeout_after_notification'
                                                                        break
                                                                    if current is None:
                                                                        result['bounded_business_stop'] = 'client_closed_after_notification'
                                                                        break
                                                                    continue
                                                                try:
                                                                    outbound_sequence += 1
                                                                    if name == 'CSAccountLoginReq':
                                                                        next_response = _candidate_local_login_response(
                                                                            message, expected_identity, ack.session_key,
                                                                            header_word4=current.header_word4,
                                                                            header_word9=outbound_sequence)
                                                                    elif name == 'CSStateGetInfoReq':
                                                                        next_response = _candidate_local_state_response(
                                                                            message, expected_identity, ack.session_key,
                                                                            header_word4=current.header_word4,
                                                                            header_word9=outbound_sequence)
                                                                    elif name == 'CSOnlineHeartbeatReq':
                                                                        next_response = _candidate_local_heartbeat_response(
                                                                            message, ack.session_key,
                                                                            header_word4=current.header_word4,
                                                                            header_word9=outbound_sequence)
                                                                    elif name in ('CSAccountValidateNickReq',
                                                                                  'CSAccountRegisterReq',
                                                                                  'CSAccountRandNickReq'):
                                                                        next_response = _candidate_local_nick_response(
                                                                            message, backend, local_session,
                                                                            ack.session_key,
                                                                            header_word4=current.header_word4,
                                                                            header_word9=outbound_sequence)
                                                                        entry['local_name_operation'] = True
                                                                        if name == 'CSAccountRegisterReq':
                                                                            game_profile = backend.native_identity(local_session)
                                                                            expected_identity['game_nick'] = game_profile['game_nick']
                                                                            expected_identity['game_registered'] = game_profile['game_registered']
                                                                    elif name == 'CSAccountGetUnicodeConfReq':
                                                                        next_response = _candidate_local_unicode_conf_response(
                                                                            message, ack.session_key,
                                                                            header_word4=current.header_word4,
                                                                            header_word9=outbound_sequence)
                                                                    elif name == 'CSClientEnterHallModeReq':
                                                                        next_response = _candidate_local_hall_mode_response(
                                                                            message, ack.session_key,
                                                                            header_word4=current.header_word4,
                                                                            header_word9=outbound_sequence)
                                                                    elif name in ('CSHeroGetHeroIDListReq',
                                                                                  'CSHeroLoadHeroListReq'):
                                                                        next_response = _candidate_local_hero_response(
                                                                            message, backend, local_session,
                                                                            ack.session_key,
                                                                            header_word4=current.header_word4,
                                                                            header_word9=outbound_sequence)
                                                                        entry['base_avatar_catalogue_probe'] = True
                                                                    elif name == 'CSHeroSelectHeroReq':
                                                                        next_response = _candidate_local_hero_select_response(
                                                                            message, backend, local_session,
                                                                            ack.session_key,
                                                                            header_word4=current.header_word4,
                                                                            header_word9=outbound_sequence)
                                                                        entry['local_hero_selection_response'] = True
                                                                    elif name == 'CSHeroGetUnlockInfoReq':
                                                                        next_response = _candidate_local_hero_unlock_response(
                                                                            message, ack.session_key,
                                                                            header_word4=current.header_word4,
                                                                            header_word9=outbound_sequence)
                                                                        entry['local_hero_unlock_response'] = True
                                                                    elif name in ('CSAccountGetPlayerProfileReq',
                                                                                  'CSPlayerGetBasicInfoReq',
                                                                                  'CSGetCurrencyReq'):
                                                                        next_response = _candidate_local_account_state_response(
                                                                            message, backend, local_session,
                                                                            expected_identity, ack.session_key,
                                                                            header_word4=current.header_word4,
                                                                            header_word9=outbound_sequence)
                                                                        entry['local_account_state_response'] = True
                                                                    elif name == 'CSDepositGetPropsReq':
                                                                        next_response = _candidate_local_deposit_response(
                                                                            message, backend, local_session, ack.session_key,
                                                                            header_word4=current.header_word4,
                                                                            header_word9=outbound_sequence)
                                                                        entry['main_warehouse_grid_probe'] = True
                                                                    elif name == 'CSDepositEquipPropReq':
                                                                        entry['local_equip_commands'] = _candidate_local_equip_summary(message)
                                                                        next_response = _candidate_local_equip_response(
                                                                            message, backend, local_session, ack.session_key,
                                                                            header_word4=current.header_word4,
                                                                            header_word9=outbound_sequence)
                                                                        entry['local_equip_response'] = True
                                                                    elif name == 'CSDepositAssemblySyncBodyContainerReq':
                                                                        entry['local_body_container_snapshots'] = _candidate_local_body_container_summary(message)
                                                                        next_response = _candidate_local_body_container_response(
                                                                            message, backend, local_session, ack.session_key,
                                                                            header_word4=current.header_word4,
                                                                            header_word9=outbound_sequence)
                                                                        entry['local_body_container_response'] = True
                                                                        entry['local_commerce_result'] = _candidate_local_commerce_result(
                                                                            next_response, ack.session_key)
                                                                    elif name == 'CSDepositOperateBulletReq':
                                                                        entry['local_bullet_commands'] = _candidate_local_bullet_summary(message)
                                                                        next_response = _candidate_local_bullet_response(
                                                                            message, backend, local_session, ack.session_key,
                                                                            header_word4=current.header_word4,
                                                                            header_word9=outbound_sequence)
                                                                        entry['local_bullet_response'] = True
                                                                        entry['local_commerce_result'] = _candidate_local_commerce_result(
                                                                            next_response, ack.session_key)
                                                                    elif name == 'CSGuideSetDataReq':
                                                                        next_response = _candidate_local_guide_progress_response(
                                                                            message, ack.session_key,
                                                                            header_word4=current.header_word4,
                                                                            header_word9=outbound_sequence)
                                                                        entry['local_guide_progress_response'] = True
                                                                    elif name in ('CSGuideSkipReq', 'CSGuidePassedReq'):
                                                                        next_response = _candidate_local_guide_stage_response(
                                                                            message, ack.session_key,
                                                                            header_word4=current.header_word4,
                                                                            header_word9=outbound_sequence)
                                                                        entry['local_guide_stage_response'] = True
                                                                    elif name == 'CSCollectionLoadPropsReq':
                                                                        next_response = _candidate_local_collection_response(
                                                                            message, backend, local_session, ack.session_key,
                                                                            header_word4=current.header_word4,
                                                                            header_word9=outbound_sequence)
                                                                        entry['local_collection_response'] = True
                                                                    elif name in ('CSDepositSortPositionReq',
                                                                                  'CSDepositSortMultiplePosReq',
                                                                                  'CSDepositSetSortConfigReq'):
                                                                        next_response = _candidate_local_deposit_sort_response(
                                                                            message, backend, local_session,
                                                                            ack.session_key,
                                                                            header_word4=current.header_word4,
                                                                            header_word9=outbound_sequence)
                                                                        entry['local_warehouse_sort_response'] = True
                                                                    elif name in ('CSSafehouseGetInfoReq',
                                                                                  'CSSafehouseGetPlayerDeviceReq'):
                                                                        next_response = _candidate_local_safehouse_response(
                                                                            message, backend, local_session,
                                                                            ack.session_key,
                                                                            header_word4=current.header_word4,
                                                                            header_word9=outbound_sequence)
                                                                        entry['local_safehouse_device_response'] = True
                                                                    elif name == 'CSSafehouseGetConfigReq':
                                                                        next_response = _candidate_local_safehouse_config_response(
                                                                            message, ack.session_key,
                                                                            header_word4=current.header_word4,
                                                                            header_word9=outbound_sequence)
                                                                        entry['local_safehouse_config_response'] = True
                                                                    elif name == 'CSSafehouseFuncIsUnlockReq':
                                                                        next_response = _candidate_local_safehouse_unlock_response(
                                                                            message, ack.session_key,
                                                                            header_word4=current.header_word4,
                                                                            header_word9=outbound_sequence)
                                                                        entry['local_safehouse_unlock_response'] = True
                                                                    elif name == 'CSSwitchLoadModuleStatusReq':
                                                                        next_response = _candidate_local_module_status_response(
                                                                            message, ack.session_key,
                                                                            header_word4=current.header_word4,
                                                                            header_word9=outbound_sequence)
                                                                        entry['local_module_status_response'] = True
                                                                    elif name in ('CSActivityGetReq',
                                                                                  'CSAuctionWithdrawReq',
                                                                                  'CSMarketWithdrawReq',
                                                                                  'CSArmedForceReportOutfitReq'):
                                                                        next_response = _candidate_local_lobby_critical_response(
                                                                            message, ack.session_key,
                                                                            header_word4=current.header_word4,
                                                                            header_word9=outbound_sequence)
                                                                        entry['local_lobby_critical_response'] = True
                                                                    elif name in ('CSPrepareMapBoardReq',
                                                                                  'CSPrepareTDMMapBoardReq',
                                                                                  'CSPrepareBombMapBoardReq'):
                                                                        next_response = _candidate_local_prepare_map_response(
                                                                            message, backend, local_session, ack.session_key,
                                                                            header_word4=current.header_word4,
                                                                            header_word9=outbound_sequence)
                                                                        entry['local_prepare_board_response'] = True
                                                                    elif name in LOCAL_COMMERCE_REQUESTS:
                                                                        if name in ('CSMarketGetTypeListReq',
                                                                                    'CSAuctionGetTypeListReq'):
                                                                            entry['local_commerce_type_filters'] = (
                                                                                _candidate_local_commerce_type_filters(message))
                                                                        if name in ('CSAuctionGetSaleListBatchReq', 'CSAuctionGetSaleListReq',
                                                                                    'CSMarketGetSaleListReq', 'CSAuctionBuyTReq',
                                                                                    'CSMarketBuyTReq', 'CSMallBuyReq'):
                                                                            entry['local_commerce_item_ids'] = _candidate_local_commerce_item_ids(message)
                                                                        if name == 'CSShopBuyLotteryItemReq':
                                                                            entry['local_lottery_purchase_items'] = _candidate_local_lottery_purchase_summary(message)
                                                                        if name == 'CSSerialCheapBuyReq':
                                                                            entry['local_serial_buy_items'] = _candidate_local_serial_buy_summary(message)
                                                                        if name == 'CSMallSellReq':
                                                                            entry['local_sell_items'] = _candidate_local_sell_summary(message)
                                                                        next_response = _candidate_local_commerce_response(
                                                                            message, backend, local_session,
                                                                            ack.session_key,
                                                                            header_word4=current.header_word4,
                                                                            header_word9=outbound_sequence)
                                                                        entry['local_commerce_response'] = True
                                                                        entry['local_commerce_result'] = _candidate_local_commerce_result(
                                                                            next_response, ack.session_key)
                                                                    elif (name and name.startswith('CS')
                                                                          and name.endswith('Req')):
                                                                        next_response = _candidate_read_only_empty_response(
                                                                            message, ack.session_key,
                                                                            header_word4=current.header_word4,
                                                                            header_word9=outbound_sequence)
                                                                        entry['empty_read_only_response_probe'] = True
                                                                    else:
                                                                        raise ValueError('Unimplemented request')
                                                                except (ValueError, DomainError) as error:
                                                                    entry['request_not_answered'] = True
                                                                    entry['failure_code'] = (
                                                                        error.code if isinstance(error, DomainError)
                                                                        else type(error).__name__)
                                                                    entry['failure_detail'] = str(error)[:160]
                                                                    _log_request_progress(entry, 'processed')
                                                                    try:
                                                                        current = _receive_one(connection, decoder, queue)
                                                                    except (TimeoutError, socket.timeout):
                                                                        result['bounded_business_stop'] = 'receive_timeout_after_unanswered_request'
                                                                        break
                                                                    if current is None:
                                                                        result['bounded_business_stop'] = 'client_closed_after_unanswered_request'
                                                                        break
                                                                    continue
                                                                connection.sendall(next_response.encode())
                                                                entry['response_sent'] = True
                                                                entry['response_elapsed_ms'] = round(
                                                                    (time.monotonic() - continuation_began) * 1000)
                                                                entry['response_header_word9'] = next_response.header_word9
                                                                if (name in ('CSShopBuyLotteryItemReq',
                                                                             'CSMarketBuyTReq',
                                                                             'CSAuctionBuyTReq',
                                                                             'CSMallBuyReq',
                                                                             'CSSerialCheapBuyReq',
                                                                             'CSMallSellReq',
                                                                             'CSDepositOperateBulletReq',
                                                                             'CSDepositAssemblySyncBodyContainerReq')
                                                                        and (entry.get('local_commerce_response')
                                                                             or entry.get('local_bullet_response')
                                                                             or entry.get('local_body_container_response'))):
                                                                    outbound_sequence += 1
                                                                    inventory_change = _candidate_local_inventory_change_notification(
                                                                        next_response, ack.session_key,
                                                                        header_word4=current.header_word4,
                                                                        header_word9=outbound_sequence)
                                                                    if inventory_change is not None:
                                                                        connection.sendall(inventory_change.encode())
                                                                        entry['local_inventory_change_notification_sent'] = True
                                                                    if name == 'CSShopBuyLotteryItemReq':
                                                                        outbound_sequence += 1
                                                                        collection_change = _candidate_local_collection_change_notification(
                                                                            next_response, ack.session_key,
                                                                            header_word4=current.header_word4,
                                                                            header_word9=outbound_sequence)
                                                                        if collection_change is not None:
                                                                            connection.sendall(collection_change.encode())
                                                                            entry['local_collection_change_notification_sent'] = True
                                                                _log_request_progress(entry, 'processed')
                                                                try:
                                                                    current = _receive_one(connection, decoder, queue)
                                                                except (TimeoutError, socket.timeout):
                                                                    result['bounded_business_stop'] = 'receive_timeout'
                                                                    break
                                                                if current is None:
                                                                    result['bounded_business_stop'] = 'client_closed'
                                                                    break
                                                            else:
                                                                result['bounded_business_stop'] = 'response_limit'
                        except (ValueError, ImportError):
                            result['post_response_data_decoded'] = False
        else:
            result['outcome'] = 'next_command_observed_without_auth_decode'
    except (TimeoutError, socket.timeout):
        result['outcome'] = ('receive_timeout_after_control_parser_probe'
                             if result['auth_response_sent'] else 'receive_timeout')
    except (ValueError, NotImplementedError):
        result['outcome'] = 'unsupported_or_invalid_protocol'
    except OSError as error:
        result['outcome'] = 'socket_error'
        result['socket_error_code'] = getattr(error, 'winerror', None) or error.errno
    return result


class Server(socketserver.ThreadingTCPServer):
    daemon_threads = True
    allow_reuse_address = False

    def __init__(self, address, state, modulus, diagnostic_exponent_one, expected_identity=None,
                 response_probe=False, ready_probe=False, ready_identity_probe=False,
                 auth_identity_probe=False, business_login_probe=False,
                 business_bootstrap_probe=False, backend=None, local_session=None,
                 continuation_seconds=360):
        if ready_probe and not response_probe:
            raise ValueError('Ready parser probe requires the auth parser probe')
        if ready_identity_probe and not ready_probe:
            raise ValueError('Derived ready probe requires the ready parser probe')
        if auth_identity_probe and not response_probe:
            raise ValueError('Session-bound auth probe requires the auth parser probe')
        if response_probe and (not diagnostic_exponent_one or expected_identity is None):
            raise ValueError('Response parser probe requires a scoped local identity trial')
        if business_login_probe and not (response_probe and ready_probe and auth_identity_probe):
            raise ValueError('Business login probe requires locally bound auth and ready probes')
        if business_bootstrap_probe and not business_login_probe:
            raise ValueError('Bootstrap probe requires the business login probe')
        self.state, self.modulus = state, modulus
        self.diagnostic_exponent_one = diagnostic_exponent_one
        self.expected_identity = expected_identity
        self.response_probe = response_probe
        self.ready_probe = ready_probe
        self.ready_identity_probe = ready_identity_probe
        self.auth_identity_probe = auth_identity_probe
        self.business_login_probe = business_login_probe
        self.business_bootstrap_probe = business_bootstrap_probe
        self.backend = backend
        self.local_session = local_session
        self.continuation_seconds = continuation_seconds
        self.slots = threading.BoundedSemaphore(4)
        super().__init__(address, Handler)

    def process_request(self, request, client_address):
        if not self.slots.acquire(blocking=False):
            self.shutdown_request(request)
            return
        try:
            super().process_request(request, client_address)
        except Exception:
            self.slots.release()
            raise

    def process_request_thread(self, request, client_address):
        try:
            super().process_request_thread(request, client_address)
        finally:
            self.slots.release()


class Handler(socketserver.BaseRequestHandler):
    def handle(self):
        print(json.dumps({'event': 'connection_started', 'observed_at_utc': _time()}), flush=True)
        result = inspect_exchange(self.request, self.server.modulus,
                                  diagnostic_exponent_one=self.server.diagnostic_exponent_one,
                                  expected_identity=self.server.expected_identity,
                                  response_probe=self.server.response_probe,
                                  ready_probe=self.server.ready_probe,
                                  ready_identity_probe=self.server.ready_identity_probe,
                                  auth_identity_probe=self.server.auth_identity_probe,
                                  business_login_probe=self.server.business_login_probe,
                                  business_bootstrap_probe=self.server.business_bootstrap_probe,
                                  backend=self.server.backend,
                                  local_session=self.server.local_session,
                                  continuation_seconds=self.server.continuation_seconds)
        self.server.state.record(result)
        print(json.dumps(result), flush=True)


def main():
    root = Path(__file__).resolve().parent.parent
    parser = argparse.ArgumentParser(description='Local DH-only diagnostic; game login is not implemented')
    modes = parser.add_mutually_exclusive_group(required=True)
    modes.add_argument('--modulus-file', type=Path,
                        help='Private file containing the verified 64-byte client DH modulus as hex')
    modes.add_argument('--diagnostic-exponent-one', action='store_true',
                       help='Insecure loopback-only handshake probe; cannot authorize a game account')
    parser.add_argument('--port', type=int, default=65010)
    parser.add_argument('--report', type=Path, default=root / 'data/local-handshake-diagnostic.json')
    args = parser.parse_args()
    if not 0 <= args.port <= 65535:
        parser.error('port must be between 0 and 65535')
    modulus = _read_modulus(args.modulus_file) if args.modulus_file else None
    state = State(args.report)
    with Server(('127.0.0.1', args.port), state, modulus, args.diagnostic_exponent_one) as server:
        state.update(listening=True, address='127.0.0.1', port=server.server_address[1])
        print(f'DH-only diagnostic listening on 127.0.0.1:{server.server_address[1]}', flush=True)
        try:
            server.serve_forever(poll_interval=0.25)
        except KeyboardInterrupt:
            pass
        finally:
            state.update(listening=False, stopped_at_utc=_time())


if __name__ == '__main__':
    main()
