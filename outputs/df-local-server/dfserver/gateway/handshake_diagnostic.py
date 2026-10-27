"""Bounded loopback GCP handshake diagnostic.

This listener supports a bounded, locally authenticated compatibility trial
against the original client. Diagnostic exponent-one mode is restricted to
loopback: the resulting session key is public and must never protect an
Internet account session. Reports contain only framing and field lengths.
"""
from dfserver._paths import SERVER_ROOT
import argparse
from collections import deque
from concurrent.futures import ThreadPoolExecutor, TimeoutError as FutureTimeout
from dataclasses import dataclass, field, replace
from datetime import datetime, timezone
from functools import lru_cache
import hashlib
import json
import os
from pathlib import Path
import secrets
import select
import socket
import socketserver
import threading
import time

from dfserver.transport.gcp.gcp_control import AuthResponse, CommonAuthResponse, ReadyResponse, parse_auth_request
from dfserver.diagnostics.business_probe import summarize_message_shape, summarize_prefixed_envelope
from dfserver.gateway.business_envelope import BusinessEnvelope, parse_business_envelope
from dfserver.gateway.candidate_business import CandidateBusinessCodec
from dfserver.gateway.client_errors import error_code, inventory_error
from dfserver.inventory.container_layouts import capacity as container_capacity
from dfserver.app.core import POCKET_LAYOUT, POCKET_POSITION, BACKPACK_LAYOUT, BACKPACK_POSITION, CHEST_RIG_LAYOUT, CHEST_RIG_POSITION, SAFE_BOX_POSITION, DomainError
from dfserver.inventory import safe_boxes
from dfserver.progression import native_safehouse
from dfserver.progression import native_quests
from dfserver.progression import native_department_queries
from dfserver.account import native_session_auxiliary
from dfserver.match import native_match_unavailable
from dfserver.progression import native_season
from dfserver.inventory import native_warehouse_extensions

ACTIVITY_REQUESTS = (native_safehouse.SUPPORTED_REQUESTS | native_quests.SUPPORTED_REQUESTS
                     | native_department_queries.SUPPORTED_REQUESTS)
from dfserver.transport.gcp.gcp_crypto import decode_received_body, encrypt_body
from dfserver.transport.gcp.gcp_data import decode_data_frame, encode_data_frame
from dfserver.transport.gcp.gcp_framing import Frame, StreamDecoder
from dfserver.transport.gcp.gcp_handshake import DhAckBody, DhAckHeader, ServerDhAcknowledgement, create_server_ack, parse_hello
from dfserver.commerce.local_commerce import SUPPORTED_REQUESTS as LOCAL_COMMERCE_REQUESTS, response_fields as local_commerce_response_fields, installed_items, item_condition_fields, inventory_location
from dfserver.weapons.melee_weapons import WEAPONS, MELEE_POSITION
from dfserver.cosmetics import hero_customization
from dfserver.commerce import premium_shop
from dfserver.cosmetics import profile_cosmetics

COLLECTION_REQUESTS = frozenset(name[:-3] + 'Req' for name in premium_shop.COLLECTION_RESPONSES)


# GuideServer.lua 0.42 stores this list directly; 0.44/0.64/0.69
# test membership for unfinished match, forced guide, and blocked item actions.
# ApplySkipAllGuideState (0.34) and SkipNewPlayerGuide (0.35.0) clear it.
LOCAL_PENDING_GUIDE_STAGES = ()


def _time():
    return datetime.now(timezone.utc).isoformat()


@lru_cache(maxsize=1)
def _candidate_codec():
    """Share immutable descriptors; per-message protobuf instances stay local."""
    from dfserver.inventory.native_warehouse_wire import WarehouseBusinessCodec
    root = SERVER_ROOT
    return WarehouseBusinessCodec(root / 'protocol/candidate_business.pb',
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
              'local_equip_commands', 'local_inventory_failure',
              'local_body_container_snapshots', 'local_serial_buy_items',
              'local_lottery_purchase_items', 'local_inventory_change_notification_sent',
              'local_premium_shop_request', 'local_customization_request',
              'local_collection_read_request',
              'local_collection_change_notification_sent', 'local_warehouse_sort_request',
              'local_warehouse_sort_result', 'local_warehouse_sort_change_count',
              'local_weapon_assembly_request', 'local_battle_pass_request',
              'local_optional_setting_key',
              'local_match_mode_info', 'local_match_alloc_result',
              'local_match_prepare_probe_sent', 'local_game_server_join_probe_sent',
              'local_solo_room_requested_id', 'local_solo_room_requested_hero_id',
              'local_solo_room_hero_response', 'local_solo_room_ready_response',
              'local_activity_request', 'local_activity_result', 'local_activity_notification_sent',
              'local_activity_accepted_quest_count', 'local_activity_error',
              'local_activity_submit_summary', 'local_activity_inventory_changes',
              'local_activity_currency_changes', 'local_activity_action_exp_changes',
              'local_activity_quality_changes', 'local_activity_completion_override_count',
              'local_department_max_level', 'local_department_cards',
              'local_wallet_quest_refresh_count', 'local_wallet_quest_error',
              'local_match_mode_info', 'local_match_waiting_for_initial_actor_profile',
              'local_match_prepare_probe_sent', 'local_game_server_join_probe_sent',
              'local_match_handoff_elapsed_ms', 'local_match_join_elapsed_ms',
              'local_match_handoff_heartbeats',
              'local_match_allocation_cancelled',
              'local_match_recovery_request', 'local_match_recovery_response',
              'local_match_recovery_bound_handoff', 'local_match_recovery_result',
              'local_match_handoff_inactive',
              'local_match_call_numeral_notice_sent', 'local_match_recovery_handoff_sent',
              'local_match_recovery_preflight_failed',
              'local_match_recovery_failure_code',
              'local_auxiliary_one_way', 'local_auxiliary_response_expected', 'local_auxiliary_result',
              'local_season_serial', 'local_season_request',
              'local_extension_request', 'local_extension_error', 'local_warehouse_projection',
              'local_telemetry_entry_count', 'local_telemetry_payload_bytes', 'local_retro_reward_pending_count')
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


def _wait_match_handoff(build, abandon, connection, decoder, queue, key,
                        outbound_sequence, entry):
    """Keep gateway heartbeats live while one Ready-owned admission is built.

    Only this calling thread reads/writes the socket. Other frames retain their
    order for the normal lobby dispatcher; the builder never handles requests.
    """
    deferred = deque()
    with ThreadPoolExecutor(max_workers=1, thread_name_prefix='match-admission') as executor:
        future = executor.submit(build)
        try:
            while True:
                try:
                    return future.result(timeout=0.02), outbound_sequence
                except FutureTimeout:
                    if future.done():
                        raise  # A TimeoutError raised by the builder itself.
                if not queue:
                    if not select.select((connection,), (), (), 0.02)[0]:
                        continue
                    chunk = connection.recv(65536)
                    if not chunk:
                        raise ConnectionError('Client closed while its admission was being built')
                    queue.extend(decoder.feed(chunk))
                    if not queue:
                        continue
                frame = queue.popleft()
                reply = None
                if frame.command == 0x9001:
                    reply = _transport_ping_reply(frame, header_word9=outbound_sequence + 1)
                elif frame.command == 0x4013:
                    messages = decode_data_frame(frame, key,
                        direction='client_to_server', compression_method=1).messages
                    if (len(messages) == 1 and summarize_prefixed_envelope(messages[0]).get(
                            'message_name') == 'CSOnlineHeartbeatReq'):
                        reply = _candidate_local_heartbeat_response(messages[0], key,
                            header_word4=frame.header_word4, header_word9=outbound_sequence + 1)
                if reply is not None:
                    connection.sendall(reply.encode())
                    outbound_sequence += 1
                    entry['local_match_handoff_heartbeats'] = entry.get(
                        'local_match_handoff_heartbeats', 0) + 1
                else:
                    deferred.append(frame)
                    if len(deferred) > 256:
                        raise ValueError('Admission pending request queue exceeds its bound')
        except BaseException:
            if not future.cancel():
                try:
                    handoff = future.result()
                except BaseException:
                    pass
                else:
                    abandon(handoff)
            raise
        finally:
            pending = tuple(queue)
            queue.clear()
            queue.extend(deferred)
            queue.extend(pending)


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


@lru_cache(maxsize=1)
def _client_online_player_state():
    """Use the client enum, rather than treating wire State=0 as idle.

    AccountServer._ParsePlayerStateCode replaces the client's current flags
    with this response. Zero is EPlayerState_Offline, so it clears the online
    bit that MatchServer checks before invoking its preparation entry event.
    """
    source = SERVER_ROOT / 'protocol/recovered_player_state_flags.json'
    document = json.loads(source.read_text(encoding='utf-8'))
    flags = document['values']
    online = flags['EPlayerState_Online']
    if (document.get('enum') != 'GlobalPlayerStateEnums' or type(online) is not int
            or online <= 0 or online & (online - 1)
            or flags['EPlayerState_Offline'] != 0):
        raise ValueError('Invalid recovered online-player state enum')
    return online


def _candidate_local_state_response(message, expected_identity, key, *, header_word4, header_word9):
    if len(message) < 5:
        raise ValueError('Truncated state package')
    codec = _candidate_codec()
    request = codec.decode(message[4:])
    if request.name != 'CSStateGetInfoReq' or request.service != 'online':
        raise ValueError('Unexpected post-login state request')
    response = codec.response(request, {
        'PlayerID': expected_identity['native_id'],
        'State': _client_online_player_state(),
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
        # ClockManager uses this value directly with os.time() in seconds.
        'tick_count': int(time.time()),
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
    root = SERVER_ROOT
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
    root = SERVER_ROOT
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
    if request.name == 'CSHeroGetHeroIDListReq':
        fields = {'result': 0, 'hero_ids': list(ids)}
    elif request.name == 'CSHeroLoadHeroListReq':
        fields = hero_customization.load_fields(backend, local_session,
            hero_ids=ids, request_fields=request.fields)
    else:
        raise ValueError('Not a supported hero catalogue request')
    response = codec.response(request, fields)
    return encode_data_frame((response,), key, direction='server_to_client',
                             opaque_flag=64, header_word4=header_word4,
                             header_word9=header_word9, max_output=1024 * 1024)


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
    backend.set_native_selected_hero_for_mode(local_session, hero_id, mode)
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
    root = SERVER_ROOT
    catalog_path = Path(os.environ.get(
        'DF_LOCAL_MAP_BOARD_CATALOG',
        root / 'protocol/local_map_board_candidates.json'))
    rows = json.loads(catalog_path.read_text(encoding='utf-8'))['operations']
    if not isinstance(rows, list):
        raise ValueError('Local map board catalog must contain an operations list')
    if len({(row['point_id'], row.get('sub_mode', 10),
             row.get('match_mode_type', 1)) for row in rows}) != len(rows):
        raise ValueError('Invalid bounded local map board candidates')
    for row in rows:
        if any(type(row[field]) is not int or row[field] <= 0 for field in
               ('map_id', 'point_id', 'match_mode_id', 'min_level')):
            raise ValueError('Invalid local map board candidate field')
        if type(row.get('match_mode_type', 1)) is not int or row.get('match_mode_type', 1) <= 0:
            raise ValueError('Invalid local map board match mode type')
        for field in ('game_mode', 'game_rule', 'sub_mode', 'team_mode', 'mode_group'):
            if field in row and (type(row[field]) is not int or row[field] < 0):
                raise ValueError(f'Invalid local map board {field}')
        if 'difficulty' in row and (type(row['difficulty']) is not int or
                                    not 0 <= row['difficulty'] <= 3):
            raise ValueError('Invalid local map board difficulty')
    return rows


@lru_cache(maxsize=1)
def _candidate_local_map_tod_policy():
    from dfserver.match.legacy_ds_local_map_rules import load_rule_sources
    path = SERVER_ROOT / 'protocol/local-map-rules/sources.json'
    return load_rule_sources(path.read_bytes())['local_map_board_tod_policy']


def _candidate_local_board_tod_fields(row):
    policy = _candidate_local_map_tod_policy().get(str(row['map_id']))
    if policy is None:
        return {}
    # The actual GameModeServer consumer copies board.tod_info into the mode;
    # IrisSafeHouse resolves this source-backed TODConfig row before events.
    return dict(tod_info=dict(policy['tod_info']))


def _candidate_local_prepare_map_response(message, backend, local_session, key,
                                          *, header_word4, header_word9, observation=None):
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
                'game_mode': row.get('game_mode', 1),
                'game_rule': row.get('game_rule', 4),
                'sub_mode': row.get('sub_mode', 10),
                'team_mode': row.get('team_mode', 3),
                'map_id': row['map_id'], 'match_mode_id': row['match_mode_id']},
             'need_level': row['min_level'], 'is_open': int(level >= row['min_level']),
             'is_show': 1, 'lock_reason': 0 if level >= row['min_level'] else 4,
             'match_mode_type': row.get('match_mode_type', 1),
             **({'difficulty': row['difficulty']} if 'difficulty' in row else {}),
             **_candidate_local_board_tod_fields(row),
             **({'mode_group': row['mode_group']} if 'mode_group' in row else {})}
            for row in _candidate_local_map_board_catalog()
            if _candidate_valid_world_map_row(row)]
    response = codec.response(request, fields)
    if observation is not None:
        # Capture what the serializer actually emitted, rather than the input
        # catalogue. MapBoardInfo contains no account credentials.
        observation.update(request_name=request.name, response_name=request.name[:-3] + 'Res',
                           observed_at_utc=_time(),
                           response_fields=codec.decode(response).fields)
    return encode_data_frame((response,), key, direction='server_to_client',
                             opaque_flag=64, header_word4=header_word4,
                             header_word9=header_word9)


def _candidate_valid_world_map_row(row):
    """Do not advertise the observed safehouse mode as a world entrance."""
    return not (int(row.get('game_mode', 1)) == 1 and
                int(row['match_mode_id']) in (1, 31100003))


def _candidate_local_room_mode_response(message, key, *, header_word4, header_word9):
    """Publish only map modes with an unambiguous ID in the trial catalogue."""
    if len(message) < 5:
        raise ValueError('Truncated room mode package')
    codec = _candidate_codec()
    request = codec.decode(message[4:])
    if request.name != 'CSRoomGetMatchModeListReq':
        raise ValueError('Not a room mode list request')
    requested_game_mode = int(request.fields.get('game_mode') or 0)
    modes = {}
    ambiguous = set()
    for row in _candidate_local_map_board_catalog():
        if not _candidate_valid_world_map_row(row):
            continue
        mode = {
            'game_mode': row.get('game_mode', 1),
            'game_rule': row.get('game_rule', 4),
            'sub_mode': row.get('sub_mode', 10),
            'team_mode': row.get('team_mode', 3),
            'map_id': row['map_id'],
            'match_mode_id': row['match_mode_id'],
        }
        if requested_game_mode and mode['game_mode'] != requested_game_mode:
            continue
        mode_id = mode['match_mode_id']
        if mode_id in modes and modes[mode_id] != mode:
            ambiguous.add(mode_id)
        else:
            modes[mode_id] = mode
    available = [mode for mode_id, mode in modes.items() if mode_id not in ambiguous]
    response = codec.response(request, {
        'result': 0,
        'mode_info_array': available,
        'mode_info_list': [
            {'mode_info': mode, 'BeginMatchMinPlayerNum': 1,
             'BeginMatchValidTeamNum': 1, 'BeginMatchCampMinPlayerNum': 1}
            for mode in available
        ],
    })
    return encode_data_frame((response,), key, direction='server_to_client',
                             opaque_flag=64, header_word4=header_word4,
                             header_word9=header_word9)


def _candidate_local_match_rank_response(message, key, *, header_word4, header_word9):
    """Answer the map-selection rank gate for the local game session."""
    if len(message) < 5:
        raise ValueError('Truncated rank-gate package')
    codec = _candidate_codec()
    request = codec.decode(message[4:])
    if request.name != 'CSMatchGateIsRankEnableReq':
        raise ValueError('Not a rank-gate request')
    response = codec.response(request, {'result': 0, 'is_rank_enable': True})
    return encode_data_frame((response,), key, direction='server_to_client',
                             opaque_flag=64, header_word4=header_word4,
                             header_word9=header_word9)


def _candidate_local_solo_room_team_response(message, backend, local_session,
                                             match_mode_info, key, *,
                                             header_word4, header_word9):
    """Return the local player's selected operator for a valid room handoff."""
    if len(message) < 5:
        raise ValueError('Truncated solo room team package')
    codec = _candidate_codec()
    request = codec.decode(message[4:])
    if request.name != 'CSMatchRoomGetSolRoomTeamTReq':
        raise ValueError('Not a solo room team request')
    identity = backend.native_identity(local_session)
    player_id = int(identity['native_id'])
    room_id = int(request.fields.get('room_id') or 0)
    if (not match_mode_info or not _candidate_valid_world_map_row(match_mode_info)
            or room_id != player_id):
        fields = {'result': 1, 'room_id': room_id}
    else:
        profile = backend.native_lobby_profile(local_session)
        hero_id = int(profile['selected_hero_id'] or 88000000025)
        if hero_id not in _candidate_known_operator_ids():
            raise ValueError('Selected hero is absent from the installed catalogue')
        hero_info = hero_customization.hero_records(
            backend, local_session, [hero_id], _candidate_operator_base_fashions())[0]
        room_start_time = int(time.time())
        fields = {
            'result': 0,
            'room_id': room_id,
            'room_start_time': room_start_time,
            # AssemblySquadPick subtracts 8 seconds from stage_end_time.
            # The normal Zero Dam trace also uses an 18-second interval,
            # giving the player a 10-second operator-selection countdown.
            'stage_end_time': room_start_time + 18,
            'player_info_array': [{
                'player_id': player_id,
                'hero_info': hero_info,
                'is_ready': False,
                'nick_name': identity.get('game_nick') or identity['username'],
                'player_idx': 1,
                'is_bot': False,
                'pre_selected_hero_id': hero_id,
            }],
        }
    response = codec.response(request, fields)
    return encode_data_frame((response,), key, direction='server_to_client',
                             opaque_flag=64, header_word4=header_word4,
                             header_word9=header_word9)


def _candidate_local_solo_room_hero_response(message, backend, local_session,
                                             match_mode_info, key, *,
                                             header_word4, header_word9):
    """Apply a room selection to the same SOL operator used by the lobby."""
    if len(message) < 5:
        raise ValueError('Truncated solo room selection package')
    codec = _candidate_codec()
    request = codec.decode(message[4:])
    if request.name not in ('CSMatchRoomSetPreSelectedHeroTReq',
                            'CSMatchRoomSetSolRoomHeroTReq',
                            'CSMatchRoomLockSelectedHeroTReq'):
        raise ValueError('Not a solo room selection request')
    identity = backend.native_identity(local_session)
    player_id = int(identity['native_id'])
    room_id = int(request.fields.get('room_id') or 0)
    preview = request.name == 'CSMatchRoomSetPreSelectedHeroTReq'
    lock = request.name == 'CSMatchRoomLockSelectedHeroTReq'
    field = 'pre_selected_hero_id' if preview else 'hero_id'
    hero_id = int(request.fields.get(field) or 0)
    if request.fields.get('random_hero') and not hero_id:
        hero_id = int(backend.native_lobby_profile(local_session)['selected_hero_id']
                      or 88000000025)
    valid = (match_mode_info and _candidate_valid_world_map_row(match_mode_info)
             and room_id == player_id and
             (hero_id in _candidate_known_operator_ids() or (preview and hero_id == 0)))
    notification = None
    if valid:
        if not preview:
            backend.set_native_selected_hero(local_session, hero_id)
        else:
            hero_id = int(backend.native_lobby_profile(local_session)['selected_hero_id']
                          or 88000000025)
        if lock:
            notice = codec.encode('CSMatchRoomSolReadyNtf', {
                'room_id': room_id, 'player_id': player_id,
            }, sequence=0)
        else:
            hero_info = hero_customization.hero_records(
                backend, local_session, [hero_id], _candidate_operator_base_fashions())[0]
            notice = codec.encode('CSMatchRoomSolChangeHeroNtf', {
                'room_id': room_id,
                'player_id': player_id,
                'hero_info': hero_info,
                'pre_selected_hero_id': int(request.fields.get(field) or 0),
            }, sequence=0)
        notification = encode_data_frame(
            (notice,), key, direction='server_to_client', opaque_flag=64,
            header_word4=header_word4, header_word9=header_word9 + 1)
    response = codec.response(request, {'result': 0 if valid else 1})
    frame = encode_data_frame((response,), key, direction='server_to_client',
                              opaque_flag=64, header_word4=header_word4,
                              header_word9=header_word9)
    return frame, notification


def _candidate_local_solo_room_ready_response(message, backend, local_session,
                                              match_mode_info, key, *,
                                              header_word4, header_word9):
    """Acknowledge the SOL panel's actual end-of-countdown request.

    AssemblySquadPick:SetHeroReady calls ArmedForceServer:ReqSolReady;
    it does not send LockSelectedHero. Ready must refer to our allocated room.
    """
    if len(message) < 5:
        raise ValueError('Truncated solo room ready package')
    codec = _candidate_codec()
    request = codec.decode(message[4:])
    if request.name != 'CSMatchRoomSolReadyTReq':
        raise ValueError('Not a solo room ready request')
    player_id = int(backend.native_identity(local_session)['native_id'])
    room_id = int(request.fields.get('room_id') or 0)
    valid = (match_mode_info and _candidate_valid_world_map_row(match_mode_info)
             and room_id == player_id)
    response = codec.response(request, {'result': 0 if valid else 1})
    frame = encode_data_frame((response,), key, direction='server_to_client',
                              opaque_flag=64, header_word4=header_word4,
                              header_word9=header_word9)
    notification = None
    if valid:
        ready = codec.encode('CSMatchRoomSolReadyNtf', {
            'room_id': room_id, 'player_id': player_id,
        }, sequence=0)
        notification = encode_data_frame((ready,), key, direction='server_to_client',
                                         opaque_flag=64, header_word4=header_word4,
                                         header_word9=header_word9 + 1)
    return frame, notification


def _candidate_local_allocation_modes_valid(modes, probe):
    """Validate the full advertised mode before replacing any owner's allocation."""
    if (probe is None or not probe.listening or type(modes) is not list
            or not 1 <= len(modes) <= 16):
        return False
    names = ('game_mode', 'game_rule', 'sub_mode', 'team_mode', 'map_id', 'match_mode_id')
    try:
        allowed = {tuple(int(row.get(name) or 0) for name in names)
                   for row in _candidate_local_map_board_catalog()
                   if _candidate_valid_world_map_row(row)}
        return all(tuple(int(mode.get(name) or 0) for name in names) in allowed for mode in modes)
    except (TypeError, ValueError, AttributeError):
        return False


def _candidate_local_match_alloc_response(message, key, *, header_word4, header_word9,
                                          game_server_probe=None):
    """Reject matchmaking until a real local game-server handoff exists.

    A successful allocation response starts the client's matching spinner.
    It must not be sent merely because this lobby service can decode the
    request: there is no local DS process to allocate or connect to yet.
    """
    if len(message) < 5:
        raise ValueError('Truncated matchmaking package')
    codec = _candidate_codec()
    request = codec.decode(message[4:])
    if request.name == 'CSRoomMatchStartAllocReq':
        modes = request.fields.get('mode_infos') or []
        fields = {'result': 0 if _candidate_local_allocation_modes_valid(modes, game_server_probe) else 1}
    elif request.name == 'CSRoomMatchQuitAllocReq':
        fields = {'result': 0}
    elif request.name in ('CSMatchCheckTReq',
                          'CSMatchRoomSolReadyTReq',
                          'CSMatchRoomStartMatchTglogTReq'):
        fields = {'result': 0}
    else:
        raise ValueError('Not a matchmaking allocation request')
    response = codec.response(request, fields)
    return encode_data_frame((response,), key, direction='server_to_client',
                             opaque_flag=64, header_word4=header_word4,
                             header_word9=header_word9)


def _candidate_local_match_prepare_probe(backend, local_session, match_mode_info, key,
                                         *, header_word4, header_word9, game_server_probe=None):
    """Probe the client's room transition with its actual local player.

    This diagnostic deliberately stops before PlayerJoinMatch: no game server
    is advertised until one actually exists at a reachable local endpoint.
    """
    mode_id = int(match_mode_info.get('match_mode_id') or 0)
    if (int(match_mode_info.get('game_mode') or 0) == 1 and
            mode_id in (1, 31100003)):
        raise ValueError('World map cannot use a placeholder or safehouse match mode')
    identity = backend.native_identity(local_session)
    player_id = int(identity['native_id'])
    local_events = {}
    prepare_room = getattr(game_server_probe, 'prepare_match_room', None)
    if callable(prepare_room):
        world = prepare_room(player_id=player_id, room_id=player_id,
            map_id=int(match_mode_info.get('map_id') or 0), match_mode_id=mode_id)
        if world is not None:
            local_events = dict(random_seed=world['seed'],
                box_event=world['selected_mandel_generator_ids'], iris_event_ids=world['iris_event_ids'])
    members = [{
        'player_id': player_id, 'team_id': 1, 'player_idx': 1, 'camp': 1,
        'nick_name': identity.get('game_nick') or identity['username'],
        'is_robot': False, 'is_team_leader': True,
    }]
    # The local bootstrap creates this player only. Additional room members
    # require actual admitted players or a running server-owned AI lifecycle.
    notification = _candidate_codec().encode('CSPrepareJoinMatchNtf', {
        'ds_room_id': player_id, 'time_stamp': int(time.time()),
        'player_id': player_id, 'team_id': 1, 'random_seed': 1,
        'player_idx': 1, 'game_mode': int(match_mode_info.get('game_mode') or 1),
        'match_mode_id': mode_id,
        'room_member_infos': members,
        **local_events,
    }, sequence=0)
    return encode_data_frame((notification,), key, direction='server_to_client',
                             opaque_flag=64, header_word4=header_word4,
                             header_word9=header_word9)


def _candidate_local_match_profile_ready(game_server_probe, match_mode_info):
    """Defer only the explicitly required local bootstrap, without blocking."""
    if getattr(game_server_probe, 'initial_actor_profile_required', False) is not True:
        return True
    readiness = getattr(game_server_probe, 'match_admission_ready', None)
    return (callable(readiness) and match_mode_info is not None and
            readiness(int(match_mode_info.get('map_id') or 0)))


def _candidate_cancel_local_match_allocation(probe, handoff, backend, session, mode):
    ticket = getattr(handoff, 'ticket', None)
    cancel = getattr(probe, 'cancel_match_admission', None)
    if ticket is not None and callable(cancel):
        return cancel(ticket)
    cancel_prepared = getattr(probe, 'cancel_prepared_match', None)
    cancel_unjoined = getattr(probe, 'cancel_unjoined_match_allocations', None)
    if backend is not None and session is not None and (callable(cancel_prepared) or callable(cancel_unjoined)):
        player_id = int(backend.native_identity(session)['native_id'])
        cancelled = bool(cancel_unjoined(player_id)) if callable(cancel_unjoined) else False
        if callable(cancel_prepared) and mode:
            cancelled = cancel_prepared(player_id=player_id, room_id=player_id,
                map_id=int(mode.get('map_id') or 0), match_mode_id=int(mode.get('match_mode_id') or 0)) or cancelled
        return cancelled
    return False


def _candidate_match_preflight_failure(entry, error):
    # Exception text can contain private admission data. Publish only a closed code.
    from dfserver.match.legacy_ds_match_admission import MatchAdmissionCapacityReached
    entry['local_match_recovery_preflight_failed'] = True
    entry['local_match_recovery_failure_code'] = (
        'local_room_capacity' if isinstance(error, MatchAdmissionCapacityReached)
        else 'local_admission_rejected')


@dataclass(frozen=True, repr=False)
class _LocalMatchHandoff:
    player_id: int
    room_id: int
    game_mode: int
    map_id: int
    match_mode_id: int
    body: bytes = field(repr=False)
    ticket: object = field(repr=False)


def _local_match_varint(value):
    if type(value) is not int or not 0 <= value < 1 << 64:
        raise ValueError('Invalid positive protobuf integer')
    output = bytearray()
    while value > 127:
        output.append((value & 127) | 128)
        value >>= 7
    output.append(value)
    return bytes(output)


def _local_match_integer(number, value):
    return _local_match_varint(number << 3) + _local_match_varint(value)


def _local_match_data(number, value):
    value = value.encode('utf-8') if isinstance(value, str) else value
    return (_local_match_varint(number << 3 | 2) +
            _local_match_varint(len(value)) + value)


def _local_match_request_unsigned(value, bits):
    # Candidate protobuf JSON represents uint64 fields as decimal strings.
    if type(value) is str and value.isascii() and value.isdecimal() and len(value) <= 20:
        value = int(value)
    if type(value) is not int or not 0 <= value < 1 << bits:
        raise ValueError('Invalid unsigned local match recovery field')
    return value


def _candidate_local_match_join_parameters(backend, local_session, match_mode_info,
                                          game_server_probe):
    """Preflight an advertised endpoint without issuing a ticket or cookie."""
    if game_server_probe is None or not game_server_probe.listening:
        raise ValueError('No active local game-server probe')
    identity = backend.native_identity(local_session)
    player_id = int(identity['native_id'])
    mode_id = int(match_mode_info.get('match_mode_id') or 0)
    if not 0 < mode_id < 1 << 32:
        raise ValueError('No bounded match mode for local game-server handoff')
    if (int(match_mode_info.get('game_mode') or 0) == 1 and
            mode_id in (1, 31100003)):
        raise ValueError('World map cannot use a placeholder or safehouse match mode')
    map_id = int(match_mode_info.get('map_id') or 0)
    map_id_override = os.environ.get('DF_LOCAL_DS_MAP_ID')
    if map_id_override and int(map_id_override) != map_id:
        raise ValueError('Local DS map ID differs from the selected map')
    if not 0 < map_id < 1 << 32:
        raise ValueError('No bounded map ID for local game-server handoff')
    if not _candidate_local_match_profile_ready(game_server_probe, match_mode_info):
        raise ValueError('Required initial Actor profile is not ready for local handoff')
    if type(game_server_probe.port) is not int or not 0 < game_server_probe.port < 1 << 16:
        raise ValueError('No bounded loopback port for local game-server handoff')
    return player_id, mode_id, map_id


def _candidate_local_match_join_handoff(backend, local_session, match_mode_info,
                                        game_server_probe):
    """Build one local handoff using the operator selected at actual issuance."""
    player_id, mode_id, map_id = _candidate_local_match_join_parameters(
        backend, local_session, match_mode_info, game_server_probe)
    integer, data = _local_match_integer, _local_match_data

    # The full MatchPlayerInfo descriptor is excluded because two unrelated
    # settlement submessages were not recovered.  Only fields observed in the
    # installed client's encoder are emitted here, without inventing those
    # missing nested definitions.
    ds_token = secrets.token_hex(16)
    ticket = None
    if getattr(game_server_probe, 'match_admission_enabled', False):
        selected_fashion = {}
        requires_appearance = getattr(game_server_probe, 'match_appearance_required', None)
        if callable(requires_appearance) and requires_appearance(map_id):
            snapshot_factory = getattr(backend, 'native_match_snapshot', None)
            if callable(snapshot_factory):
                selected_hero_id, fashion_id, loadout = snapshot_factory(local_session)
                selected_fashion['loadout_snapshot'] = loadout
            else:
                from dfserver.cosmetics.hero_customization import match_selection
                selected_hero_id, fashion_id = match_selection(backend, local_session)
            selected_fashion['selected_fashion_id'] = fashion_id
        else:
            selected_hero_id = backend.native_lobby_profile(local_session)['selected_hero_id']
        if type(selected_hero_id) is not int or not 0 < selected_hero_id < 1 << 64:
            raise ValueError('No persisted SOL operator for local match admission')
        ticket = game_server_probe.issue_match_admission(
            player_id=player_id, room_id=player_id, map_id=map_id,
            match_mode_id=mode_id,
            selected_hero_id=selected_hero_id, **selected_fashion)
        # Installed MatchServer.GetLevelUrl takes player.ds_token (field24)
        # as its Cookie option. It is distinct from top-level secret_key19.
        ds_token = ticket.cookie
    player = (integer(1, player_id) + integer(2, 1) + integer(3, 1) +
              integer(13, 1) + data(24, ds_token))
    ds_address = (data(1, '127.0.0.1') +
                  integer(2, game_server_probe.port))
    # _ParseDsInfoAsync resolves each HostInfo.ds_domain even when IPv4
    # addresses are supplied. An omitted domain becomes an empty string
    # and sends the native resolver through its failure/timeout fallback.
    # Keep both the resolver and its fallback entirely on loopback.
    ds_domain = 'localhost'
    ds_host = data(1, ds_domain) + data(2, ds_address)
    # This receiver has no negotiated DS encryption key.  Sending a random
    # hexadecimal string as secret_key falsely advertises one.  MatchServer's
    # AppendSecretKeyToUrl explicitly leaves the URL alone for an empty key.
    # Keep this transport-only probe unencrypted; a gameplay server will need
    # to implement the actual key exchange before advertising a session key.
    body = (integer(1, player_id) + data(10, '127.0.0.1') +
            integer(3, game_server_probe.port) +
            integer(5, map_id) +
            integer(6, 0) + data(8, player) + data(9, ds_domain) + integer(11, mode_id) +
            data(12, ds_host) + integer(14, 0))
    return _LocalMatchHandoff(player_id, player_id,
        int(match_mode_info.get('game_mode') or 1), map_id, mode_id, body, ticket)


def _candidate_local_match_join_frame(handoff, key, *, header_word4, header_word9):
    notification = BusinessEnvelope(handoff.body, {
        'client_sequence_id': 0, 'name': 'CSPlayerJoinMatchNtf',
        'service': 'matchroom',
    }).encode()
    return encode_data_frame((notification,), key, direction='server_to_client',
                             opaque_flag=64, header_word4=header_word4,
                             header_word9=header_word9)


def _candidate_local_match_join_probe(backend, local_session, match_mode_info,
                                      game_server_probe, key, *, header_word4, header_word9):
    handoff = _candidate_local_match_join_handoff(
        backend, local_session, match_mode_info, game_server_probe)
    return _candidate_local_match_join_frame(handoff, key,
        header_word4=header_word4, header_word9=header_word9)


def _candidate_local_match_call_numeral_notice(room_id, mode_id, key, *, header_word4, header_word9):
    """Ask the installed WaitForGotoGame consumer to query its prepared room.

    Twelve seconds is an explicit local recovery policy. The selection panel
    ordinarily counts ten seconds from its own room request, so this interval
    does not prove selection has completed. It is not an official captured delay.
    """
    notification = _candidate_codec().encode('CSMatchRoomCallNumeralNtf', {
        'ds_room_id': room_id, 'player_id': room_id,
        'match_mode_id': mode_id, 'check_gap': 12,
    }, sequence=0)
    return encode_data_frame((notification,), key, direction='server_to_client',
        opaque_flag=64, header_word4=header_word4, header_word9=header_word9)


def _candidate_local_match_call_numeral_response(message, backend, local_session,
        match_mode_info, game_server_probe, key, *, prepared, handoff,
        prepared_room_id, header_word4, header_word9, diagnostic_entry=None):
    """Recover the same prepared local handoff, without manufacturing Ready.

    Installed MatchServer callback 0.74.0 consumes Res.ntf directly as a
    CSPlayerJoinMatchNtf. The incomplete nested codec cannot be used here:
    field 2 contains only that message's body, never its business envelope.
    """
    if len(message) < 5:
        raise ValueError('Truncated match handoff recovery package')
    request = _candidate_codec().decode(message[4:])
    if request.name != 'CSMatchRoomCheckCallNumeralReq':
        raise ValueError('Not a match handoff recovery request')
    success = False
    try:
        identity = backend.native_identity(local_session)
        player_id = int(identity['native_id'])
        fields = request.fields
        requested_player = _local_match_request_unsigned(fields.get('player_id', 0), 64)
        requested_room = _local_match_request_unsigned(fields.get('ds_room_id', 0), 64)
        requested_game_mode = _local_match_request_unsigned(fields.get('game_mode', 0), 32)
        requested_mode = _local_match_request_unsigned(fields.get('match_mode_id', 0), 64)
        active = getattr(game_server_probe, 'match_admission_ticket_active', None)
        if (prepared is not True or type(prepared_room_id) is not int or
                prepared_room_id != player_id or not match_mode_info or
                not _candidate_valid_world_map_row(match_mode_info) or
                game_server_probe is None or not game_server_probe.listening or
                getattr(game_server_probe, 'match_admission_enabled', False) is not True or
                not callable(active) or
                not _candidate_local_match_profile_ready(game_server_probe, match_mode_info) or
                type(player_id) is not int or not 0 < player_id < 1 << 64 or
                requested_player != player_id or requested_room != player_id or
                requested_game_mode != int(match_mode_info.get('game_mode') or 0) or
                requested_mode != int(match_mode_info.get('match_mode_id') or 0) or
                type(fields.get('reason', 0)) is not int or fields.get('reason', 0) not in (0, 1, 2)):
            raise ValueError('Local match recovery is not bound to the prepared session')
        if handoff is None:
            try:
                handoff = _candidate_local_match_join_handoff(
                    backend, local_session, match_mode_info, game_server_probe)
            except (ValueError, DomainError):
                if diagnostic_entry is not None:
                    diagnostic_entry['local_match_recovery_preflight_failed'] = True
                raise
            except OSError:
                raise
            except Exception as error:
                # An internal defect must be reported as a failed handoff,
                # not escape and silently drop the lobby connection.
                if diagnostic_entry is not None:
                    diagnostic_entry['local_match_recovery_preflight_failed'] = True
                    diagnostic_entry['local_match_handoff_internal_error'] = type(error).__name__
                raise ValueError('Local match handoff raised an internal error') from error
        if (type(handoff) is not _LocalMatchHandoff or
                (handoff.player_id, handoff.room_id, handoff.game_mode,
                 handoff.map_id, handoff.match_mode_id) !=
                (player_id, player_id, requested_game_mode,
                 int(match_mode_info.get('map_id') or 0), requested_mode) or
                handoff.ticket is None or not active(handoff.ticket)):
            raise ValueError('The original local handoff is no longer active')
        success = True
    except (ValueError, DomainError):
        pass
    body = _local_match_integer(1, 0 if success else 1)
    if success:
        body += _local_match_data(2, handoff.body)
    response = BusinessEnvelope(body, {
        'client_sequence_id': request.sequence,
        'name': 'CSMatchRoomCheckCallNumeralRes', 'service': request.service,
    }).encode()
    frame = encode_data_frame((response,), key, direction='server_to_client',
        opaque_flag=64, header_word4=header_word4, header_word9=header_word9)
    return frame, handoff, success


def _candidate_local_commerce_response(message, backend, local_session, key,
                                       *, header_word4, header_word9, diagnostic_entry=None):
    if len(message) < 5:
        raise ValueError('Truncated commerce package')
    codec = _candidate_codec()
    request = codec.decode(message[4:])
    from dfserver.progression import battle_pass
    from dfserver.account import native_settings
    if diagnostic_entry is not None and request.name == 'CSSettingGetValueByKeyReq':
        setting_key = request.fields.get('key', '')
        diagnostic_entry['local_optional_setting_key'] = (
            setting_key if setting_key in native_settings.OPTIONAL_SETTING_KEYS else '<other>')
    if diagnostic_entry is not None and request.name == 'CSCollectionUpdateRedPointReq':
        diagnostic_entry['local_collection_read_request'] = {
            name: request.fields.get(name, [])[:32] for name in
            ('props', 'prop_ids', 'gun_skin_pattern_id', 'mystical_pendant_suit_ids')}
    if request.name in battle_pass.SUPPORTED_REQUESTS:
        committed = {}
        fields = battle_pass.response_fields(request, backend, local_session, changes=committed)
        if diagnostic_entry is not None:
            diagnostic_entry['local_battle_pass_request'] = request.fields
            diagnostic_entry['_battle_pass_changes'] = committed
    else:
        fields = local_commerce_response_fields(request, backend, local_session,
                                               diagnostic_entry=diagnostic_entry)
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


def _candidate_inventory_notice_fields(deposit, *, backend=None, local_session=None,
                                        extension_pos_order=None):
    # _OnCSDepositChangeNtf replaces this list even for an unrelated currency change.
    if extension_pos_order is None:
        extension_pos_order = (backend.native_lobby_profile(local_session)['warehouse_extensions'][
            'extension_pos_order'] if backend is not None and local_session else [])
    return {'deposit_change': deposit, 'extension_pos_order': list(extension_pos_order)}


def _candidate_local_battle_pass_notifications(entry, key, *, header_word4, header_word9,
                                               backend=None, local_session=None):
    committed = entry.pop('_battle_pass_changes', {})
    messages = []
    deposit = {'currency_changes': committed.get('currency_changes', []),
               'prop_changes': committed.get('deposit_changes', [])}
    if any(deposit.values()):
        messages.append(('CSDepositChangeNtf', _candidate_inventory_notice_fields(
            deposit, backend=backend, local_session=local_session)))
    collection = committed.get('collection_changes', [])
    if collection:
        messages.append(('CSCollectionPropChangeNtf', {'data_change': [
            {'change_type': row['change_type'], 'prop': row['prop'],
             'delta_num': row['delta'], 'after_num': row['prop']['num']}
            for row in collection]}))
    return [encode_data_frame((_candidate_codec().encode(name, fields, sequence=0),), key,
                direction='server_to_client', opaque_flag=64, header_word4=header_word4,
                header_word9=header_word9 + index + 1)
            for index, (name, fields) in enumerate(messages)]


def _candidate_local_premium_shop_summary(message):
    fields = _candidate_codec().decode(message[4:]).fields
    return {key: fields[key] for key in (
        'tab_id', 'banner_type', 'item_ids', 'goods_id', 'num', 'lottery_id', 'round',
        'currency_type', 'price', 'currency_type_substitute', 'price_substitute',
        'hero_id', 'new_fashions', 'buy_prop', 'is_cash_buy') if key in fields}


def _candidate_local_customization_summary(message):
    fields = _candidate_codec().decode(message[4:]).fields
    return {key: fields[key] for key in (
        'hero_id', 'new_fashions', 'accessory_item', 'is_unequip', 'mode',
        'prop_id', 'prop_ids', 'avatar_id', 'military_tag', 'title', 'honor_mark',
        'is_fashion_prior', 'prior_settings', 'badge', 'badges',
        'filter_by_id', 'hero_id_list') if key in fields}


def _candidate_local_inventory_change_notification(response_frame, key, *,
                                                   header_word4, header_word9,
                                                   backend=None, local_session=None):
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
              or response.fields.get('data_change')
              or response.fields.get('deposit_change')
              or response.fields.get('prop_changes')
              or response.fields.get('mall_changes')
              or response.fields.get('auction_changes'))
    if not change:
        return None
    if response.name in premium_shop.COLLECTION_RESPONSES:
        # Collection and melee instance changes precede the purchase callback.
        change = {'currency_changes': change.get('currency_changes', [])}
        if not change['currency_changes']:
            return None
    notification = codec.encode('CSDepositChangeNtf',
        _candidate_inventory_notice_fields(change, backend=backend, local_session=local_session), sequence=0)
    return encode_data_frame((notification,), key, direction='server_to_client',
                             opaque_flag=64, header_word4=header_word4,
                             header_word9=header_word9)


def _candidate_local_collection_change_notification(response_frame, key, *,
                                                    header_word4, header_word9):
    """Push Mandel purchases and scan rewards through the collection listener."""
    codec = _candidate_codec()
    decoded = decode_data_frame(response_frame, key, direction='server_to_client',
                                compression_method=1)
    if len(decoded.messages) != 1:
        raise ValueError('Expected one local purchase response')
    response = codec.decode(decoded.messages[0])
    if (response.name not in premium_shop.COLLECTION_RESPONSES
            or int(response.fields.get('result', 1)) != 0):
        return None
    changes = []
    change = response.fields.get('change') or response.fields.get('data_change') or {}
    for entry in change.get('prop_changes', []):
        prop = entry.get('prop') or {}
        if int(prop.get('id', 0)) in WEAPONS:
            continue
        changes.append({'change_type': int(entry['change_type']), 'prop': prop,
                        'delta_num': int(entry.get('delta', prop.get('num', 0))),
                        'after_num': int(prop.get('num', 0))})
    if not changes:
        return None
    notification = codec.encode('CSCollectionPropChangeNtf',
                                {'data_change': changes}, sequence=0)
    return encode_data_frame((notification,), key, direction='server_to_client',
                             opaque_flag=64, header_word4=header_word4,
                             header_word9=header_word9)


def _candidate_local_collection_response_frames(response_frame, key, backend=None, local_session=None):
    """Update collection state before a purchase callback or scan animation starts."""
    notification = _candidate_local_collection_change_notification(
        response_frame, key, header_word4=response_frame.header_word4,
        header_word9=response_frame.header_word9)
    notifications = []
    codec = _candidate_codec()
    response = codec.decode(decode_data_frame(response_frame, key,
        direction='server_to_client', compression_method=1).messages[0])
    change = response.fields.get('change') or response.fields.get('data_change') or {}
    melee_changes = []
    if response.name in premium_shop.COLLECTION_RESPONSES and int(response.fields.get('result', 1)) == 0:
        melee_changes = [row for row in change.get('prop_changes', [])
                         if int(row.get('prop', {}).get('id', 0)) in WEAPONS
                         and int(row.get('change_type', 0)) == 1]
    if melee_changes:
        # InventoryServer_Network 0.37 updates its separate melee instance list.
        body = codec.encode('CSMeleeUnlockChangeNtf',
            {'deposit_change': {'prop_changes': melee_changes}}, sequence=0)
        notifications.append(encode_data_frame((body,), key, direction='server_to_client',
            opaque_flag=64, header_word4=response_frame.header_word4,
            header_word9=response_frame.header_word9))
    if notification is not None:
        notifications.append(replace(notification,
            header_word9=response_frame.header_word9 + len(notifications)))
    if backend is not None and int(response.fields.get('result', 1)) == 0:
        heroes = {hero_id for row in change.get('prop_changes', [])
                  if int(row.get('delta', row.get('prop', {}).get('num', 0))) > 0
                  for hero_id in hero_customization.affected_heroes(int(row.get('prop', {}).get('id', 0)))}
        if heroes:
            body = codec.encode('CSHeroUnlockNtf',
                {'heros': premium_shop.hero_records(backend, local_session, heroes)}, sequence=0)
            notifications.append(encode_data_frame((body,), key, direction='server_to_client',
                opaque_flag=64, header_word4=response_frame.header_word4,
                header_word9=response_frame.header_word9 + len(notifications), max_output=1024 * 1024))
    if not notifications:
        return (response_frame,)
    if response.name in ('CSLotteryBlindBoxDrawRes', 'CSShopOpenLotteryItemRes'):
        # RewardServer.lua 0.17.0 displays positive Modify stacks regardless of delta.
        # Consumed stacks belong in the notification, not its ten-slot animation.
        fields = dict(response.fields)
        field_name = 'data_change' if response.name == 'CSLotteryBlindBoxDrawRes' else 'change'
        prizes = None if field_name == 'data_change' else {
            p['id'] for r in fields['lottery_pool_info']['lottery_rewards'] for p in r['props']}
        fields[field_name] = {**fields[field_name], 'prop_changes': [
            {**row, 'prop': {**row['prop'], 'num': int(row.get('delta', row['prop'].get('num', 0)))}}
            for row in fields[field_name]['prop_changes']
            if int(row['change_type']) in (1, 3)
            and int(row.get('delta', row['prop'].get('num', 0))) > 0
            and (prizes is None or row['prop']['id'] in prizes)]}
        body = codec.encode(response.name, fields, sequence=response.sequence)
        response_frame = encode_data_frame((body,), key, direction='server_to_client',
            opaque_flag=64, header_word4=response_frame.header_word4,
            header_word9=response_frame.header_word9 + len(notifications))
    elif melee_changes:
        fields = dict(response.fields)
        field_name = 'data_change' if 'data_change' in fields else 'change'
        fields[field_name] = {**change, 'prop_changes': [row for row in change.get('prop_changes', [])
                             if int(row.get('prop', {}).get('id', 0)) not in WEAPONS]}
        body = codec.encode(response.name, fields, sequence=response.sequence)
        response_frame = encode_data_frame((body,), key, direction='server_to_client',
            opaque_flag=64, header_word4=response_frame.header_word4,
            header_word9=response_frame.header_word9 + len(notifications))
    else:
        response_frame = replace(response_frame, header_word9=response_frame.header_word9 + len(notifications))
    return (*notifications, response_frame)


def _candidate_local_hero_unlock_response(message, key, *, header_word4, header_word9):
    """Describe the owned local operators to the selection panel."""
    if len(message) < 5:
        raise ValueError('Truncated hero unlock package')
    codec = _candidate_codec()
    request = codec.decode(message[4:])
    if request.name != 'CSHeroGetUnlockInfoReq':
        raise ValueError('Not a hero unlock catalogue request')
    root = SERVER_ROOT
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
    root = SERVER_ROOT
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
    root = SERVER_ROOT
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
    if request.name in ('CSAccountGetPlayerProfileReq', 'CSPlayerGetBasicInfoReq'):
        from dfserver.progression import native_action_progress
        with backend.connection() as connection:
            connection.execute('BEGIN IMMEDIATE')
            player_id = backend._authorize(connection, local_session)
            action = native_action_progress.profile_fields(connection, player_id)
            independent = native_action_progress.independent_profile_fields(connection, player_id)
            connection.commit()
    if request.name == 'CSAccountGetPlayerProfileReq':
        fields = {'result': 0, **action, **independent,
                  'nick_name': expected_identity.get('game_nick') or expected_identity['username']}
        fields.update(profile_cosmetics.profile_fields(backend, local_session))
    elif request.name == 'CSPlayerGetBasicInfoReq':
        target = int(request.fields.get('player_id') or 0)
        if target and target != expected_identity['native_id']:
            fields = {'result': error_code('PlayerInfoGetProfileFailed')}
        else:
            fields = {'result': 0, 'info': {
                'player_id': expected_identity['native_id'],
                'nick_name': expected_identity.get('game_nick') or expected_identity['username'],
                'sol_level': action['level'], 'mp_level': independent['account_level'],
                **profile_cosmetics.basic_info_fields(backend, local_session)}}
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
    backend.ensure_native_lobby_melee_collection(local_session)
    state = backend.native_lobby_profile(local_session)
    from dfserver.cosmetics.gun_skins import collection as gun_skin_collection
    from dfserver.cosmetics.weapon_pendants import PENDANTS, collection as pendant_collection
    from dfserver.cosmetics.native_collection import with_redpoints
    skins = gun_skin_collection(backend, local_session)
    fields = {
        'result': 0,
        'weapon_skin_props': [{'id': WEAPONS[row['template_id']], 'gid': 0, 'num': 1}
                              for row in state['melee_props']] + [row for row in skins if not row['gid']],
        'mystical_skin_props': [row for row in skins if row['gid']],
        'weapon_pendant_props': pendant_collection(backend, local_session),
        'common_props': [
            {'id': row['template_id'], 'gid': 0, 'num': row['quantity']}
            for row in state['collection_props'] if row['template_id'] not in PENDANTS],
    }
    response = codec.response(request, with_redpoints(request.name, fields, backend, local_session))
    return encode_data_frame((response,), key, direction='server_to_client',
                             opaque_flag=64, header_word4=header_word4,
                             header_word9=header_word9)


def _deposit_inventory_location(row):
    from dfserver.inventory.native_keychains import location
    return location(row)


def _candidate_local_deposit_response(message, backend, local_session, key, *, header_word4, header_word9):
    """Provide the local account's warehouse grid and its persisted props."""
    if len(message) < 5:
        raise ValueError('Truncated deposit package')
    codec = _candidate_codec()
    request = codec.decode(message[4:])
    if request.name == 'CSDepositGetExtensionPropsReq':
        # _FetchAllItems_Start2 resets warehouse extensions, not 116/116001.
        # Keychain items are loaded once in the main GetProps response.
        extensions = backend.native_lobby_profile(local_session)['warehouse_extensions']
        response = codec.response(request, {'result': 0,
            **{name: extensions[name] for name in ('extension_slots', 'in_extension_pages')}})
        return encode_data_frame((response,), key, direction='server_to_client',
                                 opaque_flag=64, header_word4=header_word4, header_word9=header_word9)
    if request.name != 'CSDepositGetPropsReq':
        raise ValueError('Not the main warehouse fetch')
    backend.ensure_native_lobby_melee_collection(local_session)
    backend.ensure_native_lobby_safe_boxes(local_session)
    state = backend.native_lobby_profile(local_session)
    grid = dict(_candidate_main_deposit_grid())
    grid.update(state['warehouse_grid'])
    grid['props'] = []
    extensions = state['warehouse_extensions']
    extension_positions = {row['position'] for row in extensions['extension_slots']} | {
        row['grid_page_id'] for row in extensions['in_extension_pages']}
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
    for position in (CHEST_RIG_POSITION, BACKPACK_POSITION):
        equipment[position] = {'position': position, 'capacity': 0,
                               'src_prop_id': 0, 'grid_space': [], 'load_props': []}
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
    safe_box = next((prop for prop in state['props'] if prop['grid_page_id'] == 109), None)
    safe_layout = safe_boxes.layout(safe_box['template_id'] if safe_box else None)
    if safe_box and safe_layout:
        equipment[SAFE_BOX_POSITION] = {
            'position': SAFE_BOX_POSITION, 'src_prop_id': safe_box['template_id'],
            'capacity': sum(x * y for x, y in safe_layout),
            'grid_space': [{'id': index, 'length': x, 'width': y}
                           for index, (x, y) in enumerate(safe_layout, 1)],
            'load_props': [],
        }
    from dfserver.inventory.native_keychains import wire_slots
    equipment.update({row['position']: row for row in wire_slots(state)})
    occupied = set()
    pocket_slots = set()
    for prop in state['props']:
        position = prop['grid_page_id']
        if position in extension_positions:
            continue
        if position in (116, 116001):
            continue
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
        elif position == SAFE_BOX_POSITION:
            if not safe_layout or not 1 <= prop['x'] <= len(safe_layout):
                raise ValueError('Unsupported safety-box placement')
            loc = inventory_location(prop)
            width, height = safe_layout[prop['x'] - 1]
            if loc['start_x'] + loc['x'] > width or loc['start_y'] + loc['y'] > height:
                raise ValueError('Safety-box item exceeds its verified layout')
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
            **item_condition_fields(prop['template_id'], components=prop.get('components'), weapon=prop.get('weapon'), health=prop.get('health')),
            **{name: prop[name] for name in ('bind_type', 'bind_player') if name in prop},
            'loc': inventory_location(prop),
        })
    if state['melee_props'] and not equipment[113]['load_props']:
        melee = next(row for row in state['melee_props']
                     if row['template_id'] == state['selected_melee_id'])
        metadata = installed_items()[str(melee['template_id'])]
        equipment[113]['src_prop_id'] = melee['template_id']
        equipment[113]['load_props'] = [{
            'id': melee['template_id'], 'gid': melee['gid'], 'num': 1, 'position': 113,
            'length': metadata['length'], 'width': metadata['width'],
            **item_condition_fields(melee['template_id']),
            'loc': {'pos': 113, 'start_x': 0, 'start_y': 0, 'x': 1, 'y': 1,
                    'space_id': 0, 'rotate': False},
        }]
    response = codec.response(request, {
        'result': 0,
        'grid_pages': [grid],
        'equiped_props': list(equipment.values()),
        'weapon_skin_setup': state['weapon_skin_setup'],
        'melee_weapons': [{'id': row['template_id'], 'gid': row['gid'], 'num': 1,
                           'position': MELEE_POSITION if row['template_id'] == state['selected_melee_id'] else 0,
                           **item_condition_fields(row['template_id'])} for row in state['melee_props']],
        'currency': [{'id': row['currency_id'], 'num': row['amount']}
                     for row in state['currencies']],
        'sort_config': state['sort_config'],
        'extension_pos_order': extensions['extension_pos_order'],
        'safe_boxes': state['safe_box_permissions'],
        'access_card_packs': state['keychain_permissions'],
        'safe_and_card_pack_permission': state['safe_box_permissions'] + state['keychain_permissions'],
        **{name: extensions[name] for name in ('cur_extension_num', 'max_extension_num',
                                              'upperlimit_extension_num')},
    })
    return encode_data_frame((response,), key, direction='server_to_client',
                             opaque_flag=64, header_word4=header_word4,
                             header_word9=header_word9)


def _candidate_local_extension_response(message, backend, local_session, key, *,
                                        header_word4, header_word9, diagnostic_entry=None):
    codec = _candidate_codec()
    request = codec.decode(message[4:])
    if diagnostic_entry is not None:
        diagnostic_entry['local_extension_request'] = {name: request.fields.get(name, 0)
            for name in ('operation', 'prop_id', 'prop_gid', 'src_pos', 'dest_pos')}
    fields = native_warehouse_extensions.response_fields(request, backend, local_session,
        diagnostic=diagnostic_entry)
    if fields is None:
        raise ValueError('Not a supported extension operation')
    if diagnostic_entry is not None and fields['result'] == 0:
        diagnostic_entry['_local_activity_changes'] = {
            'extension_deposit_change': fields['changes'],
            'extension_pos_order': fields['extension_pos_order']}
    return encode_data_frame((codec.response(request, fields),), key,
        direction='server_to_client', opaque_flag=64, header_word4=header_word4,
        header_word9=header_word9)


def _candidate_local_warehouse_projection(backend, local_session):
    state = backend.native_lobby_profile(local_session)
    extensions = state['warehouse_extensions']
    return {'grid': state['warehouse_grid'], **{name: extensions[name] for name in
        ('cur_extension_num', 'max_extension_num', 'upperlimit_extension_num')}}


def _candidate_local_warehouse_response_projection(response, key, previous):
    message = _candidate_codec().decode(decode_data_frame(response, key,
        direction='server_to_client', compression_method=1).messages[0])
    if message.fields.get('result') != 0:
        return previous
    counters = ('cur_extension_num', 'max_extension_num', 'upperlimit_extension_num')
    if message.name == 'CSDepositGetPropsRes':
        main = next(row for row in message.fields['grid_pages'] if row['grid_page_id'] == 2)
        return {'grid': {name: main[name] for name in ('grid_length', 'grid_width')},
                **{name: message.fields.get(name, 0) for name in counters}}
    if message.name == 'CSDepositOperateExtensionBoxRes' and previous is not None:
        return {**previous, **{name: message.fields['changes'][name] for name in counters}}
    return previous


def _candidate_local_warehouse_changes(backend, local_session, previous, entry):
    current = _candidate_local_warehouse_projection(backend, local_session)
    if current != previous:
        change = {name: current[name] for name in
            ('cur_extension_num', 'max_extension_num', 'upperlimit_extension_num')}
        if current['grid'] != previous['grid']:
            width, height = (current['grid'][name] for name in ('grid_length', 'grid_width'))
            change['pos_changes'] = [{'change_type': 3, 'pos_id': 2,
                'src_prop_id': 0,
                'space': [{'id': 0, 'length': width, 'width': height}]}]
        entry.setdefault('_local_activity_changes', {})['warehouse_change'] = change
        entry['local_warehouse_projection'] = current
    return current


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
                                    header_word4, header_word9, diagnostic_entry=None):
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
    receipt = {}
    try:
        moves = backend.native_lobby_move_props(local_session, commands, receipt=receipt)
    except DomainError as error:
        if diagnostic_entry is not None:
            diagnostic_entry['local_inventory_failure'] = {'code': error.code, 'detail': error.message}
        fields = {'result': inventory_error(error), 'cmds': request.fields.get('cmds', [])}
    else:
        changes = []
        for move in moves:
            before, after = move['before'], move['after']
            row = after or before
            if (before is None or after is None or before['quantity'] != after['quantity']
                    or any(prop and prop['grid_page_id'] in (109, SAFE_BOX_POSITION, 116, 116001)
                   for prop in (before, after))):
                changes.extend(_native_inventory_changes([move])['prop_changes'])
                continue
            if after['template_id'] in WEAPONS:
                # The melee owning list is outside ordinary slots. Lua Move
                # requires both slots; swap equipped instances with Del/Add.
                changes.extend(_native_inventory_changes([{
                    'before': before if before['grid_page_id'] else None,
                    'after': after if after['grid_page_id'] else None,
                }])['prop_changes'])
                continue

            changes.append({'change_type': 5,
                            'prop': {'id': after['template_id'], 'gid': after['gid'],
                                     'num': after['quantity'],
                                     'position': after['grid_page_id'],
                                     'length': after['length'], 'width': after['width'],
                                     **item_condition_fields(after['template_id'], components=after.get('components'), weapon=after.get('weapon'), health=after.get('health')),
                                     **{name: after[name] for name in ('bind_type', 'bind_player') if name in after},
                                     'loc': inventory_location(after)},
                            'src': inventory_location(before),
                            'dest': inventory_location(after),
                            'delta': after['quantity']})
        fields = {'result': 0, 'deposit_change': {'prop_changes': changes},
                  'extension_pos_order': receipt['extension_pos_order'],
                  'cmds': request.fields.get('cmds', [])}
        from dfserver.inventory.container_layouts import position_changes
        layouts = position_changes(backend.native_lobby_profile(local_session)['props'], moves)
        if layouts:
            fields['deposit_change']['pos_changes'] = layouts
        if any(command.get('target_pos') == 109 for command in commands):
            box = next(row for row in backend.native_lobby_profile(local_session)['props']
                       if row['grid_page_id'] == 109)
            fields['deposit_change'].setdefault('pos_changes', []).append(
                safe_boxes.position_change(box['template_id']))
        if any(command.get('target_pos') == 116 for command in commands):
            from dfserver.inventory.native_keycards import position_change
            bag = next(row for row in backend.native_lobby_profile(local_session)['props']
                       if row['grid_page_id'] == 116)
            fields['deposit_change'].setdefault('pos_changes', []).append(
                position_change(bag['template_id']))
    response = codec.response(request, fields)
    return encode_data_frame((response,), key, direction='server_to_client',
                             opaque_flag=64, header_word4=header_word4,
                             header_word9=header_word9)


def _native_inventory_changes(moves):
    changes = []
    for move in moves:
        before, after = move['before'], move['after']
        row = after or before
        destination = _deposit_inventory_location(after) if after else {'pos': 0}
        source = _deposit_inventory_location(before) if before else {'pos': 0}
        # common_pb.lua 0, instructions 618-642: Modify=3, ModifyWithMove=4, Move=5.
        change_type = (2 if after is None else 1 if before is None
                       else 3 if source == destination
                       else 4 if before['quantity'] != after['quantity'] else 5)
        changes.append({'change_type': change_type, 'src': source, 'dest': destination,
            'delta': (after['quantity'] if after else 0) - (before['quantity'] if before else 0),
            'prop': {'id': row['template_id'], 'gid': row['gid'], 'num': row['quantity'],
                'position': row['grid_page_id'], 'length': row['length'], 'width': row['width'],
                **item_condition_fields(row['template_id'], components=row.get('components'), weapon=row.get('weapon'), health=row.get('health')),
                **({'expire_timestamp': row['expire_timestamp']} if 'expire_timestamp' in row else {}),
                **{name: row[name] for name in ('bind_type', 'bind_player') if name in row},
                'loc': _deposit_inventory_location(row)}})
    return {'prop_changes': changes}


def _candidate_local_bullet_summary(message):
    fields = _candidate_codec().decode(message[4:]).fields
    return [{name: int(command.get(name) or 0) for name in
             ('op_type', 'bullet_id', 'bullet_gid', 'bullet_op_num',
              'target_gun_rec_id', 'target_gun_rec_gid')}
            for command in fields.get('cmds', [])[:32]]


def _candidate_local_bullet_response(message, backend, local_session, key, *, header_word4, header_word9, diagnostic_entry=None):
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
        if diagnostic_entry is not None:
            diagnostic_entry['local_inventory_failure'] = {'code': error.code, 'detail': error.message}
        fields = {'result': inventory_error(error)}
    else:
        fields = {'result': 0, 'changes': _native_inventory_changes(moves)}
    response = codec.response(request, fields)
    return encode_data_frame((response,), key, direction='server_to_client',
                             opaque_flag=64, header_word4=header_word4, header_word9=header_word9)


def _candidate_local_body_container_response(message, backend, local_session, key, *,
                                             header_word4, header_word9, diagnostic_entry=None):
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
        if diagnostic_entry is not None:
            diagnostic_entry['local_inventory_failure'] = {'code': error.code, 'detail': error.message}
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
        fields = {'result': 0, 'guide_stage_id': list(LOCAL_PENDING_GUIDE_STAGES)}
    elif request.name == 'CSGuideSkipReq':
        fields = {'result': 0}
    else:
        raise ValueError('Not a guide stage request')
    response = codec.response(request, fields)
    return encode_data_frame((response,), key, direction='server_to_client',
                             opaque_flag=64, header_word4=header_word4,
                             header_word9=header_word9)


def _candidate_local_deposit_sort_response(message, backend, local_session, key,
                                           *, header_word4, header_word9, diagnostic_entry=None):
    """Return committed inventory changes and the native client's saved settings."""
    if len(message) < 5:
        raise ValueError('Truncated warehouse sorting package')
    codec = _candidate_codec()
    request = codec.decode(message[4:])
    if request.name not in ('CSDepositSortPositionReq', 'CSDepositSortMultiplePosReq',
                            'CSDepositSetSortConfigReq', 'CSDepositSetCommonConfigReq'):
        raise ValueError('Not a warehouse sorting request')
    if diagnostic_entry is not None:
        diagnostic_entry['local_warehouse_sort_request'] = request.fields
    try:
        if request.name in ('CSDepositSortPositionReq', 'CSDepositSortMultiplePosReq'):
            positions = ([int(request.fields.get('pos_id', 0))]
                         if request.name == 'CSDepositSortPositionReq' else request.fields.get('pos_id', []))
            moves = backend.native_lobby_sort_positions(
                local_session, positions, request.fields.get('spec_extension_first_class'))
            fields = {'result': 0, 'changes': _native_inventory_changes(moves)}
            if request.name == 'CSDepositSortPositionReq':
                fields['pos_id'] = positions[0]
            if diagnostic_entry is not None:
                diagnostic_entry['local_warehouse_sort_change_count'] = len(moves)
        else:
            extension_order = (request.fields.get('extension_pos_order', [])
                               if request.name == 'CSDepositSetCommonConfigReq' else None)
            config = backend.set_native_lobby_sort_config(
                local_session, request.fields.get('sort_config', {}), extension_order)
            fields = {'result': 0, 'cur_sort_config': config}
            if extension_order is not None:
                fields['extension_pos_order'] = extension_order
    except DomainError as error:
        fields = {'result': inventory_error(error)}
        if diagnostic_entry is not None:
            diagnostic_entry['local_inventory_failure'] = {'code': error.code, 'message': error.message}
    if diagnostic_entry is not None:
        diagnostic_entry['local_warehouse_sort_result'] = fields['result']
    response = codec.response(request, fields)
    return encode_data_frame((response,), key, direction='server_to_client',
                             opaque_flag=64, header_word4=header_word4,
                             header_word9=header_word9)


def _candidate_local_activity_response(message, backend, local_session, key,
                                       *, header_word4, header_word9, diagnostic_entry=None):
    """Apply source-bound production and quest operations for this local account."""
    if len(message) < 5:
        raise ValueError('Truncated activity package')
    codec = _candidate_codec()
    request = codec.decode(message[4:])
    module = (native_safehouse if request.name in native_safehouse.SUPPORTED_REQUESTS else
              native_quests if request.name in native_quests.SUPPORTED_REQUESTS else
              native_department_queries if request.name in native_department_queries.SUPPORTED_REQUESTS else None)
    if module is None:
        raise ValueError('Not a supported local activity request')
    committed = {}
    options = {'diagnostic': diagnostic_entry}
    if module is not native_department_queries:
        options['changes'] = committed
    fields = module.response_fields(request, backend, local_session, **options)
    if committed.get('action_exp_changes'):
        from dfserver.progression import native_action_progress
        native_id = backend.native_identity(local_session)['native_id']
        committed['action_exp_notifications'] = [native_action_progress.notification_fields(native_id, receipt)
                                                 for receipt in committed['action_exp_changes']]
    if diagnostic_entry is not None:
        diagnostic_entry['local_activity_request'] = {
            name: int(request.fields[name]) for name in ('device_id', 'formula_id', 'quest_id', 'remove_quest_id')
            if name in request.fields}
        diagnostic_entry['local_activity_result'] = fields.get('result', fields.get('res'))
        if request.name == 'CSQuestSubmitPropReq':
            diagnostic_entry['local_activity_submit_summary'] = [
                {'obj_id': int(row.get('obj_id') or 0), 'props': [
                    {name: int(prop.get(name) or 0) for name in ('id', 'gid', 'num', 'position')}
                    for prop in row.get('submit_props', [])[:64]]}
                for row in request.fields.get('submit_list', [])[:64]]
        if committed.get('inventory_moves'):
            diagnostic_entry['local_activity_inventory_changes'] = [
                {'gid': (row.get('after') or row['before'])['gid'],
                 'template_id': (row.get('after') or row['before'])['template_id'],
                 'before_num': (row.get('before') or {}).get('quantity', 0),
                 'after_num': (row.get('after') or {}).get('quantity', 0)}
                for row in committed['inventory_moves'][:128]]
        if committed.get('currency_changes'):
            diagnostic_entry['local_activity_currency_changes'] = committed['currency_changes']
        if 'accepted_quests' in fields:
            diagnostic_entry['local_activity_accepted_quest_count'] = len(fields['accepted_quests'])
        if committed.get('quest_completion_override_count'):
            diagnostic_entry['local_activity_completion_override_count'] = committed['quest_completion_override_count']
        if committed.get('department_scores'):
            diagnostic_entry['local_activity_department_scores'] = committed['department_scores']
        if committed.get('quality_changes'):
            diagnostic_entry['local_activity_quality_changes'] = committed['quality_changes']
        if committed.get('action_exp_changes'):
            diagnostic_entry['local_activity_action_exp_changes'] = committed['action_exp_changes']
        if 'rep_level_configs' in fields:
            diagnostic_entry['local_department_max_level'] = len(fields['rep_level_configs'])
        if 'all_quality' in fields:
            diagnostic_entry['local_department_cards'] = fields['all_quality']
        diagnostic_entry['_local_activity_changes'] = committed
    response = codec.response(request, fields)
    return encode_data_frame((response,), key, direction='server_to_client',
                             opaque_flag=64, header_word4=header_word4,
                             header_word9=header_word9, max_output=1024 * 1024)


def _candidate_local_auxiliary_response(message, backend, local_session, key,
                                       *, header_word4, header_word9, diagnostic_entry=None):
    if len(message) < 5:
        raise ValueError('Truncated auxiliary package')
    codec = _candidate_codec()
    request = codec.decode(message[4:])
    if native_session_auxiliary.handle_one_way(
            request, backend, local_session, diagnostic_entry=diagnostic_entry):
        return None
    fields = native_session_auxiliary.response_fields(request, backend, local_session)
    if fields is None:
        fields = native_match_unavailable.response_fields(request, backend, local_session)
    if fields is None:
        fields = native_season.response_fields(request, backend, local_session)
    if fields is None:
        raise ValueError('Not a supported local auxiliary request')
    if diagnostic_entry is not None:
        diagnostic_entry['local_auxiliary_response_expected'] = True
        diagnostic_entry['local_auxiliary_result'] = fields['result']
        if request.name in native_season.SUPPORTED_REQUESTS:
            diagnostic_entry['local_season_request'] = {
                name: request.fields.get(name, 0) for name in ('mode', 'serial')}
            if fields['result'] == 0:
                diagnostic_entry['local_season_serial'] = fields['cur_serial']
    return encode_data_frame((codec.response(request, fields),), key, direction='server_to_client',
                             opaque_flag=64, header_word4=header_word4, header_word9=header_word9)


def _candidate_local_safehouse_response(message, backend, local_session, key,
                                        *, header_word4, header_word9):
    return _candidate_local_activity_response(message, backend, local_session, key,
        header_word4=header_word4, header_word9=header_word9)


def _candidate_local_wallet_quest_changes(response, key, backend, local_session, entry, request_name):
    """Catch up derived wallet goals after a successful non-quest transaction."""
    supported = (LOCAL_COMMERCE_REQUESTS | premium_shop.SUPPORTED_REQUESTS |
                 native_safehouse.SUPPORTED_REQUESTS | {'CSGetCurrencyReq'})
    if backend is None or not local_session or request_name not in supported:
        return
    try:
        callback = _candidate_codec().decode(decode_data_frame(response, key,
            direction='server_to_client', compression_method=1, max_output=1024 * 1024).messages[0])
    except (DomainError, ValueError, IndexError) as error:
        entry['local_wallet_quest_error'] = {'code': type(error).__name__,
            'message': 'Committed response could not be inspected for wallet goal refresh'}
        return
    if int(callback.fields.get('result', callback.fields.get('res', 1))) != 0:
        return
    from dfserver.progression.native_quest_wallet import refresh_committed
    from dfserver.progression.native_quest_conditions import merge_notifications
    notification = refresh_committed(backend, local_session, diagnostic=entry)
    if notification:
        committed = entry.setdefault('_local_activity_changes', {})
        committed['quest_notification'] = merge_notifications(committed.get('quest_notification'), notification)
        entry['local_wallet_quest_refresh_count'] = len(notification['player_quests'])


def _candidate_local_activity_response_frames(response, key, entry, *, backend=None, local_session=None):
    committed = entry.pop('_local_activity_changes', {})
    if not committed:
        return (response,)
    callback = _candidate_codec().decode(decode_data_frame(response, key,
        direction='server_to_client', compression_method=1, max_output=1024 * 1024).messages[0])
    if int(callback.fields.get('result', callback.fields.get('res', 1))) != 0:
        return (response,)
    messages = []
    deposit = _native_inventory_changes(committed.get('inventory_moves', []))
    deposit.update(committed.get('extension_deposit_change', {}))
    deposit.update(committed.get('warehouse_change', {}))
    if committed.get('currency_changes'):
        deposit['currency_changes'] = committed['currency_changes']
    if any(deposit.values()):
        messages.append(('CSDepositChangeNtf', _candidate_inventory_notice_fields(deposit,
            backend=backend, local_session=local_session,
            extension_pos_order=committed.get('extension_pos_order'))))
    collection = committed.get('prop_changes', [])
    if collection:
        messages.append(('CSCollectionPropChangeNtf', {'data_change': [
            {'change_type': row['change_type'], 'prop': row['prop'],
             'delta_num': row['delta'], 'after_num': row['prop']['num']}
            for row in collection]}))
    for notification in committed.get('action_exp_notifications', []):
        messages.append(('CSAccountExpChangeNtf', notification))
    if committed.get('quality_changes'):
        messages.append(('CSAttrQualityValueChangeNtf', {'change_list': committed['quality_changes']}))
    if committed.get('hero_notification'):
        messages.append(('CSHeroUnlockNtf', committed['hero_notification']))
    if committed.get('quest_notification'):
        messages.append(('CSQuestDataChangeNtf', committed['quest_notification']))
    frames = []
    for name, fields in messages:
        body = _candidate_codec().encode(name, fields, sequence=0)
        frames.append(encode_data_frame((body,), key, direction='server_to_client', opaque_flag=64,
            header_word4=response.header_word4, header_word9=response.header_word9 + len(frames),
            max_output=1024 * 1024))
    if frames:
        response = replace(response, header_word9=response.header_word9 + len(frames))
    return (*frames, response)


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
                                 outbound_sequence, result, continuation_seconds=360,
                                 *, game_server_probe=None, progress_callback=None):
    """Continue authenticated followups with the complete lobby dispatcher."""
    return _continue_local_lobby(
        connection, decoder, queue, current, ack,
        expected_identity, backend, local_session,
        outbound_sequence, result, continuation_seconds,
        game_server_probe=game_server_probe, progress_callback=progress_callback,
        records_key='registration_continuation', stop_key='registration_stop')


def _continue_local_lobby(connection, decoder, queue, current, ack,
                          expected_identity, backend, local_session,
                          outbound_sequence, result, continuation_seconds=360,
                          *, game_server_probe=None, progress_callback=None,
                          records_key='bounded_business_continuation',
                          stop_key='bounded_business_stop'):
    """Use the same lobby, inventory, and match flow after login or reconnect."""
    result[records_key] = []
    continuation_began = time.monotonic()
    continuation_deadline = time.monotonic() + continuation_seconds
    local_match_mode_info = None
    local_match_prepare_sent = False
    local_match_prepared_room_id = None
    local_match_join_sent = False
    quest_progress_loaded = False
    warehouse_projection = None
    local_match_handoff = None
    local_match_handoff_failed = False
    for _ in range(8192):
        if time.monotonic() >= continuation_deadline:
            result[stop_key] = 'continuation_deadline'
            break
        if current.command == 0x9001:
            outbound_sequence += 1
            connection.sendall(_transport_ping_reply(
                current, header_word9=outbound_sequence).encode())
            result[records_key].append(
                {'transport_command': '0x9001',
                 'wire_bytes': current.wire_size,
                 'reply_sent': True})
            try:
                current = _receive_one(connection, decoder, queue)
            except (TimeoutError, socket.timeout):
                result[stop_key] = 'receive_timeout_after_transport_heartbeat'
                break
            if current is None:
                result[stop_key] = 'client_closed_after_transport_heartbeat'
                break
            continue
        if current.command != 0x4013:
            result[stop_key] = 'non_data_command'
            result['bounded_business_non_data_command'] = f'0x{current.command:04x}'
            break
        current_data = decode_data_frame(
            current, ack.session_key,
            direction='client_to_server', compression_method=1)
        if len(current_data.messages) != 1:
            result[stop_key] = 'merged_messages'
            break
        message = current_data.messages[0]
        shape = summarize_prefixed_envelope(message)
        name = shape.get('message_name')
        entry = {'request_name': name,
                 'service': shape.get('service'),
                 'prefix_sequence': shape.get('prefix_word_be'),
                 'wire_bytes': current.wire_size,
                 'elapsed_ms': round((time.monotonic() - continuation_began) * 1000)}
        result[records_key].append(entry)
        _log_request_progress(entry, 'received')
        if name and name.startswith('CS') and name.endswith('Ntf'):
            entry['notification_observed'] = True
            try:
                current = _receive_one(connection, decoder, queue)
            except (TimeoutError, socket.timeout):
                result[stop_key] = 'receive_timeout_after_notification'
                break
            if current is None:
                result[stop_key] = 'client_closed_after_notification'
                break
            continue
        room_hero_notice = None
        if name in ('CSStateQuitMatchReq', 'CSRoomQuitTReq'):
            _candidate_cancel_local_match_allocation(game_server_probe, local_match_handoff,
                backend, local_session, local_match_mode_info)
            local_match_mode_info = None
            local_match_prepare_sent = False
            local_match_prepared_room_id = None
            local_match_join_sent = False
            local_match_handoff = None
            local_match_handoff_failed = False
            entry['local_match_allocation_cancelled'] = True
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
                    result['character_registration_observed'] = game_profile['game_registered']
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
                entry['local_customization_request'] = _candidate_local_customization_summary(message)
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
            elif name in ('CSDepositGetPropsReq', 'CSDepositGetExtensionPropsReq'):
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
                    header_word9=outbound_sequence,
                    diagnostic_entry=entry)
                entry['local_equip_response'] = True
                entry['local_commerce_result'] = _candidate_local_commerce_result(
                    next_response, ack.session_key)
            elif name == 'CSDepositAssemblySyncBodyContainerReq':
                entry['local_body_container_snapshots'] = _candidate_local_body_container_summary(message)
                next_response = _candidate_local_body_container_response(
                    message, backend, local_session, ack.session_key,
                    header_word4=current.header_word4,
                    header_word9=outbound_sequence,
                    diagnostic_entry=entry)
                entry['local_body_container_response'] = True
                entry['local_commerce_result'] = _candidate_local_commerce_result(
                    next_response, ack.session_key)
            elif name in native_warehouse_extensions.SUPPORTED_REQUESTS:
                next_response = _candidate_local_extension_response(
                    message, backend, local_session, ack.session_key,
                    header_word4=current.header_word4, header_word9=outbound_sequence,
                    diagnostic_entry=entry)
                entry['local_commerce_result'] = _candidate_local_commerce_result(
                    next_response, ack.session_key)
            elif name == 'CSDepositOperateBulletReq':
                entry['local_bullet_commands'] = _candidate_local_bullet_summary(message)
                next_response = _candidate_local_bullet_response(
                    message, backend, local_session, ack.session_key,
                    header_word4=current.header_word4,
                    header_word9=outbound_sequence,
                    diagnostic_entry=entry)
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
                          'CSDepositSetSortConfigReq', 'CSDepositSetCommonConfigReq'):
                next_response = _candidate_local_deposit_sort_response(
                    message, backend, local_session,
                    ack.session_key,
                    header_word4=current.header_word4,
                    header_word9=outbound_sequence, diagnostic_entry=entry)
                entry['local_warehouse_sort_response'] = True
            elif name in ACTIVITY_REQUESTS:
                next_response = _candidate_local_activity_response(
                    message, backend, local_session,
                    ack.session_key,
                    header_word4=current.header_word4,
                    header_word9=outbound_sequence, diagnostic_entry=entry)
                entry['local_activity_response'] = True
            elif name == 'CSSafehouseGetConfigReq':
                next_response = _candidate_local_safehouse_config_response(
                    message, ack.session_key,
                    header_word4=current.header_word4,
                    header_word9=outbound_sequence)
                entry['local_safehouse_config_response'] = True
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
                map_observation = {}
                next_response = _candidate_local_prepare_map_response(
                    message, backend, local_session, ack.session_key,
                    header_word4=current.header_word4,
                    header_word9=outbound_sequence,
                    observation=map_observation)
                entry['local_prepare_board_response'] = True
                entry['local_prepare_board_fields'] = map_observation['response_fields']
                if name == 'CSPrepareMapBoardReq' and progress_callback:
                    progress_callback(latest_map_board=map_observation)
            elif name == 'CSRoomGetMatchModeListReq':
                next_response = _candidate_local_room_mode_response(
                    message, ack.session_key,
                    header_word4=current.header_word4,
                    header_word9=outbound_sequence)
                entry['local_room_mode_response'] = True
            elif (name == 'CSMatchGateIsRankEnableReq'
                  and game_server_probe is not None and game_server_probe.listening):
                next_response = _candidate_local_match_rank_response(
                    message, ack.session_key,
                    header_word4=current.header_word4,
                    header_word9=outbound_sequence)
                entry['local_match_rank_response'] = True
            elif name == 'CSMatchRoomGetSolRoomTeamTReq':
                room_request = _candidate_codec().decode(message[4:])
                entry['local_solo_room_requested_id'] = int(
                    room_request.fields.get('room_id') or 0)
                next_response = _candidate_local_solo_room_team_response(
                    message, backend, local_session,
                    local_match_mode_info, ack.session_key,
                    header_word4=current.header_word4,
                    header_word9=outbound_sequence)
                entry['local_solo_room_team_response'] = True
            elif name == 'CSMatchRoomSolReadyTReq':
                ready_request = _candidate_codec().decode(message[4:])
                entry['local_solo_room_requested_id'] = int(
                    ready_request.fields.get('room_id') or 0)
                next_response, room_hero_notice = _candidate_local_solo_room_ready_response(
                    message, backend, local_session,
                    local_match_mode_info, ack.session_key,
                    header_word4=current.header_word4,
                    header_word9=outbound_sequence)
                entry['local_solo_room_ready_response'] = True
            elif name in ('CSMatchRoomSetPreSelectedHeroTReq',
                          'CSMatchRoomSetSolRoomHeroTReq',
                          'CSMatchRoomLockSelectedHeroTReq'):
                hero_request = _candidate_codec().decode(message[4:])
                entry['local_solo_room_requested_id'] = int(
                    hero_request.fields.get('room_id') or 0)
                entry['local_solo_room_requested_hero_id'] = int(
                    hero_request.fields.get('hero_id') or
                    hero_request.fields.get('pre_selected_hero_id') or 0)
                next_response, room_hero_notice = _candidate_local_solo_room_hero_response(
                    message, backend, local_session,
                    local_match_mode_info, ack.session_key,
                    header_word4=current.header_word4,
                    header_word9=outbound_sequence)
                entry['local_solo_room_hero_response'] = True
            elif (name in native_match_unavailable.SUPPORTED_REQUESTS
                  and (game_server_probe is None or not game_server_probe.listening)):
                next_response = _candidate_local_auxiliary_response(
                    message, backend, local_session, ack.session_key,
                    header_word4=current.header_word4,
                    header_word9=outbound_sequence, diagnostic_entry=entry)
            elif name == 'CSMatchRoomCheckCallNumeralReq':
                recovery_request = _candidate_codec().decode(message[4:])
                entry['local_match_recovery_request'] = {
                    name: recovery_request.fields.get(name, 0) for name in
                    ('game_mode', 'match_mode_id', 'reason')}
                next_response, local_match_handoff, recovered = (
                    _candidate_local_match_call_numeral_response(
                        message, backend, local_session, local_match_mode_info,
                        game_server_probe, ack.session_key,
                        prepared=local_match_prepare_sent and not local_match_handoff_failed,
                        handoff=local_match_handoff,
                        prepared_room_id=local_match_prepared_room_id,
                        header_word4=current.header_word4, header_word9=outbound_sequence,
                        diagnostic_entry=entry))
                if entry.get('local_match_recovery_preflight_failed'):
                    local_match_handoff_failed = True
                entry['local_match_recovery_response'] = True
                entry['local_match_recovery_bound_handoff'] = recovered
                entry['local_match_recovery_result'] = 0 if recovered else 1
                if recovered:
                    local_match_join_sent = True
            elif name in ('CSRoomMatchStartAllocReq',
                          'CSRoomMatchQuitAllocReq',
                          'CSMatchCheckTReq',
                          'CSMatchRoomStartMatchTglogTReq'):
                if name == 'CSRoomMatchStartAllocReq':
                    start_request = _candidate_codec().decode(message[4:])
                    mode_infos = start_request.fields.get('mode_infos') or []
                    if _candidate_local_allocation_modes_valid(mode_infos, game_server_probe):
                        replace_solo = getattr(game_server_probe, 'cancel_player_solo_match_allocations', None)
                        if callable(replace_solo) and backend is not None and local_session is not None:
                            player = int(backend.native_identity(local_session)['native_id'])
                            cancelled = bool(replace_solo(player))
                        else:
                            cancelled = _candidate_cancel_local_match_allocation(
                                game_server_probe, local_match_handoff, backend, local_session,
                                local_match_mode_info)
                        if cancelled:
                            entry['local_match_allocation_cancelled'] = True
                        local_match_mode_info = mode_infos[0]
                        local_match_prepare_sent = False
                        local_match_prepared_room_id = None
                        local_match_join_sent = False
                        local_match_handoff = None
                        local_match_handoff_failed = False
                        entry['local_match_mode_info'] = {
                            field: int(local_match_mode_info.get(field) or 0)
                            for field in ('game_mode', 'game_rule', 'sub_mode',
                                          'team_mode', 'map_id', 'match_mode_id')}
                elif name == 'CSRoomMatchQuitAllocReq':
                    _candidate_cancel_local_match_allocation(game_server_probe, local_match_handoff,
                        backend, local_session, local_match_mode_info)
                    local_match_mode_info = None
                    local_match_prepare_sent = False
                    local_match_prepared_room_id = None
                    local_match_join_sent = False
                    local_match_handoff = None
                    local_match_handoff_failed = False
                    entry['local_match_allocation_cancelled'] = True
                next_response = _candidate_local_match_alloc_response(
                    message, ack.session_key,
                    header_word4=current.header_word4,
                    header_word9=outbound_sequence,
                    game_server_probe=game_server_probe)
                entry['local_match_alloc_response'] = True
                entry['local_match_alloc_result'] = _candidate_local_commerce_result(
                    next_response, ack.session_key)
            elif name in LOCAL_COMMERCE_REQUESTS:
                if name in premium_shop.SUPPORTED_REQUESTS:
                    entry['local_premium_shop_request'] = _candidate_local_premium_shop_summary(message)
                if name.startswith('CSHero') or name in profile_cosmetics.SUPPORTED_REQUESTS:
                    entry['local_customization_request'] = _candidate_local_customization_summary(message)
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
                if name == 'CSWAssemblyDepositPropUpdateReq':
                    raw_assembly = _candidate_codec().decode(message[4:]).fields
                    entry['local_weapon_assembly_request'] = {
                        field: raw_assembly[field] for field in
                        ('prop', 'local_prop', 'unequip_pos', 'old_prop_id', 'bag_id',
                         'data_type', 'source', 'swapped_peer_gun') if field in raw_assembly}
                if name == 'CSMallSellReq':
                    entry['local_sell_items'] = _candidate_local_sell_summary(message)
                next_response = _candidate_local_commerce_response(
                    message, backend, local_session,
                    ack.session_key,
                    header_word4=current.header_word4,
                    header_word9=outbound_sequence,
                    diagnostic_entry=entry)
                entry['local_commerce_response'] = True
                entry['local_commerce_result'] = _candidate_local_commerce_result(
                    next_response, ack.session_key)
            elif name in (native_session_auxiliary.SUPPORTED_REQUESTS
                         | native_season.SUPPORTED_REQUESTS
                         | native_session_auxiliary.ONE_WAY_REQUESTS):
                next_response = _candidate_local_auxiliary_response(
                    message, backend, local_session, ack.session_key,
                    header_word4=current.header_word4,
                    header_word9=outbound_sequence, diagnostic_entry=entry)
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
                result[stop_key] = 'receive_timeout_after_unanswered_request'
                break
            if current is None:
                result[stop_key] = 'client_closed_after_unanswered_request'
                break
            continue
        if next_response is None:
            _log_request_progress(entry, 'processed')
            try:
                current = _receive_one(connection, decoder, queue)
            except (TimeoutError, socket.timeout):
                result[stop_key] = 'receive_timeout'
                break
            if current is None:
                result[stop_key] = 'client_closed'
                break
            continue
        if name == 'CSQuestGetPlayerDataReq' and entry.get('local_activity_result') == 0:
            quest_progress_loaded = True
        if backend is not None and local_session:
            if name == 'CSDepositGetPropsReq' or (name in native_warehouse_extensions.SUPPORTED_REQUESTS
                                                 and entry.get('local_commerce_result') == 0):
                warehouse_projection = _candidate_local_warehouse_response_projection(
                    next_response, ack.session_key, warehouse_projection)
            elif (warehouse_projection is not None and name in ACTIVITY_REQUESTS
                  and entry.get('local_activity_result') == 0):
                warehouse_projection = _candidate_local_warehouse_changes(
                    backend, local_session, warehouse_projection, entry)
        if quest_progress_loaded:
            _candidate_local_wallet_quest_changes(next_response, ack.session_key,
                backend, local_session, entry, name)
        frames = _candidate_local_activity_response_frames(
            next_response, ack.session_key, entry, backend=backend, local_session=local_session)
        for activity_change in frames[:-1]:
            connection.sendall(activity_change.encode())
            entry['local_activity_notification_sent'] = True
        next_response = frames[-1]
        outbound_sequence = next_response.header_word9
        if name in COLLECTION_REQUESTS:
            frames = _candidate_local_collection_response_frames(
                next_response, ack.session_key, backend, local_session)
            for collection_change in frames[:-1]:
                connection.sendall(collection_change.encode())
                entry['local_collection_change_notification_sent'] = True
            next_response = frames[-1]
            outbound_sequence = next_response.header_word9
        connection.sendall(next_response.encode())
        entry['response_sent'] = True
        entry['response_elapsed_ms'] = round(
            (time.monotonic() - continuation_began) * 1000)
        entry['response_header_word9'] = next_response.header_word9
        if entry.get('local_match_recovery_bound_handoff'):
            entry['local_match_recovery_handoff_sent'] = True
            if progress_callback:
                progress_callback(latest_match_handoff={
                    'trigger_request': name,
                    'observed_at_utc': datetime.now(timezone.utc).isoformat(),
                    'map_id': int(local_match_mode_info['map_id']),
                    'match_mode_id': int(local_match_mode_info['match_mode_id']),
                    'endpoint': '127.0.0.1', 'port': game_server_probe.port,
                    'gameplay_implemented': False})
        if (name in ('CSMatchRoomSetPreSelectedHeroTReq',
                     'CSMatchRoomSetSolRoomHeroTReq',
                     'CSMatchRoomLockSelectedHeroTReq',
                     'CSMatchRoomSolReadyTReq')
                and (entry.get('local_solo_room_hero_response') or
                     entry.get('local_solo_room_ready_response'))
                and room_hero_notice is not None):
            outbound_sequence += 1
            connection.sendall(room_hero_notice.encode())
            entry['local_solo_room_hero_notice_sent'] = True
            if (((name == 'CSMatchRoomSolReadyTReq'
                  and os.environ.get('DF_LOCAL_DS_JOIN_PROBE_AFTER_READY') == '1')
                 or (name == 'CSMatchRoomLockSelectedHeroTReq'
                     and os.environ.get('DF_LOCAL_DS_JOIN_PROBE_AFTER_HERO_LOCK') == '1'))
                    and local_match_prepare_sent
                    and not local_match_handoff_failed
                    and not local_match_join_sent
                    and local_match_mode_info
                    and game_server_probe is not None
                    and game_server_probe.listening
                    and _candidate_local_match_profile_ready(game_server_probe, local_match_mode_info)):
                handoff_began = time.perf_counter()
                try:
                    if local_match_handoff is None:
                        local_match_handoff, outbound_sequence = _wait_match_handoff(
                            lambda: _candidate_local_match_join_handoff(
                                backend, local_session, local_match_mode_info, game_server_probe),
                            lambda handoff: _candidate_cancel_local_match_allocation(
                                game_server_probe, handoff, backend, local_session, local_match_mode_info),
                            connection, decoder, queue, ack.session_key, outbound_sequence, entry)
                    active = getattr(game_server_probe, 'match_admission_ticket_active', None)
                    if (local_match_handoff.ticket is not None and callable(active) and
                            not active(local_match_handoff.ticket)):
                        entry['local_match_handoff_inactive'] = True
                        raise ValueError('The original Ready handoff is no longer active')
                    outbound_sequence += 1
                    join = _candidate_local_match_join_frame(local_match_handoff, ack.session_key,
                        header_word4=current.header_word4, header_word9=outbound_sequence)
                except (ValueError, DomainError) as error:
                    local_match_handoff_failed = True
                    _candidate_match_preflight_failure(entry, error)
                except OSError:
                    raise
                except Exception as error:
                    # An internal defect must be reported as a failed handoff,
                    # not escape and silently drop the lobby connection.
                    local_match_handoff_failed = True
                    _candidate_match_preflight_failure(entry, error)
                    entry['local_match_handoff_internal_error'] = type(error).__name__
                else:
                    connection.sendall(join.encode())
                    local_match_join_sent = True
                    entry['local_game_server_join_probe_sent'] = True
                    entry['local_match_join_elapsed_ms'] = round(
                        (time.monotonic() - continuation_began) * 1000)
                finally:
                    entry['local_match_handoff_elapsed_ms'] = round(
                        (time.perf_counter() - handoff_began) * 1000)
                if local_match_join_sent and progress_callback:
                    progress_callback(latest_match_handoff={
                        'trigger_request': name,
                        'observed_at_utc': datetime.now(timezone.utc).isoformat(),
                        'map_id': int(local_match_mode_info['map_id']),
                        'match_mode_id': int(local_match_mode_info['match_mode_id']),
                        'endpoint': '127.0.0.1',
                        'port': game_server_probe.port,
                        'gameplay_implemented': False})
        if (name == 'CSMatchCheckTReq' and not local_match_prepare_sent
                and local_match_mode_info and backend and local_session
                and game_server_probe is not None
                and game_server_probe.listening
                and _candidate_valid_world_map_row(local_match_mode_info)):
            if not _candidate_local_match_profile_ready(game_server_probe, local_match_mode_info):
                entry['local_match_waiting_for_initial_actor_profile'] = True
            else:
                outbound_sequence += 1
                prepare = _candidate_local_match_prepare_probe(
                    backend, local_session, local_match_mode_info,
                    ack.session_key,
                    header_word4=current.header_word4,
                    header_word9=outbound_sequence, game_server_probe=game_server_probe)
                connection.sendall(prepare.encode())
                prepared_message = decode_data_frame(prepare, ack.session_key,
                    direction='server_to_client', compression_method=1).messages[0]
                local_match_prepared_room_id = _local_match_request_unsigned(
                    _candidate_codec().decode(prepared_message).fields['ds_room_id'], 64)
                local_match_prepare_sent = True
                entry['local_match_prepare_probe_sent'] = True
                if (os.environ.get('DF_LOCAL_DS_CALL_NUMERAL_NOTICE_PROBE') == '1' and
                        os.environ.get('DF_LOCAL_DS_JOIN_PROBE_AFTER_READY') == '1' and
                        getattr(game_server_probe, 'match_admission_enabled', False) is True and
                        callable(getattr(game_server_probe, 'match_admission_ticket_active', None))):
                    # A failed preflight remains failed for this allocation; a
                    # later query must not silently issue a replacement ticket.
                    try:
                        player_id, mode_id, _ = _candidate_local_match_join_parameters(
                            backend, local_session, local_match_mode_info, game_server_probe)
                        if player_id != local_match_prepared_room_id:
                            raise ValueError('The prepared room identity changed')
                        # This notice carries no cookie. Freeze selected_hero_id
                        # only at the first Ready or legitimate recovery query.
                        notice = _candidate_local_match_call_numeral_notice(player_id, mode_id,
                            ack.session_key, header_word4=current.header_word4,
                            header_word9=outbound_sequence + 1)
                    except (ValueError, DomainError):
                        local_match_handoff_failed = True
                        entry['local_match_recovery_preflight_failed'] = True
                    else:
                        outbound_sequence += 1
                        connection.sendall(notice.encode())
                        entry['local_match_call_numeral_notice_sent'] = True
        for notification in _candidate_local_battle_pass_notifications(
                entry, ack.session_key, header_word4=current.header_word4,
                header_word9=outbound_sequence, backend=backend, local_session=local_session):
            connection.sendall(notification.encode())
            outbound_sequence = notification.header_word9
        if (name in ('CSShopBuyLotteryItemReq',
                     'CSLotteryBlindBoxDrawReq',
                     'CSShopBuyHotRecommendationReq',
                     'CSShopBuyMallGiftReq',
                     'CSShopOpenLotteryItemReq',
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
                header_word9=outbound_sequence, backend=backend, local_session=local_session)
            if inventory_change is not None:
                connection.sendall(inventory_change.encode())
                entry['local_inventory_change_notification_sent'] = True
        _log_request_progress(entry, 'processed')
        try:
            current = _receive_one(connection, decoder, queue)
        except (TimeoutError, socket.timeout):
            result[stop_key] = 'receive_timeout'
            break
        if current is None:
            result[stop_key] = 'client_closed'
            break
    else:
        result[stop_key] = 'response_limit'


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
        # These are pending stages, not completion records. Returning all stage
        # IDs keeps the client in its new-player path despite skip_all=True.
        fields.update({'guide_stage_id': list(LOCAL_PENDING_GUIDE_STAGES),
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
        # Active event rows and prices are still server supplied. The verified
        # response schema can encode this existing empty bootstrap directly.
        response = codec.response(request, {'result': 0})
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
                     backend=None, local_session=None, continuation_seconds=360,
                     game_server_probe=None, progress_callback=None):
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
                                    outbound_sequence, result, continuation_seconds,
                                    game_server_probe=game_server_probe,
                                    progress_callback=progress_callback)
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
                                                    outbound_sequence, result, continuation_seconds,
                                                    game_server_probe=game_server_probe,
                                                    progress_callback=progress_callback)
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
                                                            _continue_local_lobby(
                                                                connection, decoder, queue, fifth, ack,
                                                                expected_identity, backend, local_session,
                                                                outbound_sequence, result, continuation_seconds,
                                                                game_server_probe=game_server_probe,
                                                                progress_callback=progress_callback)
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
                 continuation_seconds=360, game_server_probe=None):
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
        self.game_server_probe = game_server_probe
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
                                  continuation_seconds=self.server.continuation_seconds,
                                  game_server_probe=self.server.game_server_probe,
                                  progress_callback=self.server.state.update)
        self.server.state.record(result)
        print(json.dumps(result), flush=True)


def main():
    root = SERVER_ROOT
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
