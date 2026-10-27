"""Qualify the exact existing GameState BeginPlay scalar and server transition."""
import hashlib
import json
from pathlib import Path, PurePosixPath

from dfserver.legacy_ds_actor_manifest import CLIENT_SHA256
from dfserver.legacy_ds_game_state_start import GameStateStartProfile

SPEC_PATH = 'work/evidence/map-entry-next-20261007/game-state-match-info-property-profile.json'
SPEC_SHA256 = 'fdf6ee167b7ca1bf60be2d4884bc94cd106b1d34400cd1495458ce3b19928ac8'
CLASS_PATH = '/Game/BluePrints/GameModes/TestGame/BP_GameState_PVPVE.BP_GameState_PVPVE_C'
MODULES = ('work/native_game_state_start_profile.py',
           'outputs/df-local-server/dfserver/legacy_ds_game_state_start.py',
           'outputs/df-local-server/dfserver/legacy_ds_scalar_serializers.py')


def qualify_outer_handle(commands, target):
    """Use the recorded RelativeHandle, with each array's own child scope.

    The pinned native builder assigns handles per scope. Its ordinary receiver
    skips a dynamic array's child command interval when walking the outer scope.
    Return commands terminate child scopes and have no outer wire handle.
    """
    if type(commands) is not list or not commands or len(commands) > 65535:
        raise ValueError('A bounded complete command prefix is required')
    counters = [0]
    for index, command in enumerate(commands):
        if type(command) is not dict or command.get('index') != index:
            raise ValueError('Command prefix indices changed')
        opcode, handle = command.get('dispatch_opcode'), command.get('relative_handle')
        if type(opcode) is not int or type(handle) is not int:
            raise ValueError('Native command fields are required')
        if opcode == 1:
            if len(counters) == 1 or handle != 0:
                raise ValueError('Unexpected return in the target command prefix')
            counters.pop()
            continue
        counters[-1] += 1
        if handle != counters[-1]:
            raise ValueError('Native relative handle does not match its command scope')
        if index == len(commands) - 1:
            if (len(counters) != 1 or command.get('descriptor_name') != target['name'] or
                    opcode != target.get('dispatch_opcode', 21) or handle != target['ordinary_handle'] or
                    index != target['command_index']):
                raise ValueError('Entry permission must be a scalar in the outer scope')
        if opcode == 0:
            counters.append(0)
    if len(counters) != 1:
        raise ValueError('Incomplete child command scope')
    return counters[0]


def qualified_game_state_start_sources(root):
    root = Path(root).resolve(strict=True)
    def read(relative):
        if (type(relative) is not str or ':' in relative or '\\' in relative or
                PurePosixPath(relative).is_absolute() or
                any(p in ('', '.', '..') for p in relative.split('/'))):
            raise ValueError('GameState BeginPlay evidence requires a project-relative path')
        p = (root / relative).resolve(strict=True)
        if not p.is_relative_to(root) or not p.is_file() or p.stat().st_size > 1024 * 1024:
            raise ValueError('GameState BeginPlay source is missing or outside its bound')
        raw = p.read_bytes()
        return raw, hashlib.sha256(raw).hexdigest()
    raw, digest = read(SPEC_PATH)
    if digest != SPEC_SHA256:
        raise ValueError('GameState BeginPlay source seal changed')
    spec = json.loads(raw)
    prop = spec['property'];prefix = spec['prefix_commands'];grammar = spec['ordinary_grammar']
    if (spec['kind'] != 'native_game_state_begin_play_property_profile' or
            spec['client_sha256'] != CLIENT_SHA256 or spec['class_path'] != CLASS_PATH or
            prop['name'] != 'bReplicatedHasBegunPlay' or
            not 1 <= spec['command_count'] < 65536 or
            prop['command_index'] + 1 != prop['ordinary_handle'] or
            len(prefix) != prop['command_index'] + 1 or
            any(c['index'] != i or c['dispatch_opcode'] == 0 for i, c in enumerate(prefix)) or
            prefix[-1]['descriptor_name'] != prop['name'] or
            prefix[-1]['dispatch_opcode'] != 21 or prop['dispatch_opcode'] != 21 or
            prop['value_bits'] != 1 or prop['serializer_target_rva'] != '0x10e8ebe0' or
            prop['serializer_identity_rechecked'] is not True or
            any(grammar[k] is not v for k, v in (
                ('checksum_option', False), ('internal_ack', False), ('has_rep_layout', True),
                ('actor_selector', True), ('byte_alignment', False), ('zero_terminal_handle', True)))):
        raise ValueError('GameState BeginPlay does not have the exact qualified ordinary scalar grammar')
    ready = spec['all_ready_property'];prefix = spec['all_ready_prefix_commands']
    if (ready['name'] != 'bStartMathWithAllPlayerReady' or
            ready['declared_rep_notify'] != 'OnRep_bStartMathWithAllPlayerReady' or
            ready['command_index'] + 1 != ready['ordinary_handle'] or
            len(prefix) != ready['command_index'] + 1 or
            any(c['index'] != i or c['dispatch_opcode'] == 0 for i, c in enumerate(prefix)) or
            prefix[-1]['descriptor_name'] != ready['name'] or prefix[-1]['dispatch_opcode'] != 21 or
            ready['serializer_target_rva'] != '0x10e8ebe0' or ready['value_bits'] != 1 or
            ready['serializer_identity_rechecked'] is not True):
        raise ValueError('All-player-ready requires its own qualified Boolean and RepNotify declaration')
    abseil = spec['abseil_property']
    if (abseil['name'] != 'bCanSwitchToAbseil' or
            abseil['declared_rep_notify'] != 'OnRep_CanSwitchToAbseil' or
            abseil['serializer_target_rva'] != '0x10e8ebe0' or abseil['value_bits'] != 1 or
            abseil['serializer_identity_rechecked'] is not True or
            qualify_outer_handle(spec['abseil_prefix_commands'], abseil) != abseil['ordinary_handle']):
        raise ValueError('Entry permission requires the recorded outer-scope Boolean handle')
    identities = spec['match_info_properties']
    if len(identities) != 2 or [p['name'] for p in identities] != ['MapID', 'RoomId']:
        raise ValueError('Both native MatchInfo identity fields are required')
    for identity in identities:
        prefix = spec['match_info_prefix_commands'][:identity['command_index'] + 1]
        if (identity['parent_name'] != 'MatchInfo' or identity['parent_index'] != 31 or
                identity['dispatch_opcode'] != 20 or identity['value_bits'] != 64 or
                identity['property_vtable_rva'] != '0x1ab60db0' or
                identity['serializer_target_rva'] != '0x10e5ce20' or
                identity['scalar_leaf_target_rva'] != '0x286c000' or
                identity['serializer_identity_rechecked'] is not True or
                qualify_outer_handle(prefix, identity) != identity['ordinary_handle']):
            raise ValueError('MatchInfo identity has no exact unsigned64 scalar qualification')
    pins = {SPEC_PATH: digest}
    for source in spec['sources']:
        _, actual = read(source['relative_path'])
        if actual != source['sha256']:
            raise ValueError('GameState BeginPlay supporting source changed')
        pins[source['relative_path']] = actual
    for relative in MODULES:
        _, pins[relative] = read(relative)
    if hashlib.sha256(Path(__file__).read_bytes()).hexdigest() != pins[MODULES[0]]:
        raise ValueError('GameState BeginPlay helper was imported from another checkout')
    return pins


def install_game_state_start_profile(root, probe, manifests, sealed_sources):
    pins = qualified_game_state_start_sources(root)
    if any(sealed_sources.get(k) != v for k, v in pins.items()):
        raise ValueError('GameState BeginPlay source changed after trial sealing')
    matches = [m for m in manifests if m.class_path == CLASS_PATH]
    if len(matches) != 1:
        raise ValueError('BeginPlay requires one source-qualified existing GameState Actor')
    spec = json.loads((Path(root) / SPEC_PATH).read_bytes())
    profile = GameStateStartProfile(CLASS_PATH, spec['property']['ordinary_handle'], CLIENT_SHA256, SPEC_SHA256,
                                    spec['all_ready_property']['ordinary_handle'],
                                    spec['abseil_property']['ordinary_handle'],
                                    spec['match_info_properties'][0]['ordinary_handle'],
                                    spec['match_info_properties'][1]['ordinary_handle'])
    probe.set_game_state_start_profile(2201, matches[0], profile)
    return {'status': 'explicit_game_state_start_profile_configured',
            'source_relative_path': SPEC_PATH, 'source_sha256': SPEC_SHA256,
            'property_name': spec['property']['name'], 'ordinary_handle': profile.begin_play_handle,
            'requires_active_ticket_join_and_ready_ack_delivery': True,
            'all_ready_property_name': spec['all_ready_property']['name'],
            'all_ready_ordinary_handle': profile.all_ready_handle,
            'all_ready_requires_actual_joined_room_participants': True,
            'abseil_property_name': spec['abseil_property']['name'],
            'abseil_ordinary_handle': profile.abseil_handle,
            'abseil_requires_room_ready_delivery': True,
            'match_info_identity_fields': ['MapID', 'RoomId'],
            'match_info_identity_before_begin_play': True,
            'all_player_ready_assigned': False, 'client_binding_verified': False,
            'native_begin_play_verified': False, 'playable_map_verified': False}
