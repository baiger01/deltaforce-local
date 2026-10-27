"""A source-sealed ordinary property terminator on the existing GameState.

This is an opt-in server message in the initial-association trial. It sets no
gameplay property, calls no native method and does not claim Ready or possession.
The native derived dispatch and command-count preconditions remain observable
runtime requirements; transport ACK alone cannot establish them.
"""
import hashlib
import json
from pathlib import Path, PurePosixPath
import re
import sys

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / 'outputs/df-local-server'))
from dfserver.legacy_ds_actor_manifest import ActorManifest, CLIENT_SHA256
from dfserver.legacy_ds_rep_layout_refs import build_empty_rep_layout_content

SPEC_PATH = 'work/evidence/map-entry-next-20261005/ordinary-rep-layout-empty-stream-spec.json'
SPEC_SHA256 = '66a5b1bb1a2fb636ab103ef0e71cab3c7111a20a2dff76c570fbae7135956774'
GAME_STATE_CLASS = '/Game/BluePrints/GameModes/TestGame/BP_GameState_PVPVE.BP_GameState_PVPVE_C'
MAX_SOURCE_BYTES = 32 * 1024 * 1024
MAX_TOTAL_BYTES = 96 * 1024 * 1024


def _read(root, relative, expected=None):
    if (type(relative) is not str or not relative or ':' in relative or '\\' in relative
            or PurePosixPath(relative).is_absolute()
            or any(part in ('', '.', '..') for part in relative.split('/'))):
        raise ValueError('GameState evidence requires a plain project-relative path')
    path = (root / relative).resolve()
    if not path.is_relative_to(root) or not path.is_file():
        raise ValueError('GameState evidence is missing or outside the project')
    if path.stat().st_size > MAX_SOURCE_BYTES:
        raise ValueError('GameState evidence exceeds the local byte bound')
    raw = path.read_bytes()
    digest = hashlib.sha256(raw).hexdigest()
    if expected is not None and (type(expected) is not str
            or re.fullmatch('[0-9a-f]{64}', expected) is None or digest != expected):
        raise ValueError('GameState source SHA256 mismatch')
    return raw, digest


def qualified_game_state_initialization_source_pins(root):
    root = Path(root).resolve()
    raw, digest = _read(root, SPEC_PATH, SPEC_SHA256)
    spec = json.loads(raw)
    grammar = spec.get('ordinary_grammar', {})
    if (spec.get('kind') != 'ordinary_replayout_empty_terminator_consumer_inverse_spec'
            or spec.get('client_sha256') != CLIENT_SHA256
            or spec.get('qualifications', {}).get('consumer_inverse_confirmed') is not True
            or any(grammar.get(key) is not value for key, value in (
                ('lsb_first', True), ('byte_alignment', False), ('has_rep_layout', True),
                ('actor_selector', True), ('internal_ack', False),
                ('leading_checksum_option', False), ('property_values_present', False),
                ('rpc_classnetcache_field_envelope', False), ('requires_exact_payload_eof', True)))
            or grammar.get('first_packed_handle') != 0
            or grammar.get('payload_bit_count') != 9
            or grammar.get('canonical_payload_hex') != '0000'
            or grammar.get('actor_content_bit_count') != 19
            or grammar.get('actor_content_hex') != '4b0000'):
        raise ValueError('GameState empty-stream source does not qualify this client grammar')
    sources = spec.get('source_pins')
    if type(sources) is not dict or not 1 <= len(sources) <= 64:
        raise ValueError('GameState evidence source list exceeds the local bound')
    pins, total = {SPEC_PATH: digest}, len(raw)
    for relative, expected in sources.items():
        data, actual = _read(root, relative, expected)
        total += len(data)
        if total > MAX_TOTAL_BYTES:
            raise ValueError('GameState evidence set exceeds the local byte bound')
        pins[relative] = actual
    for relative in ('work/native_game_state_initialization.py',
                     'outputs/df-local-server/dfserver/legacy_ds_rep_layout_refs.py'):
        data, actual = _read(root, relative)
        total += len(data)
        if total > MAX_TOTAL_BYTES:
            raise ValueError('GameState evidence set exceeds the local byte bound')
        pins[relative] = actual
    if hashlib.sha256(Path(__file__).read_bytes()).hexdigest() != pins['work/native_game_state_initialization.py']:
        raise ValueError('Imported GameState helper differs from the qualified project')
    return pins


def build_initial_game_state_update(root, manifests, source_pins):
    root = Path(root).resolve()
    if qualified_game_state_initialization_source_pins(root) != source_pins:
        raise ValueError('GameState source identity changed before preparation')
    if (type(manifests) is not tuple or len(manifests) != 3
            or any(type(item) is not ActorManifest for item in manifests)
            or any(item.client_sha256 != CLIENT_SHA256 for item in manifests)
            or len({item.actor_guid for item in manifests}) != 3
            or len({item.channel_index for item in manifests}) != 3
            or len({item.level_path for item in manifests}) != 1
            or len({(item.connection_network_version, item.archive_network_version)
                    for item in manifests}) != 1):
        raise ValueError('GameState initialization requires one qualified three-Actor map profile')
    candidates = [item for item in manifests if item.class_path == GAME_STATE_CLASS]
    if len(candidates) != 1:
        raise ValueError('The qualified GameState class must have exactly one existing Actor')
    actor = candidates[0]
    if (type(actor.channel_index) is not int or actor.channel_index < 2
            or type(actor.actor_guid) is not int or not 2 <= actor.actor_guid <= 0xfffffffe
            or actor.actor_guid & 1):
        raise ValueError('GameState update requires an existing dynamic Actor channel')
    block = build_empty_rep_layout_content()
    if qualified_game_state_initialization_source_pins(root) != source_pins:
        raise ValueError('GameState source identity changed during preparation')
    plan = dict(channel_index=actor.channel_index, actor_guid=actor.actor_guid,
                content_blocks=(block,))
    summary = dict(kind='source_sealed_existing_game_state_property_terminator',
        source_relative_path=SPEC_PATH, source_sha256=SPEC_SHA256,
        class_path=actor.class_path, channel_index=actor.channel_index,
        actor_guid=actor.actor_guid, payload_bits=block.payload_bit_count,
        property_values_assigned=False, ordinary_connection_required=True,
        valid_command_range_and_no_counter_wrap_required=True,
        native_command_range_verified=False, native_derived_dispatch_verified=False,
        native_acceptance_verified=False, cache_initialization_verified=False,
        ready_verified=False, playable_map_verified=False)
    return plan, summary
