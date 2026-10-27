"""Pure current-source qualification, separate from live receiver authorization.

Only supplied evidence bytes are checked. Research producers are not executed;
their sealed outputs are input data. The runtime owns fresh image/process/hook
verification and reference delivery receipts. No source-only profile activates
a sender or reuses a historical metadata record under a substituted build SHA.
"""
from dataclasses import dataclass, field
from enum import Enum
from functools import lru_cache
import hashlib
import json
from types import MappingProxyType

CURRENT_CLIENT_SHA256 = '79fb7b105170141ed863331d36833a73062e66bf5291b2364fe3a64c18336203'
CURRENT_ACTOR_PROFILE_PATH = 'work/evidence/updated-minimum-actor-profile-79fb7b10.json'
CURRENT_ACTOR_PROFILE_SHA256 = '64e5979c79b0876f62c6e03a9ad0407a88aaff3d7b9b81ed9961c920e4c2399a'
HEADER_PROOF_PATH = 'work/evidence/updated-enabled-actor-receiver-79fb7b10-v3.json'
HEADER_PROOF_SHA256 = '09ca979cf1edcb49540aa89b7a88a4d94c123b4cb1cf6a7abd663f031caf7869'
CURRENT_ARCHETYPE_QUALIFICATION = 'source_cooked_class_default_object'
MAX_SOURCE_BYTES = 32 * 1024 * 1024
MAX_TOTAL_SOURCE_BYTES = 128 * 1024 * 1024
_ROLES = frozenset(('GameState', 'Pawn', 'PlayerController', 'PlayerState'))


def _freeze(value):
    if type(value) is dict:
        return MappingProxyType({key: _freeze(item) for key, item in value.items()})
    if type(value) is list:
        return tuple(_freeze(item) for item in value)
    return value


def _checked(raw, expected):
    if (type(raw) is not bytes or not 0 < len(raw) <= MAX_SOURCE_BYTES or
            hashlib.sha256(raw).hexdigest() != expected):
        raise ValueError('Current Actor evidence bytes disagree with their exact SHA256')


@lru_cache(maxsize=1)
def _profile(raw):
    _checked(raw, CURRENT_ACTOR_PROFILE_SHA256)
    value = json.loads(raw)
    if (value.get('kind') != 'current_source_minimum_actor_profile' or
            value.get('client_sha256') != CURRENT_CLIENT_SHA256 or
            frozenset(value.get('actors', {})) != _ROLES or
            any(value.get(key) is not False for key in ('actor_transmission_enabled',
                'runtime_native_cache_observed', 'native_acceptance_verified', 'profile_guards_relaxed')) or
            sum(len(actor['properties']) for actor in value['actors'].values()) != 17):
        raise ValueError('The exact four-Actor current declaration subset is required')
    return _freeze(value)


@lru_cache(maxsize=1)
def _header(raw):
    _checked(raw, HEADER_PROOF_SHA256)
    value = json.loads(raw)
    if (value.get('kind') != 'current_actual_enabled_actor_receiver_source_contract' or
            value.get('client_sha256') != CURRENT_CLIENT_SHA256 or
            any(value.get(key) is not False for key in ('process_opened', 'native_engine_function_called',
                'process_memory_written', 'profile_activated', 'native_acceptance_verified')) or
            value['hook_gate_scope']['bytes_to_read'] != 37 or
            len(value['hook_gate_scope']['exact_read_ranges']) != 13 or
            value['wire_shape']['extra_payload_header_fields_in_native_alternate_wrappers'] is not False or
            any(value['wire_shape'].get(key) is not True for key in ('original_bunch_preserved',
                'queued_bytes_deep_copied', 'bit_position_preserved', 'package_map_versions_and_archive_flags_preserved'))):
        raise ValueError('The exact current conditional enabled receiver contract is required')
    return _freeze(value)


def _expected_pins(profile):
    return tuple(sorted({**profile['source_pins'], CURRENT_ACTOR_PROFILE_PATH: CURRENT_ACTOR_PROFILE_SHA256,
                         HEADER_PROOF_PATH: HEADER_PROOF_SHA256}.items()))


class _Seal(Enum):
    QUALIFIED = 1


@dataclass(frozen=True)
class CurrentActorSourceQualification:
    profile_bytes: bytes = field(repr=False)
    header_proof_bytes: bytes = field(repr=False)
    source_pins: tuple
    _seal: object = field(repr=False)

    def __post_init__(self):
        if self._seal is not _Seal.QUALIFIED:
            raise ValueError('Validated current Actor evidence is required')
        profile = _profile(self.profile_bytes)
        _header(self.header_proof_bytes)
        if type(self.source_pins) is not tuple or self.source_pins != _expected_pins(profile):
            raise ValueError('Current Actor qualification source pins changed')

    client_sha256 = CURRENT_CLIENT_SHA256
    source_sha256 = CURRENT_ACTOR_PROFILE_SHA256
    fresh_live_receiver_gate_required = True
    actor_transmission_enabled = False
    native_acceptance_verified = False
    archetype_qualification = CURRENT_ARCHETYPE_QUALIFICATION

    def summary(self):
        self.__post_init__()
        return dict(kind='current_actor_source_qualification', client_sha256=self.client_sha256,
            source_sha256=self.source_sha256, roles=sorted(_ROLES), source_pins=dict(self.source_pins),
            fresh_live_receiver_gate_required=True, actor_transmission_enabled=False,
            runtime_native_cache_observed=False, native_acceptance_verified=False)


def qualify_current_actor_sources(profile_bytes, *, source_blobs):
    """Validate compiled declarations plus v3 header evidence without any I/O."""
    profile = _profile(profile_bytes)
    if type(source_blobs) is not dict or len(source_blobs) > 256:
        raise ValueError('A bounded dictionary of exact current evidence bytes is required')
    total = len(profile_bytes)
    pins = _expected_pins(profile)
    for path, digest in pins:
        if path == CURRENT_ACTOR_PROFILE_PATH:
            continue
        raw = source_blobs.get(path)
        if raw is None:
            raise ValueError('Missing current Actor source bytes: ' + path)
        _checked(raw, digest)
        total += len(raw)
        if total > MAX_TOTAL_SOURCE_BYTES:
            raise ValueError('Current Actor evidence exceeds its total byte bound')
    header_bytes = source_blobs[HEADER_PROOF_PATH]
    _header(header_bytes)
    # Reuse the complete receiver/parameter qualifier rather than reinterpreting
    # an observed native cache or independently choosing current RPC mappings.
    from dfserver.transport.native.legacy_ds_current_pc_rpc_profile import (
        CURRENT_RPC_SOURCE_PATH, qualify_current_pc_rpc_sources)
    rpc = qualify_current_pc_rpc_sources(source_blobs.get(CURRENT_RPC_SOURCE_PATH), source_blobs=source_blobs)
    if any(dict(pins).get(path) != digest for path, digest in rpc.source_pins):
        raise ValueError('Current Actor and PC RPC evidence disagree')
    return CurrentActorSourceQualification(profile_bytes, header_bytes, pins, _Seal.QUALIFIED)


def require_current_actor_qualification(qualification):
    if type(qualification) is not CurrentActorSourceQualification:
        raise ValueError('An exact current Actor source qualification is required')
    qualification.__post_init__()
    return qualification


def current_actor_binding(qualification, role):
    require_current_actor_qualification(qualification)
    if type(role) is not str or role not in _ROLES:
        raise ValueError('Only the four qualified current Actor roles are supported')
    return _profile(qualification.profile_bytes)['actors'][role]


def current_actor_field(qualification, role, name):
    actor = current_actor_binding(qualification, role)
    if type(name) is not str or name not in actor['properties']:
        raise ValueError('Field is outside the qualified current minimum Actor subset')
    return actor['properties'][name]


def require_current_actor_manifest(manifest):
    from dfserver.replication.legacy_ds_current_movement_actor import (
        CurrentMovementActorQualification, require_current_movement_manifest)
    if type(manifest.current_qualification) is CurrentMovementActorQualification:
        return require_current_movement_manifest(manifest)
    qualification = require_current_actor_qualification(manifest.current_qualification)
    if (manifest.client_sha256 != CURRENT_CLIENT_SHA256 or
            manifest.source_relative_path != CURRENT_ACTOR_PROFILE_PATH or
            manifest.source_sha256 != CURRENT_ACTOR_PROFILE_SHA256 or
            manifest.archetype_qualification != CURRENT_ARCHETYPE_QUALIFICATION):
        raise ValueError('Current Actor manifest requires its own build, source and cooked CDO qualification')
    actors = _profile(qualification.profile_bytes)['actors']
    matches = [role for role, actor in actors.items() if
        (manifest.class_path, manifest.archetype_path) == (actor['class_path'], actor['archetype_path'])]
    if len(matches) != 1:
        raise ValueError('Current class/CDO pair differs from the sealed cooked package')
    role = matches[0]
    if (any(type(value) is not int or value != 13 for value in
            (manifest.connection_network_version, manifest.archive_network_version)) or
            manifest.force_unicode is not False):
        raise ValueError('Current minimum Actor profile requires its explicit ordinary version/string subset')
    if role == 'PlayerController':
        if type(manifest.local_player_index) is not int or manifest.local_player_index != 0:
            raise ValueError('Current single-player PC requires its explicit local index zero')
    elif manifest.local_player_index is not None:
        raise ValueError('Only the current PC may contain the qualified controller open tail')
    if role == 'Pawn':
        if type(manifest.game_replication_flags) is not int or not 0 <= manifest.game_replication_flags <= 255:
            raise ValueError('Current Pawn requires an explicit local server game-flags byte')
    elif manifest.game_replication_flags is not None:
        raise ValueError('Only the current Pawn has the qualified game-flags extension')
    return role
