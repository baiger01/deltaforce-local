"""Separate current native MovementReplicationActor creation qualification.

This adds no movement payload codec or runtime acceptance claim. Its caller
retains the entry profile's fresh process/receiver admission guard.
"""
from dataclasses import dataclass, field
from enum import Enum
from functools import lru_cache
import hashlib
import json

from dfserver.replication.legacy_ds_current_actor_profile import (
    CURRENT_CLIENT_SHA256, require_current_actor_qualification)


MOVEMENT_PROFILE_PATH = 'work/evidence/updated-movement-actor-profile-79fb7b10.json'
MOVEMENT_PROFILE_SHA256 = 'd507835ac7ed4a50bc245ad0161a12a31368771d2395be62e9a0f6ffb7795ee3'
MOVEMENT_ARCHETYPE_QUALIFICATION = 'source_native_class_default_object'
MOVEMENT_CLASS_PATH = '/Script/GPGameplay.MovementReplicationActor'
MOVEMENT_ARCHETYPE_PATH = '/Script/GPGameplay.Default__MovementReplicationActor'
MAX_SOURCE_BYTES = 32 * 1024 * 1024


@lru_cache(maxsize=1)
def _profile(raw):
    if (type(raw) is not bytes or not 0 < len(raw) <= MAX_SOURCE_BYTES or
            hashlib.sha256(raw).hexdigest() != MOVEMENT_PROFILE_SHA256):
        raise ValueError('The exact current native movement creation report is required')
    value = json.loads(raw)
    if (value.get('kind') != 'current_native_movement_actor_creation_source' or
            value.get('client_sha256') != CURRENT_CLIENT_SHA256 or
            value.get('class_path') != MOVEMENT_CLASS_PATH or
            value.get('archetype_path') != MOVEMENT_ARCHETYPE_PATH or
            value.get('archetype_qualification') != MOVEMENT_ARCHETYPE_QUALIFICATION or
            value.get('actor_open_tail_bits') != 0 or value.get('net_rep_actor_interface') is not None or
            value.get('actor_open_hook') != dict(slot='0x3d8', target_rva='0xd5f3d0', empty_return=True) or
            any(value.get(key) is not False for key in ('replicated_movement_payload_implemented',
                'runtime_cdo_observed', 'runtime_native_cache_observed', 'actor_transmission_enabled',
                'native_acceptance_verified', 'process_opened', 'native_function_called'))):
        raise ValueError('The current movement creation subset changed')
    return value


def _pins(raw, entry):
    return tuple(sorted({**dict(entry.source_pins), **_profile(raw)['source_pins'],
                         MOVEMENT_PROFILE_PATH: MOVEMENT_PROFILE_SHA256}.items()))


class _Seal(Enum):
    QUALIFIED = 1


@dataclass(frozen=True)
class CurrentMovementActorQualification:
    profile_bytes: bytes = field(repr=False)
    entry_qualification: object = field(repr=False)
    source_pins: tuple
    _seal: object = field(repr=False)

    client_sha256 = CURRENT_CLIENT_SHA256
    archetype_qualification = MOVEMENT_ARCHETYPE_QUALIFICATION
    fresh_live_receiver_gate_required = True
    native_acceptance_verified = False

    def __post_init__(self):
        require_current_actor_qualification(self.entry_qualification)
        if (self._seal is not _Seal.QUALIFIED or type(self.source_pins) is not tuple or
                self.source_pins != _pins(self.profile_bytes, self.entry_qualification)):
            raise ValueError('Validated current movement and entry source qualifications are required')


def qualify_current_movement_actor_sources(profile_bytes, *, source_blobs, entry_qualification):
    require_current_actor_qualification(entry_qualification)
    profile = _profile(profile_bytes)
    if type(source_blobs) is not dict or len(source_blobs) > 256:
        raise ValueError('Explicit bounded current movement source bytes are required')
    total = len(profile_bytes)
    for path, digest in profile['source_pins'].items():
        raw = source_blobs.get(path)
        if (type(raw) is not bytes or not 0 < len(raw) <= MAX_SOURCE_BYTES or
                hashlib.sha256(raw).hexdigest() != digest):
            raise ValueError('Missing or changed current movement source: '+path)
        total += len(raw)
        if total > 128 * 1024 * 1024:
            raise ValueError('Current movement source bytes exceed their bound')
    return CurrentMovementActorQualification(profile_bytes, entry_qualification,
        _pins(profile_bytes, entry_qualification), _Seal.QUALIFIED)


def require_current_movement_manifest(manifest):
    q = manifest.current_qualification
    if type(q) is not CurrentMovementActorQualification:
        raise ValueError('An exact current native movement qualification is required')
    q.__post_init__()
    if ((manifest.client_sha256, manifest.source_relative_path, manifest.source_sha256,
         manifest.class_path, manifest.archetype_path, manifest.archetype_qualification) !=
            (CURRENT_CLIENT_SHA256, MOVEMENT_PROFILE_PATH, MOVEMENT_PROFILE_SHA256,
             MOVEMENT_CLASS_PATH, MOVEMENT_ARCHETYPE_PATH, MOVEMENT_ARCHETYPE_QUALIFICATION) or
            any(type(value) is not int or value != 13 for value in
                (manifest.connection_network_version, manifest.archive_network_version)) or
            manifest.force_unicode is not False or manifest.game_replication_flags is not None or
            manifest.local_player_index is not None):
        raise ValueError('Current native movement creation cannot use cooked, Pawn or historical mappings')
    return 'MovementReplicationActor'
