"""Bounded existing WorldSettings/Level metadata; no native calls or writes.

The source-qualified static GUID is a local allocation. Its observed class and
owning Level are checked independently; transport ACK alone cannot select them.
"""
import hashlib
from pathlib import Path
import struct

from native_replication_metadata_core import MetadataSession, span
from native_static_world_settings import LOCAL_GUID, qualified_static_world_settings_source_pins

SOURCE_PINS = {
    'work/evidence/map-entry-next-20261007/level-world-settings-getter.12a938c0.code':
        'db81eca14bbb37c44fd88b7d10e9adf61305102b1dcf0c5f1db9dac49e1dba42',
    'work/evidence/map-entry-next-20261007/map-info-full.c5dcd10.asm.txt':
        '4c7d5728f74913fc915fe984c1168bb1963939352b9ece0d2225736978d5ddea',
    'work/evidence/map-entry-next-20261007/map-info-full.c5dcd10.code':
        'd6d8bdcaada059bd37804e372af8c5679af92ebb6749c70964dbe02ca1d18511',
    'work/evidence/map-entry-next-20261007/world-settings-native-field-descriptors.json':
        '326ff3cab658c74c1d191660e09251f086987bda8b0249c12d8870d8856d77a5',
}


def qualified_world_settings_context_source_pins(root):
    root = Path(root).resolve(strict=True)
    pins = qualified_static_world_settings_source_pins(root)
    for relative, expected in SOURCE_PINS.items():
        path = (root / relative).resolve(strict=True)
        if not path.is_relative_to(root) or not 0 < path.stat().st_size <= 1024 * 1024:
            raise ValueError('WorldSettings context evidence exceeds its source bound')
        actual = hashlib.sha256(path.read_bytes()).hexdigest()
        if actual != expected:
            raise ValueError('WorldSettings context evidence SHA256 mismatch')
        pins[relative] = actual
    relative = 'work/native_world_settings_context.py'
    pins[relative] = hashlib.sha256((root / relative).read_bytes()).hexdigest()
    if pins[relative] != hashlib.sha256(Path(__file__).read_bytes()).hexdigest():
        raise ValueError('WorldSettings context reader was imported from another checkout')
    return pins


def observe_world_settings_context(session, mapping, *, object_identity):
    """Read only already-mapped Actor fields and exact Level/World identities."""
    if not isinstance(session, MetadataSession) or not callable(object_identity):
        raise ValueError('WorldSettings requires the bounded typed metadata reader')
    refused = {'status': 'static_world_settings_mapping_unavailable',
               'requested_local_guid': LOCAL_GUID, 'native_getter_invoked': False,
               'memory_written': False, 'playable_map_verified': False}
    if mapping.get('status') != 'existing_guid_associations_observed':
        return refused
    matches = [row for row in mapping.get('mappings', []) if row.get('guid') == LOCAL_GUID]
    if len(matches) != 1 or matches[0].get('status') != 'existing_object_observed':
        return refused
    actor = matches[0]['object_address']; span(actor, 0x7b8)
    try:
        identity = object_identity(actor, 'DFMWorldSettings')
    except ValueError:
        # In an official capture, an unrelated static Actor may use GUID39.
        # Refuse this context view before any class-specific payload reads.
        return {**refused, 'status': 'mapped_static_actor_type_unqualified'}
    result, _ = _observe_typed_settings(session, actor, object_identity, identity)
    return {**result, 'requested_local_guid': LOCAL_GUID}


def _observe_typed_settings(session, actor, object_identity, identity):
    # Native C5DCD10 reads the complete byte at600, int32 at7b0/7b4.
    fields = session.stable(actor + 0x7b0, 8)
    contains_subworlds = session.stable(actor + 0x600, 1)
    # UObject Outer and ULevel::GetWorldSettings12a938c0 are independently
    # source-qualified metadata references, not a guessed World+f8 decoder.
    level = struct.unpack('<Q', session.stable(actor + 0x10, 8))[0]; span(level, 0x248)
    level_identity = object_identity(level, 'Level')
    selected_settings = session.stable(level + 0x240, 8)
    world = struct.unpack('<Q', session.stable(level + 0x10, 8))[0]; span(world, 1)
    world_identity = object_identity(world, 'World')
    repeated = (object_identity(actor, 'DFMWorldSettings'), object_identity(level, 'Level'),
                object_identity(world, 'World'))
    if repeated != (identity, level_identity, world_identity):
        raise ValueError('WorldSettings context identity changed during observation')
    for address, expected in ((actor + 0x7b0, fields), (actor + 0x600, contains_subworlds),
            (actor + 0x10, struct.pack('<Q', level)), (level + 0x240, selected_settings),
            (level + 0x10, struct.pack('<Q', world))):
        if session.stable(address, len(expected)) != expected:
            raise ValueError('WorldSettings context fields changed during recheck')
    map_type, override_map_type = struct.unpack('<ii', fields)
    return {'status': 'existing_world_settings_context_observed',
            'actor_class_ancestry': identity['class_ancestry'],
            'actor_name': identity['name'], 'owning_level_name': level_identity['name'],
            'owning_world_name': world_identity['name'],
            'level_world_settings_matches_actor': struct.unpack('<Q', selected_settings)[0] == actor,
            'map_type': map_type, 'override_map_type': override_map_type,
            'contains_subworlds_u8': contains_subworlds[0],
            'source_receiver_rva': '0xc5dcd10',
            'native_getter_invoked': False, 'memory_written': False,
            'playable_map_verified': False}, level


def observe_controller_world_settings(session, *, pc_address, object_identity):
    """Follow the actual typed primary controller Level, without GUID guesses.

    This works for an official connection whose server allocates different GUIDs.
    It observes the controller's Level settings, not an unproved global loading
    context or a guessed decoder for World.PersistentLevel.
    """
    return observe_actor_level_world_settings(session, actor_address=pc_address,
        actor_base_class='PlayerController', object_identity=object_identity)


def observe_actor_level_world_settings(session, *, actor_address, actor_base_class, object_identity):
    """The selected primary controller or its typed existing Pawn's Level only."""
    if actor_base_class not in ('PlayerController', 'Pawn'):
        raise ValueError('Only a qualified primary controller or its Pawn is supported')
    if not isinstance(session, MetadataSession) or not callable(object_identity):
        raise ValueError('Controller WorldSettings requires a bounded typed reader')
    span(actor_address, 0x18)
    actor_identity = object_identity(actor_address, actor_base_class)
    level_bytes = session.stable(actor_address + 0x10, 8)
    level = struct.unpack('<Q', level_bytes)[0]; span(level, 0x248)
    level_identity = object_identity(level, 'Level')
    settings_bytes = session.stable(level + 0x240, 8)
    actor = struct.unpack('<Q', settings_bytes)[0]
    if actor == 0:
        return {'status': 'controller_level_world_settings_unavailable',
                'native_getter_invoked': False, 'memory_written': False}
    span(actor, 0x7b8)
    identity = object_identity(actor, 'DFMWorldSettings')
    result, actor_level = _observe_typed_settings(session, actor, object_identity, identity)
    if (object_identity(actor_address, actor_base_class) != actor_identity or
            object_identity(level, 'Level') != level_identity or
            session.stable(actor_address + 0x10, 8) != level_bytes or
            session.stable(level + 0x240, 8) != settings_bytes):
        raise ValueError('Primary controller scene changed during observation')
    return {**result, 'observation_origin': ('typed_primary_controller_level' if
                actor_base_class == 'PlayerController' else 'typed_primary_controller_pawn_level'),
            'settings_outer_matches_actor_level': actor_level == level,
            **({'settings_outer_matches_controller_level': actor_level == level}
               if actor_base_class == 'PlayerController' else {}),
            'network_guid_assumed': False}
