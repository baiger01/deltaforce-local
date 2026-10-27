"""Source-qualified owning weapon value bits and component content only.

This module sends nothing. It has no process API, object loader or Actor GUID
allocator. Runtime callers must supply resolved, acknowledged current objects.
The class map is a pinned installed baseline, not an observed current INI map.
"""
from dataclasses import dataclass
import hashlib
import json
from pathlib import Path

from dfserver.legacy_ds_actor_content import ActorContentBlock
from dfserver.legacy_ds_actor_fields import (ClassFieldEnvelope, NormalClassFieldProfile,
    build_class_field_content)
from dfserver.legacy_ds_bit_archive import BitReader, BitWriter, UINT32_MAX
from dfserver.legacy_ds_default_subobject import DefaultSubobjectUpdate
from dfserver.legacy_ds_rep_layout_refs import ObjectReference, build_object_reference_content
from owned_weapon_fast_array_codec import (RawWeaponPairBits, WeaponFastArrayDelta,
    write_legacy_weapon_array_payload, source_binding as array_source_binding)

ROOT = Path(__file__).resolve().parent.parent
SCHEMA_PATH = 'outputs/df-local-server/protocol/portable-map-spawn/owned-weapon-schema-v3.json'
SCHEMA_SHA256 = '10e4c03ca3a0955b74d2a6c40b484f1757b645c787363f45e3584bac84c14624'
CLIENT_SHA = '4254fbe66585f260f1f9dbfc5e302887842552e7baed8939e023160a5e250be0'
ACTOR_SCHEMA_PATH = 'outputs/df-local-server/protocol/portable-map-spawn/owned-weapon-actor-schema.json'
ACTOR_SCHEMA_SHA256 = '502f98d5dd685afffed601e4baa6e95ae6e55671cc40c89024c839bb0ab7aac2'


def qualify_schema(schema):
    raw = (json.dumps(schema, indent=2, sort_keys=True)+'\n').encode()
    if (hashlib.sha256(raw).hexdigest() != SCHEMA_SHA256 or schema.get('client_sha256') != CLIENT_SHA
            or schema.get('kind') != 'client_source_derived_owned_weapon_schema'):
        raise ValueError('The exact source-qualified owning weapon schema is required')
    return schema


def schema_binding():
    """Verify the public schema and its private source pins using local files."""
    raw = (ROOT/SCHEMA_PATH).read_bytes()
    if hashlib.sha256(raw).hexdigest() != SCHEMA_SHA256:
        raise ValueError('The owning weapon source schema changed')
    schema = qualify_schema(json.loads(raw))
    for relative, digest in schema['sources'].items():
        path = (ROOT/relative).resolve()
        if (not path.is_relative_to(ROOT.resolve()) or
                hashlib.sha256(path.read_bytes()).hexdigest() != digest):
            raise ValueError('The owning weapon source pin changed: '+relative)
    array_source_binding()
    return schema


def qualify_actor_schema(schema):
    raw = (json.dumps(schema, indent=2, sort_keys=True)+'\n').encode()
    if (hashlib.sha256(raw).hexdigest() != ACTOR_SCHEMA_SHA256 or
            schema.get('kind') != 'client_source_derived_owned_weapon_actor_initialization_v1' or
            schema.get('client_sha256') != CLIENT_SHA):
        raise ValueError('The exact current weapon Actor initialization schema is required')
    return schema


def actor_schema_binding():
    """Keep the older value schema stable while qualifying the actual Actor layout."""
    raw = (ROOT/ACTOR_SCHEMA_PATH).read_bytes()
    if hashlib.sha256(raw).hexdigest() != ACTOR_SCHEMA_SHA256:
        raise ValueError('The actual weapon Actor schema changed')
    schema = qualify_actor_schema(json.loads(raw))
    for relative, expected in schema['sources'].items():
        path = (ROOT/relative).resolve()
        if (not path.is_relative_to(ROOT.resolve()) or
                hashlib.sha256(path.read_bytes()).hexdigest() != expected):
            raise ValueError('The weapon Actor source changed: '+relative)
    return schema


def _uint(value, bits, label, *, nonzero=False):
    if type(value) is not int or not int(nonzero) <= value < 1 << bits:
        raise ValueError('Invalid '+label)


@dataclass(frozen=True)
class WeaponPair:
    reserve_last: bool
    switch_type: int
    unique_id: int
    common_class_id: int
    last_active_frame: int
    weapon_slot: int
    path_type: int = 1


def _pair(pair, schema):
    qualify_schema(schema)
    if type(pair) is not WeaponPair or type(pair.reserve_last) is not bool:
        raise ValueError('An explicit WeaponPair and boolean reservation are required')
    if type(pair.switch_type) is not int or pair.switch_type not in tuple(
            entry['value'] for entry in schema['switch_type']['entries']):
        raise ValueError('An actual source-declared weapon switch value is required')
    _uint(pair.unique_id, 32, 'nonzero WeaponIdentity.UniqueId', nonzero=True)
    _uint(pair.last_active_frame, 32, 'LastActiveFrame')
    _uint(pair.weapon_slot, 8, 'WeaponSlot')
    _class_id(pair.common_class_id, schema, path_type=pair.path_type)


def _class_id(value, schema, *, path_type=1):
    _uint(value, 64, 'common class ID', nonzero=True)
    if type(path_type) is not int or path_type not in (1, 3):
        raise ValueError('Only original common or melee-table class references are supported')
    if path_type == 3:
        from portable_melee_weapon import catalog
        if value not in catalog()['rows']:
            raise ValueError('An original melee attribute row is required for Type3')
    elif str(value) not in schema['fast_class_path']['ids_to_paths']:
        raise ValueError('A source-declared Type1 common weapon class ID is required')


def write_fast_class_path(writer, common_class_id, *, schema, path_type=1):
    """Original nonzero path types share the native uint8 + uint64 grammar."""
    qualify_schema(schema)
    _class_id(common_class_id, schema, path_type=path_type)
    staged = BitWriter(maximum_bits=72)
    staged.write_bits(path_type, 8)
    staged.write_bits(common_class_id, 64)
    writer.write_payload(staged.to_bytes(), staged.bit_count)


def read_fast_class_path(reader, *, schema, with_type=False):
    qualify_schema(schema)
    path_type = reader.read_bits(8)
    value = reader.read_bits(64)
    _class_id(value, schema, path_type=path_type)
    return (path_type, value) if with_type else value


def write_weapon_pair(writer, pair, *, schema):
    """Full reflected native pair, excluding FastArrayItem memory-only header."""
    _pair(pair, schema)
    staged = BitWriter(maximum_bits=149)
    staged.write_bool(pair.reserve_last)
    staged.write_bits(pair.switch_type, 4)
    staged.write_bits(pair.unique_id, 32)
    write_fast_class_path(staged, pair.common_class_id, schema=schema, path_type=pair.path_type)
    staged.write_bits(pair.last_active_frame, 32)
    staged.write_bits(pair.weapon_slot, 8)
    writer.write_payload(staged.to_bytes(), staged.bit_count)


def read_weapon_pair(reader, *, schema):
    qualify_schema(schema)
    start = reader.position
    try:
        reserve, switch, identity = reader.read_bool(), reader.read_bits(4), reader.read_bits(32)
        path_type, class_id = read_fast_class_path(reader, schema=schema, with_type=True)
        pair = WeaponPair(reserve, switch, identity, class_id, reader.read_bits(32),
            reader.read_bits(8), path_type)
        _pair(pair, schema)
        return pair
    except Exception:
        reader.position = start
        raise


def build_weapon_info_content(changed_pairs, *, array_key, base_key, deleted_ids, schema):
    """Custom delta fieldindex5/max25, with first-receive legacy prefix false.

    This returns has_rep_layout=False, which the component wrapper must retain.
    It may alternatively follow an ordinary stream with combine_replicate_content.
    """
    qualify_schema(schema)
    if type(changed_pairs) is not tuple or len(changed_pairs) > 32:
        raise ValueError('A locally bounded tuple of changed pairs is required')
    changed = []
    seen = set()
    for entry in changed_pairs:
        if type(entry) is not tuple or len(entry) != 2:
            raise ValueError('Each change requires explicit replication ID and WeaponPair')
        replication_id, pair = entry
        _pair(pair, schema)
        if pair.unique_id in seen:
            raise ValueError('Duplicate current weapon identity')
        seen.add(pair.unique_id)
        value = BitWriter(maximum_bits=149)
        write_weapon_pair(value, pair, schema=schema)
        changed.append((replication_id, RawWeaponPairBits(value.to_bytes(), value.bit_count)))
    payload = BitWriter()
    write_legacy_weapon_array_payload(payload,
        WeaponFastArrayDelta(array_key, base_key, deleted_ids, tuple(changed)),
        binding=array_source_binding())
    return build_class_field_content((ClassFieldEnvelope(5, payload.to_bytes(), payload.bit_count),),
        profile=NormalClassFieldProfile(25, False))


def build_active_weapon_content(pairs, *, schema, character_owner_guid=None,
                                owner_open_acknowledged=False):
    """Native ordinary arrayhandle5 with flattened member handles1..6."""
    qualify_schema(schema)
    if type(pairs) is not tuple or len(pairs) != 1:
        raise ValueError('This qualified active-array subset requires exactly one slot')
    if len({p.unique_id for p in pairs if type(p) is WeaponPair}) != len(pairs):
        raise ValueError('Active identities must be distinct')
    for pair in pairs:
        _pair(pair, schema)
    writer = BitWriter()
    writer.write_bool(False)
    if character_owner_guid is not None:
        _resolved_dynamic(character_owner_guid, owner_open_acknowledged)
        writer.write_packed_int(3)
        writer.write_packed_int(character_owner_guid)
    writer.write_packed_int(5)
    writer.write_bits(len(pairs), 16)
    for pair in pairs:
        for member_handle, value, bits in ((1, int(pair.reserve_last), 1),
                (2, pair.switch_type, 4), (3, pair.unique_id, 32)):
            writer.write_packed_int(member_handle)
            writer.write_bits(value, bits)
        writer.write_packed_int(4)
        write_fast_class_path(writer, pair.common_class_id, schema=schema, path_type=pair.path_type)
        for member_handle, value, bits in ((5, pair.last_active_frame, 32), (6, pair.weapon_slot, 8)):
            writer.write_packed_int(member_handle)
            writer.write_bits(value, bits)
    writer.write_packed_int(0)
    writer.write_packed_int(0)
    return ActorContentBlock(True, writer.to_bytes(), writer.bit_count)


def combine_replicate_content(ordinary, custom_delta, *, schema):
    """Append field envelopes after the ordinary stream's terminal handle."""
    qualify_schema(schema)
    if (type(ordinary) is not ActorContentBlock or ordinary.has_rep_layout is not True or
            type(custom_delta) is not ActorContentBlock or custom_delta.has_rep_layout is not False):
        raise ValueError('Qualified ordinary content followed by custom-delta fields is required')
    writer = BitWriter()
    writer.write_payload(ordinary.payload, ordinary.payload_bit_count)
    writer.write_payload(custom_delta.payload, custom_delta.payload_bit_count)
    return ActorContentBlock(True, writer.to_bytes(), writer.bit_count)


def _resolved_dynamic(guid, acknowledged):
    if (type(guid) is not int or not 2 <= guid <= UINT32_MAX or guid & 1 or acknowledged is not True):
        raise ValueError('An explicitly acknowledged current dynamic Actor GUID is required')


def manager_empty_hand_update(schema, *, pawn_guid, component_guid, weapon_guid,
                              actor_open_acknowledged):
    qualify_schema(schema)
    _resolved_dynamic(weapon_guid, actor_open_acknowledged)
    block = build_object_reference_content((ObjectReference(7, weapon_guid),))
    update = DefaultSubobjectUpdate(pawn_guid, component_guid, 'WeaponManager', SCHEMA_SHA256,
        block.payload, block.payload_bit_count)
    update.__post_init__()
    return update


def replicate_owner_update(schema, *, pawn_guid, component_guid, pawn_open_acknowledged):
    qualify_schema(schema)
    _resolved_dynamic(pawn_guid, pawn_open_acknowledged)
    block = build_object_reference_content((ObjectReference(3, pawn_guid),))
    update = DefaultSubobjectUpdate(pawn_guid, component_guid, 'WeaponReplicate', SCHEMA_SHA256,
        block.payload, block.payload_bit_count)
    update.__post_init__()
    return update


def build_weapon_actor_initial_content(schema, *, pawn_guid, unique_id, weapon_rec_id,
        pawn_open_acknowledged, weapon_slot=None, inventory_gid=None, equip_position=None,
        root_recipe=False):
    """Actual Actor Owner/WeaponID/Identity/CharacterOwner, with explicit optional values.

    No inventory GID, equipment position or active weapon is inferred from the
    local uint32 WeaponIdentity. Missing optional values retain the native CDO.
    """
    qualify_actor_schema(schema)
    _resolved_dynamic(pawn_guid, pawn_open_acknowledged)
    _uint(unique_id, 32, 'nonzero local WeaponIdentity.UniqueId', nonzero=True)
    _uint(weapon_rec_id, 63, 'source WeaponID/RecID', nonzero=True)
    if weapon_slot is not None:
        _uint(weapon_slot, 8, 'explicit weapon slot')
    if inventory_gid is not None:
        _uint(inventory_gid, 64, 'original inventory GID', nonzero=True)
    if equip_position is not None:
        _uint(equip_position, 31, 'explicit nonnegative equipment position')
    fields = schema['actor']['fields']
    entries = [(fields['Owner']['ordinary_handle'], pawn_guid, None),
        (fields['WeaponID']['ordinary_handle'], weapon_rec_id, 64)]
    for name, value, bits in (('WeaponGuid', inventory_gid, 64),
            ('WeaponEquipPosition', equip_position, 32), ('WeaponSlot', weapon_slot, 8)):
        if value is not None:
            entries.append((fields[name]['ordinary_handle'], value, bits))
    tail = ((fields['ServerWeaponIdentity']['inner_handle'], unique_id, 32),
        (fields['CharacterOwner']['ordinary_handle'], pawn_guid, None))
    writer = BitWriter()
    writer.write_bool(False)

    from weapon_actor_network_role import write_network_role
    write_network_role(writer)

    def write(rows):
        for handle, value, bits in rows:
            writer.write_packed_int(handle)
            if bits is None:
                writer.write_packed_int(value)
            else:
                writer.write_bits(value, bits)
    write(entries)
    if root_recipe:
        # ModularReplicateInfo handles 36/37/38 sit between WeaponSlot(20) and
        # ServerWeaponIdentity(40). The client ready gate 590ce90 needs a
        # nonzero WeaponPartNodes count before it sets first/third person.
        from modular_weapon_recipe_codec import root_only, write_recipe_fields
        write_recipe_fields(writer, root_only(weapon_rec_id,
            weapon_rec_id if inventory_gid is None else inventory_gid))
    write(tail)
    writer.write_packed_int(0)
    return ActorContentBlock(True, writer.to_bytes(), writer.bit_count)


def manager_weapon_bindings_update(schema, *, pawn_guid, component_guid, bindings,
        empty_hand_guid, actor_opens_acknowledged):
    """Replace all three parallel manager arrays from one complete current binding set.

    Each binding is (actual Actor GUID, local uint32 UniqueId, source RecID).
    This is not an append operation; a caller must include every existing weapon.
    """
    qualify_actor_schema(schema)
    _resolved_dynamic(pawn_guid, actor_opens_acknowledged)
    if type(bindings) is not tuple or not 1 <= len(bindings) <= 32:
        raise ValueError('One complete bounded tuple of actual weapon bindings is required')
    actors, identities = set(), set()
    for entry in bindings:
        if type(entry) is not tuple or len(entry) != 3:
            raise ValueError('Weapon binding requires Actor GUID, UniqueId and RecID')
        actor, identity, recid = entry
        _resolved_dynamic(actor, actor_opens_acknowledged)
        _uint(identity, 32, 'nonzero local WeaponIdentity.UniqueId', nonzero=True)
        _uint(recid, 63, 'source weapon RecID', nonzero=True)
        if actor in actors or identity in identities or actor in (pawn_guid, component_guid):
            raise ValueError('Weapon Actor and local identities must be distinct')
        actors.add(actor)
        identities.add(identity)
    if empty_hand_guid not in actors or type(empty_hand_guid) is not int:
        raise ValueError('EmptyHand must be one of the complete current weapon bindings')
    writer = BitWriter()
    writer.write_bool(False)
    for name, column, bits in (('WeaponList', 0, None), ('WeaponIdentityList', 1, 32), ('WeaponIDList', 2, 64)):
        writer.write_packed_int(schema['manager']['arrays'][name]['ordinary_handle'])
        writer.write_bits(len(bindings), 16)
        for index, entry in enumerate(bindings, 1):
            writer.write_packed_int(index)
            if bits is None:
                writer.write_packed_int(entry[column])
            else:
                writer.write_bits(entry[column], bits)
        writer.write_packed_int(0)
    writer.write_packed_int(schema['manager']['empty_hand_handle'])
    writer.write_packed_int(empty_hand_guid)
    writer.write_packed_int(0)
    update = DefaultSubobjectUpdate(pawn_guid, component_guid, 'WeaponManager', ACTOR_SCHEMA_SHA256,
        writer.to_bytes(), writer.bit_count, has_rep_layout=True)
    update.__post_init__()
    return update
