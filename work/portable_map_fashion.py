"""Native-declaration-backed first update of the Pawn's default Fashion object."""
import hashlib
import json

from dfserver.legacy_ds_bit_archive import BitWriter
from dfserver.legacy_ds_default_subobject import DefaultSubobjectUpdate
from dfserver.legacy_ds_scalar_serializers import (NativeScalarBinding, SHIPPING_SHA256,
    write_uint64_value, write_bool_value)
from portable_player_appearance import avatar_ids_for_selection

SCHEMA_SHA256 = '0824530f2a9e6f533db754ce476cbe9f8c21dbef45f5ef86c015e228724dd58b'


def qualify_schema(schema):
    # This pin includes the declarations, struct records, native sorting and
    # array receive instructions. No historical process pointer is reused.
    raw = (json.dumps(schema, indent=2, sort_keys=True)+'\n').encode()
    if (hashlib.sha256(raw).hexdigest() != SCHEMA_SHA256 or
            schema.get('client_sha256') != SHIPPING_SHA256 or
            schema.get('kind') != 'client_declaration_derived_default_fashion_schema' or
            schema.get('component_class') != 'DFMCharacterFashionComponent' or
            schema.get('component_name') != 'CharacterFashionComponent' or
            schema.get('normal_receiver_rule_derived') is not True):
        raise ValueError('The pinned native default Fashion declaration schema is required')
    prefix = {r['name']: r['handle'] for r in schema['scalar_prefix']}
    children = {r['name']: r['handle'] for r in schema['fashion_array_children']}
    return prefix, children


def fashion_update(schema, hero_id, suit_id, hero_catalog, avatar_catalog, *, actor_guid, component_guid):
    prefix, children = qualify_schema(schema)
    hero, suit, _ = avatar_ids_for_selection(hero_id, suit_id, hero_catalog, avatar_catalog)
    scalar = NativeScalarBinding(SHIPPING_SHA256, 0x10e5ce20, 0x286c000, 0x1ab60db0)
    boolean = NativeScalarBinding(SHIPPING_SHA256, 0x10e8ebe0)
    writer = BitWriter(maximum_bits=512)
    writer.write_bool(False)
    writer.write_packed_int(prefix['currentCharacterHeroID'])
    write_uint64_value(writer, hero, binding=scalar, no_byteswap=True)
    writer.write_packed_int(prefix['currentUsingHeroFashionData'])
    writer.write_bits(1, 16)  # Native dynamic-array length, not a packed handle.
    for name, value in (('heroId', hero), ('fashionSuitId', suit)):
        writer.write_packed_int(children[name])
        write_uint64_value(writer, value, binding=scalar, no_byteswap=True)
    # Explicit local presentation policy, matching the admitted PlayerState.
    for name in ('fashionTeammateVisible', 'fashionEnemyVisible', 'fashionSafehouseVisible'):
        writer.write_packed_int(children[name])
        write_bool_value(writer, True, binding=boolean)
    # Leave watchItemId at its native default rather than invent an accessory.
    writer.write_packed_int(0)
    writer.write_packed_int(0)
    return DefaultSubobjectUpdate(actor_guid, component_guid, schema['component_name'],
        SCHEMA_SHA256, writer.to_bytes(), writer.bit_count)
