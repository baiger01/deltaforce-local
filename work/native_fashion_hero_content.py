"""Pure, default-off current Fashion property body; no GUID, envelope or send.

Raw saved metadata/profile bytes and their caller-verified source seal qualify
the field. Current ownership/channel and selected HeroID provenance are explicit
caller contracts, not inferred from old official runtime pointers or GUIDs.
Only a true-RepLayout property slice is returned. It is deliberately a distinct
type from ActorContentBlock and NormalClassFieldProfile.
"""
from dataclasses import dataclass, field
import hashlib
import json
from pathlib import PurePosixPath

from dfserver.legacy_ds_bit_archive import BitReader, BitWriter
from dfserver.legacy_ds_scalar_serializers import NativeScalarBinding, SHIPPING_SHA256, write_uint64_value
from native_game_state_start_profile import qualify_outer_handle

SOURCE_PROFILE = 'work/staging-ds-receipt-fix-20261009/fashion-hero-property-body/source-profile.json'
SOURCE_PROFILE_SHA = '9d26e1f1cc500912ac42c57df93d2ea48df7e315dd62d99878ac0d881f372f36'
FIELD_PROFILE = 'work/staging-ds-receipt-fix-20261009/fashion-top-level-scalar-handle/profile.json'
FIELD_PROFILE_SHA = '4010e7062422de19440fca90e7c413dbd2c369ba062fcf5fad03624791162dd5'
MAX_SOURCE_BYTES, MAX_PREFIX, MAX_COMMANDS, MAX_PARENTS, MAX_BODY_BITS = 2*1024*1024, 256, 8192, 2048, 97
PS_HANDLES = frozenset((140, 142, 143))


class FashionHeroContentError(ValueError):
    pass


def _require(condition, reason):
    if not condition:
        raise FashionHeroContentError(reason)


def _digest(value):
    return type(value) is str and len(value) == 64 and all(c in '0123456789abcdef' for c in value)


def _relative(value):
    return (type(value) is str and 0 < len(value) <= 4096 and ':' not in value and '\\' not in value
        and '\0' not in value and not PurePosixPath(value).is_absolute()
        and all(p not in ('', '.', '..') for p in value.split('/')))


@dataclass(frozen=True)
class SourcePin:
    relative_path: str
    sha256: str


@dataclass(frozen=True)
class SourceJson:
    pin: SourcePin
    raw_bytes: bytes = field(repr=False)


@dataclass(frozen=True)
class OwnedFashionContext:
    generation: int
    channel_index: int
    owner_binding_digest: str = field(repr=False)
    source_pin: SourcePin
    pawn_class_name: str
    component_class_name: str
    target_kind: str
    current_joined_owner_verified: bool
    typed_pawn_component_relationship_verified: bool
    current_channel_actor_matches_current_pawn: bool
    normal_client: bool
    internal_ack: bool
    no_byteswap: bool


@dataclass(frozen=True)
class OwnedHeroIdBinding:
    generation: int
    channel_index: int
    owner_binding_digest: str = field(repr=False)
    source_pin: SourcePin
    selected_native_hero_id: int
    current_owned_hero_id: int
    hero_id_native_type: str
    namespace: str
    selected_hero_mapping_verified: bool
    current_owned_hero_id_verified: bool
    fashion_hero_namespace_binding_verified: bool


@dataclass(frozen=True)
class FashionHeroPropertyBody:
    payload: bytes = field(repr=False)
    payload_bit_count: int
    ordinary_handle: int
    field_metadata_source_sha256: str
    has_rep_layout: bool = field(default=True, init=False)
    target_kind: str = field(default='current_owned_pawn_fashion_subobject', init=False)

    def __post_init__(self):
        _require(type(self.payload) is bytes and type(self.payload_bit_count) is int
            and 81 <= self.payload_bit_count <= MAX_BODY_BITS
            and len(self.payload) == (self.payload_bit_count + 7) // 8
            and (not self.payload_bit_count % 8 or self.payload[-1] >> (self.payload_bit_count % 8) == 0)
            and type(self.ordinary_handle) is int and 1 <= self.ordinary_handle <= 65535
            and self.ordinary_handle not in PS_HANDLES and _digest(self.field_metadata_source_sha256),
            'fashion_body_type_or_bound_refused')
        try:
            reader = BitReader(self.payload, bit_count=self.payload_bit_count)
            _require(reader.read_bool() is False and reader.read_packed_int() == self.ordinary_handle,
                'fashion_body_grammar_refused')
            value = int.from_bytes(reader.read_payload(64), 'little')
            _require(0 < value < 1 << 63 and reader.read_packed_int() == 0 and reader.remaining == 0,
                'fashion_body_grammar_refused')
            _require(self.payload_bit_count == 1 + 8*((self.ordinary_handle.bit_length()+6)//7) + 64 + 8,
                'fashion_body_grammar_refused')
        except FashionHeroContentError:
            raise
        except Exception:
            raise FashionHeroContentError('fashion_body_grammar_refused') from None


def _pin(pin, sealed):
    _require(type(pin) is SourcePin and _relative(pin.relative_path) and _digest(pin.sha256)
        and sealed.get(pin.relative_path) == pin.sha256, 'source_pin_refused')


def _json(source, sealed):
    _require(type(source) is SourceJson, 'source_json_required')
    _pin(source.pin, sealed)
    _require(type(source.raw_bytes) is bytes and 0 < len(source.raw_bytes) <= MAX_SOURCE_BYTES
        and hashlib.sha256(source.raw_bytes).hexdigest() == source.pin.sha256, 'source_json_hash_or_bound_refused')
    def pairs(rows):
        result = {}
        for key, value in rows:
            _require(key not in result, 'source_json_duplicate_key_refused')
            result[key] = value
        return result
    try:
        result = json.loads(source.raw_bytes, object_pairs_hook=pairs,
            parse_constant=lambda value: (_ for _ in ()).throw(FashionHeroContentError('source_json_nonfinite_refused')))
        _require(type(result) is dict, 'source_json_object_required')
        return result
    except FashionHeroContentError:
        raise
    except Exception:
        raise FashionHeroContentError('source_json_schema_refused') from None


def _fixed(row, expected, reason):
    _require(type(row) is dict and all(type(row.get(k)) is type(v) and row[k] == v for k, v in expected.items()), reason)


def prepare_fashion_hero_property_body(*, metadata_source=None, field_profile_source=None,
        factory_profile_source=None, observer_source_pin=None, sealed_sources=None,
        current_owner=None, hero_binding=None, enabled=False):
    """Return an isolated property body and safe grammar facts, never a packet.

    sealed_sources must be the caller's already-verified frozen source map. This
    pure factory verifies supplied byte/hash/schema consistency; it performs no
    filesystem, current-process, ownership, channel or account lookup itself.
    """
    _require(type(enabled) is bool, 'explicit_boolean_required')
    if not enabled:
        return None, {'status': 'disabled', 'packet_produced_or_sent': False}
    _require(type(sealed_sources) is dict and len(sealed_sources) <= 512
        and all(_relative(p) and _digest(h) for p, h in sealed_sources.items()), 'sealed_sources_required')
    sealed = dict(sealed_sources)
    schema = _json(factory_profile_source, sealed)
    _require(factory_profile_source.pin == SourcePin(SOURCE_PROFILE, SOURCE_PROFILE_SHA), 'factory_profile_refused')
    _fixed(schema, {'kind':'pure_current_fashion_hero_property_body_source_profile_v1',
        'client_sha256':SHIPPING_SHA256, 'default_enabled':False, 'create_guid_or_send':False,
        'raw_source_json_maximum_bytes':MAX_SOURCE_BYTES, 'maximum_prefix_commands':MAX_PREFIX,
        'maximum_layout_commands':MAX_COMMANDS, 'maximum_layout_parents':MAX_PARENTS,
        'maximum_body_bits':MAX_BODY_BITS}, 'factory_profile_refused')
    _require(type(schema.get('source_pins')) is dict, 'factory_profile_refused')
    for path, digest in schema['source_pins'].items():
        _pin(SourcePin(path, digest), sealed)
    _pin(observer_source_pin, sealed)
    _require(observer_source_pin.relative_path == 'work/native_fashion_current_class_metadata.py', 'observer_source_refused')
    profile = _json(field_profile_source, sealed)
    _require(field_profile_source.pin == SourcePin(FIELD_PROFILE, FIELD_PROFILE_SHA), 'field_profile_refused')
    _fixed(profile, {'client_sha256':SHIPPING_SHA256, 'required_component_class':'DFMCharacterFashionComponent',
        'required_pawn_class':'BP_DFMCharacter_C', 'ordinary_top_level_scalar_handle_required':True,
        'native_methods_invoked':False, 'wire_encoding_chosen':False}, 'field_profile_refused')
    _require(type(profile.get('source_files')) is dict, 'field_profile_refused')
    for path, digest in profile['source_files'].items():
        _pin(SourcePin(path, digest), sealed)
    _fixed(profile.get('field'), {'name':'currentCharacterHeroID','offset':0x508,'bytes':8,
        'native_type':'FUInt64Property','repnotify':'OnRep_CharacterAvatarID','property_vtable_rva':0x1ab60db0,
        'dispatch_opcode':20,'property_serializer_slot':0x90,'property_serializer_rva':0x10e5ce20,
        'property_scalar_leaf_slot':0x88,'property_scalar_leaf_rva':0x286c000}, 'typed_field_hooks_refused')
    capture = _json(metadata_source, sealed)
    _fixed(capture, {'status':'metadata_export_complete','client_sha256':SHIPPING_SHA256}, 'complete_metadata_required')
    receiver = capture.get('appearance_receiver_state_observation')
    _fixed(receiver, {'status':'observed','component_class':'DFMCharacterFashionComponent',
        'receiver_equals_current_pawn':True,'identity_fields_methods_and_source_rechecked':True,
        'process_memory_written':False,'native_methods_invoked':False}, 'typed_fashion_receiver_required')
    metadata = receiver.get('formal_field_metadata')
    _fixed(metadata, {'status':'observed','source_profile_sha256':FIELD_PROFILE_SHA,
        'ordinary_top_level_scalar_handle_qualified':True,'owner_equals_receiver_equals_current_pawn':True,
        'same_current_primary_driver_rechecked':True,'current_identities_relations_cache_layout_and_sources_rechecked':True,
        'late_original_observation_rechecked':True,'process_memory_written':False,'native_methods_invoked':False},
        'qualified_complete_fashion_metadata_required')
    target = metadata.get('field')
    _fixed(target, {'name':'currentCharacterHeroID','native_type':'FUInt64Property','storage_bytes':8,
        'source_offset':0x508,'declared_repnotify':'OnRep_CharacterAvatarID','dispatch_opcode':20}, 'exact_fashion_field_required')
    count, parents = metadata.get('complete_layout_command_count'), metadata.get('complete_layout_parent_count')
    ci, pi, handle = target.get('command_index'), target.get('parent_index'), target.get('ordinary_handle')
    _require(type(count) is int and 2 <= count <= MAX_COMMANDS and type(parents) is int and 1 <= parents <= MAX_PARENTS
        and type(ci) is int and 0 <= ci < count-1 and type(pi) is int and 0 <= pi < parents
        and type(handle) is int and 1 <= handle <= 65535 and handle not in PS_HANDLES
        and _digest(target.get('command_record_sha256')) and _digest(target.get('parent_record_sha256')),
        'field_layout_bounds_or_ps_handle_refused')
    prefix = metadata.get('top_level_prefix_commands')
    _require(type(prefix) is list and len(prefix) == ci+1 and 1 <= len(prefix) <= MAX_PREFIX, 'complete_prefix_required')
    for row in prefix:
        _require(type(row) is dict and type(row.get('index')) is int
            and type(row.get('dispatch_opcode')) is int and 0 <= row['dispatch_opcode'] <= 255
            and type(row.get('relative_handle')) is int and 0 <= row['relative_handle'] <= 65535
            and (type(row.get('descriptor_name')) is str and 0 < len(row['descriptor_name']) <= 1024
                or row.get('dispatch_opcode') == 1 and row.get('descriptor_name') is None), 'prefix_schema_refused')
    try:
        _require(qualify_outer_handle(prefix, {'name':'currentCharacterHeroID','dispatch_opcode':20,
            'ordinary_handle':handle,'command_index':ci}) == handle, 'top_level_scalar_handle_refused')
    except FashionHeroContentError:
        raise
    except Exception:
        raise FashionHeroContentError('top_level_scalar_handle_refused') from None
    _require(type(current_owner) is OwnedFashionContext and type(hero_binding) is OwnedHeroIdBinding,
        'typed_owned_context_and_hero_binding_required')
    owner, hero = current_owner, hero_binding
    _pin(owner.source_pin, sealed); _pin(hero.source_pin, sealed)
    _require(type(owner.generation) is int and 0 < owner.generation < 1 << 64
        and type(owner.channel_index) is int and 2 <= owner.channel_index <= 65535
        and _digest(owner.owner_binding_digest) and type(hero.generation) is int and type(hero.channel_index) is int
        and _digest(hero.owner_binding_digest)
        and hero.generation == owner.generation and hero.channel_index == owner.channel_index
        and hero.owner_binding_digest == owner.owner_binding_digest, 'current_owned_generation_channel_mismatch')
    _require(owner.pawn_class_name == 'BP_DFMCharacter_C' and owner.component_class_name == 'DFMCharacterFashionComponent'
        and owner.target_kind == 'current_owned_pawn_fashion_component'
        and all(v is True for v in (owner.current_joined_owner_verified, owner.typed_pawn_component_relationship_verified,
            owner.current_channel_actor_matches_current_pawn, owner.normal_client, owner.no_byteswap))
        and owner.internal_ack is False, 'current_non_actor_fashion_normal_channel_required')
    value = hero.current_owned_hero_id
    _require(type(value) is int and 0 < value < 1 << 63 and type(hero.selected_native_hero_id) is int
        and hero.selected_native_hero_id == value and hero.hero_id_native_type == 'FInt64Property'
        and hero.namespace == 'native_hero_configuration_id'
        and all(v is True for v in (hero.selected_hero_mapping_verified, hero.current_owned_hero_id_verified,
            hero.fashion_hero_namespace_binding_verified)), 'owned_selected_hero_id_namespace_refused')
    writer = BitWriter(maximum_bits=MAX_BODY_BITS)
    writer.write_bool(False); writer.write_packed_int(handle)
    write_uint64_value(writer, value, binding=NativeScalarBinding(SHIPPING_SHA256, 0x10e5ce20, 0x286c000, 0x1ab60db0), no_byteswap=True)
    writer.write_packed_int(0)
    body = FashionHeroPropertyBody(writer.to_bytes(), writer.bit_count, handle, metadata_source.pin.sha256)
    _require(sealed_sources == sealed, 'source_seal_changed_during_preparation')
    return body, {'status':'prepared','kind':'qualified_current_fashion_hero_true_replayout_property_body',
        'property_name':'currentCharacterHeroID','ordinary_handle':handle,'payload_bits':body.payload_bit_count,
        'metadata_source_sha256':metadata_source.pin.sha256,'payload_sha256':hashlib.sha256(body.payload).hexdigest(),
        'value_origin':'explicit_current_owned_HeroID_with_verified_selected_hero_and_namespace_binding',
        'has_rep_layout':True,'actor_envelope_created':False,'component_GUID_chosen':False,
        'stable_subobject_identity_qualified':False,'repnotify_execution_verified':False,'model_initialized':False,
        'packet_produced_or_sent':False,'process_accessed':False,'native_methods_invoked':False,'process_memory_written':False}
