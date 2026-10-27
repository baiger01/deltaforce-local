"""Initial Fashion body from fresh retained declaration admission, default closed.

Source preparation precedes the native request. The final factory performs no
file, process, native, socket, sleep or IPC operation; its authority lookup and
one-use consumption are bounded local registry operations.
"""
from copy import deepcopy
from dataclasses import dataclass, field
import hashlib
import json
from pathlib import Path
import threading
import weakref

from dfserver.legacy_ds_actor_content import (ActorContentLimits,
    ResolvedStableSubobjectContentBlock, ResolvedStableSubobjectProfile, write_actor_content_blocks)
from dfserver.legacy_ds_bit_archive import BitReader, BitWriter
from dfserver.legacy_ds_fashion_async_permit import FrozenRecipe
from dfserver.legacy_ds_fashion_runtime import (JoinedFashionOwnerContract, RuntimeSourceSeal,
    RUNTIME_MODULES, source_json, namespace_digest)
from dfserver.legacy_ds_scalar_serializers import NativeScalarBinding, write_uint64_value
from dfserver.legacy_ds_wire_codec import ChannelName, WireBunch
from native_fashion_hero_content import SourceJson, SourcePin

MODULE_RELATIVE = 'work/native_fashion_declaration_body.py'
AUTHORITY_RELATIVE = 'outputs/df-local-server/dfserver/legacy_ds_fashion_retained_protocol.py'
OWNED_PHASE_RELATIVE = 'outputs/df-local-server/dfserver/legacy_ds_fashion_owned_phase.py'
SCHEMA_RELATIVE = 'work/staging-fashion-declaration-first-body-20261010/initial-schema-profile.json'
SCHEMA_SHA = '976c1eeb6b688ed87065fc0f0736f4c871faccf6404f9e6b14bad74c7cf96f90'
CATALOG_RELATIVE = 'outputs/df-local-server/protocol/hero_customization_catalog.json'
CATALOG_SHA = '697e4a3ce2f6f43c0b28477796afd0cfa782daec38cfa3d1acae5ebbf036e64f'
HERO_EVIDENCE = 'work/evidence/map-entry-next-20261007/hero-avatar-selected-catalog-key-evidence.json'
HERO_EVIDENCE_SHA = 'c8e06388f2be03a733fdc57e254bf438cc0f6cd3e651f81194acc9be8bb1dc9a'
SHIPPING_SHA = '4254fbe66585f260f1f9dbfc5e302887842552e7baed8939e023160a5e250be0'
CORE_FREEZE_SHA = 'f694a8fc70d91e555531655b7201438c8b66c24440de84e7881d16d22a46d895'
CLASS_CHAIN = ('DFMCharacterFashionComponent', 'CharacterFashionComponent', 'ActorComponent', 'Object')
DECL_KIND = 'source_qualified_current_Fashion_declared_field_metadata_diagnostics_v1'
FACT_KIND = 'authenticated_original_live_Fashion_initial_declaration_facts_v1'
_sources = weakref.WeakKeyDictionary()
_sources_lock = threading.RLock()


class DeclarationBodyRefused(ValueError):
    pass


def require(value, reason):
    if not value:
        raise DeclarationBodyRefused(reason)


def uint(value, low, high):
    return type(value) is int and low <= value <= high


def hex64(value):
    return type(value) is str and len(value) == 64 and all(c in '0123456789abcdef' for c in value)


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=True, allow_nan=False).encode()


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def semantic_property_record(row):
    require(type(row) is dict, 'semantic_property_record_required')
    # Class setup writes RepIndex after first content; it is never a wire handle.
    return {key: deepcopy(value) for key, value in row.items() if key != 'source_rep_index'}


def semantic_declaration_snapshot(row):
    require(type(row) is dict, 'semantic_declaration_required')
    result = deepcopy(row)
    for counter in ('read_calls', 'read_bytes', 'identity_callback_calls'):
        result.pop(counter, None)
    for klass in result.get('classes', []):
        for diagnostic in ('replication_array_initialized_bit11', 'existing_descriptor_count', 'existing_descriptor_storage'):
            klass.pop(diagnostic, None)
        klass['fields'] = [semantic_property_record(item) for item in klass.get('fields', [])]
    result['net_property_prefix'] = [semantic_property_record(item) for item in result.get('net_property_prefix', [])]
    return result


@dataclass(frozen=True, eq=False)
class PreparedDeclarationSources:
    """Opaque registered source identity; constructing one does not qualify it."""
    source_revision: str
    schema_sha256: str
    _authority_type: object = field(repr=False)
    _receipt_type: object = field(repr=False)


@dataclass(frozen=True)
class PreparedDeclarationBody:
    recipe: FrozenRecipe = field(repr=False)
    component_guid: int
    source_revision: str
    declaration_fingerprint: str
    local_RepLayout_observed: bool = field(default=False, init=False)
    qualification_kind: str = field(default='declaration_equivalent_initial_schema', init=False)
    repnotify_execution_verified: bool = field(default=False, init=False)
    model_or_render_verified: bool = field(default=False, init=False)


def prepare_current_declaration_sources(*, source_seal, schema_source, native_catalog_source):
    """Run before BODY_PREPARE, outside GameProbe lock and native admission TTL."""
    require(type(source_seal) is RuntimeSourceSeal, 'executing_runtime_source_seal_required')
    sealed = source_seal.verify()
    require(type(sealed) is dict and 1 <= len(sealed) <= 512 and
        all(type(k) is str and hex64(v) for k, v in sealed.items()), 'bounded_complete_source_map_required')
    require(RUNTIME_MODULES.get('native_fashion_declaration_body') == MODULE_RELATIVE and
        RUNTIME_MODULES.get('dfserver.legacy_ds_fashion_retained_protocol') == AUTHORITY_RELATIVE and
        RUNTIME_MODULES.get('dfserver.legacy_ds_fashion_owned_phase') == OWNED_PHASE_RELATIVE,
        'factory_and_authority_executing_code_seal_required')
    require(sealed.get(MODULE_RELATIVE) == sha(Path(__file__).resolve(strict=True).read_bytes()) and
        hex64(sealed.get(AUTHORITY_RELATIVE)) and hex64(sealed.get(OWNED_PHASE_RELATIVE)),
        'executing_factory_or_authority_source_changed')
    require(type(schema_source) is SourceJson and type(schema_source.pin) is SourcePin and
        schema_source.pin.relative_path == SCHEMA_RELATIVE and hex64(SCHEMA_SHA) and
        schema_source.pin.sha256 == SCHEMA_SHA, 'reviewed_initial_schema_source_required')
    schema = source_json(schema_source, sealed)
    require(schema.get('kind') == 'source_qualified_initial_Fashion_declaration_schema_v1' and
        schema.get('client_sha256') == SHIPPING_SHA and schema.get('default_enabled') is False and
        schema.get('local_RepLayout_observed') is False, 'initial_schema_profile_refused')
    require(type(schema.get('source_pins')) is dict and schema['source_pins'] and
        all(hex64(v) and sealed.get(k) == v for k, v in schema['source_pins'].items()),
        'initial_schema_constructor_consumer_source_closure_required')
    require(type(native_catalog_source) is SourceJson and
        native_catalog_source.pin == SourcePin(CATALOG_RELATIVE, CATALOG_SHA) and
        sealed.get(HERO_EVIDENCE) == HERO_EVIDENCE_SHA, 'current_native_catalog_mapping_source_required')
    catalog = source_json(native_catalog_source, sealed)
    rows = catalog.get('fashions')
    require(type(rows) is list and 1 <= len(rows) <= 256, 'bounded_native_catalog_required')
    members = tuple(sorted({row['hero_id'] for row in rows if type(row) is dict and
        uint(row.get('hero_id'), 1, (1 << 63)-1) and row.get('default_equip') is True}))
    require(members, 'native_catalog_default_hero_membership_missing')
    # The exact class is loaded only during preflight. No late imports on the
    # freshness-critical path, and no duck-typed authority can activate it.
    from dfserver.legacy_ds_fashion_retained_protocol import OriginalWorkerAdmissionAuthority
    from dfserver.legacy_ds_fashion_owned_phase import OwnExportReceipt
    require(source_seal.verify() == sealed, 'source_changed_during_factory_preflight')
    revision = sha(canonical(sealed))
    context = PreparedDeclarationSources(revision, SCHEMA_SHA, OriginalWorkerAdmissionAuthority, OwnExportReceipt)
    retained = {'source_revision': revision, 'schema_sha256': SCHEMA_SHA,
        'authority_type': OriginalWorkerAdmissionAuthority, 'schema': deepcopy(schema),
        'receipt_type': OwnExportReceipt,
        'native_catalog_hero_ids': members}
    with _sources_lock:
        require(len(_sources) < 64, 'factory_source_context_budget_exhausted')
        _sources[context] = retained
    return context


def _source_context(context):
    require(type(context) is PreparedDeclarationSources, 'opaque_prequalified_source_context_required')
    with _sources_lock:
        retained = _sources.get(context)
        require(retained is not None and context.source_revision == retained['source_revision'] and
            context.schema_sha256 == retained['schema_sha256'] and context._authority_type is retained['authority_type'] and
            context._receipt_type is retained['receipt_type'],
            'unregistered_or_changed_source_context')
        return retained


def owner_binding_for_body(contract, prepared_sources, previous_own_receipt=None):
    source = _source_context(prepared_sources)
    require(type(contract) is JoinedFashionOwnerContract and
        uint(contract.pawn_channel, 2, 65535) and uint(contract.pawn_guid, 2, 0xffffffff) and
        hex64(contract.nonce) and hex64(contract.owner_digest), 'exact_current_join_contract_required')
    hero = getattr(contract.ticket, 'selected_hero_id', None)
    require(uint(hero, 1, (1 << 63)-1) and hero in source['native_catalog_hero_ids'],
        'current_ticket_selected_native_catalog_hero_required')
    matches = [row for row in contract.content_namespace if type(row) is tuple and len(row) == 3 and
               row[0] == contract.pawn_channel and row[1] == contract.pawn_guid]
    require(len(matches) == 1, 'one_exact_owned_pawn_association_required')
    association = matches[0][2]
    require(type(association) is WireBunch and association.channel_index == contract.pawn_channel and
        association.reliable is True and uint(association.channel_sequence, 0, 1023) and
        all(getattr(association, name) is False for name in ('open', 'close', 'partial', 'package_exports', 'must_be_mapped')),
        'exact_existing_pawn_association_bunch_required')
    require(type(contract.reserved_guids) is tuple and 1 <= len(contract.reserved_guids) <= 65536 and
        all(uint(guid, 2, 0xffffffff) for guid in contract.reserved_guids) and
        len(contract.reserved_guids) == len(set(contract.reserved_guids)), 'complete_reserved_namespace_required')
    previous_sequence = association.channel_sequence; previous_digest = None
    if previous_own_receipt is not None:
        require(type(previous_own_receipt) is source['receipt_type'] and
            uint(previous_own_receipt.next_body_reliable_sequence, 0, 1023) and
            hex64(previous_own_receipt.receipt_digest), 'source_sealed_own_export_receipt_type_required')
        previous_sequence = (previous_own_receipt.next_body_reliable_sequence - 1) & 1023
        previous_digest = previous_own_receipt.receipt_digest
    return {'join_nonce': contract.nonce, 'owner_digest': contract.owner_digest,
        'complete_namespace_digest': namespace_digest((contract.actor_namespace, contract.content_namespace,
            contract.export_namespace, contract.reserved_guids)),
        'source_seal_digest': source['source_revision'], 'selected_hero_id': hero, 'native_catalog_hero_id': hero,
        'pawn_channel': contract.pawn_channel, 'pawn_guid': contract.pawn_guid,
        'association_reliable_sequence': association.channel_sequence,
        'previous_reliable_sequence': previous_sequence, 'previous_own_export_receipt_digest': previous_digest}


def _fixed(row, expected, reason):
    require(type(row) is dict and all(type(row.get(k)) is type(v) and row[k] == v for k, v in expected.items()), reason)


def _qualify_facts(facts, schema, binding, contract, authority, previous_own_receipt):
    _fixed(facts, {'kind': FACT_KIND, 'local_RepLayout_observed': False,
        'source_seal_digest': binding['source_seal_digest'], 'native_catalog_sha256': CATALOG_SHA,
        'selected_hero_id': binding['selected_hero_id'], 'native_catalog_hero_id': binding['native_catalog_hero_id']},
        'fresh_current_ticket_catalog_source_facts_required')
    require(schema.get('qualification_complete') is True, 'immutable_initial_schema_conditions_unproven')
    declaration = facts.get('declaration')
    _fixed(declaration, {'kind': DECL_KIND, 'status': 'observed', 'original_late_rechecked': True,
        'observation_scope': 'current_declared_field_metadata_only', 'body_qualified': False,
        'wire_encoding_chosen': False, 'local_RepLayout_observed': False, 'native_methods_invoked': False,
        'process_memory_written': False, 'declaration_prefix_match_reference': True,
        'equal_offset_net_declaration_present': False, 'unmodified_hook_subset': True}, 'fresh_current_declaration_required')
    require(declaration.get('unknown_conditions') == ['first_body_qualification_not_implemented'],
        'unsupported_current_declaration_condition')
    classes = declaration.get('classes')
    require(type(classes) is list and tuple(row.get('class_name') for row in classes if type(row) is dict) == CLASS_CHAIN and
        len(classes) == len(CLASS_CHAIN), 'exact_current_native_class_parent_chain_required')
    ordered = []; total_fields = 0
    for klass in reversed(classes):
        fields = klass.get('fields')
        require(type(fields) is list and uint(klass.get('field_count'), 0, 256) and
            klass['field_count'] == len(fields), 'complete_current_class_property_list_required')
        total_fields += len(fields)
        require(total_fields <= 256, 'current_declaration_property_budget_exhausted')
        own = []
        for field in fields:
            require(type(field) is dict and type(field.get('property_flags_hex')) is str and
                type(field.get('net_flag')) is bool, 'complete_current_property_flags_required')
            try:
                flags = int(field['property_flags_hex'], 16)
            except Exception:
                raise DeclarationBodyRefused('property_flags_unqualified') from None
            require(0 <= flags < 1 << 64 and field['net_flag'] == bool(flags & 0x20), 'current_property_net_flag_mismatch')
            if field['net_flag']:
                require(uint(field.get('storage_offset'), 0, (1 << 24)-1), 'actual_property_storage_offset_required')
                own.append(field)
        offsets = [row['storage_offset'] for row in own]
        require(len(offsets) == len(set(offsets)), 'current_net_property_offset_tie_refused')
        ordered.extend(sorted(own, key=lambda row: row['storage_offset']))
    _fixed(declaration.get('metaclass'), {'name': 'Class', 'native_Class_subset': True}, 'native_metaclass_required')
    _fixed(declaration.get('CDO'), {'status': 'observed_existing', 'weak_identity_initialized': True,
        'supported_slots': True, 'actual_slot_targets_rva': {'520': 0xd5c5d0, '440': 0xafcc5c0}},
        'initialized_current_native_CDO_and_slots_required')
    _fixed(declaration.get('connection_creation_route'), {'actual_v328_target_rva': 0x12b8d6c0,
        'supported_base_creation_route': True, 'derived_override_equivalence_observed': False},
        'actual_GP_creation_route_source_subset_required')
    require(declaration.get('native_declaration_hook_bytes') == {'0x1e0b1720': 0, '0x1e0b51e8': 0,
        '0x1e0b51e9': 0, '0x1e0b51ea': 0} and
        all(type(value) is int for value in declaration['native_declaration_hook_bytes'].values()), 'inactive_native_hooks_required')
    prefix = declaration.get('net_property_prefix')
    reference = schema.get('scalar_prefix')
    require(type(prefix) is list and len(prefix) == 4 and type(reference) is list and len(reference) == 4,
        'complete_four_scalar_prefix_required')
    positions = [i for i, row in enumerate(ordered) if row.get('name') == 'currentCharacterHeroID']
    require(positions == [3] and [semantic_property_record(row) for row in ordered[:4]] ==
        [semantic_property_record(row) for row in prefix], 'fresh_complete_declarations_do_not_derive_handle4')
    for row, expected in zip(prefix, reference):
        require(type(expected) is dict and expected and
            all(type(row.get(k)) is type(v) and row[k] == v for k, v in expected.items()),
            'exact_prefix_type_offset_dimension_or_order_changed')
        require(row.get('net_flag') is True and uint(row.get('array_dimension'), 1, 1) and
            type(row.get('property_flags_hex')) is str, 'scalar_net_prefix_required')
        try:
            flags = int(row['property_flags_hex'], 16)
        except Exception:
            raise DeclarationBodyRefused('property_flags_unqualified') from None
        require(0 <= flags < 1 << 64 and flags & 0x20 and not flags & (1 << 29), 'deprecated_or_non_net_prefix_refused')
    target = prefix[-1]
    _fixed(target, {'name': 'currentCharacterHeroID', 'native_type': 'FUInt64Property', 'dispatch_opcode': 20,
        'array_dimension': 1, 'element_bytes': 8, 'storage_offset': 0x508,
        'serializer_targets_rva': {'144': 0x10e5ce20, '136': 0x286c000}, 'target_binding_matches_reference': True},
        'actual_target_serializer_storage_or_type_changed')
    notify = facts.get('actual_repnotify')
    _fixed(notify, schema['repnotify_contract'], 'actual_current_property_repnotify_required')
    require(notify.get('target_declaration_fingerprint') == sha(canonical(semantic_property_record(target))) and
        notify.get('original_session_rechecked') is True, 'notify_must_bind_same_fresh_property_declaration')
    require(int(target['property_flags_hex'], 16) & schema['repnotify_flag_mask'] != 0,
        'actual_property_repnotify_flag_missing')
    require(facts.get('native_class_setup_prerequisite_nonnull') is True,
        'current_native_class_setup_prerequisite_missing')
    archive = facts.get('archive_contract')
    _fixed(archive, schema['archive_contract'], 'normal_no_byteswap_archive_contract_required')
    require(uint(archive.get('current_connection_b4_byte'), 0, 255) and
        uint(archive.get('current_connection_180_byte'), 0, 255) and
        archive['current_connection_b4_byte'] & 1 == 0 and archive['current_connection_180_byte'] & 1 == 0 and
        archive.get('original_session_rechecked') is True and
        uint(archive.get('connection_v328_target_rva'), 0, (1 << 32)-1) and
        archive['connection_v328_target_rva'] == 0x12b8d6c0,
        'actual_original_connection_normal_archive_bytes_required')
    route = facts.get('replicator_route'); variants = schema.get('replicator_routes')
    require(type(route) is dict and type(variants) is list and len(variants) == 2 and
        any(type(expected) is dict and expected and
            all(type(route.get(k)) is type(v) and route[k] == v for k, v in expected.items())
            for expected in variants), 'source_qualified_owned_initial_base_replicator_required')
    map_matches = []
    for stem in ('current_weak_object_map_member', 'current_channel_association_member'):
        present, absent = route.get(stem + '_matches'), route.get(stem + '_absent')
        require(type(present) is bool and type(absent) is bool and absent is (not present),
            'fresh_selected_replicator_map_presence_must_be_unambiguous')
        map_matches.append(present)
    if route['qualification'] == 'current_typed_existing_base_replicator':
        require(any(map_matches), 'actual_typed_existing_replicator_map_membership_required')
    _fixed(facts.get('local_receiver'), {'pawn_guid': binding['pawn_guid'], 'pawn_channel': binding['pawn_channel'],
        'pawn_class_path': '/Game/BluePrints/Characters/BP_DFMCharacter.BP_DFMCharacter_C',
        'component_class': 'DFMCharacterFashionComponent', 'component_is_actor': False,
        'component_outer_is_current_pawn': True, 'owner_and_receiver_are_current_pawn': True,
        'direct_name_stable': True, 'reverse_and_forward_package_map_match': True,
        'current_character_hero_id': 0}, 'fresh_local_non_actor_name_owner_and_mapping_required')
    receiver = facts['local_receiver']; guid = receiver.get('component_guid')
    require(uint(guid, 2, 0xffffffff) and guid != contract.pawn_guid and guid not in contract.reserved_guids,
        'local_component_complete_namespace_collision')
    origin = receiver.get('mapping_origin')
    if origin == 'after_own_export':
        require(previous_own_receipt is not None and
            receiver.get('own_export_receipt_fingerprint') == binding['previous_own_export_receipt_digest'] and
            authority.verify_previous_own_export_receipt(previous_own_receipt, owner_binding=binding,
                component_guid=guid, expected_fingerprint=receiver.get('own_export_receipt_fingerprint')) is True,
            'own_actual_full_export_send_positive_ACK_and_fresh_mapping_required')
    else:
        raise DeclarationBodyRefused('resolved_existing_replicator_override_not_observed')
    return guid


def _body_and_recipe(contract, binding, component_guid, fingerprint):
    hero = binding['selected_hero_id']
    writer = BitWriter(maximum_bits=81)
    writer.write_bool(False); writer.write_packed_int(4)
    write_uint64_value(writer, hero, binding=NativeScalarBinding(SHIPPING_SHA, 0x10e5ce20, 0x286c000, 0x1ab60db0), no_byteswap=True)
    writer.write_packed_int(0)
    require(writer.bit_count == 81, 'initial_UInt64_wire_length_changed')
    body = writer.to_bytes()
    reader = BitReader(body, bit_count=81)
    require(reader.read_bool() is False and reader.read_packed_int() == 4 and
        int.from_bytes(reader.read_payload(64), 'little') == hero and reader.read_packed_int() == 0 and reader.remaining == 0,
        'current_ticket_UInt64_wire_grammar_changed')
    actor_guids = tuple(row[1] for row in contract.actor_namespace)
    envelope = ResolvedStableSubobjectProfile(contract.pawn_guid, actor_guids, (component_guid,),
        'normal_client', True, True, True)
    maximum = getattr(contract.connection, 'max_packet_bytes', None)
    require(uint(maximum, 64, 1492), 'current_transport_payload_bound_required')
    outer = BitWriter(maximum_bits=maximum * 8)
    write_actor_content_blocks(outer, (ResolvedStableSubobjectContentBlock(component_guid, True, body, 81),),
        limits=ActorContentLimits(1, 97, maximum * 8), allow_resolved_stable_subobjects=True,
        resolved_stable_subobject_profile=envelope)
    bunch = WireBunch(contract.pawn_channel, outer.to_bytes(), outer.bit_count, reliable=True,
        channel_sequence=(binding['previous_reliable_sequence'] + 1) & 1023,
        channel_name=ChannelName(hardcoded_index=102))
    recipe = FrozenRecipe(bunch, sha(body), sha(repr(bunch).encode()), hero,
        binding['source_seal_digest'], CORE_FREEZE_SHA)
    return PreparedDeclarationBody(recipe, component_guid, binding['source_seal_digest'], fingerprint)


def prepare_bound_current_fashion_recipe(*, authority, admission, contract, previous_own_receipt=None, source_seal):
    """Consume exact registered fresh native admission, then return immutable wire recipe."""
    sources = _source_context(source_seal)
    require(type(authority) is sources['authority_type'], 'sealed_original_worker_admission_authority_required')
    binding = owner_binding_for_body(contract, source_seal, previous_own_receipt)
    descriptor = authority.describe_current_declaration_admission(admission, owner_binding=binding, phase='body_prepare')
    require(type(descriptor) is dict and set(descriptor) == {'fingerprint', 'facts'} and
        hex64(descriptor.get('fingerprint')) and type(descriptor.get('facts')) is dict,
        'registered_immutable_admission_descriptor_required')
    # Clone only authenticated safe scalars/records, never native selectors.
    raw = canonical(descriptor['facts'])
    require(len(raw) <= 262144 and sha(raw) == descriptor['fingerprint'], 'authenticated_declaration_fingerprint_changed')
    facts = json.loads(raw)
    guid = _qualify_facts(facts, sources['schema'], binding, contract, authority, previous_own_receipt)
    prepared = _body_and_recipe(contract, binding, guid, descriptor['fingerprint'])
    require(owner_binding_for_body(contract, source_seal, previous_own_receipt) == binding,
        'owner_or_ticket_changed_during_body_preparation')
    issuance = authority.consume_current_declaration_admission(admission, expected_fingerprint=descriptor['fingerprint'],
        owner_binding=binding, phase='body_prepare')
    require(type(issuance) is dict and set(issuance) == {'fingerprint', 'facts'} and
        issuance['fingerprint'] == descriptor['fingerprint'] and canonical(issuance['facts']) == raw,
        'consumed_retained_issuance_mismatch')
    require(owner_binding_for_body(contract, source_seal, previous_own_receipt) == binding,
        'owner_or_ticket_changed_before_recipe_commit')
    return prepared
