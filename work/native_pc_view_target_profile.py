"""Source qualification and configuration of the default-transition PC RPC.

This helper checks existing static evidence and the redacted class-cache sample.
It neither reads a process nor requests/sends a view-target RPC. Configuration
does not certify native dispatch, a camera effect, possession or playability.
"""

import hashlib
import json
from pathlib import Path, PurePosixPath

from dfserver import legacy_ds_pc_view_target_rpc as _codec
from dfserver.legacy_ds_actor_manifest import ActorManifest
from dfserver.legacy_ds_static_actor_manifest import StaticActorManifest
from dfserver.legacy_ds_pc_view_target_rpc import (
    CLASS_PATH, CLIENT_FUNCTION_FLAGS, SERVER_FUNCTION_FLAGS,
    OBJECT_PROPERTY_VTABLE_RVA, PCViewTargetProfile,
)
from dfserver.legacy_ds_scalar_serializers import (
    NativeScalarBinding, OBJECT_SERIALIZER_RVA, SHIPPING_SHA256,
)


SPEC_PATH = 'work/evidence/map-entry-next-20261007/pc-view-target-rpc-profile.json'
SPEC_SHA256 = '7ae8d22cd7ecb26290e8ede40d64021a8aa9908e7755099f6c9d7149feefb8ca'
OBSERVATION_PATH = 'work/evidence/map-entry-next-20261007/pc-view-target-class-field-observation.json'
PAWN_CLASS_PATH = '/Game/BluePrints/Characters/BP_DFMCharacter.BP_DFMCharacter_C'
MAP_ID = 2201
MODULES = ('work/native_pc_view_target_profile.py',
    'outputs/df-local-server/dfserver/legacy_ds_pc_view_target_rpc.py',
    'outputs/df-local-server/dfserver/legacy_ds_actor_content.py',
    'outputs/df-local-server/dfserver/legacy_ds_actor_fields.py',
    'outputs/df-local-server/dfserver/legacy_ds_scalar_serializers.py',
    'outputs/df-local-server/dfserver/legacy_ds_bit_archive.py',
    'outputs/df-local-server/dfserver/legacy_ds_wire_codec.py',
    'outputs/df-local-server/dfserver/legacy_ds_actor_manifest.py',
    'outputs/df-local-server/dfserver/legacy_ds_static_actor_manifest.py')


def _read(root, relative):
    if (type(relative) is not str or not relative or ':' in relative or '\\' in relative or
            PurePosixPath(relative).is_absolute() or
            any(part in ('', '.', '..') for part in relative.split('/'))):
        raise ValueError('View-target evidence requires a plain project-relative path')
    try:
        path = (root / relative).resolve(strict=True)
        if (not path.is_relative_to(root) or not path.is_file() or
                not 0 < path.stat().st_size <= 1024 * 1024):
            raise ValueError('View-target source is missing or outside its bound')
        raw = path.read_bytes()
    except OSError as error:
        raise ValueError('View-target source could not be read') from error
    return raw, hashlib.sha256(raw).hexdigest()


def _ints(row, expected):
    return all(type(row.get(key)) is int and row[key] == value for key, value in expected)


def _validate(spec):
    qualification = spec.get('qualification', {})
    if (spec.get('kind') != 'source_qualified_pc_default_view_target_rpc_profile' or
            spec.get('client_sha256') != SHIPPING_SHA256 or spec.get('class_path') != CLASS_PATH or
            not _ints(spec, (('exclusive_index_maximum', 245),)) or
            spec.get('internal_ack') is not False or spec.get('export_mode') is not False or
            any(qualification.get(key) is not True for key in (
                'static_parameter_declaration_verified', 'static_function_flags_construction_verified',
                'static_object_serializer_binding_verified', 'native_parameter_grammar_recovered',
                'native_default_struct_initialization_verified', 'static_server_verify_handler_verified',
                'current_class_field_mapping_observed')) or
            any(qualification.get(key) is not False for key in (
                'runtime_function_parameter_layout_verified', 'current_instance_vtable_verified',
                'native_dispatch_verified', 'camera_effect_verified', 'possession_verified',
                'playable_map_verified'))):
        raise ValueError('View-target source differs from the recovered static qualification')
    functions = spec.get('functions')
    if type(functions) is not list or len(functions) != 2:
        raise ValueError('Exactly the two qualified view-target RPC declarations are required')
    client, server = functions
    if (client.get('name') != 'ClientSetViewTarget' or
            not _ints(client, (('rep_index', 53), ('function_flags', CLIENT_FUNCTION_FLAGS),
                ('parameter_struct_size', 24), ('parameter_parent_count', 2))) or
            client.get('function_param_record_rva') != '0x1d80bd70' or
            client.get('generated_getter_rva') != '0x133abc50' or
            client.get('network_wrapper_rva') != '0x133ae620' or
            server.get('name') != 'ServerVerifyViewTarget' or
            not _ints(server, (('rep_index', 85), ('function_flags', SERVER_FUNCTION_FLAGS),
                ('parameter_struct_size', 0), ('parameter_parent_count', 0))) or
            server.get('function_param_record_rva') != '0x1d80d260' or
            server.get('generated_getter_rva') != '0x133acfa0' or server.get('parameters') != []):
        raise ValueError('View-target function indices, flags or exact declarations changed')
    parameters = client.get('parameters')
    if type(parameters) is not list or len(parameters) != 2:
        raise ValueError('Actor A followed by TransitionParams is required')
    actor, transition = parameters
    for row, name, offset, size, generation in (
            (actor, 'A', 0, 8, 18), (transition, 'TransitionParams', 8, 16, 25)):
        if (row.get('name') != name or not _ints(row, (('data_offset', offset),
                ('memory_size', size), ('generation_type', generation), ('array_dimension', 1))) or
                row.get('property_flags') != '0x0010000000000080' or
                row.get('rpc_presence_required') is not True):
            raise ValueError('View-target parameter ordering or presence grammar changed')
    if (actor.get('expected_class') != 'Actor' or actor.get('parameter_record_rva') != '0x1b5d0038' or
            actor.get('object_class_getter_rva') != '0x1328cbe0' or
            actor.get('property_vtable_rva') != '0x15a86b80' or
            actor.get('serializer_target_rva') != '0x10e8ed20' or
            actor.get('field_class_flags') != '0x04018001' or
            transition.get('expected_struct') != 'ViewTargetTransitionParams' or
            transition.get('parameter_record_rva') != '0x1b5d0008' or
            transition.get('struct_getter_rva') != '0x133ab680' or
            transition.get('struct_record_rva') != '0x1d80a500' or
            transition.get('property_vtable_rva') != '0x15a86f40' or
            transition.get('field_class_flags') != '0x00108001'):
        raise ValueError('View-target parameter serializer binding changed')
    default = spec.get('transition_default', {})
    if (not _ints(default, (('struct_size', 16), ('alignment', 4), ('BlendFunction', 1))) or
            type(default.get('BlendTime')) is not float or default['BlendTime'] != 0.0 or
            type(default.get('BlendExp')) is not float or default['BlendExp'] != 2.0 or
            default.get('bLockOutgoing') is not False or default.get('zero_constructor') is not False or
            default.get('cppops_factory_rva') != '0x133ab990' or
            default.get('cppops_vtable_rva') != '0x1b5d7598' or
            default.get('cppops_property_flags_rva') != '0xe28c10' or
            default.get('cppops_added_property_flags') != '0x0000001000000000' or
            default.get('cppops_zero_constructor_target_rva') != '0xd5f3a0' or
            default.get('default_constructor_rva') != '0x133aed20' or
            default.get('initialized_memory_hex') != '00000000010000000000004000000000'):
        raise ValueError('The native default transition constructor qualification changed')
    chain = spec.get('default_initialization_chain', {})
    if (chain.get('formal_pointer_order') != ['TransitionParams', 'A'] or
            chain.get('native_linked_parameter_order') != ['A', 'TransitionParams'] or
            chain.get('prepend_property_rva') != '0x10cf7980' or
            chain.get('rpc_layout_builder_rva') != '0x12db2cb0' or
            chain.get('parent_zero_constructor_flag0x40') is not False or
            chain.get('property_zero_constructor_flag0x200') is not False or
            chain.get('rpc_initialization_before_presence') != ['0x12db9483', '0x12db9489'] or
            chain.get('struct_property_initializer_rva') != '0x10e8cfc0' or
            chain.get('script_struct_initializer_rva') != '0x10d01af0' or
            chain.get('cppops_zero_constructor_slot') != '0x10' or
            chain.get('cppops_construct_slot') != '0x18' or
            chain.get('presence_absent_skip_rva') != '0x12db96e1'):
        raise ValueError('Initialization before omitted struct presence is not source qualified')
    rules = spec.get('wire_rules', {})
    if (not _ints(rules, (('parameter_presence_bits', 2), ('guid2_parameter_payload_bits', 10),
                         ('server_verify_parameter_bits', 0))) or
            rules.get('parameter_order') != ['A', 'TransitionParams'] or
            rules.get('actor_present') is not True or rules.get('transition_present') is not False or
            rules.get('object_value_encoding') != 'ordinary_unaligned_packed_uint32_netguid' or
            rules.get('explicit_transition_supported') is not False or
            rules.get('argument_null_supported_by_local_subset') is not False or
            rules.get('property_rep_layout_framing_used') is not False or
            rules.get('parameter_termination') != 'exact_eof' or
            rules.get('guid2_parameter_payload_hex') != '0900'):
        raise ValueError('The minimal view-target RPC grammar changed')
    handler = spec.get('server_verify_handler', {})
    if (handler.get('native_exec_rva') != '0x133b60d0' or
            handler.get('handler_target_rva') != '0x12d5d1c0' or
            handler.get('client_set_wrapper_rva') != '0x133ae620' or
            handler.get('skip_if_view_target_equals_player_controller') is not True or
            handler.get('response_target_is_current_native_view_target') is not True or
            handler.get('response_target_always_owned_pawn') is not False):
        raise ValueError('The native verification handler limitation changed')


def qualified_pc_view_target_sources(root):
    root = Path(root).resolve(strict=True)
    raw, digest = _read(root, SPEC_PATH)
    if digest != SPEC_SHA256:
        raise ValueError('View-target declaration source seal changed')
    try:
        spec = json.loads(raw)
        _validate(spec)
    except (TypeError, KeyError, AttributeError, ValueError) as error:
        raise ValueError('View-target source is not a qualified native declaration') from error
    pins = {SPEC_PATH: digest}
    files = spec.get('source_files')
    if type(files) is not list or not 1 <= len(files) <= 128:
        raise ValueError('View-target native source list exceeds its bound')
    for row in files:
        relative = row.get('relative_path')
        _, actual = _read(root, relative)
        if actual != row.get('sha256') or relative in pins:
            raise ValueError('View-target native source changed or is duplicated')
        pins[relative] = actual
    if OBSERVATION_PATH not in pins:
        raise ValueError('View-target class-cache observation is missing')
    observation = json.loads(_read(root, OBSERVATION_PATH)[0])
    fields = observation.get('fields', [])
    if (observation.get('client_sha256') != SHIPPING_SHA256 or
            observation.get('class_name') != 'BP_DFMPlayerController_C' or
            not _ints(observation, (('exclusive_index_maximum', 245),)) or
            [(row.get('descriptor_name'), row.get('rep_index')) for row in fields] !=
                [('ClientSetViewTarget', 53), ('ServerVerifyViewTarget', 85)] or
            any(type(row.get('descriptor_representation')) is not int or
                row['descriptor_representation'] != 1 or row.get('incompatible') is not False
                for row in fields)):
        raise ValueError('View-target fields differ from the observed native class-cache sample')
    for relative in MODULES:
        _, pins[relative] = _read(root, relative)
    if (hashlib.sha256(Path(__file__).read_bytes()).hexdigest() != pins[MODULES[0]] or
            hashlib.sha256(Path(_codec.__file__).read_bytes()).hexdigest() != pins[MODULES[1]]):
        raise ValueError('View-target imported helper bytes differ from the sealed checkout')
    return pins


def load_pc_view_target_profile(root, sealed_sources):
    if type(sealed_sources) is not dict:
        raise ValueError('An explicit caller-sealed view-target source dictionary is required')
    pins = qualified_pc_view_target_sources(root)
    if any(sealed_sources.get(relative) != digest for relative, digest in pins.items()):
        raise ValueError('View-target sources changed after caller sealing')
    return PCViewTargetProfile(CLASS_PATH, 245, 53, 85, CLIENT_FUNCTION_FLAGS,
        SERVER_FUNCTION_FLAGS, SPEC_SHA256, NativeScalarBinding(SHIPPING_SHA256,
            OBJECT_SERIALIZER_RVA, property_vtable_rva=OBJECT_PROPERTY_VTABLE_RVA))


def install_pc_view_target_profile(root, probe, manifests, sealed_sources):
    """Configure the unique owned PC/Pawn manifest pair; do not request a send."""
    profile = load_pc_view_target_profile(root, sealed_sources)
    if (type(manifests) is not tuple or not 2 <= len(manifests) <= 16 or
            any(type(row) not in (ActorManifest, StaticActorManifest) for row in manifests)):
        raise ValueError('An immutable typed initial Actor set is required')
    pc = [row for row in manifests if type(row) is ActorManifest and row.class_path == CLASS_PATH]
    pawn = [row for row in manifests if type(row) is ActorManifest and row.class_path == PAWN_CLASS_PATH]
    if len(pc) != 1 or len(pawn) != 1:
        raise ValueError('View-target configuration requires one exact PlayerController and Pawn')
    pc, pawn = pc[0], pawn[0]
    for row, guid in ((pc, 4), (pawn, 2)):
        if (row.client_sha256 != SHIPPING_SHA256 or type(row.actor_guid) is not int or
                row.actor_guid != guid or type(row.channel_index) is not int or
                not 2 <= row.channel_index <= 65535 or row.references_resolvable is not True):
            raise ValueError('View-target configuration requires the qualified owned Actor pair')
    if pc.channel_index == pawn.channel_index:
        raise ValueError('PlayerController and Pawn require distinct Actor channels')
    setter = getattr(probe, 'set_pc_view_target_profile', None)
    if not callable(setter):
        raise ValueError('A view-target-capable probe is required')
    setter(MAP_ID, pc, pawn, profile)
    return {'kind': 'source_qualified_pc_view_target_profile_installation',
        'status': 'configured', 'map_id': MAP_ID, 'source_sha256': SPEC_SHA256,
        'player_controller': {'class_path': pc.class_path, 'actor_guid': pc.actor_guid,
                              'channel_index': pc.channel_index},
        'pawn': {'class_path': pawn.class_path, 'actor_guid': pawn.actor_guid,
                 'channel_index': pawn.channel_index},
        'view_target_requested': False, 'native_dispatch_verified': False,
        'camera_effect_verified': False, 'possession_verified': False, 'playable_map_verified': False}
