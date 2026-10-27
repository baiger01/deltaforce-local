"""Read-only qualification of this build's one-Pawn restart RPC declarations.

Parameter grammar is reconstructed from exact static construction and native
consumers. The observed class indices are separately pinned. No runtime layout,
dispatch, possession or scene result is manufactured by this qualification.
"""
import hashlib
import json
from pathlib import Path, PurePosixPath

from dfserver.legacy_ds_pc_restart_rpc import (
    CLASS_PATH, CLIENT_FUNCTION_FLAGS, SERVER_FUNCTION_FLAGS,
    OBJECT_PROPERTY_VTABLE_RVA, PCRestartProfile,
)
from dfserver.legacy_ds_scalar_serializers import (
    NativeScalarBinding, OBJECT_SERIALIZER_RVA, SHIPPING_SHA256,
)


SPEC_PATH = 'work/evidence/map-entry-next-20261007/pc-restart-rpc-profile.json'
SPEC_SHA256 = 'd65ad7e7013c8075851456c1bebff69d1b4487cf870de592d301732242202b0c'
OBSERVATION_PATH = 'work/evidence/map-entry-next-20261007/pc-restart-class-field-observation.json'
MODULES = ('work/native_pc_restart_profile.py',
    'outputs/df-local-server/dfserver/legacy_ds_pc_restart_rpc.py',
    'outputs/df-local-server/dfserver/legacy_ds_actor_content.py',
    'outputs/df-local-server/dfserver/legacy_ds_actor_fields.py',
    'outputs/df-local-server/dfserver/legacy_ds_scalar_serializers.py',
    'outputs/df-local-server/dfserver/legacy_ds_bit_archive.py',
    'outputs/df-local-server/dfserver/legacy_ds_wire_codec.py')


def _read(root, relative):
    if (type(relative) is not str or not relative or ':' in relative or '\\' in relative or
            PurePosixPath(relative).is_absolute() or
            any(p in ('', '.', '..') for p in relative.split('/'))):
        raise ValueError('Restart evidence requires a plain project-relative path')
    try:
        path = (root / relative).resolve(strict=True)
        if not path.is_relative_to(root) or not path.is_file() or not 0 < path.stat().st_size <= 1024 * 1024:
            raise ValueError('Restart source is missing or outside its bound')
        raw = path.read_bytes()
    except OSError as error:
        raise ValueError('Restart source could not be read') from error
    return raw, hashlib.sha256(raw).hexdigest()


def _validate(spec):
    qualification = spec.get('qualification', {})
    if (spec.get('kind') != 'source_qualified_pc_restart_rpc_profile' or
            spec.get('client_sha256') != SHIPPING_SHA256 or spec.get('class_path') != CLASS_PATH or
            type(spec.get('exclusive_index_maximum')) is not int or spec['exclusive_index_maximum'] != 245 or
            spec.get('internal_ack') is not False or spec.get('export_mode') is not False or
            any(qualification.get(key) is not True for key in (
                'static_parameter_declaration_verified', 'static_function_flags_construction_verified',
                'static_object_serializer_binding_verified', 'native_parameter_grammar_recovered',
                'current_class_field_mapping_observed')) or
            any(qualification.get(key) is not False for key in (
                'runtime_function_parameter_layout_verified', 'native_dispatch_verified',
                'possession_verified', 'playable_map_verified'))):
        raise ValueError('Restart source qualification differs from the recovered build')
    functions = spec.get('functions')
    expected = (('ClientRestart', 42, CLIENT_FUNCTION_FLAGS, 'NewPawn'),
                ('ServerAcknowledgePossession', 67, SERVER_FUNCTION_FLAGS, 'P'))
    if type(functions) is not list or len(functions) != 2:
        raise ValueError('Restart requires exactly its two qualified RPC declarations')
    for row, (name, index, flags, parameter_name) in zip(functions, expected):
        parameters = row.get('parameters', [])
        if (row.get('name') != name or type(row.get('rep_index')) is not int or row['rep_index'] != index or
                type(row.get('function_flags')) is not int or row['function_flags'] != flags or
                type(row.get('parameter_struct_size')) is not int or row['parameter_struct_size'] != 8 or
                type(row.get('parameter_parent_count')) is not int or row['parameter_parent_count'] != 1 or
                type(parameters) is not list or len(parameters) != 1):
            raise ValueError('Restart function flags or one-Pawn parameter declaration changed')
        parameter = parameters[0]
        if (parameter.get('name') != parameter_name or parameter.get('expected_class') != 'Pawn' or
                any(type(parameter.get(key)) is not int or parameter[key] != value for key, value in (
                    ('data_offset', 0), ('array_dimension', 1), ('memory_size', 8), ('generation_type', 18))) or
                parameter.get('property_flags') != '0x0010000000000080' or
                parameter.get('object_class_getter_rva') != '0x133a1780' or
                parameter.get('property_vtable_rva') != '0x15a86b80' or
                parameter.get('serializer_target_rva') != '0x10e8ed20' or
                parameter.get('field_class_flags') != '0x04018001' or
                parameter.get('rpc_presence_required') is not True):
            raise ValueError('Restart Pawn serializer or presence grammar changed')
    rules = spec.get('wire_rules', {})
    if (rules.get('parameter_presence_bits') != 1 or
            rules.get('object_value_encoding') != 'ordinary_unaligned_packed_uint32_netguid' or
            rules.get('argument_null_supported_by_local_subset') is not False or
            rules.get('property_rep_layout_framing_used') is not False or
            rules.get('parameter_termination') != 'exact_eof' or
            rules.get('guid2_parameter_payload_hex') != '0900' or rules.get('guid2_parameter_payload_bits') != 9):
        raise ValueError('Restart RPC value framing changed')


def qualified_pc_restart_sources(root):
    """Pin declarations, code, static data, observed indices and current modules."""
    root = Path(root).resolve(strict=True)
    raw, digest = _read(root, SPEC_PATH)
    if digest != SPEC_SHA256:
        raise ValueError('Restart declaration source seal changed')
    try:
        spec = json.loads(raw)
        _validate(spec)
    except (TypeError, KeyError, ValueError) as error:
        raise ValueError('Restart source is not a qualified native declaration') from error
    pins = {SPEC_PATH: digest}
    files = spec.get('source_files')
    if type(files) is not list or not 1 <= len(files) <= 96:
        raise ValueError('Restart native evidence list exceeds its bound')
    for row in files:
        relative = row.get('relative_path')
        _, actual = _read(root, relative)
        if actual != row.get('sha256') or relative in pins:
            raise ValueError('Restart native source identity changed or is duplicated')
        pins[relative] = actual
    if OBSERVATION_PATH not in pins:
        raise ValueError('Restart ClassNetCache observation is missing')
    observation = json.loads(_read(root, OBSERVATION_PATH)[0])
    expected_fields = [('ClientRestart', 42), ('ServerAcknowledgePossession', 67)]
    fields = observation.get('fields', [])
    if (observation.get('client_sha256') != SHIPPING_SHA256 or
            observation.get('class_name') != 'BP_DFMPlayerController_C' or
            observation.get('exclusive_index_maximum') != 245 or
            [(row.get('descriptor_name'), row.get('rep_index')) for row in fields] != expected_fields or
            any(row.get('descriptor_representation') != 1 or row.get('incompatible') is not False
                for row in fields)):
        raise ValueError('Restart fields differ from their existing native class-cache observation')
    for relative in MODULES:
        _, pins[relative] = _read(root, relative)
    if hashlib.sha256(Path(__file__).read_bytes()).hexdigest() != pins[MODULES[0]]:
        raise ValueError('Restart helper was imported from another checkout')
    return pins


def load_pc_restart_profile(root, sealed_sources):
    """Construct the fixed profile only after checking the caller's source seal."""
    if type(sealed_sources) is not dict:
        raise ValueError('An explicit caller-sealed restart source dictionary is required')
    pins = qualified_pc_restart_sources(root)
    if any(sealed_sources.get(relative) != digest for relative, digest in pins.items()):
        raise ValueError('Restart sources changed after caller sealing')
    return PCRestartProfile(CLASS_PATH, 245, 42, 67,
        CLIENT_FUNCTION_FLAGS, SERVER_FUNCTION_FLAGS, SPEC_SHA256,
        NativeScalarBinding(SHIPPING_SHA256, OBJECT_SERIALIZER_RVA,
            property_vtable_rva=OBJECT_PROPERTY_VTABLE_RVA))
