"""Bounded current-build PC RPC recipes from exact sealed declaration sources.

Qualification checks supplied bytes only. It performs no I/O and establishes
neither active PackageMap dispatch nor a runtime cache, CDO or RPC acceptance.
Input reports are immutable evidence; their former collector executables are
not runtime dependencies of these pure recipes.
"""
from dataclasses import dataclass, field
from enum import Enum
import hashlib
import json

from dfserver.transport.native.legacy_ds_bit_archive import BitWriter, UINT32_MAX
from dfserver.replication.legacy_ds_scalar_serializers import NativeScalarBinding


CURRENT_CLIENT_SHA256 = '79fb7b105170141ed863331d36833a73062e66bf5291b2364fe3a64c18336203'
CURRENT_RPC_SOURCE_PATH = 'work/research_updated_minimum_rpc_declarations_79fb7b10_v1.json'
CURRENT_RPC_SOURCE_SHA256 = '246c6bdbf856f638c84d3f8916ac41773c38c8f7e53b8e1fcc25e657c52a9909'
CURRENT_RPC_RECEIVE_SOURCE_PATH = 'work/research_updated_rpc_receive_79fb7b10_v2.json'
CURRENT_RPC_RECEIVE_SOURCE_SHA256 = '7463766d9602b3b96bbaa2451bcdc5c4580142f9de00463db502b5ee39c8022c'
CURRENT_PC_CLASS_PATH = '/Game/BluePrints/Characters/BP_DFMPlayerController.BP_DFMPlayerController_C'
CURRENT_PC_CACHE_MAXIMUM = 244
CURRENT_OBJECT_SERIALIZER_RVA = 0x10e8e6c0
CURRENT_OBJECT_VTABLE_RVA = 0x15a86a90
MAX_SOURCE_BYTES = 32 * 1024 * 1024
MAX_TOTAL_SOURCE_BYTES = 64 * 1024 * 1024

_INPUTS = {
    'work/research_updated_native_registration_79fb7b10_v4.json': 'e50210e8b851275204ab95ae67caedf3e03ef76353776387834578136bbda663',
    'work/research_updated_source_map_schema_79fb7b10_v1.json': 'ed591569846bb22602dbbe6571de72720b87e93f2ebb12da5dfff412696f4d27',
    'work/research_updated_deferred_struct_ops_79fb7b10_v1.json': '60426a191620a7149ffd50e34e43d858295f690ced63125f7446317363fc621e',
    'work/research_updated_ename_bindings_79fb7b10_v3.json': '4b4fc6de5a4722034517cafa60b1186f2b1d859a0aab086d3c8751126c2e73d1',
}
_HELPERS = {
    'work/research_updated_minimum_rpc_declarations.py': '29f167460654ab68c5abe0b6b5a7bf2f986b9df4aa16c7a385daf4dcec50b23a',
    'work/research_updated_native_registration.py': 'f353be3a12323d7343bf1ab66e956a5136386867db810d7dcdcc8d3627e806aa',
    'work/research_updated_minimum_leaf_bindings.py': 'e5112aae016068564d0b12c5530bb7291490d1dc7b6e7a34a6408c391f979ba2',
    'work/research_updated_enum_widths.py': 'ec8ae850fe89ce42cf1c2f5ca232e6fcdd6735c4c68f721a59030aa7f7e3035e',
}
_RECEIVE_INPUTS = {
    CURRENT_RPC_SOURCE_PATH: CURRENT_RPC_SOURCE_SHA256,
    'work/research_updated_command_shapes_79fb7b10_v1.json': '68471964b153ab566619c123fe03b53f5ac1e7221f4f74697ad3b2aaf9476989',
}
_RECEIVE_HELPERS = {
    'work/research_updated_rpc_receive.py': '954dcce05731b69c02aedaba8b8574aae8013ccd922e2bb72982a00c1fc27673',
    'work/research_updated_native_registration.py': _HELPERS['work/research_updated_native_registration.py'],
    'work/research_updated_replication_core.py': '3f9938b62167eba78650c869261f9e6e76f2e8582e058134d9f2739ca5af7c83',
    'work/research_updated_serializer_bindings.py': 'a8ff247cc4444700b3474127a9fb3ab05b87a077af795ef221b193ae6f406812',
}
_REQUIRED = {**_INPUTS, **_HELPERS, **_RECEIVE_INPUTS, **_RECEIVE_HELPERS,
             CURRENT_RPC_RECEIVE_SOURCE_PATH: CURRENT_RPC_RECEIVE_SOURCE_SHA256}
_REQUIRED.pop(CURRENT_RPC_SOURCE_PATH)
_PINS = tuple(sorted({CURRENT_RPC_SOURCE_PATH: CURRENT_RPC_SOURCE_SHA256, **_REQUIRED}.items()))
_FUNCTIONS = {
    'ServerShortTimeout': (79, 0x80220cc0, ()),
    'Server_RcvACWorldTime': (150, 0x00220cc0, (('InACWorldTime', 'FFloatProperty'),)),
    'ServerFieldOfView': (216, 0x00280cc0, (('Value', 'FFloatProperty'),)),
    'NotifySeamlessLoginReady': (141, 0x00220cc0, (('bSeamlessEnter', 'FBoolProperty'),)),
    'ClientAckSeamlessLoginReady': (131, 0x01020cc0, ()),
    'ServerBouncePing': (151, 0x00220c40, (('ServerBouncePingParams', 'FStructProperty'),)),
    'ClientReturnPing': (138, 0x01020c40, (('ClientReturnPingParams', 'FStructProperty'),)),
    'ClientRestart': (42, 0x01020cc0, (('NewPawn', 'FObjectProperty'),)),
    'ServerAcknowledgePossession': (67, 0x80220cc0, (('P', 'FObjectProperty'),)),
    'ClientSetViewTarget': (53, 0x01020cc0, (('A', 'FObjectProperty'), ('TransitionParams', 'FStructProperty'))),
    'ServerVerifyViewTarget': (85, 0x80220cc0, ()),
    'ClientSetRotation': (14, 0x01820cc0, (('NewRotation', 'FStructProperty'), ('bResetCamera', 'FBoolProperty'))),
}
_STRUCTURES = {
    'ServerBouncePingParams': (('TC1', 'FDoubleProperty'), ('ClientPingInfo', 'FStructProperty')),
    'ClientPingInfo': (('ExactPing', 'FFloatProperty'), ('DeltaTS', 'FFloatProperty'),
        ('OldPing', 'FFloatProperty'), ('DeltaTC', 'FFloatProperty'), ('ClientDeltaTime', 'FFloatProperty')),
    'ClientReturnPingParams': (('ServerReturnedClientTimeStamp', 'FDoubleProperty'),
        ('DeltaTS', 'FDoubleProperty'), ('InServerTimeStamp', 'FFloatProperty')),
    'ViewTargetTransitionParams': (('BlendTime', 'FFloatProperty'), ('BlendFunction', 'FByteProperty'),
        ('BlendExp', 'FFloatProperty'), ('bLockOutgoing', 'FBoolProperty')),
    'Rotator': (('Pitch', 'FFloatProperty'), ('Yaw', 'FFloatProperty'), ('Roll', 'FFloatProperty')),
}


class _Seal(Enum):
    QUALIFIED = 1


@dataclass(frozen=True)
class CurrentPCRPCQualification:
    source_pins: tuple
    _seal: object = field(repr=False)

    def __post_init__(self):
        if self._seal is not _Seal.QUALIFIED or type(self.source_pins) is not tuple or self.source_pins != _PINS:
            raise ValueError('Exact validated current PC RPC sources are required')

    client_sha256 = CURRENT_CLIENT_SHA256
    source_sha256 = CURRENT_RPC_SOURCE_SHA256
    runtime_native_cache_observed = False
    native_acceptance_verified = False
    current_rpc_parameter_traversal_qualified = True
    selected_connection_archive_context_qualified = False
    selected_package_map_reference_dispatch_qualified = False

    def summary(self):
        return dict(kind='current_pc_rpc_source_recipe_qualification', client_sha256=self.client_sha256,
            source_sha256=self.source_sha256, validated_source_pins=dict(self.source_pins),
            current_rpc_parameter_traversal_qualified=True,
            selected_connection_archive_context_qualified=False,
            selected_package_map_reference_dispatch_qualified=False,
            runtime_native_cache_observed=False, native_acceptance_verified=False)


def _json(raw):
    def pairs(items):
        result = {}
        for key, value in items:
            if key in result:
                raise ValueError('Duplicate current RPC source key')
            result[key] = value
        return result
    def invalid_constant(value):
        raise ValueError('Non-finite current RPC source constant')
    try:
        return json.loads(raw, object_pairs_hook=pairs, parse_constant=invalid_constant)
    except (UnicodeError, RecursionError) as error:
        raise ValueError('Malformed current RPC source document') from error


def _source(raw, expected):
    if type(raw) is not bytes or not 0 < len(raw) <= MAX_SOURCE_BYTES or hashlib.sha256(raw).hexdigest() != expected:
        raise ValueError('Current RPC source bytes disagree with their exact SHA256')


def _fields(record, expected):
    fields = record['fields']
    if (type(fields) is not list or tuple((f['name'], f['kind']) for f in fields) != expected or
            any(type(f['array_dim']) is not int or f['array_dim'] != 1 or f['children'] for f in fields)):
        raise ValueError('Current RPC parameter declaration order or type disagrees')
    return fields


def _receive_contract(document):
    if (document.get('kind') != 'current_rpc_parameter_receive_source_qualification' or
            document.get('client_sha256') != CURRENT_CLIENT_SHA256 or
            document.get('source_inputs') != _RECEIVE_INPUTS or document.get('source_pins') != _RECEIVE_HELPERS or
            any(document.get(key) is not True for key in (
                'current_complete_receiver_equivalence', 'current_rpc_parameter_traversal_qualified',
                'current_rotator_net_serialize_code_equivalence', 'current_rotator_arithmetic_constants_qualified',
                'current_property_bindings_from_pinned_declarations'))):
        raise ValueError('The complete pinned current RPC receiver qualification is required')
    expected = {
        'rpc_parameter_receiver': ('0x12db9710', 1493),
        'rpc_recursive_command_receiver': ('0x12dc2740', 499),
        'rpc_array_command_receiver': ('0x12dc2400', 824),
        'function_layout_initialize': ('0x12db3000', 838),
        'recursive_command_builder': ('0x12d9b530', 1047),
        'rotator_net_bridge': ('0x10ab4820', 25),
        'rotator_compressed_shorts': ('0x10ab7da0', 588),
        'rotator_cpp_ops_net_serialize': ('0x10e3c4a0', 10),
    }
    functions = document['functions']
    if len(functions) != len(expected) or {f['name'] for f in functions} != set(expected):
        raise ValueError('All eight current RPC receiver and Rotator bodies are required')
    for function in functions:
        if ((function['new_rva'], function['bytes']) != expected[function['name']] or
                any(function.get(key) is not True for key in (
                    'full_linear_decode', 'all_non_reference_instruction_bytes_identical',
                    'internal_direct_control_flow_preserved',
                    'structure_displacements_and_nonaddress_immediates_are_not_masked'))):
            raise ValueError('A complete current RPC receiver body qualification disagrees')
    if document['ordinary_receive_model']['guard'] != (
            'Channel connection at channel+0x28: connection byte+0xb4 bit0 clear OR channel byte+0xb0 nonzero; '
            'the selected ordinary connection path must establish this guard.'):
        raise ValueError('The current RPC channel/connection guard ownership disagrees')
    shapes = document['derived_wire_shapes']
    if (shapes['ServerBouncePing']['bits'] != 225 or shapes['ClientReturnPing']['bits'] != 161 or
            shapes['FloatParameter']['bits'] != 33 or shapes['NativeBoolParameter']['bits'] != 1 or
            shapes['ClientSetViewTarget']['transition_present_bits'] != 69 or
            shapes['ClientSetViewTarget']['constructor_default_omission_qualified'] is not False or
            shapes['ClientSetRotation']['bits'] != '5+16*n where n is number of nonzero quantized axes' or
            tuple(c['bytes_hex'] for c in document['rotator_constants']) !=
                ('610b3643', '0000003f', '0000b43b')):
        raise ValueError('Current RPC body lengths or Rotator constants disagree')


def qualify_current_pc_rpc_sources(report_bytes, *, source_blobs):
    """Validate declarations, complete receiver proof and their fourteen pins.

    Callers retain the returned pins under their existing source leases.
    Nested reports are authenticated as exact evidence bytes, not reinterpreted
    as authorization to run their historical collectors.
    """
    _source(report_bytes, CURRENT_RPC_SOURCE_SHA256)
    if type(source_blobs) is not dict or len(source_blobs) > 256:
        raise ValueError('A bounded explicit RPC source-byte dictionary is required')
    document = _json(report_bytes)
    if (type(document) is not dict or document.get('kind') != 'current_minimum_startup_rpc_declarations' or
            document.get('client_sha256') != CURRENT_CLIENT_SHA256 or
            document.get('current_parameter_declaration_trees_complete') is not True or
            document.get('source_inputs') != _INPUTS or document.get('source_pins') != _HELPERS):
        raise ValueError('The complete pinned current RPC declaration report is required')
    total = len(report_bytes)
    for path, digest in _REQUIRED.items():
        raw = source_blobs.get(path)
        _source(raw, digest)
        total += len(raw)
        if total > MAX_TOTAL_SOURCE_BYTES:
            raise ValueError('Current RPC sources exceed the local byte bound')
        if path.endswith('.json') and _json(raw).get('client_sha256') != CURRENT_CLIENT_SHA256:
            raise ValueError('Current RPC input report build disagrees')
    if CURRENT_RPC_SOURCE_PATH in source_blobs:
        _source(source_blobs[CURRENT_RPC_SOURCE_PATH], CURRENT_RPC_SOURCE_SHA256)
    _receive_contract(_json(source_blobs[CURRENT_RPC_RECEIVE_SOURCE_PATH]))
    functions = document['functions']
    if len(functions) != len(_FUNCTIONS) or {f['name'] for f in functions} != set(_FUNCTIONS):
        raise ValueError('Exactly twelve selected current RPC declarations are required')
    for row in functions:
        index, flags, fields = _FUNCTIONS[row['name']]
        declaration = row['declaration']
        if (row['class_cache_index'] != index or row['exclusive_cache_index_maximum'] != 244 or
                int(declaration['function_flags'], 16) != flags or declaration['super_function_factory_rva'] is not None):
            raise ValueError('Current RPC cache index or direction flags disagree')
        _fields(declaration['parameters'], fields)
    structures = document['structures']
    if len(structures) != len(_STRUCTURES) or {s['name'] for s in structures} != set(_STRUCTURES):
        raise ValueError('The complete selected RPC nested structure graph is required')
    for row in structures:
        _fields(row['fields'], _STRUCTURES[row['name']])
        if row['name'] != 'Rotator' and row['cpp_struct_ops_source_binding']['struct_flag_0x400_after_prepare'] is not False:
            raise ValueError('Only the qualified flattened RPC structures are supported')
    enum, = document['byte_enums']
    if (enum['declaration']['name'] != 'EViewTargetBlendFunction' or
            enum['width_candidates']['byte_property_bit_widths'] != [3] or
            [(v['name'], v['value']) for v in enum['declaration']['enumerators']] !=
            [('VTBlend_Linear', 0), ('VTBlend_Cubic', 1), ('VTBlend_EaseIn', 2),
             ('VTBlend_EaseOut', 3), ('VTBlend_EaseInOut', 4), ('VTBlend_MAX', 5)]):
        raise ValueError('The exact current three-bit view transition enum is required')
    rotator = document['rotator_net_serializer_source']
    if (rotator['net_serialize_target_rva'] != '0x10e3c4a0' or
            rotator['struct_flag_0x400_after_prepare'] is not True):
        raise ValueError('The current compressed Rotator serializer binding is required')
    return CurrentPCRPCQualification(_PINS, _Seal.QUALIFIED)


def require_current_profile(qualification, *, class_path, exclusive_index_maximum, source_sha256):
    if type(qualification) is not CurrentPCRPCQualification:
        raise ValueError('An explicit source-qualified current PC RPC profile is required')
    qualification.__post_init__()
    if (class_path != CURRENT_PC_CLASS_PATH or type(exclusive_index_maximum) is not int or
            exclusive_index_maximum != CURRENT_PC_CACHE_MAXIMUM or source_sha256 != CURRENT_RPC_SOURCE_SHA256):
        raise ValueError('Current and historical PC RPC profiles cannot be mixed')


def require_current_object_binding(binding):
    if (type(binding) is not NativeScalarBinding or binding.client_sha256 != CURRENT_CLIENT_SHA256 or
            type(binding.serializer_target_rva) is not int or binding.serializer_target_rva != CURRENT_OBJECT_SERIALIZER_RVA or
            type(binding.property_vtable_rva) is not int or binding.property_vtable_rva != CURRENT_OBJECT_VTABLE_RVA or
            binding.scalar_leaf_target_rva is not None):
        raise ValueError('The exact current object property serializer/table is required')


def write_current_object_reference(writer, guid, *, qualification, binding, reference_resolved, exports_acknowledged):
    if type(qualification) is not CurrentPCRPCQualification:
        raise ValueError('Current RPC source qualification is required')
    qualification.__post_init__()
    require_current_object_binding(binding)
    if (type(writer) is not BitWriter or reference_resolved is not True or exports_acknowledged is not True or
            type(guid) is not int or not 0 <= guid <= UINT32_MAX or guid == 1):
        raise ValueError('An ordinary resolved and export-acknowledged current object GUID is required')
    writer.write_packed_int(guid)
