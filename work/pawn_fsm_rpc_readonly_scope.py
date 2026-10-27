"""Current Pawn startup RPC metadata through the existing-only weak-key reader."""
import hashlib
import json
import struct
from copy import deepcopy

import export_native_replication_metadata as exporter
from observe_owned_gameplay_metadata import ROOT, SHIPPING_SHA256, address, source_pins as gameplay_sources
from skill_rpc_layout_readonly_scope_v2 import private_function, source_pins as weak_key_sources

PAWN_CLASS = '/Game/BluePrints/Characters/BP_DFMCharacter.BP_DFMCharacter_C'
FUNCTION_NAME = 'ServerReceiveFSMTransitionEvent'
CAPTURE = 'work/native-client-tests/1792478435036855300/owned-fsm-metadata.json'
FOLDER = 'work/evidence/model-init-chain-20261018/'
UHT = FOLDER+'native-current-pawn-fsm-character-base-uht-v1.json'
OWNER = FOLDER+'native-current-pawn-fsm-native-owner-class-body-v1.json'
PINS = {
    CAPTURE: '1cecf3eb9b10a2cdb21370d7257af9a11c98ceed6504db488d30adb9a5891590',
    UHT: 'cf200cc36bbcaa341cc3171c8f1df248004a6b946a1f77f2e400923536c44f5d',
    OWNER: 'd2227314a830d81aacd0125a21f79f1921a44caa61bc7af70d76d1f34ab4c865',
}
SIGNATURE = ('rep_index', 'descriptor_name', 'descriptor_representation', 'checksum', 'incompatible')


def source_contract():
    sources = {}
    for relative, digest in PINS.items():
        raw = (ROOT/relative).read_bytes()
        if hashlib.sha256(raw).hexdigest() != digest:
            raise ValueError('The source-qualified Pawn FSM RPC evidence changed: '+relative)
        sources[relative] = json.loads(raw)
        if sources[relative].get('client_sha256') != SHIPPING_SHA256:
            raise ValueError('The Pawn FSM RPC source belongs to another native build')
    capture, uht, owner = (sources[path] for path in (CAPTURE, UHT, OWNER))
    if (capture.get('status') != 'observed' or capture.get('identities_and_fields_rechecked') is not True or
            uht.get('process_access') is not False or owner.get('process_access') is not False):
        raise ValueError('Rechecked capture and offline native declarations are required')
    pawn, = [o for o in capture['objects'] if o['class_path'] == PAWN_CLASS]
    cache = pawn['existing_driver_class']
    if cache.get('cache_status') != 'exported_existing':
        raise ValueError('The captured actual Pawn ClassNetCache is unavailable')
    row, = [f for n in cache['cache_nodes'] for f in n['fields'] if f.get('descriptor_name') == FUNCTION_NAME]
    if row['descriptor_representation'] != 1 or row['incompatible'] is not False:
        raise ValueError('The captured Pawn startup RPC is not a compatible Function')
    declaration, = [f for c in uht['classes'] for f in c['net_function_declarations'] if f['name'] == FUNCTION_NAME]
    params = {p['name']: (p['native_gen_flags'], p['native_member_offset']) for p in declaration['parameters']}
    if (declaration['function_params_rva'] != '0x1cd052f0' or declaration['native_param_bytes'] != 2 or
            params != {'Event': ('0x0', '0x0'), 'bUpdateFSMImmediately': ('0x4c', '0x1')}):
        raise ValueError('The native Pawn startup RPC declaration changed')
    literals = {r.get('immutable_literal_candidate') for f in owner['functions']
        for i in f['instructions'] for r in i.get('rip_references', [])}
    if not {'GPCharacterBase', '/Script/GPGameplay'} <= literals:
        raise ValueError('The native startup RPC declaring class is not source-qualified')
    if exporter.RPC_LAYOUT_TABLE_OFFSET != 0x430 or exporter.RPC_FUNCTION_FLAGS_OFFSET != 0xc0:
        raise ValueError('The source-qualified existing FunctionRepLayout offsets changed')
    return dict(target={key: row[key] for key in SIGNATURE},
        exclusive_index_maximum=cache['exclusive_index_maximum'],
        function_flags=int(declaration['function_flags'], 16), native_param_bytes=declaration['native_param_bytes'],
        function_owner_path='/Script/GPGameplay.GPCharacterBase',
        key_kind='weak_object_index_and_serial', runtime_parameter_codec_claimed=False)


def source_pins():
    source_contract()
    pins = dict(gameplay_sources(), **weak_key_sources(), **PINS)
    for relative in ('work/pawn_fsm_rpc_readonly_scope.py', 'work/observe_owned_pawn_fsm_rpc_layouts.py'):
        pins[relative] = hashlib.sha256((ROOT/relative).read_bytes()).hexdigest()
    return pins


def qualify_pawn_owner(identity, class_path):
    if class_path != PAWN_CLASS or identity.get('is_cdo') is not False:
        raise ValueError('The exact current non-CDO owning Pawn class is required')


def export_existing_pawn_fsm_rpc_layouts(session, module_base, driver_address, existing, *,
        object_identity, object_path, _final_recheck_sink=None):
    contract = source_contract()
    nodes = existing.get('cache_nodes', [])
    if (existing.get('cache_status') != 'exported_existing' or
            existing.get('exclusive_index_maximum') != contract['exclusive_index_maximum'] or
            type(nodes) is not list or len(nodes) > 32):
        raise ValueError('The current Pawn cache differs from its captured complete interval')
    fields = [f for node in nodes for f in node['fields']]
    if len(fields) > 2048:
        raise ValueError('The current Pawn ClassNetCache field bound was exceeded')
    expected = contract['target']
    rows = [f for f in fields if f['rep_index'] == expected['rep_index'] or
        f.get('descriptor_name') == FUNCTION_NAME]
    if rows and (len(rows) != 1 or any(rows[0].get(k) != v for k, v in expected.items())):
        raise ValueError('The current Pawn startup RPC mapping differs from its source-qualified cache')

    owners = {}

    def typed_identity(at, kind):
        current = object_identity(at, kind)
        if kind == 'Function' and (current.get('name') != FUNCTION_NAME or
                current.get('is_cdo') is not False or 'Function' not in current.get('class_ancestry', [])):
            raise ValueError('The startup RPC name or Function class changed')
        if kind == 'Function':
            outer = address(current['outer_address'])
            owner = object_identity(outer, 'Class')
            path = object_path(outer)
            if (address(owner['address']) != outer or owner.get('is_cdo') is not False or
                    'Class' not in owner.get('class_ancestry', []) or
                    type(owner.get('serial')) is not int or owner['serial'] < 0 or
                    type(path) is not str or not 0 < len(path) <= 4096 or
                    path != contract['function_owner_path'] or
                    owners.setdefault(outer, deepcopy(owner)) != owner or
                    object_identity(outer, 'Class') != owner or object_path(outer) != path or
                    object_identity(at, kind) != current):
                raise ValueError('The startup RPC declaring Class identity or path changed')
        return current

    scoped = private_function(exporter.export_existing_pc_rpc_layouts,
        CONNECTION_RPC_LAYOUT_TARGETS={expected['rep_index']: FUNCTION_NAME})
    result = scoped(session, module_base, driver_address, nodes, object_identity=typed_identity,
        _final_recheck_sink=_final_recheck_sink)
    checked = []
    for row in result:
        row.update(key_kind=contract['key_kind'], weak_serial_assignment_invoked=False,
            pointer_key_substituted=False, layout_absence_established=False)
        if row['status'] == 'missing_current_cache_field':
            continue
        at, before = row['descriptor_address'], row['identity_qualification']
        row.update(declaring_owner_class_path=contract['function_owner_path'],
            declaring_owner_identity_rechecked=True)
        flags = session.stable(at+exporter.RPC_FUNCTION_FLAGS_OFFSET, 4)
        if struct.unpack('<I', flags)[0] != contract['function_flags']:
            raise ValueError('The actual startup UFunction flags differ from the native declaration')
        if before['serial'] == 0:
            row.update(status='existing_function_without_initialized_weak_key',
                layout_status='not_queryable_uninitialized_weak_serial',
                flags_raw_u32=struct.unpack('<I', flags)[0], flags_source_offset=exporter.RPC_FUNCTION_FLAGS_OFFSET,
                native_weak_key_construction_would_assign_serial=True)
        else:
            key = struct.pack('<iI', before['object_index'], before['serial'])
            if row['function_key'] != key.hex():
                raise ValueError('The actual Function layout key is not its exact index/serial identity')
            row['layout_absence_established'] = row['layout_table_read'] and row['layout_status'] == 'missing'
        checked.append((at, before, flags))

    def final_recheck():
        for at, before, flags in checked:
            if (typed_identity(at, 'Function') != before or
                    session.read(at+exporter.RPC_FUNCTION_FLAGS_OFFSET, 4) != flags):
                raise ValueError('The startup RPC Function identity or flags changed before publication')

    final_recheck()
    if _final_recheck_sink is not None:
        _final_recheck_sink.append(final_recheck)
    return result
