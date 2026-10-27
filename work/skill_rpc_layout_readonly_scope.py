"""Exact current DFMSkill FunctionRepLayouts through the existing-only reader.

Only Python target selection is specialized. The original metadata reader code,
native table/flags offsets, weak-key lookup, layout reader and final rechecks
remain in use. No native getter, layout construction or instance args are used.
"""
import hashlib
import json
from pathlib import Path
from types import FunctionType

import export_native_replication_metadata as exporter
from observe_owned_gameplay_metadata import ROOT, SHIPPING_SHA256, source_pins as gameplay_sources, address

SKILL_CLASS = '/Script/DFMGameplay.DFMSkillComponent'
PAWN_CLASS = '/Game/BluePrints/Characters/BP_DFMCharacter.BP_DFMCharacter_C'
CAPTURE = 'work/native-client-tests/1792460999986794500/owned-skill-entity-metadata.json'
UHT = 'work/evidence/skill-activation-authority-20261020-v1/native-gp-skill-uht-contract.json'
LOOKUP = 'work/evidence/map-system-audit-20261018/native-economy-interaction-existing-rpc-layout-lookup-v1.json'
PINS = {
    CAPTURE: '4f8becd08f296f36a219cdb31f9498d4e9b301fca74495f2f43def17a7ac2e29',
    UHT: '68e8571706b918889dc3d38a3c2848f7b2d9375c224244b792f4eb2b816b9f71',
    LOOKUP: '6a1e96b58549324868c549adbe57f024aa5a13447ff4a517725f53b04704cd6f',
}
TARGETS = {27: 'RPC_CastSkillFailed', 28: 'RPC_CastSkillSeccess', 30: 'ServerActivateState',
           31: 'ServerActivateSucess', 38: 'ServerEnterFSM'}
SIGNATURE = ('rep_index', 'descriptor_name', 'descriptor_representation', 'checksum', 'incompatible')
DECLARATION = ('name', 'storage_offset', 'element_bytes', 'array_dimension', 'property_flags',
    'field_vtable_rva', 'native_property_type', 'declared_native_class', 'declared_native_class_path',
    'declaring_class')


def _sealed(relative):
    raw = (ROOT/relative).read_bytes()
    if hashlib.sha256(raw).hexdigest() != PINS[relative]:
        raise ValueError('The fixed skill RPC source changed: '+relative)
    return json.loads(raw)


def source_contract():
    capture, uht, lookup = (_sealed(path) for path in (CAPTURE, UHT, LOOKUP))
    if (any(doc.get('client_sha256') != SHIPPING_SHA256 for doc in (capture, uht, lookup)) or
            capture.get('identities_and_fields_rechecked') is not True or
            uht.get('process_access') is not False or lookup.get('process_access') is not False or
            exporter.RPC_LAYOUT_TABLE_OFFSET != 0x430 or exporter.RPC_FUNCTION_FLAGS_OFFSET != 0xc0 or
            not any(i.get('rva') == '0x12b90978' and i.get('operands') == 'rcx, [r15 + 0x430]'
                for f in lookup['functions'] for i in f['instructions'])):
        raise ValueError('The existing-only FunctionRepLayout source or same-build root changed')
    skill, = [o for o in capture['objects'] if o['class_path'] == SKILL_CLASS and o['identity']['name'] == 'DFMSkill']
    pawn, = [o for o in capture['objects'] if o['class_path'] == PAWN_CLASS]
    if skill['existing_driver_class']['exclusive_index_maximum'] != 98:
        raise ValueError('The captured derived DFMSkill ClassNetCache interval changed')
    fields = [f for n in skill['existing_driver_class']['cache_nodes'] for f in n['fields']]
    selected, flags = [], {}
    for index, name in TARGETS.items():
        row, = [f for f in fields if f['rep_index'] == index and f['descriptor_name'] == name]
        if row['descriptor_representation'] != 1 or row['incompatible'] is not False:
            raise ValueError('The observed skill RPC is not one compatible Function')
        declaration, = [f for c in uht['classes'] for f in c['net_function_declarations'] if f['name'] == name]
        flags[name] = int(declaration['function_flags'], 16)
        selected.append({key: row[key] for key in SIGNATURE})
    field, = [dict(f, declaring_class=c['class_name']) for c in pawn['declarations']
        for f in c['fields'] if f['name'] == 'DFMSkillComponent']
    return dict(targets=selected, flags=flags, pawn_binding={key: field[key] for key in DECLARATION})


def source_pins():
    source_contract()
    pins = dict(gameplay_sources(), **PINS)
    for relative in ('work/skill_rpc_layout_readonly_scope.py', 'work/observe_owned_skill_rpc_layouts.py'):
        pins[relative] = hashlib.sha256((ROOT/relative).read_bytes()).hexdigest()
    return pins


def qualified_skill_field(declarations):
    expected = source_contract()['pawn_binding']
    rows = [dict(f, declaring_class=c['class_name']) for c in declarations
        for f in c['fields'] if f['name'] == expected['name']]
    if len(rows) != 1 or any(rows[0].get(key) != value for key, value in expected.items()):
        raise ValueError('The actual owning Pawn skill property differs from its sealed declaration')
    return rows[0]


def qualify_skill_owner(identity, class_path, pawn):
    if (class_path != SKILL_CLASS or identity.get('name') != 'DFMSkill' or
            identity.get('is_cdo') is not False or address(identity['outer_address']) != address(pawn)):
        raise ValueError('DFMSkill must be the current exact Pawn-owned non-CDO native instance')


def export_existing_skill_rpc_layouts(session, module_base, driver_address, existing, *,
        object_identity, _final_recheck_sink=None):
    contract = source_contract()
    nodes = existing.get('cache_nodes', [])
    if (existing.get('cache_status') != 'exported_existing' or
            existing.get('exclusive_index_maximum') != 98 or type(nodes) is not list or len(nodes) > 32):
        raise ValueError('The current derived DFMSkill existing cache is unavailable or outside its bound')
    fields = [f for node in nodes for f in node['fields']]
    if len(fields) > 256:
        raise ValueError('The current DFMSkill cache field bound was exceeded')
    for expected in contract['targets']:
        rows = [f for f in fields if f['rep_index'] == expected['rep_index'] or
                f.get('descriptor_name') == expected['descriptor_name']]
        if rows and (len(rows) != 1 or any(rows[0].get(k) != v for k, v in expected.items())):
            raise ValueError('The current skill RPC Function mapping differs from its source-qualified cache')
    original = exporter.export_existing_pc_rpc_layouts
    namespace = dict(original.__globals__, CONNECTION_RPC_LAYOUT_TARGETS=dict(TARGETS))
    # A private Python globals dictionary keeps the shared exporter's PC scope untouched.
    scoped = FunctionType(original.__code__, namespace, original.__name__, original.__defaults__, original.__closure__)
    scoped.__kwdefaults__ = dict(original.__kwdefaults__ or {})
    result = scoped(session, module_base, driver_address, nodes, object_identity=object_identity,
        _final_recheck_sink=_final_recheck_sink)
    for row in result:
        if 'flags_raw_u32' in row and row['flags_raw_u32'] != contract['flags'][row['function_name']]:
            raise ValueError('The actual skill UFunction flags differ from the exact native declaration')
    return result
