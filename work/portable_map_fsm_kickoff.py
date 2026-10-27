"""Pure empty ordinary content for the real Pawn default FSM component.

The caller owns fresh GUID allocation and actual transport receipts. This only
requests normal receiver metadata creation; it supplies no property handles.
"""
import argparse
import hashlib
import json
from pathlib import Path
import struct

from dfserver.legacy_ds_bit_archive import UINT32_MAX
from dfserver.legacy_ds_default_subobject import DefaultSubobjectUpdate
from dfserver.legacy_ds_rep_layout_refs import build_empty_rep_layout_content
from export_gameplay_component_probe_schema import build_schema as receive_schema

ROOT = Path(__file__).resolve().parent.parent
BASE = 'work/evidence/model-init-chain-20261018/'
CLIENT = '4254fbe66585f260f1f9dbfc5e302887842552e7baed8939e023160a5e250be0'
CAPTURE = 'work/native-client-tests/1792376752204334900/owned-fsm-metadata-retry1.json'
PINS = {
    CAPTURE: 'ee1db93f1526fd1d80311bfa0c11c0b7d5df5c2f764c6990714afdc53ec6d6bd',
    BASE+'native-current-skill-main-fsm-cooked-contract-v1.json':
        'f9deebf95291c8c90b26b6d8f86e20c2dd02df6fc669383b23fec13da785a9ca',
    BASE+'native-current-fsm-native-bindings-v1.json':
        '972f54a23a5d3d32f4d6f99af8231dd72683370e7d69950f768d3861487e5e07',
    BASE+'native-current-fsm-stable-name-vtable-v1.json':
        '9c2564219e8d37134d461f6ed91d65e0cc9731a497a1a3dc55ec4505b44e32f7',
}
SCHEMA_SHA256 = 'e8ff3d1cee81134e7a498cf32ddbc121342f693e5b57cae43b3a99a2d9127617'
SCHEMA_PATH = BASE+'native-current-fsm-empty-kickoff-contract-v1.json'
COMPONENT_CLASS = '/Script/GPGameplay.GPFSMStateMachineComponent'


def _sealed(relative, digest):
    path = (ROOT/relative).resolve()
    if not path.is_relative_to(ROOT.resolve()):
        raise ValueError('The FSM kickoff source escaped the project')
    raw = path.read_bytes()
    if hashlib.sha256(raw).hexdigest() != digest:
        raise ValueError('The FSM kickoff source changed: '+relative)
    return json.loads(raw)


def _canonical(document):
    return (json.dumps(document, indent=2, sort_keys=True)+'\n').encode()


def derive_schema():
    common = receive_schema()
    docs = {path: _sealed(path, digest) for path, digest in PINS.items()}
    pins = dict(common['sources'], **PINS)
    for source in common['cooked_sources']:
        pins[source['relative_path']] = source['sha256']
    capture = docs[CAPTURE]
    if (capture.get('client_sha256') != CLIENT or capture.get('status') != 'partial' or
            capture.get('identities_and_fields_rechecked') is not True or
            capture.get('process_memory_written') is not False or
            capture.get('native_methods_invoked') is not False):
        raise ValueError('The FSM kickoff requires the actual rechecked current metadata source')
    component, = [o for o in capture['objects'] if o['class_path'] == COMPONENT_CLASS]
    pawn, = [o for o in capture['objects'] if o['class_path'] == common['pawn_class_path']]
    identity, info = component['identity'], component['object_metadata']
    lifecycle = capture['scopes']['component']['state']['lifecycle']
    instance = capture['scopes']['component']['state']['R_Instance']
    if (identity['name'] != 'GPFSMStateMachine' or identity['is_cdo'] is not False or
            identity['outer_address'] != pawn['identity']['address'] or
            info['default_subobject_flag_present'] is not True or
            info['class_default_object_flag_present'] is not False or
            int(info['object_flags'], 16) & 0x40000 == 0 or
            lifecycle['creation_method']['raw'] != '0x0' or instance['status'] != 'null_reference'):
        raise ValueError('The actual FSM default-subobject/Outer/creation scope changed')
    cooked = docs[BASE+'native-current-skill-main-fsm-cooked-contract-v1.json']
    entry, = [e for e in cooked['entries'] if e['export']['name'] == identity['name']]
    export = entry['export']
    if (export['class_path'] != COMPONENT_CLASS or export['index'] != 104 or
            export['outer_index'] != 47 or export['template_path'] !=
            '/Script/SOL.Default__SOLCharacter.GPFSMStateMachine' or
            any(p['name'] == 'CreationMethod' for p in entry['properties'])):
        raise ValueError('The cooked FSM default identity changed')
    header_source, = [s for s in common['cooked_sources'] if s['relative_path'].endswith('.uasset')]
    header = (ROOT/header_source['relative_path']).read_bytes()
    flags, = struct.unpack_from('<I', header, export['record_offset']+24)
    if flags != 0x40029:
        raise ValueError('The cooked FSM default-subobject object flags changed')
    binding = docs[BASE+'native-current-fsm-native-bindings-v1.json']
    vtables = docs[BASE+'native-current-fsm-stable-name-vtable-v1.json']
    table, = [v for v in vtables['vtables'] if v['rva'] == binding['gp_component_vtable_rva']]
    slot, = [e for e in table['entries'] if e['slot'] == '0x1c0']
    if (vtables['client_sha256'] != CLIENT or vtables['process_access'] is not False or
            binding['gp_component_vtable_rva'] != '0x15e568d0' or slot['target_rva'] != '0x12707d00'):
        raise ValueError('The actual FSM native name-stability override changed')
    for source in binding['source_reports']:
        _sealed(source['relative_path'], source['sha256'])
        pins[source['relative_path']] = source['sha256']
    return dict(kind='source_qualified_empty_fsm_default_subobject_kickoff_v1', client_sha256=CLIENT,
        sources=pins, pawn_class_path=common['pawn_class_path'],
        component=dict(name='GPFSMStateMachine', class_path=COMPONENT_CLASS,
            pawn_binding_field='FSMComponent', pawn_binding_member_offset=0x1030,
            cooked_export_index=104, cooked_outer_export_index=47,
            cooked_object_flags=flags, default_subobject_flag_present=True, creation_method=0,
            stable_name_virtual_slot=0x1c0, stable_name_target_rva='0x12707d00',
            native_class_override_excluded_by_exact_vtable=True),
        receive_contract=common['receive_contract'], ordinary_property_handles=[],
        parent_open_ack_required=True, parent_content_ack_required=True,
        exact_kickoff_delivery_ack_required_before_dependent_fields=True,
        actual_class_layout_observation_required_before_property_encoding=True,
        source_runtime_state=dict(R_Instance='observed_null_reference', existing_class_layout='missing'),
        process_access=False, native_methods_invoked=False, packets_sent=False,
        native_acceptance_verified=False, gameplay_initialization_verified=False)


def schema_binding():
    result = derive_schema()
    if (hashlib.sha256(_canonical(result)).hexdigest() != SCHEMA_SHA256 or
            _sealed(SCHEMA_PATH, SCHEMA_SHA256) != result):
        raise ValueError('The pinned FSM kickoff schema changed')
    return result


def source_pins():
    result = dict(schema_binding()['sources'], **{SCHEMA_PATH: SCHEMA_SHA256})
    for path in ('work/portable_map_fsm_kickoff.py', 'work/export_gameplay_component_probe_schema.py',
            'outputs/df-local-server/dfserver/legacy_ds_default_subobject.py',
            'outputs/df-local-server/dfserver/legacy_ds_rep_layout_refs.py',
            'outputs/df-local-server/dfserver/legacy_ds_even_component_guid_exports.py',
            'outputs/df-local-server/dfserver/legacy_ds_actor_content.py',
            'outputs/df-local-server/dfserver/legacy_ds_bit_archive.py'):
        result[path] = hashlib.sha256((ROOT/path).read_bytes()).hexdigest()
    return result


def projection_qualification():
    """Declare delivery requirements without claiming runtime admission."""
    schema_binding()
    return dict(preflight_only=True, actual_receipts_observed=False,
        required_parent_open_and_content_ACK=True,
        runtime_stage_graph_must_enforce_parent_dependencies=True,
        exact_kickoff_delivery_ACK_required_before_dependent_fields=True,
        actual_class_layout_observation_required_before_property_encoding=True,
        native_acceptance_verified=False)


def project_fsm_kickoff_update(*, pawn_guid, component_guid, allocated_guids, existing_updates=()):
    """Preflight one source-qualified update before any runtime receipt exists.

    allocated_guids is the complete namespace before reserving component_guid.
    existing_updates also reserves every pending default Name/GUID in the group.
    Its runtime stage must require the exact parent open/content ACKs. The caller
    retains these exact bytes for retry and commits only the kickoff's real ACK.
    """
    schema = schema_binding()
    if (any(type(g) is not int or not 2 <= g <= UINT32_MAX or g & 1
                for g in (pawn_guid, component_guid)) or
            type(allocated_guids) is not tuple or not 1 <= len(allocated_guids) <= 65536 or
            any(type(g) is not int or not 2 <= g <= UINT32_MAX for g in allocated_guids) or
            len(set(allocated_guids)) != len(allocated_guids) or pawn_guid not in allocated_guids or
            component_guid in allocated_guids or type(existing_updates) is not tuple or
            len(existing_updates) >= 8 or any(type(u) is not DefaultSubobjectUpdate for u in existing_updates)):
        raise ValueError('The projected Pawn and a fresh GUID outside the complete namespace are required')
    names, guids = set(), set(allocated_guids)
    for update in existing_updates:
        update.__post_init__()
        if (update.actor_guid != pawn_guid or update.guid in guids or update.name in names or
                update.name == schema['component']['name']):
            raise ValueError('The pending default group conflicts with the FSM kickoff namespace')
        guids.add(update.guid)
        names.add(update.name)
    if component_guid in guids:
        raise ValueError('The fresh FSM GUID collides with a pending default component')
    block = build_empty_rep_layout_content()
    if block.payload_bit_count != 9 or block.payload != b'\0\0':
        raise ValueError('The ordinary no-field RepLayout slice changed')
    return DefaultSubobjectUpdate(pawn_guid, component_guid, schema['component']['name'],
        SCHEMA_SHA256, block.payload, block.payload_bit_count, True)


def build_fsm_kickoff_update(*, pawn_guid, component_guid, allocated_guids,
        existing_updates=(), current_pawn_bound=False, pawn_open_acknowledged=False,
        pawn_content_acknowledged=False):
    """Admit an update only with the caller's current actual parent receipts."""
    if (current_pawn_bound is not True or pawn_open_acknowledged is not True or
            pawn_content_acknowledged is not True):
        raise ValueError('The current Pawn and actual parent open/content ACKs are required')
    return project_fsm_kickoff_update(pawn_guid=pawn_guid, component_guid=component_guid,
        allocated_guids=allocated_guids, existing_updates=existing_updates)


def _plan(pawn_channel, update):
    if type(pawn_channel) is not int or not 2 <= pawn_channel <= 1023:
        raise ValueError('The current Pawn Actor channel is required')
    return dict(channel_index=pawn_channel, actor_guid=update.actor_guid,
        content_blocks=(build_empty_rep_layout_content(),), default_subobjects=(update,))


def project_fsm_kickoff_plan(*, pawn_channel, **kwargs):
    """Project a plan whose runtime stage must enforce the declared parent ACKs."""
    return _plan(pawn_channel, project_fsm_kickoff_update(**kwargs))


def build_fsm_kickoff_plan(*, pawn_channel, **kwargs):
    return _plan(pawn_channel, build_fsm_kickoff_update(**kwargs))


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Seal the empty FSM kickoff source schema')
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    output = args.output.resolve()
    if output.exists() or not output.is_relative_to((ROOT/'work/evidence').resolve()):
        parser.error('Use an exclusive new project evidence output')
    raw = _canonical(derive_schema())
    with output.open('xb') as stream:
        stream.write(raw)
    print(json.dumps(dict(output=str(output), sha256=hashlib.sha256(raw).hexdigest())))
