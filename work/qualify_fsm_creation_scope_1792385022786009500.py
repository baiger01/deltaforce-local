"""Seal current FSM class creation proof and exact missing property metadata."""
import argparse
import hashlib
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
FIRST = 'work/native-client-tests/1792385022786009500/owned-fsm-metadata.json'
FOLLOWUP = 'work/native-client-tests/1792385022786009500/owned-fsm-layout-followup-exclusive.json'
PINS = {FIRST: '1aa920e4db727a55e0c75cffc2bae533d83e27a9cd0d0ecb368489cebfa8f628',
    FOLLOWUP: '52f0fbe4fbdf2540103259b8e5425ef4f6d1ec0c42cbe8852b4838b8b70b771a'}
CLASS_PATH = '/Game/BluePrints/Characters/CharacterFSM/DFMCharacterFSM_Main.DFMCharacterFSM_Main_C'
CLIENT = '4254fbe66585f260f1f9dbfc5e302887842552e7baed8939e023160a5e250be0'
SNAPSHOTS = {
    ('work/export_native_replication_metadata.py', '1885b6ccc86dc5dd049ac22abc3ca7f2d7f9cee9c6eced8f430fd1f893ba3b89'):
        'work/evidence/model-init-chain-20261018/fsm-source-snapshot-1792385022786009500/export_native_replication_metadata.py',
    ('work/fsm_readonly_scope.py', '1bc3bfca9f232e2d240615fa17f6ef8a5bb73866c55c3bc6fd4f3b9bd64be2e7'):
        'work/evidence/model-init-chain-20261018/fsm-source-snapshot-1792385022786009500/fsm_readonly_scope.py',
    ('work/observe_owned_fsm_metadata.py', '5bac0947fa9a06b0eb8312060c765f956dcd6740a0ef6529d1dd94ee941651c3'):
        'work/evidence/model-init-chain-20261018/fsm-source-snapshot-1792385022786009500/observe_owned_fsm_metadata.py',
}


def _historical_source_path(relative, digest):
    selected = (ROOT/relative).resolve()
    if not selected.is_relative_to(ROOT):
        raise ValueError('The frozen current FSM dependency changed: '+relative)
    snapshot = SNAPSHOTS.get((relative, digest))
    if snapshot is not None:
        selected = (ROOT/snapshot).resolve()
    if not selected.is_relative_to(ROOT) or hashlib.sha256(selected.read_bytes()).hexdigest() != digest:
        raise ValueError('The frozen current FSM dependency changed: '+relative)
    return selected


def _sealed(relative,digest):
    path = (ROOT/relative).resolve()
    if not path.is_relative_to(ROOT) or hashlib.sha256(path.read_bytes()).hexdigest() != digest:
        raise ValueError('The exact current FSM evidence source changed: '+relative)
    return json.loads(path.read_bytes())


def _field(declarations,name):
    rows = [dict(field,declaring_class=group['class_name']) for group in declarations
        for field in group['fields'] if field['name'] == name]
    if len(rows) != 1:
        raise ValueError('One exact current FSM property declaration is required: '+name)
    return rows[0]


def _serializer(field,target):
    hook = field['hooks']['0x90']
    if (hook.get('inside_pinned_image') is not True or hook.get('identity_rechecked') is not True or
            hook.get('target_module_sha256') != CLIENT or hook.get('target_rva') != target):
        raise ValueError('The current FSM property serializer differs: '+field['name'])
    return hex(target)


def derive():
    first, follow = (_sealed(path,PINS[path]) for path in (FIRST,FOLLOWUP))
    pins = dict(PINS)
    for report in (first,follow):
        if (report.get('client_sha256') != CLIENT or report.get('pid') != 11500 or
                report.get('created_at') != 1792385029.5729253 or
                any(report.get(key) is not True for key in ('identities_and_fields_rechecked',
                    'selected_roots_rechecked','process_identity_rechecked')) or
                any(report.get(key) is not False for key in ('process_memory_written','native_methods_invoked','packets_sent'))):
            raise ValueError('The current FSM observation lacks exact owned/rechecked provenance')
        for path,digest in report['source_pins'].items():
            _sealed(path,digest) if path.endswith('.json') else None
            _historical_source_path(path, digest)
            if path in pins and pins[path] != digest:
                raise ValueError('The current FSM source graph conflicts')
            pins[path] = digest
    generated = follow['generated_instance_class']
    original = first['scopes']['component']['state']['StateMachineClass']
    if (generated['class_path'] != CLASS_PATH or generated['identity'] != original['identity'] or
            follow['current_R_Instance']['status'] != 'null_reference'):
        raise ValueError('The current class or null component reference changed between scoped captures')
    current = generated['generated_class_metadata']
    cdo = current['existing_cdo']
    if (current['reference_origin'] != 'component.StateMachineClass' or
            current['identities_and_fields_rechecked'] is not True or current['metadata_recheck_required'] is not False or
            current['is_actor_or_component'] is not False or cdo['status'] != 'existing_cdo_identity_verified' or
            cdo['class_matches_selected'] is not True or cdo['networking_virtual_slot'] != 0x1d0 or
            cdo['networking_virtual_target_rva'] != '0xd5c5d0' or
            cdo['networking_supported_by_exact_native_target'] is not True):
        raise ValueError('The exact current FSM class/CDO networking metadata is not qualified')
    component, = [r for r in follow['objects'] if r['class_path']=='/Script/GPGameplay.GPFSMStateMachineComponent']
    existing = component['existing_driver_class']
    fields = [f for node in existing['cache_nodes'] for f in node['fields'] if f['descriptor_name']=='R_Instance']
    if (existing['cache_status'] != 'exported_existing' or existing['layout_status'] != 'missing' or
            existing['exclusive_index_maximum'] != 16 or len(fields)!=1 or fields[0]['rep_index'] != 3 or
            fields[0]['descriptor_representation'] != 0 or fields[0]['incompatible'] is not False):
        raise ValueError('The exact current FSM component cache/missing-layout source changed')
    if any(row['existing_driver_class']['layout_status'] != 'missing'
            for chain in follow['ancestor_driver_metadata'].values() for row in chain):
        raise ValueError('An actual receiver layout is now available and requires separate qualification')
    instance_field = _field(component['declarations'],'R_Instance')
    context = _field(generated['declarations'],'R_StateMachineContext')
    started = _field(generated['declarations'],'R_bHasStarted')
    for field,offset in ((instance_field,0x1a8),(context,0x578),(started,0x664)):
        if field['storage_offset'] != offset or not int(field['property_flags'],16)&0x20:
            raise ValueError('The current FSM net property storage differs')
    if started['element_bytes'] != 1:
        raise ValueError('The actual started property element declaration differs')
    return dict(kind='current_fsm_creation_metadata_and_missing_layout_contract_v1',client_sha256=CLIENT,
        sources=pins,current_capture='1792385022786009500',process_access=False,
        empty_instance_creation=dict(current_class_and_cdo_metadata_qualified=True,class_path=CLASS_PATH,
            outer='current owning Pawn',default_subobject=False,instance_path_exported=False,
            networking_virtual_slot=0x1d0,networking_virtual_target_rva='0xd5c5d0',
            metadata_for_existing_creation_helper='StateMachineClass.generated_class_metadata',
            caller_still_requires_actual_class_export_and_Pawn_kickoff_ACKs=True),
        component=dict(declaring_class=instance_field['declaring_class'],name='R_Instance',storage_offset=0x1a8,
            serializer_rva=_serializer(instance_field,0x10e8ed20),native_property_type='FObjectProperty',
            class_net_cache_field_index=3,class_net_cache_exclusive_maximum=16,
            ordinary_property_handle=None,actual_RepLayout_status='missing'),
        context=dict(declaring_class=context['declaring_class'],name='R_StateMachineContext',storage_offset=0x578,
            serializer_rva=_serializer(context,0x10e8ed20),native_property_type='FObjectProperty',
            ordinary_property_handle=None,actual_class_cache_status='missing',actual_RepLayout_status='missing'),
        started=dict(declaring_class=started['declaring_class'],name='R_bHasStarted',storage_offset=0x664,
            serializer_rva=_serializer(started,0x10e8ebe0),native_property_type='FBoolProperty',
            property_element_bytes=1,native_value_read_bytes=4,native_value_mask=8,
            property_byte_masks_directly_observed=False,ordinary_property_handle=None,
            actual_class_cache_status='missing',actual_RepLayout_status='missing'),
        ordinary_property_codec_qualified=False,
        remaining=['actual component RepLayout parent/command/handle binding for R_Instance',
            'actual generated instance class RepLayout parent/command/handle bindings',
            'current started FBoolProperty descriptor ByteOffset/ByteMask/FieldMask metadata',
            'actual empty-instance creation GUID/object identity and Pawn Outer acceptance',
            'source-qualified context/reference/start RepNotify arrival sequence'],
        next_stage='export the current qualified main class, empty dynamic instance creation with Pawn Outer, then strict existing receiver metadata observation',
        process_memory_written=False,native_methods_invoked=False,packets_sent=False,native_gameplay_verified=False)


if __name__=='__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output',type=Path,required=True)
    args = parser.parse_args()
    output = args.output.resolve()
    if output.exists() or not output.is_relative_to((ROOT/'work/evidence').resolve()):
        parser.error('Use an exclusive new project evidence output')
    raw = (json.dumps(derive(),indent=2,sort_keys=True)+'\n').encode()
    with output.open('xb') as stream:
        stream.write(raw)
    print(json.dumps(dict(output=str(output),sha256=hashlib.sha256(raw).hexdigest())))
