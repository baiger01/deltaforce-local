"""Compare fresh updated property facts to sealed historical declarations.

Offline JSON analysis only. No runtime helper import, process access, native
call, schema activation or replacement of historical build identities occurs.
"""
import ast
import collections
import hashlib
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
OLD_SHA = '4254fbe66585f260f1f9dbfc5e302887842552e7baed8939e023160a5e250be0'
NEW_SHA = '79fb7b105170141ed863331d36833a73062e66bf5291b2364fe3a64c18336203'
NEW_CAPTURE = 'work/native-client-tests/1792800038357938800/updated-class-metadata.json'
OLD_CAPTURES = [
    'work/native-client-tests/1792304896147723900/owned-gameplay-metadata.json',
    'work/native-client-tests/1792314937287546900/owned-gameplay-metadata.json',
    'work/native-client-tests/1792460999986794500/owned-vitals-metadata.json',
]
INTERFACES = 'work/native-client-tests/1792297548603201600/owned-emptyhand-class-interface-cdo-metadata-final.json'
REPLICATION = 'work/evidence/updated-replication-core-79fb7b10.json'
SCHEMAS = [
    'outputs/df-local-server/protocol/portable-map-spawn/owned-weapon-schema-v3.json',
    'outputs/df-local-server/protocol/portable-map-spawn/owned-weapon-actor-schema.json',
    'work/evidence/map-system-audit-20261018/modular-weapon-actor-schema-v1.json',
    'outputs/df-local-server/protocol/portable-map-spawn/player-receiver-schema.json',
    'outputs/df-local-server/protocol/portable-map-spawn/vitals-metadata-probe-schema.json',
    'outputs/df-local-server/protocol/portable-map-spawn/rotation-schema.json',
    'work/evidence/map-system-audit-20261018/portable-weapon-switch-owner-rpc-schema-v1.json',
]
PINS = {
    NEW_CAPTURE: '4dc2803f2c41d4efdc2d93dc27487eb9a17880eb3796a87de6dd4f9586aa4168',
    OLD_CAPTURES[0]: '71a25ea64f873ba51b68a28b412755c92252d361498916eb0e5618e0add92827',
    OLD_CAPTURES[1]: '399d896dda740b768feb8e9e7bad40eab8d2798d27806731577a708704ca2873',
    OLD_CAPTURES[2]: '36f87df56c20a6f1dcdf25190fedc199415be07b0285028c246c9d1b5c0d695d',
    SCHEMAS[0]: '10e4c03ca3a0955b74d2a6c40b484f1757b645c787363f45e3584bac84c14624',
    SCHEMAS[1]: '502f98d5dd685afffed601e4baa6e95ae6e55671cc40c89024c839bb0ab7aac2',
    SCHEMAS[2]: '4399d3865172dd5b07e9355788b06032c4d82a658d48a65a9f90e9c0658e51c6',
    SCHEMAS[3]: '88eb799aa4dbc9667a320c8b95ba30af1b84fc5635a73a58bf3c7dd0ab56fe40',
    SCHEMAS[4]: 'acec9f0b1f31346933d48e410ab8c866efd9cbab0c0da144933eafae94b904aa',
    SCHEMAS[5]: '4db34bfa70e23c1f6d636dcefb659a75f2ed04e20e39a940bc7ca33660624b1b',
    SCHEMAS[6]: 'c0390175d3b9070aa7cc54d70b03c6820f5836624a12a5f88f56a483f8b1cd8a',
    INTERFACES: '3c04ac9792fc206aa1ceec1e526fda2e4071cebbfc4e8d0de19bc6a6153877da',
    REPLICATION: '762e8111b52e4bd4273489b0a9444adb2340c8a21fd6808cb23c1e1d6bb7cd58',
}
FACT_KEYS = ('storage_offset', 'array_dim', 'element_size', 'flags_low32')


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def historical_field(field):
    return dict(name=field['name'], storage_offset=field['storage_offset'],
        array_dim=field['array_dimension'], element_size=field['element_bytes'],
        flags_low32=int(field['property_flags'],16)&0xffffffff,
        rep_index=field['declared_rep_index'])


def walk(value, pointer=''):
    if isinstance(value, dict):
        yield pointer, value
        for key, child in value.items():
            escaped = str(key).replace('~','~0').replace('/','~1')
            yield from walk(child, pointer+'/'+escaped)
    elif isinstance(value, list):
        for index, child in enumerate(value):
            yield from walk(child, pointer+'/'+str(index))


def qualify():
    docs = {}
    for path, expected in PINS.items():
        raw = (ROOT/path).read_bytes()
        if sha(raw) != expected:
            raise ValueError('Pinned comparison source changed: '+path)
        docs[path] = json.loads(raw)
    fresh = docs[NEW_CAPTURE]
    if (fresh['client_sha256'] != NEW_SHA or fresh['complete'] is not True
            or fresh['class_fields_exported'] is not True
            or fresh['replication_handles_exported'] is not False
            or any(fresh[k] is not False for k in ('native_protocol_compatibility_verified',
                'process_memory_written','native_function_called','account_data_read'))):
        raise ValueError('Fresh property observation scope changed')
    current = {c['name']: c for c in fresh['selected_classes']}
    if len(current) != len(fresh['selected_classes']) or len(current) != 44:
        raise ValueError('Fresh class labels are ambiguous')
    producer = ROOT/'work/updated_client_metadata.py'
    producer_sha = sha(producer.read_bytes())
    if producer_sha != fresh['source_pins']['work/updated_client_metadata.py']:
        raise ValueError('Captured property reader source is no longer exact')
    old_fields, old_orders, examples = {}, {}, {}
    for path in OLD_CAPTURES:
        doc = docs[path]
        if (doc['client_sha256'] != OLD_SHA or doc['identities_and_fields_rechecked'] is not True
                or doc['process_memory_written'] is not False or doc['native_methods_invoked'] is not False):
            raise ValueError('Historical declaration observation scope changed')
        for collection in ('objects','loaded_named_classes'):
            for oi,obj in enumerate(doc.get(collection,[])):
                for di,decl in enumerate(obj['declarations']):
                    name = decl['class_name']
                    if name not in current:
                        continue
                    old_orders.setdefault(name,set()).add(tuple(f['name'] for f in decl['fields']))
                    for fi,field in enumerate(decl['fields']):
                        key = (name,field['name'])
                        pointer = f'/{collection}/{oi}/declarations/{di}/fields/{fi}'
                        item = dict(facts=historical_field(field), source=path, json_pointer=pointer,
                            old_property_flags64=field['property_flags'],
                            old_property_vtable_rva=hex(field['field_vtable_rva']),
                            old_hooks={slot: dict(target_rva=hex(hook['target_rva']),
                                inside_pinned_image=hook['inside_pinned_image'],
                                identity_rechecked=hook['identity_rechecked'])
                                for slot,hook in field.get('hooks',{}).items()})
                        old_fields.setdefault(key,[]).append(item)
                        examples.setdefault(key,item)
    classes, properties, unpaired = [], [], []
    totals = collections.Counter()
    for ci,klass in enumerate(fresh['selected_classes']):
        name = klass['name']
        if name not in old_orders:
            unpaired.append(dict(name=name, path=klass['path'], property_count=len(klass['own_properties'])))
            continue
        new_names = [field['name'] for field in klass['own_properties']]
        if len(set(new_names)) != len(new_names):
            raise ValueError('Duplicate fresh property names')
        historical_names = {key[1] for key in old_fields if key[0] == name}
        added = sorted(set(new_names)-historical_names)
        removed = sorted(historical_names-set(new_names))
        unchanged = changed = index_differences = 0
        for pi,field in enumerate(klass['own_properties']):
            key = (name,field['name'])
            if key not in old_fields:
                continue
            sources = old_fields[key]
            geometry = {tuple(row['facts'][k] for k in FACT_KEYS) for row in sources}
            if len(geometry) != 1:
                raise ValueError('Historical declarations disagree on property geometry: '+repr(key))
            reference = sources[0]['facts']
            difference = {k:dict(old=reference[k],new=field[k]) for k in FACT_KEYS if reference[k] != field[k]}
            old_indices = sorted({row['facts']['rep_index'] for row in sources})
            had_nonzero = any(x != 0 for x in old_indices)
            if had_nonzero and field['rep_index'] == 0:
                index_differences += 1
            unchanged += not bool(difference)
            changed += bool(difference)
            properties.append(dict(class_name=name, class_path=klass['path'], property=field['name'],
                old_facts=reference, new_facts=field, geometry_changes=difference,
                all_compared_geometry_equal=not difference,
                historical_rep_index_values=old_indices,
                historical_nonzero_rep_index_now_zero=had_nonzero and field['rep_index'] == 0,
                rep_index_is_current_wire_handle_proof=False,
                current_source=dict(path=NEW_CAPTURE,json_pointer=f'/selected_classes/{ci}/own_properties/{pi}'),
                historical_sources=sources))
        order_equal = tuple(new_names) in old_orders[name]
        classes.append(dict(name=name,path=klass['path'], own_property_count=len(new_names),
            property_order_matches_historical=order_equal, historical_order_variants=len(old_orders[name]),
            unchanged_geometry=unchanged, changed_geometry=changed, added_properties=added,
            removed_properties=removed, nonzero_rep_indices_now_zero=index_differences))
        totals.update(matched_classes=1, matched_properties=unchanged+changed,
            unchanged_geometry=unchanged,changed_geometry=changed,added=len(added),removed=len(removed),
            nonzero_rep_indices_now_zero=index_differences, property_order_changes=not order_equal)

    proof = docs[REPLICATION]
    known_code = {f['old_rva']: dict(name=f['name'], new_rva=f['new_rva'],
        new_code_sha256=f['new_code_sha256']) for f in proof['function_comparisons']}
    methods = {}
    for row in properties:
        if not row['new_facts']['flags_low32'] & 0x20:
            continue
        example = examples[(row['class_name'],row['property'])]
        for slot,hook in example['old_hooks'].items():
            key = (slot,hook['target_rva'])
            method = methods.setdefault(key, dict(historical_slot=slot, historical_target_rva=hook['target_rva'],
                affected_properties=[], full_new_code_proof=known_code.get(hook['target_rva']),
                current_property_vtable_binding_observed=False))
            method['affected_properties'].append(row['class_name']+'.'+row['property'])
    schema_fields = []
    fresh_index = {(r['class_name'],r['property']):r for r in properties}
    for path in SCHEMAS:
        for pointer,value in walk(docs[path]):
            if not {'declaring_class','name','storage_offset'} <= value.keys():
                continue
            match = fresh_index.get((value['declaring_class'],value['name']))
            schema_fields.append(dict(schema=path,json_pointer=pointer,
                declaring_class=value['declaring_class'],name=value['name'],
                historical_storage_offset=value['storage_offset'],
                current_class_captured=value['declaring_class'] in current,
                current_property_captured=match is not None,
                current_storage_offset=match['new_facts']['storage_offset'] if match else None,
                storage_offset_equal=(value['storage_offset']==match['new_facts']['storage_offset']) if match else None,
                historical_handle=value.get('ordinary_handle',value.get('inner_handle')),
                current_handle_qualified=False))

    old_interfaces = docs[INTERFACES]
    weapon = next(c for c in old_interfaces['selected_classes'] if c['name']=='WeaponBase')
    interface_rows = [dict(declaring_class=c['name'],interfaces=c['implemented_interfaces'])
        for c in weapon['ancestors'] if c['implemented_interfaces']]
    setup = next(f for f in proof['function_comparisons'] if f['name']=='class_replication_descriptor_setup')
    assignment = next(i for i in setup['decoded_new_instructions'] if i['rva']=='0x10e05297')
    if assignment['instruction'] != 'mov word ptr [rcx + 0x50], ax':
        raise ValueError('Qualified replication setup assignment witness changed')
    old_movement = next(o for o in docs[OLD_CAPTURES[2]]['objects']
        if o['class_path']=='/Script/SOL.SOLPlayerMovementComponent')
    cache = old_movement['existing_driver_class']
    moves = [field for node in cache['cache_nodes'] for field in node['fields']
             if field['descriptor_name']=='NewServerMove']
    movement = dict(historical_actual_component_class=old_movement['class_path'],
        current_actual_component_class_captured=False,
        historical_cache_exclusive_maximum=cache['exclusive_index_maximum'],
        historical_NewServerMove_rep_indices=[f['rep_index'] for f in moves],
        current_UFunction_declarations_exported=False,current_RPC_cache_index_qualified=False)
    minimum_weapon = []
    for name,value in docs[SCHEMAS[2]]['actor']['fields'].items():
        match = fresh_index[(value['declaring_class'],name)]
        minimum_weapon.append(dict(name=name,declaring_class=value['declaring_class'],
            current_facts=match['new_facts'],historical_ordinary_or_inner_handle=value.get('ordinary_handle',value.get('inner_handle')),
            historical_net_serializer=value['serializer_rva'],
            historical_archive_serializer=value['archive_serializer_rva'],
            net_serializer_code_proof=known_code.get(value['serializer_rva']),
            archive_serializer_code_proof=known_code.get(value['archive_serializer_rva']),
            current_method_binding_observed=False,current_wire_handle_qualified=False))
    iface_source = ROOT/'work/native_actor_interface_metadata.py'
    constants = {}
    for node in ast.parse(iface_source.read_text(encoding='utf-8')).body:
        if isinstance(node,ast.Assign) and len(node.targets)==1 and isinstance(node.targets[0],ast.Name):
            label = node.targets[0].id
            if label in ('SHIPPING_SHA256','INTERFACE_SINGLETON_RVA','MAIN_VTABLE_RVA',
                         'SECONDARY_VTABLE_RVA','WRITER_RVA','ADJUSTMENT','SLOT'):
                constants[label] = ast.literal_eval(node.value)
    if constants['SHIPPING_SHA256'] != OLD_SHA:
        raise ValueError('Historical Pawn interface reader no longer has old build scope')
    return dict(kind='updated_class_property_schema_comparison', client_sha256=NEW_SHA,
        old_client_sha256=OLD_SHA, process_access=False, native_called=False, runtime_sources_changed=False,
        current_class_count=len(current), current_property_count=sum(len(c['own_properties']) for c in current.values()),
        current_rep_index_distribution=dict(sorted(collections.Counter(str(f['rep_index'])
            for c in current.values() for f in c['own_properties']).items())),
        comparison_fields=['name',*FACT_KEYS,'rep_index'], totals=dict(totals),
        classes=classes, properties=properties, classes_without_historical_comparator=unpaired,
        existing_schema_field_comparisons=schema_fields,
        serializer_requirements=[methods[k] for k in sorted(methods)],
        minimal_modular_weapon_declaration_subset=minimum_weapon,
        property_rep_index_read_source=dict(path='work/updated_client_metadata.py',sha256=producer_sha,
            stored_in_capture_source_pins=True, raw_read_start='FProperty+0x18',
            raw_unpack_offset='0x38', actual_property_offset='0x50',
            zero_is_an_observed_u16_not_a_missing_dict_key_default=True),
        runtime_rep_index_setup=dict(source=REPLICATION,witness=assignment,
            zero_values_interpretation='All fresh values are zero. This is consistent with lobby classes lacking runtime replication setup, but the capture alone does not prove why. It is not evidence of new wire handles or of a changed replication algorithm.'),
        movement_requirements=movement,
        historical_weapon_interfaces=dict(source=INTERFACES,
            class_interface_array_offset=old_interfaces['implemented_interface_array_class_offset'],
            entry_bytes=old_interfaces['interface_entry_bytes'],declarations=interface_rows,
            fresh_interface_arrays_exported=False,current_pointer_adjustments_qualified=False),
        historical_pawn_interface_reference=dict(path='work/native_actor_interface_metadata.py',
            source_sha256=sha(iface_source.read_bytes()),old_binding_constants=constants,
            fresh_interface_or_vtable_values_exported=False,any_new_binding_qualified=False),
        missing_current_evidence=[
            'Current initialized RepIndex, ClassNetCache, RepLayout command handles/order/opcodes and RPC cache fields.',
            'FProperty class/type identity, full64 property flags, field vtable and slots88/90 target bindings.',
            'Nested array/struct/enum declarations, bool masks, custom struct operations and custom delta bindings.',
            'Implemented interface arrays, native pointer adjustments, CDO/instance main and secondary vtables and actual interface method targets.',
            'Concrete movement SOL/DFM subclasses; WeaponManagerComponent, MultiWeaponManagerComponent, WeaponReplicateComponent and GPWeaponReplicateComponent; EmptyHand/melee classes and CDO/template facts.',
            'UFunction declarations and parameter metadata for NewServerMove, rotation and weapon owner/switch RPCs.',
        ], minimum_migration=[
            'Preserve every historical schema and source hash. Add a separate new-build fact manifest pinned to this fresh capture and exact class/property matches.',
            'Treat unchanged storage facts as current metadata facts only. Keep historical wire handles, serializer bindings and interface adjustments inactive for the new build.',
            'Collect the missing current type/vtable/interface and initialized replication metadata for the small set of fields actually serialized; compare their concrete method bodies to qualified code.',
            'Publish a new-build schema subset only after those bindings and nested serializers are qualified. Generic numeric body equality already exists, while current property binding remains unobserved.',
        ], limitations=[
            'Historical declarations identify ancestors by unique class labels; fresh records provide paths. No absent historical per-ancestor path is invented.',
            'Equality covers only captured own-property facts, including linked-property order. Full class size, superclass links, high32 flags and type identity are not exported by this capture.',
            'An unchanged storage offset or ordinary numeric RepIndex zero does not prove a wire handle, RPC signature, serializer, interface pointer adjustment or gameplay acceptance.',
            'Unmatched current driver/core classes have no comparator in these three bounded historical captures.',
        ], sources=[dict(path=p,sha256=h) for p,h in PINS.items()],
        script_sha256=sha(Path(__file__).read_bytes()), protocol_compatibility_verified=False,
        native_gameplay_acceptance=False)


if __name__ == '__main__':
    result = qualify()
    output = ROOT/'work/research_updated_schema_comparison_79fb7b10.json'
    raw = (json.dumps(result,indent=2)+'\n').encode('utf-8')
    output.write_bytes(raw)
    print(json.dumps(dict(output=output.relative_to(ROOT).as_posix(),sha256=sha(raw),
        totals=result['totals'],current_properties=result['current_property_count'],
        current_rep_indices=result['current_rep_index_distribution'],
        serializer_method_pairs=len(result['serializer_requirements']))))
