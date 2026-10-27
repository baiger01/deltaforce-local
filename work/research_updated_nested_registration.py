"""Bounded current nested type graph for the minimum map property prefixes."""
import argparse
import json
from pathlib import Path

from research_updated_metadata_roots import ROOT,sha
from research_updated_native_registration import Archive,CLIENT_SHA
from research_updated_source_map_schema import ascii_key

INPUTS={
    'work/research_updated_native_registration_79fb7b10_v4.json':'e50210e8b851275204ab95ae67caedf3e03ef76353776387834578136bbda663',
    'work/research_updated_source_map_schema_79fb7b10_v1.json':'ed591569846bb22602dbbe6571de72720b87e93f2ebb12da5dfff412696f4d27'}
STOPS={
    'BP_DFMPlayerController_C':('Controller','Pawn'),
    'BP_DFMCharacter_C':('Pawn','Controller'),
    'BP_GameState_PVPVE_C':('GameState_PVPVE','bMatchRealStart'),
    'BP_SOLPlayerState_C':('DFMPlayerState','CurrDiffTeamAvatarId')}


def struct_references(field,context):
    rows=[]
    if field['kind'] in ('FStructProperty','FStructRefProperty'):
        callback=[c for c in field['callbacks'] if c['parameter_offset']=='0x28']
        if len(callback)!=1 or callback[0]['function_rva'] is None:
            raise ValueError('Exact struct parameter callback absent: '+context)
        rows.append(dict(context=context,struct_factory_rva=callback[0]['function_rva']))
    for child in field['children']:
        rows.extend(struct_references(child,context+'/'+child['name']))
    return rows


def derive():
    docs={}
    for path,expected in INPUTS.items():
        raw=(ROOT/path).read_bytes()
        if sha(raw)!=expected:
            raise ValueError('Current nested source input changed: '+path)
        docs[path]=json.loads(raw)
    native=docs[next(p for p in INPUTS if 'native_registration_' in p)]
    schema=docs[next(p for p in INPUTS if 'source_map_schema_' in p)]
    for doc in (native,schema):
        for source,expected in doc['source_pins'].items():
            if sha((ROOT/source).read_bytes())!=expected:
                raise ValueError('Current nested source producer changed: '+source)
    classes=native['classes']+native['supporting_native_ancestors']+schema['additional_native_classes']
    by_path={c['package']+'.'+c['name']:c for c in classes}
    a=Archive(); prefixes=[]; references=[]
    for selected in schema['selected_classes']:
        root=selected['path'].rsplit('.',1)[-1]; stop_class,stop_field=STOPS[root]
        fields=[]; found=False
        for row in selected['cache']['fields']:
            if row['kind']!='property':
                continue
            owner=by_path[row['owner']]
            matches=[p for p in owner['fields']['fields'] if ascii_key(p['name'])==ascii_key(row['name'])]
            if len(matches)!=1:
                raise ValueError('Unique source prefix property binding absent')
            field=matches[0]
            fields.append(dict(owner=row['owner'],name=field['name'],parameter_rva=field['parameter_record_rva'],
                kind=field['kind'],array_dim=field['array_dim'],property_flags64=field['property_flags64_before_factory']))
            references.extend(struct_references(field,root+'/'+owner['name']+'.'+field['name']))
            if owner['name']==stop_class and ascii_key(field['name'])==ascii_key(stop_field):
                found=True; break
        if not found:
            raise ValueError('Minimum property prefix stop was not source-bound: '+root)
        prefixes.append(dict(receiver_class=root,stop_declaring_class=stop_class,stop_property=stop_field,
            own_and_inherited_net_property_prefix=fields,native_rep_layout_observed=False))
    pending=list(references); structures={}; unresolved=[]; total_fields=0
    while pending:
        source=pending.pop(0); key=source['struct_factory_rva']
        if key in structures or any(r['struct_factory_rva']==key for r in unresolved):
            continue
        if len(structures)+len(unresolved)>=128:
            raise ValueError('Nested current struct graph exceeds local bound')
        try:
            node=a.structure(int(key,16))
        except ValueError as error:
            unresolved.append(dict(**source,reason=str(error),type_fields_exported=False))
            continue
        structures[key]=node
        total_fields+=node['fields']['parameter_record_count']
        if total_fields>8192:
            raise ValueError('Nested current property parameter graph exceeds local bound')
        if node['super_struct_factory_rva']:
            edge=dict(context=node['name']+'/SuperStruct',struct_factory_rva=node['super_struct_factory_rva'])
            references.append(edge); pending.append(edge)
        for field in node['fields']['fields']:
            edges=struct_references(field,node['name']+'/'+field['name'])
            references.extend(edges); pending.extend(edges)
    helpers=[Path(__file__),ROOT/'work/research_updated_native_registration.py',
        ROOT/'work/research_updated_source_map_schema.py']
    return dict(kind='current_minimum_map_nested_registration_graph',client_sha256=CLIENT_SHA,
        source_inputs=INPUTS,source_pins={p.relative_to(ROOT).as_posix():sha(p.read_bytes()) for p in helpers},
        property_prefixes=prefixes,type_reference_edges=references,structures=list(structures.values()),
        unresolved_struct_factories=unresolved,all_selected_nested_struct_registrations_closed=not unresolved,
        struct_count=len(structures),property_parameter_record_count=total_fields,
        native_functions=[p for _,p in a.functions.values()],immutable_reads=list(a.data.values()),
        code_source=a.code.source_evidence(),source_graph_is_not_runtime_descriptor_observation=True,
        command_handles_reconstructed=False,checksums_reconstructed=False,profile_activation_authorized=False,
        process_opened=False,native_engine_function_called=False,runtime_files_changed=False,native_acceptance_verified=False)


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output',type=Path,required=True); args=parser.parse_args(); target=args.output.resolve()
    if target.exists() or target.parent!=ROOT/'work' or not target.name.startswith('research_'):
        parser.error('Fresh work/research_ report required')
    report=derive(); raw=(json.dumps(report,ensure_ascii=True,indent=2)+'\n').encode('ascii')
    with target.open('xb') as stream:
        stream.write(raw)
    print(json.dumps(dict(output=str(target),sha256=sha(raw),structs=report['struct_count'],
        unresolved=len(report['unresolved_struct_factories']))))
