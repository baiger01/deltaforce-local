"""Finite readiness ledger for a new current-source minimum Actor profile."""
import argparse
import json
from pathlib import Path

from research_updated_metadata_roots import ROOT,sha
from research_updated_native_registration import Archive,CLIENT_SHA

PROOFS={
    'work/research_updated_native_registration_79fb7b10_v4.json':'e50210e8b851275204ab95ae67caedf3e03ef76353776387834578136bbda663',
    'work/research_updated_cooked_functions_79fb7b10_v1.json':'3e930ca5569d133bdb01121bfa6bd0169229144fff847e01dd36a50e459d9b62',
    'work/research_updated_source_map_schema_79fb7b10_v1.json':'ed591569846bb22602dbbe6571de72720b87e93f2ebb12da5dfff412696f4d27',
    'work/research_updated_source_template_bindings_79fb7b10_v1.json':'bca9a315624f5e58506387f001a719f9d8a13c629d405da0bbad9503e193512b',
    'work/research_updated_nested_registration_79fb7b10_v1.json':'418679e96c04c60e790f3633e41cccbeca8159266b21cbb46e1495ae987abf62',
    'work/research_updated_deferred_struct_ops_79fb7b10_v1.json':'60426a191620a7149ffd50e34e43d858295f690ced63125f7446317363fc621e',
    'work/research_updated_command_shapes_79fb7b10_v1.json':'68471964b153ab566619c123fe03b53f5ac1e7221f4f74697ad3b2aaf9476989',
    'work/research_updated_minimum_leaf_bindings_79fb7b10_v2.json':'21d89e42a08a38e827e7ee227e3ab1f00900b2e84b0f96a55f8dbd1a358500d6',
    'work/research_updated_enum_widths_79fb7b10_v1.json':'e0123bb8f930ef1257d765cdcd5f111a954da82f5d653df095fa39e21fd1ca6d',
    'work/research_updated_ename_bindings_79fb7b10_v3.json':'4b4fc6de5a4722034517cafa60b1186f2b1d859a0aab086d3c8751126c2e73d1',
    'work/research_updated_minimum_cpp_checksums_79fb7b10_v1.json':'91ad73a2e5371906a90e560e5e6fbc39b5c14d567501dd71613229f8873d7c55',
    'work/research_updated_minimum_rpc_declarations_79fb7b10_v1.json':'246c6bdbf856f638c84d3f8916ac41773c38c8f7e53b8e1fcc25e657c52a9909',
    'work/research_updated_generated_constructor_load_79fb7b10_v1.json':'34edf381c15a58eb81e0c59908e5b2eff31eb81a78e23e3462b42e8f167a1925',
    'work/evidence/updated-map-profile-closure-79fb7b10.json':'d3b5e2b63959859080b250ebe6badff831dd9ad4e993f2f14993367a0ab673ab'}


def derive():
    docs={}
    for path,expected in PROOFS.items():
        raw=(ROOT/path).read_bytes()
        if sha(raw)!=expected:
            raise ValueError('Minimum Actor readiness evidence changed: '+path)
        docs[path]=json.loads(raw)
    get=lambda token:next(doc for path,doc in docs.items() if token in path)
    leaves=get('minimum_leaf_bindings_')['minimum_fields']
    if len(leaves)!=17 or not get('minimum_rpc_declarations_')['current_parameter_declaration_trees_complete']:
        raise ValueError('Current minimum field/RPC declaration closure incomplete')
    a=Archive(); gate={i.address:i for i in a.instructions(0x4e24db0)}
    cells=[]
    for at in (0x4e24db6,0x4e24dc2):
        rva=a.rip(gate[at])
        try:
            initial=a.read(rva,1)[0]
        except ValueError:
            initial=None
        cells.append(dict(rva=hex(rva),bytes=1,immutable_raw_initial_value=initial,runtime_value_observed=False))
    if [r['rva'] for r in cells]!=['0x1de36180','0x1de39d25']:
        raise ValueError('Current game-spawn hook gate source cells changed')
    pc=next(r['cache'] for r in get('source_map_schema_')['selected_classes'] if r['path'].endswith('.BP_DFMPlayerController_C'))
    return dict(kind='current_minimum_actor_source_profile_readiness',client_sha256=CLIENT_SHA,
        source_proofs=PROOFS,
        source_pins={'work/research_updated_minimum_profile_readiness.py':sha(Path(__file__).read_bytes()),
            'work/research_updated_native_registration.py':sha((ROOT/'work/research_updated_native_registration.py').read_bytes())},
        ready_to_compile_distinct_source_derived_minimum_profile=True,ready_to_activate_actor_transmission=False,
        minimum_actor_scope=dict(class_count=4,property_count=17,startup_rpc_count=12,
            nested_property_structs=39,additional_rpc_structs=5,
            class_cache_maxima={r['path'].rsplit('.',1)[-1]:r['cache']['exclusive_cache_index_maximum']
                for r in get('source_map_schema_')['selected_classes']},
            minimum_fields=[{k:r[k] for k in ('receiver_class','field','declaring_owner','relative_handle','command_index','dispatch_opcode')}
                for r in leaves]),
        closed_native_inputs=[
            'Exact current class/CDO paths, CDO class references and cooked ownership from independently verified current PAKs.',
            'Complete native ancestry, Net declarations and Function flags/parameters; PC ten cooked functions have no Net bit.',
            'Current ClassReps/cache ordering; source-derived cache indices and maxima, without old index inputs.',
            'Seventeen current relative handles, complete prefix recursion/array scopes and selected scalar dispatch opcodes.',
            'Current typed property constructors, concrete vtables and complete scalar/NetSerialize method bodies.',
            'Role byte width2 and game-mode enum width4; the latter does not require the archive-version branch value.',
            'Current minimum GetCPPType lowercase inputs and seed0/nonrecursive FProperty CRCs.',
            'Ordinary cooked non-nativized generated-class constructor inheritance model and expected primary/interface target assignments.' ],
        must_close_receiver_contract_before_actor_transmission=[
            dict(requirement='Selected current PackageMap serialization dispatch and ordinary reference/archive context',
                concrete_inputs=['PackageMap selected class/constructor vtable slots0x260/0x268/0x288/0x2e0',
                    'Slot0x288 ordinary new-Actor body must bind0x12bcb3b0; game extension body must match qualified0x4e24db0',
                    'Ordinary GUID-cache mode+0x98 and relevant archive/connection version branch must follow the selected native receive path',
                    'Selected ActorChannel construction must bind SetActor slot0x308 and InitActor slot0x310 to qualified current bodies'],
                permitted_closure='Current immutable factory/default/configuration/load path proof, or bounded current connection metadata; initialized replication caches and CDO payload are not required'),
            dict(requirement='Pawn game-spawn flag reader chooses the qualified native byte-consumption branch',
                function_rva='0x4e24db0',mutable_source_gate_cells=cells,
                normal_branch_sufficient_condition='cell0x1de36180==0 OR cell0x1de39d25==0',
                unresolved_branch='When both are enabled, dispatcher0x5e286d0 may select state2 and return without consuming the native byte',
                permitted_closure='Prove the selected current script-hook/default branch from its source inputs or observe these exact source-qualified gate facts; raw PE initial zero is not a runtime observation')],
        required_integration_work=[
            dict(change='Introduce a source-derived profile mode with these current proof pins and exact four class paths',
                constraint='Keep observed-native-cache and protocol/gameplay-acceptance flags false; do not relabel historical snapshots'),
            dict(change='Replace old fixed PC cache maximum245 with qualified current maximum244 in the new-mode path',
                current_exclusive_index_maximum=pc['exclusive_cache_index_maximum'],
                constraint='Preserve the existing old-mode profiles and declaration checks; new indices/maxima come from current inputs'),
            dict(change='Bind and verify existing pure RPC recipes against the twelve current parameter trees',
                constraint='Default view-target omits the transition body; Ping fields are double+five floats / two doubles+float; Rotation is current Rotator+native bool'),
            dict(change='Retain complete logical-stage ACK, export-before-body, fragmented-body completion and tail-RPC scheduling gates',
                constraint='Source metadata qualification does not replace transport reliability/fragmentation qualification')],
        optional_or_separate_from_normal_wire_shape=[
            dict(input='Actual cached CDO pointer, object index/serial, runtime initialized ClassNetCache and RepLayout arrays',
                status='Required to claim runtime observation; not required to compute these source-derived values'),
            dict(input='Class+0x100 alternate-property mapping and final native command offsets',
                status='Constructor sums are deliberately not native mapped offsets. This map preserves the descriptor traversal/handle/opcode source used here; it can affect destination and parent bookkeeping, whose gameplay semantics remain separate. The pure sender serializes handles and values, not native offsets.'),
            dict(input='Aggregate class CRC and context-dependent RepLayout command compatibility CRC',
                status='Not emitted by the existing ordinary internal_ack=False field-header subset. A compatibility/internal-ACK path would need its own full graph/context proof.'),
            dict(input='CDO lifetime callback output and conditions',
                status='Not an input to this earlier command-numbering loop; may govern native send eligibility/notifications and gameplay semantics, not the recovered numeric handle allocation')],
        source_template_scope=get('generated_constructor_load_')['source_model'],
        no_claims=['No current game process/native method invocation or Actor trial.',
            'No native Actor acceptance, possession, map-rendering, loot or inventory success.',
            'The minimum four-Actor profile does not qualify all weapon/inventory component schemas.'],
        fastest_next_route='Compile the distinct current-source minimum profile now; close the finite PackageMap/channel/context and Pawn flag-gate contracts, then run one bounded Actor bootstrap verification with explicit success/failure telemetry. Preserve existing local random spawn/operator/weapon/map rules.',
        native_functions=[p for _,p in a.functions.values()],immutable_reads=list(a.data.values()),code_source=a.code.source_evidence(),
        profile_guards_relaxed=False,process_opened=False,native_engine_function_called=False,
        runtime_files_changed=False,native_acceptance_verified=False)


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__); parser.add_argument('--output',type=Path,required=True)
    args=parser.parse_args(); target=args.output.resolve()
    if target.exists() or target.parent!=ROOT/'work' or not target.name.startswith('research_'):
        parser.error('Fresh work/research_ report required')
    report=derive(); raw=(json.dumps(report,ensure_ascii=True,indent=2)+'\n').encode('ascii')
    with target.open('xb') as stream:
        stream.write(raw)
    print(json.dumps(dict(output=str(target),sha256=sha(raw),schema_ready=report['ready_to_compile_distinct_source_derived_minimum_profile'],
        transmission_ready=report['ready_to_activate_actor_transmission'])))
