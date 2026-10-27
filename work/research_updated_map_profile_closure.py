"""Offline audit of the finite inputs needed for an updated map bootstrap.

Historical schemas remain historical. This report qualifies selected complete
code bodies and enumerates missing current metadata; it activates no profile.
"""
import argparse
import json

from research_updated_metadata_roots import (
    ROOT, PINS, ForensicObservation, NewImage, sha,
)
from research_updated_replication_core import compare_full
from research_updated_cache_initialization import unwind_inventory


CAPTURE = 'work/native-client-tests/1792803423602487700/updated-class-metadata.json'
PROFILE = 'outputs/df-local-server/protocol/portable-map-spawn/profile-carried-inventory.json'
INPUT_PINS = {
    CAPTURE: 'ae58fa8354c4a777e32ae4dac05481dfe0bd1662f263269f6a77b2c3e93fc64f',
    PROFILE: 'd00604f590003b81ec30219f9914738d408c2d603dc87d853debc3be262511ab',
    'work/research_updated_metadata_roots.py': 'ea107a5bc475bea3ec262dd26ea91283b6fdfa5ad564e29fec3763b737c32cf6',
    'work/research_updated_replication_core.py': '3f9938b62167eba78650c869261f9e6e76f2e8582e058134d9f2739ca5af7c83',
    'work/research_updated_cache_initialization.py': '88e2502c09aeef23013c77ec3877e587ed4e10ee8785afb7a9a90ac3282fa9dd',
    'work/evidence/updated-replication-core-79fb7b10.json': '762e8111b52e4bd4273489b0a9444adb2340c8a21fd6808cb23c1e1d6bb7cd58',
    'work/research_updated_cache_initialization_79fb7b10.json': '9f27a79bd5686c0d90dd3b30d983a3b9af86516de550b0936607c061dc00b6ac',
    'work/research_updated_serializer_bindings_79fb7b10.json': 'ad8c80f26309a93a78bc2a253c469cbfe4542d5389dc393b151b7702d73310c5',
    'work/native_actor_bootstrap.py': 'ed98f6782f94c643c220a12942a6297f825634f220104386bc770a2493ae0c80',
    'work/portable_map_bootstrap.py': '7b588862aad31034082a17a2794ef10ef328de8d7884f7a38f9f6cdf9a6ce614',
    'work/portable_map_player_state.py': 'c3492e1a86c98f81098d0a909e4f779387e684624b55850f35c7336f5b8d4e6d',
    'work/portable_map_world_state.py': 'a94e4b589436369a031aa9356de661c6210a186a48ca77a7d679279babad9e4c',
}

PAIRS = [
    ('serialize_new_actor', 0x12bcb060, 0x12bcb3b0),
    ('serialize_object_guid_reader', 0x12bbb3c0, 0x12bbb710),
    ('serialize_object_guid_writer', 0x12bbc520, 0x12bbc870),
    ('optional_vector', 0x12bab4b0, 0x12bab800),
    ('short_rotator', 0x10ab83a0, 0x10ab7da0),
    ('actor_channel_process_bunch', 0x128611e0, 0x12861530),
    ('pc_on_actor_channel_open', 0x12d4ddb0, 0x12d4e100),
    ('pawn_net_rep_writer', 0x4e198f0, 0x4e19500),
    ('game_package_map_flags_reader', 0x4e251a0, 0x4e24db0),
    ('actor_state_downgrade', 0x12583dc0, 0x12584110),
    ('receive_net_guid_bunch', 0x12bc5540, 0x12bc5890),
    ('actor_channel_set_actor', 0x1286ed70, 0x1286f0c0),
    ('actor_channel_init_actor', 0x1285dd90, 0x1285e0e0),
    ('actor_channel_constructor', 0x1283fbc0, 0x1283ff10),
    ('read_content_block_payload', 0x12864a10, 0x12864d60),
]

PC = 'BP_DFMPlayerController_C'
GS = 'BP_GameState_PVPVE_C'
PAWN = 'BP_DFMCharacter_C'
PS = 'BP_SOLPlayerState_C'
RPC_NAMES = [
    'ServerShortTimeout', 'Server_RcvACWorldTime', 'ServerFieldOfView',
    'NotifySeamlessLoginReady', 'ClientAckSeamlessLoginReady',
    'ServerBouncePing', 'ClientReturnPing', 'ClientRestart',
    'ServerAcknowledgePossession', 'ClientSetViewTarget', 'ServerVerifyViewTarget',
    'ClientSetRotation',
]
PROPERTY_SPECS = {
    PC: [('Pawn', None), ('PlayerState', None)],
    PAWN: [('Controller', None), ('PlayerState', None), ('Role', None), ('RemoteRole', None)],
    GS: [('bReplicatedHasBegunPlay', None), ('bStartMathWithAllPlayerReady', None),
         ('bCanSwitchToAbseil', None), ('MapID', 31), ('RoomId', 31),
         ('bMatchRealStart', None), ('DFMGamePlayerMode', None)],
    PS: [('Uin', 22), ('HeroId', 71), ('CurrSameTeamAvatarId', 73),
         ('CurrDiffTeamAvatarId', 74)],
}


def read_inputs():
    docs, sources = {}, []
    for path, expected in INPUT_PINS.items():
        raw = (ROOT/path).read_bytes()
        if sha(raw) != expected:
            raise ValueError('Pinned map audit input changed: '+path)
        sources.append(dict(path=path, sha256=expected))
        if path.endswith('.json'):
            docs[path] = json.loads(raw)
    return docs, sources


def historical_source(profile, key, sources):
    pin = profile
    for part in key:
        pin = pin[part]
    path, expected = pin['relative_path'], pin['sha256']
    raw = (ROOT/path).read_bytes()
    if sha(raw) != expected:
        raise ValueError('Pinned historical profile source changed: '+path)
    doc = json.loads(raw)
    if doc['client_sha256'] != PINS['old'][2]:
        raise ValueError('Historical source identity changed: '+path)
    sources.append(dict(path=path, sha256=expected, identity=PINS['old'][2],
                        use='historical requirements only; not an updated binding'))
    return doc


def class_export(archive, name):
    rows = [r for r in archive['driver_class_exports']
            if r.get('class_name') == name and 'layout' in r]
    if len(rows) != 1:
        raise ValueError('Historical class layout is ambiguous: '+name)
    return rows[0]


def class_requirements(fresh, archive):
    current = {c['name']:c for c in fresh['selected_classes']}
    chains = {c['name']:[r['name'] for r in c['class_ancestry']]
              for c in archive['roots']['classes']}
    # This exact historical chain is also checked in native_actor_bootstrap.py.
    chains[PS] = [PS, 'SOLPlayerState', 'DFMPlayerState', 'GPPlayerState',
                  'BasePlayerState', 'PlayerState', 'Info', 'Actor', 'Object']
    return [dict(class_name=name, historical_ancestry=chains[name],
        current_declarations_present=[n for n in chains[name] if n in current],
        missing_current_class_declarations=[n for n in chains[name] if n not in current],
        current_leaf_class_observed=name in current,
        current_named_template_or_cdo_observed=False,
        current_selected_template_open_hook_observed=False,
        necessary_inputs=['Current class identity/path and complete ancestry',
            'Current named template/CDO identity, direct Outer and resolved asset path',
            'Selected template vtable+0x3d8 target; no inferred derived-class hook'],
        historical_ancestry_is_updated_proof=False)
        for name in (PC, GS, PAWN, PS)]


def property_requirements(fresh, archive, receiver):
    current = {c['name']:c for c in fresh['selected_classes']}
    chains = {c['class_name']:c['historical_ancestry']
              for c in class_requirements(fresh, archive)}
    records = {name:class_export(archive,name) for name in (PC,GS,PAWN)}
    records[PS] = receiver['player_state']
    result = []
    for name, specs in PROPERTY_SPECS.items():
        record = records[name]
        for field, parent in specs:
            rows = [c for c in record['layout']['commands']
                    if c.get('descriptor_name') == field and
                    (parent is None or c['parent_index'] == parent)]
            if len(rows) != 1:
                raise ValueError('Historical property is ambiguous: '+name+'.'+field)
            row = rows[0]
            observed = [dict(declaring_class=owner, **prop)
                        for owner in chains[name] if owner in current
                        for prop in current[owner]['own_properties'] if prop['name'] == field]
            hook = row.get('property_serializer_hook',{})
            result.append(dict(receiver_class=name, property=field,
                historical_command_index=row['command_index'],
                historical_parent_index=row['parent_index'],
                historical_relative_handle=row['relative_handle'],
                historical_data_offset=row['data_offset'],
                historical_dispatch_opcode=row['dispatch_opcode'],
                historical_serializer_rva=hex(hook['target_rva']) if hook else None,
                current_same_name_declarations=observed,
                current_wire_handle_known=False,
                historical_handle_authorized_for_new_build=False,
                necessary_inputs=['Current RepLayout command+parent arrays or full independently qualified reconstruction',
                    'Complete command prefix and dynamic-array return scopes through this command',
                    'Current descriptor/type/slot0x90 and applicable scalar slot0x88 bindings']))
    return result


def prefix_requirements(archive, receiver, properties):
    records = {name:class_export(archive,name) for name in (PC,GS,PAWN)}
    records[PS] = receiver['player_state']
    result = []
    for name,record in records.items():
        maximum = max(r['historical_command_index'] for r in properties
                      if r['receiver_class'] == name)
        groups = {}
        for command in record['layout']['commands'][:maximum+1]:
            groups.setdefault(command['parent_index'],[]).append(command)
        expansions = []
        for index,commands in groups.items():
            if len(commands) <= 1:
                continue
            parents = record['layout'].get('parents',[])
            parent = parents[index].get('descriptor_name') if parents else None
            expansions.append(dict(historical_parent_index=index,
                parent_property=parent,
                struct_type_name_not_captured=parent is not None,
                current_descriptor_inputs=('The selected '+name+'.'+parent+
                    ' property, actual Struct/Inner descriptor+0x90 and exact nested declaration chain'
                    if parent else 'Current parent descriptor at this index; historical scrubbed receiver schema omits parent names'),
                historical_expanded_command_prefix=[{k:c[k] for k in (
                    'command_index','descriptor_name','relative_handle','dispatch_opcode') if k in c}
                    for c in commands],
                dynamic_array_scope=commands[0]['dispatch_opcode'] == 0,
                child_handle_scopes_are_not_added_to_outer_handle=True,
                current_expansion_observed=False))
        result.append(dict(receiver_class=name,historical_command_prefix_end=maximum,
            prefix_has_not_been_requalified_for_updated_build=True,
            nested_prefix_dependencies=expansions))
    return result


def rpc_requirements(fresh, archive):
    record = class_export(archive,PC)
    fields = [f for node in record['cache_nodes'] for f in node['fields']]
    current = {c['name']:c for c in fresh['selected_classes']}
    chain = next(c['historical_ancestry'] for c in class_requirements(fresh,archive)
                 if c['class_name'] == PC)
    result = []
    for name in RPC_NAMES:
        old = [f for f in fields if f.get('descriptor_name') == name]
        if len(old) != 1:
            raise ValueError('Historical RPC is ambiguous: '+name)
        observed = [dict(declaring_class=owner,**f)
                    for owner in chain if owner in current
                    for f in current[owner]['own_net_functions'] if f['name'] == name]
        result.append(dict(receiver_class=PC, function=name,
            historical_cache_index=old[0]['rep_index'],
            historical_exclusive_index_maximum=record['exclusive_index_maximum'],
            current_declarations=observed, current_cache_index_known=False,
            current_parameters_observed=False,
            necessary_inputs=['Current complete inherited ClassNetCache field list/index maximum',
                'Current ordered UFunction parameters, flags/directions, types and serializers',
                'For reconstructed index: complete own and inherited Net properties/functions, exact owner/type/name/order; checksums need independently closed GetCPPType and FName formatting']))
    return result


def code_edges(functions, prior):
    by_old = {r['old_rva']:r for r in functions}
    for doc in prior:
        for key in ('functions','function_comparisons'):
            for row in doc.get(key,[]):
                if 'old_rva' in row and 'new_rva' in row:
                    by_old[row['old_rva']] = row
    edges = []
    for row in functions:
        begin = int(row['old_rva'],16)
        for ref in row['references']:
            if ref['kind'] != 'direct_control_flow':
                continue
            old_target = int(ref['old_target'],16)
            if begin <= old_target < begin+row['bytes']:
                continue
            proof = by_old.get(ref['old_target'])
            covered = proof is not None and proof['new_rva'] == ref['new_target']
            edges.append(dict(function=row['name'],**ref,
                target_body_compared_in_loaded_reports=covered,
                target_proof_name=proof.get('name') if covered else None))
    return edges


def qualify():
    docs, sources = read_inputs()
    fresh, profile = docs[CAPTURE], docs[PROFILE]
    if (fresh['client_sha256'] != PINS['new'][2] or fresh['complete'] is not True
            or fresh['selected_class_count'] != 45
            or any(fresh[k] is not False for k in ('process_memory_written',
                'native_function_called','native_protocol_compatibility_verified'))
            or fresh['replication_handles_exported'] is not False):
        raise ValueError('Current capture scope changed')
    if profile['client_sha256'] != PINS['old'][2]:
        raise ValueError('Historical profile identity changed')
    archive = historical_source(profile,('sources','archive'),sources)
    receiver = historical_source(profile,('player_state','schema'),sources)
    old,new,image = ForensicObservation('old'),ForensicObservation('new'),NewImage()
    functions = [compare_full(old,new,image,*row) for row in PAIRS]
    unwind = unwind_inventory(image,functions,[])
    by_name = {r['name']:r for r in functions}
    instructions = {int(i['rva'],16):i for row in functions for i in row['decoded_new_instructions']}
    checks = [
        ('dynamic Actor first object reference',0x12bcb174+0x350,'call qword ptr [r10 + 0x260]'),
        ('Actor channel PackageMap SerializeNewActor dispatch',0x128613c3+0x350,'call qword ptr [rax + 0x288]'),
        ('Actor channel SetActor dispatch',0x128614cf+0x350,'call qword ptr [rax + 0x308]'),
        ('Actor channel InitActor dispatch',0x128614e2+0x350,'call qword ptr [rax + 0x310]'),
        ('selected Actor open hook dispatch',0x1285de7e+0x350,'call qword ptr [rax + 0x3d8]'),
        ('PC local-player byte storage',0x12d4dde3+0x350,'mov byte ptr [rdi + 0x524], al'),
        ('PC unaligned byte archive call',0x12d4de05+0x350,'call qword ptr [rax + 0x60]'),
    ]
    witnesses = []
    for meaning,at,expected in checks:
        row = instructions[at]
        if row['instruction'] != expected:
            raise ValueError('Exact map-open witness changed: '+meaning)
        witnesses.append(dict(meaning=meaning,**row))
    prior = [docs[p] for p in (
        'work/evidence/updated-replication-core-79fb7b10.json',
        'work/research_updated_cache_initialization_79fb7b10.json',
        'work/research_updated_serializer_bindings_79fb7b10.json')]
    edges = code_edges(functions,prior)
    # Record current declared metadata, never a synthetic initialized cache.
    classes = class_requirements(fresh,archive)
    properties = property_requirements(fresh,archive,receiver)
    rpcs = rpc_requirements(fresh,archive)
    prefixes = prefix_requirements(archive,receiver,properties)
    return dict(kind='offline_updated_minimum_map_profile_closure_audit',
        client_sha256=PINS['new'][2], historical_client_sha256=PINS['old'][2],
        source_inputs=sources, functions=functions, unwind_inventory=unwind,
        exact_instruction_witnesses=witnesses, direct_external_control_flow_edges=edges,
        indirect_virtual_dispatch_sites=[dict(function=f['name'],**i,
                current_selected_object_binding_observed=False)
            for f in functions for i in f['decoded_new_instructions']
            if i['instruction'].startswith('call qword ptr [') and '[rip ' not in i['instruction']],
        process_access=False, client_launched=False, native_called=False,
        production_sources_changed=False, runtime_profile_activated=False,
        current_wire_handles_recovered=False, native_gameplay_acceptance=False,
        selected_full_body_qualification=dict(function_count=len(functions),
            all_nonreference_instructions_equal=True,
            external_direct_targets_are_not_masked_into_a_transitive_equivalence_claim=True,
            unqualified_direct_external_edge_count=sum(not r['target_body_compared_in_loaded_reports'] for r in edges),
            virtual_call_runtime_bindings_observed=False),
        native_actor_open=dict(current_rva=by_name['serialize_new_actor']['new_rva'],
            current_guid_read_rva=by_name['serialize_object_guid_reader']['new_rva'],
            ordinary_fields='Actor packed GUID; archetype packed GUID; Level packed GUID if connection version>=5; interleaved location/rotation/scale/velocity presence bits and values',
            current_runtime_package_map_subtype_observed=False,
            current_archetype_level_reference_resolution_observed=False,
            finite_missing_inputs=['Selected current PackageMap v0x260/0x268/0x288/0x2e0 bindings and ordinary GUID-cache mode+0x98',
                'Selected current ActorChannel v0x308/v0x310 bindings',
                'Current connection EngineNetVersion, FInBunch archive version and actual packet cap',
                'Current archetype/CDO and Iris_Entry PersistentLevel identities/Outers/paths; actual GUID export resolution',
                'Optional vector uses archive v0x68/v0x70 and delegates new1dd20c0/10e15d0; short rotator uses the calls/references recorded in its complete body. Qualify their selected archive bindings and referenced constants when emitting transforms']),
        pc_tail=dict(new_qualified_base_hook_rva='0x12d4e100',vtable_slot='0x3d8',
            encoding='one unaligned raw u8 after SerializeNewActor; selected local player index0',
            derived_class_binding_proved=False,
            missing='Observe the current BP_DFMPlayerController_C template v0x3d8 target. Base body equality cannot choose a derived-class hook.'),
        pawn_game_spawn=dict(new_qualified_writer_rva='0x4e19500',
            new_qualified_reader_rva='0x4e24db0',new_qualified_downgrade_rva='0x12584110',
            algorithm_preserved=True,
            local_server_facts=dict(original_state_u8=2,actor_byte93_mask20=True,
                owner_connection_match=True,connection_present=True,
                actor_is_connection_actor=False,actor_in_connection_actor_array=False),
            result_flags_u8=0,server_facts_are_not_cdo_defaults=True,
            missing=['Current BP_DFMCharacter_C template and declaring CharacterBase NetRepActorInterface metadata: actual class interface descriptor, pointer adjustment, vtable method0x10 binding',
                'Current game PackageMap flag extension v0x2e0 binding and interface-gate method dependencies',
                'Game flag reader hotpatch gate globals1de36180/1de39d25: actual current values or independently qualified normal branch selection; native code can bypass the byte when the patch state selects that branch',
                'Current PC/GS/PS selected hooks/interface gates to determine which roles consume extra bytes']),
        class_requirements=classes, property_requirements=properties,
        historical_prefix_dependency_inventory=prefixes,
        startup_rpc_requirements=rpcs,
        deterministic_handle_equivalence=dict(proved=False,
            class_net_cache='Can independently derive field indices from complete exact class/superclass property+function inputs and qualified ordering. Current snapshot is missing map-specific leaf/ancestor classes; current RPC parameter schemas are absent. CRC/checksum reconstruction additionally needs exact type strings/formatting and recursive type inputs.',
            class_reps='ClassReps indices are not ClassNetCache indices and not RepLayout handles. All current45 setup arrays are empty.',
            rep_layout_numeric_handles='Algorithm equality and selected field geometry do not suffice: the command builder consumes current complete ClassReps order, recursive type/struct/array expansion, optional alternate NetProperties descriptors (CDO v0x208/build context), field type classifiers and selected serializer branches. Numeric commands are built at12db25a7 before lifetime v0x1b8. Lifetime output is not asserted as an independently demonstrated numeric-handle blocker.',
            full_layout_and_conditions='The full profile additionally needs current CDO at Class+0x140 (getter v0x388), lifetime callback CDO v0x1b8 at12db28c2 and condition/notify/custom-delta context. This report does not infer their runtime outputs from code equality.',
            exact_missing_reconstruction_inputs=['For numeric PC/GS/Pawn/PS handles: current complete inherited ClassReps order, original descriptor chains/flags and complete type expansion through each required outer command; alternate NetProperties branch and exact layout-build arguments',
                'For complete PC/GS/Pawn/PS condition/profile equivalence: current CDO identity/vtable and lifetime property list including RepIndex/condition/notify flags from CDO v0x1b8',
                'For PC/Pawn earliest object-reference handles: Actor.AttachmentReplication actual Struct+0x90 and ordered AttachParent/LocationOffset/RelativeScale3D/RotationOffset/AttachSocket/AttachComponent declarations; class own-property geometry omits these struct declarations',
                'For nested MatchInfo.MapID/RoomId: current struct descriptor+0x90, complete ordered own/super property chains, scalar type identities; the class-only capture has no nested struct declarations',
                'For Pawn Role/RemoteRole: actual current enum descriptor+0x90 and enum entries/max; ordinary receiver destination remapping proof',
                'For GS DFMGamePlayerMode: current EnumProperty enum/underlying descriptor and EDFMGamePlayMode entries/max/archive-version profile',
                'For each required object property and RPC UObject parameter: declared object class+0x90 and actual PackageMap serialization branch',
                'For each required function listed above: complete current parameter descriptors, Parm/OutParm/ReturnParm flags and serialization order']),
        fastest_defensible_route=[
            'Finish current control/connection contract and select new-build pure codecs explicitly while preserving old image gates.',
            'Use the selected complete Actor-open body qualifications here. Acquire only four map Actor class/CDO/hook/interface bindings and current resolvable scene graph; then a property-free Actor-open repair probe can precede RepLayout work.',
            'Prefer bounded read-only capture of existing current PC cache plus PC/GS/Pawn/PS layouts after ordinary native initialization. It supplies final handles/indices and avoids independently recreating lifetime callbacks/checksum type strings.',
            'If current layouts cannot be observed, reconstruct only after obtaining the exact missing inputs enumerated here. Never relabel historical schemas as updated observations.',
            'Generate a separate current-build minimum profile containing the four actor roles, current references, the17 listed property requirements and12 RPC requirements, SOL mode and rotation. Add gameplay components incrementally using fresh receiver schemas.',
            'Retain local room seed, spawn allocation, loot-rule evaluator and selection semantics. Regenerate only source-bound current item/spawn/map catalogs from updated content, preserving explicit server policy.',
            'Validate ordinary actor creation, ownership/possession, movement, map selection and loot via repair validation in the shadow for the authorized1800-second observation period; ACKs are intermediate evidence.'],
        local_random_rules=dict(profile_policy=profile['random_spawn']['local_room_policy'],
            config_relative_path=profile['local_map_rules']['config_relative_path'],
            algorithm_changes_required=False,
            updated_catalog_validation_required=True,
            no_old_template_ids_or_assets_authorized_by_this_report=True),
        research_script=dict(path='work/research_updated_map_profile_closure.py',
            sha256=sha((ROOT/'work/research_updated_map_profile_closure.py').read_bytes())),
        source_observations=[old.source_evidence(),new.source_evidence()])


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--qualify',action='store_true',required=True)
    parser.parse_args()
    result = qualify()
    path = ROOT/'work/evidence/updated-map-profile-closure-79fb7b10.json'
    raw = (json.dumps(result,indent=2)+'\n').encode('utf-8')
    path.write_bytes(raw)
    print(json.dumps(dict(output=path.relative_to(ROOT).as_posix(),sha256=sha(raw),
        functions=len(result['functions']),properties=len(result['property_requirements']),
        rpcs=len(result['startup_rpc_requirements']),native_called=False,
        current_wire_handle_equivalence_proved=False)))


if __name__ == '__main__':
    main()
