"""Current configured channel/PackageMap dispatch and ordinary archive inputs."""
import argparse
import json
from pathlib import Path
import struct

from research_updated_metadata_roots import ROOT, ForensicObservation, instruction_row, sha
from research_updated_native_registration import Archive, CLIENT_SHA
from research_updated_replication_core import compare_full, locate, containing_primary
from research_updated_source_template_bindings import find_class
from research_updated_source_map_schema import private_class_arguments
from research_updated_header_cells import displacement_candidates

INPUTS = {
    'work/research_updated_network_config_79fb7b10_v2.json':'5ab79b861332997b0af261fc0a0aecd0c341aa602f6f70f5b0402c49648cd819',
    'work/research_updated_header_cells_79fb7b10_v3.json':'b0c98f1a378bca8b1c98a38cdc9a973f4c8318bc5691171133a354890baac2d8',
    'work/research_updated_rpc_receive_79fb7b10_v2.json':'7463766d9602b3b96bbaa2451bcdc5c4580142f9de00463db502b5ee39c8022c',
    'work/research_updated_transport_79fb7b10.json':'d127c9b551192ba1a126f3b5f5e2c90f9a9a6a0e6d4ff806b6d037941fb73e92',
    'work/evidence/updated-map-profile-closure-79fb7b10.json':'d3b5e2b63959859080b250ebe6badff831dd9ad4e993f2f14993367a0ab673ab',
}
PAIRS = (
    ('game_package_map_constructor',0x6046550,0x60460d0),
    ('game_package_map_object',0x49cd3b0,0x49ccfc0),
    ('game_package_map_actor',0x49cd160,0x49ccd70),
    ('game_package_map_actor_extension',0x49a9d70,0x49a9980),
    ('game_channel_constructor',0x4931800,0x4931410),
    ('game_channel_process_bunch',0x49781b0,0x4977dc0),
    ('game_channel_set_actor',0x497d930,0x497d540),
    ('game_channel_init_actor',0x4969a30,0x4969640),
    ('game_channel_alternate_process',0x4941e10,0x4941a20),
    ('game_connection_constructor',0x49999f0,0x4999600),
    ('game_connection_init_local',0x49ba520,0x49ba130),
    ('game_connection_init_remote',0x49baa60,0x49ba670),
    ('engine_package_map_constructor',0x12baa5e0,0x12baa930),
    ('engine_package_map_object',0x12bcdc20,0x12bcdf70),
    ('guid_cache_constructor',0x12ba9b00,0x12ba9e50),
    ('driver_post_init',0x12b96eb0,0x12b97200),
    ('driver_channel_definitions',0x12b94430,0x12b94780),
    ('channel_definition_map_add',0x12b86860,0x12b86bb0),
    ('archive_constructor',0x10b3aef0,0x10b3a8c0),
    ('archive_reset',0x10b4a2a0,0x10b49c70),
    ('optional_vector_save_delegate',0x1dd2370,0x1dd20c0),
    ('optional_vector_load_delegate',0x10e15b0,0x10e15d0),
    ('package_map_authority',0x12bbce20,0x12bbd170),
)


def exact(a, root, at, expected):
    ins = next((i for i in a.instructions(root) if i.address == at), None)
    if ins is None or ins.mnemonic+' '+ins.op_str != expected:
        raise ValueError('Current header instruction changed: '+hex(at))
    return instruction_row(ins)


def table(a, root, at, assignment_at, expected, vtable, slots):
    ins = next(i for i in a.instructions(root) if i.address == at)
    if ins.mnemonic != 'lea' or a.rip(ins) != vtable:
        raise ValueError('Current constructor-assigned table differs')
    write = exact(a, root, assignment_at, expected)
    methods = []
    for slot, target in slots.items():
        raw = a.read(vtable+slot,8)
        if struct.unpack('<Q',raw)[0]-a.base != target:
            raise ValueError('Current configured dispatch slot changed')
        methods.append(dict(slot=hex(slot), target_rva=hex(target), bytes_hex=raw.hex(), sha256=sha(raw)))
    return dict(constructor_rva=hex(root), assignment=write, vtable_rva=hex(vtable), methods=methods,
        source_assignment=True, runtime_pointer_observed=False)


def derive():
    docs = {}
    for path, expected in INPUTS.items():
        raw = (ROOT/path).read_bytes()
        if sha(raw) != expected:
            raise ValueError('Current header context input changed: '+path)
        docs[path] = json.loads(raw)
    a, old = Archive(), ForensicObservation('old')
    functions = [compare_full(old,a.code,a.image,name,previous,current) for name,previous,current in PAIRS]
    bindings = {
        'game_package_map':table(a,0x60460d0,0x60460f4,0x6046142,'mov qword ptr [rbx], rax',0x15a69718,
            {0x260:0x49ccfc0,0x268:0x49b10e0,0x288:0x49ccd70,0x2e0:0x49a9980}),
        'game_actor_channel':table(a,0x4931410,0x4931424,0x493142b,'mov qword ptr [rbx], rax',0x15e64ed8,
            {0x300:0x4977dc0,0x308:0x497d540,0x310:0x4969640,0x350:0x4941a20}),
    }
    config = next(d for p,d in docs.items() if 'network_config_' in p)
    default = [c for c in config['ini_payloads'] if c['path']=='../../../DeltaForce/Config/DefaultEngine.ini']
    if len(default) != 1:
        raise ValueError('Unique current DefaultEngine config source required')
    selected = [line for line in default[0]['selected_network_lines'] if line['line'] in (246,291,802,821,935)]
    if len(selected) != 5 or not any('GPActorChannel' in r['value'] for r in selected):
        raise ValueError('Current ordinary configured class chain changed')
    registrations = []
    for name in ('GPActorChannel','GPPackageMapClient','GPNetConnection','GPNetDriver','GPGameEngine'):
        row = find_class(a,name)
        args = private_class_arguments(a.instructions(int(row['private_class_getter_rva'],16)))
        registrations.append(dict(row, constructor_arguments=args))
    for root in (0x49b10e0,0x49c8790,0x1283ece0,0x10cf5530,0x10b3abf0,0x12bc5890,
            0x12b8e6f0,0x6040b40,0x24db280):
        a.instructions(root)
    checks = (
        (0x49ccd70,0x49ccd9a,'call 0x12bcb3b0','GP Actor serializer calls qualified Engine new-Actor serializer'),
        (0x49a9980,0x49a99bb,'call 0x4e24db0','GP extension calls current Pawn byte reader'),
        (0x49a9980,0x49a99c0,'mov byte ptr [rsi + 0x545], 1','GP extension marks the Pawn byte consumed'),
        (0x49ccd70,0x49cce89,'cmp byte ptr [rbx + 0x545], 0','GP Actor wrapper avoids a second Pawn byte'),
        (0x4977dc0,0x4977e3c,'call 0x12861530','Ordinary GP channel delegates base Actor process'),
        (0x497d540,0x497d5cf,'call 0x1286f0c0','GP SetActor delegates qualified base'),
        (0x4969640,0x49696c4,'call 0x1285e0e0','GP InitActor delegates qualified base'),
        (0x49ba130,0x49ba24d,'call 0x6046520','Local connection substitutes GPPackageMapClient'),
        (0x49ba130,0x49ba252,'mov qword ptr [rbx + 0x60], rax','Local substituted PackageMap class field'),
        (0x49ba670,0x49ba796,'call 0x6046520','Remote connection substitutes GPPackageMapClient'),
        (0x49ba670,0x49ba79b,'mov qword ptr [rbx + 0x60], rax','Remote substituted PackageMap class field'),
        (0x12ba9e50,0x12ba9f35,'mov byte ptr [rcx + 0x152], sil','Fresh GUID cache exporting flag clear'),
        (0x12b97200,0x12b972c1,'call 0x12ba9e50','Non-CDO NetDriver initialization constructs current GUID cache'),
        (0x12bc5890,0x12bc58dd,'movzx ebp, byte ptr [r14 + 0x152]','NetGUID export reader saves exporting flag'),
        (0x12bc5890,0x12bc5abd,'mov byte ptr [r14 + 0x152], bpl','NetGUID export reader restores prior exporting flag'),
        (0x10b49c70,0x10b49cd4,'mov word ptr [rbx + 0x28], si','Archive reset clears loading/saving and swapping bits'),
        (0x10b3abf0,0x10b3ac98,'or byte ptr [rbx + 0x28], 0x81','BitReader sets loading bit and leaves saving clear'),
        (0x10cf5530,0x10cf5555,'mov qword ptr [rdi + 0xb0], rbx','NetBitReader binds supplied PackageMap'),
        (0x1283ece0,0x1283ecf0,'mov rdx, qword ptr [rdx + 0x68]','FInBunch obtains current connection PackageMap'),
        (0x1283ece0,0x1283ed58,'xor byte ptr [rdi + 0x29], cl','FInBunch copies swapping from connection+180'),
        (0x1283ece0,0x1283ed5e,'mov edx, dword ptr [rbx + 0x1528]','FInBunch copies connection Engine network version'),
        (0x12b94780,0x12b94895,'lea r13, [rax + rdx*8]','Current ChannelDefinition stride40'),
        (0x12b94780,0x12b94ae6,'mov qword ptr [rdi + 0x10], rax','Loaded channel class stored at definition+16'),
        (0x12b94780,0x12b94aff,'call 0x12b86bb0','Loaded ChannelDefinitions populate channel-name map'),
        (0x12b8e6f0,0x12b8e844,'mov r8d, 0x30','Existing map key replacement copies key8+value40'),
        (0x49ccfc0,0x49cd0be,'call 0x12bcdf70','GP object serializer calls Engine GUID reader'),
        (0x49ccfc0,0x49cd231,'call 0x49c8790','Optional GUID diagnostics obtain a separate archive from the manager'),
        (0x49ccfc0,0x49cd245,'mov rbx, rax','Diagnostic archive replaces local RBX; input bunch remains R14'),
        (0x49ccfc0,0x49cd27d,'call qword ptr [rax + 0x60]','Diagnostic byte uses separate RBX archive, not input bunch'),
    )
    witnesses = [dict(meaning=meaning, **exact(a,root,at,text)) for root,at,text,meaning in checks]
    mode_ins = next(i for i in a.instructions(0x4977dc0) if i.address==0x4977e22)
    mode = a.rip(mode_ins)
    if mode != 0x1e322935:
        raise ValueError('Current alternate channel source gate changed')
    mode_references, rejected, seen = [], [], set()
    for first, end, _ in a.code.blocks:
        a.code.read(first,1)
        raw = a.code.loaded[first]
        for at, _ in displacement_candidates(raw,first,mode):
            root = containing_primary(a.image,first+at)
            if root is None:
                continue
            try:
                ins = a.instructions(root)
            except ValueError as exc:
                rejected.append(dict(root_rva=hex(root), reason=str(exc)))
                continue
            for i in ins:
                if i.address+i.disp_offset==first+at and 'rip' in i.op_str and a.rip(i)==mode and i.address not in seen:
                    mode_references.append(dict(root_rva=hex(root), **instruction_row(i)))
                    seen.add(i.address)
    native_driver = a.class_record(a.factory(0x1338f050),include_functions=False)
    channel_prop = next(p for p in native_driver['fields']['fields'] if p['name']=='ChannelDefinitions')
    channel_factory = next(c['function_rva'] for c in channel_prop['children'][0]['callbacks'] if c['parameter_offset']=='0x28')
    definition = a.structure(int(channel_factory,16))
    helpers = [Path(__file__), ROOT/'work/research_updated_header_cells.py', ROOT/'work/research_updated_network_config.py',
        ROOT/'work/research_updated_native_registration.py', ROOT/'work/research_updated_replication_core.py',
        ROOT/'work/research_updated_source_template_bindings.py', ROOT/'work/research_updated_source_map_schema.py']
    return dict(kind='current_source_actor_header_dispatch_context', client_sha256=CLIENT_SHA,
        source_inputs=INPUTS, source_pins={p.relative_to(ROOT).as_posix():sha(p.read_bytes()) for p in helpers},
        configured_chain=dict(config_asset=default[0]['path'], decoded_sha256=default[0]['decoded_sha256'], selected_lines=selected,
            ordinary_model='Current BaseEngine then DefaultEngine configuration with no later network override: GPGameEngine→GPNetDriver→GPNetConnection→GPPackageMapClient; Actor name resolves GPActorChannel.',
            complete_config_loader_implementation_reproved=False, runtime_effective_configuration_observed=False),
        current_native_class_registrations=registrations, constructor_dispatch_bindings=bindings,
        functions=functions, exact_instruction_witnesses=witnesses,
        channel_definition_native_declaration=definition, native_driver_configuration_declarations=native_driver,
        archive_context=dict(loading=True,saving=False, constructor_source_derived=True,
            byte_swapping='FInBunch copies connection+0x180 bit0 to Archive+0x29 bit5; current ordinary profile requires0.',
            engine_net_version='FInBunch copies connection+0x1528 to Archive+0x54; existing current Control/transport qualification supplies the value.',
            package_map='FInBunch→FNetBitReader binds connection+0x68 as reader+0xb0.',
            guid_cache='PackageMap+0x310, initialized by normal NetDriver cache construction; +0x152 is exporting, not +0x98.',
            export_restore='The qualified NetGUID export reader saves +0x152, sets1 during exports, and restores it before Actor content.',
            cache_offset_0x98_is_not_a_mode=True),
        game_object_reference_wire=dict(ordinary_input_bunch='Each path reaches one Engine SerializeObject invocation, except explicit invalid-GUID-cache failure.',
            optional_guid_diagnostic_data='Reads a separate manager-owned Archive returned by49c8790. Byte/GUID/string operations on this archive do not add fields to the input RPC/Actor bunch.',
            native_assignment_and_guid_resolution_verified=False),
        alternate_channel_gate=dict(rva=hex(mode), instruction=instruction_row(mode_ins), references=mode_references,
            rejected_candidate_functions=rejected, required_ordinary_value=0,
            direct_writer='24db302 writes1 in full function24db280 whose current diagnostic is HUClientCommandlet Main; RobotDS/RobotNum/RobotMap literals identify the commandlet route.',
            function_identity_is_literal_inference=True, ordinary_game_startup_exclusion_reproved=False,
            alternate_body_compared_but_all_custom_virtual_callees_qualified=False),
        minimum_additional_runtime_gate=dict(reads=[dict(rva='0x1de36180',bytes=1,required_value=0),
                dict(rva=hex(mode),bytes=1,required_value=0)],
            reason='The universal hook enable byte0 skips all selected GP pre/post hooks and the Pawn hook; alternate channel byte0 selects the compared Engine ProcessBunch path.',
            pawn_per_hook_state_read_required_when_global_zero=False,
            recheck='Exact image identity and guarded source instructions; reread both exact bytes after metadata callback and immediately before enabling this source-derived profile.',
            existing_connection_contract=['ordinary internal_ack=False','connection+180 byteswapping=False','connection+1528 EngineNetVersion current qualified value',
                'nonnull connection+68 PackageMap with backconnection+130 and nonnull cache+310'],
            no_native_calls=True, no_cdo_payload=True, source_derived_values_are_not_native_acceptance=True),
        static_inputs_closed=['Current configured class names and immutable file/line/hash provenance.',
            'Current GP constructor tables and their exact overrides/delegation, rather than assuming base-class virtual slots.',
            'Complete current RPC receiver and current loading archive constructor semantics.',
            'Fresh GUID cache exporting default and save/restore semantics; historical +98 mode requirement corrected.'],
        remaining=['Either prove normal startup excludes HUClientCommandlet and the registered hook table remains disabled, or observe exactly the two guarded bytes.',
            'The current-source ordinary configuration model assumes the verified Base/Default files are loaded without a later URL/plugin/commandline network-class override; no live effective class claim is made.',
            'Actual native Actor creation, reference resolution, possession, map visibility, loot and inventory acceptance require their separate trial.'],
        native_functions=[p for _,p in a.functions.values()], immutable_reads=list(a.data.values()),
        code_sources=[old.source_evidence(),a.code.source_evidence()], source_derived_header_contract_compiled=True,
        ready_for_unconditional_actor_transmission=False, process_opened=False, native_engine_function_called=False,
        runtime_files_changed=False, profile_guards_relaxed=False, native_acceptance_verified=False)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output',type=Path,required=True)
    args = parser.parse_args()
    target = args.output.resolve()
    if target.exists() or target.parent != ROOT/'work' or not target.name.startswith('research_'):
        parser.error('Fresh work/research_ report required')
    result = derive()
    raw = (json.dumps(result,ensure_ascii=True,indent=2)+'\n').encode('ascii')
    with target.open('xb') as stream:
        stream.write(raw)
    print(json.dumps(dict(output=str(target),sha256=sha(raw),functions=len(result['functions']),
        witnesses=len(result['exact_instruction_witnesses']))))
