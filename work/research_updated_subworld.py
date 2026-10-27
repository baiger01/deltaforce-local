"""Offline qualification of current FURL RedirectURL -> SubWorld consumers.

Reads the saved hash-pinned native observations and immutable updated shadow PE.
Never launches a client, opens a process, invokes native code, changes config or
accounts, or substitutes an old observation for an updated runtime observation.
"""
import argparse
import json
import struct
from pathlib import Path

from capstone.x86 import X86_OP_IMM
from research_updated_metadata_roots import ROOT,PINS,CLIENT,ForensicObservation,sha,disasm,instruction_row
from research_updated_replication_core import compare_full
from research_updated_transport_roots import TransportImage
from research_updated_control_contract import unwind_closure


OUTPUT = ROOT/'work/evidence/updated-subworld-79fb7b10.json'
CONTROL_PATH = 'work/evidence/updated-control-contract-79fb7b10.json'
CONTROL_SHA = 'e176ef7d2d33771d1f2573331f64bbfd8797e76242f9c0d1af3827ea61e6d40b'
PAIRS = [
    ('engine_constructor',0x4999630,0x4999240),
    ('engine_loadmap_override',0x49bce70,0x49bca80),
    ('seamless_redirect_subworld_loader',0x4961640,0x4961250),
    ('url_copy',0x213af80,0x213aca0),
    ('split_space_options',0x109f2ea0,0x109f2900),
    ('split_key_value',0xdf6680,0xdf66a0),
    ('string_compare',0x10a137d0,0x10a13230),
    ('name_from_text',0x10b56070,0x10b55a40),
    ('base_engine_loadmap',0x13062a70,0x13062d60),
    ('world_settings_subworld_transition',0x1c02db0,0x1c02b30),
    ('gameplay_world_name_getter',0x4d08ce0,0x4d088f0),
    ('seamless_object_from_world',0x4953730,0x4953340),
    ('seamless_clear_after_failed_load',0x497c2e0,0x497bef0),
    ('disable_device_seamless_cvar_getter',0xd41bd40,0xd41b800),
]
CURRENT_ONLY = [
    ('subworld_equals_prefix_constructor',0x47d1e0,106),
    ('disable_device_seamless_cvar_registration',0x49cea0,112),
]


def qualify():
    old,new,image = ForensicObservation('old'),ForensicObservation('new'),TransportImage()
    functions = [compare_full(old,new,image,*row) for row in PAIRS]
    current_only = []
    for name,rva,size in CURRENT_ONLY:
        fragments = image.fragments(rva)
        raw = new.read(rva,size)
        ins = disasm(new,rva,size)
        if not fragments or fragments[-1][1]!=rva+size or sum(i.size for i in ins)!=size:
            raise ValueError('Current registration is not a complete native body')
        current_only.append(dict(name=name,new_rva=hex(rva),bytes=size,
            new_code_sha256=sha(raw),instruction_count=len(ins),full_linear_decode=True,
            historical_function_identity_or_equality_claimed=False,
            new_fragments=[dict(begin=hex(a),end_exclusive=hex(b),unwind_rva=hex(c)) for a,b,c in fragments],
            decoded_new_instructions=[instruction_row(i) for i in ins]))
    raw_control = (ROOT/CONTROL_PATH).read_bytes()
    if sha(raw_control)!=CONTROL_SHA:
        raise ValueError('Sealed current Welcome/FURL qualification changed')
    control = json.loads(raw_control)
    if control['client_sha256']!=PINS['new'][2]:
        raise ValueError('Welcome/FURL source has a different executable identity')
    rows = {int(i['rva'],16):i for f in functions+current_only+control['complete_function_comparisons']
            for i in f['decoded_new_instructions']}
    def proof(rule,rva,expected):
        row = rows.get(rva)
        if row is None or row['instruction']!=expected:
            raise ValueError('Exact SubWorld native dataflow witness changed: '+rule)
        return dict(rule=rule,**row)
    checks = [
        ('Pending FNetworkNotify subobject is object+28',0x12c7ab25,'mov qword ptr [rbx + 0x28], rax'),
        ('Pending FURL storage begins object+40',0x12c7ab1a,'lea rcx, [rbx + 0x40]'),
        ('Welcome third FString destination interface+50 = Pending+78',0x12c94de7,'lea rcx, [r12 + 0x50]'),
        ('Welcome third FString copied to FURL RedirectURL+38',0x12c94df0,'call 0xd5f540'),
        ('TickWorldTravel URL copy source Pending+40',0x13075e1a,'lea rdx, [rbx + 0x40]'),
        ('TickWorldTravel calls Engine LoadMap virtual448',0x13075e38,'call qword ptr [rdi + 0x448]'),
        ('Engine constructor installs current table',0x4999260,'mov qword ptr [rbx], rax'),
        ('Engine LoadMap FURL argument R8 retained',0x49bcabb,'mov rdi, r8'),
        ('Engine LoadMap WorldContext argument RDX retained',0x49bcac5,'mov r14, rdx'),
        ('Engine LoadMap attempts existing seamless object',0x49bcbf7,'call 0x4961250'),
        ('Engine fallback reads RedirectURL FURL+38',0x49bcc17,'lea rcx, [rdi + 0x38]'),
        ('Engine fallback culls empty option chunks',0x49bcc20,'mov r9b, 1'),
        ('Engine fallback splits options on space',0x49bcc3b,'call 0x109f2900'),
        ('Engine fallback splits option by equals',0x49bcd09,'call 0xdf66a0'),
        ('Engine fallback compares option key SubWorld',0x49bcd37,'call 0x10a13230'),
        ('Engine fallback branches on exact key comparison result',0x49bcd3e,'je 0x49bcd62'),
        ('Engine fallback keeps matching option value',0x49bcd6c,'call 0xd5f540'),
        ('Engine fallback calls original LoadMap',0x49bcda2,'call 0x13062d60'),
        ('Engine fallback obtains actual WorldSettings',0x49bcdbb,'mov rbx, qword ptr [rbx + 0x668]'),
        ('Engine fallback requires value longer than terminator',0x49bcdfa,'cmp eax, 1'),
        ('Engine fallback builds FName from option value',0x49bce25,'call 0x10b55a40'),
        ('Engine fallback passes resulting FName to WorldSettings',0x49bce3e,'mov rdx, qword ptr [rax]'),
        ('Engine fallback invokes native subworld transition',0x49bce41,'call 0x1c02b30'),
        ('FURL copy reads RedirectURL+38',0x213ace5,'lea rdx, [rsi + 0x38]'),
        ('FURL copy writes RedirectURL+38',0x213ace9,'lea rcx, [rbp + 0x38]'),
        ('Seamless path also reads RedirectURL+38',0x4961f8a,'lea rdx, [r13 + 0x38]'),
        ('Seamless path splits RedirectURL options',0x4962067,'call 0x109f2900'),
        ('Seamless path splits each key/value',0x4962130,'call 0xdf66a0'),
        ('Seamless path compares SubWorld key',0x4962160,'call 0x10a13230'),
        ('Seamless path keeps matching option value',0x4962171,'call 0xd5f540'),
        ('Seamless path converts value to FName',0x49621b9,'call 0x10b55a40'),
        ('Seamless path stores selected FName',0x49621cf,'mov qword ptr [r15], rax'),
        ('GetWorldName command-line fallback parses -SUBWORLD=',0x4d08a81,'call 0x10b38d20'),
        ('Native SubWorld= prefix constructor copies20 bytes',0x47d225,'mov r8d, 0x14'),
        ('DisableDeviceSeamless native CVar default is0',0x49cec6,'xor r8d, r8d'),
        ('DisableDeviceSeamless native registration call',0x49ced8,'call qword ptr [rax + 0x18]'),
        ('DisableDeviceSeamless native registration stores interface cell',0x49cee2,'mov qword ptr [rip + 0x1d9e18c7], rax'),
        ('DisableDeviceSeamless getter reads same interface cell',0xd41b829,'mov rcx, qword ptr [rip + 0x10a62f80]'),
    ]
    witnesses = [proof(*x) for x in checks]
    strings = []
    for at,expected in [(0x14ec37e4,' '),(0x14ecf338,'='),(0x15e6e7b8,'SubWorld'),
                        (0x168c41a0,'SubWorld='),(0x168c47e0,'Game.DisableDeviceSeamless'),
                        (0x156a9a00,'-SUBWORLD=')]:
        raw = expected.encode('utf-16-le')+bytes(2)
        if image.read(at,len(raw))!=raw:
            raise ValueError('Exact current SubWorld literal changed')
        refs = [dict(function=f['name'],**r) for f in functions for r in f.get('references',[])
                if r['kind']=='rip_reference' and r['new_target']==hex(at)]
        for f in current_only:
            refs += [dict(function=f['name'],new_instruction=i['rva'],kind='current_only_rip_reference',
                          new_target=hex(at)) for i in f['decoded_new_instructions']
                     if hex(at) in i.get('rip_targets',[])]
        if not refs:
            raise ValueError('SubWorld literal has no exact qualified native reference')
        strings.append(dict(rva=hex(at),utf16=expected,bytes=len(raw),sha256=sha(raw),references=refs))
    table = 0x15e73760
    slot = image.read(table+0x448,8)
    if struct.unpack('<Q',slot)[0]-image.image_base!=0x49bca80:
        raise ValueError('Constructor-installed Engine LoadMap slot448 changed')
    ctor = next(f for f in functions if f['name']=='engine_constructor')
    refs = [r for r in ctor['references'] if r['kind']=='rip_reference' and r['new_target']==hex(table)]
    if len(refs)!=1:
        raise ValueError('Engine constructor table witness missing')
    lookup = {a:(b,name) for name,a,b in PAIRS}
    edges = []
    for f in functions:
        for r in f.get('references',[]):
            target = lookup.get(int(r['old_target'],16)) if r['kind']=='direct_control_flow' else None
            if target:
                if r['new_target']!=hex(target[0]):
                    raise ValueError('Source-qualified SubWorld helper edge changed')
                edges.append(dict(caller=f['name'],callee=target[1],**r))
    indirect_jumps = []
    for f in functions+current_only:
        for i in disasm(new,int(f['new_rva'],16),f['bytes']):
            if i.mnemonic=='jmp' and i.operands[0].type!=X86_OP_IMM:
                indirect_jumps.append(dict(function=f['name'],**instruction_row(i)))
                if (f['name'],i.op_str)!=('disable_device_seamless_cvar_getter','qword ptr [rax + 0x90]'):
                    raise ValueError('Unqualified indirect switch in SubWorld body')
    return dict(kind='updated_native_redirecturl_subworld_qualification',client_sha256=PINS['new'][2],
        old_client_sha256=PINS['old'][2],script_path=Path(__file__).relative_to(ROOT).as_posix(),
        script_sha256=sha(Path(__file__).read_bytes()),
        verification_command='python work/research_updated_subworld.py --qualify',
        process_accessed=False,client_launched=False,native_called=False,config_changed=False,
        source_observations=[old.source_evidence(),new.source_evidence()],
        new_pe=dict(path=str(CLIENT),sha256=PINS['new'][2],exception_directory_sha256=sha(image.exc_data)),
        control_source=dict(relative_path=CONTROL_PATH,sha256=CONTROL_SHA),
        full_function_comparisons=functions,current_only_full_bodies=current_only,
        full_unwind_inventory=unwind_closure(image,functions+current_only),
        exact_semantic_witnesses=witnesses,immutable_literals=strings,qualified_helper_edges=edges,
        indirect_jumps=indirect_jumps,
        engine_loadmap_binding=dict(constructor_rva='0x4999240',table_rva=hex(table),slot='0x448',
            target_rva='0x49bca80',bytes_hex=slot.hex(),sha256=sha(slot),constructor_reference=refs[0],
            current_runtime_engine_instance_observed=False,exact_derived_cpp_class_name_not_inferred=True),
        contract=dict(welcome_third_fstring='Pending interface+50 -> Pending object+78 -> FURL RedirectURL+38',
            url_copy_preserves_redirecturl=True,
            normal_loadmap='Engine slot448 ->49bca80; copies RedirectURL+38 into space-delimited options, splits each at equals, selects SubWorld value, invokes base13062d60, then if World/typedWorldSettings/nonempty value are available converts to FName and calls1c02b30.',
            seamless_loadmap='Engine override first tries current seamless object4961250; its RedirectURL+38 option parser selects the same SubWorld key, converts value to FName, and stores native subworld-name fields.',
            redirect_option_key='SubWorld',redirect_key_value_separator='=',redirect_option_separator=' ',
            current_native_redirect_subworld_consumer_qualified=True,
            startup_command_line_fallback='Separate GetWorldName4d088f0 parses -SUBWORLD= only after its existing seamless-cache path; this does not authorize a global startup override.',
            disable_device_seamless=dict(name='Game.DisableDeviceSeamless',native_default=0,
                current_registration_rva='0x49cea0',interface_cell_rva='0x1de7e7b0',
                current_registered_getter_rva='0xd41b800',requested_trial_value=1,
                required_existing_launcher_flag='--disable-device-seamless',
                required_ini='[ConsoleVariables]\nGame.DisableDeviceSeamless=1',
                effective_runtime_value_observed=False)),
        residuals=[
            'This is complete code/data qualification of concrete native paths, not execution of current Engine/WorldSettings instances or native loading acceptance.',
            'Native CVar registration/name/default/getter are qualified. Actual Engine.ini application and its live entry-mode effect require the next owned client log; no effective value is asserted offline.',
            'The constructors concrete vtable is bound to Engine slot448, but the current running engine instance/class is not observed and an exact derived C++ class name is not invented.',
            'The original LoadMap return, typed WorldSettings gates and native subworld-transition call are preserved; success of that call, active streaming state, actors, pawn and gameplay remain unverified.',
            'The native baseLoadMap full body is instruction-equal outside references. All external package loading, string storage, allocator and arbitrary virtual callees are not transitively certified.',
            'Global -SUBWORLD startup override remains distinct from the evidenced per-Welcome RedirectURL path and is not required or authorized by this report.',
        ],source_scripts=[dict(relative_path=p,sha256=sha((ROOT/p).read_bytes())) for p in [
            'work/research_updated_subworld.py','work/research_updated_metadata_roots.py',
            'work/research_updated_replication_core.py','work/research_updated_transport_roots.py',
            'work/research_updated_control_contract.py','work/native_engine_ini_override.py']])


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--qualify',action='store_true',required=True)
    parser.parse_args()
    result = qualify()
    raw = (json.dumps(result,indent=2,sort_keys=True)+'\n').encode('ascii')
    OUTPUT.write_bytes(raw)
    print(json.dumps(dict(output=OUTPUT.relative_to(ROOT).as_posix(),sha256=sha(raw),
        full_compared_functions=len(result['full_function_comparisons']),
        current_only_full_bodies=len(result['current_only_full_bodies']),
        witnesses=len(result['exact_semantic_witnesses']),
        subworld_redirect_consumer_qualified=True,native_acceptance=False)))


if __name__=='__main__':
    main()
