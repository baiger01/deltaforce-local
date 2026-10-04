"""Seal concise native Pending control-flow facts against the cached code."""
import json
import mmap
import struct
from pathlib import Path
from capstone import Cs,CS_ARCH_X86,CS_MODE_64
from analyze_cached_pending_notify import ROOT,CACHE,MANIFEST_SHA,EXE,EXE_SHA,sha
from offline_native_code_cache import read_cached_code
from read_native_control_code import Image
FOLDER=ROOT/'work/evidence/cached-pending-notify-1790902501634810000'
EDGE=ROOT/'work/evidence/cached-pending-edges-1790902501634810000'
LOGS=ROOT/'work/evidence/cached-pending-log-xrefs-1790902501634810000'

def source(path):
    raw=path.read_bytes()
    return {'relative_path':path.relative_to(ROOT).as_posix(),'sha256':sha(raw)}

def run():
    switch=json.loads((FOLDER/'notify.switch-audit.json').read_text(encoding='utf-8'))
    if switch['span_sha256']!='a8cc88c468c1344791be8134b188e73292f0f2d43dca0666a862ec4a103e1922':raise ValueError('Switch source mismatch')
    decoder=Cs(CS_ARCH_X86,CS_MODE_64);decoder.detail=True
    ins=list(decoder.disasm(read_cached_code(CACHE,0x12c93f40,4740,MANIFEST_SHA),0x12c93f40))
    if sum(i.size for i in ins)!=4740:raise ValueError('Notify code partition not fully decoded')
    by={i.address:i for i in ins}
    def proof(address,mnemonic,operands):
        i=by[address]
        if (i.mnemonic,i.op_str)!=(mnemonic,operands):raise ValueError(f'Exact native flow evidence mismatch at {address:x}')
        return {'rva':hex(address),'instruction_bytes':bytes(i.bytes).hex(),'instruction':i.mnemonic+' '+i.op_str}
    incoming={
        'Challenge':{'id':3,'switch_entry':hex(0x12c942b1),'field_sequence':[
            {'wire_type':'FString','native_destination':'connection+0x1b8','evidence':[proof(0x12c942b1,'lea','rdx, [r15 + 0x1b8]'),proof(0x12c942bb,'call','0x109ea340')]}],
            'error_gate':[proof(0x12c942c0,'movzx','eax, byte ptr [rbx + 0x29]'),proof(0x12c942c6,'test','al, 1'),proof(0x12c942c8,'je','0x12c9497e')],
            'error_behavior':'Read error takes branch that clears connection+1b8 and returns without emitting Login.'},
        'Welcome':{'id':1,'switch_entry':hex(0x12c94991),'field_sequence':[
            {'wire_type':'FString','semantic':'Level','native_destination':'FURL.Map at interface+0x40 = Pending object+0x68','evidence':[proof(0x12c94991,'lea','rdx, [r12 + 0x40]'),proof(0x12c949ab,'call','0x109ea340')]},
            {'wire_type':'FString','semantic':'Game','native_destination':'temporary rsp+0x60; logged as Game and appended as game=%s option when nonempty','evidence':[proof(0x12c949b0,'lea','rdx, [rsp + 0x60]'),proof(0x12c949b8,'call','0x109ea340'),proof(0x12c94bff,'call','0x109f45f0')]},
            {'wire_type':'FString','semantic':'RedirectURL','native_destination':'temporary rbp-0x68 -> FURL.RedirectURL at interface+0x50 = Pending object+0x78','evidence':[proof(0x12c949bd,'lea','rdx, [rbp - 0x68]'),proof(0x12c949c4,'call','0x109ea340'),proof(0x12c94a97,'lea','rcx, [r12 + 0x50]'),proof(0x12c94a9c,'lea','rdx, [rbp - 0x68]'),proof(0x12c94aa0,'call','0xd5f4c0')]}],
            'error_gate':[proof(0x12c949c9,'movzx','eax, byte ptr [rbx + 0x29]'),proof(0x12c949cf,'test','al, 1'),proof(0x12c949d1,'je','0x12c94dc6')],
            'map_url_normalization':[proof(0x12c94a70,'mov','r9d, 1'),proof(0x12c94a84,'call','0x1307ee40'),proof(0x12c94a89,'lea','rdx, [rbp + 8]'),proof(0x12c94a8d,'lea','rcx, [r12 + 0x40]'),proof(0x12c94a92,'call','0xd5f4c0')],
            'successful_connected_marker':proof(0x12c94d5e,'mov','byte ptr [r12 + 0x80], 1'),
            'marker_offset_qualification':'interface+80 = Pending object+a8; success here means successful Welcome parsing. It is not proof of map loading, actor spawn or Join transmission.'}}
    outgoing={
        'Login':{'id':5,'origin':'Challenge successful parse','byte_tag_evidence':proof(0x12c94848,'mov','byte ptr [rsp + 0x50], 5'),
            'field_sequence':[
                {'wire_type':'FString','native_source':'connection+0x1c8','semantic':'ClientResponse, native canonical literal 0','evidence':[proof(0x12c94784,'lea','rbx, [r15 + 0x1c8]'),proof(0x12c94794,'lea','rcx, [rip + 0x223626d]'),proof(0x12c947cc,'mov','ecx, dword ptr [rip + 0x2236236]'),proof(0x12c947d2,'mov','dword ptr [rax], ecx'),proof(0x12c94882,'mov','rdx, rbx'),proof(0x12c9488c,'call','0x109ea340')]},
                {'wire_type':'FString','native_source':'temporary rbp-0x40 built by URL formatting helper130aa2d0 from local URL copy','semantic':'request URL; native constructs from original Pending URL, local-player name/options, host cleared and default port restored','evidence':[proof(0x12c947d4,'xor','r8d, r8d'),proof(0x12c947d7,'lea','rdx, [rbp - 0x40]'),proof(0x12c947db,'lea','rcx, [rbp - 0x20]'),proof(0x12c947df,'call','0x130aa2d0'),proof(0x12c94891,'lea','rdx, [rbp - 0x40]'),proof(0x12c9489c,'call','0x109ea340')]},
                {'wire_type':'native UniqueNetId field helper12bab170','native_source':'connection+0x188, copied from first local-player helper12ae6ec0 when available','semantic':'Local-player identity representation; no runtime ID value read or substituted','evidence':[proof(0x12c94635,'call','0x12ae6ec0'),proof(0x12c9463a,'lea','r13, [r15 + 0x188]'),proof(0x12c948a1,'lea','rdx, [r15 + 0x188]'),proof(0x12c948af,'call','0x12bab170')]},
                {'wire_type':'FString','native_source':'rbp+0x60, copied from optional GameInstance+0x218 object virtual+0x348 return','semantic':'online platform name; concrete subsystem name not guessed','evidence':[proof(0x12c94763,'mov','rcx, qword ptr [rax + 0x218]'),proof(0x12c94776,'call','qword ptr [rax + 0x348]'),proof(0x12c947e8,'lea','rcx, [rsp + 0x70]'),proof(0x12c947ed,'call','0x10b78000'),proof(0x12c948b4,'lea','rdx, [rbp + 0x60]'),proof(0x12c948bf,'call','0x109ea340')]}],
            'send':[proof(0x12c948d1,'mov','r9b, 1'),proof(0x12c948e5,'call','qword ptr [rax + 0x2b8]')],
            'flush':proof(0x12c9492b,'call','qword ptr [rax + 0x2a8]')},
        'Netspeed':{'id':4,'origin':'Welcome successful parse','field_sequence':[{'wire_type':'32-bit integer','native_source':'connection+0x38','semantic':'configured net speed','evidence':[proof(0x12c94c82,'mov','byte ptr [rsp + 0x50], 4'),proof(0x12c94ce3,'lea','rdx, [r15 + 0x38]'),proof(0x12c94cf7,'mov','r8d, 4'),proof(0x12c94cfd,'call','qword ptr [rax + 0x60]'),proof(0x12c94d02,'call','0x10b4b540')]}],
            'send':proof(0x12c94d28,'call','qword ptr [rax + 0x2b8]'),
            'qualification':'Integer follows native archive byte order; non-swap field is ordinary little-endian32. The buffer fast path is an archive read branch, not source overwriting during actual outgoing serialization.'}}
    with EXE.open('rb') as f,mmap.mmap(f.fileno(),0,access=mmap.ACCESS_READ) as raw:
        if sha(raw)!=EXE_SHA:raise ValueError('PE identity mismatch')
        image=Image(raw)
        interface_entry=image.data(0x1b15bfd0+0x18,8)
        join_entry=image.data(0x1b20b488+0x268,8)
        if struct.unpack('<Q',interface_entry)[0]!=image.base+0x12c93f40 or struct.unpack('<Q',join_entry)[0]!=image.base+0x12c9e550:raise ValueError('Concrete Pending vtable evidence mismatch')
        zero=image.data(0x14ecaa08,4)
        if zero!='0\0'.encode('utf-16le'):raise ValueError('Native ClientResponse literal mismatch')
        outgoing['Login']['client_response_literal']={'rva':'0x14ecaa08','utf16le_bytes':zero.hex(),'sha256':sha(zero),'value':'0'}
        join=read_cached_code(CACHE,0x12c9e550,300,MANIFEST_SHA)
        joinins=list(decoder.disasm(join,0x12c9e550));jb={i.address:i for i in joinins}
        if sum(i.size for i in joinins)!=300:raise ValueError('SendJoin incomplete decode')
        def jp(at,mnemonic,operands):
            i=jb[at]
            if (i.mnemonic,i.op_str)!=(mnemonic,operands):raise ValueError('SendJoin exact evidence mismatch')
            return {'rva':hex(at),'instruction_bytes':bytes(i.bytes).hex(),'instruction':mnemonic+' '+operands}
        outgoing['Join']={'id':9,'root':['0x12c9e550','0x12c9e67c','0x1c8812c4'],'code_bytes':300,'code_sha256':sha(join),
            'immutable_pending_vtable':{'rva':'0x1b20b488','slot':'0x268','entry_sha256':sha(join_entry)},
            'field_sequence':[],'evidence':[jp(0x12c9e564,'mov','byte ptr [rcx + 0xa9], 1'),jp(0x12c9e5c0,'mov','byte ptr [rsp + 0x150], 9'),jp(0x12c9e61e,'call','qword ptr [rax + 0x2b8]'),jp(0x12c9e659,'mov','dl, 1'),jp(0x12c9e675,'jmp','qword ptr [rax + 0x2a8]')],
            'actual_send_gate':'driver+98 connection channel0 at connection+14e0 must exist and channel+30 mask2 must be clear; otherwise no outgoing byte is sent, though Pending+a9 was already set. Flush virtual2a8 always follows.',
            'caller_gate':'This function is separate from the Welcome handler. The TickWorldTravel -> actual LoadMap success -> Pending virtual270 callback -> virtual268 chain below proves Join is sent only after the native map-loading success gate.'}
        init=read_cached_code(CACHE,0x12c90440,2044,MANIFEST_SHA)
        ii=list(decoder.disasm(init,0x12c90440));ib={i.address:i for i in ii}
        if sum(i.size for i in ii)!=2044:raise ValueError('InitNetDriver incomplete decode')
        initfacts=[]
        for at,mn,ops in [(0x12c90648,'lea','rdx, [rsi + 0x28]'),(0x12c9064f,'lea','r8, [rsi + 0x40]'),(0x12c90653,'lea','r9, [rsi + 0xb0]'),(0x12c9065e,'call','qword ptr [rax + 0x270]')]:
            i=ib[at]
            if (i.mnemonic,i.op_str)!=(mn,ops):raise ValueError('Native InitConnect receiver mismatch')
            initfacts.append({'rva':hex(at),'instruction_bytes':bytes(i.bytes).hex(),'instruction':mn+' '+ops})
        tickroot,ticklength,tickfragments=image.function_span(0x13075490)
        if ticklength!=1858:raise ValueError('TickWorldTravel bounded span mismatch')
        tick=read_cached_code(CACHE,0x13075490,ticklength,MANIFEST_SHA)
        ti=list(decoder.disasm(tick,0x13075490));tb={i.address:i for i in ti}
        if sum(i.size for i in ti)!=ticklength or sha(tick)!='17c7ffe6d8dde2fc46c29d69ef800b70758a44317ec6248e5115b48890af7af4':raise ValueError('TickWorldTravel code SHA/decode mismatch')
        def tp(at,mn,ops):
            i=tb[at]
            if (i.mnemonic,i.op_str)!=(mn,ops):raise ValueError('TickWorldTravel exact gate mismatch')
            return {'rva':hex(at),'instruction_bytes':bytes(i.bytes).hex(),'instruction':mn+' '+ops}
        callbackroot,callbacklength,callbackfragments=image.function_span(0x12c931b0)
        if callbacklength!=315 or struct.unpack('<Q',image.data(0x1b20b488+0x270,8))[0]!=image.base+0x12c931b0:raise ValueError('Pending post-load callback static target mismatch')
        callback=read_cached_code(CACHE,0x12c931b0,315,MANIFEST_SHA)
        ci=list(decoder.disasm(callback,0x12c931b0));cb={i.address:i for i in ci}
        if sum(i.size for i in ci)!=315:raise ValueError('Pending post-load callback incomplete decode')
        def cp(at,mn,ops):
            i=cb[at]
            if (i.mnemonic,i.op_str)!=(mn,ops):raise ValueError('Pending post-load exact gate mismatch')
            return {'rva':hex(at),'instruction_bytes':bytes(i.bytes).hex(),'instruction':mn+' '+ops}
        tick_flow={'root':list(map(hex,tickroot)),'span_bytes':ticklength,'code_sha256':sha(tick),'full_decode':True,
            'fragments':[[hex(a),hex(b)] for a,b in tickfragments],
            'identity':'Two exact immutable UTF16 UEngine::TickWorldTravel logs have verified LEA instruction-boundary refs at130754f0 and1307570f in this exact root.',
            'context_mapping':'RSI=WorldContext, R14=Engine, R15=0. WorldContext+1a0 is PendingNetGame pointer; +218 is optional GameInstance; +278 is current World.',
            'step1_tick_pending':[tp(0x130758b8,'mov','rcx, qword ptr [rsi + 0x1a0]'),tp(0x130758ce,'call','qword ptr [rax + 0x258]')],
            'step2_error_gate':[tp(0x130758e4,'mov','eax, dword ptr [rdx + 0xb8]'),tp(0x130758f4,'lea','ecx, [rax - 1]'),tp(0x130758f7,'cmove','ecx, r15d'),tp(0x130758fd,'jle','0x13075a9a')],
            'step2_error_gate_semantic':'Only zero-length/terminator-only Pending.error FStringB0 reaches success gates. Nonempty error triggers failure callbacks/cancel path.',
            'step3_markers':[tp(0x13075a9a,'cmp','byte ptr [rdx + 0xa8], r15b'),tp(0x13075aa1,'je','0x13075a6c'),tp(0x13075aa3,'cmp','byte ptr [rdx + 0xa9], r15b'),tp(0x13075aaa,'jne','0x13075a6c')],
            'step3_marker_semantic':'Pending+a8 must be nonzero, Pending+a9 must still be zero.',
            'step4_optional_game_instance_gate':[tp(0x13075aac,'mov','rcx, qword ptr [rsi + 0x218]'),tp(0x13075ac2,'call','qword ptr [rax + 0x338]'),tp(0x13075ac8,'test','al, al'),tp(0x13075aca,'jne','0x13075a6c')],
            'step4_qualification':'If GameInstance exists, virtual338 true defers map load; method name/runtime override not inferred.',
            'step5_map_validation_normalization':[tp(0x13075ad3,'mov','rdx, qword ptr [rsi + 0x1a0]'),tp(0x13075add,'add','rdx, 0x68'),tp(0x13075ae1,'call','0x13066140'),tp(0x13075ae6,'test','al, al'),tp(0x13075ae8,'jne','0x13075b17')],
            'step5_qualification':'Helper13066140 is complete260 bytes and can rewrite the Map FString; false goes to failure3 before actual LoadMap. Lower package-name helper identities are not all recovered, so no rule substitutes a guessed path.',
            'step6_actual_load_map':[tp(0x13075b2a,'lea','rdx, [rbx + 0x40]'),tp(0x13075b2e,'call','0x213af80'),tp(0x13075b33,'mov','r8, rax'),tp(0x13075b36,'mov','r9, rbx'),tp(0x13075b3d,'mov','rdx, rsi'),tp(0x13075b40,'mov','rcx, r14'),tp(0x13075b43,'mov','qword ptr [rsp + 0x20], rax'),tp(0x13075b48,'call','qword ptr [rdi + 0x448]')],
            'step6_semantic':'Engine virtual448 receives WorldContext, copied Pending.URL, PendingNetGame, FString error output. Its returned bool is used as actual load success; concrete Engine runtime override is not read.',
            'step7_callback_after_load':[tp(0x13075b63,'movzx','r9d, al'),tp(0x13075b67,'mov','rdx, r14'),tp(0x13075b6a,'mov','r8, rsi'),tp(0x13075b6d,'call','qword ptr [r10 + 0x270]')],
            'step8_join_on_success':{'callback_root':list(map(hex,callbackroot)),'bytes':315,'code_sha256':sha(callback),'full_decode':True,
                'fragments':[[hex(a),hex(b)] for a,b in callbackfragments],
                'evidence':[cp(0x12c931c4,'test','r9b, r9b'),cp(0x12c931c7,'je','0x12c93232'),cp(0x12c931e2,'lea','rdx, [rip + 0x22304bf]'),cp(0x12c931ec,'call','0x10a137d0'),cp(0x12c931f3,'jne','0x12c93232'),cp(0x12c93204,'call','qword ptr [rax + 0x450]'),cp(0x12c9320a,'mov','rcx, qword ptr [rbx + 0x1a0]'),cp(0x12c93214,'call','qword ptr [rax + 0x268]'),cp(0x12c93221,'mov','qword ptr [rax + 0x30], 0')],
                'semantic':'Only LoadMap bool=true and error string equal empty reaches enginevirtual450(EDX0), Pendingvirtual268(SendJoin9), and clearing Pending.driver+30. Other callback paths handle failure/load completion without forcing Join.'},
            'step9_context_cleanup':tp(0x13075b78,'mov','qword ptr [r12], r15')}
        report={'kind':'PendingNativeControlFlow','client_sha256':EXE_SHA,'cache_manifest_sha256':MANIFEST_SHA,
            'scope':{'offline_only':True,'live_process_read':False,'game_started':False,'UAC_requested':False,'client_or_server_modified':False,'runtime_instance_vptr_verified':False},
            'source_evidence':[source(FOLDER/'classbody.source.json'),source(FOLDER/'constructor.source.json'),source(FOLDER/'notify.switch-audit.json'),source(EDGE/'vslot_268_12c9e550.source.json'),source(EDGE/'vslot_270_12c931b0.source.json'),source(EDGE/'direct_130aa2d0.source.json'),source(EDGE/'direct_1307ee40.source.json'),source(EDGE/'direct_13066140.source.json'),source(EDGE/'direct_213af80.source.json'),source(LOGS/'index.json'),source(ROOT/'work/evidence/native-string-field-109ea340-semantics.json'),source(ROOT/'work/evidence/control-helper-12bab170-1779fa0-native-analysis.json')],
            'concrete_class_notify_path':{'class_body':'133a23e0 exact PendingNetGame label and constructor callback133a20a0','constructor':'133a20a0 initializer tailcalls12c7a7b0; ctor installs UObject vptr1b20b488 atobject0 and FNetworkNotify vptr1b15bfd0 atobject28','interface_entry':{'table_rva':'0x1b15bfd0','slot':'0x18','target_rva':'0x12c93f40','entry_sha256':sha(interface_entry)},
                'init_net_driver_receiver_evidence':initfacts,'init_net_driver_root':'0x12c90440','init_net_driver_code_sha256':sha(init),
                'qualification':'InitConnect virtual+270 is supplied the constructed object+28 interface. The actual driver+218 assignment body and runtime driver class were not inspected. Ordinary Control ReceivedBunch dispatch uses connection.driver+218 then notify virtual+18 as previously verified.'},
            'switch':{k:switch[k] for k in ('exact_root','span_bytes','span_sha256','code_range','code_bytes','code_sha256','code_partition_fully_decoded','declared_span_is_all_instruction_bytes','table_range','table_bytes','table_sha256','table_entries','default')},
            'inbound':incoming,'outbound':outgoing,
            'log_identity':[s for s in switch['static_string_refs'] if s['rva'] in ('0x1b20e450','0x1b20e4a8','0x15e6f8d8','0x14ecaa08')],
            'map_load_to_join':tick_flow,
            'minimal_verified_flow':['client Hello0 -> server Challenge3(FString)','client Login5(FStringResponse,FStringURL,nativeUniqueNetId,FStringPlatform)','server Welcome1(FStringLevel,FStringGame,FStringRedirectURL)','client Netspeed4(int32) then Pending+a8=1','TickWorldTravel checks error/a8/a9/GI gate and validates Map; actual engineLoadMap must succeed','Pending post-load callback invokes SendJoin9; Pending.driver/context are cleared after handoff'],
            'implementation_limits':['Use an actual locally available map package path for Welcome Level; display label/map number is not a package identifier. This report does not certify a particular package path.','Respect own local account identity checks; native field syntax is not account authentication. No official account or current ID value was read.','NMT Welcome/Join do not create map authority, GameState, actors, pawn, scene replication or bots. Full playable server remains separate work.','Concrete GameInstance delay and EngineLoadMap overrides are not inspected, and no client state/UI marker is forced.']}
        out=ROOT/'work/evidence/PendingNativeControlFlow-1790902501634810000.json'
        out.write_text(json.dumps(report,indent=2,ensure_ascii=False)+'\n',encoding='utf-8')
        print(json.dumps({'output':str(out),'sha256':sha(out.read_bytes()),'verified_flow':report['minimal_verified_flow'],'code_partition_bytes':4740,'switch_table_bytes':84,'no_live_access':True},ensure_ascii=False))

if __name__=='__main__':run()
