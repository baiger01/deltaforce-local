"""Offline updated StatelessConnect handshake and handler-framing evidence.

No launch, process access, native invocation/emulation, runtime edits, secret
state reads or blanket approval of the existing server experiment.
"""
import argparse
import importlib.util
import json
import struct
import sys

from research_updated_metadata_roots import (
    ROOT, CLIENT, PINS, ForensicObservation, disasm, instruction_row, sha,
)
from research_updated_replication_core import compare_full
from research_updated_transport_roots import TransportImage
from research_updated_cache_initialization import unwind_inventory


INPUT_PINS = {
    'work/research_updated_metadata_roots.py': 'ea107a5bc475bea3ec262dd26ea91283b6fdfa5ad564e29fec3763b737c32cf6',
    'work/research_updated_replication_core.py': '3f9938b62167eba78650c869261f9e6e76f2e8582e058134d9f2739ca5af7c83',
    'work/research_updated_transport_roots.py': 'e6d76c794fd47d3010d0dde44c4986c51b1458f20e20ab7cc7c542a5d64be006',
    'work/research_updated_cache_initialization.py': '88e2502c09aeef23013c77ec3877e587ed4e10ee8785afb7a9a90ac3282fa9dd',
    'work/research_updated_transport_79fb7b10.json': 'd127c9b551192ba1a126f3b5f5e2c90f9a9a6a0e6d4ff806b6d037941fb73e92',
    'work/research_updated_transport_profile_79fb7b10.json': '2e55c4989ddb28f7ae75a6ddfd62e92f50d77bc523a99aebbf84ffd65ccd43c8',
    'work/read_named_ds_transport_code.py': '4961aab383fe69885316383fb8eb25e3b13e94493dbbdb2da1e06b2569019949',
    'work/analyze_ds_wire_samples.py': 'b57920933ff65283fa480a90c19af6eab226a3888195cc01e1bb786f94aaaa73',
    'work/analyze_ds_implementation_samples.py': '87f58115277a0c5f73f2705eea46123025d8c397b16630d61e84a6112239497f',
    'work/locate_native_ds_transport.py': 'e84a153407bd5241837a187830ccb679f2137032aa12fa08a88f855ba55f23a9',
    'outputs/df-local-server/dfserver/transport/native/unreal_handshake_payload.py':
        '03e55029883a3ad69edeb77f9252ddf6ec0152cd155de89da5d7301929fc1b2b',
    'outputs/df-local-server/dfserver/transport/native/legacy_ds_handshake_probe.py':
        '336468cdb66f364666b6554a6addf40b4224f44ddacdd8e104a1374c802aba6c',
}
PAIRS = [
    ('stateless_factory', 0x12bb12f0, 0x12bb1640),
    ('stateless_constructor', 0x12baa160, 0x12baa4b0),
    ('magic_header_cvar_registration', 0xca7e60, 0xca7ee0),
    ('handshake_parser', 0x12bc2a90, 0x12bc2de0),
    ('send_initial_packet', 0x12bc1850, 0x12bc1ba0),
    ('send_challenge_response', 0x12bc91a0, 0x12bc94f0),
    ('send_challenge_ack', 0x12bc8f30, 0x12bc9280),
    ('send_connect_challenge', 0x12bc94c0, 0x12bc9810),
    ('send_restart_request', 0x12bc97b0, 0x12bc9b00),
    ('incoming', 0x12bb9b40, 0x12bb9e90),
    ('incoming_connectionless', 0x12bb9f70, 0x12bba2c0),
    ('outgoing', 0x12bc2600, 0x12bc2950),
    ('init_from_connectionless_body', 0x12bbac20, 0x12bbaf70),
    ('set_driver_body', 0x12bce660, 0x12bce9b0),
    ('restart_handshake_body', 0x12bc8230, 0x12bc8580),
    ('cookie_sequence_copy', 0x12bb8f50, 0x12bb92a0),
    ('generate_cookie', 0x12bb6020, 0x12bb6370),
    ('get_challenge_sequence', 0x1313f030, 0x1313ed70, 12),
    ('has_passed_challenge_2d8', 0x1313e630, 0x1313e520),
    ('get_cookie', 0x1313f670, 0x1313f410),
    ('reset_challenge_data', 0x1313f360, 0x1313efd0),
    ('restarted_handshake_match', 0x1313f120, 0x1313ee50, 55),
    ('handler_handshake_complete', 0x12430d90, 0x12431110),
    ('packet_handler_initialize', 0x12431950, 0x12431cd0),
    ('packet_handler_incoming', 0x12430290, 0x12430610),
    ('packet_handler_outgoing', 0x12431040, 0x124313c0),
    ('base_connection_received_raw_packet', 0x12b9dc60, 0x12b9dfb0),
    ('named_packet_receive_logger', 0x49c0f60, 0x49c0b70),
    ('named_packet_send_logger', 0x49c1200, 0x49c0e10),
    ('named_connection_receive_logger', 0x49bf000, 0x49bec10),
    ('named_connection_send_logger', 0x49bf960, 0x49bf570),
]


def read_inputs():
    for path,expected in INPUT_PINS.items():
        if sha((ROOT/path).read_bytes()) != expected:
            raise ValueError('Handshake input changed: '+path)
    return [dict(path=p,sha256=h) for p,h in INPUT_PINS.items()]


def static_thunk(old,new,name,old_rva,new_rva,length,old_exit,new_exit):
    oi,ni = disasm(old,old_rva,length),disasm(new,new_rva,length)
    if sum(x.size for x in oi)!=length or sum(x.size for x in ni)!=length or len(oi)!=len(ni):
        raise ValueError('Named thunk extent changed')
    if old.read(old_rva+length,1)!=b'\xcc' or new.read(new_rva+length,1)!=b'\xcc':
        raise ValueError('Named thunk padding boundary changed')
    refs=[]
    for a,b in zip(oi,ni):
        if (a.address-old_rva,a.id,a.size)!=(b.address-new_rva,b.id,b.size):
            raise ValueError('Named thunk shape changed')
        aa,bb=bytearray(a.bytes),bytearray(b.bytes)
        if a.mnemonic.startswith('j'):
            if a.op_str!=old_exit or b.op_str!=new_exit:
                raise ValueError('Explicit thunk exit changed')
            if a.imm_size:
                aa[a.imm_offset:a.imm_offset+a.imm_size]=bytes(a.imm_size)
                bb[b.imm_offset:b.imm_offset+b.imm_size]=bytes(b.imm_size)
            refs.append(dict(old_instruction=hex(a.address),new_instruction=hex(b.address),old_exit=a.op_str,new_exit=b.op_str))
        if aa!=bb:
            raise ValueError('Non-reference thunk bytes changed')
    return dict(name=name,old_rva=hex(old_rva),new_rva=hex(new_rva),bytes=length,
        old_code_sha256=sha(old.read(old_rva,length)),new_code_sha256=sha(new.read(new_rva,length)),
        full_linear_decode=True,all_non_reference_instruction_bytes_identical=True,
        structure_displacements_and_nonaddress_immediates_are_not_masked=True,
        boundary_basis='Explicit bounded named tail thunk/conditional tail and final ret followed by int3.',
        new_fragments=[],references=refs,decoded_new_instructions=[instruction_row(i) for i in ni])


def qualify():
    pins=read_inputs()
    old,new,image=ForensicObservation('old'),ForensicObservation('new'),TransportImage()
    functions=[compare_full(old,new,image,*row) for row in PAIRS]
    functions += [static_thunk(old,new,*row) for row in [
        ('notify_handshake_begin_named_thunk',0x13ab170,0x13ab100,7,
         'qword ptr [rax + 0x68]','qword ptr [rax + 0x68]'),
        ('init_from_connectionless_named_thunk',0x1313e540,0x1313e460,5,'0x12bbac20','0x12bbaf70'),
        ('set_driver_named_thunk',0x1313f500,0x1313f170,5,'0x12bce660','0x12bce9b0'),
        ('restart_handshake_named_thunk',0x1313f580,0x1313f1f0,5,'0x12bc8230','0x12bc8580'),
        ('initialize_vslot60_conditional_tail',0x12bbb3b0,0x12bbb700,15,'0x12430d90','0x12431110'),
    ]]
    rows={int(i['rva'],16):i for f in functions for i in f['decoded_new_instructions']}
    witnesses=[]

    def exact(rule,address,expected):
        actual=rows.get(address)
        if actual is None or actual['instruction']!=expected:
            raise ValueError('Handshake instruction witness changed: '+rule+': '+str(actual))
        witnesses.append(dict(rule=rule,**actual))

    for check in [
        ('Factory constructs stateless body',0x12bb16ad,'call 0x12baa4b0'),
        ('Constructor magic header starts with zero Num/Max',0x12baa543,'mov qword ptr [rsi + 0xd0], rdi'),
        ('Constructor reads actual magic header console value',0x12baa55a,'mov rbp, qword ptr [rip + 0xb94c24f]'),
        ('Magic header string excludes terminator, maximum32bits',0x12baa5e2,'cmp eax, 0x20'),
        ('Magic header accepts binary0/1 only',0x12baa679,'cmp ax, 1'),
        ('Invalid magic header resets bit count',0x12baa6f5,'mov dword ptr [rsi + 0xd0], edi'),
        ('CVar registration empty FString data',0xca7eef,'mov qword ptr [rsp + 0x30], rbx'),
        ('CVar registration empty FString Num/Max',0xca7ef4,'mov qword ptr [rsp + 0x38], rbx'),
        ('CVar registration flags0',0xca7f19,'mov dword ptr [rsp + 0x20], ebx'),
        ('Parser ordinary remaining194bits',0x12bc2e17,'cmp eax, 0xc2'),
        ('Parser extended remaining354bits',0x12bc2e22,'cmp eax, 0x162'),
        ('Parser also has mini2bit branch',0x12bc2e2d,'cmp eax, 2'),
        ('Parser also has mini1bit branch',0x12bc2f10,'cmp eax, 1'),
        ('Parser full first field read advances1bit',0x12bc2fd2,'inc qword ptr [rbx + 0xa8]'),
        ('Parser timestamp32-bit raw value',0x12bc304e,'mov dword ptr [rax], ecx'),
        ('Parser ordinary cookie20bytes',0x12bc307e,'mov r8d, 0x14'),
        ('Parser extended second cookie20bytes',0x12bc309e,'mov r8d, 0x14'),
        ('Initial alloc prefixbits+196bits',0x12bc1bfc,'add eax, 0xc4'),
        ('Initial copies configured prefix bits',0x12bc1c42,'call 0x10b4ac50'),
        ('Initial first discriminator true',0x12bc1c47,'mov dl, 1'),
        ('Initial restart flag follows component9c',0x12bc1c53,'cmp byte ptr [rdi + 0x9c], 0'),
        ('Initial third flag false',0x12bc1c67,'xor edx, edx'),
        ('Initial timestamp+cookie is24zero bytes',0x12bc1c81,'mov r8d, 0x18'),
        ('Initial terminator true',0x12bc1cf4,'mov dl, 1'),
        ('Initial bypasses ordinary PacketHandler outgoing',0x12bc1d04,'mov byte ptr [rax + 0x290], 1'),
        ('Initial uses connection low-level send slot288',0x12bc1d47,'call qword ptr [r10 + 0x288]'),
        ('Response chooses ordinary196 or extended356 capacity',0x12bc953e,'mov ecx, 0x164'),
        ('Response third flag from argument',0x12bc95be,'movzx edx, r12b'),
        ('Response cookie20bytes',0x12bc9644,'mov r8d, 0x14'),
        ('Response restart appends old authorized cookie+9d',0x12bc9660,'lea rdx, [rdi + 0x9d]'),
        ('Response terminator true',0x12bc96d7,'mov dl, 1'),
        ('Response sequence0 from low14 cookie word0',0x12bc977e,'and eax, 0x3fff'),
        ('Response sequence1 from low14 cookie word1',0x12bc978a,'and eax, 0x3fff'),
        ('Ack timestamp bit pattern minus1float',0x12bc92d6,'mov dword ptr [rbp + 0x30], 0xbf800000'),
        ('Ack restart false',0x12bc9317,'xor edx, edx'),
        ('Ack third flag true',0x12bc9323,'mov dl, 1'),
        ('Ack cookie20bytes',0x12bc9371,'mov r8d, 0x14'),
        ('Ack terminator true',0x12bc93e5,'mov dl, 1'),
        ('Native challenge timestamp from driver+220',0x12bc986e,'movss xmm0, dword ptr [rax + 0x220]'),
        ('Native challenge third flag component50',0x12bc9922,'movzx edx, byte ptr [rdi + 0x50]'),
        ('Native challenge cookie20bytes',0x12bc9973,'mov r8d, 0x14'),
        ('Native mini restart request is variable2or3bodybits',0x12bc9b3f,'add ecx, 3'),
        ('Incoming skips configured prefix length',0x12bb9eb4,'movsxd rcx, dword ptr [rcx + 0xd0]'),
        ('Incoming consumes discriminator1bit',0x12bb9f9c,'inc qword ptr [rdi + 0xa8]'),
        ('Incoming then calls parser',0x12bba003,'call 0x12bc2de0'),
        ('Client positive timestamp path responds',0x12bba1f3,'call 0x12bc94f0'),
        ('Client normal negative ack initializes cookie sequence',0x12bba243,'call qword ptr [rax + 0x310]'),
        ('Client negative ack completes handshake',0x12bba26a,'call 0x12431110'),
        ('Client restart negative ack bypasses sequence initialization',0x12bba20d,'cmp byte ptr [rbx + 0x9c], 0'),
        ('Outgoing ordinary packet adds prefix plus discriminator0',0x12bc29bf,'xor edx, edx'),
        ('PacketHandler component count',0x1243062b,'cmp dword ptr [rcx + 0x200], 0'),
        ('PacketHandler reads final byte',0x12430648,'movzx r9d, byte ptr [rax + r8 - 1]'),
        ('PacketHandler excludes highest set terminator bit',0x12430657,'dec r10d'),
        ('PacketHandler scans padding above terminator',0x12430663,'add r9b, r9b'),
        ('PacketHandler connectionless virtual slot30',0x12430828,'call qword ptr [rax + 0x30]'),
        ('PacketHandler connected virtual slot18',0x1243084e,'call qword ptr [rax + 0x18]'),
        ('PacketHandler raw-send flag skips ordinary outgoing components',0x124313d6,'cmp byte ptr [rcx + 0x290], 0'),
        ('Raw-send branch returns original payload',0x1243183d,'mov qword ptr [rdx], r12'),
        ('Raw-send branch returns original bit length',0x12431840,'mov dword ptr [rdx + 8], ebx'),
        ('Ordinary PacketHandler outgoing appends termination1',0x124315e1,'mov dl, 1'),
        ('Base connection actual PacketHandler pointer+168',0x12b9e036,'mov rcx, qword ptr [rbx + 0x168]'),
        ('Base connection invokes qualified PacketHandler Incoming',0x12b9e069,'call 0x12430610'),
    ]:
        exact(*check)

    immutable=[]

    def datum(label,address,length):
        raw=image.read(address,length)
        section=next((r,s,o) for r,s,o in image.sections if r<=address<address+length<=r+s)
        immutable.append(dict(label=label,rva=hex(address),file_offset=hex(section[2]+address-section[0]),
            bytes=length,bytes_hex=raw.hex(),sha256=sha(raw)))
        return raw

    def wide(label,address,value):
        raw=datum(label,address,(len(value)+1)*2)
        if raw!=(value+'\0').encode('utf-16-le'):
            raise ValueError('Handshake immutable string changed: '+label)

    wide('Stateless class factory name',0x1b1e32e0,'StatelessConnectHandlerComponent')
    wide('Console variable name',0x1b1dc5b8,'net.MagicHeader')
    stateless_table=struct.unpack('<21Q',datum('Constructor-backed Stateless vtable',0x1b1e3238,21*8))
    expected_slots={0x18:0x12bb9e90,0x20:0x12bc2950,0x30:0x12bba2c0,
                    0x60:0x12bbb700,0x68:0x12bc1ba0}
    if any(stateless_table[slot//8]!=image.image_base+target for slot,target in expected_slots.items()):
        raise ValueError('Stateless vtable mapping changed')
    if struct.unpack('<Q',datum('Base connection ReceivedRawPacket vslot338',0x1b1d5fa0+0x338,8))[0]!=image.image_base+0x12b9dfb0:
        raise ValueError('Base connection receiver binding changed')
    for address,target in [(0x12bb16b2,0x1b1e3238),(0x12baa4cc,0x1b1e3238)]:
        ins=next(i for f in functions for i in f['decoded_new_instructions'] if int(i['rva'],16)==address)
        if ins.get('rip_targets')!=[hex(target)]:
            raise ValueError('Factory/constructor vtable reference changed')
    names={
        'NotifyHandshakeBegin':0x13ab100,'InitFromConnectionless':0x1313e460,
        'HasPassedChallenge_2d8':0x1313e520,'GetChallengeSequence':0x1313ed70,
        'DoesRestartedHandshakeMatch':0x1313ee50,'ResetChallengeData':0x1313efd0,
        'SetDriver':0x1313f170,'RestartHandshakeRequest':0x1313f1f0,'GetCookie':0x1313f410,
    }
    bindings=[]
    for address in range(0x1b2ca8c0,0x1b2cab00,48):
        raw=datum('Stateless native reflection method record',address,48)
        name,impl,invoker,result,args,count=struct.unpack('<6Q',raw)
        label=image.read(name-image.image_base,96).split(b'\0')[0].decode('ascii')
        if label not in names:
            continue
        first_type=struct.unpack('<Q',image.read(args-image.image_base,8))[0]
        first_label=image.read(first_type-image.image_base,96).split(b'\0')[0].decode('ascii')
        if impl-image.image_base!=names[label] or first_label!='StatelessConnectHandlerComponent *' or not 1<=count<=8:
            raise ValueError('Exact native Stateless binding changed')
        bindings.append(dict(name=label,record_rva=hex(address),implementation_rva=hex(impl-image.image_base),
            first_argument_type=first_label,argument_count=count))
    if len(bindings)!=len(names):
        raise ValueError('Missing selected stateless native method record')
    inventory=unwind_inventory(image,functions,[])
    inventory.pop('leaf_crc_boundary')
    inventory['explicit_small_functions']=[dict(name=f['name'],bytes=f['bytes'],basis=f['boundary_basis'])
        for f in functions if not f['new_fragments']]

    # Exercise only the pure Python payload codec against native-derived append order.
    codec_path=ROOT/'outputs/df-local-server/dfserver/transport/native/unreal_handshake_payload.py'
    spec=importlib.util.spec_from_file_location('updated_handshake_pure_codec',codec_path)
    codec=importlib.util.module_from_spec(spec)
    sys.modules[spec.name]=codec
    spec.loader.exec_module(codec)
    fixtures=[]
    for name,restart,third,timestamp,cookie,old_cookie in [
        ('initial',False,False,0.0,bytes(20),None),
        ('challenge',False,False,1.5,bytes(range(20)),None),
        ('echo_thirdflag1',False,True,1.5,bytes(range(20)),None),
        ('ack',False,True,-1.0,bytes(range(20)),None),
        ('extended_restart_echo',True,False,2.5,bytes(range(20)),bytes(range(20,40))),
    ]:
        bits=[1,int(restart),int(third)]
        values=struct.pack('<f',timestamp)+cookie+(old_cookie or b'')
        bits.extend((byte>>bit)&1 for byte in values for bit in range(8))
        body_bits=len(bits)
        bits.append(1)
        expected=bytearray((len(bits)+7)//8)
        for at,value in enumerate(bits):
            expected[at//8]|=value<<(at%8)
        payload=codec.LegacyHandshakePayload(restart,third,timestamp,cookie,old_cookie)
        encoded=codec.encode_payload(payload)
        if encoded!=bytes(expected) or codec.decode_payload(encoded)!=payload:
            raise ValueError('Pure payload codec differs from native-derived append layout')
        fixtures.append(dict(name=name,body_bits=body_bits,wire_bits_with_terminator=len(bits),
            wire_bytes=len(encoded),bytes_hex=encoded.hex(),sha256=sha(encoded),
            native_executed=False,native_emulated=False))

    missing_paths=[p for p in [
        'work/evidence/ds-readonly-transport',
        'work/evidence/native-restart-handshake-minimal-state-machine.json',
        'work/evidence/native_ds_transport_locations.json'] if not (ROOT/p).exists()]
    return dict(kind='updated_stateless_handshake_offline_qualification',
        client_sha256=PINS['new'][2],historical_client_sha256=PINS['old'][2],
        process_access=False,native_called=False,native_emulated=False,client_launched=False,
        runtime_sources_changed=False,native_acceptance_verified=False,input_sources=pins,
        functions=functions,exact_instruction_witnesses=witnesses,immutable_data=immutable,
        native_named_bindings=bindings,unwind_inventory=inventory,
        stateless_vtable=dict(rva='0x1b1e3238',basis='Exact constructor/factory RIP references plus immutable qword targets.',
            slots={hex(k):hex(v) for k,v in expected_slots.items()}),
        ordinary_body_layout=[
            dict(start_bit=0,bits=1,value=1,meaning='Stateless handshake discriminator'),
            dict(start_bit=1,bits=1,meaning='restart boolean'),
            dict(start_bit=2,bits=1,meaning='third boolean; echoed challenge field, kept generic by codec'),
            dict(start_bit=3,bits=32,meaning='raw float32 little-endian timestamp'),
            dict(start_bit=35,bits=160,meaning='opaque20-byte cookie'),
            dict(start_bit=195,bits=1,value=1,meaning='native writer termination bit'),
            dict(start_bit=196,bits=4,value=0,meaning='zero storage padding for no MagicHeader prefix'),
        ],extended_body_layout=dict(ordinary_first195bits=True,old_cookie_start_bit=195,
            old_cookie_bits=160,termination_bit=355,padding_bits=4,wire_bytes_when_prefix0=45),
        native_flow=[
            'SendInitialPacket emits discriminator1, component restart flag, third flag0, timestamp0+zero cookie, terminator1.',
            'Native connectionless receiver consumes optional MagicHeader prefix and discriminator, parser requires remaining194bits (ordinary) or354bits (extended), then reads booleans/float32/cookie(s).',
            'Native server challenge uses driver timestamp+220, component third flag+50 and20-byte generated cookie; native client positive timestamp branch echoes using SendChallengeResponse.',
            'Native ACK writes restart0, third flag1, float32 -1,20-byte authorized cookie and terminator1.',
            'Normal native client negative ACK initializes14-bit sequences from cookie words0/1, stores authorized cookie, completes handshake. Restart ACK skips sequence/cookie replacement branch.',
        ],
        handler_framing=dict(
            packet_handler_incoming_rva='0x12430610',
            packet_handler_outgoing_rva='0x124313c0',
            terminator='If component count>0, final byte must be nonzero; highest set bit is excluded with higher zero padding. Remaining bits feed FBitReader.',
            stateless_dispatch='Connected vslot18 or connectionless vslot30 using actual constructor-backed Stateless vtable.',
            handshake_writers_direct_send='Writers already append their own terminator and set Handler+290 bypass flag while invoking connection vslot288 or driver vslot300. No ordinary outgoing zero discriminator should be prepended again.',
            ordinary_data='Stateless Outgoing prepends configured MagicHeader bits then discriminator0 to an ordinary packet; this is a distinct path from handshake direct send.',
            magic_header=dict(console_variable='net.MagicHeader',registration_rva='0xca7ee0',
                default='empty FString',registered_flags=0,value_cell_rva='0x1e4f67b0',
                constructor_rva='0x12baa4b0',prefix_bits_count_offset='0xd0',prefix_bit_storage_offset='0xb8',
                maximum_valid_bits=32,invalid_value_clears_prefix=True,
                current_runtime_value_observed=False),
            native_core_framing_qualified=True,current_raw_udp_envelope_qualified=False,
            current_handler_chain_observed=False),
        pure_codec_fixtures=fixtures,
        existing_probe_scope=dict(
            payload_codec_source=codec_path.relative_to(ROOT).as_posix(),
            ordinary25_and_extended45_codec_layout_qualified=True,
            current_code_skips_client_bytes=8,server_response_bytes=25,
            current_client_outer8_interpretation_qualified=False,
            restart_full_state_machine_approved=False,
            native_mini_restart_request_missing_from_codec=True,
            mini_restart_detail='Native parser additionally supports remaining1/2bits; SendRestartRequest emits2/3body bits plus terminator, unlike fixed25/45-byte payload codec.',
            arbitrary20byte_loopback_nonce='Local diagnostic policy. Native server HMAC/secret rotation semantics and account authorization are not implemented/approved by body layout proof.',
            named_packet_loggers='Named OnPacketRecv/OnPacketSend direct targets serialize diagnostics and call trace helpers. Their matching does not identify or qualify an eight-byte UDP transform.'),
        next_concrete_probe=dict(
            passive_new_build_udp_capture_ready_without_old_memory_reader=True,
            stateless_payload_only_serializer_can_be_reused_with_explicit_new_proof=True,
            fully_qualified_raw_udp_challenge_reply_ready=False,
            ordinary_handshake_isolated_scope='packet_ack_probe=False, control_probe=False, no admissions, no Actor/schema construction; record all datagrams/directions and explicit new EXE identity.',
            required_before_claiming_response_envelope_qualified=[
                'Current new-build raw UDP initial datagram observation and verified body start/length; capture alone can supply this without opening a memory reader.',
                'Actual enabled handler chain and runtime net.MagicHeader prefix length/value, or packet observations proving the no-prefix single-stateless subset for this connection.',
                'Actual custom driver/socket envelope path or a current native initial→challenge→echo observation proving the direction-specific raw reply envelope. The eight stripped client bytes cannot be explained by a maximum32-bit MagicHeader.',
            ],
            exact_unresolved_native_boundary='Stateless direct send uses connection virtual+288 / NetDriver virtual+300 and CanSend+380; actual derived driver/socket targets and routing prefix transform are not observed in these class-only captures.',
            old_hash_spoofing_required=False,
            implementation_boundary='Use a new explicit diagnostic profile keyed by new EXE SHA and these proof hashes. Keep historical metadata readers/image gates unchanged; handshake payload codec is pure and needs no old-image session.'),
        missing_historical_files=missing_paths,
        limits=[
            'Historical handshake JSON/dfcode files are absent; old/new code is rederived from exact pinned complete code observations, with updated immutable named records and constructor-backed vtable evidence.',
            'Whole function comparisons retain all field/slot offsets and nonaddress constants. Only RIP references and direct control-flow operands may relocate; dynamic callees and runtime overrides are not approved wholesale.',
            'Current packet capture acceptance remains necessary to qualify the proprietary raw UDP envelope. Native core bit layout equality does not prove existing outer8 stripping or bare25-byte response acceptance.',
            'Only pure Python codec fixtures executed. No native code was executed/emulated and no secret, account, process or runtime source was accessed/modified.',
        ],source_observations=[old.source_evidence(),new.source_evidence()],
        research_script=dict(path='work/research_updated_stateless_handshake.py',
            sha256=sha((ROOT/'work/research_updated_stateless_handshake.py').read_bytes())))


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--qualify',action='store_true',required=True)
    parser.parse_args()
    result=qualify()
    path=ROOT/'work/research_updated_stateless_handshake_79fb7b10.json'
    raw=(json.dumps(result,indent=2)+'\n').encode('utf-8')
    path.write_bytes(raw)
    print(json.dumps(dict(output=path.relative_to(ROOT).as_posix(),sha256=sha(raw),
        functions=len(result['functions']),witnesses=len(result['exact_instruction_witnesses']),
        native_core_framing_qualified=True,current_raw_udp_envelope_qualified=False)))


if __name__=='__main__':
    main()
