"""Offline updated Control grammar qualification; never opens a game process.

Compares complete saved native bodies, with explicitly partitioned switch data,
and checks the already captured updated Hello. Does not select a runtime profile,
change a build guard, send packets, or claim native map/gameplay acceptance.
"""
import argparse
import bisect
import json
import mmap
import struct
import sys
from pathlib import Path

from capstone.x86 import X86_OP_IMM, X86_OP_MEM, X86_REG_RIP
from research_updated_metadata_roots import (
    ROOT, PINS, CLIENT, ForensicObservation, sha, disasm, instruction_row,
)
from research_updated_transport_roots import TransportImage
from research_updated_replication_core import compare_full


OUTPUT = ROOT / 'work/evidence/updated-control-contract-79fb7b10.json'
CAPTURE = ROOT / 'work/native-client-tests/1792984987382326700/game-server-packets'
CAPTURE_PINS = {
    '05-udp.bin': '3e10e018138dd51128c9d6cd986a0f6d4fa543575fba6a12b23600b095d68ec5',
    'report.json': '3fcfba8a0133183cef2dd23972c3c99859205f17896bbfa35df65b5efed699ac',
}
PAIRS = [
    ('control_check_endian', 0x1284b240, 0x1284b590),
    ('control_queue_message', 0x128634a0, 0x128637f0),
    ('control_send_bunch', 0x1286d3a0, 0x1286d6f0),
    ('control_tick_candidate', 0x128677a0, 0x12867af0),
    ('control_candidate_12867a00', 0x12867a00, 0x12867d50),
    ('send_bunch_wrapper', 0x5bfbfd0, 0x5bfbb80),
    ('in_bunch_constructor', 0x1283e990, 0x1283ece0),
    ('net_reader_constructor', 0x10cf5b90, 0x10cf5530),
    ('bit_reader_constructor', 0x10b3b220, 0x10b3abf0),
    ('fstring_archive', 0x109ea340, 0x109e9da0),
    ('scalar32_archive_swap', 0x10b4b540, 0x10b4af10),
    ('counted_narrow_to_wide', 0xd60360, 0xd603e0),
    ('counted_wide_to_narrow', 0xd92e70, 0xd92e90),
    ('identity_archive_branch_selector', 0x12bab170, 0x12bab4c0),
    ('identity_delegated_physical_fields', 0x12bc0e60, 0x12bc11b0),
    ('four_scalar32_archive', 0x1779fa0, 0x1779e10),
    ('pending_constructor', 0x12c7a7b0, 0x12c7ab00),
    ('pending_send_initial_join_log_owner', 0x12c90440, 0x12c90790),
    ('hello_local_network_checksum', 0x10b044b0, 0x10b03eb0),
    ('pending_send_join', 0x12c9e550, 0x12c9e8a0),
    ('pending_post_load_callback', 0x12c931b0, 0x12c93500),
    ('engine_tick_world_travel', 0x13075490, 0x13075780),
    ('map_validation_normalization', 0x13066140, 0x13066430),
    ('url_format', 0x130aa2d0, 0x130aa5c0),
    ('fstring_equality', 0x10a137d0, 0x10a13230),
    ('fstring_option_append', 0x109f45f0, 0x109f4050),
    ('local_player_identity_getter', 0x12ae6ec0, 0x12ae7210),
]
# Exact source-specific indexed-RVA operands. No arbitrary immediates are masked.
SWITCHES = [
    ('control_received_bunch', 0x128668d0, 0x12866c20, 3784,
     0x12867724, 0x12867a74, 29, 0, 0x12867160, 0x128674b0),
    ('pending_notify_control', 0x12c93f40, 0x12c94290, 4824,
     0x12c951c4, 0x12c95514, 21, 1, 0x12c93f8d, 0x12c942dd),
]
CODEC_PATHS = [
    'outputs/df-local-server/dfserver/transport/native/legacy_ds_control_fields.py',
    'outputs/df-local-server/dfserver/transport/native/legacy_ds_identity_field.py',
    'outputs/df-local-server/dfserver/transport/native/legacy_ds_login_fields.py',
    'outputs/df-local-server/dfserver/transport/native/legacy_ds_wire_codec.py',
]


def switched_body(old, new, image, spec):
    name, a, b, size, ta, tb, count, first_id, sa, sb = spec
    fragments = image.fragments(b)
    if not fragments or fragments[-1][1] != b+size or tb+count*4 != b+size:
        raise ValueError('Switch body is not the complete unwind span: '+name)
    aa, bb = old.read(a, size), new.read(b, size)
    oi, ni = disasm(old, a, ta-a), disasm(new, b, tb-b)
    if (sum(i.size for i in oi) != ta-a or sum(i.size for i in ni) != tb-b
            or len(oi) != len(ni)):
        raise ValueError('Switch code/table partition does not fully decode')
    refs = []
    for x, y in zip(oi, ni):
        if (x.address-a, x.size, x.id, len(x.operands)) != (y.address-b, y.size, y.id, len(y.operands)):
            raise ValueError('Switch instruction structure changed: '+name)
        xc, yc = bytearray(x.bytes), bytearray(y.bytes)
        for p, q in zip(x.operands, y.operands):
            if (p.type, p.size, p.access) != (q.type, q.size, q.access):
                raise ValueError('Switch operand shape changed')
            kind, targets, encoding = None, None, None
            if p.type == X86_OP_MEM:
                if (p.mem.base, p.mem.index, p.mem.scale) != (q.mem.base, q.mem.index, q.mem.scale):
                    raise ValueError('Switch addressing mode changed')
                if p.mem.base == X86_REG_RIP:
                    kind, targets = 'rip_reference', (x.address+x.size+p.mem.disp, y.address+y.size+q.mem.disp)
                    encoding = (x.disp_offset, 4)
                elif (x.address, y.address) == (sa, sb):
                    if (p.mem.disp, q.mem.disp) != (ta, tb):
                        raise ValueError('Explicit indexed switch RVA changed')
                    kind, targets, encoding = 'exact_indexed_switch_rva', (ta, tb), (x.disp_offset, 4)
            elif p.type == X86_OP_IMM and x.mnemonic.startswith(('j', 'call')):
                old_internal, new_internal = a <= p.imm < ta, b <= q.imm < tb
                if old_internal != new_internal or old_internal and p.imm-a != q.imm-b:
                    raise ValueError('Switch internal control flow changed')
                kind, targets, encoding = 'direct_control_flow', (p.imm, q.imm), (x.imm_offset, x.imm_size)
            if encoding:
                at, n = encoding
                xc[at:at+n] = yc[at:at+n] = bytes(n)
                refs.append(dict(kind=kind, old_instruction=hex(x.address), new_instruction=hex(y.address),
                                 old_target=hex(targets[0]), new_target=hex(targets[1])))
        if xc != yc:
            raise ValueError(f'Non-reference bytes changed: {name}/{x.address:x}')
    av, bv = struct.unpack('<'+'I'*count, aa[ta-a:]), struct.unpack('<'+'I'*count, bb[tb-b:])
    old_boundaries, new_boundaries = {i.address for i in oi}, {i.address for i in ni}
    if ([v-a for v in av] != [v-b for v in bv] or
            not all(v in old_boundaries for v in av) or not all(v in new_boundaries for v in bv)):
        raise ValueError('Full switch case/target grammar changed')
    return dict(name=name, old_rva=hex(a), new_rva=hex(b), bytes=size,
        old_code_sha256=sha(aa), new_code_sha256=sha(bb),
        instruction_bytes=tb-b, instruction_count=len(ni), full_code_partition_decode=True,
        all_non_reference_instruction_bytes_identical=True,
        structure_displacements_and_nonaddress_immediates_are_not_masked=True,
        internal_direct_control_flow_preserved=True,
        new_fragments=[dict(begin=hex(x), end_exclusive=hex(y), unwind_rva=hex(z)) for x,y,z in fragments],
        references=refs, decoded_new_instructions=[instruction_row(i) for i in ni],
        table=dict(old_rva=hex(ta), new_rva=hex(tb), bytes=count*4,
            old_sha256=sha(aa[ta-a:]), new_sha256=sha(bb[tb-b:]),
            all_relative_case_targets_identical=True,
            cases=[dict(message_id=i+first_id, old_target=hex(x), new_target=hex(y),
                        instruction_boundary_verified=True) for i,(x,y) in enumerate(zip(av,bv))]))


def unwind_closure(image, functions):
    roots = {int(f['new_rva'],16): set(image.fragments(int(f['new_rva'],16))) for f in functions}
    known = {fragment:root for root,fragments in roots.items() for fragment in fragments}
    sections, chained = sorted(image.sections), []
    starts = [r[0] for r in sections]
    with CLIENT.open('rb') as stream, mmap.mmap(stream.fileno(),0,access=mmap.ACCESS_READ) as raw:
        for row in image.entries:
            first, size, offset = sections[bisect.bisect_right(starts,row[2])-1]
            at = offset+row[2]-first
            if not first <= row[2] < first+size or at+4 > len(raw):
                raise ValueError('Unwind header not raw backed')
            if raw[at] >> 3 == 4:
                tail = at+4+((raw[at+2]+1)&~1)*2
                if tail+12 > offset+size:
                    raise ValueError('Unwind parent not raw backed')
                chained.append((row,struct.unpack_from('<III',raw,tail)))
    missing = []
    for _ in range(64):
        changed = False
        for row,parent in chained:
            if parent in known and row not in known:
                known[row] = known[parent]
                missing.append((known[parent],row))
                changed = True
        if not changed:
            break
    else:
        raise ValueError('Unwind closure depth exceeded')
    if missing:
        raise ValueError('Detached uncompared fragments: '+repr(missing))
    return dict(exception_entries_scanned=len(image.entries), chained_entries_scanned=len(chained),
                selected_roots=len(roots), selected_fragments=len(known),
                detached_uncompared_fragments=0, transitive_closure_verified=True)


def literal(image, rva, value):
    raw = value.encode('utf-16-le')+b'\0\0'
    if image.read(rva,len(raw)) != raw:
        raise ValueError('Runtime-used immutable string changed')
    return dict(rva=hex(rva), utf16=value, bytes=len(raw), sha256=sha(raw))


def captured_hello():
    sys.path.insert(0,str(ROOT/'outputs/df-local-server'))
    from dfserver.transport.native.legacy_ds_wire_codec import decode_observed_application
    from dfserver.transport.native.legacy_ds_control_fields import decode_messages
    raw = (CAPTURE/'05-udp.bin').read_bytes()
    if sha(raw) != CAPTURE_PINS['05-udp.bin']:
        raise ValueError('Exact historical captured Hello changed')
    packet = decode_observed_application(raw[8:],max_packet_bytes=1024,received_by_server=True)
    if len(packet.bunches) != 1:
        raise ValueError('Updated captured Hello bunch count changed')
    bunch = packet.bunches[0]
    messages = decode_messages(bunch.payload,payload_bits=bunch.payload_bits)
    if (bunch.channel_index != 0 or not bunch.reliable or bunch.partial or
            bunch.channel_name.hardcoded_index != 255 or
            len(messages) != 1 or messages[0].message_id != 0 or
            messages[0].fields != (1,1077088301,'')):
        raise ValueError('Exact updated captured Hello shape changed')
    report_raw = (CAPTURE/'report.json').read_bytes()
    if sha(report_raw) != CAPTURE_PINS['report.json']:
        raise ValueError('Exact historical trial packet report changed')
    report = json.loads(report_raw)
    if report['handshake_probe']['events']['valid_challenge_echo_ack_prepared'] != 1:
        raise ValueError('Captured trial handshake report changed')
    # Never put routing bytes, cookies, identifiers or token-bearing strings in output.
    return dict(capture=(CAPTURE/'05-udp.bin').relative_to(ROOT).as_posix(),
        capture_sha256=sha(raw), capture_bytes=len(raw),
        report=(CAPTURE/'report.json').relative_to(ROOT).as_posix(), report_sha256=sha(report_raw),
        candidate_outer_prefix_bytes=8, opaque_outer_routing_semantics_verified=False,
        executable_build_attribution='updated-build trial supplied by enclosing research task; packet bytes do not contain executable SHA',
        packet_sequence=packet.sequence, channel_index=0, reliable=True,
        channel_sequence=bunch.channel_sequence, channel_hardcoded_name_index=255,
        payload_bits=bunch.payload_bits, payload_sha256=sha(bunch.payload),
        message_id=0, endian=1, network_version_u32=1077088301, trailing_string_units=0,
        live_protocol_acceptance=False, token_values_recorded=False)


def qualify():
    old,new,image = ForensicObservation('old'),ForensicObservation('new'),TransportImage()
    functions = [compare_full(old,new,image,*row) for row in PAIRS]
    functions += [switched_body(old,new,image,spec) for spec in SWITCHES]
    rows = {int(i['rva'],16):i for f in functions for i in f['decoded_new_instructions']}
    def witness(meaning, address, expected):
        ins = rows[address]
        if ins['instruction'] != expected:
            raise ValueError('Control semantic witness changed: '+meaning)
        return dict(meaning=meaning,**ins)
    checks = [
        ('received Notify interface from driver+218',0x12867470,'mov rcx, qword ptr [rax + 0x218]'),
        ('received Notify slot18',0x1286747a,'call qword ptr [rax + 0x18]'),
        ('fallback only when Notify consumed no additional bits',0x1286747d,'cmp r13, qword ptr [rbx + 0xa8]'),
        ('fallback skips when Notify advanced position',0x12867484,'jne 0x128678ba'),
        ('fallback rejects archive error',0x1286748f,'test r8b, 1'),
        ('fallback largest table index28',0x128674a0,'cmp edx, 0x1c'),
        ('identity delegated branch archive+28 sign',0x12bab4cf,'cmp byte ptr [rcx + 0x28], 0'),
        ('identity delegated branch archive+2b mask10',0x12bab4df,'test byte ptr [rcx + 0x2b], 0x10'),
        ('identity delegated reader',0x12bab685,'call 0x12bc11b0'),
        ('incoming bit reader archive+28 flags select delegated identity',0x10b3ac98,'or byte ptr [rbx + 0x28], 0x81'),
        ('incoming bit reader archive+2b flags select delegated identity',0x10b3ac9c,'or byte ptr [rbx + 0x2b], 0x10'),
        ('pending Challenge string',0x12c9460b,'call 0x109e9da0'),
        ('pending Welcome first string',0x12c94cfb,'call 0x109e9da0'),
        ('pending Welcome second string',0x12c94d08,'call 0x109e9da0'),
        ('pending Welcome third string',0x12c94d14,'call 0x109e9da0'),
        ('pending Welcome success marker interface+80',0x12c950ae,'mov byte ptr [r12 + 0x80], 1'),
        ('pending Login message id5',0x12c94b98,'mov byte ptr [rsp + 0x50], 5'),
        ('pending Login response string',0x12c94bdc,'call 0x109e9da0'),
        ('pending Login URL string',0x12c94bec,'call 0x109e9da0'),
        ('pending Login identity',0x12c94bff,'call 0x12bab4c0'),
        ('pending Login platform string',0x12c94c0f,'call 0x109e9da0'),
        ('pending Netspeed message id4',0x12c94fd2,'mov byte ptr [rsp + 0x50], 4'),
        ('pending Netspeed scalar32',0x12c95047,'mov r8d, 4'),
        ('pending Join message id9',0x12c9e910,'mov byte ptr [rsp + 0x150], 9'),
        ('pending Hello endian byte1',0x12c90b28,'mov byte ptr [rbp + 0xd0], 1'),
        ('pending Hello current checksum getter',0x12c90b2f,'call 0x10b03eb0'),
        ('pending Hello zero tag source',0x12c90caa,'mov byte ptr [rbp + 0xc8], r12b'),
        ('pending Hello tag archive byte',0x12c90cd8,'mov r8d, 1'),
        ('pending Hello endian archive byte',0x12c90d12,'mov r8d, 1'),
        ('pending Hello checksum scalar32',0x12c90d57,'mov r8d, 4'),
        ('pending Hello trailing string',0x12c90d71,'call 0x109e9da0'),
    ]
    witnesses = [witness(*check) for check in checks]
    # Numeric IDs come exclusively from this body's verified switch and direct comparisons.
    grammar = {
        0:['u8','u32','FString'],1:['FString','FString','FString'],2:['u32'],3:['FString'],
        4:['u32'],5:['FString','FString','identity_branch_selector','FString'],6:['FString'],
        9:[],10:['FString','identity_branch_selector'],12:['four_u32'],13:['four_u32'],
        15:['u32'],16:['u32'],17:['FString'],18:['packed_u32','FString'],21:[],25:[],
        26:['FString','identity_branch_selector'],27:['packed_u32'],28:['FString'],
    }
    fallback = next(f for f in functions if f['name']=='control_received_bunch')
    fallback_rows = [dict(case,fields=grammar.get(case['message_id']),
        disposition='consume fields' if case['message_id'] in grammar else 'default close path')
        for case in fallback['table']['cases']]
    source_map = {r[1]:(r[2],r[0]) for r in PAIRS}
    source_map.update({r[1]:(r[2],r[0]) for r in SWITCHES})
    edges = []
    for f in functions:
        for ref in f.get('references',[]):
            target = source_map.get(int(ref['old_target'],16)) if ref['kind']=='direct_control_flow' else None
            if target:
                if ref['new_target'] != hex(target[0]):
                    raise ValueError('Qualified helper edge changed')
                edges.append(dict(caller=f['name'],callee=target[1],**ref))
    constructor = next(f for f in functions if f['name']=='pending_constructor')
    object_table,notify_table = 0x1b20b038,0x1b15bb80
    bindings = []
    for name,table,slot,target in [
        ('PendingNetGame FNetworkNotify.NotifyControlMessage',notify_table,0x18,0x12c94290),
        ('PendingNetGame SendJoin',object_table,0x268,0x12c9e8a0),
        ('PendingNetGame post-load callback',object_table,0x270,0x12c93500),
    ]:
        raw = image.read(table+slot,8)
        if struct.unpack('<Q',raw)[0]-image.image_base != target:
            raise ValueError('Updated concrete Pending vtable target changed: '+name)
        refs = [r for r in constructor['references'] if r['kind']=='rip_reference' and r['new_target']==hex(table)]
        if len(refs)!=1:
            raise ValueError('Pending constructor table reference missing')
        bindings.append(dict(name=name,table_rva=hex(table),slot=hex(slot),target_rva=hex(target),
            bytes_hex=raw.hex(),sha256=sha(raw),constructor_reference=refs[0],runtime_instance_observed=False))
    # Both RIP references are used to build the literal ClientResponse, not account tokens.
    zero_refs = [r for f in functions if f['name']=='pending_notify_control' for r in f['references']
                 if r['kind']=='rip_reference' and r['old_target']=='0x14ecaa08']
    if not zero_refs or len({r['new_target'] for r in zero_refs})!=1:
        raise ValueError('Canonical response literal reference missing')
    literals = [dict(literal(image,int(zero_refs[0]['new_target'],16),'0'),references=zero_refs)]
    # Extract only printable native diagnostic/format literals referenced by qualified code.
    seen = {int(literals[0]['rva'],16)}
    for f in functions:
        for ref in f.get('references',[]):
            if ref['kind']!='rip_reference':
                continue
            if not rows[int(ref['new_instruction'],16)]['instruction'].startswith('lea '):
                continue
            at = int(ref['new_target'],16)
            if at in seen:
                continue
            try:
                raw = image.read(at,512)
                end = next(i for i in range(0,512,2) if raw[i:i+2]==b'\0\0')
                text = raw[:end].decode('utf-16-le')
            except (ValueError,StopIteration,UnicodeDecodeError):
                continue
            if not text or len(text)>254 or not all(32<=ord(c)<=126 or c in '\n\r\t' for c in text):
                continue
            seen.add(at)
            literals.append(dict(literal(image,at,text),function=f['name'],reference=ref,
                comparison='current immutable literal; historical contents not read from executable cache'))
    pins = [dict(path=p,sha256=sha((ROOT/p).read_bytes())) for p in CODEC_PATHS+[
        'work/research_updated_metadata_roots.py','work/research_updated_replication_core.py',
        'work/research_updated_transport_roots.py','work/seal_pending_control_flow_evidence.py',
        'work/analyze_cached_pending_notify.py','work/analyze_control_candidate_interval.py',
    ]]
    return dict(kind='updated_control_offline_full_body_qualification',
        client_sha256=PINS['new'][2],old_client_sha256=PINS['old'][2],
        script_path=Path(__file__).relative_to(ROOT).as_posix(),script_sha256=sha(Path(__file__).read_bytes()),
        verification_command='python work/research_updated_control_contract.py --qualify',
        process_accessed=False,client_launched=False,native_invoked=False,packet_emitted=False,
        production_sources_changed=False,build_guard_changed=False,map_gameplay_accepted=False,
        complete_function_comparisons=functions,full_unwind_inventory=unwind_closure(image,functions),
        exact_semantic_witnesses=witnesses,qualified_helper_edges=edges,
        concrete_pending_vtable_bindings=bindings,runtime_used_immutable_literals=literals,
        immutable_literal_scope='Canonical response0 and printable NUL-terminated UTF16 address operands from exact qualified LEA instructions; raw scalar/SIMD loads and apparent string fragments are excluded. This is a selected runtime-used literal inventory, not all PE strings.',
        primitive_field_rules=dict(message_tag='one raw byte',scalar32='four archive bytes; little endian in the qualified non-swapped profile',
            packed_u32='archive virtual slot78; current reader implementation is qualified separately in updated transport roots',
            FString='signed int32 count includes final terminator; positive count uses narrow bytes, negative count UTF16 units; INT_MIN invalid; archive+38 positive unit bound applies; loader overwrites final unit with NUL; narrow high bytes become question mark; wide0xffff normalizes and first-NUL shrinks',
            identity='incoming FInBunch -> FNetBitReader -> FBitReader constructors set archive+28 mask81 and +2b mask10; selector therefore delegates to12bc11b0. flags1+2 exits explicit-empty; otherwise flags>>3 gives opaque type hash, hash0 needs runtime default registry resolution, hash31 adds FString type name; encoded flag1 reads u8 byte count then counted bytes, unencoded reads FString. Native factory acceptance is separate.',
            four_u32='four consecutive scalar32 fields; semantic type name not inferred'),
        fallback_field_grammar=fallback_rows,
        direct_pre_notify_grammar=[
            dict(message_id=16,fields=['u32'],entry_rva='0x12866f68',
                 condition='connection.driver+98 null; otherwise no field consumed and fallback remains eligible'),
            dict(message_id=19,fields=['FString'],entry_rva='0x1286742b'),
            dict(message_id=20,fields=['u8','FString'],entry_rva='0x128672e7')],
        notify_contract=dict(interface_dispatch_slot='0x18',driver_interface_offset='0x218',
            concrete_pending_messages={'1':['FString Level','FString Game','FString RedirectURL'],
                '2':['u32'],'3':['FString Challenge'],'6':['FString Failure'],
                '18':['packed_u32','FString'],'21':[]},
            outgoing_hello0=['u8 endian','u32 current10b03eb0 checksum','FString EncryptionToken URL option'],
            outgoing_login5=['FString Response','FString URL','delegated identity','FString Platform'],
            welcome_connected_marker='Pending object+a8; successful parse only',
            join_gate='TickWorldTravel validates Map and requires actual Engine virtual448 LoadMap success, then Pending post-load virtual270 invokes SendJoin virtual268.',
            full_pending_notify_body_qualified=True,arbitrary_notify_overrides_qualified=False),
        updated_captured_hello=captured_hello(),
        codec_reuse=dict(non_swapped_control_fields_unchanged=True,
            supported_message_ids=[0,1,2,3,4,6,9,16,20],
            delegated_identity_physical_parser_unchanged=True,login5_field_order_unchanged=True,
            production_codecs_need_no_field_grammar_edit=True,runtime_profile_update_performed=False,
            local_bounds_and_canonicalization_remain_local_policy=True,
            native_account_identity_acceptance_qualified=False),
        residuals=[
            'This is offline code/data and captured-Hello qualification, not a native Challenge/Login/Welcome/Join acceptance trial.',
            'A complete Control field grammar does not implement maps, GameState, actor replication, ownership, pawn possession or gameplay.',
            'Old helpers and old client SHA guards remain intact. This report does not authorize a blanket old-to-new hash replacement.',
            'Pure codecs cover their stated non-swapped ordinary archive profile only; swapped archives and arbitrary Notify overrides are not certified.',
            'Fallback runs only if the concrete Notify/direct handler left read position unchanged and no archive error occurred. Its grammar is not business acceptance.',
            'Identity factories, registry resolution/default type hashes, concrete account/provider identity values and arbitrary virtual methods are outside this physical grammar qualification.',
            'Updated vtables and literals are read from the SHA-pinned current PE; historical immutable data-table byte equality is not asserted.',
            'External allocation, diagnostics, FString storage and arbitrary virtual callees are not all transitively certified; selected grammar/helper edges are explicit.',
            'Complete current unwind spans and all chained fragments are checked. Historical bodies use exact corresponding roots and equal extents; old PE unwind data is not reconstructed from executable-only observations.',
            'Opaque outer8 routing semantics and live PacketHandler/driver overrides remain separate; only the saved Hello decodes under the observed local envelope.',
            'Control table IDs7,8,11,14,19,20,22,23,24 select default fallback. IDs19/20 have earlier direct handlers; this is not a claim they are invalid overall.',
            'Names of control_tick_candidate/control_candidate_12867a00 are deliberately not inferred from proximity; their complete native bodies are compared as supporting code only.',
        ],source_scripts=pins,source_observations=[old.source_evidence(),new.source_evidence()],
        new_pe=dict(path=str(CLIENT),sha256=PINS['new'][2],image_base=hex(image.image_base),
                    exception_directory_sha256=sha(image.exc_data)))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--qualify',action='store_true',required=True)
    parser.parse_args()
    result = qualify()
    raw = (json.dumps(result,indent=2)+'\n').encode('utf-8')
    OUTPUT.write_bytes(raw)
    print(json.dumps(dict(output=OUTPUT.relative_to(ROOT).as_posix(),sha256=sha(raw),
        full_functions=len(result['complete_function_comparisons']),
        witnesses=len(result['exact_semantic_witnesses']),
        hello_net_version=result['updated_captured_hello']['network_version_u32'],
        field_grammar_unchanged=result['codec_reuse']['production_codecs_need_no_field_grammar_edit'],
        native_acceptance=False)))


if __name__=='__main__':
    main()
