"""Offline qualification of updated packet/bunch transport and fragmentation.

Only explicit saved observations and the SHA-pinned shadow PE are read. Existing
runtime helpers and production gates are not changed or imported for execution.
"""
import argparse
import bisect
import json
import mmap
import struct

from capstone.x86 import X86_OP_IMM, X86_OP_MEM, X86_REG_RIP
from research_updated_metadata_roots import ROOT, PINS, CLIENT, ForensicObservation, NewImage, sha, disasm
from research_updated_replication_core import locate, compare_full, containing_primary


class TransportImage(NewImage):
    def fragments(self, rva):
        index = bisect.bisect_left(self.starts, rva)
        if index == len(self.entries) or self.entries[index][0] != rva:
            return []
        rows = [self.entries[index]]
        accepted = set(rows)
        for row in self.entries[index+1:index+513]:
            if row[0] != rows[-1][1]:
                break
            head = self.read(row[2], 4)
            if head[0] >> 3 != 4:
                break
            chained = struct.unpack('<III', self.read(row[2]+4+((head[2]+1)&~1)*2, 12))
            if chained not in accepted:
                break
            if len(rows) >= 512:
                raise ValueError('Transport unwind fragment budget exceeded')
            rows.append(row)
            accepted.add(row)
        return rows


PAIRS = [
    ('send_bunch_wrapper', 0x5bfbfd0, 0x5bfbb80),
    ('control_send_bunch', 0x1286d3a0, 0x1286d6f0),
    ('channel_send_bunch_and_split', 0x1286c6f0, 0x1286ca40),
    ('received_next_bunch_partial_assembly', 0x12867ac0, 0x12867e10),
    ('received_raw_bunch', 0x12868710, 0x12868a60),
    ('received_sequenced_bunch', 0x12868ac0, 0x12868e10),
    ('received_packet', 0x12b9abf0, 0x12b9af40),
    ('notify_update_ack', 0x12b86f80, 0x12b872d0),
    ('notify_read_header', 0x12b7e360, 0x12b7e6b0),
    ('notify_sequence_validation', 0x12b911c0, 0x12b91510, 0x71),
    ('read_packet_metadata', 0x12b9a510, 0x12b9a860),
    ('connection_constructor', 0x12b87c00, 0x12b87f50),
    ('send_raw_bunch_header_writer', 0x12ba0af0, 0x12ba0e40),
    ('packet_bit_writer', 0x12ba7de0, 0x12ba8130),
    ('in_bunch_constructor', 0x1283e990, 0x1283ece0),
    ('in_bunch_copy_constructor', 0x1283e770, 0x1283eac0),
    ('out_bunch_constructor', 0x1283efc0, 0x1283f310),
    ('out_bunch_assignment', 0x4933170, 0x4932d80),
    ('net_reader_constructor', 0x10cf5b90, 0x10cf5530),
    ('net_writer_constructor', 0x10cf5bd0, 0x10cf5570),
    ('bit_reader_constructor', 0x10b3b220, 0x10b3abf0),
    ('bit_writer_constructor', 0x10b3b3e0, 0x10b3adb0),
    ('read_bits', 0xe509a0, 0xe509c0),
    ('read_bounded_int', 0xe50ad0, 0xe50af0),
    ('read_packed_uint32', 0x10b4c190, 0x10b4bb60),
    ('write_archive_bytes', 0x10b4a840, 0x10b4a210),
    ('write_archive_bits', 0x10b4b280, 0x10b4ac50),
    ('write_bounded_int_virtual', 0x10b4be80, 0x10b4b850),
    ('write_packed_uint32', 0x10b4c310, 0x10b4bce0),
    ('write_bit', 0x10b4ea60, 0x10b4e430),
    ('write_bounded_int_direct', 0x10b4eb30, 0x10b4e500),
    ('copy_bits', 0x10b4ec70, 0x10b4e640),
    ('reader_copy_unread_payload', 0x10b4cee0, 0x10b4c8b0),
    ('reader_append_unread_payload', 0x10b3e870, 0x10b3e240),
    ('reader_set_error', 0x10b4d150, 0x10b4cb20),
    ('channel_name_archive', 0x10e05bc0, 0x10e05560),
    ('array_data_accessor', 0xd968d0, 0xd968f0, 4),
]


CHECKS = [
    ('notify sequence shifted18', 0x12b7e72e, 'shr eax, 0x12'),
    ('notify ack shifted4', 0x12b7e737, 'shr eax, 4'),
    ('notify ack mask14', 0x12b7e71f, 'mov edx, 0x3fff'),
    ('notify history count nibble', 0x12b7e743, 'and eax, 0xf'),
    ('notify history count plus1', 0x12b7e746, 'inc rax'),
    ('notify consumes at most8 words', 0x12b7e717, 'mov esi, 8'),
    ('notify min8 count', 0x12b7e750, 'cmovbe rsi, rax'),
    ('ordinary packet notify reader', 0x12b9b096, 'call 0x12b7e6b0'),
    ('packet metadata reader binding', 0x12b9b3f8, 'call 0x12b9a860'),
    ('packet info bit advances1', 0x12b9a8ce, 'inc qword ptr [rdi + 0xa8]'),
    ('packet info conditional frame-time', 0x12b9a8ed, 'test bpl, bpl'),
    ('packet frame-time byte', 0x12b9a91b, 'mov r8d, 1'),
    ('packet frame always byte', 0x12b9a972, 'mov r8d, 1'),
    ('close reason version7 switch', 0x12b9b7ba, 'cmp dword ptr [rbp + 0x24], 7'),
    ('close reason bound15', 0x12b9b98e, 'mov r8d, 0xf'),
    ('packed channel version3 switch', 0x12b9bb0a, 'cmp dword ptr [rbp + 0x24], 3'),
    ('packed channel reader slot78', 0x12b9bb35, 'call qword ptr [rax + 0x78]'),
    ('received reliable sequence bound1024', 0x12b9bd3d, 'mov r8d, 0x400'),
    ('received reliable sequence reconstruct signed delta', 0x12b9bd5d, 'and eax, 0x3ff'),
    ('unreliable partial sequence uses packetid', 0x12b9bd77, 'mov eax, dword ptr [r14 + 0x14cc]'),
    ('received partial gate', 0x12b9bd8c, 'test byte ptr [rbp + 0xb4], 0x20'),
    ('received initial flag shifted6', 0x12b9bdfb, 'shl cl, 6'),
    ('received final flag shifted7', 0x12b9be73, 'shl cl, 7'),
    ('received channel name version6 switch', 0x12b9be83, 'cmp dword ptr [rbp + 0x24], 6'),
    ('received channel name archive', 0x12b9bf88, 'call 0x10e05560'),
    ('received payload bound from MaxPacket', 0x12b9c08b, 'mov r8d, dword ptr [r14 + 0xb0]'),
    ('received payload bound in bits', 0x12b9c09e, 'shl r8d, 3'),
    ('received payload bitcount slot70', 0x12b9c0a6, 'call qword ptr [rax + 0x70]'),
    ('received payload reader copies declared bits', 0x12b9c1ff, 'call 0x10b4c8b0'),
    ('send control flag open or close', 0x12ba0e96, 'test byte ptr [rsi + 0xf0], 6'),
    ('send control bit', 0x12ba0ea3, 'call 0x10b4e430'),
    ('send open shift1', 0x12ba0eb4, 'shr dl, 1'),
    ('send close shift2', 0x12ba0ecb, 'shr dl, 2'),
    ('send close reason bound15', 0x12ba0ef5, 'mov r8d, 0xf'),
    ('send flag4 shift4', 0x12ba0f0e, 'shr dl, 4'),
    ('send reliable shift5', 0x12ba0f23, 'shr dl, 5'),
    ('send connection flag', 0x12ba0f2e, 'movzx edx, byte ptr [r15 + 0xb8]'),
    ('send channel index packed slot78', 0x12ba0f59, 'call qword ptr [rax + 0x78]'),
    ('send exports shift1', 0x12ba0f66, 'shr dl, 1'),
    ('send mapped shift2', 0x12ba0f7a, 'shr dl, 2'),
    ('send partial shift6', 0x12ba0f8f, 'shr dl, 6'),
    ('send reliable seq bound1024', 0x12ba0fbd, 'mov r8d, 0x400'),
    ('send sequence bounded writer', 0x12ba0fc6, 'call 0x10b4e500'),
    ('send partial header gate', 0x12ba0fd2, 'test dl, 0x40'),
    ('send initial shift7', 0x12ba0fd7, 'shr dl, 7'),
    ('send final low bit', 0x12ba0fec, 'and dl, 1'),
    ('send channel name reliable or open', 0x12ba0ff4, 'test byte ptr [rsi + 0xf0], 0x22'),
    ('send channel name archive', 0x12ba1007, 'call 0x10e05560'),
    ('send payload bound from MaxPacket', 0x12ba100c, 'mov r8d, dword ptr [r15 + 0xb0]'),
    ('send payload bitcount', 0x12ba1016, 'mov edx, dword ptr [rsi + 0xa0]'),
    ('send payload bound in bits', 0x12ba101c, 'shl r8d, 3'),
    ('send payload length bounded writer', 0x12ba1020, 'call 0x10b4e500'),
    ('send header and payload copied separately', 0x12ba1208, 'call 0x12ba8130'),
    ('fragment budget MaxPacket', 0x1286cb86, 'mov eax, dword ptr [rcx + 0xb0]'),
    ('fragment budget packet bytes to bits', 0x1286cb93, 'shl eax, 3'),
    ('fragment budget connection overhead', 0x1286cb96, 'sub eax, dword ptr [rcx + 0x158]'),
    ('fragment budget reserved562 bits', 0x1286cb9f, 'sub eax, 0x232'),
    ('fragment budget rounded down positive multiple8', 0x1286cbb2, 'and rax, 0xfffffffffffffff8'),
    ('split only above full bunch bit budget', 0x1286cd5f, 'cmp qword ptr [r13 + 0xa0], rsi'),
    ('split chooses minimum remaining or aligned budget', 0x1286cdd3, 'cmovle rdi, rsi'),
    ('split copies exact fragment bitcount', 0x1286cddd, 'call qword ptr [rax + 0x68]'),
    ('split subtracts fragment bits', 0x1286ce0d, 'sub rsi, rdi'),
    ('split source advances bytes', 0x1286ce17, 'sar rax, 3'),
    ('partial only multiple fragments', 0x1286d391, 'cmp dword ptr [r15 + 8], 1'),
    ('partial initial first index', 0x1286d398, 'test esi, esi'),
    ('partial initial bit80', 0x1286d39a, 'mov eax, 0x80'),
    ('partial initial only first', 0x1286d3a2, 'cmove ecx, eax'),
    ('partial flag40', 0x1286d3b2, 'or cl, 0x40'),
    ('partial final only last', 0x1286d3c4, 'sete al'),
    ('open only first fragment', 0x1286d3de, 'and r8b, cl'),
    ('close only last fragment', 0x1286d3f8, 'cmp eax, esi'),
    ('reliable outgoing per-channel seq array', 0x1286d44a, 'add rcx, 0x14f0'),
    ('reliable each new fragment increments seq', 0x1286d45c, 'inc dword ptr [rax + rdi*4]'),
    ('reliable fragment assigned seq', 0x1286d462, 'mov dword ptr [r14 + 0xe8], eax'),
    ('each fragment SendRawBunch slot340', 0x1286d599, 'call qword ptr [rax + 0x340]'),
    ('fragment loop', 0x1286d65a, 'jl 0x1286d2b0'),
    ('partial dispatch candidate initially cleared', 0x12867e89, 'mov r13d, r15d'),
    ('partial initial branch', 0x12867e8c, 'test r8b, 0x40'),
    ('partial saved at channel68', 0x12868000, 'mov qword ptr [r14], rax'),
    ('initial fragment byte aligned', 0x12868024, 'test r12b, 7'),
    ('initial fragment unaligned sets error', 0x12867f2c, 'or byte ptr [rdi + 0x29], 1'),
    ('continuation previous sequence', 0x12868180, 'mov r9d, dword ptr [rcx + 0xe0]'),
    ('continuation incoming sequence', 0x12868187, 'mov edx, dword ptr [rdi + 0xe0]'),
    ('continuation seq plus1', 0x1286818d, 'lea eax, [r9 + 1]'),
    ('unreliable continuation same sequence allowed', 0x12868199, 'cmp edx, r9d'),
    ('reliable continuation requires next seq', 0x128681af, 'test dl, 0x10'),
    ('reliable selects strict next seq', 0x128681b9, 'cmovne ecx, eax'),
    ('continuation rejects finalized buffer', 0x128681be, 'js 0x12868519'),
    ('continuation reliability must match', 0x128681cf, 'test dl, 0x10'),
    ('continuation append unread bits', 0x1286826e, 'call 0x10b3e240'),
    ('nonfinal continuation byte aligned', 0x128682a0, 'test al, 7'),
    ('assembled seq updated', 0x12868352, 'mov dword ptr [rcx + 0xe0], eax'),
    ('final is sign bit', 0x1286835c, 'cmp byte ptr [rdi + 0xe4], r13b'),
    ('nonfinal retains buffer', 0x12868363, 'jge 0x128684bb'),
    ('final cannot carry package exports', 0x128683c2, 'test byte ptr [r14], 1'),
    ('final becomes dispatch candidate', 0x12868420, 'mov r13, qword ptr [rsi + 0x68]'),
    ('assembled final set', 0x12868424, 'or byte ptr [r13 + 0xe4], 0x80'),
    ('partial max bypass internalACK', 0x12868699, 'test byte ptr [rax + 0xb4], 1'),
    ('partial max ceil bytes', 0x128686b5, 'add rcx, 7'),
    ('partial max bytes compared', 0x128686bd, 'cmp rcx, rdx'),
    ('no candidate no dispatch', 0x12868707, 'test r13, r13'),
    ('complete candidate dispatch slot288', 0x128689a2, 'call qword ptr [rax + 0x288]'),
    ('hardcoded names receive bound605', 0x10e055c0, 'cmp edx, 0x25d'),
    ('hardcoded names writer canonical410', 0x10e056ce, 'cmp dword ptr [rax], 0x19a'),
    ('bounded reader little-endian bit shift', 0xe50b62, 'shl r8b, cl'),
    ('bounded reader termination accumulator plusmask', 0xe50b87, 'add eax, edi'),
    ('bounded reader termination below max', 0xe50b89, 'cmp eax, r15d'),
    ('append rounds unread bits up to bytes', 0x10b3e26b, 'lea ebp, [r14 + 7]'),
    ('append updates exact logical bitcount', 0x10b3e2b4, 'mov qword ptr [rsi + 0xa0], rbx'),
]


def verify_all_unwind_fragments(image):
    roots = {row[2]: set(image.fragments(row[2])) for row in PAIRS if len(row) == 3}
    known = {fragment: root for root, fragments in roots.items() for fragment in fragments}
    sections = sorted(image.sections)
    starts = [row[0] for row in sections]
    chained = []
    # Inspect the entire exception directory so detached cold chained ranges
    # cannot silently escape the contiguous-fragment comparison above.
    with CLIENT.open('rb') as stream, mmap.mmap(stream.fileno(), 0, access=mmap.ACCESS_READ) as raw:
        for row in image.entries:
            first, size, offset = sections[bisect.bisect_right(starts, row[2])-1]
            at = offset+row[2]-first
            if not first <= row[2] < first+size or at+4 > len(raw):
                raise ValueError('Unwind header outside raw-backed image')
            if raw[at] >> 3 == 4:
                tail = at+4+((raw[at+2]+1)&~1)*2
                if tail+12 > offset+size:
                    raise ValueError('Unwind chain outside raw-backed section')
                chained.append((row, struct.unpack_from('<III', raw, tail)))
    missing = []
    for phase in range(64):
        changed = False
        for row, parent in chained:
            if parent in known and row not in known:
                known[row] = known[parent]
                missing.append((known[parent], row))
                changed = True
        if not changed:
            break
    else:
        raise ValueError('Unwind closure depth exceeded')
    if missing:
        raise ValueError(f'Detached function fragments were not compared: {missing}')
    return dict(exception_entries_scanned=len(image.entries), chain_entries_scanned=len(chained),
        qualified_primary_roots=len(roots), qualified_fragments=len(known),
        detached_uncompared_fragments=0, transitive_chain_closure_verified=True)


def qualify():
    old, new, image = ForensicObservation('old'), ForensicObservation('new'), TransportImage()
    functions = [compare_full(old, new, image, *row) for row in PAIRS]
    rows = {int(ins['rva'], 16): ins for function in functions
            for ins in function['decoded_new_instructions']}
    witnesses = []
    for label, address, expected in CHECKS:
        actual = rows.get(address)
        if actual is None or actual['instruction'] != expected:
            raise ValueError(f'Transport witness changed: {label}: {actual}')
        witnesses.append(dict(rule=label, **actual))

    # This tiny byte-to-bit adapter has no unwind entry and deliberately tail
    # delegates to virtual SerializeBits. Compare the entire closed three-op body.
    a, b = old.read(0xe50750, 15), new.read(0xe50770, 15)
    if a != b or b.hex() != '488b014e8d04c50000000048ff6068':
        raise ValueError('Byte-to-bit archive leaf changed')
    functions.append(dict(name='read_archive_bytes_leaf', old_rva='0xe50750',
        new_rva='0xe50770', bytes=15, old_code_sha256=sha(a), new_code_sha256=sha(b),
        instruction_count=3, all_instruction_bytes_identical=True,
        boundary_basis='three exact instructions through tail virtual slot68',
        decoded_new_instructions=[dict(rva=hex(i.address), bytes_hex=bytes(i.bytes).hex(),
            instruction=f'{i.mnemonic} {i.op_str}') for i in disasm(new, 0xe50770, 15)]))

    names = {row[1]: (row[2], row[0]) for row in PAIRS}
    relevant_edges = []
    for function in functions:
        for reference in function.get('references', []):
            if reference['kind'] != 'direct_control_flow':
                continue
            target = names.get(int(reference['old_target'], 16))
            if target:
                if reference['new_target'] != hex(target[0]):
                    raise ValueError('Qualified direct call target changed')
                relevant_edges.append(dict(caller=function['name'], callee=target[1], **reference))
    indirect_jumps = []
    for row in PAIRS:
        function = next(f for f in functions if f['name'] == row[0])
        instructions = disasm(new, row[2], function['bytes'])
        previous = {i.address-row[1]: i for i in disasm(old, row[1], function['bytes'])}
        for ins in instructions:
            if ins.mnemonic.startswith('j') and ins.operands[0].type == X86_OP_IMM:
                old_ins = previous[ins.address-row[2]]
                old_internal = row[1] <= old_ins.operands[0].imm < row[1]+function['bytes']
                new_internal = row[2] <= ins.operands[0].imm < row[2]+function['bytes']
                if old_internal != new_internal:
                    raise ValueError('Branch crossed full-function boundary')
            if ins.mnemonic == 'jmp' and ins.operands[0].type != X86_OP_IMM:
                indirect_jumps.append(dict(function=row[0], rva=hex(ins.address), target=ins.op_str))
                if (row[0], ins.op_str) != ('reader_copy_unread_payload', 'qword ptr [r9 + 0x68]'):
                    raise ValueError('Unqualified indirect jump / switch table')

    tables = []
    for label, table, constructor, expected in [
        ('FInBunch', 0x1b148020, 'in_bunch_constructor', [0xe50770, 0xe509c0, 0xe50af0, 0x10b4bb60]),
        ('FNetBitReader', 0x16559bb8, 'net_reader_constructor', [0xe50770, 0xe509c0, 0xe50af0, 0x10b4bb60]),
        ('FOutBunch', 0x1b147e00, 'out_bunch_constructor', [0x10b4a210, 0x10b4ac50, 0x10b4b850, 0x10b4bce0]),
        ('FBitWriter', 0x15c47580, 'bit_writer_constructor', [0x10b4a210, 0x10b4ac50, 0x10b4b850, 0x10b4bce0]),
    ]:
        function = next(f for f in functions if f['name'] == constructor)
        refs = [r for r in function['references']
                if r['kind'] == 'rip_reference' and r['new_target'] == hex(table)]
        if len(refs) != 1:
            raise ValueError('Constructor vtable reference missing')
        raw = image.read(table+0x60, 32)
        actual = [x[0]-image.image_base for x in struct.iter_unpack('<Q', raw)]
        if actual != expected:
            raise ValueError('Current vtable method binding changed')
        tables.append(dict(name=label, table_rva=hex(table), constructor_reference=refs[0],
            observed_range_rva=hex(table+0x60), observed_bytes_hex=raw.hex(), sha256=sha(raw),
            slots=[dict(slot=hex(0x60+8*i), target_rva=hex(x)) for i,x in enumerate(actual)],
            provenance='updated immutable PE; historical data table unavailable'))
    conn_slot = image.read(0x1b1d5fa0+0x340, 8)
    if struct.unpack('<Q', conn_slot)[0]-image.image_base != 0x12ba0e40:
        raise ValueError('Connection SendRawBunch slot340 changed')
    conn = next(f for f in functions if f['name'] == 'connection_constructor')
    conn_refs = [r for r in conn['references'] if r['kind'] == 'rip_reference'
                 and r['new_target'] == '0x1b1d5fa0']
    if len(conn_refs) != 1:
        raise ValueError('Connection vtable constructor reference missing')
    tables.append(dict(name='UNetConnection.SendRawBunch', table_rva='0x1b1d5fa0',
        constructor_reference=conn_refs[0], slot='0x340', target_rva='0x12ba0e40',
        bytes_hex=conn_slot.hex(), sha256=sha(conn_slot)))
    getter = image.read(0x1d59de88, 8)
    if struct.unpack('<Q', getter)[0]-image.image_base != 0xd968f0:
        raise ValueError('Dynamic array data accessor cell changed')
    tables.append(dict(name='array_data_accessor_cell', cell_rva='0x1d59de88',
        target_rva='0xd968f0', bytes_hex=getter.hex(), sha256=sha(getter)))

    masks = image.read(0x1ab0fb70, 16)
    if masks != bytes([1<<i for i in range(8)]+[(1<<i)-1 for i in range(8)]):
        raise ValueError('Bit mask tables differ from bit archive arithmetic')
    max_partial = image.read(0x1d7668c0, 4)
    limits = [
        'No process access, native invocation, client launch, packet emission or protocol acceptance is performed.',
        'The ordinary, non-internalACK, non-byte-swapped path with close-reason version>=7, packed channel version>=3 and channel-name version>=6 is qualified.',
        'Code relocation preserves selected fields, constants and branch structure. External allocator, logging, FString and arbitrary virtual override implementations are not all transitively certified.',
        'Updated vtables and bit masks are verified against the updated PE. Old data tables were not captured; identical historical table bytes are not claimed.',
        'Hardcoded name numeric bounds and encoding are qualified. New hardcoded-index-to-name contents are not qualified by this report.',
        'The partial maximum is a mutable runtime cell. The file-backed default65536 does not prove a live value or authorize a fixed runtime limit.',
        'MaxPacket and connection overhead values are runtime inputs; the historical local1024-byte packet profile is not a native universal constant.',
        'Opaque routing bytes, PacketHandler termination, gameplay serialization and application delivery/acceptance remain separate evidence.',
        'The packet metadata extra-byte gate is the NetDriver virtual slot360 predicate. Its received_by_server interpretation is inherited from the existing codec; this report qualifies the concrete branch without identifying every driver override.',
        'The existing codec stricter policies (including history<=8 and rejecting control=1/open=0/close=0) are local canonicalization, not additional native rejection claims.',
        'No fragmentation implementation or production gate change is made. Syntactic codec support for partial headers alone does not implement native partial assembly.',
        'Initial+final in one partial header is not a native completed-bunch witness: the initial branch keeps its dispatch candidate null.',
    ]
    scripts = ['work/research_updated_metadata_roots.py', 'work/research_updated_replication_core.py',
               'work/research_updated_transport_roots.py',
               'outputs/df-local-server/dfserver/transport/native/legacy_ds_wire_codec.py',
               'outputs/df-local-server/dfserver/transport/native/legacy_ds_bit_archive.py']
    return dict(kind='updated_transport_offline_native_code_qualification',
        client_sha256=PINS['new'][2], old_client_sha256=PINS['old'][2],
        process_access=False, client_launched=False, native_called=False, memory_write=False,
        production_sources_changed=False, native_control_protocol_verified=False,
        protocol_acceptance=False, functions=functions, witnesses=witnesses,
        qualified_direct_edges=relevant_edges, indirect_jumps=indirect_jumps,
        full_unwind_inventory=verify_all_unwind_fragments(image),
        jump_table_status='No indirect branch switch tables in selected full functions; the only indirect jump is the explicit archive slot68 payload delegate.',
        vtable_bindings=tables,
        updated_static_data=[dict(rva='0x1ab0fb70', bytes_hex=masks.hex(), sha256=sha(masks),
            meaning='bit weights8 and low-bit masks8'),
            dict(rva='0x1d7668c0', bytes_hex=max_partial.hex(), sha256=sha(max_partial),
                 signed_value=struct.unpack('<i', max_partial)[0], meaning='file-backed partial-size default only')],
        wire_header_order=['control1', 'if control: open1 close1', 'if close: bounded_int15 reason',
            'flag4_1 reliable1 connection_flag1', 'packed_uint32 channel_index',
            'package_exports1 must_be_mapped1 partial1', 'if reliable: bounded_int1024 sequence',
            'if partial: initial1 final1', 'if reliable or open: ChannelName',
            'bounded_int(MaxPacketBytes*8) payload_bits', 'payload_bits raw bits'],
        packet_notify='u32: sequence14<<18 | acknowledged14<<4 | (history_count-1); then min(advertised_count,8) u32 history words',
        packet_metadata='packet_info1; if NetDriver slot360 predicate is false and packet_info=true: extra frame-time8; frame8 always. Existing codec interprets the predicate as received_by_server.',
        fragment_sender='Positive budget=MaxPacketBytes*8-connection_overhead_bits-562. Split only above budget. Fragment payload bound=floor(budget/8)*8. Partial flag only when count>1; initial/open only first; final/close only last. New reliable fragments increment the per-channel outgoing sequence separately.',
        partial_receiver='Initial saves a new buffer and never selects a dispatch candidate. Initial and nonfinal unread payloads must be byte aligned unless package-export branch skips data. Continuation requires a buffer not already final and matching reliable flag: reliable sequence=previous+1, unreliable sequence=previous or previous+1. Final continuation may have a partial byte, must not carry package exports, propagates final close/mapped flags and selects assembled buffer for later dispatch gates.',
        limits=limits, source_scripts=[dict(path=p, sha256=sha((ROOT/p).read_bytes())) for p in scripts],
        source_observations=[old.source_evidence(), new.source_evidence()],
        new_pe_unwind_directory_sha256=sha(image.exc_data))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--locate', nargs='+', type=lambda x:int(x, 0))
    parser.add_argument('--qualify', action='store_true')
    args = parser.parse_args()
    if args.qualify:
        result = qualify()
        output = ROOT/'work/research_updated_transport_79fb7b10.json'
        raw = (json.dumps(result, indent=2)+'\n').encode('utf-8')
        output.write_bytes(raw)
        print(json.dumps(dict(output=output.relative_to(ROOT).as_posix(), sha256=sha(raw),
            functions=len(result['functions']), witnesses=len(result['witnesses']),
            direct_edges=len(result['qualified_direct_edges']), protocol_acceptance=False)))
        return
    old, new = ForensicObservation('old'), ForensicObservation('new')
    image = TransportImage()
    if args.locate:
        rows = []
        for rva in args.locate:
            hits = locate(old, new, rva)
            candidates = []
            for hit in hits:
                root = containing_primary(image, hit)
                fragments = image.fragments(root) if root else []
                candidates.append(dict(rva=hex(hit), root=hex(root) if root else None,
                    bytes=fragments[-1][1]-root if fragments else None, fragments=len(fragments)))
            rows.append(dict(old_rva=hex(rva), candidates=candidates))
        print(json.dumps(rows, indent=2))


if __name__ == '__main__':
    main()
