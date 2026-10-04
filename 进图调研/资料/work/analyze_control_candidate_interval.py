"""Disk-only analysis of the fixed, still-unknown control candidate interval.

This module never imports a process reader, launches/elevates a client, follows
a live object, or expands the interval. Log/call matches identify semantic
candidates; they do not prove a concrete vtable override or a playable map.
The private fourth dfcode header qword is checked only through whole-file SHA
and never included in evidence or output.
"""
import argparse
import hashlib
import json
import mmap
from pathlib import Path
import struct

import capstone
from capstone.x86 import X86_OP_IMM, X86_OP_MEM, X86_REG_RIP
import pefile

ROOT = Path(__file__).resolve().parent.parent
DEFAULT_PLAN = ROOT / 'work/evidence/native-control-bounded-candidate-plan.json'
EXE_RELATIVE = Path('DeltaForce/Binaries/Win64/DeltaForceClient-Win64-Shipping.exe')
IMAGE_SHA = '4254fbe66585f260f1f9dbfc5e302887842552e7baed8939e023160a5e250be0'
MAGIC = 0x0000000145444344
START, END = 0x128635d0, 0x12867ac0
READ_BYTES, CODE_BYTES = END - START, 17564
MAX_FUNCTION, MAX_FRAGMENTS, MAX_JSON = 8192, 32, 512 * 1024
ROOT_RVAS = (0x128635d0, 0x12863600, 0x12864a10, 0x12864bf0,
             0x128654a0, 0x128658b0, 0x12865cc0, 0x12865d90,
             0x12865fe0, 0x128668a0, 0x128668d0, 0x128677a0, 0x12867a00)
LOGS = (
    (0x1b14ab50, 'UControlChannel::ReceivedBunch: NetConnection::Close() [%s] [%s] [%s] from CheckEndianess(). FAILED. Closing connection.'),
    (0x1b14aca0, 'UControlChannel::ReceivedBunch: NetConnection::Close() [%s] [%s] [%s] from failed to initialize the PlayerController channel. Closing connection.'),
    (0x1b14add0, 'UControlChannel::RecievedBunch: The client is sending an actor channel failure message with an invalid actor channel index.'),
    (0x1b14afd0, 'UControlChannel::ReceivedBunch: Failed to read control channel message'),
)
BODY_RVA, PREFIX_RVA = 0x1284b240, 0x1311f310
PREFIX_SOURCE = ROOT / ('work/native-client-tests/1790847786646593300/'
                        'ds-native-control-code/UControlChannel.CheckEndianess.prefix.dfcode')
PREFIX_FILE_SHA = 'a44f3787becc946e604aca6991ce5e4bb6d8222b6debcccbd0154b5c3c7aafce'
PREFIX_CODE_SHA = 'ae4351d9e73a2bddc680e5c1a346ff903e638ee36dd5692f330f42cbd38199b3'
PDATA_RVA, PDATA_BYTES = 0x1e5d1000, 15300936
PDATA_SHA = 'aae32c4f1cc7196c7a2b78a4adc4e5dae29e5a200ad7415ab2ed69f06cd70d5e'
TABLE_ROOT, CODE_END, TABLE_START, TABLE_END = 0x128668d0, 0x12867722, 0x12867724, 0x12867798
TABLE_SAMPLE_SHA = '33eacb39840b9cc13600d0b23fe64f0a5fe459ce751cf1c4c6fccc4152837cb2'
HELPER_SOURCE = PREFIX_SOURCE.with_name('UControlChannel.CheckEndianess.implementation.dfcode')
HELPER_FILE_SHA = '97a67bd3c19d75d2d396a1a0cda539218e26d7a8fa8a097d81f0eaf079650ff0'
HELPER_CODE_SHA = 'f9893067148f6f9f27192556452daa2d3c6bb4839549c59074533696d96be149'


def sha(data):
    return hashlib.sha256(data).hexdigest()


def json_bytes(path):
    path = Path(path)
    if not 0 < path.stat().st_size <= MAX_JSON:
        raise ValueError('JSON input exceeds the fixed file-size bound')
    with path.open('rb') as stream:
        value = stream.read(MAX_JSON + 1)
    if len(value) > MAX_JSON:
        raise ValueError('JSON input changed beyond its fixed file-size bound')
    return value


def load_json(path):
    value = json.loads(json_bytes(path))
    if not isinstance(value, dict):
        raise ValueError('JSON input must be an object')
    return value


def rva(value):
    if isinstance(value, str) and value.startswith('0x'):
        result = int(value, 16)
    elif type(value) is int:
        result = value
    else:
        raise ValueError('Invalid RVA representation')
    if not 0 <= result <= 0xffffffff:
        raise ValueError('RVA is outside the PE32+ RVA domain')
    return result


class Image:
    def __init__(self, raw):
        self.raw = raw
        self.pe = pefile.PE(data=raw, fast_load=True)
        self.size = self.pe.OPTIONAL_HEADER.SizeOfImage
        directory = self.pe.OPTIONAL_HEADER.DATA_DIRECTORY[3]
        if (directory.VirtualAddress, directory.Size) != (PDATA_RVA, PDATA_BYTES):
            raise ValueError('Pinned exception directory mismatch')
        self.table = self.data(PDATA_RVA, PDATA_BYTES)
        if sha(self.table) != PDATA_SHA:
            raise ValueError('Pinned exception directory SHA mismatch')
        self.count = len(self.table) // 12

    def data(self, address, length):
        if length <= 0 or not any(not s.Characteristics & 0x20000000 and
                s.VirtualAddress <= address < address + length <= s.VirtualAddress + s.SizeOfRawData
                for s in self.pe.sections):
            raise ValueError('Immutable metadata/log reference is not backed image data')
        offset = self.pe.get_offset_from_rva(address)
        value = bytes(self.raw[offset:offset + length])
        if len(value) != length:
            raise ValueError('Immutable image data is truncated')
        return value

    def executable(self, address, length):
        return length > 0 and any(s.Characteristics & 0x20000000 and
            s.VirtualAddress <= address < address + length <=
            s.VirtualAddress + min(s.SizeOfRawData, s.Misc_VirtualSize)
            for s in self.pe.sections)

    def entry(self, index):
        return struct.unpack_from('<III', self.table, index * 12)

    def unwind(self, entry):
        header = self.data(entry[2], 4)
        version, flags, count = header[0] & 7, header[0] >> 3, header[2]
        size = 4 + 4 * ((count + 1) // 2)
        if flags == 4:
            size += 12
        elif flags:
            raise ValueError('Unexpected unwind handler in fixed candidate metadata')
        value = self.data(entry[2], size)
        parent = struct.unpack_from('<III', value, size - 12) if flags == 4 else None
        return version, flags, parent, value

    def function(self, address):
        low, high = 0, self.count
        while low < high:
            mid = (low + high) // 2
            if self.entry(mid)[0] < address:
                low = mid + 1
            else:
                high = mid
        if low == self.count or self.entry(low)[0] != address:
            raise ValueError('Candidate is not an exact exception-directory root')
        root = self.entry(low)
        version, flags, _, _ = self.unwind(root)
        if version != 1 or flags:
            raise ValueError('Candidate root is an unwind continuation/unsupported version')
        accepted, entries, finish = {root}, [root], root[1]
        for index in range(low + 1, min(self.count, low + MAX_FRAGMENTS + 1)):
            item = self.entry(index)
            if item[0] != finish:
                break
            version, flags, parent, _ = self.unwind(item)
            if version != 1 or flags != 4 or parent not in accepted:
                break
            if index >= low + MAX_FRAGMENTS:
                raise ValueError('Complete function exceeds the fixed fragment budget')
            if not item[0] < item[1] <= address + MAX_FUNCTION:
                raise ValueError('Continuation exceeds the single-function byte bound')
            accepted.add(item)
            entries.append(item)
            finish = item[1]
        if not address < finish <= address + MAX_FUNCTION or not self.executable(address, finish-address):
            raise ValueError('Candidate function is outside backed executable bounds')
        return entries, finish


def dfcode(path, address, length, file_sha=None, code_sha=None):
    path = Path(path)
    if path.stat().st_size != length + 32:
        raise ValueError('Saved code file length mismatch')
    with path.open('rb') as stream:
        sample = stream.read(length + 33)
    if len(sample) != length + 32:
        raise ValueError('Saved code file length mismatch')
    magic, recorded_rva, recorded_length, _private_qword = struct.unpack('<4Q', sample[:32])
    if magic != MAGIC or (recorded_rva, recorded_length) != (address, length):
        raise ValueError('Saved code header identity mismatch')
    code = sample[32:]
    if file_sha is not None and sha(sample) != file_sha:
        raise ValueError('Saved code full-file SHA mismatch')
    if code_sha is not None and sha(code) != code_sha:
        raise ValueError('Saved code payload SHA mismatch')
    return code, sha(sample)


def verify_prefix():
    code, file_sha = dfcode(PREFIX_SOURCE, PREFIX_RVA, 32, PREFIX_FILE_SHA, PREFIX_CODE_SHA)
    old_result = load_json(PREFIX_SOURCE.parent / 'result.json')
    item = next((x for x in old_result.get('functions', []) if
                 x.get('name') == 'UControlChannel.CheckEndianess.prefix'), None)
    if (old_result.get('client_sha256') != IMAGE_SHA or not item or
            item.get('rva') != hex(PREFIX_RVA) or item.get('code_bytes') != 32 or
            item.get('read_succeeded') is not True or item.get('code_sha256') != PREFIX_CODE_SHA):
        raise ValueError('Saved CheckEndianess prefix/report mismatch')
    decoder = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
    decoder.detail = True
    first = next(decoder.disasm(code[:5], PREFIX_RVA), None)
    if (code[0] != 0xe9 or first is None or first.mnemonic != 'jmp' or first.size != 5 or
            len(first.operands) != 1 or first.operands[0].type != X86_OP_IMM or
            first.operands[0].imm != BODY_RVA):
        raise ValueError('Saved CheckEndianess prefix does not lead directly to fixed body')
    return {'source_relative_path': PREFIX_SOURCE.relative_to(ROOT).as_posix(),
            'file_sha256': file_sha, 'code_sha256': PREFIX_CODE_SHA,
            'prefix_rva': hex(PREFIX_RVA), 'verified_direct_e9_target_rva': hex(BODY_RVA)}


def validate_plan(plan, image):
    if (plan.get('kind') != 'bounded_unknown_control_candidate_interval_plan' or
            plan.get('client_sha256') != IMAGE_SHA or plan.get('plan_accepted') is not True):
        raise ValueError('Fixed candidate plan identity mismatch')
    fixed = plan.get('fixed_range', {})
    if not isinstance(fixed, dict):
        raise ValueError('Invalid fixed candidate interval metadata')
    if (rva(fixed.get('start_rva')), rva(fixed.get('end_rva_exclusive')),
            fixed.get('read_budget_bytes')) != (START, END, READ_BYTES):
        raise ValueError('Candidate interval differs from the fixed range')
    declared = plan.get('candidate_roots', [])
    if (not isinstance(declared, list) or len(declared) != len(ROOT_RVAS) or
            not all(isinstance(x, dict) for x in declared) or
            tuple(rva(x.get('read_rva')) for x in declared) != ROOT_RVAS):
        raise ValueError('Fixed thirteen candidate roots mismatch')
    targets = plan.get('identity_targets', {})
    if (not isinstance(targets, dict) or
            not isinstance(targets.get('fixed_utf16_received_bunch_logs'), list) or
            not all(isinstance(x, dict) for x in targets['fixed_utf16_received_bunch_logs']) or
            not isinstance(targets.get('exact_direct_e8_call_targets'), list)):
        raise ValueError('Invalid fixed semantic identity target metadata')
    if ([(rva(x.get('rva')), x.get('literal')) for x in targets.get('fixed_utf16_received_bunch_logs', [])]
            != list(LOGS) or
            {rva(x) for x in targets.get('exact_direct_e8_call_targets', [])} != {BODY_RVA, PREFIX_RVA}):
        raise ValueError('Fixed semantic identity targets mismatch')
    for address, literal in LOGS:
        encoded = literal.encode('utf-16le') + b'\0\0'
        if image.data(address, len(encoded)) != encoded:
            raise ValueError('Immutable ReceivedBunch log literal mismatch')
    entries, padding, total, previous = [], [], 0, START
    for row in declared:
        address = rva(row['read_rva'])
        actual, finish = image.function(address)
        if (row.get('label') != 'unknown_' + format(address, 'x') or
                tuple(rva(x) for x in row.get('root', [])) != actual[0] or
                rva(row.get('end_rva')) != finish or row.get('code_bytes') != finish-address or
                [(rva(a), rva(b)) for a, b in row.get('unwind_fragments', [])] !=
                [(x[0], x[1]) for x in actual] or row.get('continuations') != len(actual)-1 or
                row.get('issues') != [] or not START <= address < finish <= END):
            raise ValueError('Candidate root/complete boundary differs from immutable metadata')
        if previous > address:
            raise ValueError('Candidate functions overlap')
        if previous < address:
            padding.append([hex(previous), hex(address)])
        previous = finish
        total += finish-address
        entries.extend(actual)
    if previous < END:
        padding.append([hex(previous), hex(END)])
    if total != CODE_BYTES or plan.get('excluded_padding') != padding:
        raise ValueError('Candidate byte total/padding differs from fixed bounds')
    metadata = plan.get('runtime_function_entries', [])
    if (not isinstance(metadata, list) or len(metadata) != len(entries) or
            not all(isinstance(x, dict) for x in metadata)):
        raise ValueError('Candidate metadata entry count mismatch')
    for row, item in zip(metadata, entries):
        version, flags, parent, value = image.unwind(item)
        if (tuple(rva(x) for x in row.get('entry', [])) != item or row.get('version') != version or
                row.get('flags') != flags or row.get('metadata_bytes') != len(value) or
                row.get('metadata_sha256') != sha(value) or
                (None if row.get('chain_parent') is None else tuple(rva(x) for x in row['chain_parent'])) != parent):
            raise ValueError('Immutable unwind metadata/parent SHA mismatch')
    summary = plan.get('summary', {})
    if not isinstance(summary, dict):
        raise ValueError('Invalid fixed candidate plan summary')
    if (summary.get('candidate_roots') != 13 or summary.get('entries') != len(entries) or
            summary.get('complete_function_bytes') != CODE_BYTES or
            summary.get('padding_bytes') != READ_BYTES-CODE_BYTES or
            summary.get('strict_closure_passed') is not True or summary.get('issues') != []):
        raise ValueError('Fixed candidate plan summary mismatch')
    if not image.executable(PREFIX_RVA, 32) or image.function(BODY_RVA)[1] != BODY_RVA + 287:
        raise ValueError('Saved CheckEndianess target metadata mismatch')
    return declared


def exact_instructions(instructions, expected):
    by_address = {x.address: x for x in instructions}
    records = []
    for address, mnemonic, operands in expected:
        ins = by_address.get(address)
        if ins is None or (ins.mnemonic, ins.op_str) != (mnemonic, operands):
            raise ValueError('Pinned code/table semantic instruction mismatch')
        records.append({'instruction_rva': hex(address), 'mnemonic': mnemonic, 'operands': operands})
    return records


def classify_known_table(code, address, decoder):
    """A single saved, SHA-pinned switch; never infer tables in arbitrary roots."""
    if address != TABLE_ROOT:
        return None
    if len(code) != TABLE_END - TABLE_ROOT or sha(code) != TABLE_SAMPLE_SHA:
        raise ValueError('Known table-bearing sample differs from the audited payload')
    instructions = list(decoder.disasm(code[:CODE_END-address], address))
    if sum(x.size for x in instructions) != CODE_END-address:
        raise ValueError('Audited executable range does not fully decode')
    dispatch = exact_instructions(instructions, (
        (0x12867149, 'movzx', 'edx, byte ptr [rbp + 0xb0]'),
        (0x12867150, 'cmp', 'edx, 0x1c'),
        (0x12867153, 'ja', '0x1286762f'),
        (0x12867159, 'lea', 'r13, [rip - 0x12867160]'),
        (0x12867160, 'mov', 'ecx, dword ptr [r13 + rdx*4 + 0x12867724]'),
        (0x12867168, 'add', 'rcx, r13'),
        (0x1286716b, 'jmp', 'rcx'),
        (0x12867721, 'ret', ''),
    ))
    pad = code[CODE_END-address:TABLE_START-address]
    padding = list(decoder.disasm(pad, CODE_END))
    if len(padding) != 1 or padding[0].mnemonic != 'nop' or padding[0].size != 2:
        raise ValueError('Audited return/table padding is not the exact two-byte NOP')
    table = code[TABLE_START-address:TABLE_END-address]
    targets = struct.unpack('<29I', table)
    boundaries = {x.address: x for x in instructions}
    if any(x not in boundaries for x in targets):
        raise ValueError('Switch target is outside verified instruction boundaries')
    # Follow only existing decoded instruction boundaries and the proved table.
    # Calls do not expand the graph. External indirect tail calls remain explicit.
    pending, visited, exits, indirect_exits = [address], set(), [], []
    while pending:
        current = pending.pop()
        if current in visited:
            continue
        ins = boundaries.get(current)
        if ins is None:
            raise ValueError('Bounded CFG enters padding/table or a non-instruction byte')
        visited.add(current)
        if ins.group(capstone.CS_GRP_RET) or ins.mnemonic in ('int3', 'ud2'):
            continue
        successors = []
        if ins.group(capstone.CS_GRP_JUMP):
            if len(ins.operands) == 1 and ins.operands[0].type == X86_OP_IMM:
                target = ins.operands[0].imm
                if address <= target < CODE_END:
                    successors.append(target)
                else:
                    exits.append({'instruction_rva': hex(current), 'target_rva': hex(target)})
            elif current == 0x1286716b:
                successors.extend(targets)
            else:
                indirect_exits.append({'instruction_rva': hex(current),
                                       'mnemonic': ins.mnemonic, 'operands': ins.op_str})
            if ins.mnemonic != 'jmp':
                successors.append(current+ins.size)
        else:
            successors.append(current+ins.size)
        pending.extend(successors)
    proof = {
        'classification': 'SHA-pinned executable range, NOP padding, and bounded RVA jump table',
        'code_ranges': [[hex(address), hex(CODE_END)]],
        'padding_ranges': [[hex(CODE_END), hex(TABLE_START)]],
        'table_ranges': [[hex(TABLE_START), hex(TABLE_END)]],
        'code_instruction_bytes': CODE_END-address,
        'padding_bytes': len(pad), 'table_bytes': len(table),
        'table_sha256': sha(table), 'table_entry_count': len(targets),
        'table_representation': 'uint32 RVA; image-base r13 + entry RVA',
        'dispatch_instructions': dispatch,
        'table_targets': [{'control_message_index': n, 'target_rva': hex(x)}
                          for n, x in enumerate(targets)],
        'all_table_targets_verified_instruction_boundaries': True,
        'code_ranges_fully_decoded': True, 'all_payload_bytes_classified': True,
        'cfg_instruction_count': len(visited), 'cfg_instruction_bytes': sum(boundaries[x].size for x in visited),
        'cfg_unreached_instruction_rvas': [hex(x) for x in boundaries if x not in visited],
        'cfg_external_direct_exits': exits, 'cfg_indirect_exits_not_followed': indirect_exits,
        'cfg_entered_table_or_padding': False,
        'all_payload_bytes_are_instructions': False,
    }
    return instructions, proof


def inline_endian_correspondence(instructions):
    helper, helper_sha = dfcode(HELPER_SOURCE, BODY_RVA, 287, HELPER_FILE_SHA, HELPER_CODE_SHA)
    old_result = load_json(HELPER_SOURCE.parent / 'result.json')
    row = next((x for x in old_result.get('functions', []) if
                x.get('name') == 'UControlChannel.CheckEndianess.implementation'), None)
    if (old_result.get('client_sha256') != IMAGE_SHA or row is None or
            row.get('read_succeeded') is not True or row.get('rva') != hex(BODY_RVA) or
            row.get('code_bytes') != 287 or row.get('code_sha256') != HELPER_CODE_SHA):
        raise ValueError('Saved CheckEndianess body/report mismatch')
    decoder = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
    decoder.detail = True
    helper_ins = list(decoder.disasm(helper, BODY_RVA))
    if sum(x.size for x in helper_ins) != len(helper):
        raise ValueError('Saved CheckEndianess body does not fully decode')
    incoming = exact_instructions(instructions, (
        (0x128668e5, 'xor', 'esi, esi'),
        (0x128668e7, 'mov', 'rbx, rdx'), (0x128668f0, 'mov', 'r12, rcx'),
        (0x128668f6, 'cmp', 'qword ptr [rcx + 0x28], rsi'),
        (0x128668fa, 'je', '0x128669e6'),
        (0x12866900, 'cmp', 'byte ptr [rcx + 0x70], sil'),
        (0x12866904, 'je', '0x128669e6'),
        (0x1286690a, 'lea', 'rcx, [rdx + 0x90]'),
        (0x12866911, 'call', 'qword ptr [rip + 0xad37541]'),
        (0x12866917, 'mov', 'rcx, qword ptr [rbx + 0xa0]'),
        (0x1286691e, 'add', 'rcx, 7'), (0x12866922, 'and', 'rcx, 0xfffffffffffffff8'),
        (0x12866926, 'cmp', 'rcx, 0x10'), (0x1286692a, 'jl', '0x12866a61'),
        (0x12866930, 'cmp', 'byte ptr [rax], sil'), (0x12866933, 'jne', '0x12866a61'),
        (0x12866939, 'movzx', 'edi, byte ptr [rax + 1]'),
        (0x128669b3, 'movzx', 'eax, byte ptr [rbx + 0x29]'),
        (0x128669b7, 'cmp', 'dil, 1'), (0x128669bb, 'je', '0x128669d0'),
        (0x128669bd, 'or', 'al, 0x20'), (0x128669bf, 'mov', 'byte ptr [rbx + 0x29], al'),
        (0x128669c2, 'mov', 'rax, qword ptr [r12 + 0x28]'),
        (0x128669c7, 'mov', 'byte ptr [rax + 0x180], 1'),
        (0x128669d0, 'and', 'al, 0xdf'), (0x128669d2, 'mov', 'byte ptr [rbx + 0x29], al'),
        (0x128669d5, 'mov', 'rax, qword ptr [r12 + 0x28]'),
        (0x128669da, 'mov', 'byte ptr [rax + 0x180], sil'),
        (0x128669e1, 'mov', 'byte ptr [r12 + 0x70], sil'),
    ))
    saved = exact_instructions(helper_ins, (
        (0x1284b24a, 'mov', 'rdi, rcx'), (0x1284b24d, 'mov', 'rbx, rdx'),
        (0x1284b250, 'lea', 'rcx, [rdx + 0x90]'),
        (0x1284b257, 'call', 'qword ptr [rip + 0xad52bfb]'),
        (0x1284b260, 'mov', 'rax, qword ptr [rbx + 0xa0]'),
        (0x1284b267, 'add', 'rax, 7'), (0x1284b26b, 'and', 'rax, 0xfffffffffffffff8'),
        (0x1284b26f, 'cmp', 'rax, 0x10'), (0x1284b273, 'jl', '0x1284b352'),
        (0x1284b279, 'cmp', 'byte ptr [rcx], 0'), (0x1284b27c, 'jne', '0x1284b352'),
        (0x1284b28e, 'movzx', 'esi, byte ptr [rcx + 1]'),
        (0x1284b301, 'movzx', 'eax, byte ptr [rbx + 0x29]'),
        (0x1284b305, 'cmp', 'sil, 1'), (0x1284b30e, 'je', '0x1284b331'),
        (0x1284b310, 'or', 'al, 0x20'), (0x1284b312, 'mov', 'byte ptr [rbx + 0x29], al'),
        (0x1284b315, 'mov', 'rax, qword ptr [rdi + 0x28]'),
        (0x1284b319, 'mov', 'byte ptr [rax + 0x180], 1'),
        (0x1284b322, 'mov', 'byte ptr [rdi + 0x70], 0'),
        (0x1284b331, 'and', 'al, 0xdf'), (0x1284b333, 'mov', 'byte ptr [rbx + 0x29], al'),
        (0x1284b336, 'mov', 'rax, qword ptr [rdi + 0x28]'),
        (0x1284b33a, 'mov', 'byte ptr [rax + 0x180], 0'),
        (0x1284b343, 'mov', 'byte ptr [rdi + 0x70], 0'),
    ))
    incoming_accessor = next(x for x in instructions if x.address == 0x12866911)
    saved_accessor = next(x for x in helper_ins if x.address == 0x1284b257)
    slots = [x.address+x.size+x.operands[0].mem.disp for x in (incoming_accessor, saved_accessor)]
    if slots[0] != slots[1]:
        raise ValueError('Inlined endian check uses a different buffer accessor slot')
    return {'source_relative_path': HELPER_SOURCE.relative_to(ROOT).as_posix(),
            'file_sha256': helper_sha, 'code_sha256': HELPER_CODE_SHA,
            'saved_helper_instructions': saved, 'inlined_instructions': incoming,
            'same_buffer_accessor_slot_rva': hex(slots[0]),
            'correspondence': ['buffer accessor for bunch+0x90',
                'rounded (bunch+0xa0 + 7) & ~7 must be at least 16',
                'first byte must be 0; second byte compared with 1',
                'bunch+0x29 bit 0x20 and connection+0x180 set/clear together',
                'channel+0x70 cleared after endian handling'],
            'compiler_inlining_is_an_inference': True,
            'memory_offsets_are_not_wire_bit_offsets': True,
            'strict_direct_call_identity_rule_satisfied': False}


def inspect_code(code, address, image_size):
    decoder = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
    decoder.detail = True
    instructions = list(decoder.disasm(code, address))
    decoded = sum(x.size for x in instructions)
    complete = decoded == len(code)
    classified = classify_known_table(code, address, decoder)
    classification, inline = None, None
    if classified is not None:
        instructions, classification = classified
        inline = inline_endian_correspondence(instructions)
    logs, calls, escapes = [], [], []
    if complete or classification is not None:
        log_map = dict(LOGS)
        for ins in instructions:
            if (ins.mnemonic == 'lea' and len(ins.operands) == 2 and
                    ins.operands[1].type == X86_OP_MEM and ins.operands[1].mem.base == X86_REG_RIP):
                target = ins.address + ins.size + ins.operands[1].mem.disp
                if target in log_map:
                    logs.append({'instruction_rva': hex(ins.address), 'log_rva': hex(target),
                                 'literal': log_map[target]})
            if (ins.mnemonic == 'call' and ins.size == 5 and ins.bytes[0] == 0xe8 and
                    len(ins.operands) == 1 and ins.operands[0].type == X86_OP_IMM):
                target = ins.operands[0].imm
                calls.append({'instruction_rva': hex(ins.address),
                              'target_rva': hex(target) if 0 <= target < image_size else None,
                              'same_image_target': 0 <= target < image_size,
                              'check_endianess': target in (BODY_RVA, PREFIX_RVA),
                              'via_verified_prefix': target == PREFIX_RVA})
            if (ins.group(capstone.CS_GRP_JUMP) and len(ins.operands) == 1 and
                    ins.operands[0].type == X86_OP_IMM and
                    not address <= ins.operands[0].imm < address + len(code)):
                target = ins.operands[0].imm
                escapes.append({'instruction_rva': hex(ins.address),
                                'target_rva': hex(target) if 0 <= target < image_size else None,
                                'same_image_target': 0 <= target < image_size})
    matched_logs = sorted({rva(x['log_rva']) for x in logs})
    candidate = (complete or classification is not None) and matched_logs == sorted(dict(LOGS)) and any(x['check_endianess'] for x in calls)
    record = {'disassembled_bytes': decoded, 'instruction_count': len(instructions),
            'full_decode': complete, 'fixed_log_references': logs, 'direct_calls': calls,
            'escaping_direct_branches': escapes,
            'identity_status': 'semantic_identity_candidate' if candidate else 'unknown',
            'proposed_role': 'UControlChannel::ReceivedBunch' if candidate else None,
            'concrete_vtable_override_verified': False}
    if classification is not None:
        record['payload_classification'] = classification
        record['inline_endian_correspondence'] = inline
        record['all_four_fixed_logs_verified'] = matched_logs == sorted(dict(LOGS))
        record['observed_semantic_role'] = ('UControlChannel::ReceivedBunch with endian handling'
                                             if record['all_four_fixed_logs_verified'] else None)
        record['identity_rule_limitation'] = ('strict E8 matcher does not support the independently '
                                              'audited inline endian sequence; unknown does not mean missing function')
    return record


def analyze_samples(folder, plan, declared, image_size):
    result = load_json(folder / 'result.json')
    rows = result.get('functions', [])
    expected_names = {x['label'] for x in declared}
    if (result.get('client_sha256') != IMAGE_SHA or not isinstance(rows, list) or
            len(rows) != 13 or not all(isinstance(x, dict) for x in rows) or
            {x.get('name') for x in rows} != expected_names):
        raise ValueError('Capture report does not contain exactly the fixed thirteen candidates')
    files = {x.name for x in folder.glob('unknown_*.dfcode')}
    succeeded_names = {x['name'] for x in rows if x.get('read_succeeded') is True}
    if not files <= {name + '.dfcode' for name in succeeded_names}:
        raise ValueError('Saved candidate files include an extra or failed-report root')
    records = []
    for root in declared:
        row = next(x for x in rows if x['name'] == root['label'])
        address, length = rva(root['read_rva']), root['code_bytes']
        item = {'name': root['label'], 'rva': hex(address), 'planned_code_bytes': length,
                'identity_status': 'unknown', 'proposed_role': None}
        try:
            if (row.get('read_succeeded') is not True or rva(row.get('rva')) != address or
                    row.get('code_bytes') != length or
                    any(not isinstance(row.get(key), str) or len(row[key]) != 64 or
                        any(c not in '0123456789abcdef' for c in row[key])
                        for key in ('file_sha256', 'code_sha256'))):
                raise ValueError('Candidate capture report identity/SHA/read status mismatch')
            path = folder / (root['label'] + '.dfcode')
            code, file_sha = dfcode(path, address, length, row['file_sha256'], row['code_sha256'])
            item.update({'saved_header_and_report_sha_verified': True, 'file_sha256': file_sha,
                         'code_sha256': sha(code), 'source_filename': path.name})
            item.update(inspect_code(code, address, image_size))
            if row.get('disassembled_bytes') is not None and row['disassembled_bytes'] != item['disassembled_bytes']:
                raise ValueError('Saved report decode length differs from independent decode')
        except (ValueError, OSError) as error:
            item.update(identity_status='unknown', proposed_role=None,
                        validation_error=str(error), saved_input_valid=False)
        else:
            item['saved_input_valid'] = (item['full_decode'] or
                item.get('payload_classification', {}).get('all_payload_bytes_classified') is True)
        records.append(item)
    return records


def run(game_root, plan_path, sample_folder=None):
    plan_bytes = json_bytes(plan_path)
    plan = json.loads(plan_bytes)
    if not isinstance(plan, dict):
        raise ValueError('Candidate plan must be a JSON object')
    executable = Path(game_root) / EXE_RELATIVE
    with executable.open('rb') as stream, mmap.mmap(stream.fileno(), 0, access=mmap.ACCESS_READ) as raw:
        if sha(raw) != IMAGE_SHA:
            raise ValueError('Shipping executable version SHA mismatch')
        image = Image(raw)
        declared = validate_plan(plan, image)
        prefix = verify_prefix()
        report = {'kind': 'offline_unknown_control_candidate_interval_analysis',
                  'client_sha256': IMAGE_SHA, 'plan_sha256': sha(plan_bytes),
                  'process_access': False, 'game_launched': False, 'elevation_requested': False,
                  'runtime_code_read': False, 'raw_cookie_or_aslr_exported': False,
                  'fixed_range': {'start_rva': hex(START), 'end_rva_exclusive': hex(END),
                                  'maximum_candidate_code_bytes': CODE_BYTES, 'candidate_count': 13},
                  'immutable_plan_and_logs_verified': True, 'check_endianess_prefix': prefix,
                  'required_identity_rule': 'all four fixed LEA-RIP UTF16 log references and direct E8 to fixed body or SHA/E9-verified prefix',
                  'candidates': [], 'concrete_vtable_override_verified': False,
                  'control_protocol_verified': False, 'playable_map_verified': False}
        if sample_folder is None:
            report['status'] = 'offline_plan_validated_no_new_samples'
        else:
            report['candidates'] = analyze_samples(Path(sample_folder), plan, declared, image.size)
            matches = [x['name'] for x in report['candidates'] if x['identity_status'] == 'semantic_identity_candidate']
            valid_count = sum(x.get('saved_input_valid') is True for x in report['candidates'])
            report['semantic_identity_candidates'] = matches
            report['fully_verified_roots'] = valid_count
            report['full_instruction_decode_roots'] = sum(x.get('full_decode') is True
                                                          for x in report['candidates'])
            report['classified_code_and_data_roots'] = sum(
                x.get('payload_classification', {}).get('all_payload_bytes_classified') is True
                for x in report['candidates'])
            report['semantic_observations_outside_strict_direct_call_rule'] = [
                {'name': x['name'], 'role': x['observed_semantic_role'],
                 'identity_rule_limitation': x['identity_rule_limitation']}
                for x in report['candidates'] if x.get('observed_semantic_role')]
            report['unverified_roots'] = len(declared) - valid_count
            report['only_one_observed_semantic_candidate'] = len(matches) == 1
            report['unique_semantic_candidate'] = len(matches) == 1 and valid_count == len(declared)
            report['status'] = ('analysis_complete' if valid_count == len(declared)
                                else 'partial_analysis_input_validation_failed')
        return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--game-root', required=True)
    parser.add_argument('--plan', type=Path, default=DEFAULT_PLAN)
    parser.add_argument('--samples', type=Path)
    parser.add_argument('--output', type=Path)
    arguments = parser.parse_args()
    try:
        report = run(arguments.game_root, arguments.plan, arguments.samples)
    except (ValueError, OSError, KeyError, TypeError, struct.error) as error:
        report = {'kind': 'offline_unknown_control_candidate_interval_analysis',
                  'status': 'offline_validation_failed', 'validation_error': str(error),
                  'process_access': False, 'game_launched': False, 'elevation_requested': False,
                  'control_protocol_verified': False, 'playable_map_verified': False}
    output = arguments.output
    if output:
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(json.dumps(report, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')
    print(json.dumps({'status': report['status'],
                      'candidate_count': len(report.get('candidates', [])),
                      'semantic_candidate_count': len(report.get('semantic_identity_candidates', [])),
                      'process_access': False}, ensure_ascii=False))
    return 0 if report['status'] in ('analysis_complete', 'offline_plan_validated_no_new_samples') else 2


if __name__ == '__main__':
    raise SystemExit(main())
