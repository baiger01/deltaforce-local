"""Offline forensic comparison of two explicitly hash-pinned code observations.

Research only. Does not import or relax any production CodeCache/image guard,
open a process, call a native getter, or publish a runtime metadata binding.
"""
import argparse
import bisect
import hashlib
import json
import struct
from pathlib import Path

from capstone import Cs, CS_ARCH_X86, CS_MODE_64
from capstone.x86 import X86_OP_IMM, X86_OP_MEM, X86_REG_RIP

ROOT = Path(__file__).resolve().parent.parent
PINS = {
    'old': ('1792259162856698600',
            'dfd5c279d7db45842cee2bbc485ac8bf3cab03e4249ef5fe36bc9e8d6cd14754',
            '4254fbe66585f260f1f9dbfc5e302887842552e7baed8939e023160a5e250be0'),
    'new': ('1792785456045583200',
            'cb773fb7c9d51725b9b811e8f95967ecb26a0633c63dd0c2bea24b612597f765',
            '79fb7b105170141ed863331d36833a73062e66bf5291b2364fe3a64c18336203'),
}
CLIENT = Path('F:/deltaforce-local-shadow-build-79fb7b10/DeltaForce/Binaries/Win64/DeltaForceClient-Win64-Shipping.exe')


def sha(data):
    return hashlib.sha256(data).hexdigest()


class ForensicObservation:
    def __init__(self, label):
        folder, pin, client = PINS[label]
        self.folder = ROOT / 'work/native-code-cache' / folder
        self.raw_manifest = (self.folder / 'manifest.json').read_bytes()
        if sha(self.raw_manifest) != pin:
            raise ValueError('Exact historical observation manifest changed')
        self.doc = json.loads(self.raw_manifest)
        expected_kind = ('private_file_backed_executable_code_cache' if label == 'old'
                         else 'private_client_update_code_observation')
        if (self.doc['client_sha256'] != client or self.doc['kind'] != expected_kind
                or not self.doc['complete'] or not self.doc['scope_coverage_complete']):
            raise ValueError('Observation provenance/coverage mismatch')
        self.blocks, self.loaded, self.reads = [], {}, []
        total = 0
        for section in self.doc['sections']:
            at = first = int(section['rva'], 16)
            for block in section['blocks']:
                length = block['bytes']
                if (int(block['rva'], 16) != at or not block['available']
                        or not 0 < length <= 1048576
                        or block['file'] != f'section_{section["index"]:02d}_rva_{at:08x}.code'):
                    raise ValueError('Observation block coverage/path changed')
                self.blocks.append((at, at + length, block))
                at += length
            if at - first != section['bytes'] or section['available_bytes'] != at - first:
                raise ValueError('Observation section coverage changed')
            total += at - first
        if total != self.doc['saved_code_bytes']:
            raise ValueError('Observation byte accounting changed')
        self.starts = [x[0] for x in self.blocks]

    def read(self, rva, length):
        if not 0 < length <= 65536:
            raise ValueError('Bounded research query required')
        out = bytearray()
        at = rva
        while at < rva + length:
            index = bisect.bisect_right(self.starts, at) - 1
            first, end, block = self.blocks[index]
            if not first <= at < end:
                raise ValueError('Unavailable code interval')
            if first not in self.loaded:
                path = self.folder / block['file']
                data = path.read_bytes()
                if (path.resolve().parent != self.folder.resolve() or len(data) != end-first
                        or sha(data) != block['code_sha256']):
                    raise ValueError('Observation block SHA/size changed')
                self.loaded[first] = data
            high = min(end, rva + length)
            out.extend(self.loaded[first][at-first:high-first])
            at = high
        self.reads.append((rva, length, sha(out)))
        return bytes(out)

    def source_evidence(self):
        if (self.folder / 'manifest.json').read_bytes() != self.raw_manifest:
            raise ValueError('Observation changed during analysis')
        return {'manifest': str((self.folder / 'manifest.json').relative_to(ROOT)),
                'manifest_sha256': sha(self.raw_manifest),
                'client_sha256': self.doc['client_sha256'],
                'verified_blocks': [dict(rva=hex(first), bytes=end-first,
                    file=block['file'], sha256=block['code_sha256'])
                    for first, end, block in self.blocks if first in self.loaded],
                'reads': [dict(rva=hex(r), bytes=n, sha256=h) for r, n, h in sorted(set(self.reads))]}


class NewImage:
    def __init__(self):
        with CLIENT.open('rb') as stream:
            if hashlib.file_digest(stream, 'sha256').hexdigest() != PINS['new'][2]:
                raise ValueError('New shadow immutable PE SHA changed')
            stream.seek(0x3c)
            pe, = struct.unpack('<I', stream.read(4))
            stream.seek(pe)
            header = stream.read(0x108)
            if header[:4] != b'PE\0\0':
                raise ValueError('PE signature mismatch')
            count, = struct.unpack_from('<H', header, 6)
            opt_size, = struct.unpack_from('<H', header, 20)
            self.image_base, = struct.unpack_from('<Q', header, 24+24)
            self.image_size, = struct.unpack_from('<I', header, 24+56)
            exc_rva, exc_size = struct.unpack_from('<II', header, 24+112+3*8)
            stream.seek(pe+24+opt_size)
            self.sections = []
            for _ in range(count):
                row = stream.read(40)
                vsize, rva, raw_size, raw_at = struct.unpack_from('<4I', row, 8)
                self.sections.append((rva, raw_size, raw_at))
        self.exc_data = self.read(exc_rva, exc_size)
        self.entries = list(struct.iter_unpack('<III', self.exc_data))
        self.starts = [x[0] for x in self.entries]

    def read(self, rva, length):
        for first, raw_size, raw_at in self.sections:
            if first <= rva < rva+length <= first+raw_size:
                with CLIENT.open('rb') as stream:
                    stream.seek(raw_at+rva-first)
                    data = stream.read(length)
                if len(data) == length:
                    return data
        raise ValueError('RVA outside one immutable raw-backed section')

    def fragments(self, rva):
        i = bisect.bisect_left(self.starts, rva)
        if i == len(self.entries) or self.entries[i][0] != rva:
            return []
        rows = [self.entries[i]]
        accepted = set(rows)
        for row in self.entries[i+1:i+64]:
            if row[0] != rows[-1][1]:
                break
            head = self.read(row[2], 4)
            if head[0] >> 3 != 4:
                break
            offset = 4 + ((head[2]+1)&~1)*2
            chained = struct.unpack('<III', self.read(row[2]+offset, 12))
            if chained not in accepted:
                break
            rows.append(row)
            accepted.add(row)
        return rows


def decoder():
    result = Cs(CS_ARCH_X86, CS_MODE_64)
    result.detail = True
    return result


def disasm(observation, rva, length):
    return list(decoder().disasm(observation.read(rva, length), rva))


def instruction_row(ins):
    row = dict(rva=hex(ins.address), bytes_hex=bytes(ins.bytes).hex(),
               instruction=f'{ins.mnemonic} {ins.op_str}')
    rip = [hex(ins.address + ins.size + op.mem.disp) for op in ins.operands
           if op.type == X86_OP_MEM and op.mem.base == X86_REG_RIP]
    if rip:
        row['rip_targets'] = rip
    return row


def dump(label, rva, length):
    observation = ForensicObservation(label)
    for ins in disasm(observation, rva, length):
        row = instruction_row(ins)
        print(row['rva'], row['instruction'], ' '.join(row.get('rip_targets', [])))


PAIRS = [
    ('chunk_quotient', 0xd60500, 0xd60580, 0x614),
    ('chunk_remainder', 0xd60d00, 0xd60d80, 0x644),
    ('name_ascii_transform', 0x10b5fd00, 0x10b5f6d0, 0x1ec),
    ('name_wide_transform', 0x10b5ff10, 0x10b5f8e0, 0x25e),
    ('object_path', 0x10ead090, 0x10eaca30, 0x148),
    ('object_path_append', 0x10ead1e0, 0x10eacb80, 0x12e),
    ('package_class_getter', 0x10e564e0, 0x10e55e80, 0xb3),
    ('name_entry_lookup', 0x10b638b0, 0x10b63280, 0x58),
    ('name_entry_to_string', 0x10b68690, 0x10b68060, 0x158),
    ('name_entry_append', 0x10b5bde0, 0x10b5b7b0, 0xd7),
    ('name_token_append', 0x10b5bec0, 0x10b5b890, 0x188),
    ('name_token_to_string', 0x10b78000, 0x10b779d0, 0x229),
    ('signed_number_append', 0x109ed950, 0x109ed3b0, 0xbc),
    ('narrow_utf16_conversion', 0xd60360, 0xd603e0, 0xa4),
    ('weak_object_get', 0x10ecea20, 0x10ece3c0, 0x9a),
    ('object_registry_serial_get_or_allocate', 0x10ea1680, 0x10ea1020, 0xb8),
    ('name_pool_ctor_prefix', 0x10b562d0, 0x10b55ca0, 0x8f),
    ('field_or_object_representation_name', 0x10e1c980, 0x10e1c320, 0x37),
    ('field_full_name', 0x10e1c900, 0x10e1c2a0, 0x79),
    ('field_outer_path', 0x10e1f740, 0x10e1f0e0, 0x3bb),
    ('object_full_name', 0x10eac970, 0x10eac310, 0x1ec),
]


def compare_pair(old, new, name, old_rva, new_rva, length, image):
    old_code, new_code = old.read(old_rva, length), new.read(new_rva, length)
    oi, ni = disasm(old, old_rva, length), disasm(new, new_rva, length)
    if (sum(i.size for i in oi) != length or sum(i.size for i in ni) != length
            or len(oi) != len(ni)):
        raise ValueError('Incomplete instruction comparison: ' + name)
    refs, anchors = [], []
    for a, b in zip(oi, ni):
        if (a.address-old_rva, a.size, a.id) != (b.address-new_rva, b.size, b.id):
            raise ValueError('Instruction shape changed: ' + name)
        aa, bb = bytearray(a.bytes), bytearray(b.bytes)
        kinds = []
        for index, (x, y) in enumerate(zip(a.operands, b.operands)):
            if (x.type, x.size, x.access) != (y.type, y.size, y.access):
                raise ValueError('Instruction operand structure changed: ' + name)
            if x.type == X86_OP_MEM:
                if (x.mem.base, x.mem.index, x.mem.scale) != (y.mem.base, y.mem.index, y.mem.scale):
                    raise ValueError('Memory addressing mode changed: ' + name)
                if x.mem.base == X86_REG_RIP:
                    kinds.append(('rip_reference', a.disp_offset, a.disp_size,
                                  a.address+a.size+x.mem.disp, b.address+b.size+y.mem.disp))
                elif x.mem.disp != y.mem.disp and 0x100000 < x.mem.disp < image.image_size:
                    # Explicit base/index RVA operand; retain both targets as evidence.
                    kinds.append(('image_base_indexed_rva', a.disp_offset, a.disp_size,
                                  x.mem.disp, y.mem.disp))
            if (x.type == X86_OP_IMM and a.mnemonic.startswith(('j', 'call'))):
                if old_rva <= x.imm < old_rva+length:
                    if x.imm-old_rva != y.imm-new_rva:
                        raise ValueError('Internal control-flow target changed: ' + name)
                kinds.append(('direct_control_flow', a.imm_offset, a.imm_size, x.imm, y.imm))
        for kind, offset, size, old_target, new_target in kinds:
            if not size:
                raise ValueError('Reference encoding missing')
            aa[offset:offset+size] = bytes(size)
            bb[offset:offset+size] = bytes(size)
            refs.append(dict(kind=kind, old_instruction=hex(a.address),
                new_instruction=hex(b.address), old_target=hex(old_target), new_target=hex(new_target)))
        if aa != bb:
            raise ValueError(f'Non-reference bytes changed: {name} at {a.address:x}/{b.address:x}')
        anchors.append(instruction_row(b))
    fragments = image.fragments(new_rva)
    is_prefix = name.endswith('_prefix')
    if fragments and not is_prefix and fragments[-1][1]-new_rva != length:
        raise ValueError('Complete chained unwind coverage changed: ' + name)
    return dict(name=name, old_rva=hex(old_rva), new_rva=hex(new_rva), bytes=length,
        old_code_sha256=sha(old_code), new_code_sha256=sha(new_code),
        full_linear_decode=True, instructions=len(ni),
        all_non_reference_instruction_bytes_identical=True,
        internal_direct_control_flow_preserved=True, references=refs,
        new_fragments=[dict(begin=hex(a), end_exclusive=hex(b), unwind_rva=hex(c))
                       for a, b, c in fragments],
        scope='constructor prefix only' if is_prefix else 'complete fixed function code',
        decoded_new_instructions=anchors)


def compare_tables(old, new):
    rows = []
    for name, old_start, new_start, old_table, new_table, cases in [
        ('chunk_quotient', 0xd60500, 0xd60580, 0xd60b14, 0xd60b94, 10),
        ('chunk_remainder', 0xd60d00, 0xd60d80, 0xd61344, 0xd613c4, 10),
        ('name_ascii_transform', 0x10b5fd00, 0x10b5f6d0, 0x10b5feec, 0x10b5f8bc, 9),
        ('name_wide_transform', 0x10b5ff10, 0x10b5f8e0, 0x10b60170, 0x10b5fb40, 9),
    ]:
        old_raw, new_raw = old.read(old_table, cases*4), new.read(new_table, cases*4)
        old_targets = struct.unpack('<'+'I'*cases, old_raw)
        new_targets = struct.unpack('<'+'I'*cases, new_raw)
        boundaries = {i.address for i in disasm(new, new_start, new_table-new_start)}
        if ([v-old_start for v in old_targets] != [v-new_start for v in new_targets]
                or not all(v in boundaries for v in new_targets)):
            raise ValueError('Jump table case/target mapping changed: ' + name)
        rows.append(dict(name=name, old_table_rva=hex(old_table), new_table_rva=hex(new_table),
            cases=cases, old_sha256=sha(old_raw), new_sha256=sha(new_raw),
            old_targets=[hex(v) for v in old_targets], new_targets=[hex(v) for v in new_targets],
            raw_new_hex=new_raw.hex(), case_relative_targets_identical=True,
            all_targets_valid_instruction_boundaries=True))
    return rows


def static_report():
    old, new, image = ForensicObservation('old'), ForensicObservation('new'), NewImage()
    comparisons = [compare_pair(old, new, *pair, image) for pair in PAIRS]
    tables = compare_tables(old, new)
    literals = []
    for rva, length, expected in [(0x1ab58db2, 16, 'Package\0'),
            (0x15a84fb8, 40, '/Script/CoreUObject\0'), (0x14ec37c8, 10, 'None\0'),
            (0x1aad78d8, 40, '9876543210123456789\0')]:
        data = image.read(rva, length)
        if data.decode('utf-16-le') != expected:
            raise ValueError('New immutable literal mismatch')
        literals.append(dict(rva=hex(rva), bytes=length, sha256=sha(data), utf16=expected))
    root_code = new.read(0x10992480, 0x3b)
    root_ins = disasm(new, 0x10992480, 0x3b)
    if sum(i.size for i in root_ins) != len(root_code):
        raise ValueError('Registry root constructor decode incomplete')
    instructions = {int(row['rva'], 16): row for func in comparisons
                    for row in func['decoded_new_instructions']}
    instructions.update({ins.address: instruction_row(ins) for ins in root_ins})
    binding_witnesses = []
    for label, rva, target in [
        ('registry_rva', 0x10992493, 0x1e34ee88),
        ('count_rva', 0x10ece3d7, 0x1e34ee9c),
        ('chunks_rva', 0x10ece3f8, 0x1e34eea8),
        ('pointer_decoder_rva', 0x10ece423, 0x1db3a770),
        ('outer_selector_rva', 0xd60580, 0x1e3187c4),
        ('first_inner_selector_rva', 0xd605b1, 0x1e3187cc),
        ('last_inner_selector_rva', 0xd60b2c, 0x1e3187f0),
        ('parameter_rva', 0xd605bb, 0x1e3187f4),
        ('name_pool_rva', 0x10b632a3, 0x1e326ac0),
        ('name_pool_initialized_rva', 0x10b63292, 0x1e3267ec),
        ('package_class_rva', 0x10e55e8a, 0x1e34cad0),
    ]:
        witness = instructions[rva]
        if witness.get('rip_targets') != [hex(target)]:
            raise ValueError('Binding lacks its exact native RIP witness: '+label)
        binding_witnesses.append(dict(binding=label, **witness))
    semantic_witnesses = []
    for meaning, rva, expected in [
        ('UObject index at +0x24', 0x1099248e, 'mov edx, dword ptr [rdx + 0x24]'),
        ('registry relative count at +0x14', 0x10ea1039, 'cmp edx, dword ptr [rcx + 0x14]'),
        ('registry relative chunks at +0x20', 0x10ea1045, 'mov rbx, qword ptr [rsi + 0x20]'),
        ('entry stride part one: 3*remainder', 0x10ece3ff, 'lea rdx, [rcx + rcx*2]'),
        ('entry stride part two: 8*(3*remainder)', 0x10ece40c, 'lea rax, [rcx + rdx*8]'),
        ('slot serial at +0x14', 0x10ece415, 'cmp dword ptr [rax + 0x14], esi'),
        ('excluded flags at +8', 0x10ece41a, 'test dword ptr [rax + 8], 0x30000000'),
        ('direct object pointer at slot+0 when callback is null', 0x10ece43f, 'mov rax, qword ptr [rax]'),
        ('UObject Outer at +0x10', 0x10eaca68, 'mov rbx, qword ptr [rcx + 0x10]'),
        ('UObject Class at +8', 0x10eaca91, 'cmp qword ptr [rbx + 8], rax'),
        ('UObject 8-byte name token at +0x1c', 0x10eacb22, 'mov rax, qword ptr [rsi + 0x1c]'),
        ('field name token at +0x28', 0x10e1f146, 'lea rcx, [rsi + 0x28]'),
        ('name entry block id is id>>18', 0x10b6328a, 'shr ebx, 0x12'),
        ('name entry within-block units id&0x3ffff', 0x10b6328d, 'and eax, 0x3ffff'),
        ('name pool blocks at root+8 with 8-byte stride', 0x10b632cd, 'add rax, qword ptr [rdx + rbx*8 + 8]'),
        ('name header is u16', 0x10b68084, 'movzx eax, word ptr [rcx]'),
        ('name payload begins at +2', 0x10b6808d, 'lea rdx, [rcx + 2]'),
        ('name length is header>>6', 0x10b68097, 'shr edi, 6'),
        ('wide flag is header&1', 0x10b6809f, 'test al, 1'),
        ('zero-number narrow high-byte replacement is question mark', 0x10b68168, 'mov word ptr [rsp + 0x20], 0x3f'),
        ('append narrow widening sign-extends bytes', 0x10b5b843, 'movsx edx, byte ptr [rsp + rax + 0x20]'),
        ('name number loaded as u32 at token+4', 0x10b77b7c, 'mov edx, dword ptr [rsi + 4]'),
        ('name suffix subtracts one', 0x10b77b7f, 'dec edx'),
        ('name suffix decimal sign bit', 0x109ed3d9, 'shr r11d, 0x1f'),
    ]:
        witness = instructions[rva]
        if witness['instruction'] != expected:
            raise ValueError('Exact semantic instruction changed: '+meaning)
        semantic_witnesses.append(dict(meaning=meaning, **witness))
    return dict(kind='offline_updated_metadata_root_qualification',
        native_protocol_compatibility_verified=False, runtime_metadata_recovered=False,
        process_accessed=False, process_memory_written=False, native_getter_called=False,
        production_reader_changed=False, old_image_identity_spoofed=False,
        source_code=Path(__file__).relative_to(ROOT).as_posix(),
        source_code_sha256=sha(Path(__file__).read_bytes()),
        sources=[old.source_evidence(), new.source_evidence()],
        immutable_new_pe=dict(path=str(CLIENT), sha256=PINS['new'][2],
            size=CLIENT.stat().st_size, image_base=hex(image.image_base), image_size=image.image_size,
            exception_table_sha256=sha(image.exc_data), exception_entries=len(image.entries)),
        function_comparisons=comparisons, jump_tables=tables, immutable_literals=literals,
        binding_witnesses=binding_witnesses, semantic_witnesses=semantic_witnesses,
        registry_root_constructor=dict(rva='0x10992480', bytes=len(root_code), sha256=sha(root_code),
            instructions=[instruction_row(i) for i in root_ins]),
        bindings=dict(registry_rva='0x1e34ee88', count_rva='0x1e34ee9c', chunks_rva='0x1e34eea8',
            pointer_decoder_rva='0x1db3a770', outer_selector_rva='0x1e3187c4',
            inner_selectors_rva='0x1e3187cc', inner_selector_count=10, parameter_rva='0x1e3187f4',
            name_pool_rva='0x1e326ac0', name_pool_initialized_rva='0x1e3267ec',
            package_class_rva='0x1e34cad0'))


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--dump', choices=['old', 'new'])
    parser.add_argument('--rva', type=lambda x: int(x, 0))
    parser.add_argument('--bytes', type=lambda x: int(x, 0), default=0x200)
    parser.add_argument('--static', action='store_true')
    args = parser.parse_args()
    if args.dump:
        dump(args.dump, args.rva, args.bytes)
    if args.static:
        result = static_report()
        output = ROOT / 'work/evidence/updated-metadata-roots-79fb7b10-static.json'
        output.write_text(json.dumps(result, indent=2)+'\n', encoding='utf-8')
        print(json.dumps(dict(output=str(output.relative_to(ROOT)), sha256=sha(output.read_bytes()),
            functions=len(result['function_comparisons']), tables=len(result['jump_tables']))))
