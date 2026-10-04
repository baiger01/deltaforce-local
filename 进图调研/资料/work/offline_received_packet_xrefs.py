"""Exact receive-log RIP references in a bounded, validated private code cache.

Disk/cache-only. This tool has no launch, process, or elevation API. A log xref
establishes a code role, not a working receiver or an accepted native packet.
"""
import argparse
from bisect import bisect_right
import hashlib
import json
import mmap
from pathlib import Path
import re
import struct

from capstone import Cs, CS_ARCH_X86, CS_MODE_64
from capstone.x86_const import X86_OP_MEM, X86_REG_RIP
import offline_native_code_cache as cache

ROOT = Path(__file__).resolve().parent.parent
CLIENT = Path('D:/个人工作区/DeltaForce-local-client/DeltaForce/Binaries/Win64/DeltaForceClient-Win64-Shipping.exe')
SOURCE_SHA = cache.SOURCE_SHA
ANCHORS = {
    0x1B1D96F0: (256, '0d723824cdaf2a5ee2aa714cef9a0afc904304dd444849a136217be7d1dd0293'),
    0x1B1D9080: (138, 'c21ea86e9a3114b75a3319f2a2c677566662ebdcbb08b1542fd15469976d070e'),
    0x1B1D9110: (154, 'e9d39320c7c38f587fd7d257bd2d9c8f7a715014d4d9fe3e3a305b9a9031ad69'),
    0x1B1D7890: (80, 'ae126aecb1af8bcf7cffc321c01597cb96dfbe4ed021151182f925343d3dab2f'),
    0x1B1D78E0: (96, 'a79ade6616fc682d2d91f78418657527d0f6d4317b35e1c2d7e3875aff33b882'),
}
# Only LEA/MOV RIP forms used to obtain exact immutable literal pointers. This
# does not claim exhaustive instruction coverage. Decoding happens only at hits.
RIP_POINTER = re.compile(rb'[\x40-\x4f][\x8d\x8b][\x05\x0d\x15\x1d\x25\x2d\x35\x3d]')
MAX_SEARCH_BYTES = 0x80000
MAX_FUNCTION_BYTES = 0x10000


def sha(data):
    return hashlib.sha256(data).hexdigest()


def literal_candidates(data, first_rva, targets):
    result = []
    for match in RIP_POINTER.finditer(data):
        offset = match.start()
        if offset + 7 > len(data):
            continue
        target = first_rva + offset + 7 + struct.unpack_from('<i', data, offset + 3)[0]
        if target in targets:
            result.append((first_rva + offset, target, bytes(data[offset:offset + 7])))
    return result


class ImmutableImage:
    def __init__(self, data):
        self.data = data
        nt = struct.unpack_from('<I', data, 0x3C)[0]
        if data[nt:nt + 4] != b'PE\0\0':
            raise ValueError('Not the pinned PE image')
        optional = nt + 24
        if struct.unpack_from('<H', data, optional)[0] != 0x20B:
            raise ValueError('Expected PE32+')
        self.image_base = struct.unpack_from('<Q', data, optional + 24)[0]
        self.sections = []
        section_count = struct.unpack_from('<H', data, nt + 6)[0]
        section_table = optional + struct.unpack_from('<H', data, nt + 20)[0]
        for index in range(section_count):
            at = section_table + index * 40
            virtual_size, rva, raw_size, raw = struct.unpack_from('<IIII', data, at + 8)
            self.sections.append((rva, raw_size, raw, virtual_size))
        pdata, amount = struct.unpack_from('<II', data, optional + 112 + 3 * 8)
        if amount % 12:
            raise ValueError('Malformed immutable pdata size')
        self.entries = [struct.unpack_from('<III', self.read(pdata + offset, 12))
                        for offset in range(0, amount, 12)]
        self.begins = [row[0] for row in self.entries]
        if self.begins != sorted(self.begins):
            raise ValueError('Immutable pdata is not ordered')

    def read(self, rva, amount):
        matches = [(base, raw) for base, size, raw, _ in self.sections
                   if base <= rva < rva + amount <= base + size]
        if len(matches) != 1:
            raise ValueError('Immutable RVA is outside a unique file-backed section')
        base, raw = matches[0]
        return self.data[raw + rva - base:raw + rva - base + amount]

    def containing(self, rva):
        at = bisect_right(self.begins, rva) - 1
        if at < 0 or not self.entries[at][0] <= rva < self.entries[at][1]:
            return None
        return self.entries[at]

    def unwind(self, row):
        begin, end, unwind_rva = row
        first = self.read(unwind_rva, 4)
        flags, count = first[0] >> 3, first[2]
        amount = 4 + ((count + 1) // 2) * 4
        if flags & 4:
            amount += 12
        elif flags & 3:
            amount += 4
        metadata = self.read(unwind_rva, amount)
        result = {'begin': hex(begin), 'end_exclusive': hex(end), 'bytes': end - begin,
                  'unwind_rva': hex(unwind_rva), 'unwind_flags': flags,
                  'metadata_bytes': amount, 'metadata_sha256': sha(metadata)}
        if flags & 4:
            result['chained_entry'] = [hex(v) for v in struct.unpack_from('<III', metadata, amount - 12)]
        return result


def validated_range(folder, first, amount, manifest_sha):
    return b''.join(cache.read_cached_code(folder, rva, min(8192, first + amount - rva), manifest_sha)
                    for rva in range(first, first + amount, 8192))


def exact_cache_index(folder, manifest):
    """Index fixed literal references, validating each manifest block exactly once.

    This mirrors the existing reader's path/size/hash qualification. Function
    bodies are still read via that reader. No whole-image Capstone pass occurs.
    """
    for section in manifest['sections']:
        previous = b''
        for block in section['blocks']:
            if not block['available']:
                raise ValueError('Exact receive index overlaps an unavailable interval')
            path = folder / block['file']
            amount, first = block['bytes'], int(block['rva'], 16)
            if path.resolve().parent != folder or path.stat().st_size != amount:
                raise ValueError('Cache code-block path/size mismatch')
            with path.open('rb') as stream:
                code = stream.read(amount + 1)
            if len(code) != amount or cache.sha(code) != block['code_sha256']:
                raise ValueError('Cache code-block SHA mismatch')
            yield from literal_candidates(previous + code, first - len(previous), ANCHORS)
            previous = code[-6:]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--cache', type=Path, required=True)
    parser.add_argument('--manifest-sha256', required=True)
    parser.add_argument('--start', type=lambda s: int(s, 0), default=0x12800000)
    parser.add_argument('--end', type=lambda s: int(s, 0), default=0x12880000)
    parser.add_argument('--search-all-fixed-literals', action='store_true')
    parser.add_argument('--out', type=Path, required=True)
    args = parser.parse_args()
    if not 0 < args.end - args.start <= MAX_SEARCH_BYTES:
        raise ValueError('Only one bounded receive neighborhood of at most512 KiB is supported')
    out = args.out.resolve()
    if out.parent != (ROOT / 'work/evidence').resolve():
        raise ValueError('Output must be a private work/evidence JSON file')
    folder, manifest, manifest_sha = cache.validate_manifest(args.cache, args.manifest_sha256)
    if not manifest['complete']:
        raise ValueError('Exact receive search requires complete coverage and saved sender matches')
    with CLIENT.open('rb') as stream:
        if hashlib.file_digest(stream, 'sha256').hexdigest() != SOURCE_SHA:
            raise ValueError('Immutable executable SHA mismatch')
    result = {'kind': 'bounded_exact_receive_log_native_cache_xrefs', 'client_sha256': SOURCE_SHA,
              'cache_relative_path': folder.relative_to(ROOT).as_posix(), 'manifest_sha256': manifest_sha,
              'snapshot_is_atomic': False, 'game_launched': False, 'process_accessed': False,
              'live_object_read': False, 'native_packet_accepted': False,
              'search': {'begin': hex(args.start), 'end_exclusive': hex(args.end),
                         'bytes': args.end - args.start, 'pattern_scope': 'REX LEA/MOV RIP exact literal references'},
              'anchors': [], 'xrefs': [], 'functions': []}
    disassembler = Cs(CS_ARCH_X86, CS_MODE_64)
    disassembler.detail = True
    with CLIENT.open('rb') as stream, mmap.mmap(stream.fileno(), 0, access=mmap.ACCESS_READ) as mapped:
        image = ImmutableImage(mapped)
        for rva, (amount, expected_sha) in ANCHORS.items():
            raw = image.read(rva, amount)
            if sha(raw) != expected_sha:
                raise ValueError('Immutable log anchor changed')
            result['anchors'].append({'rva': hex(rva), 'bytes': amount, 'sha256': sha(raw),
                                      'utf16': raw.decode('utf-16-le').rstrip('\0')})
        if args.search_all_fixed_literals:
            candidates = exact_cache_index(folder, manifest)
            result['search'] = {'bytes': manifest['saved_code_bytes'],
                'pattern_scope': 'five fixed literal references only; independently hashed manifest blocks',
                'whole_image_disassembly': False}
        else:
            data = validated_range(folder, args.start, args.end - args.start, manifest_sha)
            candidates = literal_candidates(data, args.start, ANCHORS)
        roots = {}
        for rva, target, raw in candidates:
            inst = next(disassembler.disasm(raw, rva, count=1), None)
            if inst is None or inst.size != len(raw) or not any(
                    op.type == X86_OP_MEM and op.mem.base == X86_REG_RIP and
                    inst.address + inst.size + op.mem.disp == target for op in inst.operands):
                continue
            row = image.containing(rva)
            result['xrefs'].append({'instruction_rva': hex(rva), 'target_literal_rva': hex(target),
                                    'instruction': f'{inst.mnemonic} {inst.op_str}',
                                    'instruction_bytes_hex': raw.hex(),
                                    'pdata_begin': hex(row[0]) if row else None})
            if row:
                roots[row[0]] = row
        for begin, row in sorted(roots.items()):
            root = image.unwind(row)
            if root['bytes'] > MAX_FUNCTION_BYTES:
                root['body_status'] = 'above_offline_function_budget'
            else:
                body = validated_range(folder, begin, root['bytes'], manifest_sha)
                instructions = list(disassembler.disasm(body, begin))
                addresses = {ins.address for ins in instructions}
                root.update(body_status='private_cache_saved_code', code_sha256=sha(body),
                            decoded_instruction_count=len(instructions),
                            linear_disassembly_covers_entire_pdata=bool(instructions) and
                                instructions[-1].address + instructions[-1].size == row[1])
                asm_path = out.with_name(out.stem + '.' + hex(begin)[2:] + '.asm.txt')
                asm = '\n'.join(f'0x{i.address:x}: {i.mnemonic} {i.op_str}' for i in instructions) + '\n'
                asm_path.write_bytes(asm.encode('utf-8'))
                root.update(asm_relative_path=asm_path.relative_to(ROOT).as_posix(), asm_sha256=sha(asm.encode('utf-8')))
                for xref in result['xrefs']:
                    if xref['pdata_begin'] == hex(begin):
                        xref['verified_root_linear_instruction_boundary'] = int(xref['instruction_rva'], 16) in addresses
            result['functions'].append(root)
    cache.validate_manifest(folder, manifest_sha)
    out.write_text(json.dumps(result, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')
    print(json.dumps({'evidence': out.name, 'sha256': sha(out.read_bytes()),
                      'exact_literal_xrefs': len(result['xrefs']), 'pdata_functions': len(result['functions'])}))


if __name__ == '__main__':
    main()
