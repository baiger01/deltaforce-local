"""Bounded offline analysis of exact weak-reference registry helpers."""
import hashlib
import json
import mmap
from pathlib import Path
import struct

from capstone import Cs, CS_ARCH_X86, CS_MODE_64
from offline_received_packet_xrefs import (
    CLIENT, ROOT, SOURCE_SHA, ImmutableImage, validated_range, literal_candidates,
)

PIN = '0dc6c0bb1c4ac55f437f07fde93ac2575425d008892e1ff6e6cac9385e4568cf'
CACHE = ROOT / 'work/native-code-cache/1790902501634810000'
OUT = ROOT / 'work/evidence'


def sha(data):
    return hashlib.sha256(data).hexdigest()


def main():
    with CLIENT.open('rb') as stream:
        if hashlib.file_digest(stream, 'sha256').hexdigest() != SOURCE_SHA:
            raise ValueError('Immutable source mismatch')
    dis = Cs(CS_ARCH_X86, CS_MODE_64)
    result = {
        'kind': 'exact_call_target_internal_split_helpers',
        'cache_manifest_sha256': PIN, 'client_sha256': SOURCE_SHA,
        'roots': [], 'bounded_global_xrefs': [],
        'process_accessed': False, 'game_launched': False,
    }
    with CLIENT.open('rb') as stream, mmap.mmap(
        stream.fileno(), 0, access=mmap.ACCESS_READ
    ) as mapped:
        image = ImmutableImage(mapped)
        for begin, end, table in (
            (0xd60500, 0xd60b3c, 0xd60b14),
            (0xd60d00, 0xd6136c, 0xd61344),
        ):
            code = validated_range(CACHE, begin, end - begin, PIN)
            stem = OUT / ('native-object-registry-split-helper.' + hex(begin)[2:])
            payload, table_bytes = code[:table-begin], code[table-begin:]
            if len(table_bytes) != 40:
                raise ValueError('Expected exact ten DWORD table')
            targets = struct.unpack('<10I', table_bytes)
            if not all(begin <= target < table for target in targets):
                raise ValueError('Dispatch branch outside fixed source interval')
            instructions = list(dis.disasm(payload, begin))
            asm = '\n'.join(
                f'0x{i.address:x}: {i.mnemonic} {i.op_str}' for i in instructions
            ) + '\n'
            blob = struct.pack(
                '<4sIQQQ', b'DCDE', 1, begin, len(code), image.image_base
            ) + code
            code_path = Path(str(stem) + '.dfcode')
            asm_path = Path(str(stem) + '.asm.txt')
            code_path.write_bytes(blob)
            asm_path.write_bytes(asm.encode('utf-8'))
            result['roots'].append({
                'begin': hex(begin), 'end_exclusive': hex(end), 'bytes': len(code),
                'boundary_basis': 'Exact E8 target through its indexed ten-DWORD table; no pdata; table excluded from instruction decode',
                'code_sha256': sha(code), 'file_sha256': sha(blob),
                'asm_sha256': sha(asm.encode()),
                'dispatch_table_rva': hex(table),
                'dispatch_table_sha256': sha(table_bytes),
                'table_targets': [hex(target) for target in targets],
                'code_relative_path': code_path.relative_to(ROOT).as_posix(),
                'asm_relative_path': asm_path.relative_to(ROOT).as_posix(),
            })
        for begin, length in ((0x10992000, 8192), (0x10ea1600, 2048)):
            code = validated_range(CACHE, begin, length, PIN)
            targets = {0x1e34ee48, 0x1e34ee5c, 0x1e34ee68}
            hits = literal_candidates(code, begin, targets)
            entries = []
            for source, target, instruction in hits:
                row = image.containing(source)
                entries.append({
                    'source_rva': hex(source), 'target_rva': hex(target),
                    'instruction_hex': instruction.hex(),
                    'containing_pdata': [hex(v) for v in row] if row else None,
                })
            result['bounded_global_xrefs'].append({
                'range_rva': hex(begin), 'bytes': length,
                'range_sha256': sha(code), 'hits': entries,
            })
    path = OUT / 'native-object-registry-split-helper.json'
    path.write_text(json.dumps(result, indent=2) + '\n', encoding='utf-8')
    print(json.dumps({'report': path.relative_to(ROOT).as_posix(),
                      'sha256': sha(path.read_bytes()),
                      'xrefs': result['bounded_global_xrefs']}))


if __name__ == '__main__':
    main()
