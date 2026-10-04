"""Dump exact immutable pdata code fragments from the validated private cache."""
import argparse
import hashlib
import json
import mmap
from pathlib import Path
import struct

from capstone import Cs, CS_ARCH_X86, CS_MODE_64
from offline_received_packet_xrefs import CLIENT, ROOT, SOURCE_SHA, ImmutableImage, validated_range, sha
import offline_native_code_cache as cache


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--cache', type=Path, required=True)
    parser.add_argument('--manifest-sha256', required=True)
    parser.add_argument('--rva', type=lambda s: int(s, 0), action='append', required=True)
    parser.add_argument('--out', type=Path, required=True)
    args = parser.parse_args()
    out = args.out.resolve()
    if out.parent != (ROOT / 'work/evidence').resolve() or not 0 < len(args.rva) <= 32:
        raise ValueError('Bounded private offline roots only')
    folder, manifest, manifest_sha = cache.validate_manifest(args.cache, args.manifest_sha256)
    if not manifest['complete']:
        raise ValueError('Incomplete native cache')
    with CLIENT.open('rb') as stream:
        if hashlib.file_digest(stream, 'sha256').hexdigest() != SOURCE_SHA:
            raise ValueError('Immutable PE identity mismatch')
    result = {'kind': 'immutable_pdata_private_cache_exact_roots', 'client_sha256': SOURCE_SHA,
              'manifest_sha256': manifest_sha, 'roots': [], 'process_accessed': False,
              'live_object_read': False, 'game_launched': False, 'native_acceptance': False}
    disassembler = Cs(CS_ARCH_X86, CS_MODE_64)
    seen = set()
    with CLIENT.open('rb') as stream, mmap.mmap(stream.fileno(), 0, access=mmap.ACCESS_READ) as mapped:
        image = ImmutableImage(mapped)
        for requested in args.rva:
            row = image.containing(requested)
            if row is None:
                result['roots'].append({'requested_rva': hex(requested), 'status': 'no_containing_pdata'})
                continue
            while row:
                if row in seen:
                    break
                seen.add(row)
                root = image.unwind(row)
                if not 0 < root['bytes'] <= 65536:
                    raise ValueError('Exact root exceeds65536-byte budget')
                code = validated_range(folder, row[0], root['bytes'], manifest_sha)
                instructions = list(disassembler.disasm(code, row[0]))
                stem = out.stem + '.' + hex(row[0])[2:]
                code_path, asm_path = out.with_name(stem + '.dfcode'), out.with_name(stem + '.asm.txt')
                file_bytes = struct.pack('<4sIQQQ', b'DCDE', 1, row[0], len(code), image.image_base) + code
                code_path.write_bytes(file_bytes)
                asm = ('\n'.join(f'0x{i.address:x}: {i.mnemonic} {i.op_str}' for i in instructions) + '\n').encode('utf-8')
                asm_path.write_bytes(asm)
                root.update(requested_rva=hex(requested), code_sha256=sha(code), file_sha256=sha(file_bytes),
                            code_relative_path=code_path.relative_to(ROOT).as_posix(),
                            asm_relative_path=asm_path.relative_to(ROOT).as_posix(), asm_sha256=sha(asm),
                            decoded_instruction_count=len(instructions),
                            linear_disassembly_covers_entire_pdata=bool(instructions) and
                            instructions[-1].address + instructions[-1].size == row[1])
                result['roots'].append(root)
                if root['unwind_flags'] & 4:
                    row = tuple(int(v, 16) for v in root['chained_entry'])
                    if row not in image.entries:
                        raise ValueError('Chained immutable runtime-function entry not in pdata')
                else:
                    row = None
    cache.validate_manifest(folder, manifest_sha)
    out.write_text(json.dumps(result, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')
    print(json.dumps({'evidence': out.name, 'sha256': sha(out.read_bytes()),
                      'roots': [{'begin': x.get('begin'), 'bytes': x.get('bytes'),
                                 'code_sha256': x.get('code_sha256')} for x in result['roots']]}))


if __name__ == '__main__':
    main()
