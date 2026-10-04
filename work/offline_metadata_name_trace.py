"""Fixed call-edge name helper extraction from the private saved code cache."""
import argparse
import bisect
import hashlib
import json
import mmap
import struct
from pathlib import Path
from capstone import Cs, CS_ARCH_X86, CS_MODE_64
from offline_received_packet_xrefs import CLIENT, ROOT, SOURCE_SHA, ImmutableImage, validated_range, sha
import offline_native_code_cache as cache

CACHE = ROOT / 'work/native-code-cache/1790902501634810000'
MANIFEST = '0dc6c0bb1c4ac55f437f07fde93ac2575425d008892e1ff6e6cac9385e4568cf'

def extract(targets, output):
    folder, manifest, pin = cache.validate_manifest(CACHE, MANIFEST)
    if not manifest['complete']:
        raise ValueError('Incomplete saved cache')
    with CLIENT.open('rb') as stream:
        if hashlib.file_digest(stream, 'sha256').hexdigest() != SOURCE_SHA:
            raise ValueError('Immutable image SHA mismatch')
    result = {'kind': 'bounded_saved_name_call_edges', 'client_sha256': SOURCE_SHA,
              'cache_manifest_sha256': pin, 'process_accessed': False,
              'game_launched': False, 'native_called': False, 'roots': []}
    decoder = Cs(CS_ARCH_X86, CS_MODE_64)
    decoder.detail = True
    with CLIENT.open('rb') as stream, mmap.mmap(stream.fileno(), 0, access=mmap.ACCESS_READ) as raw:
        image = ImmutableImage(raw)
        for target in targets:
            row = image.containing(target)
            if not row or row[0] != target or image.unwind(row)['unwind_flags'] & 4:
                raise ValueError('Target not exact independent root')
            rows = [row]
            accepted = {row}
            index = bisect.bisect_left(image.begins, target) + 1
            for candidate in image.entries[index:index + 32]:
                if candidate[0] != rows[-1][1]:
                    break
                metadata = image.unwind(candidate)
                if metadata['unwind_flags'] != 4 or tuple(int(x, 16) for x in metadata['chained_entry']) not in accepted:
                    break
                if len(rows) >= 32:
                    raise ValueError('Fragment budget exceeded')
                rows.append(candidate)
                accepted.add(candidate)
            length = rows[-1][1] - target
            if not 0 < length <= 8192:
                raise ValueError('Root byte budget exceeded')
            code = validated_range(folder, target, length, pin)
            instructions = list(decoder.disasm(code, target))
            complete = sum(i.size for i in instructions) == length
            binary = struct.pack('<4sIQQQ', b'DCDE', 1, target, length, image.image_base) + code
            stem = output.with_name(output.stem + '.' + hex(target)[2:])
            binary_path = Path(str(stem) + '.dfcode')
            asm_path = Path(str(stem) + '.asm.txt')
            asm = ('\n'.join(f'0x{i.address:x}: {i.mnemonic} {i.op_str}' for i in instructions) + '\n').encode()
            binary_path.write_bytes(binary)
            asm_path.write_bytes(asm)
            result['roots'].append({'begin': hex(target), 'end_exclusive': hex(target + length),
                'bytes': length, 'fragments': [image.unwind(x) for x in rows],
                'full_linear_decode': complete, 'instruction_count': len(instructions),
                'code_sha256': sha(code), 'file_sha256': sha(binary), 'asm_sha256': sha(asm),
                'code_relative_path': binary_path.relative_to(ROOT).as_posix(),
                'asm_relative_path': asm_path.relative_to(ROOT).as_posix()})
    cache.validate_manifest(folder, pin)
    output.write_text(json.dumps(result, indent=2) + '\n', encoding='utf-8')
    print(json.dumps({'evidence': output.name, 'sha256': sha(output.read_bytes()),
                     'roots': [{k: r[k] for k in ('begin', 'bytes', 'full_linear_decode')} for r in result['roots']]}))

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--rva', action='append', type=lambda x: int(x, 0), required=True)
    parser.add_argument('--out', type=Path, required=True)
    args = parser.parse_args()
    output = args.out.resolve()
    if output.parent != (ROOT / 'work/evidence').resolve() or not 0 < len(args.rva) <= 12:
        raise ValueError('Only a bounded private evidence file is allowed')
    extract(args.rva, output)
