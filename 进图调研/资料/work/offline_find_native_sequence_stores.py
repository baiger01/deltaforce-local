"""Locate exact sequence stores in the already identified connection neighborhood."""
import argparse
import json
import mmap
import struct

from capstone import Cs, CS_ARCH_X86, CS_MODE_64
from capstone.x86_const import X86_OP_MEM
from offline_received_packet_xrefs import CLIENT, ROOT, ImmutableImage, validated_range, sha
import offline_native_code_cache as cache


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--cache', required=True)
    parser.add_argument('--manifest-sha256', required=True)
    args = parser.parse_args()
    first, amount = 0x12b80000, 0x20000
    code = validated_range(args.cache, first, amount, args.manifest_sha256)
    cs = Cs(CS_ARCH_X86, CS_MODE_64)
    cs.detail = True
    targets, rows, seen = (0x14cc, 0x14d0), [], set()
    with CLIENT.open('rb') as stream, mmap.mmap(stream.fileno(), 0, access=mmap.ACCESS_READ) as mapped:
        image = ImmutableImage(mapped)
        for field in targets:
            needle, cursor = struct.pack('<i', field), 0
            while True:
                hit = code.find(needle, cursor)
                if hit < 0:
                    break
                cursor = hit + 1
                for prefix in range(2, 6):
                    start = hit - prefix
                    if start < 0:
                        continue
                    inst = next(cs.disasm(code[start:start + 15], first + start, count=1), None)
                    if (inst is None or inst.address in seen or not inst.operands or
                            inst.operands[0].type != X86_OP_MEM or inst.operands[0].mem.disp != field or
                            inst.mnemonic not in ('mov', 'inc', 'add', 'sub', 'and', 'or')):
                        continue
                    row = image.containing(inst.address)
                    if row is None:
                        continue
                    body = validated_range(args.cache, row[0], row[1] - row[0], args.manifest_sha256)
                    boundaries = {x.address for x in cs.disasm(body, row[0])}
                    if inst.address not in boundaries:
                        continue
                    seen.add(inst.address)
                    root = row
                    meta = image.unwind(root)
                    while meta['unwind_flags'] & 4:
                        root = tuple(int(v, 16) for v in meta['chained_entry'])
                        meta = image.unwind(root)
                    rows.append({'instruction_rva': hex(inst.address), 'field': hex(field),
                                 'instruction': inst.mnemonic + ' ' + inst.op_str,
                                 'operand0_base': inst.reg_name(inst.operands[0].mem.base),
                                 'operand0_bytes': inst.operands[0].size,
                                 'code_bytes_hex': bytes(inst.bytes).hex(),
                                 'pdata_fragment_begin': hex(row[0]), 'pdata_root_begin': hex(root[0]),
                                 'fragment_sha256': sha(body), 'native_boundary_verified': True})
    out = ROOT / 'work/evidence/native-sequence-initialization-store-candidates.json'
    result = {'kind': 'bounded_exact_native_connection_sequence_stores',
              'manifest_sha256': args.manifest_sha256,
              'scope_begin': hex(first), 'scope_end_exclusive': hex(first + amount),
              'scope_bytes': amount, 'exact_memory_displacements': [hex(x) for x in targets],
              'process_accessed': False, 'native_initialization_semantics_claimed': False,
              'stores': sorted(rows, key=lambda r: int(r['instruction_rva'], 16))}
    out.write_text(json.dumps(result, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')
    print(json.dumps({'evidence': out.name, 'sha256': sha(out.read_bytes()), 'stores': result['stores']}))


if __name__ == '__main__':
    main()
