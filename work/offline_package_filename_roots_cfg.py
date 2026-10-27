"""Decode the pinned saved filename converter; no process or native access."""

import argparse
import hashlib
import json
import mmap
from pathlib import Path
import struct

import capstone


CAPTURE = Path(__file__).resolve().parent / 'evidence/live-package-filename-roots-bundle-20261005-private.json'
CAPTURE_SHA = 'cb5c826b72479ef6c5583def7d2cc252d392cf4aa14dfce4ac89923cebefad4e'
PE_SHA = '4254fbe66585f260f1f9dbfc5e302887842552e7baed8939e023160a5e250be0'
SOURCE_SHA = 'a91145bea6fb87c45fe31a79d9c34ab13a26a4505f49bb402a9e86a089f7069d'
SPANS = {
    'caller': (0x10ecd110, 1024, 'a577995db5aa053db3a4aca176bd0352d104530972184f531822d1ad0ad96635'),
    'wrapper': (0x10cd47f0, 130, 'e468901e3a9e2c7c23c40ae4f453a74a621ea7c965cf6a4965b32a6919629b83'),
    'roots': (0x10ce8870, 2653, '96b0cffc40775053776d87f87f792fa2f0365f88c1427786be6f2459edcc0649'),
    'extension': (0x1e340388, 16, 'c8ff891ea453ba7ec1f4b8bc5f9325988f5f2ec202a52fe273cec5b4b082b9e5'),
}


def load_capture(path):
    path = Path(path)
    if not 0 < path.stat().st_size <= 65536:
        raise ValueError('bounded_saved_capture_required')
    raw = path.read_bytes()
    if hashlib.sha256(raw).hexdigest() != CAPTURE_SHA:
        raise ValueError('saved_capture_full_hash_changed')
    report = json.loads(raw)
    if report['native_pe_sha256'] != PE_SHA or report['source_capture_sha256'] != SOURCE_SHA:
        raise ValueError('saved_capture_source_changed')
    blocks = {'caller': report['source_code'],
              'wrapper': report['fixed_code']['PackageFilenameTransform'],
              'roots': report['fixed_code']['PackageFilenameRoots'],
              'extension': report['static_extension_header']}
    for name, (rva, size, digest) in SPANS.items():
        block = blocks[name]
        data = bytes.fromhex(block['bytes'])
        if ((block['rva'], block['size'], block['sha256']) != (rva, size, digest)
                or len(data) != size or hashlib.sha256(data).hexdigest() != digest):
            raise ValueError('saved_capture_span_changed: ' + name)
    roots = blocks['roots']
    data = bytes.fromhex(roots['bytes'])
    for chunk in roots['chunk_spans']:
        offset = chunk['rva'] - roots['rva']
        part = data[offset:offset + chunk['size']]
        if len(part) != chunk['size'] or hashlib.sha256(part).hexdigest() != chunk['sha256']:
            raise ValueError('saved_capture_chunk_changed')
    return blocks


def decode_cfg(data, rva):
    decoder = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
    decoder.detail = True
    instructions = list(decoder.disasm(data, rva))
    end = rva + len(data)
    if (not instructions or instructions[-1].address + instructions[-1].size != end
            or sum(insn.size for insn in instructions) != len(data)):
        raise ValueError('incomplete_instruction_coverage')
    by_address = {insn.address: insn for insn in instructions}
    successors = {}
    calls = []
    for insn in instructions:
        following = insn.address + insn.size
        if insn.group(capstone.CS_GRP_CALL):
            if insn.operands[0].type == capstone.x86.X86_OP_IMM:
                calls.append({'site': hex(insn.address), 'target': hex(insn.operands[0].imm),
                              'bytes': insn.bytes.hex()})
        if insn.group(capstone.CS_GRP_RET):
            edges = []
        elif insn.group(capstone.CS_GRP_JUMP):
            if insn.operands[0].type != capstone.x86.X86_OP_IMM:
                raise ValueError('unresolved_indirect_jump')
            target = insn.operands[0].imm
            edges = [target] if insn.mnemonic == 'jmp' else [target, following]
        else:
            edges = [following]
        if any(edge not in by_address for edge in edges):
            raise ValueError('branch_outside_function_or_instruction_boundary')
        successors[insn.address] = edges
    reachable = set()
    pending = [rva]
    while pending:
        address = pending.pop()
        if address in reachable:
            continue
        reachable.add(address)
        pending.extend(successors[address])
    leaders = {rva}
    for insn in instructions:
        if insn.group(capstone.CS_GRP_JUMP):
            leaders.update(successors[insn.address])
        if (insn.group(capstone.CS_GRP_RET) or insn.group(capstone.CS_GRP_JUMP)):
            following = insn.address + insn.size
            if following < end:
                leaders.add(following)
    ordered = sorted(leaders)
    blocks = []
    for number, start in enumerate(ordered):
        stop = ordered[number + 1] if number + 1 < len(ordered) else end
        members = [insn for insn in instructions if start <= insn.address < stop]
        blocks.append({'begin': hex(start), 'end_exclusive': hex(stop),
                       'successors': [hex(edge) for edge in successors[members[-1].address]],
                       'reachable': start in reachable})
    return instructions, {'begin': hex(rva), 'end_exclusive': hex(end),
                          'bytes': len(data), 'instructions': len(instructions),
                          'reachable_instructions': len(reachable),
                          'return_sites': [hex(insn.address) for insn in instructions
                                           if insn.group(capstone.CS_GRP_RET)],
                          'direct_calls': calls, 'blocks': blocks}


def read_getter_disk(path):
    import pefile

    with Path(path).open('rb') as source:
        if hashlib.file_digest(source, 'sha256').hexdigest() != PE_SHA:
            raise ValueError('original_source_executable_sha256_mismatch')
        with mmap.mmap(source.fileno(), 0, access=mmap.ACCESS_READ) as mapped:
            pe = pefile.PE(data=mapped, fast_load=True)
        def file_offset(rva, size):
            section = pe.get_section_by_rva(rva)
            if (section is None or not section.VirtualAddress <= rva
                    < rva + size <= section.VirtualAddress + section.SizeOfRawData):
                raise ValueError('target_not_in_initialized_PE_range')
            return section.PointerToRawData + rva - section.VirtualAddress

        directory = pe.OPTIONAL_HEADER.DATA_DIRECTORY[3]
        if directory.Size % 12 or not directory.Size:
            raise ValueError('invalid_exception_directory')
        count = directory.Size // 12
        target = 0x10ccc040
        low, high = 0, count
        found = None
        while low < high:
            index = (low + high) // 2
            offset = file_offset(directory.VirtualAddress + index * 12, 12)
            source.seek(offset)
            row = source.read(12)
            begin, end, unwind = struct.unpack('<III', row)
            if target < begin:
                high = index
            elif target >= end:
                low = index + 1
            else:
                found = (offset, row, begin, end, unwind)
                break
        if found is None or found[2] != target or not 0 < found[3] - target <= 16384:
            raise ValueError('exact_bounded_getter_extent_required')
        offset, row, begin, end, unwind = found
        unwind_offset = file_offset(unwind, 4)
        source.seek(unwind_offset)
        unwind_header = source.read(4)
        flags = unwind_header[0] >> 3
        unwind_size = 4 + ((unwind_header[2] + 1) // 2) * 4
        if flags & 4:
            unwind_size += 12
        elif flags & 3:
            unwind_size += 4
        source.seek(unwind_offset)
        unwind_bytes = source.read(unwind_size)
        file_offset(unwind, unwind_size)
        code_offset = file_offset(begin, end - begin)
        source.seek(code_offset)
        code = source.read(end - begin)
    result = {'native_pe_sha256': PE_SHA, 'begin_rva': begin, 'end_exclusive_rva': end,
              'size': end - begin, 'file_offset': code_offset, 'bytes': code.hex(),
              'sha256': hashlib.sha256(code).hexdigest(),
              'pdata_file_offset': offset, 'pdata_bytes': row.hex(),
              'pdata_sha256': hashlib.sha256(row).hexdigest(),
              'unwind_rva': unwind, 'unwind_file_offset': unwind_offset,
              'unwind_bytes': unwind_bytes.hex(),
              'unwind_sha256': hashlib.sha256(unwind_bytes).hexdigest()}
    try:
        insns, cfg = decode_cfg(code, begin)
        result['instruction_coverage_complete'] = True
        result['cfg'] = cfg
        result['disassembly'] = [f'{insn.address:08x} {insn.bytes.hex()} {insn.mnemonic} {insn.op_str}'
                                 for insn in insns]
    except ValueError as error:
        result['instruction_coverage_complete'] = False
        result['disk_decode_error'] = str(error)
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--capture', type=Path, default=CAPTURE)
    parser.add_argument('--start', type=lambda value: int(value, 0))
    parser.add_argument('--end', type=lambda value: int(value, 0))
    parser.add_argument('--disassembly', action='store_true')
    parser.add_argument('--getter-disk', type=Path)
    args = parser.parse_args()
    block = load_capture(args.capture)['roots']
    if args.getter_disk is not None:
        print(json.dumps(read_getter_disk(args.getter_disk), indent=2))
        return
    instructions, cfg = decode_cfg(bytes.fromhex(block['bytes']), block['rva'])
    if args.disassembly:
        print('\n'.join(f'{insn.address:08x} {insn.bytes.hex():24s} {insn.mnemonic} {insn.op_str}'
                        for insn in instructions if (args.start is None or insn.address >= args.start)
                        and (args.end is None or insn.address < args.end)))
    else:
        print(json.dumps(cfg, indent=2))


if __name__ == '__main__':
    main()
