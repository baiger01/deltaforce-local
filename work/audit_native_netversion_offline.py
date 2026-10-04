"""Narrow offline references to source-known conn+1528 and its default getter."""
import hashlib
import json
import mmap
from pathlib import Path
import re
import struct

import capstone
from capstone.x86 import X86_OP_MEM, X86_REG_RIP
from locate_native_connection_writer import Cache, Image, root_for_instruction, reachable_instructions

BASE = Path(__file__).resolve().parent.parent
SOURCE_SHA = '4254fbe66585f260f1f9dbfc5e302887842552e7baed8939e023160a5e250be0'
MANIFEST_SHA = '0dc6c0bb1c4ac55f437f07fde93ac2575425d008892e1ff6e6cac9385e4568cf'
GLOBAL = 0x1d59de4c
FIELD = b'\x28\x15\x00\x00'


def fixed_large_root(image, rva):
    """Only the exact Hello log owner, offline; no live collector bound change."""
    if rva != 0x130f29d0:
        raise ValueError('Only the independently anchored Hello owner is allowed')
    lo, hi = 0, image.unwind_count
    while lo < hi:
        mid = (lo + hi) // 2
        if image.unwind_entry(mid)[0] < rva:
            lo = mid + 1
        else:
            hi = mid
    root = image.unwind_entry(lo)
    if root != (0x130f29d0, 0x130f5c5c, 0x1c8b2be0):
        raise ValueError('Exact Hello owner immutable unwind record changed')
    head = image.data(root[2], 4)
    if head[0] & 7 != 1 or head[0] >> 3 & 4:
        raise ValueError('Known Hello owner is not a root')
    end, accepted, fragments = root[1], {root}, [root[:2]]
    for index in range(lo + 1, min(image.unwind_count, lo + 32)):
        item = image.unwind_entry(index)
        if item[0] != end:
            break
        header = image.data(item[2], 4)
        if header[0] & 7 != 1 or header[0] >> 3 != 4:
            break
        parent = struct.unpack('<III', image.data(item[2] + 4 + 4*((header[2]+1)//2), 12))
        if parent not in accepted:
            break
        if item[1] > rva + 16384:
            raise ValueError('Exact offline Hello scope exceeds16384')
        accepted.add(item)
        fragments.append(item[:2])
        end = item[1]
    if end - rva > 16384 or not image.executable(rva, end - rva):
        raise ValueError('Offline Hello code boundary invalid')
    return root, end - rva, fragments


def extract_fixed_hello(cache, image):
    root, length, fragments = fixed_large_root(image, 0x130f29d0)
    code = cache.read(root[0], length)
    decoded, limitations = reachable_instructions(code, root[0])
    target = 0x130f37dc
    # Switch targets require table verification before they can be evidence.
    directory = BASE / 'work/evidence/native-netversion-offline'
    directory.mkdir(exist_ok=True)
    stem = directory / 'hello_version_log_root_130f29d0'
    payload = struct.pack('<4Q', 0x145444344, root[0], len(code), image.base) + code
    stem.with_suffix('.dfcode').write_bytes(payload)
    stem.with_suffix('.asm.txt').write_text('\n'.join(f'{item.address:08x} {item.bytes.hex()} {item.mnemonic} {item.op_str}' for item in sorted(decoded.values(), key=lambda item: item.address)) + '\n', encoding='utf-8')
    result = {'root': list(map(hex, root)), 'fragments': [list(map(hex, item)) for item in fragments],
              'code_bytes': len(code), 'code_sha256': hashlib.sha256(code).hexdigest(),
              'file_sha256': hashlib.sha256(payload).hexdigest(), 'cfg_limitations': limitations,
              'exact_log_reference_rva': hex(target), 'exact_log_target_rva': '0x1b29a040',
              'log_reference_direct_CFG_boundary': target in decoded,
              'all_direct_field_1528_references': [hex(item.address)+': '+item.mnemonic+' '+item.op_str for item in decoded.values() if any(op.type == X86_OP_MEM and op.mem.disp == 0x1528 for op in item.operands)],
              'process_accessed': False, 'live_collector_limits_changed': False}
    table_rva = 0x130f5c14
    md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
    md.detail = True
    linear = list(md.disasm(code[:table_rva-root[0]], root[0]))
    instructions = {item.address: item for item in linear}
    dispatch = {0x130f36cb: '83f811', 0x130f36ce: '0f8722250000',
                0x130f36d4: '488d1525c9f0ec', 0x130f36db: '8b8c82145c0f13',
                0x130f36e2: '4803ca', 0x130f36e5: 'ffe1'}
    if (sum(item.size for item in linear) != table_rva-root[0] or
            any(addr not in instructions or instructions[addr].bytes.hex() != expected for addr, expected in dispatch.items())):
        raise ValueError('Exact bounded Hello switch dataflow changed')
    table = code[table_rva-root[0]:table_rva-root[0]+72]
    if len(table) != 72 or table_rva+72 != root[0]+length:
        raise ValueError('Exact switch table extent changed')
    targets = struct.unpack('<18I', table)
    if any(addr not in instructions for addr in targets) or targets[0] != 0x130f36e7:
        raise ValueError('Hello switch enters invalid native boundaries')
    pending, visited = [targets[0]], set()
    while pending:
        addr = pending.pop()
        if addr in visited or not root[0] <= addr < table_rva:
            continue
        if addr not in instructions:
            raise ValueError('Hello CFG enters an instruction body')
        item = instructions[addr]
        visited.add(addr)
        if item.group(capstone.CS_GRP_RET) or item.mnemonic in ('int3', 'ud2'):
            continue
        if item.group(capstone.CS_GRP_JUMP):
            if len(item.operands) != 1 or item.operands[0].type != capstone.x86.X86_OP_IMM:
                raise ValueError('Unverified extra Hello indirect branch')
            pending.append(item.operands[0].imm)
            if item.mnemonic != 'jmp':
                pending.append(addr+item.size)
        else:
            pending.append(addr+item.size)
    if target not in visited:
        raise ValueError('Exact Hello version log is not ID0 reachable')
    result['switch_table'] = {'rva': hex(table_rva), 'bytes': 72, 'sha256': hashlib.sha256(table).hexdigest(),
                              'u8_id_bound': 17, 'targets': list(map(hex, targets)),
                              'all_targets_on_native_instruction_boundaries': True, 'id0_target': hex(targets[0])}
    result['hello_id0_CFG_instruction_count'] = len(visited)
    result['hello_id0_has_no_indirect_jump'] = True
    result['hello_log_id0_reachability_verified'] = True
    result['hello_id0_field_1528_references'] = [hex(item.address) for item in linear if item.address in visited and any(op.type == X86_OP_MEM and op.mem.disp == 0x1528 for op in item.operands)]
    result['hello_id0_direct_calls'] = [[hex(item.address), hex(item.operands[0].imm)] for item in linear if item.address in visited and item.mnemonic == 'call' and item.operands[0].type == capstone.x86.X86_OP_IMM]
    (directory/'hello_id0_verified_cfg.asm.txt').write_text('\n'.join(f'{item.address:08x} {item.bytes.hex()} {item.mnemonic} {item.op_str}' for item in linear if item.address in visited)+'\n', encoding='utf-8')
    (directory/'hello_owner_complete_linear.asm.txt').write_text('\n'.join(f'{item.address:08x} {item.bytes.hex()} {item.mnemonic} {item.op_str}' for item in linear)+'\n', encoding='utf-8')
    stem.with_suffix('.source.json').write_text(json.dumps(result, indent=2)+'\n', encoding='utf-8')
    print('HELLO', json.dumps(result))


def main():
    mf = BASE / 'work/native-code-cache/1790902501634810000/manifest.json'
    manifest = json.loads(mf.read_text(encoding='utf-8'))
    cache = Cache(mf.parent, manifest['plan'])
    if cache.manifest_sha != MANIFEST_SHA:
        raise ValueError('Exact cache manifest changed')
    executable = Path('D:/三角洲/WeGameApps/rail_apps/DeltaForce(2001918)') / manifest['plan']['client_relative_to_game_root']
    md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
    md.detail = True
    candidates, global_refs, occurrences = {}, {}, 0
    tail, last = b'', None
    rip_pattern = re.compile(rb'[\x8b\x89\x8d\xc7\xc6\x81\x83\x3b\x39\x85\xf7][\x05\x0d\x15\x1d\x25\x2d\x35\x3d].{4}', re.S)
    for row in cache.blocks:
        data = cache.block(row)
        previous = tail if last == row[0] else b''
        part, start = previous + data, row[0] - len(previous)
        for match in re.finditer(re.escape(FIELD), part):
            occurrences += 1
            if occurrences > 2048:
                raise ValueError('Field byte candidate cap exceeded')
            pos = match.start()
            for at in range(max(0, pos - 12), pos):
                ins = next(md.disasm(part[at:at + 15], start + at, count=1), None)
                if ins and any(o.type == X86_OP_MEM and o.mem.disp == 0x1528 for o in ins.operands):
                    candidates[ins.address] = ins
        for match in rip_pattern.finditer(part):
            at = match.start()
            disp = struct.unpack_from('<i', part, at + 2)[0]
            if start + at + 6 + disp not in (GLOBAL, GLOBAL - 1, GLOBAL - 4):
                continue
            for iat in (at, max(0, at - 1)):
                ins = next(md.disasm(part[iat:iat + 15], start + iat, count=1), None)
                if ins and any(o.type == X86_OP_MEM and o.mem.base == X86_REG_RIP and ins.address + ins.size + o.mem.disp == GLOBAL for o in ins.operands):
                    global_refs[ins.address] = ins
        tail, last = data[-16:], row[0] + row[1]
    with executable.open('rb') as stream, mmap.mmap(stream.fileno(), 0, access=mmap.ACCESS_READ) as raw:
        if hashlib.sha256(raw).hexdigest() != SOURCE_SHA:
            raise ValueError('Immutable Shipping source changed')
        image, roots = Image(raw), {}
        extract_fixed_hello(cache, image)
        result = {'kind': 'offline_exact_connection_engine_net_version_references', 'manifest_sha256': MANIFEST_SHA,
                  'client_sha256': SOURCE_SHA, 'connection_field_offset': '0x1528', 'getter_rva': '0x10b04350',
                  'getter_native_bytes': cache.read(0x10b04350, 7).hex(), 'global_rva': hex(GLOBAL),
                  'disk_initial_u32': struct.unpack('<I', image.data(GLOBAL, 4))[0],
                  'raw_field_displacement_occurrences': occurrences, 'field_candidates': [], 'global_candidates': [],
                  'process_accessed': False, 'runtime_global_or_instance_value_read': False}
        for name, group in (('field_candidates', candidates), ('global_candidates', global_refs)):
            for addr, ins in sorted(group.items()):
                record = {'rva': hex(addr), 'bytes': ins.bytes.hex(), 'instruction': ins.mnemonic + ' ' + ins.op_str, 'root_reachable': False}
                try:
                    root, length, fragments = root_for_instruction(image, addr)
                    if length > 65536:
                        raise ValueError('Offline root scope exceeds65536')
                    if root[0] not in roots:
                        code = cache.read(root[0], length)
                        decoded, limitations = reachable_instructions(code, root[0])
                        roots[root[0]] = (code, decoded, limitations, fragments)
                    code, decoded, limitations, fragments = roots[root[0]]
                    record.update(root=hex(root[0]), root_bytes=length, root_code_sha256=hashlib.sha256(code).hexdigest(),
                                  root_reachable=addr in decoded and bytes(decoded[addr].bytes) == bytes(ins.bytes))
                    if record['root_reachable']:
                        ordered = sorted(decoded.values(), key=lambda item: item.address)
                        index = next(i for i, item in enumerate(ordered) if item.address == addr)
                        record['context'] = [hex(item.address) + ': ' + item.mnemonic + ' ' + item.op_str for item in ordered[max(0, index - 4):index + 5]]
                    else:
                        record['reason'] = 'not_at_direct_CFG_boundary; indirect tables not followed'
                except ValueError as error:
                    record['reason'] = str(error)
                result[name].append(record)
        result['global_direct_rip_scan_scope'] = 'Specified opcode+RIP operand set only; does not enumerate indirect global pointer writes'
        result['all_file_backed_executable_chunks_sha_verified'] = True
        path = BASE / 'work/evidence/native-netversion-exact-references.json'
        path.write_text(json.dumps(result, indent=2) + '\n', encoding='utf-8')
        print('SAVED', path.name, hashlib.sha256(path.read_bytes()).hexdigest())
        for name in ('field_candidates', 'global_candidates'):
            print(name, len(result[name]))
            for record in result[name]:
                if record['root_reachable']:
                    print(json.dumps(record))


if __name__ == '__main__':
    main()
