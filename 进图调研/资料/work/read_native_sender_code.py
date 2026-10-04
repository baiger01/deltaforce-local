"""Read one typed SendBunch image-code prefix from an already running client.

The default command validates immutable files only. Explicit --collect uses
ordinary process permissions and never launches, elevates, writes memory, reads
objects/vtables, or changes the SDK. One leading E9 or a fully decoded receiver
virtual thunk may select one immutable, bounded implementation. A static-table
candidate is not proof of the current instance's table or a packet-header writer.
"""
import argparse
import ctypes as C
from datetime import datetime, timezone
import hashlib
import json
import mmap
import os
from pathlib import Path
import struct

import capstone
from capstone.x86 import (X86_OP_MEM, X86_OP_REG, X86_REG_RCX,
                          X86_REG_RAX, X86_REG_R10, X86_REG_R11)
import psutil

from capture_official_ds import SOURCE_SHA, digest, verified_pids, save
from read_named_ds_transport_code import kernel, Module, Memory
from read_native_control_code import Image, direct_e9_span

ROOT = Path(__file__).resolve().parent.parent
EXECUTABLE_RELATIVE = Path('DeltaForce/Binaries/Win64/DeltaForceClient-Win64-Shipping.exe')
FIXED_PLAN = ROOT / 'work/evidence/native-sender-bounded-read-plan.json'
FIXED_PLAN_SHA = 'b5205c3987f64a6b53d72f00bf8a83eef7aa003884a578ddcabd23e049bfcc0a'
TYPED_PLAN = ROOT / 'work/evidence/native-channel-sendbunch-typed-prefix-plan.json'
TYPED_PLAN_SHA = '4241f756bd0d6f5dd8168f56aef2ff5f14da00b6fcfd110a41822cbb171ab87d'
TABLE_EVIDENCE = ROOT / 'work/evidence/native-control-static-vtable-crosscheck.json'
TABLE_EVIDENCE_SHA = '0476fa4b8ee9ea0e517e038117af515d6ecc10edf88540d3dc024a21b8cd1f0b'
PLAN_OUTPUT = ROOT / 'work/evidence/native-sender-code-plan.json'
PREFIX_RVA, PREFIX_BYTES = 0x5bfbfd0, 32
MAX_FUNCTION_BYTES, MAX_FRAGMENTS, MAX_READS, MAX_CODE_BYTES = 8192, 32, 2, 8224
TABLE_BASE, TABLE_BYTES, MAX_SLOT = 0x167ea6c8, 672, 0x298
TABLE_SHA = '76bb687145cdab7ff6e2116771279b8c5eb05feba6aa763f6f6416481632e848'
TABLE_ANCHOR_SHA = '437f3b7f7b8776b7681b0652141dfe0f4e8bdb8eb90eccdf218b747563c22f1f'
PDATA_RVA, PDATA_BYTES = 0x1e5d1000, 15300936
PDATA_SHA = 'aae32c4f1cc7196c7a2b78a4adc4e5dae29e5a200ad7415ab2ed69f06cd70d5e'
BINDINGS = (
    ('UControlChannel.SendBunch', 0x1b3e8b60, 0x1d7a1190,
     ('UControlChannel *', 0x1b3eb790),
     'd533d587d3267db9512d7f0e0e9b95ae154f079415f2fe73fd453432539dd937'),
    ('UChannel.SendBunch', 0x1b42f110, 0x1d7a9518,
     ('UChannel *', 0x16076050),
     'a302d4e15011802a34d139f75cc2364abac92f7cc62eb01f45904b2ca1a200c2'),
)


def sealed_json(path, pin):
    if not 0 < path.stat().st_size <= 256 * 1024:
        raise ValueError('Sealed evidence file size bound exceeded')
    with path.open('rb') as stream:
        raw = stream.read(256 * 1024 + 1)
    if len(raw) > 256 * 1024 or hashlib.sha256(raw).hexdigest() != pin:
        raise ValueError('Sealed evidence file identity mismatch')
    return json.loads(raw)


def validate_table(image):
    evidence = sealed_json(TABLE_EVIDENCE, TABLE_EVIDENCE_SHA)
    if (evidence.get('client_sha256') != SOURCE_SHA or
            evidence.get('actual_client_instance_ownership_verified') is not False):
        raise ValueError('Static table evidence identity/qualification mismatch')
    row = next((r for r in evidence['tables'] if r['label'] == 'control'), None)
    if (row is None or row['candidate_vptr_base_rva'] != hex(TABLE_BASE) or
            row['immutable_table_window_file_sha256'] != TABLE_ANCHOR_SHA or
            row['84_slot_window_executable_pointer_count'] != 84):
        raise ValueError('Static Control table evidence window mismatch')
    # The previous audit sealed the preceding qword plus the 84-slot window.
    if hashlib.sha256(image.data(TABLE_BASE - 8, TABLE_BYTES + 8)).hexdigest() != TABLE_ANCHOR_SHA:
        raise ValueError('Static Control table anchor window identity mismatch')
    window = image.data(TABLE_BASE, TABLE_BYTES)
    if hashlib.sha256(window).hexdigest() != TABLE_SHA:
        raise ValueError('Static Control table window identity mismatch')
    if not any(not s.Characteristics & 0xa0000000 and
               s.VirtualAddress <= TABLE_BASE < TABLE_BASE + TABLE_BYTES <=
               s.VirtualAddress + min(s.SizeOfRawData, s.Misc_VirtualSize)
               for s in image.pe.sections):
        raise ValueError('Static Control table is not immutable nonexecutable data')
    pointers = struct.unpack('<84Q', window)
    if not all(image.executable(p - image.base) for p in pointers):
        raise ValueError('Static Control table window code-pointer mismatch')
    if (pointers[0x288 // 8] != image.base + 0x128668d0 or
            pointers[0x290 // 8] != image.base + 0x12867a00):
        raise ValueError('Static Control ReceivedBunch/NAK anchor mismatch')
    return window


def validate_image(image):
    fixed = sealed_json(FIXED_PLAN, FIXED_PLAN_SHA)
    typed = sealed_json(TYPED_PLAN, TYPED_PLAN_SHA)
    for relative, pin in fixed['guard_dependencies'].items():
        if digest(ROOT / relative) != pin:
            raise ValueError('Shared immutable guard dependency identity mismatch')
    if (hashlib.sha256(image.raw).hexdigest() != SOURCE_SHA or
            image.base != 0x140000000 or image.size != 536408064 or
            fixed['client_sha256'] != SOURCE_SHA or typed['source_sha256'] != SOURCE_SHA or
            fixed['client_relative_executable'] != EXECUTABLE_RELATIVE.as_posix() or
            fixed['source_record_rvas'] != [hex(row[1]) for row in BINDINGS] or
            fixed['prefix_rva'] != hex(PREFIX_RVA) or fixed['prefix_bytes'] != PREFIX_BYTES or
            (fixed['maximum_reads'], fixed['maximum_code_bytes']) != (MAX_READS, MAX_CODE_BYTES)):
        raise ValueError('Sender immutable source or fixed budget mismatch')
    directory = image.pe.OPTIONAL_HEADER.DATA_DIRECTORY[3]
    if (directory.VirtualAddress != PDATA_RVA or directory.Size != PDATA_BYTES or
            directory.Size % 12 or image.unwind_count != PDATA_BYTES // 12 or
            hashlib.sha256(image.data(PDATA_RVA, PDATA_BYTES)).hexdigest() != PDATA_SHA):
        raise ValueError('Sender complete pdata identity mismatch')
    bindings = []
    for label, record, arguments, first_type, record_sha in BINDINGS:
        rows = [r for r in typed['bindings'] if r['label'] == label]
        if len(rows) != 1:
            raise ValueError('Typed SendBunch source binding is not unique')
        row = rows[0]
        expected = (image.base + 0x16437b20, image.base + PREFIX_RVA,
                    image.base + 0x5b998b0, image.base + 0x164e43e0,
                    image.base + arguments, 3)
        record_bytes = image.data(record, 48)
        types = (first_type, ('FOutBunch *', 0x15768828), ('bool', 0x14ee4878))
        if (row['record_rva'] != hex(record) or row['record_sha256'] != record_sha or
                hashlib.sha256(record_bytes).hexdigest() != record_sha or
                struct.unpack('<6Q', record_bytes) != expected or
                row['six_qwords'] != [hex(v) for v in expected] or
                row['argument_table_rva'] != hex(arguments) or row['argument_count'] != 3 or
                row['arguments'] != [{'label': name, 'label_rva': hex(rva)} for name, rva in types] or
                row['return_type'] != 'FPacketIdRange' or row['code_rva'] != hex(PREFIX_RVA)):
            raise ValueError('Complete typed SendBunch six-qword signature mismatch')
        image.label(0x16437b20, 'SendBunch')
        image.label(0x164e43e0, 'FPacketIdRange')
        if struct.unpack('<3Q', image.data(arguments, 24)) != tuple(image.base + r for _, r in types):
            raise ValueError('Complete typed SendBunch argument table mismatch')
        for name, rva in types:
            image.label(rva, name)
        bindings.append({'label': label, 'record_rva': hex(record), 'record_sha256': record_sha,
                         'six_qwords': [hex(v) for v in expected],
                         'argument_types': [n for n, _ in types], 'return_type': 'FPacketIdRange'})
    if not image.executable(PREFIX_RVA, PREFIX_BYTES) or not image.executable(0x5b998b0):
        raise ValueError('Typed SendBunch prefix/invoker is outside executable image')
    validate_table(image)
    return {'kind': 'validated_single_typed_sender_prefix_plan', 'client_sha256': SOURCE_SHA,
        'client_relative_to_game_root': EXECUTABLE_RELATIVE.as_posix(),
        'fixed_plan_sha256': FIXED_PLAN_SHA, 'typed_evidence_sha256': TYPED_PLAN_SHA,
        'static_table_evidence_sha256': TABLE_EVIDENCE_SHA, 'guard_dependencies': fixed['guard_dependencies'],
        'bindings': bindings, 'initial_read_rva': hex(PREFIX_RVA), 'initial_read_bytes': PREFIX_BYTES,
        'fixed_read_count': 1, 'maximum_reads': MAX_READS, 'maximum_code_bytes': MAX_CODE_BYTES,
        'maximum_function_bytes': MAX_FUNCTION_BYTES, 'maximum_fragments_per_function': MAX_FRAGMENTS,
        'known_static_table_window_bytes': TABLE_BYTES, 'follow_policy': fixed['follow_policy'],
        'process_memory_read': False, 'client_launched': False, 'elevation_requested': False,
        'live_object_or_vtable_read': False, 'actual_instance_table_ownership_verified': False,
        'sender_header_writer_role_verified': False, 'playable_map_verified': False,
        'status': 'offline_plan_validated'}


def build_plan(game_root):
    executable = Path(game_root) / EXECUTABLE_RELATIVE
    if digest(executable) != SOURCE_SHA:
        raise ValueError('Client version hash mismatch')
    with executable.open('rb') as stream, mmap.mmap(stream.fileno(), 0, access=mmap.ACCESS_READ) as raw:
        return validate_image(Image(raw))


def virtual_slot(code):
    """Prove the first two actual instructions; never evaluate either pointer."""
    if len(code) != PREFIX_BYTES:
        raise ValueError('Sender prefix length mismatch')
    decoder = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
    decoder.detail = True
    instructions = list(decoder.disasm(code, PREFIX_RVA))
    if len(instructions) < 2 or sum(i.size for i in instructions) != PREFIX_BYTES:
        raise ValueError('Virtual sender prefix does not fully decode')
    load, jump = instructions[:2]
    if (load.address != PREFIX_RVA or load.mnemonic != 'mov' or len(load.operands) != 2 or
            load.operands[0].type != X86_OP_REG or load.operands[0].size != 8 or
            load.operands[0].reg not in (X86_REG_RAX, X86_REG_R10, X86_REG_R11) or
            load.operands[1].type != X86_OP_MEM or load.operands[1].size != 8 or
            load.operands[1].mem.base != X86_REG_RCX or load.operands[1].mem.index != 0 or
            load.operands[1].mem.disp != 0 or load.operands[1].mem.segment != 0 or
            jump.address != load.address + load.size or jump.mnemonic != 'jmp' or
            len(jump.operands) != 1 or jump.operands[0].type != X86_OP_MEM or
            jump.operands[0].size != 8 or jump.operands[0].mem.base != load.operands[0].reg or
            jump.operands[0].mem.index != 0 or jump.operands[0].mem.segment != 0):
        raise ValueError('Sender prefix is not an exact unchanged-RCX virtual tail thunk')
    slot = jump.operands[0].mem.disp
    if slot < 0 or slot % 8 or slot > MAX_SLOT:
        raise ValueError('Measured virtual slot is outside the audited aligned static window')
    return slot, bytes(load.bytes + jump.bytes).hex()


def metadata_span(image, target):
    root, length, fragments = image.function_span(target)
    if (root[0] != target or type(length) is not int or not 0 < length <= MAX_FUNCTION_BYTES or
            not 1 <= len(fragments) <= MAX_FRAGMENTS or fragments[0] != root[:2] or
            fragments[-1][1] - target != length or not image.executable(target, length)):
        raise ValueError('Sender target does not have a complete bounded same-root span')
    accepted, metadata, previous_end = set(), [], target
    for begin, end in fragments:
        low, high = 0, image.unwind_count
        while low < high:
            middle = (low + high) // 2
            if image.unwind_entry(middle)[0] < begin:
                low = middle + 1
            else:
                high = middle
        if low >= image.unwind_count:
            raise ValueError('Sender fragment has no exact immutable pdata record')
        triple = image.unwind_entry(low)
        if triple[:2] != (begin, end) or begin != previous_end or not begin < end <= target + length:
            raise ValueError('Sender function fragments are not exact and contiguous')
        header = image.data(triple[2], 4)
        version, flags, count = header[0] & 7, header[0] >> 3, header[2]
        if version != 1 or (not accepted and flags not in (0, 1, 2, 3)) or (accepted and flags != 4):
            raise ValueError('Sender fragment unwind version/flags mismatch')
        size = 4 + 4 * ((count + 1) // 2) + (12 if flags == 4 else 4 if flags else 0)
        data = image.data(triple[2], size)
        parent = struct.unpack_from('<III', data, size - 12) if flags == 4 else None
        if parent is not None and parent not in accepted:
            raise ValueError('Sender fragment chains outside its accepted same-root function')
        metadata.append({'entry': [hex(x) for x in triple], 'metadata_bytes': size,
                         'metadata_sha256': hashlib.sha256(data).hexdigest(),
                         'chain_parent': None if parent is None else [hex(x) for x in parent]})
        accepted.add(triple)
        previous_end = end
    return {'target_rva': hex(target), 'code_bytes': length, 'unwind_root': [hex(x) for x in root],
            'unwind_fragments': [[hex(a), hex(b)] for a, b in fragments], 'unwind_metadata': metadata}


def select_follow(image, code):
    if len(code) != PREFIX_BYTES:
        raise ValueError('Sender prefix length mismatch')
    if code[0] == 0xe9:
        target, _, _, _ = direct_e9_span(image, PREFIX_RVA, code)
        evidence = metadata_span(image, target)
        evidence.update(route='leading_direct_E9', source_instruction_hex=code[:5].hex())
    else:
        slot, instructions = virtual_slot(code)
        window = validate_table(image)
        target = struct.unpack_from('<Q', window, slot)[0] - image.base
        if PREFIX_RVA <= target < PREFIX_RVA + PREFIX_BYTES:
            raise ValueError('Static target loops into its named prefix')
        evidence = metadata_span(image, target)
        evidence.update(route='receiver_virtual_thunk_static_table_candidate',
                        source_instruction_hex=instructions, measured_slot_offset=hex(slot),
                        immutable_table_pointer_rva=hex(TABLE_BASE + slot),
                        actual_instance_table_ownership_verified=False)
    evidence.update(source_prefix_rva=hex(PREFIX_RVA), source_prefix_code_sha256=hashlib.sha256(code).hexdigest(),
                    recursive_follow=False, sender_header_writer_role_verified=False)
    return evidence


def process_identity(api, handle, pid, expected, started=None):
    if api.GetProcessId(handle) != pid:
        raise RuntimeError('Opened process identity mismatch')
    current = psutil.Process(pid)
    created = current.create_time()
    if (os.path.normcase(str(Path(current.exe()).resolve())) != expected or
            started is not None and created != started):
        raise RuntimeError('Original process path or creation time changed')
    return created


def guarded_read(api, handle, image, base, size, rva, length):
    address, memory = base + rva, Memory()
    if not (type(length) is int and 0 < length <= MAX_FUNCTION_BYTES and
            image.executable(rva, length) and 0 <= rva < rva + length <= size and
            api.VirtualQueryEx(handle, address, C.byref(memory), C.sizeof(memory)) == C.sizeof(memory) and
            memory.State == 0x1000 and memory.Type == 0x1000000 and memory.AllocationBase == base and
            memory.Protect & 0xff in (0x10, 0x20, 0x40, 0x80) and not memory.Protect & 0x100 and
            memory.BaseAddress <= address < address + length <= memory.BaseAddress + memory.RegionSize):
        raise RuntimeError('Image executable page guard not satisfied')
    buffer, copied = (C.c_ubyte * length)(), C.c_size_t()
    if not api.ReadProcessMemory(handle, address, buffer, length, C.byref(copied)) or copied.value != length:
        raise RuntimeError('Bounded image code read failed or was incomplete')
    return bytes(buffer)


def collect(game_root, folder):
    game_root, folder = Path(game_root), Path(folder)
    plan = build_plan(game_root)  # All sealed evidence before any process access.
    executable = game_root / EXECUTABLE_RELATIVE
    folder.mkdir(parents=True, exist_ok=True)
    report = {'kind': 'bounded_typed_sender_code_read', 'client_sha256': SOURCE_SHA,
        'offline_plan': plan, 'functions': [], 'maximum_code_bytes': MAX_CODE_BYTES,
        'actual_code_bytes': 0, 'attempted_code_bytes': 0, 'actual_read_count': 0, 'maximum_reads': MAX_READS,
        'client_launched': False, 'elevation_requested': False, 'game_modified': False,
        'process_memory_written': False, 'credential_memory_read': False, 'live_object_or_vtable_read': False,
        'actual_instance_table_ownership_verified': False, 'sender_header_writer_role_verified': False,
        'playable_map_verified': False, 'observed_at_utc': datetime.now(timezone.utc).isoformat()}
    save(folder / 'plan.json', plan)
    pids = verified_pids(executable)
    if len(pids) != 1:
        report['status'] = 'original_process_not_unique'
        save(folder / 'result.json', report)
        return report
    api = kernel()
    handle = api.OpenProcess(0x1010, False, pids[0])
    if not handle:
        report.update(status='read_not_permitted', windows_error=C.get_last_error())
        save(folder / 'result.json', report)
        return report
    snapshot = None
    try:
        report['phase'] = 'process_handle_and_executable_identity'
        expected = os.path.normcase(str(executable.resolve()))
        started = process_identity(api, handle, pids[0], expected)
        report['phase'] = 'executable_module_snapshot'
        snapshot = api.CreateToolhelp32Snapshot(0x18, pids[0])
        if not snapshot or snapshot == C.c_void_p(-1).value:
            raise RuntimeError('Executable module snapshot unavailable')
        module = Module()
        module.dwSize = C.sizeof(module)
        matches, examined = [], 0
        ok = api.Module32FirstW(snapshot, C.byref(module))
        while ok:
            examined += 1
            if examined > 4096:
                raise RuntimeError('Executable module snapshot entry bound exceeded')
            if os.path.normcase(str(Path(module.szExePath).resolve())) == expected:
                matches.append((module.modBaseAddr, module.modBaseSize))
            ok = api.Module32NextW(snapshot, C.byref(module))
        report['module_entries_examined'], report['exact_module_matches'] = examined, len(matches)
        if len(matches) != 1 or not matches[0][0]:
            raise RuntimeError('Verified executable module unavailable or ambiguous')
        base, size = matches[0]
        report['phase'] = 'immutable_source_revalidation'
        with executable.open('rb') as stream, mmap.mmap(stream.fileno(), 0, access=mmap.ACCESS_READ) as raw:
            image = Image(raw)
            if validate_image(image) != plan:
                raise RuntimeError('Sender source evidence changed after process access')
            report['module_size_bytes'], report['immutable_image_size_bytes'] = size, image.size
            if size != image.size:
                raise RuntimeError('Verified executable module size mismatch')
            reads = [('SendBunch.prefix', PREFIX_RVA, PREFIX_BYTES, None)]
            for name, rva, length, evidence in reads:
                report['phase'] = 'bounded_image_code_read'
                if (len(reads) > MAX_READS or report['actual_read_count'] >= MAX_READS or
                        report['attempted_code_bytes'] + length > MAX_CODE_BYTES):
                    raise RuntimeError('Sender read-count or byte budget exceeded')
                process_identity(api, handle, pids[0], expected, started)
                entry = {'name': name, 'rva': hex(rva), 'code_bytes': length, 'read_succeeded': False}
                if evidence is not None:
                    entry['source_prefix_evidence'] = evidence
                report['functions'].append(entry)
                report['actual_read_count'] += 1
                report['attempted_code_bytes'] += length
                code = guarded_read(api, handle, image, base, size, rva, length)
                process_identity(api, handle, pids[0], expected, started)
                saved = struct.pack('<4Q', 0x0000000145444344, rva, length, base) + code
                decoder = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
                instructions = list(decoder.disasm(code, rva))
                entry.update(read_succeeded=True, file_sha256=hashlib.sha256(saved).hexdigest(),
                             code_sha256=hashlib.sha256(code).hexdigest(),
                             disassembled_bytes=sum(i.size for i in instructions))
                report['actual_code_bytes'] += length
                (folder / (name + '.dfcode')).write_bytes(saved)
                (folder / (name + '.asm.txt')).write_text('\n'.join(
                    f'{i.address:#x}: {i.mnemonic} {i.op_str}' for i in instructions) + '\n', encoding='utf-8')
                if name == 'SendBunch.prefix':
                    try:
                        follow = select_follow(image, code)
                        entry['implementation_follow'] = follow
                        reads.append(('SendBunch.implementation', int(follow['target_rva'], 16),
                                      follow['code_bytes'], follow))
                    except ValueError as error:
                        entry['implementation_not_followed'] = str(error)
                save(folder / 'result.json', report)
        report['status'] = 'bounded_read_attempt_complete'
    except Exception as error:
        report.update(status='bounded_read_failed', error_type=type(error).__name__, error_reason=str(error))
    finally:
        if snapshot and snapshot != C.c_void_p(-1).value:
            api.CloseHandle(snapshot)
        api.CloseHandle(handle)
    save(folder / 'result.json', report)
    return report


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--game-root', type=Path, required=True)
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument('--validate-plan', action='store_true', help='Default: immutable files only')
    mode.add_argument('--collect', action='store_true', help='Read one existing process without elevation')
    parser.add_argument('--output-dir', type=Path, help='Required for explicit --collect')
    args = parser.parse_args(argv)
    if args.collect:
        if args.output_dir is None:
            parser.error('--collect requires --output-dir')
        report = collect(args.game_root, args.output_dir)
        print(report['status'])
        return 0 if report['status'] == 'bounded_read_attempt_complete' else 1
    plan = build_plan(args.game_root)
    PLAN_OUTPUT.parent.mkdir(parents=True, exist_ok=True)
    save(PLAN_OUTPUT, plan)
    print('Offline sender plan validated: 1 prefix, 32 initial bytes; 2 reads/8224 bytes maximum. No process access.')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
