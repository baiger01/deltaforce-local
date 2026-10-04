"""Four source-proved control-field continuation roots; offline by default.

This independent reader never launches, elevates, writes memory, reads objects,
or follows targets. Explicit collect reads only one already-running pinned image.
Saved instructions are evidence, not proof of a working native control protocol.
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
from capstone.x86 import X86_OP_IMM
import psutil

from capture_official_ds import SOURCE_SHA, digest, verified_pids, save
from read_native_control_code import Image
from read_named_ds_transport_code import kernel, Module, Memory

ROOT = Path(__file__).resolve().parent.parent
EXECUTABLE_RELATIVE = Path('DeltaForce/Binaries/Win64/DeltaForceClient-Win64-Shipping.exe')
FIXED_PLAN = ROOT / 'work/evidence/native-control-continuation-fixed-source-plan.json'
FIXED_PLAN_SHA = '65a7ccbd8552a4c71893c4fdcb91ba684175ee6e0ba43bfbf17362c1940fba17'
PLAN_OUTPUT = ROOT / 'work/evidence/native-control-continuation-code-plan.json'
MAX_JSON_BYTES = 256 * 1024
MAX_FUNCTION_BYTES, MAX_FRAGMENTS = 8192, 32
FIXED_READS, FIXED_BYTES = 4, 2346
MAGIC = 0x0000000145444344
IMAGE_SIZE = 536408064
PDATA_RVA, PDATA_BYTES = 0x1e5d1000, 15300936
PDATA_SHA = 'aae32c4f1cc7196c7a2b78a4adc4e5dae29e5a200ad7415ab2ed69f06cd70d5e'
CAPTURE = 'work/native-client-tests/1790875160889006700/ds-native-control-code/'
REPORT_PATH = CAPTURE + 'result.json'
REPORT_SHA = '3f6ec5672c17b65d05b9c72d6ba05708f1d5003df9aec5e9f12112dbf9a368b5'
GUARD_DEPENDENCIES = {
    'work/read_native_control_code.py': '71a8a770a9792e149b2fe363e3b83c07d7140880228e883280f1cadacb3f0e6d',
    'work/read_named_ds_transport_code.py': '503cf438ed5b0720a2d03e0f3d786f7f88efbcf56c4ce549015eeca27eb8de78',
    'work/capture_official_ds.py': '39d453ca19bc4e3a3a4513b5f85974bad26f5ec739d19e44de6e0b213834a4b0',
}
PROVENANCE = {
    'work/evidence/native-string-field-109ea340-semantics.json':
        'd8aa5c211d85da8ee390162780c9e23d4f1012f445ce13c2e1105062f67cd012',
    'work/evidence/control-helper-lower-direct-call-plan.json':
        'cfa80ea98f30be9d57a6e5d4ccbf4603fe653964b1b979c806fec91fd456522e',
}
# Only these exact saved sources and instruction sites can authorize these roots.
SOURCE_SPECS = (
    (0x109ea340, 1679, 0x1bdd77ec,
     '1f2746e42afcba80170572265706c823ea15d7068355174412b3346d2faaa6f8',
     'ac7168027c0f6346062fe45c773b71bed613431c3d6a01c4415278e7726adf19',
     ((0x109ea3b3, 0x10b4b540), (0x109ea69d, 0xd60360),
      (0x109ea77a, 0x10b4b540), (0x109ea7fa, 0xd92e70), (0x109ea8e7, 0x10b4b540))),
    (0x12bab170, 474, 0x1bf5bcf0,
     '4901d3a505519f8f6d34300c354528172d5f0f7ca85cdfd01ebc7571d905ccf7',
     '2eea247e27d6d870dcc1de442c60bf800a932e18db517f4c752c0f76b24b4df2',
     ((0x12bab1f6, 0x10b4b540), (0x12bab335, 0x12bc0e60))),
)
TARGET_SPECS = (
    (0x10b4b540, 0x10b4b597, 0x1bdcbaf0, 87),
    (0xd60360, 0xd60404, 0x1bdcb494, 164),
    (0xd92e70, 0xd92f44, 0x1bdccfb0, 212),
    (0x12bc0e60, 0x12bc15bb, 0x1c8764b4, 1883),
)


def sha(value):
    return hashlib.sha256(value).hexdigest()


def sealed_json(path, expected):
    if not 0 < path.stat().st_size <= MAX_JSON_BYTES:
        raise ValueError('Sealed JSON size bound failed')
    with path.open('rb') as stream:
        raw = stream.read(MAX_JSON_BYTES + 1)
    if len(raw) > MAX_JSON_BYTES or sha(raw) != expected:
        raise ValueError('Sealed JSON file identity mismatch')
    return json.loads(raw)


def executable_backed(image, rva, length):
    return (type(length) is int and 0 < length <= MAX_FUNCTION_BYTES and
            0 <= rva < rva+length <= image.size and image.executable(rva, length) and
            any(s.Characteristics & 0x20000000 and s.VirtualAddress <= rva < rva+length <=
                s.VirtualAddress + min(s.SizeOfRawData, s.Misc_VirtualSize)
                for s in image.pe.sections))


def exact_span(image, rva, end, unwind, length):
    root, actual, fragments = image.function_span(rva)
    if (root != (rva, end, unwind) or actual != length or fragments != [(rva, end)] or
            len(fragments) > MAX_FRAGMENTS or not executable_backed(image, rva, length)):
        raise ValueError('Exact complete function boundary mismatch')
    header = image.data(unwind, 4)
    version, flags, count = header[0] & 7, header[0] >> 3, header[2]
    if version != 1 or flags not in (0, 1, 2, 3):
        raise ValueError('Exact root unwind version/flags mismatch')
    metadata_length = 4 + 4*((count+1)//2) + (4 if flags else 0)
    metadata = image.data(unwind, metadata_length)
    handler = None if not flags else hex(struct.unpack_from('<I', metadata, metadata_length-4)[0])
    return {'root': list(map(hex, root)), 'read_rva': hex(rva),
        'end_rva_exclusive': hex(end), 'code_bytes': length,
        'unwind_fragments': [[hex(a), hex(b)] for a, b in fragments],
        'fragment_count': len(fragments), 'root_is_chain_continuation': False,
        'unwind_metadata': {'entry': list(map(hex, root)), 'version': version, 'flags': flags,
            'prolog_bytes': header[1], 'unwind_code_count': count,
            'metadata_prefix_bytes': metadata_length, 'metadata_prefix_sha256': sha(metadata),
            'handler_rva': handler, 'custom_handler_data_not_read': bool(flags)},
        'file_backed_executable_scope_verified': True}


def validate_source(sample, declared, spec):
    rva, length, _, file_hash, code_hash, sites = spec
    name = 'unknown_control_field_' + format(rva, 'x')
    if (len(sample) != length+32 or sha(sample) != file_hash or
            declared.get('path') != CAPTURE+name+'.dfcode' or
            declared.get('file_sha256') != file_hash or declared.get('code_sha256') != code_hash or
            declared.get('rva') != hex(rva) or declared.get('payload_bytes') != length or
            declared.get('code_ranges') != [[hex(rva), hex(rva+length)]]):
        raise ValueError('Continuation source file/scope identity mismatch')
    magic, header_rva, header_bytes, _private_module_base = struct.unpack('<4Q', sample[:32])
    code = sample[32:]
    if magic != MAGIC or (header_rva, header_bytes) != (rva, length) or sha(code) != code_hash:
        raise ValueError('Continuation source header/code identity mismatch')
    decoder = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
    decoder.detail = True
    instructions = list(decoder.disasm(code, rva))
    if (sum(i.size for i in instructions) != length or
            len(instructions) != declared.get('instruction_count') or
            declared.get('full_decode_verified') is not True):
        raise ValueError('Continuation saved source does not completely decode')
    targets = {t[0] for t in TARGET_SPECS}
    calls = [i for i in instructions if i.mnemonic == 'call' and i.size == 5 and
             i.bytes[0] == 0xe8 and len(i.operands) == 1 and
             i.operands[0].type == X86_OP_IMM and i.operands[0].imm in targets]
    if tuple((i.address, i.operands[0].imm) for i in calls) != sites:
        raise ValueError('Continuation exact selected source-call domain mismatch')
    evidence = []
    for ins, (site, target) in zip(calls, sites):
        if not rva <= site < site+5 <= rva+length or site+5+struct.unpack('<i', ins.bytes[1:])[0] != target:
            raise ValueError('Continuation E8 relative target mismatch')
        evidence.append({'call_rva': hex(site), 'instruction_bytes_hex': bytes(ins.bytes).hex(),
                         'target_rva': hex(target)})
    if declared.get('selected_e8_calls') != evidence:
        raise ValueError('Continuation sealed E8 instruction evidence mismatch')
    return evidence


def validate_image(image):
    evidence = sealed_json(FIXED_PLAN, FIXED_PLAN_SHA)
    if (evidence.get('kind') != 'fixed_native_control_continuation_source_plan' or
            evidence.get('client_sha256') != SOURCE_SHA or evidence.get('plan_only') is not True or
            evidence.get('client_relative_executable') != EXECUTABLE_RELATIVE.as_posix() or
            image.size != IMAGE_SIZE or sha(image.raw) != SOURCE_SHA or
            evidence.get('guard_dependencies') != GUARD_DEPENDENCIES or
            evidence.get('provenance') != PROVENANCE):
        raise ValueError('Continuation plan/image/dependency scope mismatch')
    for path, expected in GUARD_DEPENDENCIES.items():
        if digest(ROOT/path) != expected:
            raise ValueError('Shared process guard dependency identity mismatch')
    for path, expected in PROVENANCE.items():
        sealed_json(ROOT/path, expected)
    directory = image.pe.OPTIONAL_HEADER.DATA_DIRECTORY[3]
    pdata = {'rva': hex(PDATA_RVA), 'bytes': PDATA_BYTES, 'sha256': PDATA_SHA,
             'entry_count': PDATA_BYTES//12}
    if (evidence.get('pdata') != pdata or directory.VirtualAddress != PDATA_RVA or
            directory.Size != PDATA_BYTES or directory.Size % 12 or
            image.unwind_count != PDATA_BYTES//12 or sha(image.data(PDATA_RVA, PDATA_BYTES)) != PDATA_SHA):
        raise ValueError('Continuation complete pdata identity mismatch')
    if evidence.get('source_report') != {'path': REPORT_PATH, 'sha256': REPORT_SHA}:
        raise ValueError('Continuation source report scope mismatch')
    report = sealed_json(ROOT/REPORT_PATH, REPORT_SHA)
    if report.get('client_sha256') != SOURCE_SHA:
        raise ValueError('Continuation saved report client identity mismatch')
    sources = evidence.get('sources')
    if not isinstance(sources, list) or len(sources) != 2:
        raise ValueError('Continuation fixed source count mismatch')
    all_calls = []
    for declared, spec in zip(sources, SOURCE_SPECS):
        rva, length, unwind, file_hash, code_hash, _ = spec
        expected_span = exact_span(image, rva, rva+length, unwind, length)
        if declared.get('immutable_span') != expected_span:
            raise ValueError('Continuation saved source unwind identity mismatch')
        name = 'unknown_control_field_' + format(rva, 'x')
        rows = [v for v in report.get('functions', []) if v.get('name') == name]
        if (len(rows) != 1 or rows[0].get('read_succeeded') is not True or
                rows[0].get('rva') != hex(rva) or rows[0].get('code_bytes') != length or
                rows[0].get('file_sha256') != file_hash or rows[0].get('code_sha256') != code_hash or
                rows[0].get('disassembled_bytes') != length):
            raise ValueError('Continuation saved source report row mismatch')
        path = ROOT/(CAPTURE+name+'.dfcode')  # Fixed source path; never resolve a declared arbitrary path.
        if path.stat().st_size != length+32:
            raise ValueError('Continuation saved source file length mismatch')
        with path.open('rb') as stream:
            sample = stream.read(length+33)
        calls = validate_source(sample, declared, spec)
        all_calls.extend(dict(call, source_rva=hex(rva)) for call in calls)
    targets = evidence.get('targets')
    if not isinstance(targets, list) or len(targets) != FIXED_READS:
        raise ValueError('Continuation fixed target count mismatch')
    validated = []
    for declared, spec in zip(targets, TARGET_SPECS):
        rva, end, unwind, length = spec
        label = 'unknown_control_continuation_' + format(rva, 'x')
        actual = exact_span(image, *spec)
        calls = [v for v in all_calls if v['target_rva'] == hex(rva)]
        if (declared.get('label') != label or declared.get('immutable_span') != actual or
                declared.get('source_e8_calls') != calls or not calls):
            raise ValueError('Continuation fixed target evidence mismatch')
        validated.append({'label': label, 'rva': hex(rva), 'code_bytes': length,
            'immutable_span': actual, 'source_e8_calls': calls,
            'typed_signature_verified': False, 'wire_semantics_verified': False})
    summary = {'maximum_reads': FIXED_READS, 'maximum_code_bytes': FIXED_BYTES,
        'maximum_function_bytes': MAX_FUNCTION_BYTES, 'maximum_fragments': MAX_FRAGMENTS,
        'source_count': 2, 'selected_source_e8_count': 7, 'follow_count': 0}
    if evidence.get('summary') != summary or sum(v['code_bytes'] for v in validated) != FIXED_BYTES:
        raise ValueError('Continuation fixed read/byte budget mismatch')
    return {'kind': 'fixed_native_control_continuation_code_plan', 'client_sha256': SOURCE_SHA,
        'client_relative_to_game_root': EXECUTABLE_RELATIVE.as_posix(),
        'sealed_source_plan_sha256': FIXED_PLAN_SHA, 'continuation_roots': validated,
        'fixed_read_count': FIXED_READS, 'initial_read_bytes': FIXED_BYTES,
        'maximum_reads': FIXED_READS, 'maximum_code_bytes': FIXED_BYTES,
        'follow_policy': 'four fixed source-proved E8 roots; no follow or object reads',
        'process_memory_read': False, 'client_launched': False, 'elevation_requested': False,
        'image_modified': False, 'native_control_logic_verified': False,
        'playable_map_verified': False, 'status': 'offline_plan_validated'}


def build_plan(game_root):
    executable = Path(game_root)/EXECUTABLE_RELATIVE
    if digest(executable) != SOURCE_SHA:
        raise ValueError('Client version hash mismatch')
    with executable.open('rb') as stream, mmap.mmap(stream.fileno(), 0, access=mmap.ACCESS_READ) as raw:
        return validate_image(Image(raw))


def collect(game_root, folder):
    game_root, folder = Path(game_root), Path(folder)
    plan = build_plan(game_root)  # All disk/source/guard evidence before process access.
    executable = game_root/EXECUTABLE_RELATIVE
    folder.mkdir(parents=True, exist_ok=True)
    save(folder/'plan.json', plan)
    report = {'kind': 'bounded_native_control_continuation_read', 'client_sha256': SOURCE_SHA,
        'offline_plan': plan, 'functions': [], 'actual_code_bytes': 0,
        'maximum_reads': FIXED_READS, 'maximum_code_bytes': FIXED_BYTES,
        'client_launched': False, 'elevation_requested': False, 'game_modified': False,
        'process_memory_written': False, 'credential_memory_read': False,
        'live_object_or_vtable_read': False, 'native_control_logic_verified': False,
        'playable_map_verified': False, 'observed_at_utc': datetime.now(timezone.utc).isoformat()}
    pids = verified_pids(executable)
    if len(pids) != 1:
        report['status'] = 'original_process_not_unique'
        save(folder/'result.json', report)
        return report
    api = kernel()
    handle = api.OpenProcess(0x1010, False, pids[0])
    if not handle:
        report.update(status='read_not_permitted', windows_error=C.get_last_error())
        save(folder/'result.json', report)
        return report
    snapshot = None
    try:
        if api.GetProcessId(handle) != pids[0]:
            raise RuntimeError('Opened process identity mismatch')
        expected = os.path.normcase(str(executable.resolve()))
        process = psutil.Process(pids[0])
        started = process.create_time()
        if os.path.normcase(str(Path(process.exe()).resolve())) != expected:
            raise RuntimeError('Original process executable identity mismatch')
        snapshot = api.CreateToolhelp32Snapshot(0x18, pids[0])
        base, size = None, None
        if snapshot and snapshot != C.c_void_p(-1).value:
            item = Module()
            item.dwSize = C.sizeof(item)
            ok = api.Module32FirstW(snapshot, C.byref(item))
            while ok:
                if os.path.normcase(str(Path(item.szExePath).resolve())) == expected:
                    base, size = item.modBaseAddr, item.modBaseSize
                    break
                ok = api.Module32NextW(snapshot, C.byref(item))
        if base is None or size != IMAGE_SIZE:
            raise RuntimeError('Verified executable module path/size unavailable')
        with executable.open('rb') as stream, mmap.mmap(stream.fileno(), 0, access=mmap.ACCESS_READ) as raw:
            image = Image(raw)
            if size != image.size or validate_image(image) != plan:
                raise RuntimeError('Continuation evidence changed after process access')
            decoder = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
            for index, root in enumerate(plan['continuation_roots']):
                rva, length = int(root['rva'], 16), root['code_bytes']
                if index >= FIXED_READS or report['actual_code_bytes']+length > FIXED_BYTES:
                    raise RuntimeError('Continuation fixed read/byte budget exceeded')
                current = psutil.Process(pids[0])
                if (current.create_time() != started or
                        os.path.normcase(str(Path(current.exe()).resolve())) != expected):
                    raise RuntimeError('Original process identity changed')
                address, memory = base+rva, Memory()
                entry = {'name': root['label'], 'rva': hex(rva), 'code_bytes': length,
                         'source_evidence': root, 'read_succeeded': False}
                valid = (executable_backed(image, rva, length) and rva+length <= size and
                    api.VirtualQueryEx(handle, address, C.byref(memory), C.sizeof(memory)) == C.sizeof(memory) and
                    memory.State == 0x1000 and memory.Type == 0x1000000 and memory.AllocationBase == base and
                    (memory.Protect & 0xff) in (0x10, 0x20, 0x40, 0x80) and not memory.Protect & 0x100 and
                    memory.BaseAddress <= address < address+length <= memory.BaseAddress+memory.RegionSize)
                if not valid:
                    entry['read_refused_reason'] = 'image_executable_page_guard_not_satisfied'
                else:
                    buffer, copied = (C.c_ubyte*length)(), C.c_size_t()
                    if api.ReadProcessMemory(handle, address, buffer, length, C.byref(copied)) and copied.value == length:
                        code = bytes(buffer)
                        report['actual_code_bytes'] += length
                        instructions = list(decoder.disasm(code, rva))
                        saved = struct.pack('<4Q', MAGIC, rva, length, base)+code
                        entry.update(read_succeeded=True, code_sha256=sha(code), file_sha256=sha(saved),
                            disassembled_bytes=sum(i.size for i in instructions),
                            full_linear_decode=sum(i.size for i in instructions) == length)
                        (folder/(root['label']+'.dfcode')).write_bytes(saved)
                        (folder/(root['label']+'.asm.txt')).write_text('\n'.join(
                            f'{i.address:#x}: {i.mnemonic} {i.op_str}' for i in instructions)+'\n', encoding='utf-8')
                    else:
                        entry['read_refused_reason'] = 'exact_copy_not_completed'
                        entry['windows_error'] = C.get_last_error()
                report['functions'].append(entry)
                save(folder/'result.json', report)
        report['status'] = ('bounded_read_attempt_complete' if len(report['functions']) == FIXED_READS and
            all(v['read_succeeded'] for v in report['functions']) else 'bounded_read_partial')
    except Exception as error:
        report.update(status='bounded_read_failed', error_type=type(error).__name__)
        if isinstance(error, RuntimeError):
            report['error_reason'] = str(error)  # Only fixed local reasons; no private live addresses.
    finally:
        if snapshot and snapshot != C.c_void_p(-1).value:
            api.CloseHandle(snapshot)
        api.CloseHandle(handle)
    save(folder/'result.json', report)
    return report


def argument_parser():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--game-root', type=Path, required=True)
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument('--validate-plan', action='store_true', help='Disk evidence only (default)')
    mode.add_argument('--collect', action='store_true', help='Explicitly read an already-running pinned image')
    parser.add_argument('--output-dir', type=Path, help='Required only for --collect')
    return parser


if __name__ == '__main__':
    parser = argument_parser()
    args = parser.parse_args()
    if args.collect:
        if args.output_dir is None:
            parser.error('--collect requires --output-dir')
        result = collect(args.game_root, args.output_dir)
        print(result['status'])
        raise SystemExit(0 if result['status'] == 'bounded_read_attempt_complete' else 1)
    if args.output_dir is not None:
        parser.error('--output-dir is only used with explicit --collect')
    plan = build_plan(args.game_root)
    PLAN_OUTPUT.parent.mkdir(parents=True, exist_ok=True)
    save(PLAN_OUTPUT, plan)
    print('Offline continuation plan validated: 4 fixed reads, 2346 bytes, no target follow or process access.')
