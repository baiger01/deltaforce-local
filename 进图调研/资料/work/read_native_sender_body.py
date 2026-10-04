"""Bounded sender bodies with source wrapper and conditional E8 verification.

Default CLI only validates disk evidence. Explicit collect reads one existing
version-pinned process; it never launches, elevates, patches, writes memory,
reads an object/vtable, or recursively follows code. Static-table candidates do
not prove actual instance ownership, wire format, or playable map entry.
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
FIXED_PLAN = ROOT/'work/evidence/native-sender-body-fixed-source-plan.json'
FIXED_PLAN_SHA = 'e2aa1953027d091210d371bbbc7519f3f3bd5e6edcc6d43331bb8bef522b2d64'
PLAN_OUTPUT = ROOT/'work/evidence/native-sender-body-code-plan.json'
MAX_JSON_BYTES, MAX_FUNCTION_BYTES, MAX_FRAGMENTS = 256*1024, 8192, 32
MAX_READS, MAX_CODE_BYTES, INITIAL_BYTES = 3, 3737, 499
MAGIC, IMAGE_BASE, IMAGE_SIZE = 0x0000000145444344, 0x140000000, 536408064
PREFIX_RVA, PREFIX_BYTES, WRAPPER_BYTES = 0x5bfbfd0, 32, 36
CONTROL_RVA, CONTROL_BYTES = 0x1286d3a0, 463
BASE_RVA, BASE_BYTES = 0x1286c6f0, 3238
SOURCE_PATH = 'work/native-client-tests/1790883169018138400/ds-native-control-code/sender/SendBunch.prefix.dfcode'
SOURCE_FILE_SHA = '23f87e123a9d570be806302d9ff85d236c37cc7dbc1a848f8a06ad1f7a4161d8'
SOURCE_CODE_SHA = '2112fcd1eef27a284ab09ccc8ee057adbfe5571cbee6c7f4c1822337fb9179d7'
SOURCE_RESULT = 'work/native-client-tests/1790883169018138400/ds-native-control-code/sender/result.json'
SOURCE_RESULT_SHA = '3b499b93f44f1a22f06a60095469af54883aba0a182a078c187b6269af7656a6'
GUARD_DEPENDENCIES = {
    'work/read_native_control_code.py': '71a8a770a9792e149b2fe363e3b83c07d7140880228e883280f1cadacb3f0e6d',
    'work/read_named_ds_transport_code.py': '503cf438ed5b0720a2d03e0f3d786f7f88efbcf56c4ce549015eeca27eb8de78',
    'work/capture_official_ds.py': '39d453ca19bc4e3a3a4513b5f85974bad26f5ec739d19e44de6e0b213834a4b0',
}
PROVENANCE = {
    'typed_evidence': ('work/evidence/native-channel-sendbunch-typed-prefix-plan.json',
        '4241f756bd0d6f5dd8168f56aef2ff5f14da00b6fcfd110a41822cbb171ab87d'),
    'audit': ('work/evidence/native-sendbunch-prefix-1790883169018138400-audit.json',
        '5bf2b25c22592fa6f63b88423f68b8cd6fbf190e3c39a7be95989dd55231e827'),
    'static_anchor_evidence': ('work/evidence/native-control-static-vtable-crosscheck.json',
        '0476fa4b8ee9ea0e517e038117af515d6ecc10edf88540d3dc024a21b8cd1f0b'),
}
SPECS = (
    ('SendBunch.complete_wrapper', PREFIX_RVA, WRAPPER_BYTES,
     (0x5bfbfd0, 0x5bfbff4, 0x1bdcb3ac), ((0x5bfbfd0, 0x5bfbff4),)),
    ('Control.SendBunch.static_slot_candidate', CONTROL_RVA, CONTROL_BYTES,
     (0x1286d3a0, 0x1286d495, 0x1be49b40),
     ((0x1286d3a0, 0x1286d495), (0x1286d495, 0x1286d555), (0x1286d555, 0x1286d56f))),
    ('Channel.SendBunch.actor_static_slot_candidate', BASE_RVA, BASE_BYTES,
     (0x1286c6f0, 0x1286d396, 0x1c84a41c), ((0x1286c6f0, 0x1286d396),)),
)
STATIC_REGIONS = (
    (0x167ea6c8, 704, '3910c3d478d7887a83d524653ad1868a57e1e921f69b3a5ceccb7b362b114de8'),
    (0x167ea950, 56, 'af49f63f43ff0b338c0bb68a9153e55490ba987d19d03695771febc5415ac60b'),
    (0x167ea968, 32, 'cd45066348167f12335e071144bc6fea583e79cc88348a420427ca1e5e71a951'),
    (0x1b148fa0, 56, 'ee37f062b15c562a070c21fe4a8b55c820257d0ecc42ef848c31028f39e5a360'),
)
PDATA_RVA, PDATA_BYTES = 0x1e5d1000, 15300936
PDATA_SHA = 'aae32c4f1cc7196c7a2b78a4adc4e5dae29e5a200ad7415ab2ed69f06cd70d5e'
TYPED_SPECS = (
    ('UControlChannel.SendBunch', 0x1b3e8b60, 0x1d7a1190, 'UControlChannel *', 0x1b3eb790),
    ('UChannel.SendBunch', 0x1b42f110, 0x1d7a9518, 'UChannel *', 0x16076050),
)
WRAPPER_INSTRUCTIONS = (
    (0x5bfbfd0, 'push', 'rbx'), (0x5bfbfd2, 'sub', 'rsp, 0x20'),
    (0x5bfbfd6, 'mov', 'rax, qword ptr [rdx]'), (0x5bfbfd9, 'mov', 'r10, rdx'),
    (0x5bfbfdc, 'mov', 'rbx, rcx'), (0x5bfbfdf, 'mov', 'rdx, rcx'),
    (0x5bfbfe2, 'mov', 'rcx, r10'), (0x5bfbfe5, 'call', 'qword ptr [rax + 0x2b8]'),
    (0x5bfbfeb, 'mov', 'rax, rbx'), (0x5bfbfee, 'add', 'rsp, 0x20'),
    (0x5bfbff2, 'pop', 'rbx'), (0x5bfbff3, 'ret', ''),
)


def sha(value):
    return hashlib.sha256(value).hexdigest()


def sealed_json(path, expected):
    if not 0 < path.stat().st_size <= MAX_JSON_BYTES:
        raise ValueError('Sender body sealed JSON size bound failed')
    with path.open('rb') as stream:
        value = stream.read(MAX_JSON_BYTES+1)
    if len(value) > MAX_JSON_BYTES or sha(value) != expected:
        raise ValueError('Sender body sealed JSON identity mismatch')
    return json.loads(value)


def executable_backed(image, rva, length):
    return (type(length) is int and 0 < length <= MAX_FUNCTION_BYTES and
        0 <= rva < rva+length <= image.size and image.executable(rva, length) and
        any(s.Characteristics & 0x20000000 and s.VirtualAddress <= rva < rva+length <=
            s.VirtualAddress+min(s.SizeOfRawData, s.Misc_VirtualSize) for s in image.pe.sections))


def complete_decode(code, rva, length):
    if len(code) != length:
        raise ValueError('Sender code exact payload length mismatch')
    decoder = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
    decoder.detail = True
    instructions = list(decoder.disasm(code, rva))
    cursor = rva
    for ins in instructions:
        if ins.address != cursor:
            raise ValueError('Sender code instruction coverage is noncontiguous')
        cursor += ins.size
    if cursor != rva+length:
        raise ValueError('Sender code does not fully decode without skipdata')
    return instructions


def source_prefix(evidence):
    expected = {
        'source_native_prefix_relative_path': SOURCE_PATH, 'source_file_sha256': SOURCE_FILE_SHA,
        'source_code_sha256': SOURCE_CODE_SHA, 'source_prefix_bytes': PREFIX_BYTES,
        'source_result_relative_path': SOURCE_RESULT, 'source_result_sha256': SOURCE_RESULT_SHA,
        'source_call_instruction_rva': '0x5bfbfe5', 'source_call_instruction_bytes': 'ff90b8020000',
        'source_measured_slot': '0x2b8',
    }
    if any(evidence.get(key) != value for key, value in expected.items()):
        raise ValueError('Sender saved prefix scope mismatch')
    path = ROOT/SOURCE_PATH
    if path.stat().st_size != PREFIX_BYTES+32:
        raise ValueError('Sender saved prefix file length mismatch')
    with path.open('rb') as stream:
        saved = stream.read(PREFIX_BYTES+33)
    if len(saved) != PREFIX_BYTES+32 or sha(saved) != SOURCE_FILE_SHA:
        raise ValueError('Sender saved prefix file SHA mismatch')
    magic, rva, length, _private_module_base = struct.unpack('<4Q', saved[:32])
    code = saved[32:]
    if ((magic, rva, length) != (MAGIC, PREFIX_RVA, PREFIX_BYTES) or sha(code) != SOURCE_CODE_SHA or
        evidence.get('source_prefix_hex') != code.hex() or
        evidence.get('source_header') != {'magic': '0x0000000145444344', 'rva': hex(PREFIX_RVA),
            'code_bytes': PREFIX_BYTES, 'header_bytes': 32}):
        raise ValueError('Sender saved prefix header/code identity mismatch')
    report = sealed_json(ROOT/SOURCE_RESULT, SOURCE_RESULT_SHA)
    functions = report.get('functions', [])
    if (report.get('client_sha256') != SOURCE_SHA or len(functions) != 1 or
            functions[0].get('name') != 'SendBunch.prefix' or
            functions[0].get('rva') != hex(PREFIX_RVA) or functions[0].get('code_bytes') != PREFIX_BYTES or
            functions[0].get('read_succeeded') is not True or
            functions[0].get('file_sha256') != SOURCE_FILE_SHA or
            functions[0].get('code_sha256') != SOURCE_CODE_SHA or functions[0].get('disassembled_bytes') != 30):
        raise ValueError('Sender saved prefix report identity mismatch')
    # The fixed 32-byte prefix ends two bytes into the 4-byte stack epilogue.
    decoder = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
    instructions = list(decoder.disasm(code, PREFIX_RVA))
    if (sum(i.size for i in instructions) != 30 or evidence.get('source_prefix_decoded_bytes') != 30 or
            [(i.address, i.mnemonic, i.op_str) for i in instructions] != list(WRAPPER_INSTRUCTIONS[:9]) or
            code[-2:] != b'\x48\x83'):
        raise ValueError('Sender saved ABI wrapper prefix instruction mismatch')
    return code


def validate_wrapper(code, prefix):
    if len(code) != WRAPPER_BYTES or len(prefix) != PREFIX_BYTES or code[:PREFIX_BYTES] != prefix:
        raise ValueError('Complete sender wrapper differs from saved first32 bytes')
    instructions = complete_decode(code, PREFIX_RVA, WRAPPER_BYTES)
    if [(i.address, i.mnemonic, i.op_str) for i in instructions] != list(WRAPPER_INSTRUCTIONS):
        raise ValueError('Complete sender wrapper ABI permutation or normal epilogue mismatch')
    call = instructions[7]
    if bytes(call.bytes).hex() != 'ff90b8020000':
        raise ValueError('Complete sender wrapper exact virtual call mismatch')
    return {'complete_decode_verified': True, 'instruction_count': len(instructions),
        'saved_first32_bytes_match': True, 'receiver_and_return_buffer_permutation_verified': True,
        'normal_epilogue_and_return_verified': True, 'call_rva': hex(call.address),
        'call_instruction_bytes': bytes(call.bytes).hex(), 'measured_virtual_slot': '0x2b8',
        'actual_instance_table_ownership_verified': False}


def conditional_e8(code):
    instructions = complete_decode(code, CONTROL_RVA, CONTROL_BYTES)
    matches = []
    for ins in instructions:
        if (ins.mnemonic == 'call' and ins.size == 5 and ins.bytes[0] == 0xe8 and
            len(ins.operands) == 1 and ins.operands[0].type == X86_OP_IMM and
            ins.operands[0].imm == BASE_RVA):
            if not CONTROL_RVA <= ins.address < ins.address+5 <= CONTROL_RVA+CONTROL_BYTES:
                raise ValueError('Conditional sender E8 leaves saved source function')
            if ins.address+5+struct.unpack('<i', ins.bytes[1:])[0] != BASE_RVA:
                raise ValueError('Conditional sender E8 rel32 and decoded target differ')
            matches.append(ins)
    if len(matches) != 1:
        raise ValueError('Conditional sender direct E8 evidence absent or ambiguous')
    ins = matches[0]
    return {'source_rva': hex(CONTROL_RVA), 'source_code_bytes': CONTROL_BYTES,
        'source_code_sha256': sha(code), 'source_complete_decode_verified': True,
        'call_rva': hex(ins.address), 'call_instruction_bytes': bytes(ins.bytes).hex(),
        'target_rva': hex(BASE_RVA), 'single_valid_instruction_boundary_E8_verified': True,
        'recursive_follow': False, 'base_implementation_role_verified': False}


def metadata_span(image, spec):
    label, rva, length, expected_root, expected_fragments = spec
    root, actual_bytes, fragments = image.function_span(rva)
    if (root != expected_root or actual_bytes != length or tuple(fragments) != expected_fragments or
            not 1 <= len(fragments) <= MAX_FRAGMENTS or not executable_backed(image, rva, length)):
        raise ValueError('Sender body complete same-root boundary mismatch')
    accepted, metadata = set(), []
    for begin, end in fragments:
        low, high = 0, image.unwind_count
        while low < high:
            mid = (low+high)//2
            if image.unwind_entry(mid)[0] < begin:
                low = mid+1
            else:
                high = mid
        if low >= image.unwind_count:
            raise ValueError('Sender body fragment has no exact pdata entry')
        triple = image.unwind_entry(low)
        if triple[:2] != (begin, end):
            raise ValueError('Sender body exact fragment pdata mismatch')
        header = image.data(triple[2], 4)
        version, flags, count = header[0]&7, header[0]>>3, header[2]
        if version != 1 or (not accepted and flags not in (0, 1, 2, 3)) or (accepted and flags != 4):
            raise ValueError('Sender body unwind root/continuation flags mismatch')
        size = 4+4*((count+1)//2)+(12 if flags == 4 else 4 if flags else 0)
        data = image.data(triple[2], size)
        parent = struct.unpack_from('<III', data, size-12) if flags == 4 else None
        if parent is not None and parent not in accepted:
            raise ValueError('Sender body unwind chain leaves accepted same root')
        metadata.append({'entry': list(map(hex, triple)), 'version': version, 'flags': flags,
            'metadata_bytes': size, 'metadata_sha256': sha(data),
            'chain_parent': None if parent is None else list(map(hex, parent))})
        accepted.add(triple)
    return {'label': label, 'read_rva': hex(rva), 'code_bytes': length,
        'root': list(map(hex, root)), 'fragments': [[hex(a), hex(b)] for a, b in fragments],
        'unwind_metadata': metadata}


def validate_typed_bindings(image, evidence):
    rows = evidence.get('typed_bindings')
    if not isinstance(rows, list) or len(rows) != 2:
        raise ValueError('Sender body typed binding count mismatch')
    for row, (label, record, args, receiver, receiver_rva) in zip(rows, TYPED_SPECS):
        returns_rva, name_rva, invoker = 0x164e43e0, 0x16437b20, 0x5b998b0
        expected = (image.base+name_rva, image.base+PREFIX_RVA, image.base+invoker,
                    image.base+returns_rva, image.base+args, 3)
        raw_record = image.data(record, 48)
        raw_args = image.data(args, 24)
        expected_args = (image.base+receiver_rva, image.base+0x15768828, image.base+0x14ee4878)
        if (row.get('label') != label or row.get('record_rva') != hex(record) or row.get('code_rva') != hex(PREFIX_RVA) or
            row.get('name_rva') != hex(name_rva) or row.get('invoker_rva') != hex(invoker) or
            row.get('return_type') != 'FPacketIdRange' or row.get('return_label_rva') != hex(returns_rva) or
            row.get('record_bytes') != 48 or row.get('argument_table_bytes') != 24 or row.get('argument_count') != 3 or
            row.get('argument_table_rva') != hex(args) or row.get('six_qwords') != list(map(hex, expected)) or
            struct.unpack('<6Q', raw_record) != expected or sha(raw_record) != row.get('record_sha256') or
            struct.unpack('<3Q', raw_args) != expected_args or row.get('argument_table_qwords') != list(map(hex, expected_args)) or
            sha(raw_args) != row.get('argument_table_sha256') or row.get('arguments') != [
                {'label': receiver, 'label_rva': hex(receiver_rva)},
                {'label': 'FOutBunch *', 'label_rva': '0x15768828'}, {'label': 'bool', 'label_rva': '0x14ee4878'}]):
            raise ValueError('Sender body full sixQ/parameter record identity mismatch')
        image.label(name_rva, 'SendBunch')
        image.label(returns_rva, 'FPacketIdRange')
        for text, rva in ((receiver, receiver_rva), ('FOutBunch *', 0x15768828), ('bool', 0x14ee4878)):
            image.label(rva, text)
        if not executable_backed(image, PREFIX_RVA, WRAPPER_BYTES) or not executable_backed(image, invoker, 1):
            raise ValueError('Sender body typed implementation/invoker outside backed executable scope')
        offset = image.pe.get_offset_from_rva(PREFIX_RVA)
        disk = bytes(image.raw[offset:offset+PREFIX_BYTES])
        if (sha(disk) != row.get('disk_prefix_sha256') or disk[:16].hex() != row.get('disk_prefix_first16') or
            row.get('disk_prefix_is_not_assumed_native_runtime_code') is not True or
            row.get('full_six_qword_signature_verified') is not True):
            raise ValueError('Sender body immutable encoded prefix identity mismatch')
    return rows


def validate_image(image):
    evidence = sealed_json(FIXED_PLAN, FIXED_PLAN_SHA)
    if (evidence.get('kind') != 'fixed_sender_body_source_plan' or evidence.get('plan_only') is not True or
        evidence.get('source_sha256') != SOURCE_SHA or sha(image.raw) != SOURCE_SHA or
        image.base != IMAGE_BASE or image.size != IMAGE_SIZE or
        evidence.get('client_relative_to_game_root') != EXECUTABLE_RELATIVE.as_posix() or
        evidence.get('preferred_image_base') != hex(IMAGE_BASE) or evidence.get('immutable_image_size_bytes') != IMAGE_SIZE or
        evidence.get('guard_dependencies') != GUARD_DEPENDENCIES):
        raise ValueError('Sender body source plan/image identity mismatch')
    for path, expected in GUARD_DEPENDENCIES.items():
        if digest(ROOT/path) != expected:
            raise ValueError('Sender body shared guard dependency identity mismatch')
    for kind, (path, expected) in PROVENANCE.items():
        if evidence.get(kind+'_relative_path') != path or evidence.get(kind+'_sha256') != expected:
            raise ValueError('Sender body sealed provenance scope mismatch')
        sealed_json(ROOT/path, expected)
    prefix = source_prefix(evidence)
    directory = image.pe.OPTIONAL_HEADER.DATA_DIRECTORY[3]
    if (evidence.get('pdata') != {'rva': hex(PDATA_RVA), 'bytes': PDATA_BYTES, 'sha256': PDATA_SHA} or
        directory.VirtualAddress != PDATA_RVA or directory.Size != PDATA_BYTES or directory.Size % 12 or
        image.unwind_count != PDATA_BYTES//12 or sha(image.data(PDATA_RVA, PDATA_BYTES)) != PDATA_SHA):
        raise ValueError('Sender body complete pdata identity mismatch')
    regions = evidence.get('static_regions')
    if not isinstance(regions, list) or len(regions) != len(STATIC_REGIONS):
        raise ValueError('Sender body static region count mismatch')
    for row, (rva, length, expected) in zip(regions, STATIC_REGIONS):
        data = image.data(rva, length)
        if row.get('rva') != hex(rva) or row.get('bytes') != length or row.get('sha256') != expected or sha(data) != expected:
            raise ValueError('Sender body fixed static region identity mismatch')
        if row.get('qwords') is not None and row['qwords'] != list(map(hex, struct.unpack('<'+'Q'*(length//8), data))):
            raise ValueError('Sender body static region pointer values mismatch')
    for kind, table, received, nak, sender in (
        ('control', 0x167ea6c8, 0x128668d0, 0x12867a00, CONTROL_RVA),
        ('actor', 0x1b148d18, 0x12865fe0, 0x128677a0, BASE_RVA),
    ):
        expected = {'table_base': hex(table), 'received_slot': '0x288', 'received_target': hex(received),
            'nak_slot': '0x290', 'nak_target': hex(nak), 'sender_slot': '0x2b8', 'sender_target': hex(sender)}
        if evidence.get('required_immutable_'+kind+'_anchors') != expected:
            raise ValueError('Sender body fixed static anchor scope mismatch')
        for slot, target in ((0x288, received), (0x290, nak), (0x2b8, sender)):
            if struct.unpack('<Q', image.data(table+slot, 8))[0] != image.base+target:
                raise ValueError('Sender body fixed static anchor pointer mismatch')
    validate_typed_bindings(image, evidence)
    declared = evidence.get('initial_reads')
    conditional = evidence.get('conditional_single_e8_read')
    if not isinstance(declared, list) or len(declared) != 2 or not isinstance(conditional, dict):
        raise ValueError('Sender body fixed initial/conditional target count mismatch')
    validated = []
    for row, spec in zip(declared+[conditional], SPECS):
        actual = metadata_span(image, spec)
        if any(row.get(k) != v for k, v in actual.items()):
            raise ValueError('Sender body sealed exact root/fragment/unwind identity mismatch')
        validated.append(actual)
    limits = {'initial_read_count': 2, 'initial_code_bytes': INITIAL_BYTES,
        'maximum_reads': MAX_READS, 'maximum_code_bytes': MAX_CODE_BYTES,
        'maximum_function_bytes': MAX_FUNCTION_BYTES, 'maximum_fragments_per_function': MAX_FRAGMENTS,
        'maximum_attempted_reads': MAX_READS, 'maximum_attempted_code_bytes': MAX_CODE_BYTES,
        'no_recursive_follow': True, 'no_additional_targets': True,
        'actual_current_instance_table_ownership_verified': False,
        'actual_packet_header_writer_role_verified': False, 'playable_map_verified': False}
    if (any(evidence.get(k) != v for k, v in limits.items()) or len(prefix) != PREFIX_BYTES or
        sum(row['code_bytes'] for row in validated) != MAX_CODE_BYTES):
        raise ValueError('Sender body fixed read/byte/qualification bounds mismatch')
    return {'kind': 'fixed_sender_body_code_plan', 'client_sha256': SOURCE_SHA,
        'client_relative_to_game_root': EXECUTABLE_RELATIVE.as_posix(), 'source_plan_sha256': FIXED_PLAN_SHA,
        'initial_reads': validated[:2], 'conditional_single_e8_read': validated[2],
        'source_prefix_code_sha256': SOURCE_CODE_SHA, 'initial_code_bytes': INITIAL_BYTES,
        'maximum_reads': MAX_READS, 'maximum_code_bytes': MAX_CODE_BYTES,
        'follow_policy': 'full wrapper then fixed Control candidate; one same-source direct E8 to fixed conditional root only',
        'process_memory_read': False, 'client_launched': False, 'elevation_requested': False,
        'image_modified': False, 'actual_instance_table_ownership_verified': False,
        'base_implementation_role_verified': False, 'packet_header_writer_role_verified': False,
        'playable_map_verified': False, 'status': 'offline_plan_validated'}


def build_plan(game_root):
    executable = Path(game_root)/EXECUTABLE_RELATIVE
    if digest(executable) != SOURCE_SHA:
        raise ValueError('Sender body client version hash mismatch')
    with executable.open('rb') as stream, mmap.mmap(stream.fileno(), 0, access=mmap.ACCESS_READ) as raw:
        return validate_image(Image(raw))


def process_identity(api, handle, pid, expected, started=None):
    if api.GetProcessId(handle) != pid:
        raise RuntimeError('Opened process identity mismatch')
    process = psutil.Process(pid)
    created = process.create_time()
    if (os.path.normcase(str(Path(process.exe()).resolve())) != expected or
        started is not None and created != started):
        raise RuntimeError('Original process path or creation time changed')
    return created


def guarded_read(api, handle, image, base, size, rva, length, report=None):
    address, info = base+rva, Memory()
    if not (executable_backed(image, rva, length) and rva+length <= size and
        api.VirtualQueryEx(handle, address, C.byref(info), C.sizeof(info)) == C.sizeof(info) and
        info.State == 0x1000 and info.Type == 0x1000000 and info.AllocationBase == base and
        (info.Protect & 0xff) in (0x10, 0x20, 0x40, 0x80) and not info.Protect & 0x100 and
        info.BaseAddress <= address < address+length <= info.BaseAddress+info.RegionSize):
        raise RuntimeError('Image executable page guard not satisfied')
    buffer, copied = (C.c_ubyte*length)(), C.c_size_t()
    if report is not None:
        if report['actual_read_count'] >= MAX_READS or report['rpm_requested_bytes']+length > MAX_CODE_BYTES:
            raise RuntimeError('Sender body actual RPM count/byte budget exceeded')
        report['actual_read_count'] += 1
        report['rpm_requested_bytes'] += length
    if not api.ReadProcessMemory(handle, address, buffer, length, C.byref(copied)) or copied.value != length:
        raise RuntimeError('Bounded sender body image read failed or was incomplete')
    return bytes(buffer)


def collect(game_root, folder):
    game_root, folder = Path(game_root), Path(folder)
    plan = build_plan(game_root)
    executable = game_root/EXECUTABLE_RELATIVE
    folder.mkdir(parents=True, exist_ok=True)
    save(folder/'plan.json', plan)
    report = {'kind': 'bounded_sender_body_code_read', 'client_sha256': SOURCE_SHA,
        'offline_plan': plan, 'functions': [], 'maximum_reads': MAX_READS, 'maximum_code_bytes': MAX_CODE_BYTES,
        'actual_read_count': 0, 'attempted_read_count': 0, 'rpm_requested_bytes': 0,
        'actual_code_bytes': 0, 'attempted_code_bytes': 0,
        'read_count_unit': 'ReadProcessMemory invocations',
        'attempted_read_count_unit': 'fixed function request attempts',
        'actual_code_bytes_unit': 'verified saved code bytes',
        'client_launched': False, 'elevation_requested': False, 'game_modified': False,
        'process_memory_written': False, 'credential_memory_read': False, 'live_object_or_vtable_read': False,
        'actual_instance_table_ownership_verified': False, 'base_implementation_role_verified': False,
        'packet_header_writer_role_verified': False, 'playable_map_verified': False,
        'observed_at_utc': datetime.now(timezone.utc).isoformat()}
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
        expected = os.path.normcase(str(executable.resolve()))
        started = process_identity(api, handle, pids[0], expected)
        snapshot = api.CreateToolhelp32Snapshot(0x18, pids[0])
        if not snapshot or snapshot == C.c_void_p(-1).value:
            raise RuntimeError('Executable module snapshot unavailable')
        item = Module()
        item.dwSize = C.sizeof(item)
        matches, examined = [], 0
        ok = api.Module32FirstW(snapshot, C.byref(item))
        while ok:
            examined += 1
            if examined > 4096:
                raise RuntimeError('Executable module snapshot entry bound exceeded')
            if os.path.normcase(str(Path(item.szExePath).resolve())) == expected:
                matches.append((item.modBaseAddr, item.modBaseSize))
            ok = api.Module32NextW(snapshot, C.byref(item))
        if len(matches) != 1 or not matches[0][0]:
            raise RuntimeError('Verified executable module unavailable or ambiguous')
        base, size = matches[0]
        with executable.open('rb') as stream, mmap.mmap(stream.fileno(), 0, access=mmap.ACCESS_READ) as raw:
            image = Image(raw)
            if validate_image(image) != plan or size != image.size:
                raise RuntimeError('Sender body source evidence or module size changed')
            prefix = source_prefix(sealed_json(FIXED_PLAN, FIXED_PLAN_SHA))
            reads = list(plan['initial_reads'])
            for root in reads:
                if (len(reads) > MAX_READS or report['attempted_read_count'] >= MAX_READS or
                    report['attempted_code_bytes']+root['code_bytes'] > MAX_CODE_BYTES):
                    raise RuntimeError('Sender body fixed read/byte budget exceeded')
                rva, length = int(root['read_rva'], 16), root['code_bytes']
                process_identity(api, handle, pids[0], expected, started)
                entry = {'name': root['label'], 'rva': hex(rva), 'code_bytes': length,
                         'read_succeeded': False, 'immutable_source_evidence': root}
                report['functions'].append(entry)
                report['attempted_read_count'] += 1
                report['attempted_code_bytes'] += length
                code = guarded_read(api, handle, image, base, size, rva, length, report)
                process_identity(api, handle, pids[0], expected, started)
                saved = struct.pack('<4Q', MAGIC, rva, length, base)+code
                decoder = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
                instructions = list(decoder.disasm(code, rva))
                entry.update(read_succeeded=True, code_sha256=sha(code), file_sha256=sha(saved),
                    disassembled_bytes=sum(i.size for i in instructions))
                report['actual_code_bytes'] += length
                (folder/(root['label']+'.dfcode')).write_bytes(saved)
                (folder/(root['label']+'.asm.txt')).write_text('\n'.join(
                    f'{i.address:#x}: {i.mnemonic} {i.op_str}' for i in instructions)+'\n', encoding='utf-8')
                if rva == PREFIX_RVA:
                    entry['wrapper_verification'] = validate_wrapper(code, prefix)
                elif rva == CONTROL_RVA:
                    try:
                        direct = conditional_e8(code)
                    except ValueError as error:
                        entry['conditional_target_not_read'] = str(error)
                        report['status'] = 'bounded_read_conditional_refused'
                        save(folder/'result.json', report)
                        break
                    direct['source_file_sha256'] = entry['file_sha256']
                    direct['independent_target_source_evidence'] = plan['conditional_single_e8_read']
                    entry['conditional_direct_e8_proof'] = direct
                    reads.append(plan['conditional_single_e8_read'])
                save(folder/'result.json', report)
            if report.get('status') != 'bounded_read_conditional_refused':
                if report['actual_read_count'] != MAX_READS or report['actual_code_bytes'] != MAX_CODE_BYTES:
                    raise RuntimeError('Sender body fixed successful coverage mismatch')
                report['status'] = 'bounded_read_attempt_complete'
    except Exception as error:
        report.update(status='bounded_read_failed', error_type=type(error).__name__)
        if isinstance(error, (RuntimeError, ValueError)):
            report['error_reason'] = str(error)
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
    mode.add_argument('--validate-plan', action='store_true', help='Default: immutable files only')
    mode.add_argument('--collect', action='store_true', help='Explicitly read one existing pinned process')
    parser.add_argument('--output-dir', type=Path, help='Required only for explicit --collect')
    return parser


if __name__ == '__main__':
    parser = argument_parser()
    args = parser.parse_args()
    if args.collect:
        if args.output_dir is None:
            parser.error('--collect requires --output-dir')
        report = collect(args.game_root, args.output_dir)
        print(report['status'])
        raise SystemExit(0 if report['status'] == 'bounded_read_attempt_complete' else 1)
    if args.output_dir is not None:
        parser.error('--output-dir is only used with --collect')
    plan = build_plan(args.game_root)
    PLAN_OUTPUT.parent.mkdir(parents=True, exist_ok=True)
    save(PLAN_OUTPUT, plan)
    print('Offline sender-body plan validated: 2 initial reads/499 bytes; conditional third read, max3737 bytes. No process access.')
