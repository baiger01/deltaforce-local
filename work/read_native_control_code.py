"""Optional bounded image-code read for exact native control/bunch anchors.

The default command validates the offline plan only. --collect reads an already
running, version-pinned client using ordinary process permissions; this module
never launches a client, requests elevation, writes process memory, follows a
live pointer, or traverses a type-adapter graph. Obtaining these code samples is
not proof that the native control protocol or playable map has been restored.
--candidate-interval opts in to thirteen fixed unknown code roots with no follow.
--field-helpers opts in to three source-proved direct helper roots with no follow.
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
from capstone.x86 import X86_OP_IMM, X86_OP_MEM, X86_REG_RIP
import pefile
import psutil

from capture_official_ds import SOURCE_SHA, digest, verified_pids, save
from read_named_ds_transport_code import kernel, Module, Memory

ROOT = Path(__file__).resolve().parent.parent
EXECUTABLE_RELATIVE = Path('DeltaForce/Binaries/Win64/DeltaForceClient-Win64-Shipping.exe')
PLAN_OUTPUT = ROOT / 'work/evidence/native-control-code-plan.json'
CANDIDATE_PLAN = ROOT / 'work/evidence/native-control-bounded-candidate-plan.json'
CANDIDATE_PLAN_SHA = 'f33463b61a22a4c74f68f613aa509841ab44ba15d6a917326821ba1fde9f9dc6'
CANDIDATE_PLAN_OUTPUT = ROOT / 'work/evidence/native-control-candidate-code-plan.json'
CANDIDATE_LOW, CANDIDATE_HIGH = 0x128635d0, 0x12867ac0
CANDIDATE_CODE_BYTES, CANDIDATE_READS, CANDIDATE_ENTRIES = 17564, 13, 43
FIELD_PLAN = ROOT / 'work/evidence/native-control-field-helper-source-plan.json'
FIELD_PLAN_SHA = 'b0c5a19b073431d9071ab3dd8c15ea3b9216ed81291d0bd652f2287dee6cbef4'
FIELD_PLAN_OUTPUT = ROOT / 'work/evidence/native-control-field-helper-code-plan.json'
FIELD_SOURCE_SAMPLE = ROOT / ('work/native-client-tests/1790852438755252500/'
                              'ds-native-control-code/unknown_128668d0.dfcode')
FIELD_SOURCE_FILE_SHA = 'ce504dacd1b93b617c54b872ec468660b05bf6cfd37fce6f388d5c2617140353'
FIELD_SOURCE_CODE_SHA = '33eacb39840b9cc13600d0b23fe64f0a5fe459ce751cf1c4c6fccc4152837cb2'
FIELD_SOURCE_RVA, FIELD_SOURCE_BYTES, FIELD_SOURCE_CODE_END = 0x128668d0, 3784, 0x12867722
FIELD_PDATA_RVA, FIELD_PDATA_BYTES = 0x1e5d1000, 15300936
FIELD_PDATA_SHA = 'aae32c4f1cc7196c7a2b78a4adc4e5dae29e5a200ad7415ab2ed69f06cd70d5e'
FIELD_READS, FIELD_BYTES = 3, 2487
FIELD_MAX_PLAN_BYTES = 256 * 1024
FIELD_TARGETS = (
    (0x109ea340, 0x109ea9cf, 0x1bdd77ec, 1679,
     (0x12866fdf, 0x128670ee, 0x12867203, 0x12867251, 0x1286725e,
      0x1286726b, 0x128672ee, 0x12867359, 0x12867366, 0x1286737f,
      0x128673a6, 0x128673ec, 0x12867462, 0x128674d5, 0x1286755c)),
    (0x12bab170, 0x12bab34a, 0x1bf5bcf0, 474,
     (0x12867373, 0x128673f9, 0x128674e2)),
    (0x1779fa0, 0x177a0ee, 0x1bdcb484, 334, (0x12867424, 0x12867445)),
)
PREFIX_BYTES = 32
MAX_FUNCTION_BYTES = 8192
MAX_UNWIND_ENTRIES = 32
COMPLETION_RVA = 0x12430d90
COMPLETION_ROOT = (COMPLETION_RVA, 0x12430db5, 0x1bdcdad4)
COMPLETION_FRAGMENTS = ((COMPLETION_RVA, 0x12430db5), (0x12430db5, 0x12430dde),
                       (0x12430dde, 0x12430e68), (0x12430e68, 0x12430e84),
                       (0x12430e84, 0x12430e8b))
COMPLETION_BYTES = COMPLETION_FRAGMENTS[-1][1] - COMPLETION_RVA
LOWER_RVA = 0x12867ac0
LOWER_ROOT = (LOWER_RVA, 0x12868710, 0x1bf59918)
LOWER_BYTES = LOWER_ROOT[1] - LOWER_RVA
SOURCE_SAMPLE = ROOT / 'work/native-client-tests/1790778056317888200/ds-vtable-slot4-candidate.dfcode'
SOURCE_FILE_SHA = '7c793921a98866d1653f96de07c2656bfbf4ec668fc5ce2bafc26670f9f87523'
SOURCE_CODE_SHA = '6c6b6ca77a23a366a6d7c428465bdf191636f2e130de0a6cdb9151f6eb39f46e'
SOURCE_RVA, SOURCE_BYTES, SOURCE_CALL_RVA = 0x12bb9b40, 1069, 0x12bb9f1a
LOWER_SOURCE_SAMPLE = ROOT / ('work/native-client-tests/1790845340083127000/'
                            'ds-native-control-code/UChannel.ReceivedRawBunch.implementation.dfcode')
LOWER_SOURCE_FILE_SHA = 'bacb1a352f80e702802a30e272ddc3e7a4b4a0b47a49987186c45c64a3f4f0b0'
LOWER_SOURCE_CODE_SHA = '06c81120e891c6a4ef02a408fc5bf19271f0419d9521316ebcfaebca2dd00773'
LOWER_SOURCE_RVA, LOWER_SOURCE_BYTES, LOWER_CALL_RVA = 0x12868710, 944, 0x12868922
LOWER_LOGS = (
    (0x1286893a, 0x1b149650,
     'UChannel::ReceivedRawBunch: Bunch.IsError() after ReceivedNextBunch 1'),
    (0x12868a7e, 0x1b1497e0,
     'UChannel::ReceivedRawBunch: Bunch.IsError() after ReceivedNextBunch 2'),
)
VOID_RVA, BOOL_RVA = 0x14edf3dc, 0x14ee4878
BINDINGS = (
    {'label': 'FNetworkNotify.NotifyControlMessage', 'method': 'NotifyControlMessage',
     'record': 0x1b35f170, 'name': 0x1b361da0, 'code': 0xe8c420,
     'invoker': 0x1247f10, 'returns': ('void', VOID_RVA), 'arguments': 0x1d790280,
     'types': (('FNetworkNotify *', 0x1612f5b0), ('UNetConnection *', 0x15036df0),
               ('unsigned char', 0x15056fc8), ('FInBunch *', 0x1612fbc8))},
    {'label': 'UChannel.ReceivedRawBunch', 'method': 'ReceivedRawBunch',
     'record': 0x1b42f080, 'name': 0x1b4334e0, 'code': 0x13149d40,
     'invoker': 0xdffaa0, 'returns': ('void', VOID_RVA), 'arguments': 0x1d7a94b8,
     'types': (('UChannel *', 0x16076050), ('FInBunch *', 0x1612fbc8),
               ('bool *', 0x14ede548))},
    {'label': 'UChannel.ReceivedSequencedBunch', 'method': 'ReceivedSequencedBunch',
     'record': 0x1b42f050, 'name': 0x1b433490, 'code': 0x13149a80,
     'invoker': 0xdfe010, 'returns': ('bool', BOOL_RVA), 'arguments': 0x1d7a94a0,
     'types': (('UChannel *', 0x16076050), ('FInBunch *', 0x1612fbc8))},
    {'label': 'UControlChannel.ReceivedBunch', 'method': 'ReceivedBunch',
     'record': 0x1b3e8bf0, 'name': 0x1624c548, 'code': 0xe08180,
     'invoker': 0xdfea50, 'returns': ('void', VOID_RVA), 'arguments': 0x1d7a11f8,
     'types': (('UControlChannel *', 0x1b3eb790), ('FInBunch *', 0x1612fbc8))},
    {'label': 'UControlChannel.CheckEndianess', 'method': 'CheckEndianess',
     'record': 0x1b3e8ad0, 'name': 0x1b3ec150, 'code': 0x1311f310,
     'invoker': 0xdfe010, 'returns': ('bool', BOOL_RVA), 'arguments': 0x1d7a1040,
     'types': (('UControlChannel *', 0x1b3eb790), ('FInBunch *', 0x1612fbc8))},
    {'label': 'UControlChannel.QueueMessage', 'method': 'QueueMessage',
     'record': 0x1b3e8b00, 'name': 0x1b3ec1b8, 'code': 0x1311f360,
     'invoker': 0xdfea50, 'returns': ('void', VOID_RVA), 'arguments': 0x1d7a10c8,
     'types': (('UControlChannel *', 0x1b3eb790), ('FOutBunch *', 0x15768828))},
)
MAX_CODE_BYTES = (len(BINDINGS) * PREFIX_BYTES + COMPLETION_BYTES + LOWER_BYTES +
                  len(BINDINGS) * MAX_FUNCTION_BYTES)
MAX_READS = 2 * len(BINDINGS) + 2


class Image:
    """Immutable PE metadata only; no process-pointer resolution."""
    def __init__(self, raw):
        self.raw = raw
        self.pe = pefile.PE(data=raw, fast_load=True)
        self.base = self.pe.OPTIONAL_HEADER.ImageBase
        self.size = self.pe.OPTIONAL_HEADER.SizeOfImage
        directory = self.pe.OPTIONAL_HEADER.DATA_DIRECTORY[3]
        self.unwind_offset = self.pe.get_offset_from_rva(directory.VirtualAddress)
        self.unwind_count = directory.Size // 12

    def executable(self, rva, length=1):
        return length > 0 and any(s.Characteristics & 0x20000000 and
            s.VirtualAddress <= rva < rva + length <= s.VirtualAddress + s.Misc_VirtualSize
            for s in self.pe.sections)

    def data(self, rva, length):
        if length <= 0 or not any(not s.Characteristics & 0x20000000 and
                s.VirtualAddress <= rva < rva + length <= s.VirtualAddress + s.SizeOfRawData
                for s in self.pe.sections):
            raise ValueError('Reflection reference is outside immutable image data')
        offset = self.pe.get_offset_from_rva(rva)
        result = bytes(self.raw[offset:offset + length])
        if len(result) != length:
            raise ValueError('Immutable data is truncated')
        return result

    def label(self, rva, expected):
        if self.data(rva, len(expected) + 1) != expected.encode('ascii') + b'\0':
            raise ValueError('Reflection string mismatch')

    def unwind_entry(self, index):
        return struct.unpack_from('<III', self.raw, self.unwind_offset + index * 12)

    def function_span(self, rva):
        """Exact root and contiguous CHAININFO descendants of that same root.

        A continuation may name an earlier accepted continuation rather than
        the root directly. Requiring the exact parent triple to be in this
        already proven function preserves the root by induction. No arbitrary
        metadata graph, noncontiguous range, or live pointer is followed.
        """
        low, high = 0, self.unwind_count
        while low < high:
            middle = (low + high) // 2
            if self.unwind_entry(middle)[0] < rva:
                low = middle + 1
            else:
                high = middle
        if low >= self.unwind_count or self.unwind_entry(low)[0] != rva:
            raise ValueError('Direct target is not an exact unwind root')
        root = self.unwind_entry(low)
        offset = self.pe.get_offset_from_rva(root[2])
        flags = self.raw[offset]
        if flags & 7 != 1 or flags >> 3 & 4:
            raise ValueError('Direct target is an unwind continuation')
        end, fragments, accepted = root[1], [root[:2]], {root}
        for index in range(low + 1, min(self.unwind_count, low + MAX_UNWIND_ENTRIES + 1)):
            entry = self.unwind_entry(index)
            if entry[0] != end:
                break
            offset = self.pe.get_offset_from_rva(entry[2])
            flags, _, count, _ = struct.unpack_from('<4B', self.raw, offset)
            if flags & 7 != 1 or flags >> 3 != 4:
                break
            chain = offset + 4 + 4 * ((count + 1) // 2)
            if struct.unpack_from('<III', self.raw, chain) not in accepted:
                break
            if index >= low + MAX_UNWIND_ENTRIES:
                raise ValueError('Complete unwind function exceeds the fragment budget')
            if not entry[0] < entry[1] <= rva + MAX_FUNCTION_BYTES:
                raise ValueError('Unwind continuation exceeds function bounds')
            end = entry[1]
            fragments.append(entry[:2])
            accepted.add(entry)
        if not rva < end <= rva + MAX_FUNCTION_BYTES or not self.executable(rva, end - rva):
            raise ValueError('Direct implementation exceeds executable function bounds')
        return root, end - rva, fragments


def validate_bindings(image):
    rows = []
    for entry in BINDINGS:
        returns, return_rva = entry['returns']
        expected = (image.base + entry['name'], image.base + entry['code'],
                    image.base + entry['invoker'], image.base + return_rva,
                    image.base + entry['arguments'], len(entry['types']))
        if struct.unpack('<6Q', image.data(entry['record'], 48)) != expected:
            raise ValueError('Complete six-qword reflection record mismatch')
        image.label(entry['name'], entry['method'])
        image.label(return_rva, returns)
        pointers = tuple(image.base + rva for _, rva in entry['types'])
        if struct.unpack('<' + 'Q' * len(pointers),
                image.data(entry['arguments'], len(pointers) * 8)) != pointers:
            raise ValueError('Complete reflection argument table mismatch')
        for typename, rva in entry['types']:
            image.label(rva, typename)
        if not image.executable(entry['code'], PREFIX_BYTES) or not image.executable(entry['invoker']):
            raise ValueError('Named prefix or invoker is outside image code')
        rows.append({'label': entry['label'], 'method': entry['method'],
            'record_rva': hex(entry['record']), 'name_string_rva': hex(entry['name']),
            'implementation_rva': hex(entry['code']), 'invoker_rva': hex(entry['invoker']),
            'return_type': returns, 'arguments_table_rva': hex(entry['arguments']),
            'argument_types': [name for name, _ in entry['types']], 'prefix_bytes': PREFIX_BYTES,
            'complete_record_and_parameters_verified': True})
    return rows


def validate_source_sample(sample):
    if hashlib.sha256(sample).hexdigest() != SOURCE_FILE_SHA or len(sample) != SOURCE_BYTES + 32:
        raise ValueError('Handshake source sample file identity mismatch')
    magic, rva, length, _private_module_base = struct.unpack('<4Q', sample[:32])
    code = sample[32:]
    if (magic != 0x0000000145444344 or (rva, length) != (SOURCE_RVA, SOURCE_BYTES) or
            hashlib.sha256(code).hexdigest() != SOURCE_CODE_SHA):
        raise ValueError('Handshake source sample code identity mismatch')
    decoder = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
    decoder.detail = True
    instructions = list(decoder.disasm(code, rva))
    call = next((i for i in instructions if i.address == SOURCE_CALL_RVA), None)
    if (sum(i.size for i in instructions) != len(code) or call is None or
            call.mnemonic != 'call' or call.size != 5 or call.bytes[0] != 0xe8 or
            len(call.operands) != 1 or call.operands[0].type != X86_OP_IMM or
            call.operands[0].imm != COMPLETION_RVA):
        raise ValueError('Saved direct completion CALL evidence mismatch')
    return {'source_relative_to_project_root': SOURCE_SAMPLE.relative_to(ROOT).as_posix(),
            'file_sha256': SOURCE_FILE_SHA, 'code_sha256': SOURCE_CODE_SHA,
            'source_rva': hex(SOURCE_RVA), 'source_code_bytes': SOURCE_BYTES,
            'call_rva': hex(SOURCE_CALL_RVA), 'call_instruction_bytes': bytes(call.bytes).hex(),
            'direct_target_rva': hex(COMPLETION_RVA), 'direct_call_verified': True}


def validate_lower_source_sample(sample):
    """One fixed direct E8 in the saved, named RawBunch implementation."""
    if (hashlib.sha256(sample).hexdigest() != LOWER_SOURCE_FILE_SHA or
            len(sample) != LOWER_SOURCE_BYTES + 32):
        raise ValueError('RawBunch source sample file identity mismatch')
    magic, rva, length, _private_module_base = struct.unpack('<4Q', sample[:32])
    code = sample[32:]
    if (magic != 0x0000000145444344 or (rva, length) != (LOWER_SOURCE_RVA, LOWER_SOURCE_BYTES) or
            hashlib.sha256(code).hexdigest() != LOWER_SOURCE_CODE_SHA):
        raise ValueError('RawBunch source sample code identity mismatch')
    decoder = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
    decoder.detail = True
    instructions = list(decoder.disasm(code, rva))
    call = next((i for i in instructions if i.address == LOWER_CALL_RVA), None)
    if (sum(i.size for i in instructions) != len(code) or call is None or
            call.mnemonic != 'call' or call.size != 5 or call.bytes[0] != 0xe8 or
            len(call.operands) != 1 or call.operands[0].type != X86_OP_IMM or
            call.operands[0].imm != LOWER_RVA):
        raise ValueError('Saved RawBunch direct CALL evidence mismatch')
    log_references = []
    for instruction_rva, label_rva, expected_text in LOWER_LOGS:
        ins = next((i for i in instructions if i.address == instruction_rva), None)
        if (ins is None or ins.mnemonic != 'lea' or len(ins.operands) != 2 or
                ins.operands[1].type != X86_OP_MEM or ins.operands[1].mem.base != X86_REG_RIP or
                ins.address + ins.size + ins.operands[1].mem.disp != label_rva):
            raise ValueError('Saved RawBunch log reference mismatch')
        log_references.append({'instruction_rva': hex(instruction_rva),
                               'string_rva': hex(label_rva), 'text': expected_text})
    return {'source_relative_to_project_root': LOWER_SOURCE_SAMPLE.relative_to(ROOT).as_posix(),
            'file_sha256': LOWER_SOURCE_FILE_SHA, 'code_sha256': LOWER_SOURCE_CODE_SHA,
            'source_rva': hex(LOWER_SOURCE_RVA), 'source_code_bytes': LOWER_SOURCE_BYTES,
            'call_rva': hex(LOWER_CALL_RVA), 'call_instruction_bytes': bytes(call.bytes).hex(),
            'direct_target_rva': hex(LOWER_RVA), 'direct_call_verified': True,
            'caller_log_references': log_references,
            'role': 'UChannel::ReceivedNextBunch, supported by caller log strings; no symbol-name claim'}


def validate_candidate_interval(image):
    """Revalidate a hash-locked fixed interval; proximity proves no method name."""
    sealed = CANDIDATE_PLAN.read_bytes()
    if hashlib.sha256(sealed).hexdigest() != CANDIDATE_PLAN_SHA:
        raise ValueError('Fixed candidate plan file identity mismatch')
    evidence = json.loads(sealed)
    if (evidence['client_sha256'] != SOURCE_SHA or
            hashlib.sha256(image.raw).hexdigest() != SOURCE_SHA):
        raise ValueError('Candidate image version hash mismatch')
    low, high = CANDIDATE_LOW, CANDIDATE_HIGH
    bounds = evidence['fixed_range']
    if (int(bounds['start_rva'], 16) != low or int(bounds['end_rva_exclusive'], 16) != high or
            high - low != 17648 or bounds['read_budget_bytes'] != high - low or
            not image.executable(low, high - low)):
        raise ValueError('Fixed candidate interval bounds mismatch')
    directory = image.pe.OPTIONAL_HEADER.DATA_DIRECTORY[3]
    pdata = evidence['pdata']
    if (directory.VirtualAddress != int(pdata['rva'], 16) or directory.Size != pdata['bytes'] or
            image.unwind_count != pdata['entry_count'] or directory.Size % 12 or
            hashlib.sha256(image.data(directory.VirtualAddress, directory.Size)).hexdigest() != pdata['sha256']):
        raise ValueError('Candidate complete pdata identity mismatch')
    entries = evidence['runtime_function_entries']
    if len(entries) != CANDIDATE_ENTRIES:
        raise ValueError('Candidate unwind entry count mismatch')
    actual_entries = []
    for entry in entries:
        triple = tuple(int(value, 16) for value in entry['entry'])
        begin, end, unwind = triple
        if not low <= begin < end <= high:
            raise ValueError('Candidate unwind entry crosses fixed interval')
        metadata = image.data(unwind, entry['metadata_bytes'])
        if hashlib.sha256(metadata).hexdigest() != entry['metadata_sha256']:
            raise ValueError('Candidate unwind metadata identity mismatch')
        flags, _, count, _ = struct.unpack_from('<4B', metadata)
        version, flags = flags & 7, flags >> 3
        expected_bytes = 4 + 4 * ((count + 1) // 2) + (12 if flags & 4 else 0)
        if (version != 1 or version != entry['version'] or flags != entry['flags'] or
                len(metadata) != expected_bytes):
            raise ValueError('Candidate unwind metadata shape mismatch')
        parent = None if not flags & 4 else list(struct.unpack_from('<III', metadata, expected_bytes - 12))
        expected_parent = entry['chain_parent']
        if parent != (None if expected_parent is None else [int(x, 16) for x in expected_parent]):
            raise ValueError('Candidate unwind chain parent mismatch')
        actual_entries.append(triple)
    # Only the exact interval entries are admitted, including every continuation.
    first, last = 0, image.unwind_count
    while first < last:
        middle = (first + last) // 2
        if image.unwind_entry(middle)[0] < low:
            first = middle + 1
        else:
            last = middle
    index, interval_entries = first, []
    while index < image.unwind_count and image.unwind_entry(index)[0] < high:
        interval_entries.append(image.unwind_entry(index))
        index += 1
    if interval_entries != actual_entries or first == 0 or index >= image.unwind_count:
        raise ValueError('Candidate exact interval pdata records mismatch')
    if (image.unwind_entry(first - 1) != tuple(int(x, 16) for x in bounds['previous_exact_root']) or
            image.unwind_entry(index) != tuple(int(x, 16) for x in bounds['following_exact_root'])):
        raise ValueError('Candidate adjacent boundary roots mismatch')
    candidates = evidence['candidate_roots']
    if len(candidates) != CANDIDATE_READS:
        raise ValueError('Candidate fixed read-count mismatch')
    validated, covered, total, preceding_end = [], [], 0, low
    for candidate in candidates:
        rva = int(candidate['read_rva'], 16)
        length = candidate['code_bytes']
        end = int(candidate['end_rva'], 16)
        if (type(length) is not int or not 0 < length <= MAX_FUNCTION_BYTES or
                not low <= rva < end <= high or end - rva != length or rva < preceding_end or
                not image.executable(rva, length) or candidate['method_role_verified'] is not False or
                candidate['label'] != 'unknown_' + hex(rva)[2:]):
            raise ValueError('Candidate root bounds or identity-claim mismatch')
        root, actual_length, fragments = image.function_span(rva)
        expected_root = tuple(int(x, 16) for x in candidate['root'])
        expected_fragments = [tuple(int(x, 16) for x in part) for part in candidate['unwind_fragments']]
        if (root != expected_root or actual_length != length or fragments != expected_fragments or
                len(fragments) > MAX_UNWIND_ENTRIES or len(fragments) - 1 != candidate['continuations']):
            raise ValueError('Candidate complete same-root function boundary mismatch')
        covered.extend(fragments)
        total += length
        preceding_end = end
        validated.append({'label': candidate['label'], 'rva': hex(rva),
            'code_bytes': length, 'unwind_root': [hex(x) for x in root],
            'unwind_fragments': [[hex(a), hex(b)] for a, b in fragments],
            'method_role_verified': False})
    if covered != [entry[:2] for entry in actual_entries] or total != CANDIDATE_CODE_BYTES:
        raise ValueError('Candidate complete coverage or total-byte bound mismatch')
    return {'kind': 'fixed_unknown_control_candidate_code_plan', 'client_sha256': SOURCE_SHA,
        'client_relative_to_game_root': EXECUTABLE_RELATIVE.as_posix(),
        'candidate_interval': True, 'candidate_evidence_sha256': CANDIDATE_PLAN_SHA,
        'candidate_evidence_relative_to_project_root': CANDIDATE_PLAN.relative_to(ROOT).as_posix(),
        'process_memory_read': False, 'client_launched': False, 'elevation_requested': False,
        'image_modified': False, 'live_object_or_vtable_read': False,
        'candidate_roots': validated, 'fixed_read_count': CANDIDATE_READS,
        'initial_read_bytes': CANDIDATE_CODE_BYTES, 'maximum_code_bytes': CANDIDATE_CODE_BYTES,
        'maximum_reads': CANDIDATE_READS, 'maximum_unwind_entries_per_function': MAX_UNWIND_ENTRIES,
        'follow_policy': 'fixed candidate roots only; no direct or indirect target follow',
        'candidate_method_identity_verified': False, 'native_control_logic_verified': False,
        'playable_map_verified': False, 'status': 'offline_plan_validated',
        'observed_at_utc': datetime.now(timezone.utc).isoformat()}


def sealed_field_plan():
    if not 0 < FIELD_PLAN.stat().st_size <= FIELD_MAX_PLAN_BYTES:
        raise ValueError('Field-helper plan file exceeds fixed size bound')
    with FIELD_PLAN.open('rb') as stream:
        sealed = stream.read(FIELD_MAX_PLAN_BYTES + 1)
    if len(sealed) > FIELD_MAX_PLAN_BYTES or hashlib.sha256(sealed).hexdigest() != FIELD_PLAN_SHA:
        raise ValueError('Field-helper plan file identity mismatch')
    return json.loads(sealed)


def validate_field_source_sample(sample, evidence):
    """Check only the sealed source's executable range, excluding its switch table."""
    if (len(sample) != FIELD_SOURCE_BYTES + 32 or
            hashlib.sha256(sample).hexdigest() != FIELD_SOURCE_FILE_SHA):
        raise ValueError('Field-helper source sample file identity mismatch')
    magic, rva, length, _private_module_base = struct.unpack('<4Q', sample[:32])
    code = sample[32:]
    if (magic != 0x0000000145444344 or (rva, length) != (FIELD_SOURCE_RVA, FIELD_SOURCE_BYTES) or
            hashlib.sha256(code).hexdigest() != FIELD_SOURCE_CODE_SHA):
        raise ValueError('Field-helper source sample header/code identity mismatch')
    expected_range = [[hex(FIELD_SOURCE_RVA), hex(FIELD_SOURCE_CODE_END)]]
    if (evidence.get('source_sample_relative_path') != FIELD_SOURCE_SAMPLE.relative_to(ROOT).as_posix() or
            evidence.get('source_file_sha256') != FIELD_SOURCE_FILE_SHA or
            evidence.get('source_code_sha256') != FIELD_SOURCE_CODE_SHA or
            evidence.get('source_header_rva') != hex(FIELD_SOURCE_RVA) or
            evidence.get('source_payload_bytes') != FIELD_SOURCE_BYTES or
            evidence.get('source_code_ranges') != expected_range or
            evidence.get('source_jump_table_excluded') is not True):
        raise ValueError('Field-helper source evidence scope mismatch')
    rows = evidence.get('fixed_direct_targets')
    if not isinstance(rows, list) or len(rows) != FIELD_READS:
        raise ValueError('Field-helper fixed target count mismatch')
    decoder = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
    decoder.detail = True
    instructions = list(decoder.disasm(code[:FIELD_SOURCE_CODE_END-rva], rva))
    if sum(i.size for i in instructions) != FIELD_SOURCE_CODE_END-rva:
        raise ValueError('Field-helper source executable range does not fully decode')
    by_rva = {i.address: i for i in instructions}
    actual_calls = {target: [] for target, *_ in FIELD_TARGETS}
    for ins in instructions:
        if (ins.mnemonic == 'call' and ins.size == 5 and ins.bytes[0] == 0xe8 and
                len(ins.operands) == 1 and ins.operands[0].type == X86_OP_IMM and
                ins.operands[0].imm in actual_calls):
            actual_calls[ins.operands[0].imm].append(ins.address)
    verified_calls = []
    for row, (target, end, unwind, target_bytes, call_rvas) in zip(rows, FIELD_TARGETS):
        declared = row.get('source_direct_calls')
        if (row.get('read_rva') != hex(target) or not isinstance(declared, list) or
                len(declared) != len(call_rvas) or tuple(actual_calls[target]) != call_rvas):
            raise ValueError('Field-helper fixed source call count/target mismatch')
        for call, expected_rva in zip(declared, call_rvas):
            ins = by_rva.get(expected_rva)
            if (not isinstance(call, dict) or call.get('instruction_rva') != hex(expected_rva) or
                    call.get('direct_target_rva') != hex(target) or ins is None or
                    ins.mnemonic != 'call' or ins.size != 5 or ins.bytes[0] != 0xe8 or
                    not rva <= ins.address < ins.address+5 <= FIELD_SOURCE_CODE_END or
                    ins.operands[0].type != X86_OP_IMM or ins.operands[0].imm != target or
                    ins.address+5+struct.unpack('<i', ins.bytes[1:])[0] != target or
                    call.get('instruction_bytes_hex') != bytes(ins.bytes).hex()):
                raise ValueError('Field-helper exact E8 source instruction mismatch')
            verified_calls.append({'call_rva': hex(expected_rva), 'target_rva': hex(target),
                                   'instruction_bytes': bytes(ins.bytes).hex()})
    if len(verified_calls) != 20:
        raise ValueError('Field-helper total source call count mismatch')
    return {'source_relative_to_project_root': FIELD_SOURCE_SAMPLE.relative_to(ROOT).as_posix(),
            'file_sha256': FIELD_SOURCE_FILE_SHA, 'code_sha256': FIELD_SOURCE_CODE_SHA,
            'source_rva': hex(rva), 'source_payload_bytes': length,
            'verified_source_code_ranges': expected_range, 'jump_table_excluded': True,
            'verified_direct_e8_calls': verified_calls, 'call_count': len(verified_calls)}


def validate_field_helpers(image):
    evidence = sealed_field_plan()
    if (evidence.get('kind') != 'native_control_field_helper_fixed_source_plan' or
            evidence.get('client_sha256') != SOURCE_SHA or
            evidence.get('client_relative_executable') != EXECUTABLE_RELATIVE.as_posix() or
            evidence.get('plan_only') is not True or hashlib.sha256(image.raw).hexdigest() != SOURCE_SHA):
        raise ValueError('Field-helper image/source-plan identity mismatch')
    if FIELD_SOURCE_SAMPLE.stat().st_size != FIELD_SOURCE_BYTES + 32:
        raise ValueError('Field-helper source sample file length mismatch')
    with FIELD_SOURCE_SAMPLE.open('rb') as stream:
        sample = stream.read(FIELD_SOURCE_BYTES + 33)
    source = validate_field_source_sample(sample, evidence)
    directory = image.pe.OPTIONAL_HEADER.DATA_DIRECTORY[3]
    if (directory.VirtualAddress != FIELD_PDATA_RVA or directory.Size != FIELD_PDATA_BYTES or
            directory.Size % 12 or image.unwind_count != FIELD_PDATA_BYTES // 12 or
            hashlib.sha256(image.data(FIELD_PDATA_RVA, FIELD_PDATA_BYTES)).hexdigest() != FIELD_PDATA_SHA):
        raise ValueError('Field-helper complete pdata identity mismatch')
    validated, total = [], 0
    for row, (target, end, unwind, length, _) in zip(evidence['fixed_direct_targets'], FIELD_TARGETS):
        expected_root = (target, end, unwind)
        expected_fragments = [(target, end)]
        if (row.get('root') != [hex(x) for x in expected_root] or row.get('code_bytes') != length or
                row.get('end_rva_exclusive') != hex(end) or row.get('fragment_count') != 1 or
                row.get('unwind_fragments') != [[hex(target), hex(end)]] or
                row.get('root_is_chain_continuation') is not False or
                row.get('label') != 'unknown_control_field_' + format(target, 'x') or
                not 0 < length <= MAX_FUNCTION_BYTES or
                not image.executable(target, length) or
                not any(s.Characteristics & 0x20000000 and s.VirtualAddress <= target < end <=
                        s.VirtualAddress + min(s.SizeOfRawData, s.Misc_VirtualSize) for s in image.pe.sections)):
            raise ValueError('Field-helper fixed target executable scope mismatch')
        root, actual_length, fragments = image.function_span(target)
        if (root != expected_root or actual_length != length or fragments != expected_fragments or
                len(fragments) > MAX_UNWIND_ENTRIES):
            raise ValueError('Field-helper complete same-root function boundary mismatch')
        metadata_rows = row.get('unwind_metadata')
        if not isinstance(metadata_rows, list) or len(metadata_rows) != 1:
            raise ValueError('Field-helper unwind metadata count mismatch')
        info = metadata_rows[0]
        header = image.data(unwind, 4)
        version, flags, count = header[0] & 7, header[0] >> 3, header[2]
        if version != 1 or flags not in (0, 1, 2, 3):
            raise ValueError('Field-helper root unwind flags/version mismatch')
        metadata_length = 4 + 4 * ((count+1)//2) + (4 if flags else 0)
        metadata = image.data(unwind, metadata_length)
        handler = None if not flags else hex(struct.unpack_from('<I', metadata, metadata_length-4)[0])
        if (info.get('entry') != [hex(x) for x in root] or info.get('version') != version or
                info.get('flags') != flags or info.get('metadata_prefix_bytes') != metadata_length or
                hashlib.sha256(metadata).hexdigest() != info.get('metadata_prefix_sha256') or
                info.get('chain_parent') is not None or info.get('handler_rva') != handler or
                info.get('custom_handler_data_not_read') is not bool(flags)):
            raise ValueError('Field-helper unwind metadata identity mismatch')
        total += length
        validated.append({'label': row['label'], 'rva': hex(target), 'code_bytes': length,
            'unwind_root': [hex(x) for x in root],
            'unwind_fragments': [[hex(a), hex(b)] for a, b in fragments],
            'source_direct_calls': [x for x in source['verified_direct_e8_calls'] if x['target_rva'] == hex(target)],
            'typed_signature_verified': False, 'wire_field_type_verified': False})
    summary = evidence.get('summary', {})
    if (total != FIELD_BYTES or summary.get('target_count') != FIELD_READS or
            summary.get('maximum_fixed_reads') != FIELD_READS or
            summary.get('total_planned_code_bytes') != FIELD_BYTES or
            summary.get('maximum_function_bytes') != MAX_FUNCTION_BYTES or
            summary.get('maximum_fragments_per_function') != MAX_UNWIND_ENTRIES or
            summary.get('source_call_instruction_count') != 20):
        raise ValueError('Field-helper fixed total budget mismatch')
    return {'kind': 'fixed_native_control_field_helper_code_plan', 'client_sha256': SOURCE_SHA,
        'client_relative_to_game_root': EXECUTABLE_RELATIVE.as_posix(), 'field_helpers': True,
        'candidate_interval': False, 'field_evidence_sha256': FIELD_PLAN_SHA,
        'field_evidence_relative_to_project_root': FIELD_PLAN.relative_to(ROOT).as_posix(),
        'process_memory_read': False, 'client_launched': False, 'elevation_requested': False,
        'image_modified': False, 'live_object_or_vtable_read': False,
        'source_direct_call_proof': source, 'field_helper_roots': validated,
        'fixed_read_count': FIELD_READS, 'initial_read_bytes': FIELD_BYTES,
        'maximum_code_bytes': FIELD_BYTES, 'maximum_reads': FIELD_READS,
        'maximum_unwind_entries_per_function': MAX_UNWIND_ENTRIES,
        'follow_policy': 'three fixed source-proved E8 helper roots only; no address follow',
        'helper_wire_types_verified': False, 'native_control_logic_verified': False,
        'playable_map_verified': False, 'status': 'offline_plan_validated',
        'observed_at_utc': datetime.now(timezone.utc).isoformat()}


def build_plan(game_root, candidate_interval=False, field_helpers=False):
    if type(candidate_interval) is not bool:
        raise ValueError('Candidate interval must be an explicit bool')
    if type(field_helpers) is not bool:
        raise ValueError('Field helpers must be an explicit bool')
    if candidate_interval and field_helpers:
        raise ValueError('Candidate interval and field helpers are mutually exclusive')
    executable = Path(game_root) / EXECUTABLE_RELATIVE
    if digest(executable) != SOURCE_SHA:
        raise ValueError('Client version hash mismatch')
    if candidate_interval:
        with executable.open('rb') as stream, mmap.mmap(stream.fileno(), 0, access=mmap.ACCESS_READ) as raw:
            return validate_candidate_interval(Image(raw))
    if field_helpers:
        with executable.open('rb') as stream, mmap.mmap(stream.fileno(), 0, access=mmap.ACCESS_READ) as raw:
            return validate_field_helpers(Image(raw))
    source = validate_source_sample(SOURCE_SAMPLE.read_bytes())
    lower_source = validate_lower_source_sample(LOWER_SOURCE_SAMPLE.read_bytes())
    with executable.open('rb') as stream, mmap.mmap(stream.fileno(), 0, access=mmap.ACCESS_READ) as raw:
        image = Image(raw)
        bindings = validate_bindings(image)
        for _, label_rva, expected_text in LOWER_LOGS:
            encoded = expected_text.encode('utf-16le') + b'\0\0'
            if image.data(label_rva, len(encoded)) != encoded:
                raise ValueError('Immutable ReceivedNextBunch caller log string mismatch')
        root, length, fragments = image.function_span(COMPLETION_RVA)
        if (root != COMPLETION_ROOT or length != COMPLETION_BYTES or
                tuple(fragments) != COMPLETION_FRAGMENTS):
            raise ValueError('Exact completion function boundary mismatch')
        lower_root, lower_length, lower_fragments = image.function_span(LOWER_RVA)
        if lower_root != LOWER_ROOT or lower_length != LOWER_BYTES or lower_fragments != [lower_root[:2]]:
            raise ValueError('Exact lower RawBunch candidate boundary mismatch')
    return {'kind': 'fixed_native_control_code_plan', 'client_sha256': SOURCE_SHA,
        'client_relative_to_game_root': EXECUTABLE_RELATIVE.as_posix(),
        'process_memory_read': False, 'client_launched': False, 'elevation_requested': False,
        'image_modified': False, 'live_object_or_vtable_read': False,
        'named_prefixes': bindings, 'completion_source': source,
        'lower_raw_bunch_source': lower_source,
        'completion_function': {'rva': hex(COMPLETION_RVA), 'code_bytes': COMPLETION_BYTES,
            'unwind_root': [hex(x) for x in root],
            'unwind_fragments': [[hex(a), hex(b)] for a, b in fragments]},
        'lower_raw_bunch_candidate': {'rva': hex(LOWER_RVA), 'code_bytes': LOWER_BYTES,
            'unwind_root': [hex(x) for x in lower_root],
            'unwind_fragments': [[hex(a), hex(b)] for a, b in lower_fragments],
            'log_supported_method_name': 'UChannel::ReceivedNextBunch',
            'exact_cpp_symbol_verified': False},
        'fixed_read_count': len(BINDINGS) + 2,
        'initial_read_bytes': len(BINDINGS) * PREFIX_BYTES + COMPLETION_BYTES + LOWER_BYTES,
        'maximum_code_bytes': MAX_CODE_BYTES, 'maximum_reads': MAX_READS,
        'maximum_unwind_entries_per_function': MAX_UNWIND_ENTRIES,
        'follow_policy': 'only one leading E9 per named prefix, exact independent unwind root; no recursive references',
        'native_control_logic_verified': False, 'playable_map_verified': False,
        'status': 'offline_plan_validated', 'observed_at_utc': datetime.now(timezone.utc).isoformat()}


def direct_e9_span(image, rva, code):
    if len(code) != PREFIX_BYTES or code[0] != 0xe9:
        raise ValueError('Named prefix does not begin with a direct E9')
    decoder = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
    decoder.detail = True
    first = next(decoder.disasm(code[:5], rva), None)
    target = rva + 5 + struct.unpack_from('<i', code, 1)[0]
    if (first is None or first.mnemonic != 'jmp' or first.size != 5 or
            len(first.operands) != 1 or first.operands[0].type != X86_OP_IMM or
            first.operands[0].imm != target):
        raise ValueError('Direct E9 instruction decode mismatch')
    if rva <= target < rva + PREFIX_BYTES:
        raise ValueError('Direct target loops into its named prefix')
    root, length, fragments = image.function_span(target)
    return target, length, fragments, root


def collect(game_root, folder, candidate_interval=False, field_helpers=False):
    game_root, folder = Path(game_root), Path(folder)
    plan = build_plan(game_root, candidate_interval, field_helpers)  # Validate evidence before process access.
    executable = game_root / EXECUTABLE_RELATIVE
    folder.mkdir(parents=True, exist_ok=True)
    report = {'kind': 'bounded_native_control_code_read', 'client_sha256': SOURCE_SHA,
        'offline_plan': plan, 'functions': [], 'maximum_code_bytes': plan['maximum_code_bytes'],
        'actual_code_bytes': 0, 'maximum_reads': plan['maximum_reads'], 'client_launched': False,
        'elevation_requested': False, 'game_modified': False, 'process_memory_written': False,
        'credential_memory_read': False, 'live_object_or_vtable_read': False,
        'native_control_logic_verified': False, 'playable_map_verified': False,
        'observed_at_utc': datetime.now(timezone.utc).isoformat()}
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
        report['phase'] = 'process_handle_identity'
        opened_pid = api.GetProcessId(handle)
        report['opened_process_id_matches'] = opened_pid == pids[0]
        if opened_pid != pids[0]:
            report['windows_error'] = C.get_last_error()
            raise RuntimeError('Opened process identity mismatch')
        report['phase'] = 'process_executable_identity'
        expected = os.path.normcase(str(executable.resolve()))
        process = psutil.Process(pids[0])
        started = process.create_time()
        process_path = os.path.normcase(str(Path(process.exe()).resolve()))
        report['process_executable_path_matches'] = process_path == expected
        if process_path != expected:
            raise RuntimeError('Original process executable identity changed')
        report['phase'] = 'executable_module_snapshot'
        snapshot = api.CreateToolhelp32Snapshot(0x18, pids[0])
        base, size = None, None
        report['module_entries_examined'] = 0
        report['same_name_module_candidates'] = []
        if snapshot and snapshot != C.c_void_p(-1).value:
            item = Module()
            item.dwSize = C.sizeof(item)
            ok = api.Module32FirstW(snapshot, C.byref(item))
            while ok:
                report['module_entries_examined'] += 1
                module_path = os.path.normcase(str(Path(item.szExePath).resolve()))
                if Path(item.szExePath).name.lower() == executable.name.lower():
                    report['same_name_module_candidates'].append({
                        'path_matches': module_path == expected,
                        'module_size_bytes': item.modBaseSize,
                        'normalized_path_sha256': hashlib.sha256(module_path.encode('utf-8')).hexdigest()})
                if module_path == expected:
                    base, size = item.modBaseAddr, item.modBaseSize
                    break
                ok = api.Module32NextW(snapshot, C.byref(item))
            if not ok:
                report['module_enumeration_windows_error'] = C.get_last_error()
        else:
            report['module_snapshot_windows_error'] = C.get_last_error()
        if base is None:
            raise RuntimeError('Verified executable module unavailable')
        report['phase'] = 'module_image_size'
        with executable.open('rb') as stream, mmap.mmap(stream.fileno(), 0, access=mmap.ACCESS_READ) as raw:
            image = Image(raw)
            report['module_size_bytes'] = size
            report['immutable_image_size_bytes'] = image.size
            if size != image.size:
                raise RuntimeError('Verified executable module size mismatch')
            decoder = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
            if candidate_interval:
                revalidated = validate_candidate_interval(image)
                if revalidated['candidate_roots'] != plan['candidate_roots']:
                    raise RuntimeError('Candidate root evidence changed after process access')
                reads = [(entry['label'], int(entry['rva'], 16), entry['code_bytes'], False, entry)
                         for entry in plan['candidate_roots']]
            elif field_helpers:
                revalidated = validate_field_helpers(image)
                if (revalidated['field_helper_roots'] != plan['field_helper_roots'] or
                        revalidated['source_direct_call_proof'] != plan['source_direct_call_proof']):
                    raise RuntimeError('Field-helper evidence changed after process access')
                reads = [(entry['label'], int(entry['rva'], 16), entry['code_bytes'], False, entry)
                         for entry in plan['field_helper_roots']]
            else:
                reads = [(b['label'] + '.prefix', b['code'], PREFIX_BYTES, True, None) for b in BINDINGS]
                reads.append(('HandshakeComplete.direct', COMPLETION_RVA, COMPLETION_BYTES, False, None))
                reads.append(('UChannel.ReceivedNextBunch.direct_log_supported', LOWER_RVA, LOWER_BYTES, False,
                              plan['lower_raw_bunch_source']))
            index = 0
            while index < len(reads):
                report['phase'] = 'bounded_image_code_read'
                if len(reads) > plan['maximum_reads']:
                    raise RuntimeError('Control code read-count bound exceeded')
                name, rva, length, may_follow, follow_evidence = reads[index]
                index += 1
                if report['actual_code_bytes'] + length > plan['maximum_code_bytes']:
                    raise RuntimeError('Control code total-byte bound exceeded')
                current = psutil.Process(pids[0])
                if (current.create_time() != started or
                        os.path.normcase(str(Path(current.exe()).resolve())) != expected):
                    raise RuntimeError('Original process identity changed')
                address, memory = base + rva, Memory()
                entry = {'name': name, 'rva': hex(rva), 'code_bytes': length, 'read_succeeded': False}
                if follow_evidence is not None:
                    key = ('candidate_root_evidence' if candidate_interval else
                           'field_helper_source_evidence' if field_helpers else 'source_prefix')
                    entry[key] = follow_evidence
                valid = (image.executable(rva, length) and rva + length <= size and
                    api.VirtualQueryEx(handle, address, C.byref(memory), C.sizeof(memory)) == C.sizeof(memory) and
                    memory.State == 0x1000 and memory.Type == 0x1000000 and memory.AllocationBase == base and
                    memory.Protect & 0xff in (0x10, 0x20, 0x40, 0x80) and not memory.Protect & 0x100 and
                    address + length <= memory.BaseAddress + memory.RegionSize)
                if not valid:
                    entry['read_refused_reason'] = 'image_executable_page_guard_not_satisfied'
                else:
                    buffer, copied = (C.c_ubyte * length)(), C.c_size_t()
                    if api.ReadProcessMemory(handle, address, buffer, length, C.byref(copied)) and copied.value == length:
                        code = bytes(buffer)
                        report['actual_code_bytes'] += length
                        instructions = list(decoder.disasm(code, rva))
                        entry.update(read_succeeded=True, code_sha256=hashlib.sha256(code).hexdigest(),
                            disassembled_bytes=sum(i.size for i in instructions))
                        saved_code = struct.pack('<4Q', 0x0000000145444344, rva, length, base) + code
                        entry['file_sha256'] = hashlib.sha256(saved_code).hexdigest()
                        (folder / (name + '.dfcode')).write_bytes(saved_code)
                        (folder / (name + '.asm.txt')).write_text('\n'.join(
                            f'{i.address:#x}: {i.mnemonic} {i.op_str}' for i in instructions) + '\n', encoding='utf-8')
                        if may_follow:
                            try:
                                target, span, fragments, root = direct_e9_span(image, rva, code)
                                evidence = {'prefix_rva': hex(rva), 'prefix_code_sha256': entry['code_sha256'],
                                    'target_rva': hex(target), 'code_bytes': span,
                                    'unwind_root': [hex(x) for x in root],
                                    'unwind_fragments': [[hex(a), hex(b)] for a, b in fragments]}
                                entry['direct_e9_follow'] = evidence
                                reads.append((name.removesuffix('.prefix') + '.implementation',
                                              target, span, False, evidence))
                            except ValueError as error:
                                entry['direct_implementation_not_followed'] = str(error)
                    else:
                        entry['windows_error'] = C.get_last_error()
                report['functions'].append(entry)
                save(folder / 'result.json', report)
        report['status'] = 'bounded_read_attempt_complete'
    except Exception as error:
        report.update(status='bounded_read_failed', error_type=type(error).__name__)
        if isinstance(error, RuntimeError):
            report['error_reason'] = str(error)
    finally:
        if snapshot and snapshot != C.c_void_p(-1).value:
            api.CloseHandle(snapshot)
        api.CloseHandle(handle)
    save(folder / 'result.json', report)
    return report


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--game-root', type=Path, required=True)
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument('--validate-plan', action='store_true', help='Immutable files only; no process access')
    mode.add_argument('--collect', action='store_true', help='Read one already running, pinned client without elevation')
    parser.add_argument('--output-dir', type=Path, help='Required for --collect')
    profile = parser.add_mutually_exclusive_group()
    profile.add_argument('--candidate-interval', action='store_true',
                         help='Opt in to 13 fixed unknown candidate roots only; no target follow')
    profile.add_argument('--field-helpers', action='store_true',
                         help='Opt in to 3 fixed source-proved field helper roots only; no target follow')
    args = parser.parse_args()
    if args.validate_plan:
        plan = build_plan(args.game_root, args.candidate_interval, args.field_helpers)
        plan_output = (CANDIDATE_PLAN_OUTPUT if args.candidate_interval else
                       FIELD_PLAN_OUTPUT if args.field_helpers else PLAN_OUTPUT)
        plan_output.parent.mkdir(parents=True, exist_ok=True)
        save(plan_output, plan)
        print(f"Offline plan validated: {plan['fixed_read_count']} fixed reads, {plan['initial_read_bytes']} initial bytes, "
              f"{plan['maximum_code_bytes']} maximum bytes; no process access.")
    else:
        if args.output_dir is None:
            parser.error('--collect requires --output-dir')
        result = collect(args.game_root, args.output_dir, args.candidate_interval, args.field_helpers)
        print(result['status'])
        raise SystemExit(0 if result['status'] == 'bounded_read_attempt_complete' else 1)
