"""Plan three exact field-helper reads from saved control code and disk metadata.

No process API, client launch, elevation, image mutation, or runtime read exists
in this module. Reflection absence is qualified: thunks may hide native helpers.
"""
import argparse
import json
import mmap
from pathlib import Path
import re
import struct

import analyze_control_candidate_interval as audit

ROOT = Path(__file__).resolve().parent.parent
SOURCE = ROOT / 'work/native-client-tests/1790852438755252500/ds-native-control-code'
TARGETS = (0x109ea340, 0x12bab170, 0x1779fa0)
OUTPUT = ROOT / 'work/evidence/native-control-field-helper-source-plan.json'


def unwind(image, entry):
    header = image.data(entry[2], 4)
    version, flags, count = header[0] & 7, header[0] >> 3, header[2]
    if version != 1 or flags not in (0, 1, 2, 3, 4):
        raise ValueError('Unsupported immutable unwind information')
    length = 4 + 4 * ((count + 1) // 2) + (12 if flags == 4 else 4 if flags else 0)
    value = image.data(entry[2], length)
    parent = struct.unpack_from('<III', value, length-12) if flags == 4 else None
    return {'entry': list(map(hex, entry)), 'version': version, 'flags': flags,
            'metadata_prefix_bytes': length, 'metadata_prefix_sha256': audit.sha(value),
            'chain_parent': None if parent is None else list(map(hex, parent)),
            'handler_rva': hex(struct.unpack_from('<I', value, length-4)[0]) if flags and flags != 4 else None,
            'custom_handler_data_not_read': bool(flags and flags != 4)}, parent


def function_span(image, target):
    low, high = 0, image.count
    while low < high:
        mid = (low+high)//2
        if image.entry(mid)[0] < target:
            low = mid+1
        else:
            high = mid
    if low == image.count or image.entry(low)[0] != target:
        raise ValueError('Direct target has no exact immutable unwind root')
    root = image.entry(low)
    proof, _ = unwind(image, root)
    if proof['flags'] == 4:
        raise ValueError('Direct target is a CHAININFO continuation')
    accepted, entries, proofs, finish = {root}, [root], [proof], root[1]
    for index in range(low+1, min(image.count, low+33)):
        entry = image.entry(index)
        if entry[0] != finish:
            break
        proof, parent = unwind(image, entry)
        if proof['flags'] != 4 or parent not in accepted:
            break
        if index >= low+32 or not entry[0] < entry[1] <= target+8192:
            raise ValueError('Function fragment/byte budget exceeded')
        accepted.add(entry)
        entries.append(entry)
        proofs.append(proof)
        finish = entry[1]
    if not 0 < finish-target <= 8192 or not image.executable(target, finish-target):
        raise ValueError('Direct target is outside backed executable function bounds')
    return {'root': list(map(hex, root)), 'read_rva': hex(target),
            'end_rva_exclusive': hex(finish), 'code_bytes': finish-target,
            'unwind_fragments': [[hex(v[0]), hex(v[1])] for v in entries],
            'unwind_metadata': proofs, 'fragment_count': len(entries),
            'root_is_chain_continuation': False, 'maximum_function_bytes': 8192,
            'maximum_fragments': 32, 'file_backed_executable_scope_verified': True}


def reflection(image, targets):
    """Only exact target pointer references; no generalized reflection graph."""
    base = image.pe.OPTIONAL_HEADER.ImageBase
    sections = [s for s in image.pe.sections if not s.Characteristics & 0x20000000 and s.SizeOfRawData]

    def label(va):
        if not base <= va < base+image.size:
            return None
        try:
            value = image.data(va-base, 140).split(b'\0', 1)[0].decode('ascii')
        except (ValueError, UnicodeDecodeError):
            return None
        return value if re.fullmatch(r'[A-Za-z_][A-Za-z0-9_ :*<>~,&]{0,138}', value) else None

    def hits(needle):
        for section in sections:
            start = section.PointerToRawData
            end, at = start+section.SizeOfRawData, start
            while True:
                hit = image.raw.find(needle, at, end)
                if hit < 0:
                    break
                at = hit+len(needle)
                yield section.VirtualAddress+hit-start, hit, start

    bindings, references = {t: [] for t in targets}, {t: [] for t in targets}
    for target in targets:
        seen = set()
        for slot, _, _ in hits(struct.pack('<Q', base+target)):
            if slot % 8:
                continue
            references[target].append(hex(slot))
            for role, delta in (('implementation', 8), ('invoker', 16)):
                record = slot-delta
                if record in seen:
                    continue
                seen.add(record)
                try:
                    data = image.data(record, 48)
                    name, implementation, invoker, returns, args, count = struct.unpack('<6Q', data)
                except ValueError:
                    continue
                if not 1 <= count <= 16 or not image.executable(implementation-base, 1) or not image.executable(invoker-base, 1):
                    continue
                method, returned = label(name), label(returns)
                if method is None or returned is None:
                    continue
                try:
                    arg_bytes = image.data(args-base, count*8)
                    pointers = struct.unpack('<'+'Q'*count, arg_bytes)
                except ValueError:
                    continue
                types = [label(v) for v in pointers]
                if any(v is None for v in types):
                    continue
                bindings[target].append({'record_rva': hex(record), 'matched_role': role,
                    'record_48bytes_sha256': audit.sha(data),
                    'record_relative_rvas_or_count': [hex(v-base) for v in (name, implementation, invoker, returns, args)]+[count],
                    'name': method, 'return_type': returned, 'argument_types': types,
                    'argument_table_bytes': count*8, 'argument_table_sha256': audit.sha(arg_bytes),
                    'argument_type_string_rvas': [hex(v-base) for v in pointers],
                    'all_6_qwords_and_argument_types_verified': True})
    labels = {}
    for typename in ('FArchive *', 'FString *', 'FString', 'FArchive &', 'FString &'):
        labels[typename] = [hex(rva) for rva, hit, start in hits(typename.encode()+b'\0')
                           if hit == start or image.raw[hit-1] == 0]
    return bindings, references, labels


def run(game_root):
    report = audit.load_json(SOURCE/'result.json')
    row = next(x for x in report['functions'] if x['name'] == 'unknown_128668d0')
    if report.get('client_sha256') != audit.IMAGE_SHA or row.get('read_succeeded') is not True:
        raise ValueError('Saved source report client/read identity mismatch')
    code, file_sha = audit.dfcode(SOURCE/'unknown_128668d0.dfcode', audit.TABLE_ROOT, 3784,
                                 row['file_sha256'], row['code_sha256'])
    classification = audit.inspect_code(code, audit.TABLE_ROOT, 0x40000000)
    if not classification['all_four_fixed_logs_verified'] or not classification['payload_classification']['all_payload_bytes_classified']:
        raise ValueError('Saved control-body identity/code-table evidence failed')
    decoder = audit.capstone.Cs(audit.capstone.CS_ARCH_X86, audit.capstone.CS_MODE_64)
    decoder.detail = True
    instructions = list(decoder.disasm(code[:3666], audit.TABLE_ROOT))
    calls = {t: [] for t in TARGETS}
    for index, ins in enumerate(instructions):
        if (ins.mnemonic != 'call' or ins.size != 5 or ins.bytes[0] != 0xe8 or
                ins.operands[0].type != audit.X86_OP_IMM or ins.operands[0].imm not in calls):
            continue
        target = ins.operands[0].imm
        if ins.address+5+struct.unpack('<i', ins.bytes[1:])[0] != target:
            raise ValueError('Source E8 rel32 and decoded immediate differ')
        calls[target].append({'instruction_rva': hex(ins.address),
            'instruction_bytes_hex': bytes(ins.bytes).hex(), 'direct_target_rva': hex(target),
            'preceding_instructions': [{'rva': hex(v.address), 'mnemonic': v.mnemonic, 'operands': v.op_str}
                                       for v in instructions[max(0, index-4):index]]})
    if tuple(len(calls[t]) for t in TARGETS) != (15, 3, 2):
        raise ValueError('Source exact direct-call count mismatch')
    with (Path(game_root)/audit.EXE_RELATIVE).open('rb') as stream, mmap.mmap(stream.fileno(), 0, access=mmap.ACCESS_READ) as raw:
        if audit.sha(raw) != audit.IMAGE_SHA:
            raise ValueError('Shipping immutable SHA mismatch')
        image = audit.Image(raw)
        for address, literal in audit.LOGS:
            encoded = literal.encode('utf-16le')+b'\0\0'
            if image.data(address, len(encoded)) != encoded:
                raise ValueError('Source control-body immutable log literal mismatch')
        roots = {t: function_span(image, t) for t in TARGETS}
        bindings, references, labels = reflection(image, TARGETS)
    inventory, samples = [], []
    for path in sorted((ROOT/'work/native-client-tests').rglob('*.dfcode')):
        relative = path.relative_to(ROOT).as_posix()
        inventory.append(relative)
        with path.open('rb') as stream:
            header = stream.read(32)
        if len(header) != 32:
            continue
        magic, address, length, _private = struct.unpack('<4Q', header)
        if magic != audit.MAGIC:
            continue
        for target in TARGETS:
            finish = int(roots[target]['end_rva_exclusive'], 16)
            if address <= target < finish <= address+length:
                samples.append({'path': relative, 'target_rva': hex(target),
                    'source_header_rva': hex(address), 'declared_bytes': length,
                    'standalone_exact_target': address == target,
                    'complete_target_span_in_declared_sample': True,
                    'saved_sample_content_not_yet_validated': True})
    functions = []
    for target in TARGETS:
        root = roots[target]
        root.update({'label': 'unknown_control_field_'+format(target, 'x'),
            'source_direct_calls': calls[target], 'immutable_reflection_records': bindings[target],
            'immutable_target_pointer_reference_rvas': references[target],
            'typed_signature_verified': bool(bindings[target]),
            'argument_types_must_not_be_guessed': not bool(bindings[target]),
            'runtime_sample_collected': False,
            'existing_complete_saved_sample_candidates': [v for v in samples if v['target_rva'] == hex(target)]})
        functions.append(root)
    return {'kind': 'native_control_field_helper_fixed_source_plan',
        'client_sha256': audit.IMAGE_SHA, 'client_relative_executable': audit.EXE_RELATIVE.as_posix(),
        'source_sample_relative_path': (SOURCE/'unknown_128668d0.dfcode').relative_to(ROOT).as_posix(),
        'source_file_sha256': file_sha, 'source_code_sha256': audit.sha(code),
        'source_header_rva': hex(audit.TABLE_ROOT), 'source_payload_bytes': 3784,
        'source_code_ranges': [[hex(audit.TABLE_ROOT), hex(audit.CODE_END)]],
        'source_jump_table_excluded': True, 'source_control_body_log_identity_verified': True,
        'process_access': False, 'game_launched': False, 'elevation_requested': False,
        'image_modified': False, 'reader_or_runner_modified': False, 'plan_only': True,
        'fixed_direct_targets': functions,
        'summary': {'target_count': 3, 'maximum_fixed_reads': 3,
            'total_planned_code_bytes': sum(v['code_bytes'] for v in functions),
            'maximum_function_bytes': 8192, 'maximum_fragments_per_function': 32,
            'direct_call_counts': {hex(t): len(calls[t]) for t in TARGETS},
            'source_call_instruction_count': sum(map(len, calls.values())),
            'saved_sample_inventory_count': len(inventory),
            'saved_sample_path_inventory_sha256': audit.sha(('\n'.join(inventory)+'\n').encode()),
            'existing_complete_sample_candidates_count': len(samples)},
        'immutable_type_label_observations': labels,
        'reflection_search_scope': 'Only aligned immutable non-executable references to three exact targets, at 6Q implementation/invoker slots; full records and typed tables validated. No match cannot exclude a forwarding thunk.',
        'next_collection_conditions': ['Plan only; no collection executed.',
            'Reuse version/process identity and committed executable MEM_IMAGE guards for only these three exact spans.',
            'Each root <=8192 bytes and <=32 contiguous same-root CHAININFO fragments; never read objects or generalized call graphs.',
            'Save full-file/payload SHA and report. Distinguish code, padding, and tables when analyzing saved data.',
            'Do not infer wire types from register arguments or local offsets alone.'],
        'control_field_wire_types_verified': False, 'native_control_protocol_verified': False,
        'playable_map_verified': False}


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--game-root', required=True)
    parser.add_argument('--output', type=Path, default=OUTPUT)
    args = parser.parse_args()
    result = run(args.game_root)
    args.output.write_text(json.dumps(result, indent=2)+'\n', encoding='utf-8')
    print(json.dumps({'output': args.output.relative_to(ROOT).as_posix(), 'summary': result['summary'],
        'roots': [{'label': v['label'], 'root': v['root'], 'bytes': v['code_bytes'],
                   'fragments': v['unwind_fragments'], 'reflection_records': v['immutable_reflection_records']}
                  for v in result['fixed_direct_targets']],
        'type_labels': result['immutable_type_label_observations']}, indent=2))
