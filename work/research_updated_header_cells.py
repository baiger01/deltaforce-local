"""Read-only cached-code inventory of the two current Pawn header hook cells."""
import argparse
import json
from pathlib import Path

import numpy as np
from capstone import CS_AC_WRITE
from capstone.x86 import X86_OP_MEM, X86_REG_RIP

from research_updated_metadata_roots import ROOT, instruction_row, sha
from research_updated_native_registration import Archive, CLIENT_SHA
from research_updated_replication_core import containing_primary


def displacement_candidates(raw, first, target):
    """Locate disp32 candidates; native instruction decoding must validate each."""
    result = []
    for alignment in range(4):
        length = ((len(raw)-alignment)//4)*4
        if length <= 0:
            continue
        values = np.frombuffer(raw, dtype='<i4', count=length//4, offset=alignment).astype(np.int64)
        addresses = first+alignment+np.arange(len(values), dtype=np.int64)*4+4
        tails = target-addresses-values
        for index in np.flatnonzero((tails >= 0) & (tails <= 8)):
            at, tail = alignment+int(index)*4, int(tails[index])
            if at+4+tail <= len(raw):
                result.append((at, tail))
    return sorted(result)


def direct_write_opcode(raw, at):
    if at < 2:
        return False
    opcode, modrm = raw[at-2:at]
    return (modrm & 0xc7 == 5 and opcode in (0x88, 0x89, 0x86, 0x87, 0xc6, 0xc7)
        or opcode in (0x80, 0x81, 0x83) and modrm in (0x05, 0x0d, 0x25, 0x2d, 0x35))


def derive():
    a = Archive()
    cells = (0x1de36180, 0x1de39d25)
    results = {target: [] for target in cells}
    rejected, searched, unqualified = 0, 0, {}
    for first, end, _ in a.code.blocks:
        a.code.read(first, 1)
        raw = a.code.loaded[first]
        searched += len(raw)
        for target in cells:
            for at, tail in displacement_candidates(raw, first, target):
                address_opcode = at >= 2 and raw[at-2] == 0x8d and raw[at-1] & 0xc7 == 5
                if target == cells[0] and not direct_write_opcode(raw, at) and not address_opcode:
                    continue
                root = containing_primary(a.image, first+at)
                if root is None:
                    rejected += 1
                    continue
                if root in unqualified:
                    continue
                try:
                    instructions = a.instructions(root)
                except ValueError as exc:
                    unqualified[root] = dict(root_rva=hex(root), reason=str(exc),
                        candidate_cell_rva=hex(target), candidate_disp_rva=hex(first+at), approved=False)
                    continue
                for ins in instructions:
                    matches = [o for o in ins.operands if o.type == X86_OP_MEM
                        and o.mem.base == X86_REG_RIP and ins.address+ins.size+o.mem.disp == target
                        and ins.address+ins.disp_offset == first+at]
                    if matches:
                        row = dict(root_rva=hex(root), **instruction_row(ins),
                            memory_write=any(o.access & CS_AC_WRITE for o in matches),
                            address_taken=ins.mnemonic == 'lea', displacement_tail_bytes=tail)
                        if row not in results[target]:
                            results[target].append(row)
    gate = {i.address: i for i in a.instructions(0x4e24db0)}
    expected = {0x4e24db6: ('cmp byte ptr [rip + 0x190113c3], 0', cells[0]),
        0x4e24dc2: ('cmp byte ptr [rip + 0x19014f5c], 0', cells[1]),
        0x4e24dd8: ('cmp byte ptr [rip + 0x19014f46], 2', cells[1])}
    witnesses = []
    for at, (text, target) in expected.items():
        ins = gate[at]
        if ins.mnemonic+' '+ins.op_str != text or a.rip(ins) != target:
            raise ValueError('Current Pawn gate source binding changed')
        witnesses.append(dict(cell_rva=hex(target), **instruction_row(ins)))
    for rva in (0x5e286d0, 0x10c8dc00, 0x3d7a40, 0x10c92380):
        a.instructions(rva)
    registration = {i.address: i for i in a.instructions(0x3d7a40)}
    if a.rip(registration[0x3d7a64]) != cells[0] or registration[0x3d7a6b].op_str != 'qword ptr [rax + 0x10], rcx':
        raise ValueError('Hook-state table address escape registration changed')
    pins = [Path(__file__), ROOT/'work/research_updated_header_cells_test.py',
        ROOT/'work/research_updated_native_registration.py', ROOT/'work/research_updated_replication_core.py']
    cell_rows = []
    for target in cells:
        try:
            initial = a.read(target, 1).hex()
        except ValueError:
            initial = None
        cell_rows.append(dict(rva=hex(target), bytes=1, references=results[target], immutable_raw_initial=initial,
            runtime_value_observed=False))
    return dict(kind='current_pawn_header_mutable_gate_cells_source_inventory', client_sha256=CLIENT_SHA,
        source_pins={p.relative_to(ROOT).as_posix(): sha(p.read_bytes()) for p in pins},
        code_source=a.code.source_evidence(), searched_code_bytes=searched,
        scope='All cached bytes searched for RIP disp32 candidates; complete native instruction decoding validates retained references. Global-enable cell retains common direct writes and address-taking; per-hook cell retains all RIP references. This is not an exhaustive proof against indirect or external writes.',
        rejected_candidates_without_unwind_root=rejected,
        unqualified_candidate_functions=list(unqualified.values()),
        cells=cell_rows,
        exact_gate_witnesses=witnesses,
        dispatcher=dict(per_hook_state_rva='0x1de36180+0x3ba5=0x1de39d25',
            table_registration_rva='0x3d7a40', registered_group_id=11, registered_byte_count=0x8f56,
            table_pointer_record_offset='0x10', registry_append_rva='0x10c92380',
            typed_dispatcher_rva='0x5e286d0', generic_dispatcher_rva='0x10c8dc00',
            external_callback_slot='dispatcher singleton+0x128', callback_instruction_rva='0x10c8dd68',
            source_does_not_force_callback_target_or_effects=True),
        native_functions=[p for _, p in a.functions.values()],
        minimum_observation=dict(client_sha256=CLIENT_SHA, reads=[dict(rva=hex(target), bytes=1) for target in cells],
            code_guards=[dict(rva=hex(at), bytes=len(gate[at].bytes), bytes_hex=gate[at].bytes.hex(), sha256=sha(gate[at].bytes)) for at in expected],
            required_recheck='Re-read both exact bytes and source instruction guards after the callback; reject changed values or image identity.',
            accepts_native_byte_branch='global enable ==0 OR hook state ==0',
            rejects_unresolved_branch='Both nonzero: callback dispatcher can set hook state2 and skip the native byte; pre-call state alone does not approve the callback branch.',
            native_function_invocation_required=False, arbitrary_global_scan_allowed=False),
        static_default_is_not_runtime_branch_proof=True, native_byte_branch_statically_forced=False,
        process_opened=False, native_engine_function_called=False, runtime_files_changed=False,
        profile_guards_relaxed=False, native_acceptance_verified=False)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    target = args.output.resolve()
    if target.exists() or target.parent != ROOT/'work' or not target.name.startswith('research_'):
        parser.error('Fresh work/research_ report required')
    result = derive()
    raw = (json.dumps(result, ensure_ascii=True, indent=2)+'\n').encode('ascii')
    with target.open('xb') as stream:
        stream.write(raw)
    print(json.dumps(dict(output=str(target), sha256=sha(raw), references=[len(c['references']) for c in result['cells']])))
