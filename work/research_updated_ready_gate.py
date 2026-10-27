"""Offline source proof of current first-player completion prerequisites.

Reads sealed code and a completed trial's diagnostic log. Does not open a
process, change runtime profiles or turn transport receipts into gameplay proof.
"""
import argparse
import hashlib
import json
from pathlib import Path

from capstone.x86 import X86_OP_MEM, X86_REG_RIP
from research_updated_native_registration import Archive, CLIENT_SHA, text
from research_updated_metadata_roots import ROOT, instruction_row


PREPROCESS = 0x4951ce0
MOVEMENT_PREDICATE = 0x492fb80
MOVEMENT_CLASS_GETTER = 0x60bf2d0
INTERFACE_GETTER = 0x606aaa0
TRIAL = 'work/native-client-tests/1793076660826961200/client-alerts.log'
TRIAL_SHA256 = '255071c7411a8db3a5c53ef931b77a0b9563e0d195aafaba0475738b0626c864'
PROFILE = 'work/evidence/updated-minimum-actor-profile-79fb7b10.json'
PROFILE_SHA256 = '64e5979c79b0876f62c6e03a9ad0407a88aaff3d7b9b81ed9961c920e4c2399a'


def checked(path, digest):
    raw = (ROOT / path).read_bytes()
    if hashlib.sha256(raw).hexdigest() != digest:
        raise ValueError('Pinned current readiness input changed: ' + path)
    return raw


def derive():
    actor_profile = json.loads(checked(PROFILE, PROFILE_SHA256))
    log = checked(TRIAL, TRIAL_SHA256).decode('utf-8')
    a = Archive()
    ins = a.instructions(PREPROCESS)
    instructions = {i.address: i for i in ins}
    expected = {
        0x4951db6: ('test', 'byte ptr [rax + 8], 0x40'),
        0x4951dc1: ('call', '0x492fb80'),
        0x4951dc8: ('je', '0x4951e01'),
        0x4951dca: ('or', 'byte ptr [rbx + 8], 0x40'),
        0x4952409: ('movzx', 'eax, byte ptr [rdi + 8]'),
        0x495240d: ('and', 'al, 0x6e'),
        0x495240f: ('cmp', 'al, 0x6e'),
        0x4952411: ('jne', '0x495245f'),
        0x4952413: ('cmp', 'byte ptr [rdi + 0x121], 0'),
        0x495241a: ('je', '0x495245f'),
        0x495245a: ('call', '0xe59610'),
    }
    for at, pair in expected.items():
        if (instructions[at].mnemonic, instructions[at].op_str) != pair:
            raise ValueError('The complete current preprocessing gate changed')
    predicate = a.instructions(MOVEMENT_PREDICATE)
    if not any(i.mnemonic == 'call' and i.op_str == hex(MOVEMENT_CLASS_GETTER) for i in predicate):
        raise ValueError('The movement prerequisite must use the exact current class getter')
    movement = a.class_identity(MOVEMENT_CLASS_GETTER)
    interface = a.class_identity(INTERFACE_GETTER)
    if (movement['package'], movement['name']) != ('/Script/GPGameplay', 'MovementReplicationActor'):
        raise ValueError('The prerequisite class identity changed')
    if interface['name'] != 'GPSeamlessConnectionInterface':
        raise ValueError('The owning interface identity changed')
    log_strings = []
    for i in ins:
        if (i.mnemonic != 'lea' or not i.op_str.startswith('rax, ') or
                i.operands[1].type != X86_OP_MEM or i.operands[1].mem.base != X86_REG_RIP):
            continue
        target = i.address + i.size + i.operands[1].mem.disp
        value = text(a.read, target, wide=True)
        if value.startswith(('FirstPlayerPreprocessDefault', 'UGPActorChannel::FirstPlayerPreprocessDefault', 'NotMove ')):
            log_strings.append(dict(instruction_rva=hex(i.address), literal_rva=hex(target), text=value))
    required_literals = ('Find MovementActor', 'Complete, OnPostConnectDS Broadcast!')
    if any(not any(part in row['text'] for row in log_strings) for part in required_literals):
        raise ValueError('The current diagnostic literals must identify the movement/completion branches')
    observed = []
    for number, line in enumerate(log.splitlines(), 1):
        if 'SerializeNewActor|GUID=' in line:
            observed.append(dict(line=number, message=line.split('LogNet: Warning: ', 1)[-1].split(':PersistentLevel.', 1)[-1]))
    markers = {
        'movement_preprocess_observed': 'FirstPlayerPreprocessDefault Find MovementActor',
        'completion_broadcast_observed': 'FirstPlayerPreprocessDefault Complete, OnPostConnectDS Broadcast!',
        'travel_timeout_observed': 'OnTimeout: flow SeamlessFlow_TravelToDS timeout',
    }
    return dict(kind='current_first_player_completion_prerequisite_source_proof', client_sha256=CLIENT_SHA,
        source_pins={PROFILE: PROFILE_SHA256, TRIAL: TRIAL_SHA256,
            'work/research_updated_ready_gate.py': hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
            'work/research_updated_native_registration.py': hashlib.sha256((ROOT/'work/research_updated_native_registration.py').read_bytes()).hexdigest()},
        preprocessing_rva=hex(PREPROCESS), movement_predicate_rva=hex(MOVEMENT_PREDICATE),
        required_movement_class=movement, owning_seamless_interface=interface,
        gate=dict(pending_mask='0x6e', movement_required_bit='0x40', additional_nonzero_byte_offset='0x121',
            instructions=[instruction_row(instructions[at]) for at in expected]),
        source_log_strings=log_strings, minimum_profile_roles=sorted(actor_profile['actors']),
        trial=dict(actor_open_log_entries=observed, **{key: marker in log for key, marker in markers.items()}),
        runtime_pending_flags_observed=False, missing_movement_prerequisite_is_a_source_based_diagnosis=True,
        avatar_readiness_sufficiency_proven=False, exact_movement_actor_schema_qualified=False,
        process_opened=False, process_memory_written=False, native_function_called=False,
        runtime_profile_changed=False, native_entry_or_gameplay_acceptance=False,
        native_code_functions=[report for _, report in a.functions.values()],
        immutable_reads=list(a.data.values()), code_source=a.code.source_evidence())


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    target = args.output.resolve()
    if target.parent != ROOT/'work/evidence' or target.exists():
        parser.error('A fresh work/evidence output is required')
    result = derive()
    raw = (json.dumps(result, sort_keys=True, indent=2) + '\n').encode('ascii')
    with target.open('xb') as stream:
        stream.write(raw)
    print(json.dumps(dict(path=str(target), sha256=hashlib.sha256(raw).hexdigest(),
        required_class=result['required_movement_class']['name'], gate=result['gate']['pending_mask'],
        movement_log=result['trial']['movement_preprocess_observed'],
        completion_log=result['trial']['completion_broadcast_observed'])))
