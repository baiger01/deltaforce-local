"""Audit archived first-entry weapon logs and qualified owning switch dispatch.

This reads saved files and the already generated offline code reports only.
It does not inspect a process, execute client code, or interpret refused reads
as object values. The saved transport report stops before the user's inputs.
"""
import argparse
import hashlib
import json
from pathlib import Path
import re


ROOT = Path(__file__).resolve().parent.parent
EVIDENCE = ROOT / 'work/evidence/map-system-audit-20261018'
SNAPSHOT = ROOT / ('work/native-client-tests/1792368031415613200/'
                   'diagnostic-snapshots/1792368692388093900')
LOG_SHA256 = '2ad80296109ea6caa9fd7db5746f57c448eddeaf9fdcce5de72c9e7868ce229f'
SENSITIVE = re.compile(r'token|cookie|authorization|password|secret|access.?key|login|https?', re.I)
STAMP = re.compile(r'^\[2026\.10\.19-(08\.0[2-5]\.\d\d:\d{3})\]')
SOURCE_FILES = (
    'native-owned-weapon-switch-rpc-and-multi-slot-static-v1.json',
    'native-owned-weapon-manager-switch-rpc-uht-v1.json',
    'native-owned-weapon-switch-interface-and-rpc-vtables-v1.json',
    'native-owned-weapon-submit-to-owning-rpc-v1.json',
    'native-owned-weapon-base-multi-rpc-dispatch-vtables-v1.json',
    'native-owned-weapon-server-verify-and-switch-implementation-v1.json',
    'native-owned-weapon-runtime-timeline-invalidation-vtable-v1.json',
    'native-owned-weapon-validate-invalidate-remove-consumers-v1.json',
    'native-owned-weapon-frame-checkcode-struct-v1.json',
)


def safe_events(text):
    """Return only explicit first-entry lifecycle lines; reject entire secrets."""
    result = []
    for number, line in enumerate(text.splitlines(), 1):
        match = STAMP.match(line)
        if match is None or SENSITIVE.search(line):
            continue
        stamp = match.group(1)
        if stamp >= '08.05.40:814':
            continue
        allowed = ('LogWeaponManager:' in line or
                   'LogGPCharacter:' in line and any(word in line for word in (
                       'ActivateSkillByUISlot', 'CanEnterFSM', 'CanActivateSkill')) or
                   'OnPostEnterGameFlow: EGameFlowStageType::Game' in line)
        if not allowed:
            continue
        # Account UINs and arbitrary runtime addresses have no role in this audit.
        line = re.sub(r'(?<!\d)\d{15,}(?!\d)', '<redacted-id>', line)
        line = re.sub(r'0x[0-9a-fA-F]{9,}', '<runtime-address>', line)
        result.append(dict(line_number=number, timestamp_local=stamp, text=line))
    return result


def _function(document, target):
    return next(row for row in document['functions'] if row['requested_rva'] == target)


def _instruction(document, target, address, mnemonic, operand):
    row = next(row for row in _function(document, target)['instructions'] if row['rva'] == address)
    if row['mnemonic'] != mnemonic or operand not in row['operands']:
        raise ValueError('Pinned native switch instruction differs: ' + address)


def qualify_sources(documents):
    first, uht, interface, submit, dispatch, implementations, invalidation, consumers, check = (
        documents[name] for name in SOURCE_FILES)
    _instruction(first, '0x58d0b20', '0x58d0b30', 'call', '[rax + 0x98]')
    _instruction(first, '0x58d0b20', '0x58d0cc2', 'call', '[rbx + 0x50]')
    _instruction(submit, '0x561f840', '0x561f8a3', 'cmp', '[rax + 0x130], 3')
    _instruction(submit, '0x5646760', '0x56467f0', 'call', '[rax + 0x558]')
    _instruction(implementations, '0x6143fc0', '0x6144078', 'call', '[rbx + 0x220]')
    _instruction(first, '0x6146e40', '0x6146f1e', 'call', '[rax + 0x418]')
    _instruction(implementations, '0x563d260', '0x563d2ce', 'call', '[rax + 0x78]')
    _instruction(consumers, '0x5600fd0', '0x5601908', 'cmp', '[r12 + 0x218]')
    interface_slots = {row['slot']: row['target_rva'] for row in interface['vtables'][0]['entries']}
    if any(interface_slots[slot] != target for slot, target in (
            ('0x50', '0x5646760'), ('0x78', '0x5899e90'), ('0x88', '0x58d0b20'),
            ('0x98', '0x561f840'))):
        raise ValueError('Manager timeline interface dispatch differs')
    # The first slice starts at primary vtable +0x410. The second slice is a
    # different component and is deliberately excluded from this qualification.
    primary = dispatch['vtables'][0]
    if primary['rva'] != '0x15fa4d00':
        raise ValueError('Unexpected manager primary vtable slice')
    slots = {int(row['slot'], 16) + 0x410: row['target_rva'] for row in primary['entries']}
    if (slots[0x410], slots[0x418], slots[0x558]) != ('0x563d260', '0x563ed10', '0x6143fc0'):
        raise ValueError('Manager switch RPC virtual dispatch differs')
    local_slots = {row['slot']: row['target_rva'] for row in invalidation['vtables'][0]['entries']}
    if local_slots['0x48'] != '0x58d5f50':
        raise ValueError('Local timeline invalidation virtual dispatch differs')
    functions = {row['name']: row for row in uht['classes'][0]['net_function_declarations']}
    verify = functions['RPC_ServerVerifyFrame']
    if (verify['function_flags'], verify['native_param_bytes']) != ('0x220cc0', 64):
        raise ValueError('ServerVerifyFrame UHT contract differs')
    params = {row['name']: (row['native_member_offset'], row['native_gen_flags'],
                           row.get('extra_pointer_rva')) for row in verify['parameters']}
    if params != {'ClientFrame': ('0x0', '0x19', '0x60df3b0'),
                  'InCheckCode': ('0x38', '0x19', '0x60df380')}:
        raise ValueError('ServerVerifyFrame parameter declarations differ')
    return {name: dict(flags=row['function_flags'], params_rva=row['function_params_rva'],
        native_parameter_bytes=row['native_param_bytes'], parameters=[
            dict(name=p['name'], offset=p.get('native_member_offset'),
                 native_gen_flags=p['native_gen_flags']) for p in row['parameters']
            if p['name'] != 'UnderlyingType']) for name, row in functions.items()}


def derive():
    pins = {}

    def read(path):
        raw = path.read_bytes()
        pins[path.relative_to(ROOT).as_posix()] = hashlib.sha256(raw).hexdigest()
        return raw

    documents = {name: json.loads(read(EVIDENCE / name)) for name in SOURCE_FILES}
    rpc = qualify_sources(documents)
    raw = read(SNAPSHOT / 'private-client-log.bin')
    if hashlib.sha256(raw).hexdigest() != LOG_SHA256:
        raise ValueError('Archived private log changed')
    decoded = bytes(value ^ 0x5c for value in raw)
    encoding = 'utf-16' if decoded[:2] in (b'\xff\xfe', b'\xfe\xff') else 'utf-8'
    text = decoded.decode(encoding, errors='replace')
    events = safe_events(text)
    client = [row for row in events if '[Client|' in row['text'] and 'LogWeaponManager:' in row['text']]
    activation = [row for row in client if 'Active Weapon:' in row['text']]
    missing_slot = [row for row in client if 'weapon manager[2] is not found' in row['text']]
    removal = [row for row in client if any(word in row['text'] for word in (
        'DoRemoveWeapon', 'Start Remove Weapon', 'DropWeapon', 'FrameInValid'))]
    if (len(activation), len(missing_slot), len(removal)) != (1, 10, 0):
        raise ValueError('Actual first-entry lifecycle evidence differs')
    report = json.loads(read(SNAPSHOT / 'private-server-report.json'))
    control = report['handshake_probe']['native_control_probe']
    records = report['records']
    read(ROOT / 'outputs/df-local-server/dfserver/legacy_ds_control_connection.py')
    return dict(kind='archived_ingame_weapon_switch_lifecycle_audit_v1',
        process_access=False, client_launched=False, packets_sent=False,
        process_memory_written=False, source_pins=pins, native_rpc_contracts=rpc,
        text_encoding=encoding, undecodable_code_units_replaced=text.count('\ufffd'),
        events=events, actual_current_client_initial_activation_count=len(activation),
        current_client_remove_drop_or_invalid_frame_log_count=len(removal),
        missing_skill_manager_slot2_count=len(missing_slot),
        skill_manager_slot2_is_not_normal_weapon_slot0_evidence=True,
        source_qualified_submission_chain=[
            'AddSwitchFrame 55e7ce0 -> local timeline AddFrame 587e4a0',
            'manager+118 v88 58d0b20 -> authority test v98 561f840',
            'non-authority -> v50 5646760 -> primary v558 6143fc0',
            'ProcessEvent RPC_ServerVerifyFrame -> exec6146e40 -> primary v418 563ed10'],
        source_qualified_invalidation_chain=[
            'RPC_ClientNotifyFrameInValid exec5fe6310 -> primary v410 563d260',
            'manager+118 v78 5899e90 -> local timeline v48 58d5f50'],
        server=dict(unsupported_application_packets=control['events'].get(
                'application_channel_payload_unsupported', 0),
            opaque_pc_reliable_bodies=control['pc_opaque_reliable_bodies_received'],
            opaque_pc_gameplay_handled=control['pc_opaque_rpc_gameplay_handled'],
            saved_records=len(records), first_saved_utc=records[0]['captured_at_utc'],
            last_saved_utc=records[-1]['captured_at_utc']),
        receiver_gap=dict(file='outputs/df-local-server/dfserver/legacy_ds_control_connection.py',
            pc_only_channel_guard_line=1246, actor_only_field_decode_line=1277,
            unknown_body_rejection_line=1302,
            repair_boundary='Admitted Pawn stable WeaponManager component owning RPC receiver; '
                'qualified parameter decode, ticket/transport ownership, frame/identity/slot validation, '
                'stateful accepted owner timeline, reliable retry and actual ACK journal.'),
        limits=[
            'Saved packets stop at 08:03:15.567, before later user switching inputs.',
            'No particular user switch RPC, invalid-frame notification or Drop was observed in saved packets.',
            'Absence of a lifecycle log is not proof that no unlogged state change occurred.',
            'Current-weapon observer refused root selection; no current pointer/null value was observed.',
            'Both Modular log EquipPos0; keyboard caller/default position source is not yet closed.',
            'RPC parameter native sizes are not their wire bit widths; no speculative codec is emitted.',
            'This establishes an unimplemented receiver, not the exact cause of later weapon disappearance.'])


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    if args.output.exists() or not args.output.resolve().is_relative_to(EVIDENCE):
        parser.error('Use a fresh work/evidence/map-system-audit-20261018 output')
    result = derive()
    args.output.write_text(json.dumps(result, indent=2, ensure_ascii=True) + '\n', encoding='utf-8')
    print(json.dumps(dict(path=str(args.output), sha256=hashlib.sha256(args.output.read_bytes()).hexdigest(),
                         activations=result['actual_current_client_initial_activation_count'],
                         missing_skill_manager_slot2=result['missing_skill_manager_slot2_count'])))
