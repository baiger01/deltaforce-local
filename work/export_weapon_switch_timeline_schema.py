"""Seal the observed manager timeline layout and its actual native receiver."""
import argparse
import hashlib
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
BASE = 'work/evidence/map-system-audit-20261018/'
OUTPUT = ROOT / (BASE + 'portable-weapon-switch-timeline-schema-v1.json')
CLIENT_SHA = '4254fbe66585f260f1f9dbfc5e302887842552e7baed8939e023160a5e250be0'
PINS = {
    'native-owned-weapon-switch-frame-enum-records-v1.json': '6103a146f6eab6b26b3068cf3d940222b5b943dc51ae6c983f1e07f70bb54367',
    'native-owned-weapon-switch-frame-fields-v1.json': 'c2ca168bdc6f52a14cc3a4da7b46d1a8bf74a1dc9c3513d4a063e3d1539f2cee',
    'native-owned-weapon-switch-frame-base-fields-v1.json': '12345399f34b3b7f4b7b1160ba1bfbd4d328a4321e9d1dd2d8242216aaac57d2',
    'native-owned-weapon-runtime-timeline-struct-fields-v1.json': 'b98ce3947141f0708cf0c8e1ee2945f5689cf13024af34601db9eb41fc16d421',
    'native-owned-weapon-timeline-notify-and-client-switch-execs-v1.json': 'ce0387c48f31d3b35a29f9c713927b0e1df52ff3d97150ffd014997ad03ac9ad',
    'native-owned-weapon-manager-timeline-list-notify-bodies-v1.json': 'bafb852fc855cd50a689f999d4f7d19432a0467867c157fe3424ce7cd88d2e79',
    'native-owned-weapon-runtime-context-current-frame-v1.json': '09395d8386b871d9a124314b6ddb54ac253875fe1224e3519a5eb80fb0c55070',
    'native-owned-weapon-current-switch-and-timeline-source-v1.json': '2cbf0b5202a5bc2de32b7bb75b54e5a9dd4019337bd9870816be93ccf57c2cf9',
    'native-owned-weapon-local-current-writer-and-timeline-selector-v1.json': '012477e0e1ded2e6a1c512a8b5ea43f6b5a3699a5383d30e02ca9826ffaff81c',
    'native-owned-weapon-timeline-remote-data-binding-v1.json': '0c2ccc340d830d2c9d44fba9f903d1da4cb3d7c609e7e73b0e8552799cf33b04',
    'native-owned-weapon-timeline-ring-import-and-binding-v1.json': 'a8dc9db88f8c349060f7bb5f1e7a5e017a74fac8a9c125523e69f681ff0eb953',
    'native-owned-weapon-base-preview-frame-defaults-v1.json': 'b17e65b4116d39d61830189a345c8a82c5e21264ea7c709834650b52e0cb0854',
    'native-owned-weapon-manager-timeline-vtable-bindings-v1.json': '4ae38454a772eea519b37d90f2caed06cce8a2ac08b8425c6901f38319b5ffcc',
    'native-owned-weapon-timeline-vtable-and-frame-enum-records-v1.json': '5ff4ad29aae29d71baa30a34aaf37c44000ce8c4a05ba842dad738b530793826',
    'native-owned-weapon-timeline-actual-remote-import-v1.json': '0197ef9850ac38ad711b7db8625555ed39edda8fff6523a608c6d86c18eb1fac',
}
CAPTURE = 'work/native-client-tests/1792343957590810500/owned-weapon-state.json'
CAPTURE_SHA = 'e9a923c075c5a462b7dec9a38bc4fd2fc233c519a7b3dacda89e8809233aaf63'


def derive():
    sources, documents = {}, {}
    def load(path, expected):
        raw = (ROOT/path).read_bytes()
        if hashlib.sha256(raw).hexdigest() != expected:
            raise ValueError('Changed switch timeline source: ' + path)
        sources[path] = expected
        return json.loads(raw)
    for name, digest in PINS.items():
        documents[name] = load(BASE + name, digest)
    observed = load(CAPTURE, CAPTURE_SHA)
    if (observed.get('status') != 'observed' or observed.get('client_sha256') != CLIENT_SHA or
            not all(observed.get(k) is True for k in ('identities_and_fields_rechecked',
                'selected_roots_rechecked', 'process_identity_rechecked'))):
        raise ValueError('A rechecked actual manager layout is required')
    manager = next(o for o in observed['objects'] if o['scope'] == 'manager')
    if manager['identity']['name'] != 'WeaponManager' or manager['status'] != 'observed':
        raise ValueError('The actual default manager component changed')
    layout = manager['existing_driver_class']['layout']
    rows = [r for r in layout['commands'] if r.get('parent_index') == 8]
    parent = next(r for r in layout['parents'] if r['parent_index'] == 8)
    expected = [(16, 9, 864, 'Data', 0), (17, 1, 8, 'LocalFrameNo', 5),
        (18, 2, 12, 'RemoteFrameNo', 5), (19, 3, 16, 'DepFrameNo', 5),
        (20, 4, 32, 'WorldTime', 4), (21, 5, 40, 'UniqueId', 9),
        (22, 6, 44, 'UniqueId', 9), (23, 7, 48, 'SwitchType', 6),
        (24, 8, 49, 'Operation', 6), (25, 9, 50, 'SwitchWeaponContext', 6),
        (27, 10, 880, 'Front', 5), (28, 11, 884, 'Rear', 5), (29, 12, 888, 'MaxSize', 5)]
    if (parent['descriptor_name'] != 'TimeLineRepData' or
            [(r['command_index'], r['relative_handle'], r['data_offset'],
              r['descriptor_name'], r['dispatch_opcode']) for r in rows] != expected):
        raise ValueError('The actual timeline array or scalar layout changed')
    def native(name, at, mnemonic, operands):
        matches = [i for f in documents[name]['functions'] for i in f['instructions'] if i['rva'] == at]
        if len(matches) != 1 or (matches[0]['mnemonic'], matches[0]['operands']) != (mnemonic, operands):
            raise ValueError('The actual switch timeline consumer changed: ' + at)
    native('native-owned-weapon-timeline-notify-and-client-switch-execs-v1.json',
        '0x6146825', 'jmp', '0x5631dc0')
    native('native-owned-weapon-manager-timeline-list-notify-bodies-v1.json',
        '0x5631e1d', 'call', 'qword ptr [rax + 0x80]')
    native('native-owned-weapon-manager-timeline-list-notify-bodies-v1.json',
        '0x5631e26', 'call', '0x55ec380')
    native('native-owned-weapon-runtime-context-current-frame-v1.json',
        '0x55ef4c9', 'call', '0x5651590')
    native('native-owned-weapon-current-switch-and-timeline-source-v1.json',
        '0x565fdb4', 'cmp', 'byte ptr [rsp + 0x70], 2')
    native('native-owned-weapon-current-switch-and-timeline-source-v1.json',
        '0x565fdfa', 'call', 'qword ptr [rax + 0x4e8]')
    native('native-owned-weapon-local-current-writer-and-timeline-selector-v1.json',
        '0x55e53a3', 'mov', 'qword ptr [rbx], rax')
    native('native-owned-weapon-timeline-remote-data-binding-v1.json',
        '0x58ef374', 'mov', 'dword ptr [rsp + 0x28], edx')
    native('native-owned-weapon-timeline-remote-data-binding-v1.json',
        '0x58ef381', 'mov', 'dword ptr [rsp + 0x2c], r8d')
    enums = documents['native-owned-weapon-switch-frame-enum-records-v1.json']['enums']
    if [(r['name'], r['value']) for r in enums['Operation']['entries']] != [
            ('ESwitchWeaponOperation::OP_Start', 0),
            ('ESwitchWeaponOperation::OP_ActivatePending', 1),
            ('ESwitchWeaponOperation::OP_Cancel', 2)]:
        raise ValueError('The switch-frame operation enum changed')
    return dict(kind='source_qualified_owned_weapon_switch_timeline_v1', client_sha256=CLIENT_SHA,
        sources=sources, manager=dict(class_path=manager['class_path'], stable_name='WeaponManager',
            native_offset=864, parent_index=8, rep_notify='OnRep_RemoteTimeLineData',
            ordinary_handles=dict(Data=9, Front=10, Rear=11, MaxSize=12)),
        frame=dict(native_bytes=56, array_count_bits=16, inner_handle_stride=9,
            leaves=[dict(handle=handle, name=name, offset=offset, opcode=opcode)
                    for _, handle, offset, name, opcode in expected[1:10]],
            signed_int32=['LocalFrameNo', 'RemoteFrameNo', 'DepFrameNo'],
            identity_uint32_offsets=[40, 44], world_time='finite_float32'),
        enums=enums,
        native_receive=dict(actual_exec='0x6146810 -> 0x5631dc0',
            generated_getter_is_not_handler='0x61422f0',
            receiver='interface+0x80 remote rebase, then ApplyCurrentFrame 0x55ec380',
            remote_import='0x58ef280 exchanges LocalFrameNo and RemoteFrameNo',
            native_current_writer='0x55e50f0: manager PendingActiveWeapon+0x228 -> CurrentActiveWeapon+0x218',
            direct_internal_field_replication=False, role_gate_in_this_onrep=False),
        local_initialization_policy=dict(kind='explicit_local_server_fresh_initial_instant_switch',
            operation=0, switch_type=2, context=2, last_identity=0,
            no_previous_client_frame=-1, no_dependency_frame=-1,
            clock='caller explicit local server nonzero frame and finite nonnegative world time',
            ring=dict(front=0, rear=1, max_size=1, data_count=2,
                index0='unused native default frame', index1='one initial switch frame'),
            ring_size_is_local_policy_not_observed_native_default=True,
            official_current_frame_or_current_weapon_claimed=False),
        scheduling=dict(after=['all exact weapon Actor opens and identity/owner ACK',
            'every complete Actor recipe ACK', 'complete manager lists, WeaponInfo and Active ACK'],
            separate_complete_component_bunch=True, partial_frame_splitting=False,
            required_positive_current_generation_full_send_ack=True),
        diagnostics=dict(current_timeline_and_internal_context_observed=False,
            native_held_weapon_verified=False,
            recipe_received_and_modular_initialization_observed=True,
            internal_state_or_role_emitted=False,
            inventory_ui_readiness_repaired_by_this_field=False))


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, default=OUTPUT)
    args = parser.parse_args()
    if args.output.exists() or not args.output.resolve().is_relative_to(ROOT / 'work/evidence'):
        parser.error('Use a fresh evidence output')
    encoded = (json.dumps(derive(), indent=2, sort_keys=True) + '\n').encode()
    with args.output.open('xb') as stream:
        stream.write(encoded)
    print(json.dumps(dict(output=str(args.output), sha256=hashlib.sha256(encoded).hexdigest())))
