"""Seal plain-struct owning switch RPC grammar from same-build cached source."""
import hashlib
import json
from pathlib import Path

from audit_weapon_switch_ingame_lifecycle import SOURCE_FILES, qualify_sources

ROOT = Path(__file__).resolve().parent.parent
FOLDER = ROOT / 'work/evidence/map-system-audit-20261018'
OUTPUT = FOLDER / 'portable-weapon-switch-owner-rpc-schema-v1.json'
EXTRA = (
    'native-owned-weapon-rpc-struct-receive-and-netserialize-v1.json',
    'native-owned-weapon-rpc-struct-ops-and-command-loop-v1.json',
    'native-owned-weapon-frame-checkcode-cppops-vtables-v1.json',
    'native-owned-weapon-rpc-property-layout-builder-v1.json',
    'native-owned-weapon-rpc-layout-and-directional-content-header-v1.json',
    'native-owned-weapon-rpc-field-order-and-defaults-v1.json',
    'native-owned-weapon-switch-frame-fields-v1.json',
    'native-owned-weapon-switch-frame-base-fields-v1.json',
    'native-owned-weapon-local-current-writer-and-timeline-selector-v1.json',
    'native-owned-weapon-multi-constructor-active-consumers-v1.json',
)
METADATA = 'work/native-client-tests/1792337436036819800/owned-gameplay-metadata.json'


def derive():
    sources = {}

    def read(path):
        raw = path.read_bytes()
        sources[path.relative_to(ROOT).as_posix()] = hashlib.sha256(raw).hexdigest()
        return json.loads(raw)

    documents = {name: read(FOLDER / name) for name in SOURCE_FILES + EXTRA}
    rpc = qualify_sources(documents)

    def instruction(name, target, at, mnemonic, operand):
        function = next(row for row in documents[name]['functions'] if row['requested_rva'] == target)
        row = next(row for row in function['instructions'] if row['rva'] == at)
        if row['mnemonic'] != mnemonic or operand not in row['operands']:
            raise ValueError('The owning RPC source instruction changed: ' + at)

    instruction(EXTRA[0], '0x12db9682', '0x12db96e1', 'je', '0x12db98ad')
    instruction(EXTRA[0], '0x12db9682', '0x12db9742', 'call', '0x12dc23f0')
    instruction(EXTRA[3], '0x12d9b1e0', '0x12d9b365', 'test', 'al, 1')
    instruction(EXTRA[3], '0x12d9b1e0', '0x12d9b367', 'je', '0x12d9b3d9')
    instruction(EXTRA[3], '0x12d9b1e0', '0x12d9b41b', 'jb', '0x12d9b445')
    instruction(EXTRA[3], '0x12d9b1e0', '0x12d9b54c', 'call', '0x12d9b1e0')
    instruction(EXTRA[5], '0x4a24e50', '0x4a24f77', 'cmp', '[rdx + 0x54]')
    instruction(EXTRA[5], '0xd5f3a0', '0xd5f3a0', 'xor', 'al, al')
    instruction(EXTRA[5], '0xe3f5c0', '0xe3f5c2', 'mov', 'qword ptr [rdx], rax')
    header = EXTRA[4]
    instruction(header, '0x12863812', '0x12863650', 'movzx', 'r15d, al')
    instruction(header, '0x12863812', '0x12863d2f', 'test', 'r15b, r15b')
    instruction(header, '0x12863812', '0x12863d39', 'jne', '0x128648d7')
    tables = documents[EXTRA[2]]['vtables']
    if len(tables) != 3 or any(next(row for row in table['entries'] if row['slot'] == '0x70')
                              ['target_rva'] != '0xd5f3a0' for table in tables):
        raise ValueError('A switch RPC struct acquired a native NetSerialize operation')
    metadata = read(ROOT / METADATA)
    managers = [row['existing_driver_class'] for row in metadata['objects']
        if any(any(field.get('descriptor_name') == 'RPC_ServerVerifyFrame'
            for field in node.get('fields', ()))
            for node in row.get('existing_driver_class', {}).get('cache_nodes', ()))]
    if len(managers) != 1 or managers[0]['exclusive_index_maximum'] != 17:
        raise ValueError('The actual archived MultiWeaponManager class cache changed')
    fields = {field['descriptor_name']: field['rep_index'] for node in managers[0]['cache_nodes']
              for field in node['fields']}
    if (fields['RPC_ServerVerifyFrame'], fields['RPC_ClientNotifyFrameInValid']) != (10, 9):
        raise ValueError('The archived owning switch RPC indices changed')
    frame = [dict(name=row['name'], offset=int(row['native_member_offset'], 16),
                  gen_flags=row['native_gen_flags'])
        for name in (EXTRA[7], EXTRA[6]) for row in documents[name]['structs'][0]['fields']
        if row['name'] != 'UnderlyingType']
    frame.sort(key=lambda row: row['offset'])
    if [row['name'] for row in frame] != ['LocalFrameNo', 'RemoteFrameNo', 'DepFrameNo',
            'WorldTime', 'LastWeaponIdentity', 'PendingWeaponIdentity', 'SwitchType',
            'Operation', 'SwitchWeaponContext']:
        raise ValueError('The plain switch-frame reflected leaf order changed')
    return dict(kind='source_qualified_weapon_switch_owner_rpc_v1',
        client_sha256=documents[SOURCE_FILES[0]]['client_sha256'], sources=sources,
        class_path='/Script/GPGameplay.MultiWeaponManagerComponent',
        component_name='WeaponManager', exclusive_index_maximum=17,
        verify_index=10, invalid_frame_index=9, rpc=rpc,
        verify_parameters=dict(parent_presence_bits=2, frame_leaf_bits=204, check_code_bits=64,
            maximum_bits=270, frame_leaves=frame, struct_native_netserialize=False,
            children_have_individual_presence_bits=False),
        client_to_server_subobject_header=dict(has_rep_layout=False, actor_selector=False,
            packed_guid=True, stable_name_bit=False, dynamic_class_reference=False),
        invalid_frame_parameters=dict(presence_bit=True, signed_frame_bits=32),
        current_values_observed=False, native_runtime_rpc_acceptance_verified=False,
        local_policy='Authenticated exact equipped identities; native anti-cheat parity is not claimed.')


if __name__ == '__main__':
    if OUTPUT.exists():
        raise SystemExit('Refusing to replace an existing sealed schema')
    OUTPUT.write_text(json.dumps(derive(), indent=2, sort_keys=True) + '\n', encoding='utf-8')
    print(json.dumps(dict(path=str(OUTPUT), sha256=hashlib.sha256(OUTPUT.read_bytes()).hexdigest())))
