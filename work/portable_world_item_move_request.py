"""Decode the actual observed ItemMove function's plain reflected struct.

This is a value decoder. Its caller must first admit the exact current Pawn
channel and InventoryManager GUID. It neither trusts client object references
nor executes a transfer, opens a box, sends a response or changes an account.
"""
from dataclasses import dataclass
from functools import lru_cache
import hashlib
import json
from pathlib import Path

from dfserver.legacy_ds_actor_fields import ClassFieldEnvelope, NormalClassFieldProfile, read_class_fields
from dfserver.legacy_ds_bit_archive import BitReader
from dfserver.legacy_ds_wire_codec import WireBunch, ChannelName
from normal_map_archive_values import (qualify_vector_contract, read_plain_vector,
    vector_source_pins)


ROOT = Path(__file__).resolve().parent.parent
CLIENT = '4254fbe66585f260f1f9dbfc5e302887842552e7baed8939e023160a5e250be0'
BASE = 'work/evidence/map-system-audit-20261018/'
CAPTURE = 'work/native-client-tests/1792401899578422100/world-interaction-rpc-metadata.json'
PINS = {
    CAPTURE: '63c3730cfab6d18619fb92c2b375bb00aeb510349c1107f5d8e04d52cfcdbb99',
    BASE + 'native-world-item-move-rpc-recursive-enum-source-v1.json':
        'd31c32daa82d8781591141ef1fa5ad756130f5bf3c29a75695072de6edfaf5f8',
    BASE + 'native-world-item-move-rpc-array-source-v1.json':
        '3d11b9bd9efb3f786a47ca280e3de1fbe259a30ebb3b15c22b98a8d87d609676',
    BASE + 'native-economy-interaction-normal-rpc-object-receive-v1.json':
        '70a2014b8e805279607b5b417b4b9151bd2d30c51baf7ae4210114cff2a0eb41',
    BASE + 'native-economy-world-rpc-struct-ops-records-v2.json':
        '6a01a8fa7b6e41dabbf90b8413088fd67c7f497e844a33563d40efe7c5cdf9c4',
    BASE + 'native-economy-item-move-command-reflected-fields.json':
        'dfb9f47bf8412378bc14ef69ab1c9c59aadb656850121e061985f39816e3ab76',
    BASE + 'native-owned-weapon-rpc-field-order-and-defaults-v1.json':
        '3bc1618dd70a6579da47a18e6958de5590ba57a560897be9f4c0d3663fd4d051',
    BASE + 'native-owned-weapon-rpc-layout-and-directional-content-header-v1.json':
        '87c30714d14d61c187fd47de93d03aaaa6bb9ee00d62481acd860cfd6fe507d4',
    'outputs/df-local-server/protocol/portable-map-spawn/inventory-schema.json':
        'c0ff0436a36ee6e1c0e66c7a69039a4f3375eabe9308353116dcc23a41e63ad7',
}
RPC_INDEX = 45
EXCLUSIVE_INDEX_MAXIMUM = 53
MAX_PARAMETER_BITS = 8192
MAX_TARGET_GIDS = 64
MAX_REFERENCE_ARRAY = 16

LEAVES = (
    ('CmdGid', 0, 20), ('SourceGid', 8, 20), ('TargetGids', 16, 0),
    ('TargetGids', 0, 20), (None, 0, 1), ('SourcePos', 32, 9),
    ('TargetPos', 36, 9), ('TargetX', 40, 5), ('TargetY', 44, 5),
    ('bRotated', 48, 21), ('MoveNum', 52, 5), ('TargetIndex', 56, 5),
    ('SourceLootObj', 64, 8), ('TargetLootObjs', 72, 0),
    ('TargetLootObjs', 0, 8), (None, 0, 1),
    ('bAllowContainerReplaceFailBackup', 88, 21), ('bDropItemsFromContainer', 89, 21),
    ('bForceReplaceShell', 90, 21), ('bAllowRelocate', 91, 21),
    ('SourceWeaponGid', 120, 20), ('TargetWeaponGid', 128, 20),
    ('OriginPos1P', 136, 10), ('OriginForward1P', 148, 10),
    ('bHitInteractor1P', 160, 21), ('CmdOwner', 168, 8),
    ('SourceSpace', 232, 8), ('TargetSpace', 240, 8), ('SpacesToSync', 248, 0),
    ('SpacesToSync', 0, 8), (None, 0, 1), ('bUseErrorLog', 321, 21),
    ('EnableClientTips', 328, 21), (None, 0, 1),
)


@dataclass(frozen=True)
class ItemMoveRequest:
    command_gid: int
    source_gid: int
    target_gids: tuple
    source_position: int
    target_position: int
    target_x: int
    target_y: int
    rotated: bool
    move_count: int
    target_index: int
    source_loot_guid: int
    target_loot_guids: tuple
    allow_container_replace_backup: bool
    drop_container_items: bool
    force_replace_shell: bool
    allow_relocate: bool
    source_weapon_gid: int
    target_weapon_gid: int
    origin_position: tuple
    origin_forward: tuple
    hit_interactor: bool
    command_owner_guid: int
    source_space_guid: int
    target_space_guid: int
    spaces_to_sync_guids: tuple
    use_error_log: bool
    enable_client_tips: bool


def _anchor(document, at, mnemonic, operands):
    rows = [row for function in document['functions'] for row in function['instructions']
        if row['rva'] == at]
    if not rows or any((row['mnemonic'], row['operands']) != (mnemonic, operands) for row in rows):
        raise ValueError('The native ItemMove serialization anchor changed: ' + at)


@lru_cache(maxsize=1)
def schema():
    documents = {}
    for relative, digest in PINS.items():
        raw = (ROOT / relative).read_bytes()
        if hashlib.sha256(raw).hexdigest() != digest:
            raise ValueError('The exact current ItemMove source changed: ' + relative)
        documents[relative] = json.loads(raw)
    capture = documents[CAPTURE]
    if (capture.get('client_sha256') != CLIENT or capture.get('status') != 'observed' or
            capture.get('identities_and_fields_rechecked') is not True or
            capture.get('native_methods_invoked') is not False or
            capture.get('native_layouts_constructed') is not False):
        raise ValueError('The actual existing native function qualification changed')
    owner, = [row for row in capture['owners'] if row['scope'] == 'InventoryManager']
    if (owner['class_path'] != '/Script/DFMGameplay.InventoryManager' or
            owner['existing_driver_class']['exclusive_index_maximum'] != EXCLUSIVE_INDEX_MAXIMUM):
        raise ValueError('The actual InventoryManager receiver changed')
    function, = [row for row in owner['rpc_functions']
        if row['function_name'] == 'ServerProcessItemMoveCmd']
    if (function['network_index'] != RPC_INDEX or function['layout_status'] != 'exported_existing' or
            function['status'] != 'observed_existing_function' or
            function['layout']['parent_count'] != 2 or function['layout']['command_count'] != 34):
        raise ValueError('The actual existing ItemMove function layout changed')
    commands = function['layout']['commands']
    actual = tuple((row.get('descriptor_name'), row['data_offset'], row['dispatch_opcode']) for row in commands)
    if actual != LEAVES:
        raise ValueError('The actual flattened ItemMove leaf order changed')
    hooks = {20: (0x10e5ce20, 0x286c000, 0x1ab60db0),
             5: (0x10e5ce20, 0x286bf70, 0x15a863c0)}
    for row in commands:
        opcode = row['dispatch_opcode']
        if opcode in hooks:
            hook = row['property_serializer_hook']
            leaf = row['property_scalar_leaf_hook']
            if (hook['target_rva'], leaf['target_rva'], hook['vtable_rva']) != hooks[opcode]:
                raise ValueError('The actual numeric ItemMove serializer changed')
        elif opcode in (0, 8, 9, 10, 21):
            target = {0: 0x10e5cde0, 8: 0x10e8ed20, 9: 0x10e29fa0,
                      10: 0x10e8ee50, 21: 0x10e8ebe0}[opcode]
            if row['property_serializer_hook']['target_rva'] != target:
                raise ValueError('The actual ItemMove property serializer changed')
    parameters = function['parameter_declarations']
    if ([(p['field']['name'], p['field']['storage_offset'], p['field']['element_bytes'])
            for p in parameters] != [('MoveCmd', 0, 328), ('EnableClientTips', 328, 1)] or
            parameters[0]['declared_struct_path'] != '/Script/DFMGameplay.ItemMoveCmd' or
            parameters[1]['bool_masks_hex'] != '0001ff'):
        raise ValueError('The actual ItemMove parent declaration changed')
    fields = {row['field']['name']: row for row in parameters[0]['fields']}
    for name in ('OriginPos1P', 'OriginForward1P'):
        if fields[name]['declared_struct_path'] != '/Script/CoreUObject.Vector':
            raise ValueError('The command vector is not the qualified plain native Vector')
    ops = documents[BASE + 'native-economy-world-rpc-struct-ops-records-v2.json']
    table, = [row for row in ops['vtables'] if row['name'] == 'ItemMoveCmdOps']
    if next(row for row in table['entries'] if row['slot'] == '0x70')['target_rva'] != '0xd5f3a0':
        raise ValueError('ItemMoveCmd acquired a native custom NetSerialize operation')
    defaults = documents[BASE + 'native-owned-weapon-rpc-field-order-and-defaults-v1.json']
    _anchor(defaults, '0xd5f3a0', 'xor', 'al, al')
    static = documents[BASE + 'native-economy-item-move-command-reflected-fields.json']
    declared, = [s for s in static['structs'] if s['name'] == 'ItemMoveCmd']
    for name in ('SourcePos', 'TargetPos'):
        field, = [row for row in declared['fields'] if row['name'] == name]
        if field['extra_pointer_rva'] != '0xd3c5a20':
            raise ValueError('The attach-position native enum getter changed')
    recursive = documents[BASE + 'native-world-item-move-rpc-recursive-enum-source-v1.json']
    _anchor(recursive, '0x12dc2554', 'call', 'qword ptr [rax + 0x90]')
    _anchor(recursive, '0x10e29faa', 'cmp', 'dword ptr [rdx + 0x54], 0xc')
    _anchor(recursive, '0x10e29fe2', 'inc', 'rax')
    enum_getter, = [f for f in recursive['functions'] if f['requested_rva'] == '0xd3c5a20']
    refs = [ref['rva'] for row in enum_getter['instructions'] for ref in row.get('rip_references', ())]
    enum, = documents['outputs/df-local-server/protocol/portable-map-spawn/inventory-schema.json']['enums']
    if enum['name'] != 'EAttachPosition' or enum['params_rva'] not in refs:
        raise ValueError('The native command enum is not the source-qualified EAttachPosition')
    maximum = max(row['value'] for row in enum['values'])
    width = (maximum + 1).bit_length()
    if width != maximum.bit_length() or width != 27:
        raise ValueError('The native enum and its automatic MAX no longer have the same 27-bit extent')
    arrays = documents[BASE + 'native-world-item-move-rpc-array-source-v1.json']
    _anchor(arrays, '0x12dc2125', 'mov', 'r8d, 2')
    _anchor(arrays, '0x12dc212b', 'call', 'qword ptr [rax + 0x60]')
    _anchor(arrays, '0x12dc23c5', 'call', '0x12dc23f0')
    rpc = documents[BASE + 'native-economy-interaction-normal-rpc-object-receive-v1.json']
    _anchor(rpc, '0x12db9679', 'shr', 'rcx, 0x11')
    _anchor(rpc, '0x12db9680', 'jne', '0x12db96e7')
    _anchor(rpc, '0x12db96cf', 'inc', 'qword ptr [r13 + 0xa8]')
    _anchor(rpc, '0x12db9742', 'call', '0x12dc23f0')
    header = documents[BASE + 'native-owned-weapon-rpc-layout-and-directional-content-header-v1.json']
    _anchor(header, '0x12863d2f', 'test', 'r15b, r15b')
    _anchor(header, '0x12863d39', 'jne', '0x128648d7')
    vector_source_pins()
    return dict(enum_bits=width, enum_values=tuple(row['value'] for row in enum['values']),
        command_count=34, parent_count=2, plain_struct_parent_presence_bits=1,
        bool_parent_additional_presence_bits=0, array_count_bits=16,
        exclusive_index_maximum=EXCLUSIVE_INDEX_MAXIMUM, rpc_index=RPC_INDEX,
        sources=dict(PINS), native_request_acceptance_verified=False)


def source_pins():
    result = dict(schema()['sources'])
    result.update(vector_source_pins())
    for relative in ('work/portable_world_item_move_request.py',
            'work/normal_map_archive_values.py',
            'outputs/df-local-server/dfserver/legacy_ds_bit_archive.py',
            'outputs/df-local-server/dfserver/legacy_ds_actor_fields.py'):
        result[relative] = hashlib.sha256((ROOT / relative).read_bytes()).hexdigest()
    return result


def _signed(reader):
    raw = reader.read_bits(32)
    return raw - (1 << 32) if raw & (1 << 31) else raw


def _guid(reader):
    value = reader.read_packed_int()
    if value == 1:
        raise ValueError('The default/export GUID branch is outside this ordinary request grammar')
    return value


def _array(reader, maximum, read):
    count = reader.read_bits(16)
    if count > maximum:
        raise ValueError('The native request array exceeds its explicit local bound')
    return tuple(read(reader) for _ in range(count))


def decode_field(field):
    contract = schema()
    if type(field) is not ClassFieldEnvelope or field.rep_index != RPC_INDEX:
        raise ValueError('Only the exact observed InventoryManager ItemMove field is supported')
    bits = field.payload_bit_count
    if (type(bits) is not int or not 1 <= bits <= MAX_PARAMETER_BITS or
            type(field.payload) is not bytes or len(field.payload) != (bits + 7) // 8 or
            int.from_bytes(field.payload, 'little') >> bits):
        raise ValueError('One exact bounded native ItemMove parameter archive is required')
    reader = BitReader(field.payload, bit_count=bits)
    if not reader.read_bool():
        raise ValueError('A gameplay transfer requires its present MoveCmd parent')
    values = [reader.read_bits(64), reader.read_bits(64),
        _array(reader, MAX_TARGET_GIDS, lambda r: r.read_bits(64))]
    for _ in range(2):
        value = reader.read_bits(contract['enum_bits'])
        if value not in contract['enum_values']:
            raise ValueError('The command attach position has no installed enum declaration')
        values.append(value)
    values.extend((_signed(reader), _signed(reader), reader.read_bool(),
        _signed(reader), _signed(reader), _guid(reader),
        _array(reader, MAX_REFERENCE_ARRAY, _guid)))
    values.extend(reader.read_bool() for _ in range(4))
    values.extend(reader.read_bits(64) for _ in range(2))
    binding = qualify_vector_contract()
    values.extend(read_plain_vector(reader, binding=binding, no_byteswap=True) for _ in range(2))
    values.extend((reader.read_bool(), _guid(reader), _guid(reader), _guid(reader),
        _array(reader, MAX_REFERENCE_ARRAY, _guid), reader.read_bool(), reader.read_bool()))
    if reader.remaining:
        raise ValueError('The native ItemMove parameters do not end at exact EOF')
    return ItemMoveRequest(*values)


def decode_bunch(bunch, *, pawn_channel, inventory_manager_guid):
    """One admitted complete owning component request; this does no admission."""
    schema()
    if (type(pawn_channel) is not int or not 2 <= pawn_channel <= 65535 or
            type(inventory_manager_guid) is not int or
            not 2 <= inventory_manager_guid < 1 << 32 or inventory_manager_guid & 1):
        raise ValueError('The actual owning Pawn channel and default InventoryManager GUID are required')
    if (type(bunch) is not WireBunch or bunch.channel_index != pawn_channel or
            type(bunch.channel_sequence) is not int or not 0 <= bunch.channel_sequence < 1024 or
            bunch.reliable is not True or type(bunch.channel_name) is not ChannelName or
            bunch.channel_name != ChannelName(hardcoded_index=102) or
            type(bunch.close_reason) is not int or bunch.close_reason != 0 or
            any(getattr(bunch, name) is not False for name in (
                'open', 'close', 'flag4', 'connection_flag', 'package_exports', 'must_be_mapped',
                'partial', 'partial_initial', 'partial_final'))):
        raise ValueError('One complete reliable admitted owning InventoryManager RPC is required')
    bits = bunch.payload_bits
    if (type(bits) is not int or not 1 <= bits <= MAX_PARAMETER_BITS + 256 or
            type(bunch.payload) is not bytes or len(bunch.payload) != (bits + 7) // 8 or
            int.from_bytes(bunch.payload, 'little') >> bits):
        raise ValueError('One exact bounded owning component archive is required')
    reader = BitReader(bunch.payload, bit_count=bits)
    if reader.read_bool() or reader.read_bool() or reader.read_packed_int() != inventory_manager_guid:
        raise ValueError('The request is not the current ordinary InventoryManager content block')
    # Client to server headers omit the server's stable-name selector bit.
    length = reader.read_packed_int()
    payload = reader.read_payload(length)
    if reader.remaining:
        raise ValueError('Mixed owning component content must be isolated by the admitted caller')
    fields = read_class_fields(BitReader(payload, bit_count=length),
        profile=NormalClassFieldProfile(EXCLUSIVE_INDEX_MAXIMUM, False))
    if len(fields) != 1:
        raise ValueError('Only one isolated native ItemMove field is supported')
    return decode_field(fields[0])
