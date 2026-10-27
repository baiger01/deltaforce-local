"""Native SafeBox F-action values when current tag nonfast mode is confirmed.

Only ordinary FName tags are supported. The caller proves current owned
Interactor admission, singleton mode, static box resolution and export ACKs.
Context coordinates are decoded as client input and confer no movement or
distance authority. No request is executed or acknowledged by this decoder.
"""
from dataclasses import dataclass
from functools import lru_cache
import hashlib
import json

from dfserver.legacy_ds_actor_fields import ClassFieldEnvelope
from dfserver.legacy_ds_bit_archive import BitReader
from normal_map_archive_values import (qualify_contract, read_name, source_pins as name_pins,
    qualify_vector_contract, read_plain_vector)
import portable_loot_box_codec as boxes
import portable_world_item_move_request as moves
import portable_world_box_seed as seeds

ROOT = moves.ROOT
BASE = moves.BASE
PINS = {
    BASE + 'native-economy-tag-serialize-and-end-delegate-v1.json':
        '5afd0921a60808438512a7357eab70c77eca704c11d98ffe9a1a90f564e7405f',
    BASE + 'native-economy-gameplaytag-ops-vtable-probe-v1.json':
        '8ac2b717eef9a7ed00655aae54f6459f9a84940692761f05f259b4f7241fd781',
    BASE + 'native-world-gameplaytag-ops-wrapper-v1.json':
        'aa13dfc62ee8c48cae7978986a8b0815c45a48307fb659f931a57c4b6132cebe',
    BASE + 'native-world-gameplaytag-ops-netserialize-bridge-v1.json':
        '3b37ade1ac8fb14bb42279a894f8a0722b1d40f3b2da602260e2c7aafc7448de',
    BASE + 'native-world-interacting-context-struct-ops-record-v1.json':
        'd90bf9a7bbb9b4b9159c03aa524cfabab88a73c8590e110c1d00ea1d38fc1528',
    BASE + 'native-world-interacting-context-ops-factory-v1.json':
        'edd0a9598d1053dadc0f76cdb7cf1620d0ec4e1b64fb4035bf21660139498989',
    BASE + 'native-world-interacting-context-ops-vtable-v1.json':
        '7b47614cb918665f4894c2d03e9a27ce6ca904beb00906d7ec17805643106058',
}
CONTEXT_FIELDS = (
    ('OpenDoorInFrontOrBack', 0, 4, 0x15a863c0),
    ('CloseDoorPushOrPull', 4, 4, 0x15a863c0),
    ('OverrideOpenDoorInFrontOrBack', 8, 4, 0x15a863c0),
    ('SingleItemContainerIndex', 12, 4, 0x15a863c0),
    ('Client2ServerIndex', 16, 4, 0x15a863c0),
    ('OriginPosByClient', 20, 12, 0x15a86f40),
    ('OriginForwardByClient', 32, 12, 0x15a86f40),
    ('bHitInteractorByClient', 44, 1, 0x15a868a0),
    ('bDownloadItemToSafeBoxFirst', 45, 1, 0x15a868a0),
    ('bCanCharacterEnterEgg', 46, 1, 0x15a868a0),
    ('bBraveGameConvey_FirstMeet', 47, 1, 0x15a868a0),
    ('DialogueSelectIndex', 48, 4, 0x15a863c0),
)


@dataclass(frozen=True)
class InteractingContext:
    open_front_or_back: int
    close_push_or_pull: int
    override_open_front_or_back: int
    single_item_index: int
    client_to_server_index: int
    origin_position: tuple
    origin_forward: tuple
    hit_interactor: bool
    download_safe_first: bool
    can_character_enter_egg: bool
    brave_first_meet: bool
    dialogue_select_index: int


@dataclass(frozen=True)
class InteractRequest:
    function_index: int
    target_guid: int
    binding: boxes.LootBoxBinding
    operator_tag: object
    interacting_context: InteractingContext | None


@lru_cache(maxsize=1)
def schema():
    moves.schema()
    documents = {}
    for relative, digest in PINS.items():
        raw = (ROOT / relative).read_bytes()
        if hashlib.sha256(raw).hexdigest() != digest:
            raise ValueError('The exact native F-interaction source changed: ' + relative)
        documents[relative] = json.loads(raw)
    capture = json.loads((ROOT / moves.CAPTURE).read_bytes())
    owner, = [row for row in capture['owners'] if row['scope'] == 'InteractorComponent']
    if (owner['class_path'] != '/Script/SOL.SOLInteractorComponent' or
            owner['existing_driver_class']['exclusive_index_maximum'] != 168):
        raise ValueError('The actual owning Interactor receiver changed')
    for name, index, names in (
            ('ServerInteractAction', 72, ('targetObj', 'OperatorTag')),
            ('ServerExecuteInteractByTag', 71, ('InActor', 'InTag', 'InInteractingContext'))):
        function, = [row for row in owner['rpc_functions'] if row['function_name'] == name]
        if function['network_index'] != index:
            raise ValueError('The actual native interaction RPC index changed')
        params = function['parameter_declarations']
        if tuple(row['field']['name'] for row in params) != names:
            raise ValueError('The actual interaction parent order changed')
        if (params[0]['declared_native_class_path'] != '/Script/Engine.Actor' or
                params[0]['serializer_hook']['target_rva'] != 0x10e8ed20 or
                params[1]['declared_struct_path'] != '/Script/GameplayTags.GameplayTag' or
                params[1]['serializer_hook']['target_rva'] != 0x10e8ee50):
            raise ValueError('The actual interaction Actor/tag property types changed')
        if index == 71:
            context = params[2]
            if (context['declared_struct_path'] != '/Script/GPGameplay.InteractingContext' or
                    context['field']['element_bytes'] != 52):
                raise ValueError('The exact plain native interaction context changed')
            actual = tuple((row['field']['name'], row['field']['storage_offset'],
                row['field']['element_bytes'], row['field']['field_vtable_rva']) for row in context['fields'])
            if actual != CONTEXT_FIELDS:
                raise ValueError('The exact interaction context reflected leaf order changed')
            if any(row.get('bool_masks_hex') != '0001ff' for row in context['fields']
                    if row['field']['field_vtable_rva'] == 0x15a868a0):
                raise ValueError('The actual interaction context bool masks changed')
    table = documents[BASE + 'native-world-interacting-context-ops-vtable-v1.json']['records'][0]
    if (table['rva'] != '0x167ad210' or next(row for row in table['qwords']
            if row['offset'] == '0x70')['image_rva'] != '0xd5f3a0'):
        raise ValueError('The context acquired a native custom NetSerialize operation')
    factory = documents[BASE + 'native-world-interacting-context-ops-factory-v1.json']
    moves._anchor(factory, '0x60a4d6a', 'mov', 'dword ptr [rax + 8], 0x34')
    tag = documents[BASE + 'native-economy-tag-serialize-and-end-delegate-v1.json']
    moves._anchor(tag, '0x1242797e', 'cmp', 'byte ptr [rdi + 0x181], 0')
    moves._anchor(tag, '0x1242798d', 'je', '0x12427e69')
    moves._anchor(tag, '0x12427e72', 'call', 'qword ptr [rax + 0x50]')
    wrapper = documents[BASE + 'native-world-gameplaytag-ops-wrapper-v1.json']
    bridge = documents[BASE + 'native-world-gameplaytag-ops-netserialize-bridge-v1.json']
    moves._anchor(wrapper, '0x1242c505', 'jmp', '0x12427750')
    moves._anchor(bridge, '0x12427759', 'call', '0x12427940')
    ops = documents[BASE + 'native-economy-gameplaytag-ops-vtable-probe-v1.json']['vtables'][0]
    if next(row for row in ops['entries'] if row['slot'] == '0x70')['target_rva'] != '0x1242c500':
        raise ValueError('The source GameplayTag CppOps path changed')
    defaults = seeds._sources()[seeds.BASE + 'native-economy-door-container-component-defaults-and-tags-v1.json']
    box, = [e for p in defaults['packages'] for e in p['exports']
        if e['name'] == 'Default__BP_Interactor_Container_SafeBox_C']
    tags = tuple(box['properties']['InteractableTags']['value']['tag_names'])
    if 'Interactor.CheckCollision.ContainerBox.Open' not in tags:
        raise ValueError('The actual SafeBox native open operator tag changed')
    qualify_contract()
    return dict(exclusive_index_maximum=168, action_index=72, execute_index=71,
        supported_source_tags=tags, context_leaf_bits=388,
        existing_function_layout_observed=False, native_request_acceptance_verified=False)


def source_pins():
    schema()
    pins = moves.source_pins()
    pins.update(seeds.source_pins())
    pins.update({row['path']: row['sha256'] for row in name_pins()})
    pins.update(PINS)
    relative = 'work/portable_world_interact_request.py'
    pins[relative] = hashlib.sha256((ROOT / relative).read_bytes()).hexdigest()
    return pins


def decode_field(field, *, bindings_by_guid, nonfast_replication_confirmed,
        references_resolved, exports_acknowledged):
    contract = schema()
    if (nonfast_replication_confirmed is not True or references_resolved is not True or
            exports_acknowledged is not True):
        raise ValueError('Actual current nonfast tag mode and mapped export ACKs are required')
    if type(field) is not ClassFieldEnvelope or field.rep_index not in (71, 72):
        raise ValueError('Only the actual owning Interactor action/execute fields are supported')
    if type(bindings_by_guid) is not dict or not 1 <= len(bindings_by_guid) <= 3:
        raise ValueError('The bounded actual static box mapping is required')
    paths = set()
    for guid, binding in bindings_by_guid.items():
        boxes.qualify_binding(binding)
        if (type(guid) is not int or not 3 <= guid < 1 << 32 or not guid & 1 or
                binding.object_path in paths):
            raise ValueError('The current source box GUID bindings are invalid or aliased')
        paths.add(binding.object_path)
    bits = field.payload_bit_count
    if (type(bits) is not int or not 1 <= bits <= 4096 or type(field.payload) is not bytes or
            len(field.payload) != (bits + 7) // 8 or int.from_bytes(field.payload, 'little') >> bits):
        raise ValueError('One exact bounded native interaction archive is required')
    reader = BitReader(field.payload, bit_count=bits)
    if not reader.read_bool():
        raise ValueError('A world interaction requires its present target Actor')
    guid = reader.read_packed_int()
    if guid not in bindings_by_guid or not reader.read_bool():
        raise ValueError('A world interaction requires its exact mapped target and present native tag')
    tag = read_name(reader, binding=qualify_contract())
    if tag.original_number != 0 or tag.base_name not in contract['supported_source_tags']:
        raise ValueError('The native operator has no actual SafeBox source tag')
    context = None
    if field.rep_index == 71 and reader.read_bool():
        values = [moves._signed(reader) for _ in range(5)]
        vector = qualify_vector_contract()
        values.extend(read_plain_vector(reader, binding=vector, no_byteswap=True) for _ in range(2))
        values.extend(reader.read_bool() for _ in range(4))
        values.append(moves._signed(reader))
        context = InteractingContext(*values)
    if reader.remaining:
        raise ValueError('The native interaction archive must end at exact EOF')
    return InteractRequest(field.rep_index, guid, bindings_by_guid[guid], tag, context)
