"""Pure source-qualified SafeBox content values and per-recipient ACK cursors.

The caller binds the existing static Actor and commits cursor_after_ack only
after every returned stage has a real receipt. This module sends no packet,
opens no Actor channel, allocates no item GID and decodes no unqualified RPC.
"""
from dataclasses import dataclass,replace
import hashlib
import json
from pathlib import Path
import sys

ROOT=Path(__file__).resolve().parent.parent
SERVER=ROOT/'outputs/df-local-server'
if str(SERVER) not in sys.path:
    sys.path.insert(0,str(SERVER))
from dfserver.legacy_ds_bit_archive import BitReader,BitWriter
from dfserver.legacy_ds_actor_content import ActorContentBlock,write_actor_content_block
from dfserver.legacy_ds_actor_fields import ClassFieldEnvelope,NormalClassFieldProfile,build_class_field_content
from dfserver.legacy_ds_inventory_items import InventoryFastArrayElement,InventoryFastArrayDelta
from dfserver.legacy_ds_inventory_state import (InventoryStateProfile,CLIENT_SHA256,SCHEMA_SHA256,
    write_inventory_spaces,read_inventory_spaces,inventory_state_source_pins)
from dfserver.legacy_ds_inventory_gun import (GunInventoryItem,write_inventory_custom_delta,
    write_inventory_item,inventory_gun_source_pins)
from dfserver.legacy_ds_inventory_stack import StackedInventoryItem
from dfserver.legacy_ds_inventory_condition import ConditionInventoryItem
import portable_map_inventory as inventory_adapter

CAPTURE='work/native-client-tests/1792328560808149500/economy-loaded-interactors.json'
RPC_CAPTURE='work/native-client-tests/1792337436036819800/world-interaction-rpc-metadata.json'
PINS={
    CAPTURE:'2125c1de4c447bfac89a40da89cf991c29cb566e0833f2d88448cb668adc9c2b',
    RPC_CAPTURE:'56d64f3cc8dab71d6b62f7e7cb98f6f63584b503af8340be40a295ded314f50c',
    'work/evidence/map-system-audit-20261018/native-economy-lootbox-correct-netserialize-body-v1.json':
        'cb24ad7a10659c46eba8904f992b06fc2ee7dbc2c12891503e05cc7f1982ab4d',
    'work/evidence/map-system-audit-20261018/native-economy-lootbox-actual-netserialize-v1.json':
        '758270fe6bad07f4e07d810d9a6f4e968d23a664e4ccb04dc417d00636d5ea91',
    'outputs/df-local-server/protocol/game_item_catalog.json':
        '5b30d2179d77e62294e71d7510c21e03aa664f97c9c1c07399e911f8c91376e8',
}
for _catalog in ('protocol/native_keycard_catalog.json','protocol/weapon_component_catalog.json',
        'protocol/portable-map-spawn/equipment-condition-catalog.json'):
    PINS['outputs/df-local-server/'+_catalog]=inventory_adapter.CATALOG_PINS[_catalog]
PROFILE=InventoryStateProfile(CLIENT_SHA256,SCHEMA_SHA256,13,True,False)
SAFE_CLASS='/Game/BluePrints/Interact/BP_Interactor_Container_SafeBox.BP_Interactor_Container_SafeBox_C'
MAX_ITEMS=256
MAX_BLOCK_BITS=8192
_DOCUMENTS={}


@dataclass(frozen=True)
class ValueBits:
    payload: bytes
    payload_bit_count: int


@dataclass(frozen=True)
class LootBoxBinding:
    object_path: str
    class_path: str
    schema_sha256: str
    exclusive_index_maximum: int
    item_cache_index: int
    spaces_handle: int
    empty_handle: int
    opened_handle: int = 116


@dataclass(frozen=True)
class LootBoxCursor:
    recipient_scope: tuple[str,int]
    object_path: str
    schema_sha256: str
    last_array_key: int
    known_items: tuple
    known_spaces: tuple
    known_opened: bool | None = None


@dataclass(frozen=True)
class LootBoxProjection:
    stages: tuple[ActorContentBlock,...]
    cursor_after_ack: LootBoxCursor
    qualification: dict


def _sources():
    docs={}
    for relative,expected in PINS.items():
        raw=(ROOT/relative).read_bytes()
        if hashlib.sha256(raw).hexdigest()!=expected:
            raise ValueError('Changed loot-box source '+relative)
        if relative not in _DOCUMENTS:
            _DOCUMENTS[relative]=json.loads(raw)
        docs[relative]=_DOCUMENTS[relative]
    return docs


def source_pins():
    _sources()
    pins=dict(PINS)
    pins.update({'outputs/df-local-server/'+key:value for key,value in inventory_state_source_pins().items()})
    pins.update({'outputs/df-local-server/'+key:value for key,value in inventory_gun_source_pins().items()})
    for relative in ('work/portable_loot_box_codec.py','work/portable_map_inventory.py',
            'outputs/df-local-server/dfserver/legacy_ds_actor_content.py',
            'outputs/df-local-server/dfserver/legacy_ds_actor_fields.py',
            'outputs/df-local-server/dfserver/legacy_ds_bit_archive.py',
            'outputs/df-local-server/dfserver/legacy_ds_wire_codec.py',
            'outputs/df-local-server/dfserver/legacy_ds_inventory_state.py',
            'outputs/df-local-server/dfserver/legacy_ds_inventory_items.py',
            'outputs/df-local-server/dfserver/legacy_ds_inventory_stack.py',
            'outputs/df-local-server/dfserver/legacy_ds_inventory_gun.py',
            'outputs/df-local-server/dfserver/legacy_ds_inventory_gun_desc.py',
            'outputs/df-local-server/dfserver/legacy_ds_inventory_condition.py',
            'outputs/df-local-server/dfserver/legacy_ds_inventory_keychain.py'):
        pins[relative]=hashlib.sha256((ROOT/relative).read_bytes()).hexdigest()
    return pins


def qualified_bindings():
    docs=_sources()
    result=[]
    for actor in docs[CAPTURE]['actors']:
        current=actor['existing_driver_class']
        cache=[field for node in current['cache_nodes'] for field in node['fields']]
        fields=current['layout']['commands']
        def one(rows,name):
            matches=[row for row in rows if row.get('descriptor_name')==name]
            if len(matches)!=1:
                raise ValueError('The actual box receiver field is ambiguous: '+name)
            return matches[0]
        item=one(cache,'RepItemArray')
        spaces,empty,opened=(one(fields,name) for name in ('LootBoxRepData','bIsEmpty','bIsOpened'))
        if (actor['class_path']!=SAFE_CLASS or current['exclusive_index_maximum']!=85 or
                item['rep_index']!=55 or item['descriptor_representation']!=0 or
                (spaces['relative_handle'],spaces['dispatch_opcode'])!=(103,2) or
                (empty['relative_handle'],empty['dispatch_opcode'])!=(113,21) or
                (opened['relative_handle'],opened['dispatch_opcode'])!=(116,21)):
            raise ValueError('The source SafeBox receiver binding changed')
        result.append(LootBoxBinding(actor['object_path'],SAFE_CLASS,PINS[CAPTURE],85,55,103,113))
    if len(result)!=3 or len({row.object_path for row in result})!=3:
        raise ValueError('The source-qualified SafeBox subset changed')
    return tuple(result)


def qualify_binding(binding):
    if type(binding) is not LootBoxBinding or binding not in qualified_bindings():
        raise ValueError('An exact source-qualified existing SafeBox binding is required')
    return binding


def encode_spaces(spaces):
    source_pins()
    writer=BitWriter(maximum_bits=MAX_BLOCK_BITS)
    write_inventory_spaces(writer,spaces,profile=PROFILE)
    return ValueBits(writer.to_bytes(),writer.bit_count)


def read_spaces(reader):
    source_pins()
    return read_inventory_spaces(reader,profile=PROFILE)


def decode_spaces(payload,bit_count):
    reader=BitReader(payload,bit_count=bit_count)
    value=read_spaces(reader)
    if reader.remaining:
        raise ValueError('Trailing box space value bits are outside the qualified grammar')
    return value


def item_quantity(value):
    from dfserver.legacy_ds_inventory_stack import StackedInventoryItem
    cursor,count=value,None
    while hasattr(cursor,'item'):
        if type(cursor) is StackedInventoryItem:
            if count is not None:
                raise ValueError('Repeated optional stack features are unsupported')
            count=cursor.stack.item_count
        cursor=cursor.item
    return cursor.item_count if count is None else count


def validate_items(items):
    if type(items) is not tuple or len(items)>MAX_ITEMS:
        raise ValueError('A bounded complete typed box item tuple is required')
    docs=_sources()
    definitions=docs['outputs/df-local-server/protocol/game_item_catalog.json']['rows']
    cards=docs['outputs/df-local-server/protocol/native_keycard_catalog.json']['keycards']
    equipment=docs['outputs/df-local-server/protocol/portable-map-spawn/equipment-condition-catalog.json']['rows']
    guns=docs['outputs/df-local-server/protocol/weapon_component_catalog.json']['rows']
    gids,ids=set(),set()
    for element in items:
        if type(element) is not InventoryFastArrayElement or type(element.element_id) is not int or not 0<=element.element_id<1<<31:
            raise ValueError('A separate nonnegative FastArray element ID is required')
        base=inventory_adapter.base_item(element.item)
        row=definitions.get(str(base.template_id))
        if row is None or type(base.item_gid) is not int or not 0<base.item_gid<1<<64:
            raise ValueError('The box item has no real installed template or instance GID')
        count=item_quantity(element.item)
        if type(count) is not int or not 1<=count<=row['max_stack_count']:
            raise ValueError('The box quantity exceeds its actual catalog maximum')
        layers=[]
        cursor=element.item
        while hasattr(cursor,'item'):
            layers.append(cursor)
            cursor=cursor.item
        stack=next((value.stack for value in layers if type(value) is StackedInventoryItem),None)
        if ((row['max_stack_count']>1 and stack is None) or
                stack is not None and stack.item_num_max!=row['max_stack_count']):
            raise ValueError('The actual source stack maximum must be preserved in its optional block')
        template=str(base.template_id)
        condition=next((value for value in layers if type(value) is ConditionInventoryItem),None)
        expected=cards.get(template) or equipment.get(template)
        if expected is not None:
            maximum=expected.get('durability',expected.get('max_durability'))
            if (condition is None or condition.durability is None or
                    not 0<condition.durability[1]<=maximum or
                    template in cards and condition.durability[1]!=maximum):
                raise ValueError('The actual required item condition block is missing or outside source bounds')
        if template in guns and not any(type(value) is GunInventoryItem for value in layers):
            raise ValueError('The actual firearm requires its complete qualified GunDesc block')
        for value in layers:
            if type(value) is GunInventoryItem and any(row.durability!=0 for row in value.description.rows):
                raise ValueError('Nonzero gun-part raw health needs separate native type qualification')
        if base.item_gid in gids or element.element_id in ids:
            raise ValueError('Repeated box GID or FastArray element ID')
        gids.add(base.item_gid)
        ids.add(element.element_id)
        writer=BitWriter(maximum_bits=MAX_BLOCK_BITS)
        write_inventory_item(writer,element.item,profile=PROFILE)
    return items


def _batches(values):
    pending=[]
    for value in values:
        if type(value.item) is GunInventoryItem:
            if pending:
                yield tuple(pending)
                pending=[]
            yield (value,)
        else:
            pending.append(value)
            if len(pending)==4:
                yield tuple(pending)
                pending=[]
    if pending:
        yield tuple(pending)


def project(binding,spaces,items,*,recipient_scope,cursor=None,opened=None):
    """Build values for an already-bound Actor; returned cursor is pending ACK."""
    qualify_binding(binding)
    if opened is not None and type(opened) is not bool:
        raise ValueError('An explicit authoritative boolean opened state is required')
    if (type(recipient_scope) is not tuple or len(recipient_scope)!=2 or
            type(recipient_scope[0]) is not str or not 1<=len(recipient_scope[0])<=256 or
            type(recipient_scope[1]) is not int or not 0<recipient_scope[1]<1<<64):
        raise ValueError('An explicit current match/player recipient namespace is required')
    pins=source_pins()
    encoded=encode_spaces(spaces)
    validate_items(items)
    if cursor is not None:
        if (type(cursor) is not LootBoxCursor or cursor.recipient_scope!=recipient_scope or cursor.object_path!=binding.object_path or
                cursor.schema_sha256!=binding.schema_sha256 or type(cursor.last_array_key) is not int or
                not -1<=cursor.last_array_key<1<<31 or
                cursor.known_opened is not None and type(cursor.known_opened) is not bool):
            raise ValueError('The committed box recipient cursor is foreign or invalid')
        validate_items(cursor.known_items)
    previous={} if cursor is None else {v.element_id:v for v in cursor.known_items}
    current={v.element_id:v for v in items}
    if any(previous[key].item.item_gid!=current[key].item.item_gid for key in previous.keys()&current.keys()):
        raise ValueError('A FastArray element ID cannot be rebound to another inventory GID')
    deleted=tuple(sorted(previous.keys()-current.keys()))
    changed=tuple(v for v in items if previous.get(v.element_id)!=v)
    geometry_changed=cursor is None or cursor.known_spaces!=spaces
    empty_changed=cursor is None or bool(cursor.known_items)!=bool(items)
    opened_changed=opened is not None and (cursor is None or cursor.known_opened is not opened)
    stages=[]
    ordinary=None
    if geometry_changed or empty_changed or opened_changed:
        writer=BitWriter(maximum_bits=MAX_BLOCK_BITS)
        writer.write_bool(False)
        if geometry_changed:
            writer.write_packed_int(binding.spaces_handle)
            writer.write_payload(encoded.payload,encoded.payload_bit_count)
        if empty_changed:
            writer.write_packed_int(binding.empty_handle)
            writer.write_bool(not items)
        if opened_changed:
            writer.write_packed_int(binding.opened_handle)
            writer.write_bool(opened)
        writer.write_packed_int(0)
        ordinary=ActorContentBlock(True,writer.to_bytes(),writer.bit_count)
        if geometry_changed:
            stages.append(ordinary)
    key=-1 if cursor is None else cursor.last_array_key
    batches=list(_batches(changed))
    if deleted and not batches:
        batches=[()]
    for index,batch in enumerate(batches):
        if key>=(1<<31)-1:
            raise ValueError('The local box recipient key is exhausted; a new qualified baseline is required')
        next_key=max(1,key+1)
        delta=InventoryFastArrayDelta(next_key,key,
            deleted if index==0 else (),batch)
        writer=BitWriter(maximum_bits=MAX_BLOCK_BITS)
        write_inventory_custom_delta(writer,delta,profile=PROFILE)
        stages.append(build_class_field_content((ClassFieldEnvelope(binding.item_cache_index,
            writer.to_bytes(),writer.bit_count),),profile=NormalClassFieldProfile(binding.exclusive_index_maximum,False)))
        key=next_key
    if ordinary is not None and not geometry_changed:
        stages.append(ordinary)
    bits=[]
    for stage in stages:
        writer=BitWriter(maximum_bits=MAX_BLOCK_BITS)
        write_actor_content_block(writer,stage)
        bits.append(writer.bit_count)
    known_opened=opened if opened is not None else None if cursor is None else cursor.known_opened
    after=LootBoxCursor(recipient_scope,binding.object_path,binding.schema_sha256,key,items,spaces,known_opened)
    report=dict(kind='source_qualified_existing_safebox_content_projection',source_pins=pins,
        object_path=binding.object_path,ordinary_spaces_handle=binding.spaces_handle,
        recipient_scope=recipient_scope,
        ordinary_empty_handle=binding.empty_handle,item_class_cache_index=binding.item_cache_index,
        ordinary_opened_handle=binding.opened_handle,opened_state=known_opened,
        class_cache_exclusive_maximum=binding.exclusive_index_maximum,
        deleted_element_ids=list(deleted),changed_gids=[e.item.item_gid for e in changed],
        stage_count=len(stages),actor_block_bits=bits,max_actor_block_bits=MAX_BLOCK_BITS,
        cursor_committed_by_this_pure_function=False,cursor_commit_requires_all_stages_actual_ACK=True,
        static_actor_reference_and_current_world_membership_required=True,
        full_udp_packet_budget_checked=False,native_receipt_verified=False,
        rpc_parameter_decoder_qualified=False)
    return LootBoxProjection(tuple(stages),after,report)


def preflight_packets(projection,*,channel_index,initial_channel_sequence,packet_template,max_packet_bytes):
    """Budget complete application datagrams with explicit caller transport state.

    This serializes nothing for transmission and does not acknowledge or advance
    a live channel. Root transport must build fresh headers when actually sending.
    """
    from dfserver.legacy_ds_wire_codec import (WirePacket,WireBunch,ChannelName,
        SEQUENCE_MASK,encode_observed_application)
    if (type(projection) is not LootBoxProjection or type(packet_template) is not WirePacket or
            packet_template.bunches or type(channel_index) is not int or not 2<=channel_index<=65535 or
            type(initial_channel_sequence) is not int or not 0<=initial_channel_sequence<1024):
        raise ValueError('Explicit source projection and current empty Actor packet template are required')
    source_pins()
    packets=[]
    for index,stage in enumerate(projection.stages):
        writer=BitWriter(maximum_bits=max_packet_bytes*8)
        write_actor_content_block(writer,stage)
        bunch=WireBunch(channel_index,writer.to_bytes(),writer.bit_count,reliable=True,
            channel_sequence=(initial_channel_sequence+index)%1024,
            channel_name=ChannelName(hardcoded_index=102))
        packet=replace(packet_template,sequence=(packet_template.sequence+index)&SEQUENCE_MASK,
            bunches=(bunch,),consumed_bits=0)
        packets.append(encode_observed_application(packet,max_packet_bytes=max_packet_bytes,
            received_by_server=False))
    return tuple(packets)
