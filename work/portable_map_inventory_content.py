"""Pure ACK-ordered content groups for the existing owning InventoryManager.

The caller owns Actor/component GUID bindings and transports each later group
only after the previous group's real ACK. No process reads or sends occur here.
"""
from dataclasses import dataclass
import hashlib
import json
from pathlib import Path

import portable_map_inventory as adapter
from dfserver.legacy_ds_actor_fields import (ClassFieldEnvelope,NormalClassFieldProfile,build_class_field_content)
from dfserver.legacy_ds_bit_archive import BitWriter, MAX_BITS
from dfserver.legacy_ds_default_subobject import DefaultSubobjectUpdate
from dfserver.legacy_ds_inventory_items import InventoryFastArrayDelta
from dfserver.legacy_ds_inventory_state import (InventoryStateProfile,CLIENT_SHA256,SCHEMA_SHA256,write_inventory_repdata)
from dfserver.legacy_ds_inventory_gun import GunInventoryItem,write_inventory_custom_delta

ROOT=adapter.ROOT
SCHEMA_PATH='outputs/df-local-server/protocol/portable-map-spawn/inventory-schema.json'
CONTINUATION_PATH='work/evidence/map-system-audit-20261018/native-economy-inventory-append-continuation-contract.json'
CONTINUATION_SHA='d35465c3c36bd057288c8bd3129aa98ac99f677ef7a5349cc43279fca30217aa'
PROFILE=InventoryStateProfile(CLIENT_SHA256,SCHEMA_SHA256,13,True,False)
ZERO_VALUES=(0,0,0,0,0,0,0)


@dataclass(frozen=True)
class InventoryContentProjection:
    groups: tuple[tuple[DefaultSubobjectUpdate,...],...]
    qualification: dict


def _schema(schema):
    path=ROOT/SCHEMA_PATH if schema is None else schema
    if isinstance(path,(Path,str)):
        raw=Path(path).read_bytes()
    elif type(path) is bytes:
        raw=path
    else:
        raise ValueError('Exact source inventory schema bytes or path required')
    if hashlib.sha256(raw).hexdigest()!=SCHEMA_SHA256:
        raise ValueError('Changed actual inventory schema')
    value=json.loads(raw)
    binding=value['binding']
    properties={p['name']:p for p in binding['properties']}
    if (binding['component_name']!='InventoryManager' or binding['component_class']!='/Script/DFMGameplay.InventoryManager' or
            binding['exclusive_index_maximum']!=53 or properties['RepData']['layout_relative_handle']!=10 or
            properties['RepData']['wire_path']!='ordinary_rep_layout_netserialize' or
            properties['RepItemArray']['class_cache_index']!=7 or properties['RepItemArray']['wire_path']!='class_cache_custom_delta' or
            value['fast_array']['archive_network_version']!=13 or value['fast_array']['legacy_prefix_value'] is not False):
        raise ValueError('Changed source native inventory binding')
    return value


def source_pins():
    pins=adapter.source_pins()
    raw=(ROOT/CONTINUATION_PATH).read_bytes()
    if hashlib.sha256(raw).hexdigest()!=CONTINUATION_SHA:
        raise ValueError('Changed native append continuation source')
    contract=json.loads(raw)
    if (contract['kind']!='native_inventory_monotonic_append_continuation_contract' or
            contract['sender_old_state_absent_base_key']!=-1):
        raise ValueError('Unqualified continuation key policy')
    pins[CONTINUATION_PATH]=CONTINUATION_SHA
    for relative in ('work/portable_map_inventory_content.py',
            'outputs/df-local-server/dfserver/legacy_ds_inventory_items.py',
            'outputs/df-local-server/dfserver/legacy_ds_inventory_state.py',
            'outputs/df-local-server/dfserver/legacy_ds_inventory_stack.py',
            'outputs/df-local-server/dfserver/legacy_ds_inventory_keychain.py',
            'outputs/df-local-server/dfserver/legacy_ds_inventory_condition.py',
            'outputs/df-local-server/dfserver/legacy_ds_inventory_gun.py',
            'outputs/df-local-server/dfserver/legacy_ds_inventory_gun_desc.py',
            'outputs/df-local-server/dfserver/legacy_ds_inventory_geometry.py',
            'outputs/df-local-server/dfserver/legacy_ds_actor_fields.py',
            'outputs/df-local-server/dfserver/legacy_ds_default_subobject.py'):
        pins[relative]=hashlib.sha256((ROOT/relative).read_bytes()).hexdigest()
    return pins


def _item_groups(items):
    pending=[]
    for element in items:
        if type(element.item) is GunInventoryItem:
            if pending:
                yield tuple(pending)
                pending=[]
            yield (element,)
        else:
            pending.append(element)
            if len(pending)==4:
                yield tuple(pending)
                pending=[]
    if pending:
        yield tuple(pending)


def build(snapshot,*,pawn_guid,component_guid,value_fields,owner_player_id,schema=None,
        space_revision=adapter.INITIAL_SPACE_REVISION):
    """RepData once; one gun or at most four other original GIDs per ACK stage."""
    actual=_schema(schema)
    pins=source_pins()
    if type(value_fields) is not tuple or value_fields!=ZERO_VALUES or any(type(x) is not int for x in value_fields):
        raise ValueError('Explicit zero native valuation policy required')
    if type(owner_player_id) is not int or not 1<=owner_player_id<(1<<64):
        raise ValueError('Explicit actual local owner player ID required')
    projection=adapter.build(snapshot,value_fields=value_fields,owner_player_id=owner_player_id,
        space_revision=space_revision)
    writer=BitWriter(maximum_bits=MAX_BITS)
    writer.write_bool(False)
    writer.write_packed_int(10)
    write_inventory_repdata(writer,projection.repdata,profile=PROFILE)
    writer.write_packed_int(0)
    groups=[(DefaultSubobjectUpdate(pawn_guid,component_guid,'InventoryManager',SCHEMA_SHA256,
        writer.to_bytes(),writer.bit_count,True),)]
    repdata_bits=writer.bit_count
    chunks=[]
    delta_bits=[]
    for number,values in enumerate(_item_groups(projection.items),1):
        delta=InventoryFastArrayDelta(number,number-1 if number>1 else -1,(),values)
        writer=BitWriter(maximum_bits=MAX_BITS)
        write_inventory_custom_delta(writer,delta,profile=PROFILE)
        block=build_class_field_content((ClassFieldEnvelope(7,writer.to_bytes(),writer.bit_count),),
            profile=NormalClassFieldProfile(actual['binding']['exclusive_index_maximum'],False))
        groups.append((DefaultSubobjectUpdate(pawn_guid,component_guid,'InventoryManager',SCHEMA_SHA256,
            block.payload,block.payload_bit_count,False),))
        delta_bits.append(writer.bit_count)
        chunks.append(dict(array_key=number,base_key=delta.base_replication_key,
            item_count=len(values),gids=[e.item.item_gid for e in values],
            gun_item_count=sum(type(e.item) is GunInventoryItem for e in values),
            content_bits=block.payload_bit_count))
    report=dict(projection.qualification,ordinary_space_count=len(projection.repdata.spaces),
        ordinary_grid_count=sum(len(s.grids) for s in projection.repdata.spaces),
        repdata_content_bits=repdata_bits,custom_delta_value_bits=delta_bits,
        item_chunk_count=len(chunks),chunks=chunks,source_pins=pins,
        required_gate='ACK previous content group before sending next; keys assume no other writer mutates RepItemArray',
        actual_owner_id_explicit=True,valuation_policy='local_zero_values',
        client_receipt_verified=False,packet_budget_checked=False)
    return InventoryContentProjection(tuple(groups),report)


def build_content_groups(snapshot,**kwargs):
    return build(snapshot,**kwargs).groups
