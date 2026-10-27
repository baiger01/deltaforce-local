"""Offline qualification of current inventory content and complete packet budget."""
import argparse
import hashlib
import json
from pathlib import Path

import portable_map_inventory as adapter
import portable_map_inventory_content as content
from portable_map_bootstrap import load_plan
from dfserver.legacy_ds_actor_content import ActorContentBlock
from dfserver.legacy_ds_actor_fields import NormalClassFieldProfile,read_class_field_content
from dfserver.legacy_ds_actor_manifest import preflight_actor_manifest
from dfserver.legacy_ds_bit_archive import BitReader
from dfserver.legacy_ds_control_connection import preflight_actor_content_plans
from dfserver.legacy_ds_inventory_gun import GunInventoryItem,read_inventory_custom_delta
from dfserver.legacy_ds_inventory_stack import StackedInventoryItem
from dfserver.legacy_ds_packet_ack_probe import MASK
from dfserver.legacy_ds_wire_codec import WirePacket,encode_observed_application

ROOT=adapter.ROOT
SNAPSHOT='work/evidence/map-system-audit-20261018/carried-snapshot-offline.json'
PROFILE='outputs/df-local-server/protocol/portable-map-spawn/profile-carried-inventory.json'


def _require(value,message):
    if not value:
        raise ValueError(message)


def _quantity(item):
    while hasattr(item,'item') and type(item) is not StackedInventoryItem:
        item=item.item
    return item.stack.item_count if type(item) is StackedInventoryItem else 1


def qualify():
    raw=(ROOT/SNAPSHOT).read_bytes()
    snapshot=json.loads(raw)
    pins=content.source_pins()
    # The production runtime seals each public contract. This offline proof also
    # revalidates its underlying immutable native/Lua research evidence.
    for relative in (adapter.REVISION_CONTRACT,
            'protocol/portable-map-spawn/inventory-gun-desc-contract.json',
            'protocol/portable-map-spawn/inventory-gun-contract.json'):
        contract=json.loads((adapter.SERVER/relative).read_bytes())
        for source,digest in contract['source_pins'].items():
            _require(hashlib.sha256((ROOT/source).read_bytes()).hexdigest()==digest,
                'Changed underlying inventory source '+source)
            pins[source]=digest
    projected=adapter.build(raw,value_fields=content.ZERO_VALUES,owner_player_id=101)
    result=content.build(raw,pawn_guid=2,component_guid=2008,
        value_fields=content.ZERO_VALUES,owner_player_id=101)
    original_gids={p['gid'] for p in snapshot['props']}|{snapshot['selected_melee']['gid']}
    received=[]
    chunk_bits=[]
    for number,group in enumerate(result.groups[1:],1):
        update,=group
        fields=read_class_field_content(ActorContentBlock(False,update.payload,update.payload_bit_count),
            profile=NormalClassFieldProfile(53,False))
        _require(len(fields)==1 and fields[0].rep_index==7,'Changed inventory class-cache field')
        reader=BitReader(fields[0].payload,bit_count=fields[0].payload_bit_count)
        delta=read_inventory_custom_delta(reader,profile=content.PROFILE)
        _require(reader.remaining==0,'Inventory delta has trailing bits')
        _require((delta.array_replication_key,delta.base_replication_key)==
            (number,number-1 if number>1 else -1),'Changed ACK continuation keys')
        _require(not any(type(e.item) is GunInventoryItem for e in delta.changed) or len(delta.changed)==1,
            'A gun was not isolated in its ACK stage')
        received.extend(delta.changed)
        chunk_bits.append(update.payload_bit_count)
    _require(tuple(received)==projected.items,'Decoded inventory differs from original projection')
    _require({e.item.item_gid for e in received}==original_gids,'Original top-level GIDs changed')
    _require(len(received)==52 and sum(_quantity(e.item) for e in received)==544,
        'Saved snapshot item/quantity count changed')
    _require(len(projected.repdata.spaces)==13 and sum(len(s.grids) for s in projected.repdata.spaces)==23,
        'Saved snapshot source geometry changed')
    _require(all(s.server_update_count==1 for s in projected.repdata.spaces),
        'Local initial revision does not cross the original zero gate')
    plan=load_plan(ROOT,ROOT/PROFILE)
    hero,fashion=snapshot['selected_hero_id'],snapshot['selected_fashion_id']
    plans=plan.admission_content_factory(101,hero,fashion,plan.contents)
    plans=plan.inventory_content_factory(101,hero,fashion,raw,plans)
    opens=tuple(preflight_actor_manifest(m,channel_sequence=1023,max_packet_bytes=1024)
        for m in plan.manifests)
    deliveries=preflight_actor_content_plans(tuple(dict(p.actor_fields) for p in opens),plans,
        initial_channel_sequence=1023,max_packet_bytes=1024)
    packet_rows=[]
    for channel,head in sorted(deliveries.items()):
        for stage,item in enumerate((head,*head.continuations)):
            packet=encode_observed_application(WirePacket(MASK,MASK,(0xffffffff,),False,0,None,
                (item.bunch,),0),max_packet_bytes=1024,received_by_server=False)
            packet_rows.append(dict(channel=channel,actor_guid=item.actor_guid,stage=stage,
                channel_sequence=item.bunch.channel_sequence,application_packet_bytes=len(packet),
                bunch_payload_bits=item.bunch.payload_bits))
    pins[SNAPSHOT]=hashlib.sha256(raw).hexdigest()
    for relative in (PROFILE,'work/qualify_economy_inventory_production_revision.py',
            'work/test_portable_map_inventory.py','work/test_portable_map_inventory_content.py',
            'work/test_portable_inventory_gun_desc.py','work/test_portable_inventory_gun_items.py',
            'work/test_portable_carried_inventory_plan.py'):
        pins[relative]=hashlib.sha256((ROOT/relative).read_bytes()).hexdigest()
    return dict(kind='current_local_match_inventory_production_revision_qualification_v1',
        client_sha256=content.CLIENT_SHA256,source_pins=pins,
        client_launched=False,process_read=False,account_or_game_install_written=False,
        top_level_item_count=len(received),quantity_sum=sum(_quantity(e.item) for e in received),
        original_top_level_gids_preserved=True,typed_item_roundtrip_equal=True,
        ordinary_space_count=13,ordinary_grid_count=23,space_revision=1,
        space_revision_policy='explicit local initial match revision, not an official constant',
        lua_zero_gate_crossed_by_all_spaces=True,
        gun_sources=result.qualification['gun_sources'],
        condition_sources=result.qualification['condition_sources'],
        optional_feature_gaps=[g for g in result.qualification['optional_feature_gaps']
            if g['unserialized_snapshot_fields'] or g.get('condition_gap')],
        content_stage_count=len(result.groups),repdata_content_bits=result.qualification['repdata_content_bits'],
        item_chunk_content_bits=chunk_bits,maximum_content_bits=max(g[0].payload_bit_count for g in result.groups),
        complete_packet_budget=dict(limit_application_packet_bytes=1024,
            worst_case_packet_and_ack_headers=True,includes_guid_exports_and_bunch_headers=True,
            maximum_actor_open_packet_bytes=max(p.conservative_packet_bytes for p in opens),
            maximum_followup_packet_bytes=max(p['application_packet_bytes'] for p in packet_rows),
            session_envelope_bytes_outside_application_budget=8,packets=packet_rows),
        delivery_required='Each following FastArray group waits for actual previous ACK; no concurrent array writer',
        native_client_receive_verified=False,weapon_actor_created_or_equipped=False,
        remaining_weapon_lifecycle='Inventory GunDesc does not bind an equipped weapon Actor, BP class/CDO, WeaponID, slot, owner or FPP lifecycle')


def main():
    parser=argparse.ArgumentParser()
    parser.add_argument('--output',type=Path,required=True)
    args=parser.parse_args()
    if args.output.exists():
        parser.error('Use a fresh output path')
    result=qualify()
    args.output.parent.mkdir(parents=True,exist_ok=True)
    args.output.write_text(json.dumps(result,indent=2,sort_keys=True)+'\n',encoding='utf8')
    print(json.dumps(dict(output=str(args.output),sha256=hashlib.sha256(args.output.read_bytes()).hexdigest(),
        item_count=result['top_level_item_count'],quantity_sum=result['quantity_sum'],
        content_stages=result['content_stage_count'],maximum_content_bits=result['maximum_content_bits'],
        maximum_packet_bytes=result['complete_packet_budget']['maximum_followup_packet_bytes'])))


if __name__=='__main__':
    main()
