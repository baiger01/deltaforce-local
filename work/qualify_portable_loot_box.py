"""Offline qualification against the exact admitted 52-item account snapshot.

Additional test-only loot instance GIDs are explicit local fixture allocations.
No account, profile, native process, installation or packet transport is touched.
"""
import argparse
from dataclasses import replace
import hashlib
import json
from pathlib import Path

import portable_loot_box_codec as boxes
from portable_finite_loot import FiniteLootAuthority,source_pins as authority_pins
import portable_loot_box_request as requests
import portable_map_inventory as carried
from dfserver.legacy_ds_inventory_items import MinimalInventoryItem,InventoryItemLocation,InventoryFastArrayElement
from dfserver.legacy_ds_inventory_stack import StackedInventoryItem,InventoryStackData
from dfserver.legacy_ds_inventory_condition import ConditionInventoryItem
from dfserver.legacy_ds_inventory_state import InventorySpace,InventorySpaceGrid
from dfserver.legacy_ds_wire_codec import WirePacket,decode_observed_application


def derive(snapshot_path):
    raw=snapshot_path.read_bytes()
    snapshot=json.loads(raw)
    owner=6311504805269387056
    projected=carried.build(snapshot,value_fields=(0,0,0,0,0,0,0),owner_player_id=owner)
    store=FiniteLootAuthority('offline-loot-wire-qualification-only')
    store.register_inventory(owner,projected.repdata.spaces,projected.items)
    binding=boxes.qualified_bindings()[0]
    generated=[]
    templates=(14020000001,37110400001,15050101019)
    for index,template in enumerate(templates):
        category,sequence=divmod(template,10000)
        value=MinimalInventoryItem(category,sequence,(1<<63)+1000+index,302,
            InventoryItemLocation(index,0,1,1,False,1),0.0,0,0,False,0,0,0,0.0,False,0,0,False)
        if template==37110400001:
            value=StackedInventoryItem(value,InventoryStackData(20,60,(),()))
        elif template==15050101019:
            value=ConditionInventoryItem(value,(3.0,4.0),None)
        generated.append(InventoryFastArrayElement(index,value))
    generated=tuple(generated)
    spaces=(InventorySpace(302,1,(InventorySpaceGrid(1,0,0,4,4,0,0),)),)
    store.register_box(binding,spaces,generated,world_position=(0,0,0))
    opened=store.open_box(owner,binding.object_path,player_position=(0,0,0),maximum_distance_cm=200)
    initial=boxes.project(binding,opened.spaces,opened.items,recipient_scope=(store.match_id,owner))
    packet_template=WirePacket(16383,31,(0xffffffff,),False,0,None,(),0)
    packets=boxes.preflight_packets(initial,channel_index=7,initial_channel_sequence=1023,
        packet_template=packet_template,max_packet_bytes=1024)
    before={value.item.item_gid for value in projected.items+generated}
    before_quantity=sum(boxes.item_quantity(value.item) for value in projected.items+generated)
    target_space=next(space for space in projected.repdata.spaces if space.space_type==108001)
    target_grid=target_space.grids[0]
    occupied=set()
    for value in projected.items:
        item=carried.base_item(value.item)
        location=item.location
        if item.attach_position!=target_space.space_type or location.grid_index!=target_grid.grid_id:
            continue
        width=location.height if location.rotated else location.length
        height=location.length if location.rotated else location.height
        occupied.update((x,y) for x in range(location.x,location.x+width)
                        for y in range(location.y,location.y+height))
    free=[(x,y) for y in range(target_grid.height) for x in range(target_grid.length) if (x,y) not in occupied]
    if len(free)<len(generated):
        raise ValueError('The real carried layout has insufficient free cells for this explicit offline fixture')
    receipts=[]
    for value,(x,y) in zip(generated,free):
        args=dict(player_id=owner,cmd_gid=(1<<63)+2000+value.element_id,box_path=binding.object_path,
            item_gid=value.item.item_gid,destination_position=108001,
            destination_location=InventoryItemLocation(x,y,1,1,False,target_grid.grid_id),
            player_position=(0,0,0),maximum_distance_cm=200)
        receipt=store.move_whole(**args)
        if store.move_whole(**args)!=receipt:
            raise ValueError('The exact repeated CmdGid changed the committed result')
        receipts.append(receipt)
    final=store.box_snapshot(binding.object_path)
    inventory=store.inventory_snapshot(owner)
    after={value.item.item_gid for value in final.items+inventory.items}
    after_quantity=sum(boxes.item_quantity(value.item) for value in final.items+inventory.items)
    if before!=after or before_quantity!=after_quantity or len(inventory.items)!=len(projected.items)+3:
        raise ValueError('The offline finite-box transfer violated instance or quantity conservation')
    update=boxes.project(binding,final.spaces,final.items,recipient_scope=(store.match_id,owner),
        cursor=initial.cursor_after_ack)
    update_packets=boxes.preflight_packets(update,channel_index=7,initial_channel_sequence=1,
        packet_template=replace(packet_template,sequence=1),max_packet_bytes=1024)
    for packet in packets+update_packets:
        decode_observed_application(packet,max_packet_bytes=1024,received_by_server=False)
    pins=authority_pins()
    pins.update(requests.source_pins())
    path=Path(__file__).resolve()
    pins[path.relative_to(boxes.ROOT).as_posix()]=hashlib.sha256(path.read_bytes()).hexdigest()
    return dict(kind='offline_complete_box_packet_and_finite_exchange_qualification',
        exact_admitted_snapshot_sha256=hashlib.sha256(raw).hexdigest(),source_pins=pins,
        real_carried_item_count=len(projected.items),real_carried_quantity=sum(boxes.item_quantity(v.item) for v in projected.items),
        test_only_new_local_instance_gids=[value.item.item_gid for value in generated],
        seeded_real_template_ids=list(templates),seeded_quantities=[boxes.item_quantity(value.item) for value in generated],
        preserved_gid_union=before==after,preserved_total_quantity=before_quantity==after_quantity,
        original_carried_gids_all_retained={value.item.item_gid for value in projected.items}<=after,
        original_carried_optional_features_retained=inventory.items[:len(projected.items)]==projected.items,
        source_box_remaining_items=len(final.items),destination_final_items=len(inventory.items),
        initial_actor_block_bits=initial.qualification['actor_block_bits'],
        initial_full_application_packet_bytes=[len(packet) for packet in packets],
        update_full_application_packet_bytes=[len(packet) for packet in update_packets],
        max_packet_bytes=1024,packet_budget_passed=True,command_retries_idempotent=True,
        source_box_path=binding.object_path,box_handles=dict(spaces=103,empty=113,item_cache_index=55,exclusive_max=85),
        local_fixture_channel_and_sequences_are_not_native_guid_receipt_proof=True,
        account_written=False,production_modified=False,packets_sent=False,process_access=False,
        native_client_receipt_verified=False,door_GameplayTag_decoder_qualified=False,
        ItemMoveCmd_wire_decoder_qualified=False)


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--snapshot',type=Path,required=True)
    parser.add_argument('--output',type=Path,required=True)
    args=parser.parse_args()
    if args.output.exists() or not args.output.resolve().is_relative_to(boxes.ROOT/'work/evidence'):
        parser.error('Use an exclusive new evidence path')
    encoded=(json.dumps(derive(args.snapshot),indent=2,sort_keys=True)+'\n').encode()
    with args.output.open('xb') as stream:
        stream.write(encoded)
    print(hashlib.sha256(encoded).hexdigest())
