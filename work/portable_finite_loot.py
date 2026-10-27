"""Finite local box contents and atomic whole-instance transfers.

The caller supplies source-qualified complete typed item instances, accepted
server positions and decoded commands. This is explicit local policy. It does
not claim to decode the native RPC, allocate GIDs, complete search animations,
grant keycard permissions, mutate accounts or send replication.
"""
from dataclasses import dataclass,replace
import hashlib
import math
from pathlib import Path
import threading

import portable_loot_box_codec as box_codec
from dfserver.legacy_ds_inventory_items import InventoryFastArrayElement,InventoryItemLocation,MinimalInventoryItem
from dfserver.legacy_ds_inventory_state import InventorySpace
import portable_map_inventory as inventory_adapter


@dataclass(frozen=True)
class LootSnapshot:
    owner_key: str
    revision: int
    spaces: tuple
    items: tuple


@dataclass(frozen=True)
class TransferReceipt:
    match_id: str
    player_id: int
    cmd_gid: int
    item_gid: int
    template_id: int
    quantity: int
    source_path: str
    source_deleted_element_id: int
    destination_element: InventoryFastArrayElement
    source_revision: int
    destination_revision: int
    source_is_empty: bool


def source_pins():
    pins=box_codec.source_pins()
    path=Path(__file__).resolve()
    pins['work/portable_finite_loot.py']=hashlib.sha256(path.read_bytes()).hexdigest()
    return pins


def _uint(value,label):
    if type(value) is not int or not 0<value<1<<64:
        raise ValueError('An actual positive uint64 '+label+' is required')
    return value


def _position(value):
    if type(value) is not tuple or len(value)!=3 or any(type(v) not in (int,float) or not math.isfinite(v) for v in value):
        raise ValueError('An explicit finite current server position is required')
    return value


def _replace_base(item,transform):
    if type(item) is MinimalInventoryItem:
        return transform(item)
    inventory_adapter.base_item(item)
    return replace(item,item=_replace_base(item.item,transform))


def _geometry(spaces):
    box_codec.encode_spaces(spaces)
    result={}
    for space in spaces:
        if type(space) is not InventorySpace or space.server_update_count<1:
            raise ValueError('A positive explicit local space revision is required')
        for grid in space.grids:
            if not (1<=grid.grid_id<=255 and 1<=grid.length<=255 and 1<=grid.height<=255):
                raise ValueError('The source grid exceeds supported native item location bytes')
            result[(space.space_type,grid.grid_id)]=grid
    return result


def _cells(item,grids):
    base=inventory_adapter.base_item(item)
    location=base.location
    grid=grids.get((base.attach_position,location.grid_index))
    if grid is None:
        raise ValueError('The item destination has no source-qualified grid')
    width=location.height if location.rotated else location.length
    height=location.length if location.rotated else location.height
    if (not all(type(v) is int for v in (location.x,location.y,width,height)) or
            location.x<0 or location.y<0 or width<1 or height<1 or
            location.x+width>grid.length or location.y+height>grid.height):
        raise ValueError('The item exceeds its source-qualified destination grid')
    return {(base.attach_position,location.grid_index,x,y)
        for x in range(location.x,location.x+width) for y in range(location.y,location.y+height)}


class FiniteLootAuthority:
    """One match namespace; all mutating operations are short atomic sections."""
    def __init__(self,match_id):
        if type(match_id) is not str or not 1<=len(match_id)<=256:
            raise ValueError('An explicit current match namespace is required')
        self.match_id=match_id
        self.source_pins=source_pins()
        self._catalog=box_codec._sources()['outputs/df-local-server/protocol/game_item_catalog.json']['rows']
        self._lock=threading.RLock()
        self._boxes={}
        self._inventories={}
        self._owners={}
        self._commands={}
        self._opened=set()

    def _reserve(self,owner,items):
        for element in items:
            if element.item.item_gid in self._owners:
                raise ValueError('An item GID already has one authoritative owner')
        for element in items:
            self._owners[element.item.item_gid]=owner

    def register_box(self,binding,spaces,items,*,world_position):
        box_codec.qualify_binding(binding)
        box_codec.validate_items(items)
        grids=_geometry(spaces)
        position=_position(world_position)
        occupied=set()
        for element in items:
            base=inventory_adapter.base_item(element.item)
            row=self._catalog[str(base.template_id)]
            if (base.location.length,base.location.height)!=(row['width'],row['length']):
                raise ValueError('Box item geometry differs from installed native location dimensions')
            cells=_cells(element.item,grids)
            if occupied&cells:
                raise ValueError('Configured box items overlap')
            occupied.update(cells)
        with self._lock:
            if binding.object_path in self._boxes:
                raise ValueError('A finite box may be seeded only once per match')
            snapshot=LootSnapshot(binding.object_path,1,spaces,items)
            self._reserve(binding.object_path,items)
            self._boxes[binding.object_path]=(snapshot,position,grids)
            return snapshot

    def register_inventory(self,player_id,spaces,items):
        _uint(player_id,'player UIN')
        box_codec.validate_items(items)
        grids=_geometry(spaces)
        with self._lock:
            if len(self._inventories)>=64:
                raise ValueError('The explicit local owning-inventory count bound is exhausted')
            if player_id in self._inventories:
                raise ValueError('The actual carried inventory is already registered')
            owner='player:'+str(player_id)
            snapshot=LootSnapshot(owner,1,spaces,items)
            self._reserve(owner,items)
            self._inventories[player_id]=(snapshot,grids)
            return snapshot

    def box_snapshot(self,path):
        with self._lock:
            if path not in self._boxes:
                raise ValueError('The source-qualified box is not registered')
            return self._boxes[path][0]

    def inventory_snapshot(self,player_id):
        with self._lock:
            if player_id not in self._inventories:
                raise ValueError('The current owning inventory is not registered')
            return self._inventories[player_id][0]

    def _near(self,player_id,path,position,maximum):
        _uint(player_id,'player UIN')
        _position(position)
        if type(maximum) not in (int,float) or not math.isfinite(maximum) or not 0<maximum<=10000:
            raise ValueError('An explicit bounded local interaction distance policy is required')
        if path not in self._boxes or player_id not in self._inventories:
            raise ValueError('The current source box and owning inventory must be registered')
        if math.dist(position,self._boxes[path][1])>maximum:
            raise ValueError('The current accepted position is outside the box interaction range')

    def open_box(self,player_id,box_path,*,player_position,maximum_distance_cm):
        with self._lock:
            self._near(player_id,box_path,player_position,maximum_distance_cm)
            self._opened.add((player_id,box_path))
            return self._boxes[box_path][0]

    def move_whole(self,*,player_id,cmd_gid,box_path,item_gid,destination_position,
            destination_location,player_position,maximum_distance_cm):
        _uint(player_id,'player UIN')
        _uint(cmd_gid,'CmdGid')
        _uint(item_gid,'item GID')
        if type(destination_location) is not InventoryItemLocation or type(destination_position) is not int:
            raise ValueError('An explicit typed native destination location is required')
        if 100<=destination_position<=160:
            raise ValueError('Automatic equipment and weapon lifecycle changes are outside this box transfer')
        intent=(box_path,item_gid,destination_position,destination_location)
        command=(player_id,cmd_gid)
        with self._lock:
            if command in self._commands:
                previous,receipt=self._commands[command]
                if previous!=intent:
                    raise ValueError('A CmdGid was reused for a different authoritative move')
                return receipt
            if len(self._commands)>=4096:
                raise ValueError('The local command journal bound is exhausted; committed CmdGids are never evicted')
            self._near(player_id,box_path,player_position,maximum_distance_cm)
            if (player_id,box_path) not in self._opened:
                raise ValueError('The source box has not been opened by this owning player')
            source,position,source_grids=self._boxes[box_path]
            destination,target_grids=self._inventories[player_id]
            if max(source.revision,destination.revision)>=(1<<31)-1:
                raise ValueError('The local authoritative content revision namespace is exhausted')
            candidates=[e for e in source.items if e.item.item_gid==item_gid]
            if len(candidates)!=1 or self._owners.get(item_gid)!=box_path:
                raise ValueError('The source item is absent or belongs to another owner')
            element=candidates[0]
            base=inventory_adapter.base_item(element.item)
            if (destination_location.length,destination_location.height)!=(base.location.length,base.location.height):
                raise ValueError('A whole-instance move must preserve its qualified unrotated shape')
            transferred=_replace_base(element.item,lambda value:replace(value,
                attach_position=destination_position,location=destination_location,owner_player_id=player_id))
            wanted=_cells(transferred,target_grids)
            occupied=set()
            for existing in destination.items:
                existing_base=inventory_adapter.base_item(existing.item)
                if (existing_base.attach_position,existing_base.location.grid_index) in target_grids:
                    occupied.update(_cells(existing.item,target_grids))
            if occupied&wanted:
                raise ValueError('The actual destination inventory cells are occupied')
            next_id=max((e.element_id for e in destination.items),default=-1)+1
            if next_id>=1<<31:
                raise ValueError('The local destination FastArray element namespace is exhausted')
            changed=InventoryFastArrayElement(next_id,transferred)
            next_source=replace(source,revision=source.revision+1,
                items=tuple(e for e in source.items if e.item.item_gid!=item_gid))
            next_destination=replace(destination,revision=destination.revision+1,items=destination.items+(changed,))
            receipt=TransferReceipt(self.match_id,player_id,cmd_gid,item_gid,base.template_id,
                box_codec.item_quantity(element.item),box_path,element.element_id,changed,
                next_source.revision,next_destination.revision,not next_source.items)
            self._boxes[box_path]=(next_source,position,source_grids)
            self._inventories[player_id]=(next_destination,target_grids)
            self._owners[item_gid]=destination.owner_key
            self._commands[command]=(intent,receipt)
            return receipt
