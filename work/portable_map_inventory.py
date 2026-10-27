"""Pure frozen-account inventory projection; no transport or process access.

Initial mandatory item values use native constructor defaults except explicit
identity, count and location. Qualified stack, keychain, condition and gun blocks
preserve original account values. Remaining feature gaps are explicit.
"""
from dataclasses import dataclass
import hashlib
import json
from pathlib import Path
import sys

ROOT=Path(__file__).resolve().parent.parent
SERVER=ROOT/'outputs/df-local-server'
if str(SERVER) not in sys.path:
    sys.path.insert(0,str(SERVER))

from dfserver.legacy_ds_inventory_items import MinimalInventoryItem, InventoryFastArrayElement
from dfserver.legacy_ds_inventory_stack import StackedInventoryItem, InventoryStackData, inventory_stack_source_pins
from dfserver.legacy_ds_inventory_state import InventoryManagerRepData, InventorySpace, InventorySpaceGrid, inventory_state_source_pins
from dfserver.legacy_ds_inventory_geometry import (grids_from_raw_layout,equipment_location,
    location_from_business_location,inventory_geometry_source_pins)
from dfserver.legacy_ds_inventory_items import inventory_source_pins
from dfserver.legacy_ds_inventory_keychain import (KeychainInventoryItem,InventoryKeychainSpace,
    inventory_keychain_source_pins)
from dfserver.legacy_ds_inventory_condition import ConditionInventoryItem,inventory_condition_source_pins
from dfserver.legacy_ds_inventory_gun import GunInventoryItem,inventory_gun_source_pins
from dfserver.legacy_ds_inventory_gun_desc import from_snapshot_prop as gun_from_snapshot_prop
from dfserver.local_commerce import inventory_location
from dfserver.native_prop_bindings import snapshot_binding

CATALOG_PINS={
    'protocol/game_item_catalog.json':'5b30d2179d77e62294e71d7510c21e03aa664f97c9c1c07399e911f8c91376e8',
    'protocol/container_layout_catalog.json':'40fcb83378d776f83387916226299da203883ce346282d3a8096c5ef4a81401c',
    'protocol/safe_box_layout_catalog.json':'26f7bb9051394fb759dae9bb24fb107ee0f166455ba9642befb88eb999506964',
    'protocol/deposit_slot_catalog.json':'1e814fb877256a105b3c6020029c84329cbc938e3cec8bd99845b9e786b13a76',
    'protocol/native_keycard_catalog.json':'6cc762a8442cc3c2ca139c2477115950a19541b1eb3c2b83f44836dc73df3397',
    'protocol/portable-map-spawn/equipment-condition-catalog.json':'c7cd128ce5f06fcb49f4da40d66f187188be2b93e8debd82302fa7a10c27bffe',
    'protocol/weapon_component_catalog.json':'9521d8ad19eb7dad4149195961f454f4ae64ed1008efa24fdf81af9b6624acd1',
}
POCKET_SOURCE='work/evidence/map-system-audit-20261018/native-economy-pocket-space-description-actual-row.json'
POCKET_SHA='638bd0cf05247cb81bd130a2312febe9c0d92af2df8140640d78759ded91b3df'
CONDITION_SOURCE='work/evidence/map-system-audit-20261018/native-economy-condition-fallback-installed-lua.json'
CONDITION_SHA='7de29fb6d5a231556488504e8f938648700ab94a550e7ec8fcc3cd480d57c329'
CONTAINER_EQUIPMENT={107001:107,108001:108,109001:109}
INITIAL_SPACE_REVISION=1  # Local match revision; ItemSlot's initial zero must change.
REVISION_CONTRACT='protocol/portable-map-spawn/inventory-space-revision-contract.json'
REVISION_CONTRACT_SHA='4a855e85c8304e5d140cba7b806192d32f8a75e37c6ccaf5830e3c54aaf6d6b1'


@dataclass(frozen=True)
class InventoryProjection:
    repdata: InventoryManagerRepData
    items: tuple[InventoryFastArrayElement,...]
    qualification: dict


def source_pins():
    pins={}
    for relative,digest in CATALOG_PINS.items():
        if hashlib.sha256((SERVER/relative).read_bytes()).hexdigest()!=digest:
            raise ValueError('Changed inventory adapter catalog '+relative)
        pins['outputs/df-local-server/'+relative]=digest
    if hashlib.sha256((ROOT/POCKET_SOURCE).read_bytes()).hexdigest()!=POCKET_SHA:
        raise ValueError('Changed source PocketSpaceDesc')
    pins[POCKET_SOURCE]=POCKET_SHA
    _qualified_json(ROOT/CONDITION_SOURCE,CONDITION_SHA)
    pins[CONDITION_SOURCE]=CONDITION_SHA
    revision=_qualified_json(SERVER/REVISION_CONTRACT,REVISION_CONTRACT_SHA)
    if revision['local_policy']['initial_space_revision']!=INITIAL_SPACE_REVISION:
        raise ValueError('Changed local inventory initial revision policy')
    pins['outputs/df-local-server/'+REVISION_CONTRACT]=REVISION_CONTRACT_SHA
    for loader in (inventory_source_pins,inventory_state_source_pins,inventory_stack_source_pins,
            inventory_geometry_source_pins,inventory_keychain_source_pins,inventory_condition_source_pins,
            inventory_gun_source_pins):
        pins.update({'outputs/df-local-server/'+k:v for k,v in loader().items()})
    for relative in ('work/portable_map_inventory.py','outputs/df-local-server/dfserver/local_commerce.py',
            'outputs/df-local-server/dfserver/native_prop_bindings.py',
            'outputs/df-local-server/dfserver/inventory/native_prop_bindings.py',
            'outputs/df-local-server/dfserver/inventory/__init__.py',
            'outputs/df-local-server/dfserver/_compat.py'):
        pins[relative]=hashlib.sha256((ROOT/relative).read_bytes()).hexdigest()
    return pins


def _catalogs():
    source_pins()
    return {name:_qualified_json(SERVER/name,digest) for name,digest in CATALOG_PINS.items()}


def _qualified_json(path,digest):
    raw=path.read_bytes()
    if hashlib.sha256(raw).hexdigest()!=digest:
        raise ValueError('Changed inventory source snapshot '+str(path))
    return json.loads(raw)


def _integer(value,low,high,label):
    if type(value) is not int or not low<=value<=high:
        raise ValueError('Invalid '+label)
    return value


def _document(snapshot):
    if isinstance(snapshot,(bytes,str)):
        snapshot=json.loads(snapshot)
    if type(snapshot) is not dict or snapshot.get('kind')!='local_account_carried_loadout_v1':
        raise ValueError('The frozen carried account snapshot is required')
    if type(snapshot.get('props')) is not list or len(snapshot['props'])>2048:
        raise ValueError('Bounded frozen carried props required')
    if snapshot.get('source_item_catalog_sha256')!=CATALOG_PINS['protocol/game_item_catalog.json']:
        raise ValueError('Snapshot item source differs from the adapter catalog')
    if snapshot.get('source_slot_catalog_sha256')!=CATALOG_PINS['protocol/deposit_slot_catalog.json']:
        raise ValueError('Snapshot destination source differs from the adapter catalog')
    return snapshot


def _props(snapshot):
    props=list(snapshot['props'])
    melee=snapshot.get('selected_melee')
    if melee is not None:
        if any(p['gid']==melee['gid'] for p in props):
            raise ValueError('Selected melee GID already appears in ordinary carried props')
        props.append(dict(melee,template_id=melee.get('template_id',melee.get('id')),
            quantity=melee.get('quantity',melee.get('num')),grid_page_id=melee.get('grid_page_id',melee.get('position')),
            x=0,y=0,length=1,width=1,rotated=0))
    gids=[_integer(p.get('gid'),1,(1<<64)-1,'carried GID') for p in props]
    if len(gids)!=len(set(gids)):
        raise ValueError('Repeated carried GID')
    return props


def _spaces(snapshot,props,catalogs,space_revision):
    slots=catalogs['protocol/deposit_slot_catalog.json']['rows']
    layouts=catalogs['protocol/container_layout_catalog.json']['rows']
    safes=catalogs['protocol/safe_box_layout_catalog.json']['rows']
    equipped={}
    spaces={}
    for prop in props:
        position=prop['grid_page_id']
        if 100<position<139:
            if position in equipped:
                raise ValueError('Multiple items occupy equipment position '+str(position))
            row=slots.get(str(position))
            if row is None or (row['grid_length'],row['grid_width'])!=(1,1):
                raise ValueError('Unqualified equipment slot '+str(position))
            equipped[position]=prop
            spaces[position]=InventorySpace(position,space_revision,(InventorySpaceGrid(1,0,0,1,1,0,0),))
    for position,equipment in CONTAINER_EQUIPMENT.items():
        if equipment not in equipped:
            if any(p['grid_page_id']==position for p in props):
                raise ValueError('Container contents have no equipped source item')
            continue
        item=equipped[equipment]['template_id']
        if equipment in (107,108):
            row=layouts.get(str(item))
            expected='chest_rig' if equipment==107 else 'backpack'
            if row is None or row['kind']!=expected:
                raise ValueError('Unqualified carrying layout for '+str(item))
            grids=grids_from_raw_layout(row['raw_layout'])
        else:
            row=safes.get(str(item))
            if row is None or row['dimension_a']!=row['dimension_b'] or not 1<=row['dimension_a']<=255:
                raise ValueError('Safe-box axis binding is not qualified for '+str(item))
            size=row['dimension_a']
            grids=(InventorySpaceGrid(1,0,0,size,size,0,0),)
        spaces[position]=InventorySpace(position,space_revision,grids)
    pocket=_qualified_json(ROOT/POCKET_SOURCE,POCKET_SHA)['rows']['PocketSpaceDesc']['fields']['Value']
    spaces[199997]=InventorySpace(199997,space_revision,grids_from_raw_layout(pocket))
    keychain=_keychain_spaces(props,catalogs)
    if keychain:
        # Validation geometry only. Native keychain UI spaces come from the
        # equipment item's KeyChainSpaceArr, not ordinary SpaceRepData grids.
        spaces[116001]=InventorySpace(116001,space_revision,tuple(InventorySpaceGrid(s.index,0,0,
            s.length,(s.base_count+sum(s.total_locked)+s.length-1)//s.length,0,0) for s in keychain))
    elif any(p['grid_page_id']==116001 for p in props):
        raise ValueError('Keychain contents have no equipped source item')
    frozen={row['business_position']:{r['business_space_id']:(r['width'],r['height']) for r in row['spaces']}
        for row in snapshot.get('body_layouts',[])}
    for position,space in spaces.items():
        if position in (107001,108001,109001,116001,199997) and position in frozen:
            expected={g.grid_id:(g.length,g.height) for g in space.grids}
            if frozen[position]!=expected:
                raise ValueError('Frozen layout differs from the actual source '+str(position))
    return spaces


def _keychain_spaces(props,catalogs):
    equipped=next((p for p in props if p['grid_page_id']==116),None)
    if equipped is None:
        return ()
    rows=[r for r in catalogs['protocol/native_keycard_catalog.json']['resolved_key_boxes']
        if r['item_id']==equipped['template_id']]
    if not rows or len({r['MapID'] for r in rows})!=len(rows):
        raise ValueError('Unqualified equipped keychain layout')
    result=[]
    for row in sorted(rows,key=lambda r:r['Index']):
        index=_integer(row['MapID'],1,255,'native keychain MapID')
        length=_integer(row['BoxLength'],1,255,'native keychain length')
        base=_integer(row['DefaultSlotNum'],1,255,'native keychain base count')
        locked=tuple(_integer(row['LevelSlotNums'+str(n)],0,255,'native keychain locked count') for n in range(1,5))
        if any(locked):
            raise ValueError('Keychain unlock ownership is not present in the frozen snapshot')
        result.append(InventoryKeychainSpace(index,length,base,locked,(0,0,0,0)))
    return tuple(result)


def _location(prop,spaces):
    position=prop['grid_page_id']
    if 100<position<139:
        return equipment_location()
    if position not in spaces:
        raise ValueError('Unqualified carried destination '+str(position))
    grid_id=_integer(prop['x'],1,255,'business space ID')
    grid=next((g for g in spaces[position].grids if g.grid_id==grid_id),None)
    if grid is None:
        raise ValueError('Carried item has no actual source grid')
    if prop.get('space_width',grid.length)!=grid.length:
        raise ValueError('Saved flattening width differs from actual source grid')
    if position==116001:
        pb=dict(pos=position,start_x=prop['y']%grid.length,start_y=prop['y']//grid.length,
            x=prop['width'],y=prop['length'],space_id=grid_id,rotate=bool(prop.get('rotated',False)))
    else:
        pb=inventory_location(dict(prop,space_width=grid.length))
    if (pb['space_id']!=grid_id or pb['start_x']<0 or pb['start_y']<0 or
            pb['start_x']+pb['x']>grid.length or pb['start_y']+pb['y']>grid.height):
        raise ValueError('Carried item exceeds its source-backed grid')
    return location_from_business_location(pb)


def base_item(item):
    while type(item) in (StackedInventoryItem,KeychainInventoryItem,ConditionInventoryItem,GunInventoryItem):
        item=item.item
    if type(item) is not MinimalInventoryItem:
        raise ValueError('Unqualified typed inventory item wrapper')
    return item


def _condition(item,prop,catalogs):
    template=str(prop['template_id'])
    card=catalogs['protocol/native_keycard_catalog.json']['keycards'].get(template)
    catalog=catalogs['protocol/portable-map-spawn/equipment-condition-catalog.json']
    row=catalog['rows'].get(template)
    durability=armor=None
    source=None
    if card is not None:
        maximum=card['durability']
        if prop.get('health_max')!=maximum or type(prop.get('health')) is not int or not 0<=prop['health']<=maximum:
            return item,None,'keycard actual health/maximum missing or differs from installed definition'
        durability=(float(prop['health']),float(maximum))
        source=dict(kind='keycard',source_catalog='protocol/native_keycard_catalog.json',
            source_item_id=template,value_source='frozen health/health_max')
    elif row is not None:
        current=prop.get('health',row['max_durability'])
        maximum=prop.get('health_max',row['max_durability'])
        if (any(type(v) not in (int,float) for v in (current,maximum)) or
                not 0<=current<=maximum<=row['max_durability'] or maximum<=0):
            raise ValueError('Frozen equipment condition exceeds the installed source row')
        durability=(float(current),float(maximum))
        kind=row['source_id']
        source_info=catalog['sources'].get(kind)
        if source_info is None or row['source_row']!=template:
            raise ValueError('Equipment condition source identity differs')
        if kind=='body_armor':
            armor_value=(row['damage_max_armor_value'] if current<=row['max_durability']*row['damaged_durability_rate']
                else row['max_armor_value']) if current>0 else 0
            if type(armor_value) not in (float,int) or armor_value<0:
                raise ValueError('Unqualified armor-health source')
            if armor_value>0:
                armor=(float(armor_value),float(armor_value))
        elif kind!='helmet':
            raise ValueError('Unknown equipment condition family')
        source=dict(kind=kind,source_catalog='protocol/portable-map-spawn/equipment-condition-catalog.json',
            source_id=kind,source_row=template,serialized_uexp_offset=row['serialized_uexp_offset'],
            source_table=source_info['source_table'],source_uexp_sha256=source_info['source_uexp_sha256'],
            value_source='frozen health/health_max, or original Lua table fallback when absent',
            health_absent='health' not in prop,health_max_absent='health_max' not in prop)
    if source is None:
        return item,None,None
    source.update(gid=prop['gid'],durability=durability,armor_health=armor)
    return ConditionInventoryItem(item,durability,armor),source,None


def build(snapshot,*,value_fields,owner_player_id=0,space_revision=INITIAL_SPACE_REVISION):
    """Project all top-level carried GIDs; valuation is explicit local policy.

    value_fields is seven integers: six raw native int64 values followed by the
    raw int32 PickupCurrency. This adapter assigns no official value formula.
    space_revision is the positive local match initialization revision, not an
    official constant or a replacement for subsequent per-space revision tracking.
    """
    snapshot=_document(snapshot)
    catalogs=_catalogs()
    props=_props(snapshot)
    _integer(space_revision,1,(1<<31)-1,'positive local inventory space revision')
    spaces=_spaces(snapshot,props,catalogs,space_revision)
    _integer(owner_player_id,0,(1<<64)-1,'explicit local owner ID')
    if type(value_fields) is not tuple or len(value_fields)!=7:
        raise ValueError('Explicit seven-field native valuation policy required')
    for index,value in enumerate(value_fields):
        bits=64 if index<6 else 32
        _integer(value,-(1<<(bits-1)),(1<<(bits-1))-1,'native valuation')
    items=[]
    gaps=[]
    conditions=[]
    guns=[]
    definitions=catalogs['protocol/game_item_catalog.json']['rows']
    receivers=catalogs['protocol/weapon_component_catalog.json']['rows']
    keychain=_keychain_spaces(props,catalogs)
    cards=catalogs['protocol/native_keycard_catalog.json']['keycards']
    occupied=set()
    for index,prop in enumerate(props):
        item_id=prop.get('template_id')
        row=definitions.get(str(item_id))
        if type(item_id) is not int or row is None:
            raise ValueError('Carried item has no installed definition: '+str(item_id))
        count=_integer(prop.get('quantity'),1,(1<<31)-1,'frozen quantity')
        maximum=_integer(row.get('max_stack_count'),1,(1<<31)-1,'installed maximum stack')
        if count>maximum:
            raise ValueError('Frozen quantity exceeds native maximum for GID '+str(prop['gid']))
        location=_location(prop,spaces)
        if prop['grid_page_id']==116001:
            card=cards.get(str(item_id))
            if card is None or card['map_id']!=location.grid_index:
                raise ValueError('The installed keycard MapID differs from its native grid')
            actual_space=next(s for s in keychain if s.index==location.grid_index)
            if location.y*actual_space.length+location.x>=actual_space.base_count:
                raise ValueError('Keycard exceeds source unlocked cells')
        if prop['grid_page_id'] not in range(101,139):
            displayed_w=location.height if location.rotated else location.length
            displayed_h=location.length if location.rotated else location.height
            for x in range(location.x,location.x+displayed_w):
                for y in range(location.y,location.y+displayed_h):
                    cell=(prop['grid_page_id'],location.grid_index,x,y)
                    if cell in occupied:
                        raise ValueError('Frozen carried positions overlap')
                    occupied.add(cell)
        category,sequence=divmod(item_id,10000)
        _,bind_player=snapshot_binding(prop)
        raw_bound=prop.get('bRawBinded',False)
        if type(raw_bound) is not bool:
            raise ValueError('The actual inventory raw-bound flag must be boolean')
        item=MinimalInventoryItem(category,sequence,prop['gid'],prop['grid_page_id'],location,
            0.0,0,0,raw_bound,bind_player,0,0,0.0,False,owner_player_id,0,False)
        if maximum>1:
            item=StackedInventoryItem(item,InventoryStackData(count,maximum,(),()))
        if prop['grid_page_id']==116:
            if maximum!=1:
                raise ValueError('Native keychain stack combination is unqualified')
            item=KeychainInventoryItem(item,keychain)
        item,condition,condition_gap=_condition(item,prop,catalogs)
        if condition is not None:
            conditions.append(condition)
        gun=None
        if str(item_id) in receivers:
            description=gun_from_snapshot_prop(prop)
            item=GunInventoryItem(item,description)
            gun=dict(gid=prop['gid'],receiver_id=item_id,node_count=len(description.rows),
                nodes=[dict(gid=n.gid,item_id=n.item_id,index=n.index,parent_index=n.parent_index,
                    parent_socket_id=n.parent_socket_id) for n in description.rows],
                loaded_ammo=[dict(gid=a.gid,item_id=a.item_id,num=a.num) for a in description.ammo],
                skin_id=description.skin.skin_id,skin_gid=description.skin.skin_gid,
                receiver_source='protocol/weapon_component_catalog.json',
                magazine_capacity_hint_not_serialized=True,weapon_actor_created=False)
            guns.append(gun)
        elif prop['grid_page_id'] in (111,112):
            raise ValueError('Equipped firearm receiver has no qualified installed definition')
        items.append(InventoryFastArrayElement(index,item))
        fields=[name for name in ('health','health_max','weapon','components','expire_timestamp') if prop.get(name) is not None]
        if condition is not None:
            fields=[name for name in fields if name not in ('health','health_max')]
        if gun is not None:
            fields=[name for name in fields if name not in ('weapon','components')]
        gaps.append(dict(gid=prop['gid'],template_id=item_id,unserialized_snapshot_fields=fields,
            native_optional_features_qualified=not fields and condition_gap is None,
            condition_gap=condition_gap))
    repdata=InventoryManagerRepData(True,*value_fields,tuple(spaces[k] for k in sorted(spaces) if k!=116001))
    report=dict(kind='frozen_inventory_mandatory_and_stack_projection',
        all_top_level_gids_preserved=True,all_quantities_preserved=True,
        top_level_item_count=len(props),quantity_sum=sum(p['quantity'] for p in props),
        space_revision=space_revision,space_revision_policy='explicit_local_match_revision_not_official_constant',
        keychain_spaces_from_item_feature=[s.index for s in keychain],
        condition_item_count=len(conditions),condition_sources=conditions,
        gun_item_count=len(guns),gun_sources=guns,inventory_description_does_not_create_or_equip_weapon_actor=True,
        optional_feature_gaps=gaps,optional_features_complete=False,
        component_weapon_children_are_not_duplicated_as_top_level_items=True,
        mandatory_state_defaults_source='native_item_constructor; local initial state, not recovered official match state',
        native_valuation_source='explicit_local_policy',native_inventory_display_verified=False,
        source_pins=source_pins())
    return InventoryProjection(repdata,tuple(items),report)


def build_inventory_repdata(snapshot,*,value_fields,space_revision=INITIAL_SPACE_REVISION):
    return build(snapshot,value_fields=value_fields,space_revision=space_revision).repdata


def build_items(snapshot,*,owner_player_id=0,space_revision=INITIAL_SPACE_REVISION):
    return build(snapshot,value_fields=(0,0,0,0,0,0,0),owner_player_id=owner_player_id,space_revision=space_revision).items
