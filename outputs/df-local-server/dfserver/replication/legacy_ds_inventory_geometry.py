"""Pinned native grid parsing and PB/native UI location equivalence.

Accepts explicit source layouts and business locations. It selects no item,
container, equipment slot, or destination, and infers nothing from occupied cells.
"""
from dfserver._paths import SERVER_ROOT
import hashlib
import json
from pathlib import Path
import re

from dfserver.replication.legacy_ds_inventory_items import InventoryItemLocation
from dfserver.replication.legacy_ds_inventory_state import InventorySpaceGrid

GEOMETRY_RELATIVE_PATH='protocol/portable-map-spawn/inventory-geometry-contract.json'
GEOMETRY_SHA256='53580f8789338f37564312ce130e095ccfdd53b56207728b28a7de4c21bf3c61'
SEGMENT=re.compile(r'\((\d+),(\d+)\)\((-?\d+),(-?\d+)\)')


def inventory_geometry_source_pins(server_root=None):
    root=Path(server_root) if server_root is not None else SERVER_ROOT
    try:
        raw=(root/GEOMETRY_RELATIVE_PATH).read_bytes()
    except OSError as error:
        raise ValueError('Inventory geometry source is unavailable') from error
    if hashlib.sha256(raw).hexdigest()!=GEOMETRY_SHA256:
        raise ValueError('Inventory geometry source changed')
    document=json.loads(raw)
    if document.get('kind')!='source_qualified_inventory_geometry_contract':
        raise ValueError('Unexpected inventory geometry contract')
    return {GEOMETRY_RELATIVE_PATH:GEOMETRY_SHA256}


def grids_from_raw_layout(raw_layout):
    inventory_geometry_source_pins()
    if type(raw_layout) is not str or not 1<=len(raw_layout)<=8192:
        raise ValueError('An explicit bounded source layout required')
    parts=raw_layout.split('|')
    if not 1<=len(parts)<=64:
        raise ValueError('Source layout exceeds local grid bound')
    grids=[]
    for index,part in enumerate(parts,1):
        match=SEGMENT.fullmatch(part)
        if match is None:
            raise ValueError('Unrecognized source grid segment')
        length,height,half_x,half_y=map(int,match.groups())
        if not (1<=length<=255 and 1<=height<=255 and -128<=half_x<=127 and -128<=half_y<=127):
            raise ValueError('Source layout exceeds the bounded native scalar subset')
        grids.append(InventorySpaceGrid(index,0,0,length,height,half_x,half_y))
    return tuple(grids)


def equipment_location():
    inventory_geometry_source_pins()
    return InventoryItemLocation(0,0,1,1,False,1)


def container_self_location():
    inventory_geometry_source_pins()
    return InventoryItemLocation(0,0,1,1,False,0)


def location_from_business_location(location):
    """Invert InitFromCpp to match InitFromPb displayed coordinates and shape.

    This takes PB location dimensions, which may already be rotated, rather than
    a lobby database row or unqualified item template dimensions.
    """
    inventory_geometry_source_pins()
    if type(location) is not dict:
        raise ValueError('An explicit business PB location required')
    x,y,length,height,index=(location[k] for k in ('start_x','start_y','x','y','space_id'))
    if any(type(v) is not int or not 0<=v<=255 for v in (x,y,index)):
        raise ValueError('Business position exceeds native location bytes')
    if any(type(v) is not int or not 1<=v<=255 for v in (length,height)):
        raise ValueError('Business item dimensions exceed native location bytes')
    rotated=location['rotate']
    if type(rotated) is not bool:
        raise ValueError('Explicit business rotation required')
    rotated=rotated and length!=height
    return InventoryItemLocation(x,y,height if rotated else length,length if rotated else height,
        rotated,index or 1)
