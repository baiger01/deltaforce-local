"""Finite configured items in the actual cooked SafeBox capacity.

The three qualified static instances have no capacity override; their exact
SafeBox CDO supplies 4 by 4. Grid ID1 and item element IDs0..N are explicit local
instance indices. Template IDs, item shapes and stack maxima come from sources.
GIDs must be reserved by the caller's match allocator before registration.
"""
from dataclasses import dataclass
import hashlib
import json
from pathlib import Path

from dfserver.legacy_ds_inventory_items import (InventoryItemLocation, MinimalInventoryItem,
    InventoryFastArrayElement)
from dfserver.legacy_ds_inventory_stack import StackedInventoryItem, InventoryStackData
from dfserver.legacy_ds_inventory_state import InventorySpace, InventorySpaceGrid
import portable_loot_box_codec as boxes


ROOT = Path(__file__).resolve().parent.parent
BASE = 'work/evidence/map-system-audit-20261018/'
PINS = {
    BASE + 'native-economy-door-container-component-defaults-and-tags-v1.json':
        'faa9159b4a817f0dedba832614680117325fbc1e16918388b7b7f83875a257a3',
    BASE + 'native-economy-loaded-level1-container-door-catalog-v2.json':
        'd0b9dd3a71225f6cb5aab029658a6a852eb75378a89a99746ac0bfc5d4ed9bdc',
}


@dataclass(frozen=True)
class SafeBoxSeed:
    spaces: tuple
    items: tuple
    qualification: dict


def _sources():
    documents = {}
    for relative, digest in PINS.items():
        raw = (ROOT / relative).read_bytes()
        if hashlib.sha256(raw).hexdigest() != digest:
            raise ValueError('The exact SafeBox cooked capacity source changed: ' + relative)
        documents[relative] = json.loads(raw)
    return documents


def source_pins():
    _sources()
    pins = boxes.source_pins()
    pins.update(PINS)
    pins['work/portable_world_box_seed.py'] = hashlib.sha256(Path(__file__).read_bytes()).hexdigest()
    return pins


def _capacity(binding):
    boxes.qualify_binding(binding)
    docs = _sources()
    defaults = docs[BASE + 'native-economy-door-container-component-defaults-and-tags-v1.json']
    cdo, = [export for package in defaults['packages'] for export in package['exports']
        if package['source']['indexed_path'] == '../../../DeltaForce/Content/BluePrints/Interact/BP_Interactor_Container_SafeBox.uasset'
        and export['name'] == 'Default__BP_Interactor_Container_SafeBox_C']
    cooked = docs[BASE + 'native-economy-loaded-level1-container-door-catalog-v2.json']
    actor, = [row for row in cooked['actors'] if row['cooked_object_path'] == binding.object_path]
    if actor['class_import'] != boxes.SAFE_CLASS or any(
            name in actor['properties'] for name in ('CapacityLength', 'CapacityWidth')):
        raise ValueError('The actual selected box has an unsupported source capacity override')
    values = []
    for name in ('CapacityLength', 'CapacityWidth'):
        row = cdo['properties'][name]
        if row['serialized_kind'] != 'ByteProperty' or row['payload_bytes'] != 1 or row['value'] != 4:
            raise ValueError('The actual SafeBox CDO capacity changed')
        values.append(row['value'])
    return tuple(values)


def _rows(drops):
    source_pins()
    if type(drops) is not tuple or len(drops) > 64:
        raise ValueError('A bounded frozen local drop tuple is required')
    catalog = boxes._sources()['outputs/df-local-server/protocol/game_item_catalog.json']['rows']
    result = []
    total = 0
    for drop in drops:
        if (type(drop) is not tuple or len(drop) != 2 or type(drop[0]) is not int or
                type(drop[1]) is not int or drop[1] < 1):
            raise ValueError('Each frozen drop must specify an actual integer template and quantity')
        template, quantity = drop
        row = catalog.get(str(template))
        if row is None:
            raise ValueError('The frozen drop has no real installed GameItem row')
        maximum = row['max_stack_count']
        if (type(maximum) is not int or maximum < 1 or row['is_model_only'] or
                any(type(row[key]) is not int or not 1 <= row[key] <= 255 for key in ('width', 'length'))):
            raise ValueError('The frozen drop has no supported actual stack or inventory shape')
        instances = (quantity + maximum - 1) // maximum
        total += instances
        if total > boxes.MAX_ITEMS:
            raise ValueError('The frozen finite item instance count exceeds its bound')
        while quantity:
            count = min(quantity, maximum)
            result.append((template, count, row))
            quantity -= count
    return result


def required_instances(drops):
    return len(_rows(drops))


def build_seed(binding, *, drops, allocated_gids):
    dimensions = _capacity(binding)
    rows = _rows(drops)
    if (type(allocated_gids) is not tuple or len(allocated_gids) != len(rows) or
            any(type(gid) is not int or not 0 < gid < 1 << 64 for gid in allocated_gids) or
            len(set(allocated_gids)) != len(allocated_gids)):
        raise ValueError('Exactly one unique reserved local instance GID per actual stack is required')
    length, height = dimensions
    occupied = set()
    items = []
    for element_id, ((template, count, row), gid) in enumerate(zip(rows, allocated_gids)):
        width, item_height = row['width'], row['length']
        wanted = None
        for y in range(height - item_height + 1):
            for x in range(length - width + 1):
                cells = {(xx, yy) for yy in range(y, y + item_height) for xx in range(x, x + width)}
                if not occupied & cells:
                    wanted = (x, y, cells)
                    break
            if wanted is not None:
                break
        if wanted is None:
            raise ValueError('The configured finite contents do not fit the actual cooked box capacity')
        x, y, cells = wanted
        occupied.update(cells)
        category, sequence = divmod(template, 10000)
        value = MinimalInventoryItem(category, sequence, gid, 302,
            InventoryItemLocation(x, y, width, item_height, False, 1),
            0.0, 0, 0, False, 0, 0, 0, 0.0, False, 0, 0, False)
        if row['max_stack_count'] > 1:
            value = StackedInventoryItem(value,
                InventoryStackData(count, row['max_stack_count'], (), ()))
        items.append(InventoryFastArrayElement(element_id, value))
    items = tuple(items)
    # This also rejects templates requiring gun/keycard/equipment features.
    # Those rows need a complete separately sourced typed instance producer.
    boxes.validate_items(items)
    spaces = (InventorySpace(302, 1, (InventorySpaceGrid(1, 0, 0, length, height, 0, 0),)),)
    return SafeBoxSeed(spaces, items, dict(source_pins=source_pins(),
        capacity_from_actual_class_cdo=True, cooked_instance_capacity_override_present=False,
        local_grid_instance_id=1, finite_stack_count=len(items),
        native_world_binding_verified=False, packets_sent=False, account_written=False))
