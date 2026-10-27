"""Source-qualified carried gun selection only; no actor wire/layout guesses."""
from dataclasses import dataclass
import hashlib
import json

from dfserver.legacy_ds_inventory_gun_desc import (GunDescription, from_snapshot_prop,
    inventory_gun_desc_source_pins)
from portable_map_owned_weapon import _admitted_loadout
from export_portable_carried_weapon_schema import ROOT, OUTPUT, derive
from portable_source_guard import cached_qualification

SCHEMA_SHA256 = 'cee72ef7d250ac1fb42adf8bf259f4bf3b53379e6dd488b8a53ce1ab7cee89b3'


@cached_qualification(ROOT, extra_pins=lambda: {
    OUTPUT.relative_to(ROOT).as_posix(): SCHEMA_SHA256,
    **{p: hashlib.sha256((ROOT/p).read_bytes()).hexdigest() for p in (
        'work/portable_carried_weapon_selection.py', 'work/export_portable_carried_weapon_schema.py',
        'work/portable_source_guard.py')}})
def binding():
    raw = OUTPUT.read_bytes()
    if hashlib.sha256(raw).hexdigest() != SCHEMA_SHA256:
        raise ValueError('Carried weapon public schema changed')
    actual = json.loads(raw)
    if actual != derive():
        raise ValueError('Carried weapon schema differs from qualified sources')
    return actual


def source_pins():
    pins = dict(binding()['sources'])
    pins[OUTPUT.relative_to(ROOT).as_posix()] = SCHEMA_SHA256
    for relative, digest in inventory_gun_desc_source_pins().items():
        pins['outputs/df-local-server/'+relative] = digest
    for relative in ('work/portable_carried_weapon_selection.py',
            'work/export_portable_carried_weapon_schema.py', 'work/portable_map_owned_weapon.py'):
        pins[relative] = hashlib.sha256((ROOT/relative).read_bytes()).hexdigest()
    return pins


@dataclass(frozen=True)
class CarriedGunSelection:
    weapon_rec_id: int
    inventory_gid: int
    class_path: str
    cdo_path: str
    business_position: int
    description: GunDescription
    weapon_slot: None = None
    actor_equip_position: None = None


@dataclass(frozen=True)
class CarriedWeaponSelection:
    guns: tuple[CarriedGunSelection, ...]
    selected_melee: object
    gaps: tuple[str, ...]
    qualification: dict


def select(ticket, *, schema=None):
    actual = binding()
    if schema is not None and schema != actual:
        raise ValueError('Changed carried weapon schema')
    document = _admitted_loadout(ticket)
    slots = actual['business_slots']
    equipped_gun_positions = {slots['MainWeaponLeft'], slots['MainWeaponRight']}
    seen, occupied, guns = set(), set(), []
    for prop in document['props']:
        gid = prop.get('gid')
        if type(gid) is not int or not 1 <= gid < 1 << 64 or gid in seen:
            raise ValueError('Exact distinct frozen inventory GIDs are required')
        seen.add(gid)
        if not prop.get('weapon') or prop.get('grid_page_id') not in equipped_gun_positions:
            continue
        position = prop['grid_page_id']
        if (type(position) is not int or position in occupied or
                type(prop.get('quantity')) is not int or prop['quantity'] != 1):
            raise ValueError('One exact carried gun per business weapon position is required')
        occupied.add(position)
        receiver = prop.get('template_id')
        if type(receiver) is not int or str(receiver) not in actual['receivers']:
            raise ValueError('The frozen equipped gun has no qualified receiver-to-class row')
        description = from_snapshot_prop(prop)
        if description.rows[0].item_id != receiver or description.rows[0].gid != gid:
            raise ValueError('GunDesc root identity differs from native Actor initialization input')
        row = actual['receivers'][str(receiver)]
        guns.append(CarriedGunSelection(receiver, gid, row['class_path'],
            actual['modular_actor']['cdo_path'], position, description))
    gaps = ['modular_actor_actual_rep_layout', 'business_position_to_actor_equip_position',
        'owning_manager_weapon_slot_current_value', 'complete_manager_binding_and_active_choice']
    selected = document.get('selected_melee')
    if selected is not None:
        gaps.append('selected_melee_actor_class_recid_and_slot')
    return CarriedWeaponSelection(tuple(sorted(guns, key=lambda g: g.business_position)), selected,
        tuple(gaps), dict(snapshot_sha256=hashlib.sha256(ticket.loadout_snapshot).hexdigest(),
            schema_sha256=hashlib.sha256(OUTPUT.read_bytes()).hexdigest(),
            gun_recid_and_class_source_qualified=True, actor_wire_content_generated=False,
            native_gameplay_verified=False))
