"""Ammunition compatibility and capacities from the installed client tables."""

import json
from pathlib import Path

from .weapon_components import PRESETS


CATALOG = json.loads((Path(__file__).resolve().parent.parent /
                     'protocol/weapon_ammo_catalog.json').read_text(encoding='utf-8'))
LOAD = CATALOG['operate_types']['load']
UNLOAD = CATALOG['operate_types']['unload']


def matches_ammo(receiver_id, bullet_id):
    weapon = CATALOG['weapons'].get(str(PRESETS.get(int(receiver_id), int(receiver_id))))
    bullet = CATALOG['bullets'].get(str(bullet_id))
    return bool(weapon and bullet and weapon['ammo_type'] == bullet['ammo_type'])


def magazine_capacity(components, receiver_id=None):
    magazines = []
    unknown_magazine = False
    additions = []

    def visit(parts):
        nonlocal unknown_magazine
        for component in parts:
            prop = component['prop_data']
            row = CATALOG['magazines'].get(str(prop['id']))
            if row:
                magazines.append(row)
            elif int(prop['id']) in CATALOG['magazine_item_ids']:
                unknown_magazine = True
            addition = CATALOG.get('capacity_additions', {}).get(str(prop['id']))
            if addition:
                additions.append(addition['capacity'])
            visit(prop.get('components', []))

    visit(components)
    if unknown_magazine or len(magazines) > 1:
        return None
    row = magazines[0] if magazines else None
    if row is None or row.get('capacity_mode') == 'base':
        weapon = CATALOG['weapons'].get(str(PRESETS.get(int(receiver_id), int(receiver_id)))) if receiver_id else None
        if weapon is None:
            return None
        capacity = weapon['base_capacity']
    else:
        capacity = row['capacity']
    if row and row['dual_clip']:
        capacity += row['sub_clip_capacity']
    return capacity + sum(additions)
