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

    def visit(parts):
        nonlocal unknown_magazine
        for component in parts:
            prop = component['prop_data']
            row = CATALOG['magazines'].get(str(prop['id']))
            if row:
                magazines.append(row)
            elif int(prop['id']) in CATALOG['magazine_item_ids']:
                unknown_magazine = True
            visit(prop.get('components', []))

    visit(components)
    if unknown_magazine or len(magazines) > 1:
        return None
    if not magazines:
        weapon = CATALOG['weapons'].get(str(PRESETS.get(int(receiver_id), int(receiver_id)))) if receiver_id else None
        return weapon['base_capacity'] if weapon else None
    row = magazines[0]
    return row['capacity'] + (row['sub_clip_capacity'] if row['dual_clip'] else 0)
