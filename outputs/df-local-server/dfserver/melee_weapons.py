"""Real client melee receiver/skin pairs for local account equipment."""

import json
from pathlib import Path


ROOT = Path(__file__).resolve().parent.parent / 'protocol'
CATALOG = json.loads((ROOT / 'melee_weapon_catalog.json').read_text(encoding='utf-8'))
SKINS = {row['skin_id']: row['weapon_id'] for row in CATALOG['rows']}
WEAPONS = {weapon: skin for skin, weapon in SKINS.items()}
LOCAL_WEAPONS = {row['weapon_id'] for row in CATALOG['rows']
                 if row['native_collection_unlock_confirmed']}
DEFAULT_WEAPON = SKINS[CATALOG['local_default_skin_id']]
ITEMS = {row['weapon_id']: row for row in CATALOG['rows']}
MELEE_POSITION = 113


def melee_prop(row, position):
    """Return an inventory row with the skin required by ItemBase.lua 0.22."""
    weapon = row['template_id']
    item = ITEMS[weapon]
    return {**row, 'quantity': 1, 'grid_page_id': position, 'x': 0, 'y': 0,
            'length': item['length'], 'width': item['width'],
            'weapon': {'skin_id': WEAPONS[weapon], 'skin_gid': 0}}
