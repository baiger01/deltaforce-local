"""Original keycard metadata and guarded native keychain layout helpers."""

from functools import lru_cache
import json
from pathlib import Path


EQUIPMENT_POSITION = 116
CONTENTS_POSITION = 116001
SCHEMA = """
CREATE TABLE IF NOT EXISTS native_lobby_keycard_health (
    gid INTEGER PRIMARY KEY REFERENCES native_lobby_props(gid) ON DELETE CASCADE,
    health INTEGER NOT NULL CHECK(health>=0),
    health_max INTEGER NOT NULL CHECK(health_max>=health)
);
"""


class UnverifiedKeychainLayout(ValueError):
    pass


@lru_cache(maxsize=1)
def catalog():
    return json.loads((Path(__file__).resolve().parent.parent /
                       'protocol/native_keycard_catalog.json').read_text(encoding='utf-8'))


def keycard_fields(item_id, health=None):
    row = catalog()['keycards'].get(str(item_id))
    if row is None:
        return {}
    maximum = row['durability']
    if health is None:
        health = maximum
    if type(health) is not int or not 0 <= health <= maximum:
        raise ValueError('Keycard health is outside the original maximum durability')
    return {'health': health, 'health_max': maximum}


def persisted_fields(connection, row):
    if str(row['template_id']) not in catalog()['keycards']:
        return {}
    owner = connection.execute('SELECT player_id,template_id FROM native_lobby_props WHERE gid=?',
                               (row['gid'],)).fetchone()
    if owner is None or tuple(owner) != (row['player_id'], row['template_id']):
        raise ValueError('The keycard GID does not belong to this physical inventory item')
    stored = connection.execute('SELECT health,health_max FROM native_lobby_keycard_health WHERE gid=?',
                                (row['gid'],)).fetchone()
    if stored is None:
        return keycard_fields(row['template_id'])
    if stored[1] != catalog()['keycards'][str(row['template_id'])]['durability']:
        raise ValueError('Saved keycard maximum differs from the original table')
    return keycard_fields(row['template_id'], stored[0])


def can_store(item_id, map_id=None):
    row = catalog()['keycards'].get(str(item_id))
    if row is None or any(str(item_id).startswith(prefix)
                          for prefix in catalog()['contents_ignore_prefixes']):
        return False
    return map_id is None or type(map_id) is int and row['map_id'] == map_id


def is_keychain(item_id):
    return type(item_id) is int and item_id in catalog()['keychain_template_ids']


def _rows(item_id):
    rows = [row for row in catalog()['resolved_key_boxes'] if row['item_id'] == item_id]
    if not is_keychain(item_id) or not rows:
        raise UnverifiedKeychainLayout('The installed keychain FName-to-item-ID binding is not verified')
    if len({row['MapID'] for row in rows}) != len(rows):
        raise UnverifiedKeychainLayout('The installed keychain has duplicate map spaces')
    return sorted(rows, key=lambda row: row['Index'])


def grid_spaces(item_id):
    spaces = []
    for row in _rows(item_id):
        length, base = row['BoxLength'], row['DefaultSlotNum']
        locked = [row[f'LevelSlotNums{level}'] for level in range(1, 5)]
        if length <= 0 or base <= 0 or any(count < 0 for count in locked):
            raise UnverifiedKeychainLayout('The installed keychain has invalid native dimensions')
        total = base + sum(locked)
        spaces.append({'id': row['MapID'], 'length': length,
            'width': (total + length - 1) // length, 'base_cnt': base,
            'total_locked': locked, 'unlocked': [0] * len(locked),
            'is_map_unlocked': True})
    return spaces


def layout_map(item_id):
    return {space['id']: (space['length'], space['width']) for space in grid_spaces(item_id)}


def validate_location(item_id, card_id, space_id, start_x, start_y):
    spaces = grid_spaces(item_id)
    if not can_store(card_id, space_id):
        raise ValueError('The original keycard does not fit this map space')
    space = next((space for space in spaces if space['id'] == space_id), None)
    if (space is None or type(start_x) is not int or type(start_y) is not int or
            start_x < 0 or start_y < 0 or start_x >= space['length'] or start_y >= space['width'] or
            start_y * space['length'] + start_x >= space['base_cnt']):
        raise ValueError('The keycard location is outside the native unlocked cells')
    return {'pos': CONTENTS_POSITION, 'space_id': space_id,
            'start_x': start_x, 'start_y': start_y, 'x': 1, 'y': 1, 'rotate': False}


def position_change(item_id):
    return {'pos_id': CONTENTS_POSITION, 'change_type': 3,
            'src_prop_id': item_id, 'space': grid_spaces(item_id)}
