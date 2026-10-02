"""Owned keychain permissions and placements backed by native Key/KeyBox rows."""

import time

from . import native_keycards as keys


SCHEMA = """
CREATE TABLE IF NOT EXISTS native_lobby_keychain_permissions (
 player_id TEXT NOT NULL REFERENCES players(id),
 template_id INTEGER NOT NULL,
 gid INTEGER NOT NULL UNIQUE CHECK(gid>0),
 expire_timestamp INTEGER NOT NULL DEFAULT 0,
 PRIMARY KEY(player_id,template_id)
);
"""


def _fail(code, message):
    from .core import fail
    fail(code, message)


def verified_spaces(item_id):
    try:
        return keys.grid_spaces(item_id)
    except (ValueError, TypeError):
        _fail('INVALID_EQUIPMENT', 'Keychain has no independently verified native layout')


def permissions(connection, player_id):
    return [{'id': row['template_id'], 'gid': row['gid'], 'num': 1,
             'expire_timestamp': row['expire_timestamp']}
            for row in connection.execute(
                'SELECT * FROM native_lobby_keychain_permissions WHERE player_id=? ORDER BY template_id',
                (player_id,))]


def equipped(connection, player_id, *, active=False):
    row = connection.execute('SELECT p.*,k.expire_timestamp FROM native_lobby_props p '
        'JOIN native_lobby_keychain_permissions k ON k.player_id=p.player_id '
        'AND k.template_id=p.template_id AND k.gid=p.gid '
        'WHERE p.player_id=? AND p.grid_page_id=?', (player_id, keys.EQUIPMENT_POSITION)).fetchone()
    if row is None:
        _fail('INVALID_EQUIPMENT', 'No owned keychain is equipped')
    if active and row['expire_timestamp'] > 0 and row['expire_timestamp'] <= time.time():
        _fail('PROP_NOT_FOUND', 'The equipped keychain permission has expired')
    verified_spaces(row['template_id'])
    return row


def layout(connection, player_id):
    exists = connection.execute('SELECT 1 FROM native_lobby_props WHERE player_id=? AND grid_page_id=?',
                                (player_id, keys.EQUIPMENT_POSITION)).fetchone()
    if not exists:
        return None
    bag = equipped(connection, player_id)
    return keys.layout_map(bag['template_id'])


def location(row):
    if row['grid_page_id'] != keys.CONTENTS_POSITION:
        from .local_commerce import inventory_location
        return inventory_location(row)
    width = row.get('space_width')
    if not width:
        raise ValueError('Keycard coordinates require the equipped native map layout')
    return {'pos': keys.CONTENTS_POSITION, 'space_id': row['x'],
            'start_x': row['y'] % width, 'start_y': row['y'] // width,
            'x': row['width'], 'y': row['length'], 'rotate': bool(row.get('rotated', False))}


def validate_card(item_id, row, loc):
    if (row['quantity'], row['length'], row['width']) != (1, 1, 1):
        _fail('INVALID_ARGUMENT', 'Keychain cards must be single native one-cell instances')
    try:
        return keys.validate_location(item_id, row['template_id'], loc['space_id'],
                                      loc['start_x'], loc['start_y'])
    except (ValueError, TypeError):
        _fail('INVALID_ARGUMENT', 'Keycard does not fit an unlocked cell of its native map')


def container_position(connection, player_id, card_id, length, width, ignored, spec_loc, *, quantity):
    bag = equipped(connection, player_id, active=True)
    if not keys.can_store(card_id) or (quantity, length, width) != (1, 1, 1):
        _fail('INVALID_ARGUMENT', 'Native keychain rules reject this item')
    spaces = verified_spaces(bag['template_id'])
    by_id = {space['id']: space for space in spaces}
    occupied = {space_id: set() for space_id in by_id}
    for row in connection.execute('SELECT * FROM native_lobby_props '
            'WHERE player_id=? AND grid_page_id=?', (player_id, keys.CONTENTS_POSITION)):
        if row['gid'] in ignored:
            continue
        space = by_id.get(row['x'])
        if space is None:
            _fail('INVALID_EQUIPMENT', 'Saved keycard map is not in the equipped keychain')
        loc = location({**dict(row), 'space_width': space['length']})
        validate_card(bag['template_id'], dict(row), loc)
        if row['y'] in occupied[row['x']]:
            _fail('INVALID_EQUIPMENT', 'Saved keycards overlap')
        occupied[row['x']].add(row['y'])
    requested_map = int(spec_loc.get('space_id') or 0)
    exact = bool(spec_loc)
    for space in spaces:
        if requested_map and space['id'] != requested_map:
            continue
        if not keys.can_store(card_id, space['id']):
            continue
        candidates = range(space['base_cnt'])
        if exact:
            sx, sy = int(spec_loc.get('start_x') or 0), int(spec_loc.get('start_y') or 0)
            validate_card(bag['template_id'], {'template_id': card_id, 'quantity': 1,
                'length': 1, 'width': 1}, {'space_id': space['id'], 'start_x': sx, 'start_y': sy})
            candidates = (sy * space['length'] + sx,)
        for index in candidates:
            if index not in occupied[space['id']]:
                return space['id'], index, 1, 1, bool(spec_loc.get('rotate', False))
    _fail('POSITION_OCCUPIED' if exact else 'KEYCHAIN_FULL',
          'No unlocked keychain cell is available in the keycard native map')


def equip(backend, connection, player_id, command):
    from .core import integer
    from .local_commerce import installed_items
    item_id = integer(command.get('prop_id'), 'prop_id', 1, 2**63 - 1)
    spaces = {space['id']: space for space in verified_spaces(item_id)}
    permission = connection.execute('SELECT * FROM native_lobby_keychain_permissions '
        'WHERE player_id=? AND template_id=?', (player_id, item_id)).fetchone()
    if permission is None or (permission['expire_timestamp'] > 0 and permission['expire_timestamp'] <= time.time()):
        _fail('PROP_NOT_FOUND', 'This keychain permission is not owned or has expired')
    if command.get('prop_gid') and command['prop_gid'] != permission['gid']:
        _fail('PROP_NOT_FOUND', 'The keychain instance does not match its permission')
    old = connection.execute('SELECT * FROM native_lobby_props '
        'WHERE player_id=? AND grid_page_id=?', (player_id, keys.EQUIPMENT_POSITION)).fetchone()
    changed = []
    for saved in connection.execute('SELECT p.*,COALESCE(r.rotated,0) AS rotated '
            'FROM native_lobby_props p LEFT JOIN native_lobby_prop_rotations r ON r.gid=p.gid '
            'WHERE player_id=? AND grid_page_id=?', (player_id, keys.CONTENTS_POSITION)):
        before = backend._container_prop(connection, player_id, saved)
        loc = location(before)
        validate_card(item_id, before, loc)
        width = spaces[loc['space_id']]['length']
        after = {**before, 'y': loc['start_y'] * width + loc['start_x'], 'space_width': width}
        changed.append({'before': before, 'after': after})
    metadata = installed_items().get(str(item_id))
    if metadata is None:
        _fail('INVALID_EQUIPMENT', 'Keychain is not in the native GameItem catalog')
    chosen = {'gid': permission['gid'], 'template_id': item_id, 'quantity': 1,
              'grid_page_id': keys.EQUIPMENT_POSITION, 'x': 0, 'y': 0,
              'length': metadata['length'], 'width': metadata['width'], 'rotated': False,
              'expire_timestamp': permission['expire_timestamp']}
    if old and old['gid'] == permission['gid']:
        return [{'before': backend._container_prop(connection, player_id, old), 'after': chosen}]
    changes = [{'before': backend._container_prop(connection, player_id, old), 'after': None}] if old else []
    for move in changed:
        gid = move['after']['gid']
        connection.execute('UPDATE native_lobby_props SET grid_page_id=999999,x=?,y=0 WHERE gid=?', (gid, gid))
    for move in changed:
        after = move['after']
        connection.execute('UPDATE native_lobby_props SET grid_page_id=?,x=?,y=? WHERE gid=?',
            (keys.CONTENTS_POSITION, after['x'], after['y'], after['gid']))
    connection.execute('DELETE FROM native_lobby_props WHERE player_id=? AND grid_page_id=?',
                       (player_id, keys.EQUIPMENT_POSITION))
    connection.execute('INSERT INTO native_lobby_props VALUES (?,?,?,?,?,?,?,?,?)',
        (chosen['gid'], player_id, item_id, 1, keys.EQUIPMENT_POSITION, 0, 0,
         chosen['length'], chosen['width']))
    return changes + [{'before': None, 'after': chosen}] + changed


def ensure(backend, token, *, template_ids, selected_template_id=None):
    """Explicit local grants; the caller must supply source-verified bag IDs."""
    from .core import integer
    if not isinstance(template_ids, (list, tuple)) or not 1 <= len(template_ids) <= 26:
        _fail('INVALID_ARGUMENT', 'Explicit verified keychain templates are required')
    ids = list(dict.fromkeys(integer(value, 'template_id', 1, 2**63 - 1) for value in template_ids))
    for item_id in ids:
        verified_spaces(item_id)
    if selected_template_id is not None and selected_template_id not in ids:
        _fail('INVALID_ARGUMENT', 'Selected keychain must be among the explicit grants')
    with backend.connection() as connection:
        connection.execute('BEGIN IMMEDIATE')
        player_id = backend._authorize(connection, token)
        for item_id in ids:
            if not connection.execute('SELECT 1 FROM native_lobby_keychain_permissions '
                'WHERE player_id=? AND template_id=?', (player_id, item_id)).fetchone():
                connection.execute('INSERT INTO native_lobby_keychain_permissions VALUES (?,?,?,0)',
                    (player_id, item_id, backend._next_native_prop_gid(connection)))
        if selected_template_id is not None:
            equip(backend, connection, player_id, {'prop_id': selected_template_id, 'target_pos': 116})
        connection.commit()


def prop_info(row):
    from .local_commerce import item_condition_fields
    return {'id': row['template_id'], 'gid': row['gid'], 'num': row['quantity'],
            'position': row['grid_page_id'], 'length': row['length'], 'width': row['width'],
            **item_condition_fields(row['template_id'], health=row.get('health')),
            **({'expire_timestamp': row['expire_timestamp']} if 'expire_timestamp' in row else {}),
            'loc': location(row)}


def wire_slots(state):
    props = state['props']
    bag = next((row for row in props if row['grid_page_id'] == keys.EQUIPMENT_POSITION), None)
    spaces = verified_spaces(bag['template_id']) if bag else []
    source_id = bag['template_id'] if bag else 0
    cards = [row for row in props if row['grid_page_id'] == keys.CONTENTS_POSITION]
    occupied = set()
    for card in cards:
        if not bag:
            raise ValueError('Saved keycards have no equipped keychain')
        validate_card(source_id, card, location(card))
        cell = (card['x'], card['y'])
        if cell in occupied:
            raise ValueError('Saved keycards overlap')
        occupied.add(cell)
    return [
        {'position': keys.EQUIPMENT_POSITION, 'capacity': 1,
         'src_prop_id': source_id, 'grid_space': [{'id': 1, 'length': 1, 'width': 1}],
         'load_props': [prop_info(bag)] if bag else []},
        {'position': keys.CONTENTS_POSITION, 'capacity': sum(space['base_cnt'] for space in spaces),
         'src_prop_id': source_id, 'grid_space': spaces, 'load_props': [prop_info(row) for row in cards]},
    ]
