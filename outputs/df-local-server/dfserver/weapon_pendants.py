"""Native pendant collection and independent skin/pendant equipment state.

Ordinary local test grants are sourced and explicit. Mystical instance data is
read from the save only; no rarity, wear, appearance or instance IDs are created.
"""

import json
from pathlib import Path

from . import gun_skins


ROOT = Path(__file__).resolve().parent.parent / 'protocol'
CATALOG = json.loads((ROOT / 'weapon_pendant_catalog.json').read_text(encoding='utf-8'))
PENDANTS = {row['pendant_id']: row for row in CATALOG['rows']}
ORDINARY = frozenset(item for item, row in PENDANTS.items() if row['local_test_grant'])
RECEIVERS = frozenset(int(item) for item in json.loads(
    (ROOT / 'weapon_component_catalog.json').read_text(encoding='utf-8'))['rows'])
SKIN_RECEIVERS = frozenset(row['weapon_id'] for row in gun_skins.SKINS.values())
SUPPORTED_REQUESTS = frozenset(('CSWAssemblyApplySkinReq', 'CSCollectionLoadMysticalPendantPropsReq'))

SCHEMA = """
CREATE TABLE IF NOT EXISTS native_lobby_weapon_pendants (
 weapon_gid INTEGER PRIMARY KEY REFERENCES native_lobby_props(gid) ON DELETE CASCADE,
 pendant_id INTEGER NOT NULL, pendant_gid INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS native_lobby_default_pendants (
 player_id TEXT NOT NULL REFERENCES players(id), weapon_id INTEGER NOT NULL,
 pendant_id INTEGER NOT NULL, pendant_gid INTEGER NOT NULL,
 PRIMARY KEY(player_id,weapon_id));
CREATE TABLE IF NOT EXISTS native_lobby_pendant_instances (
 player_id TEXT NOT NULL REFERENCES players(id), template_id INTEGER NOT NULL,
 gid INTEGER NOT NULL UNIQUE CHECK(gid>0), mystical_json TEXT NOT NULL,
 PRIMARY KEY(player_id,template_id,gid));
"""


def provision(connection, player_id):
    connection.executemany('INSERT OR IGNORE INTO native_lobby_collection_props VALUES (?,?,1)',
                           ((player_id, item) for item in sorted(ORDINARY)))


def collection(backend, token):
    with backend.connection() as connection:
        connection.execute('BEGIN IMMEDIATE')
        player_id = backend._authorize(connection, token)
        provision(connection, player_id)
        ordinary = [{'id': row['template_id'], 'gid': 0, 'num': row['quantity']}
                    for row in connection.execute('SELECT template_id,quantity '
                        'FROM native_lobby_collection_props WHERE player_id=? ORDER BY template_id',
                        (player_id,)) if row['template_id'] in PENDANTS
                    and not PENDANTS[row['template_id']]['is_mystical']]
        mystical = [{'id': row['template_id'], 'gid': row['gid'], 'num': 1,
                     'mystical_pendant_data': json.loads(row['mystical_json'])}
                    for row in connection.execute('SELECT * FROM native_lobby_pendant_instances '
                        'WHERE player_id=? ORDER BY template_id,gid', (player_id,))
                    if row['template_id'] in PENDANTS and PENDANTS[row['template_id']]['is_mystical']]
        connection.commit()
    return ordinary + mystical


def weapon_state(connection, player_id, prop):
    row = connection.execute('SELECT p.pendant_id,p.pendant_gid '
        'FROM native_lobby_weapon_pendants p JOIN native_lobby_props w ON w.gid=p.weapon_gid '
        'WHERE p.weapon_gid=? AND w.player_id=?', (prop['gid'], player_id)).fetchone()
    if row is None:
        row = connection.execute('SELECT pendant_id,pendant_gid FROM native_lobby_default_pendants '
            'WHERE player_id=? AND weapon_id=?',
            (player_id, gun_skins.receiver(prop['template_id']))).fetchone()
    return dict(row) if row is not None else {}


def setups(connection, player_id):
    defaults = {row['weapon_id']: row for row in gun_skins.setups(connection, player_id)}
    for row in connection.execute('SELECT weapon_id,pendant_id,pendant_gid '
        'FROM native_lobby_default_pendants WHERE player_id=? ORDER BY weapon_id', (player_id,)):
        defaults.setdefault(row['weapon_id'], {'weapon_id': row['weapon_id']}).update(dict(row))
    return [defaults[item] for item in sorted(defaults)]


def _pendant(connection, player_id, command):
    from .core import fail

    item_id, gid = int(command.get('pendant_id') or 0), int(command.get('pendant_gid') or 0)
    if not item_id:
        if gid:
            fail('INVALID_ARGUMENT', 'An empty pendant cannot have an instance ID')
        return 0, 0
    row = PENDANTS.get(item_id)
    if row is None:
        fail('INVALID_EQUIPMENT', 'Pendant template has not been recovered')
    if not row['is_mystical']:
        # GunsmithPendantLogic.NormalizePendantGUID normalizes ordinary UI IDs.
        if gid not in (0, item_id):
            fail('INVALID_ARGUMENT', 'An ordinary pendant cannot have an instance ID')
        owned = connection.execute('SELECT 1 FROM native_lobby_collection_props '
            'WHERE player_id=? AND template_id=? AND quantity>0', (player_id, item_id)).fetchone()
        gid = 0
    else:
        owned = connection.execute('SELECT 1 FROM native_lobby_pendant_instances '
            'WHERE player_id=? AND template_id=? AND gid=?', (player_id, item_id, gid)).fetchone()
    if not owned:
        fail('INVALID_EQUIPMENT', 'Pendant instance is not owned')
    return item_id, gid


def apply(backend, token, fields):
    from .core import fail
    from .local_commerce import inventory_location, item_condition_fields

    data_type = int(fields.get('data_type') or 0)
    commands = fields.get('cmds', [])
    if data_type not in (0, 99) or not 1 <= len(commands) <= 32:
        fail('INVALID_ARGUMENT', 'Unsupported cosmetic command')
    changes, changed_defaults = [], set()
    with backend.connection() as connection:
        connection.execute('BEGIN IMMEDIATE')
        player_id = backend._authorize(connection, token)
        gun_skins.provision(connection, player_id)
        provision(connection, player_id)
        backend._ensure_weapon_parts(connection, player_id)
        for command in commands:
            weapon_id, weapon_gid = int(command.get('weapon_id') or 0), int(command.get('weapon_gid') or 0)
            receiver = gun_skins.receiver(weapon_id)
            if receiver not in RECEIVERS and receiver not in SKIN_RECEIVERS:
                fail('INVALID_EQUIPMENT', 'Weapon receiver has not been recovered')
            # WeaponSkinDataTable can recover cosmetics before a usable component tree.
            if receiver not in RECEIVERS and (int(command.get('pendant_id') or 0)
                    or int(command.get('pendant_gid') or 0) or command.get('pendant_apply_all')):
                fail('INVALID_EQUIPMENT', 'Weapon pendant attachment has not been recovered')
            skin_id, skin_gid = int(command.get('skin_id') or 0), int(command.get('skin_gid') or 0)
            if skin_id:
                skin = gun_skins.SKINS.get(skin_id)
                owned = connection.execute('SELECT 1 FROM native_lobby_gun_skins '
                    'WHERE player_id=? AND skin_id=? AND gid=?', (player_id, skin_id, skin_gid)).fetchone()
                if not skin or skin['weapon_id'] != receiver or not owned:
                    fail('INVALID_EQUIPMENT', 'Skin is not owned for this weapon')
            elif skin_gid:
                fail('INVALID_ARGUMENT', 'Default skin cannot have an instance ID')
            pendant_id, pendant_gid = _pendant(connection, player_id, command)
            skin_all, pendant_all = bool(command.get('apply_all')), bool(command.get('pendant_apply_all'))
            rows = [row for row in connection.execute('SELECT * FROM native_lobby_props WHERE player_id=?',
                                                     (player_id,))
                    if gun_skins.receiver(row['template_id']) == receiver]
            current = [row for row in rows if row['gid'] == weapon_gid and row['template_id'] == weapon_id]
            if weapon_gid and not current:
                fail('PROP_NOT_FOUND', 'Weapon instance is not owned')
            if not current and not (skin_all or pendant_all):
                fail('PROP_NOT_FOUND', 'A single-weapon command requires its instance ID')
            if skin_all:
                connection.execute('INSERT INTO native_lobby_default_skins VALUES (?,?,?,?) '
                    'ON CONFLICT(player_id,weapon_id) DO UPDATE SET skin_id=excluded.skin_id,skin_gid=excluded.skin_gid',
                    (player_id, receiver, skin_id, skin_gid))
                changed_defaults.add(receiver)
            if pendant_all:
                connection.execute('INSERT INTO native_lobby_default_pendants VALUES (?,?,?,?) '
                    'ON CONFLICT(player_id,weapon_id) DO UPDATE SET '
                    'pendant_id=excluded.pendant_id,pendant_gid=excluded.pendant_gid',
                    (player_id, receiver, pendant_id, pendant_gid))
                changed_defaults.add(receiver)
            skin_targets = rows if skin_all else current
            pendant_targets = rows if pendant_all else current
            for row in skin_targets:
                connection.execute('INSERT INTO native_lobby_weapon_skins VALUES (?,?,?) '
                    'ON CONFLICT(weapon_gid) DO UPDATE SET skin_id=excluded.skin_id,skin_gid=excluded.skin_gid',
                    (row['gid'], skin_id, skin_gid))
            for row in pendant_targets:
                connection.execute('INSERT INTO native_lobby_weapon_pendants VALUES (?,?,?) '
                    'ON CONFLICT(weapon_gid) DO UPDATE SET '
                    'pendant_id=excluded.pendant_id,pendant_gid=excluded.pendant_gid',
                    (row['gid'], pendant_id, pendant_gid))
            targets = {row['gid']: row for row in skin_targets + pendant_targets}
            for row in targets.values():
                after = backend._container_prop(connection, player_id, row)
                after.setdefault('weapon', {'load_bullets': []}).update(weapon_state(connection, player_id, row))
                loc = inventory_location(after)
                changes.append({'change_type': 3, 'delta': 0, 'src': loc, 'dest': loc,
                    'prop': {'id': after['template_id'], 'gid': after['gid'], 'num': after['quantity'],
                             'position': after['grid_page_id'], 'length': after['length'], 'width': after['width'],
                             'loc': loc, **item_condition_fields(after['template_id'],
                                 components=after.get('components'), weapon=after['weapon'])}})
        defaults = [row for row in setups(connection, player_id) if row['weapon_id'] in changed_defaults]
        connection.commit()
    return {'result': 0, 'data_type': data_type,
            'changes': {'prop_changes': changes, 'weapon_skin_setup': defaults}}


def response_fields(request, backend, token):
    if request.name not in SUPPORTED_REQUESTS:
        return None
    from .core import DomainError
    from .client_errors import inventory_error

    try:
        if request.name == 'CSCollectionLoadMysticalPendantPropsReq':
            page = int(request.fields.get('page') or 0)
            if page < 0:
                from .core import fail
                fail('INVALID_ARGUMENT', 'Invalid pendant collection page')
            owned = [row for row in collection(backend, token) if row['gid']]
            return {'result': 0, 'cur_page': page, 'sum_page': max(1, (len(owned) + 99) // 100),
                    'mystical_pendant_props': owned[page * 100:(page + 1) * 100]}
        return apply(backend, token, request.fields)
    except (ValueError, TypeError):
        result = 14026
    except DomainError as error:
        result = inventory_error(error)
    if request.name == 'CSWAssemblyApplySkinReq':
        return {'result': result, 'data_type': request.fields.get('data_type') or 0}
    return {'result': result}
