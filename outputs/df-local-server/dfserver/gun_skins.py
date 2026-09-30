"""Client-defined skin ownership and equipment for the local test account."""

import json
from pathlib import Path


ROOT = Path(__file__).resolve().parent.parent / 'protocol'
CATALOG = json.loads((ROOT / 'gun_skin_catalog.json').read_text(encoding='utf-8'))
SKINS = {row['skin_id']: row for row in CATALOG['rows']}
ORDINARY = frozenset(skin for skin, row in SKINS.items()
                     if row['open_collection'] and not row['is_mystical'])
PRESETS = {int(k): v for k, v in json.loads(
    (ROOT / 'weapon_preset_catalog.json').read_text(encoding='utf-8'))[
        'default_preset_to_receiver'].items()}


def receiver(item_id):
    return PRESETS.get(item_id, item_id)


def provision(connection, player_id):
    connection.executemany('INSERT OR IGNORE INTO native_lobby_gun_skins '
                           'VALUES (?,?,0,NULL)',
                           ((player_id, skin_id) for skin_id in sorted(ORDINARY)))


def collection(backend, token):
    with backend.connection() as connection:
        connection.execute('BEGIN IMMEDIATE')
        player_id = backend._authorize(connection, token)
        provision(connection, player_id)
        rows = connection.execute('SELECT * FROM native_lobby_gun_skins '
                                  'WHERE player_id=? ORDER BY skin_id,gid', (player_id,)).fetchall()
        connection.commit()
        return [{'id': row['skin_id'], 'gid': row['gid'], 'num': 1,
                 **({'mystical_skin_data': json.loads(row['mystical_json'])}
                    if row['mystical_json'] else {})} for row in rows]


def setups(connection, player_id):
    return [dict(row) for row in connection.execute(
        'SELECT weapon_id,skin_id,skin_gid FROM native_lobby_default_skins '
        'WHERE player_id=? ORDER BY weapon_id', (player_id,))]


def weapon_state(connection, player_id, prop):
    row = connection.execute('SELECT skin_id,skin_gid FROM native_lobby_weapon_skins '
                             'WHERE weapon_gid=?', (prop['gid'],)).fetchone()
    if row is None:
        row = connection.execute('SELECT skin_id,skin_gid FROM native_lobby_default_skins '
                                 'WHERE player_id=? AND weapon_id=?',
                                 (player_id, receiver(prop['template_id']))).fetchone()
    return dict(row) if row is not None else {}


def apply(backend, token, fields):
    from .core import fail
    from .local_commerce import inventory_location, item_condition_fields

    data_type = int(fields.get('data_type') or 0)
    # cs_weaponassembly_pb.lua: SOL=0, ALL=99. Other mode inventories are separate.
    if data_type not in (0, 99) or not 1 <= len(fields.get('cmds', [])) <= 32:
        fail('INVALID_ARGUMENT', 'Unsupported skin command')
    changes, defaults = [], []
    with backend.connection() as connection:
        connection.execute('BEGIN IMMEDIATE')
        player_id = backend._authorize(connection, token)
        provision(connection, player_id)
        backend._ensure_weapon_parts(connection, player_id)
        for command in fields['cmds']:
            weapon_id = int(command.get('weapon_id') or 0)
            weapon_gid = int(command.get('weapon_gid') or 0)
            skin_id = int(command.get('skin_id') or 0)
            skin_gid = int(command.get('skin_gid') or 0)
            if command.get('pendant_id') or command.get('pendant_gid'):
                fail('INVALID_ARGUMENT', 'Pendant ownership has not been recovered')
            if skin_id:
                skin = SKINS.get(skin_id)
                owned = connection.execute('SELECT 1 FROM native_lobby_gun_skins '
                    'WHERE player_id=? AND skin_id=? AND gid=?',
                    (player_id, skin_id, skin_gid)).fetchone()
                if not skin or skin['weapon_id'] != receiver(weapon_id) or not owned:
                    fail('INVALID_EQUIPMENT', 'Skin is not owned for this weapon')
            elif skin_gid:
                fail('INVALID_ARGUMENT', 'Default skin cannot have an instance ID')
            rows = connection.execute('SELECT * FROM native_lobby_props '
                'WHERE player_id=? AND template_id=?', (player_id, weapon_id)).fetchall()
            if weapon_gid:
                selected = [row for row in rows if row['gid'] == weapon_gid]
                if not selected:
                    fail('PROP_NOT_FOUND', 'Weapon instance is not owned')
            else:
                selected = []
            if command.get('apply_all'):
                selected = [row for row in connection.execute(
                    'SELECT * FROM native_lobby_props WHERE player_id=?', (player_id,))
                    if receiver(row['template_id']) == receiver(weapon_id)]
                connection.execute('INSERT INTO native_lobby_default_skins VALUES (?,?,?,?) '
                    'ON CONFLICT(player_id,weapon_id) DO UPDATE SET '
                    'skin_id=excluded.skin_id,skin_gid=excluded.skin_gid',
                    (player_id, receiver(weapon_id), skin_id, skin_gid))
                defaults.append({'weapon_id': receiver(weapon_id),
                                 'skin_id': skin_id, 'skin_gid': skin_gid})
            elif not selected:
                fail('PROP_NOT_FOUND', 'A single-weapon command requires its instance ID')
            for row in selected:
                connection.execute('INSERT INTO native_lobby_weapon_skins VALUES (?,?,?) '
                    'ON CONFLICT(weapon_gid) DO UPDATE SET '
                    'skin_id=excluded.skin_id,skin_gid=excluded.skin_gid',
                    (row['gid'], skin_id, skin_gid))
                after = backend._container_prop(connection, player_id, row)
                loc = inventory_location(after)
                changes.append({'change_type': 3, 'delta': 0, 'src': loc, 'dest': loc,
                    'prop': {'id': after['template_id'], 'gid': after['gid'], 'num': after['quantity'],
                             'position': after['grid_page_id'], 'length': after['length'],
                             'width': after['width'], 'loc': loc,
                             **item_condition_fields(after['template_id'],
                                  components=after.get('components'), weapon=after.get('weapon'))}})
        connection.commit()
    return {'result': 0, 'data_type': data_type,
            'changes': {'prop_changes': changes, 'weapon_skin_setup': defaults}}


def response_fields(request, backend, token):
    if request.name == 'CSWAssemblySkinInfoGetReq':
        return {'result': 0, 'infos': [{'skin_id': row['id'], 'skin_gid': row['gid']}
                                      for row in collection(backend, token)]}
    if request.name == 'CSCollectionLoadMysticalSkinPropsReq':
        owned = [row for row in collection(backend, token) if row['gid']]
        page = int(request.fields.get('page') or 0)
        return {'result': 0, 'cur_page': page, 'sum_page': max(1, (len(owned) + 99) // 100),
                'mystical_skin_props': owned[page * 100:(page + 1) * 100]}
    if request.name == 'CSWAssemblyApplySkinReq':
        from .core import DomainError
        from .client_errors import inventory_error
        try:
            return apply(backend, token, request.fields)
        except (ValueError, TypeError):
            return {'result': 14026, 'data_type': int(request.fields.get('data_type') or 0)}
        except DomainError as error:
            return {'result': inventory_error(error), 'data_type': int(request.fields.get('data_type') or 0)}
    return None
