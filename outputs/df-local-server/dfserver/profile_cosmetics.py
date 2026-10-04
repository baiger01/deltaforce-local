"""Installed account cosmetic ownership, selection and profile persistence."""

import json
from pathlib import Path

from .client_errors import error_code


PROTOCOL = Path(__file__).resolve().parent.parent / 'protocol'
CATALOG = json.loads((PROTOCOL / 'profile_cosmetics_catalog.json').read_text(encoding='utf-8'))
SOCIAL_ITEMS = {row['item_id']: row['social_type'] for row in CATALOG['rows']}
SCHEMA = """
CREATE TABLE IF NOT EXISTS native_lobby_profile_cosmetics (
 player_id TEXT PRIMARY KEY REFERENCES players(id),
 avatar_id INTEGER NOT NULL DEFAULT 0,
 military_tag INTEGER NOT NULL DEFAULT 0,
 title INTEGER NOT NULL DEFAULT 0,
 honor_mark INTEGER NOT NULL DEFAULT 0);
"""
SELECTIONS = {
    'CSAccountUpdateAvatarReq': ('avatar_id', 1, 'AccountAvatar'),
    'CSPlayerUpdateMilitaryTagReq': ('military_tag', 2, 'PlayerInfoMilitaryTag'),
    'CSPlayerUpdateTitleReq': ('title', 3, 'PlayerInfoTitle'),
    'CSPlayerUpdateHonorMarkReq': ('honor_mark', 4, 'PlayerInfoHonorMark'),
}
SUPPORTED_REQUESTS = frozenset((*SELECTIONS, 'CSCollectionUnlockAvatarsReq'))


def owned_items(connection, player_id):
    return {row['template_id']: row['quantity'] for row in connection.execute(
        'SELECT template_id,quantity FROM native_lobby_collection_props '
        'WHERE player_id=? ORDER BY template_id', (player_id,))
        if row['template_id'] in SOCIAL_ITEMS}


def profile_fields(backend, token):
    with backend.connection() as connection:
        player_id = backend._authorize(connection, token)
        row = connection.execute('SELECT avatar_id,military_tag,title,honor_mark '
            'FROM native_lobby_profile_cosmetics WHERE player_id=?', (player_id,)).fetchone()
        selected = dict(row) if row is not None else dict.fromkeys(
            ('avatar_id', 'military_tag', 'title', 'honor_mark'), 0)
        owned = owned_items(connection, player_id)
        for field, kind, _ in SELECTIONS.values():
            if selected[field] and (selected[field] not in owned or
                                    SOCIAL_ITEMS.get(selected[field]) != kind):
                selected[field] = 0
    avatar_id = selected.pop('avatar_id')
    return {'pic_url': str(avatar_id) if avatar_id else '', **selected}


def basic_info_fields(backend, token):
    fields = profile_fields(backend, token)
    return {key: fields[key] for key in ('pic_url', 'military_tag', 'title')}


def unlocks(backend, token):
    with backend.connection() as connection:
        player_id = backend._authorize(connection, token)
        props = [{'id': item_id, 'gid': 0, 'num': quantity}
                 for item_id, quantity in owned_items(connection, player_id).items()]
    return {'result': 0, 'props': props, 'redpoint_list': [], 'limit_social_props': [],
            'show_time_info': [], 'rank_title_info': [], 'roll_bp_title_info': []}


def select(backend, token, name, fields):
    field, kind, error_prefix = SELECTIONS[name]
    try:
        item_id = int(fields.get(field) or 0)
    except (ValueError, TypeError):
        return {'result': error_code(error_prefix + 'NotUnlock')}
    with backend.connection() as connection:
        connection.execute('BEGIN IMMEDIATE')
        player_id = backend._authorize(connection, token)
        owned = owned_items(connection, player_id)
        if item_id and (SOCIAL_ITEMS.get(item_id) != kind or item_id not in owned):
            return {'result': error_code(error_prefix + 'NotUnlock')}
        row = connection.execute(f'SELECT {field} FROM native_lobby_profile_cosmetics '
                                 'WHERE player_id=?', (player_id,)).fetchone()
        if row is not None and row[field] == item_id:
            return {'result': error_code(error_prefix + 'AlreadyEquip')}
        connection.execute(f'INSERT INTO native_lobby_profile_cosmetics (player_id,{field}) '
            f'VALUES (?,?) ON CONFLICT(player_id) DO UPDATE SET {field}=excluded.{field}',
            (player_id, item_id))
        connection.commit()
    return {'result': 0}


def response_fields(request, backend, token):
    if request.name == 'CSCollectionUnlockAvatarsReq':
        return unlocks(backend, token)
    if request.name in SELECTIONS:
        return select(backend, token, request.name, request.fields)
    return None
