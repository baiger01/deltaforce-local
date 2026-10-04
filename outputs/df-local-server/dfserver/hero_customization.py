"""Native Hero cosmetic catalog, grant ownership, and saved selections."""

import json
from pathlib import Path

from .client_errors import error_code


CATALOG = json.loads((Path(__file__).resolve().parent.parent /
    'protocol/hero_customization_catalog.json').read_text(encoding='utf-8'))
FASHIONS = {row['id']: row for row in CATALOG['fashions']}
ACCESSORIES = {row['id']: row for row in CATALOG['accessories']}
BASES = {row['hero_id']: row['id'] for row in FASHIONS.values() if row['default_equip']}
SUPPORTED_REQUESTS = frozenset({
    'CSHeroLoadHeroListReq', 'CSHeroGetHeroIDListReq', 'CSHeroGetSelectedHeroReq',
    'CSHeroEquipFashionReq', 'CSHeroSelectAccessoryReq',
    'CSHeroChangeAccessoryReadStatReq', 'CSHeroChangeAccessoryPlayStatReq',
    'CSHeroChangeFashionPriorReq', 'CSHeroGetBadgeShowReq', 'CSHeroSetBadgeShowReq',
    'CSHeroGrowLineRewardViewReq'})


def affected_heroes(item_id):
    item_id = int(item_id)
    if item_id in FASHIONS:
        return (FASHIONS[item_id]['hero_id'],)
    row = ACCESSORIES.get(item_id)
    if not row:
        return ()
    return tuple(sorted(BASES if 0 in row['hero_ids'] else set(row['hero_ids']) & set(BASES)))


def _owned(connection, player_id):
    return {row['template_id'] for row in connection.execute(
        'SELECT template_id FROM native_lobby_collection_props WHERE player_id=? AND quantity>0',
        (player_id,))}


def _unlocked(row, owned):
    return bool(row['default_unlock'] or row['default_equip'] or row['id'] in owned)


def hero_record(connection, player_id, hero_id, bases=None):
    bases = BASES if bases is None else bases
    hero_id = int(hero_id)
    if hero_id not in bases:
        raise ValueError('Unknown native Hero')
    base = bases[hero_id]
    owned = _owned(connection, player_id)
    state = {r['prop_id']: r for r in connection.execute(
        'SELECT prop_id,is_read,is_play FROM native_lobby_hero_cosmetic_state WHERE player_id=?', (player_id,))}
    rows = sorted((r for r in FASHIONS.values() if r['hero_id'] == hero_id),
                  key=lambda r: (r['id'] != base, r['id']))
    fashion_list = [{'fashion': {'slot': r['slot'], 'id': r['id']},
        'is_unlock': _unlocked(r, owned), 'is_def': bool(r['default_equip']),
        'is_read': bool(state[r['id']]['is_read']) if r['id'] in state else bool(r['default_unlock']),
        'is_play': bool(state[r['id']]['is_play']) if r['id'] in state else False} for r in rows]
    if not any(r['fashion']['id'] == base for r in fashion_list):
        raise ValueError('Base fashion has no native catalog evidence')
    saved = connection.execute('SELECT fashion_id FROM native_lobby_hero_fashions '
                               'WHERE player_id=? AND hero_id=?', (player_id, hero_id)).fetchone()
    unlocked = {r['fashion']['id'] for r in fashion_list if r['is_unlock']}
    selected_fashion = saved['fashion_id'] if saved and saved['fashion_id'] in unlocked else base
    equipment = {(r['subtype'], r['slot']): r['prop_id'] for r in connection.execute(
        'SELECT subtype,slot,prop_id FROM native_lobby_hero_accessory_equipment '
        'WHERE player_id=? AND hero_id=?', (player_id, hero_id))}
    applicable = [r for r in ACCESSORIES.values() if hero_id in r['hero_ids'] or 0 in r['hero_ids']]
    accessories = []
    for row in applicable:
        item_id, subtype = row['id'], row['subtype']
        unlocked = _unlocked(row, owned)
        selected_slots = [slot for (kind, slot), prop_id in equipment.items() if kind == subtype and prop_id == item_id]
        has_override = any(kind == subtype or subtype in range(2, 6) and kind in range(2, 6) and slot == 0
                           for kind, slot in equipment)
        selected = bool(unlocked and (selected_slots or row['default_equip'] and not has_override))
        if row.get('fashion_ids') and 0 not in row['fashion_ids'] and selected_fashion not in row['fashion_ids']:
            selected = False
        accessories.append({'item': {'prop_id': item_id, 'slot': selected_slots[0] if selected_slots else 0,
                                      'unlock_time': 0, 'card_level': 0},
            'is_unlock': unlocked, 'is_selected': selected,
            'is_read': bool(state[item_id]['is_read']) if item_id in state else bool(row['default_unlock']),
            'is_play': bool(state[item_id]['is_play']) if item_id in state else False,
            'unlocked_timestamp': 0})
    return {'hero_id': hero_id, 'is_unlock': True, 'can_use': True, 'is_blast_unlock': True,
            'fashion_list': fashion_list, 'fashion_equipped': [{'slot': 0, 'id': selected_fashion}],
            'accessories': accessories}


def hero_records(backend, token, hero_ids=None, bases=None):
    bases = BASES if bases is None else bases
    ids = sorted(bases) if hero_ids is None else list(dict.fromkeys(int(i) for i in hero_ids))
    with backend.connection() as connection:
        player_id = backend._authorize(connection, token)
        return [hero_record(connection, player_id, hero_id, bases) for hero_id in ids if hero_id in bases]


def equip_hero(backend, token, hero_id, new_fashions, bases=None):
    bases = BASES if bases is None else bases
    hero_id = int(hero_id)
    if hero_id not in bases:
        return {'result': error_code('HeroUnknownHeroId')}
    # Native HeroFashion requests omit the default FashionSuit slot (0).
    if len(new_fashions) != 1 or int(new_fashions[0].get('slot', 0)) != 0:
        return {'result': error_code('HeroSkinPositionInvaild')}
    fashion_id = int(new_fashions[0].get('id', 0))
    row = FASHIONS.get(fashion_id)
    if row is None or row['hero_id'] != hero_id:
        return {'result': error_code('HeroSkinInvaild')}
    with backend.connection() as connection:
        connection.execute('BEGIN IMMEDIATE')
        player_id = backend._authorize(connection, token)
        if not _unlocked(row, _owned(connection, player_id)):
            return {'result': error_code('HeroSkinNotExist')}
        connection.execute('INSERT INTO native_lobby_hero_fashions VALUES (?,?,?) '
            'ON CONFLICT(player_id,hero_id) DO UPDATE SET fashion_id=excluded.fashion_id',
            (player_id, hero_id, fashion_id))
        target = hero_record(connection, player_id, hero_id, bases)
        connection.commit()
    return {'result': 0, 'target_hero': target}


def select_accessory(backend, token, fields):
    hero_id = int(fields.get('hero_id') or 0)
    item = fields.get('accessory_item') or {}
    item_id, slot = int(item.get('prop_id') or 0), int(item.get('slot') or 0)
    row = ACCESSORIES.get(item_id)
    if hero_id not in BASES:
        return {'result': error_code('HeroUnknownHeroId')}
    if row is None:
        return {'result': error_code('HeroAccessoryIllegal')}
    if hero_id not in row['hero_ids'] and 0 not in row['hero_ids']:
        return {'result': error_code('HeroAccessoryHeroNotMatch')}
    if slot < 0 or row['subtype'] not in range(2, 6) and slot != 0:
        return {'result': error_code('HeroAccessorySlotNotEnought')}
    with backend.connection() as connection:
        connection.execute('BEGIN IMMEDIATE')
        player_id = backend._authorize(connection, token)
        if not _unlocked(row, _owned(connection, player_id)):
            return {'result': error_code('HeroAccessoryNotUnlock')}
        if not fields.get('is_unequip') and row.get('fashion_ids') and 0 not in row['fashion_ids']:
            fashion = hero_record(connection, player_id, hero_id)['fashion_equipped'][0]['id']
            if fashion not in row['fashion_ids']:
                return {'result': error_code('HeroAccessoryIllegal')}
        if fields.get('is_unequip'):
            current = connection.execute('SELECT prop_id FROM native_lobby_hero_accessory_equipment '
                'WHERE player_id=? AND hero_id=? AND subtype=? AND slot=?',
                (player_id, hero_id, row['subtype'], slot)).fetchone()
            if current is not None:
                selected = current['prop_id'] == item_id
            else:
                selected = any(r['item']['prop_id'] == item_id and r['item']['slot'] == slot
                    and r['is_selected'] for r in hero_record(connection, player_id, hero_id)['accessories'])
            if not selected:
                return {'result': error_code('HeroAccessoryIllegal')}
            # A tombstone suppresses the configured default after explicit removal.
            connection.execute('INSERT INTO native_lobby_hero_accessory_equipment VALUES (?,?,?,?,0) '
                'ON CONFLICT(player_id,hero_id,subtype,slot) DO UPDATE SET prop_id=0',
                (player_id, hero_id, row['subtype'], slot))
        else:
            if row['subtype'] in range(2, 6):
                connection.execute('DELETE FROM native_lobby_hero_accessory_equipment '
                    'WHERE player_id=? AND hero_id=? AND slot=? AND subtype BETWEEN 2 AND 5',
                    (player_id, hero_id, slot))
            connection.execute('DELETE FROM native_lobby_hero_accessory_equipment '
                'WHERE player_id=? AND hero_id=? AND prop_id=?', (player_id, hero_id, item_id))
            connection.execute('INSERT INTO native_lobby_hero_accessory_equipment VALUES (?,?,?,?,?) '
                'ON CONFLICT(player_id,hero_id,subtype,slot) DO UPDATE SET prop_id=excluded.prop_id',
                (player_id, hero_id, row['subtype'], slot, item_id))
        target = hero_record(connection, player_id, hero_id)
        connection.commit()
    return {'result': 0, 'target_hero': target}


def _mark(backend, token, fields, column):
    ids = list(dict.fromkeys(int(i) for i in fields.get('prop_ids', [])))
    if fields.get('prop_id') and int(fields['prop_id']) not in ids:
        ids.insert(0, int(fields['prop_id']))
    success, failed = [], []
    with backend.connection() as connection:
        connection.execute('BEGIN IMMEDIATE')
        player_id = backend._authorize(connection, token)
        owned = _owned(connection, player_id)
        for item_id in ids:
            row = ACCESSORIES.get(item_id) or FASHIONS.get(item_id)
            if not row or not _unlocked(row, owned):
                failed.append(item_id)
                continue
            connection.execute(f'INSERT INTO native_lobby_hero_cosmetic_state (player_id,prop_id,{column}) '
                f'VALUES (?,?,1) ON CONFLICT(player_id,prop_id) DO UPDATE SET {column}=1', (player_id, item_id))
            success.append(item_id)
        connection.commit()
    return {'result': 0, 'succ_prop_ids': success, 'failed_prop_ids': failed}


def _badge_show(backend, token, fields, write=False):
    if not write and fields.get('player_id') and int(fields['player_id']) != backend.native_identity(token)['native_id']:
        return {'result': error_code('HeroUnknownHeroId'), 'badges': []}
    with backend.connection() as connection:
        player_id = backend._authorize(connection, token)
        if write:
            badge = fields.get('badge') or {}
            item_id, slot = int(badge.get('prop_id') or 0), int(badge.get('slot') or 0)
            row = ACCESSORIES.get(item_id)
            if slot < 0 or item_id and (not row or row['subtype'] != 8):
                return {'result': error_code('HeroAccessoryIllegal'), 'badges': []}
            if item_id and not _unlocked(row, _owned(connection, player_id)):
                return {'result': error_code('HeroAccessoryNotUnlock'), 'badges': []}
            connection.execute('DELETE FROM native_lobby_hero_badge_show WHERE player_id=? AND (slot=? OR prop_id=?)',
                               (player_id, slot, item_id))
            if item_id:
                connection.execute('INSERT INTO native_lobby_hero_badge_show VALUES (?,?,?)', (player_id, slot, item_id))
            connection.commit()
        owned = _owned(connection, player_id)
        badges = [{'prop_id': r['prop_id'], 'slot': r['slot']} for r in connection.execute(
            'SELECT prop_id,slot FROM native_lobby_hero_badge_show WHERE player_id=? ORDER BY slot', (player_id,))
            if r['prop_id'] in ACCESSORIES and _unlocked(ACCESSORIES[r['prop_id']], owned)]
    return {'result': 0, 'badges': badges}


def _prior(backend, token, fields):
    mode = int(fields.get('mode') or 0)
    # HeroServer.lua 0.73 constructs this request with literal mode 1. Its
    # SOL counterpart 0.72 is empty; other numeric modes have no recovered path.
    if mode != 1:
        return {'result': error_code('HeroFashionPriorityChangeBan'), 'mode': mode}
    rows = fields.get('prior_settings', [])
    with backend.connection() as connection:
        player_id = backend._authorize(connection, token)
        connection.execute('INSERT INTO native_lobby_hero_fashion_prior VALUES (?,?,0,?) '
            'ON CONFLICT(player_id,mode,category) DO UPDATE SET is_fashion_prior=excluded.is_fashion_prior',
            (player_id, mode, bool(fields.get('is_fashion_prior'))))
        for row in rows:
            connection.execute('INSERT INTO native_lobby_hero_fashion_prior VALUES (?,?,?,?) '
                'ON CONFLICT(player_id,mode,category) DO UPDATE SET is_fashion_prior=excluded.is_fashion_prior',
                (player_id, mode, int(row['category']), bool(row.get('is_fashion_prior'))))
        connection.commit()
    return {'result': 0, 'mode': mode, 'is_fashion_prior': bool(fields.get('is_fashion_prior')),
            'prior_settings': rows}


def load_fields(backend, token, hero_ids=None, *, request_fields=None):
    fields = request_fields or {}
    roster_ids = sorted(BASES) if hero_ids is None else list(hero_ids)
    detail_ids = roster_ids
    if fields.get('filter_by_id'):
        requested = {int(i) for i in fields.get('hero_id_list', [])}
        detail_ids = [i for i in roster_ids if i in requested]
    profile = backend.native_lobby_profile(token)
    selected = profile['selected_hero_id'] or 88000000025
    if selected not in BASES:
        selected = 88000000025
    selected_mp = profile.get('selected_mp_hero_id') or selected
    if selected_mp not in BASES:
        selected_mp = selected
    with backend.connection() as connection:
        player_id = backend._authorize(connection, token)
        priors = list(connection.execute('SELECT mode,category,is_fashion_prior '
            'FROM native_lobby_hero_fashion_prior WHERE player_id=? ORDER BY mode,category', (player_id,)))
    # The native lobby displays the saved suit directly; these explicit show
    # flags are the local account preference rather than an ownership signal.
    # HeroServer.lua 0.19.0 replaces its entire roster with hero_ids and prunes
    # cached fashions; filtering applies only to the requested hero details.
    return {'result': 0, 'hero_ids': roster_ids, 'heros': hero_records(backend, token, detail_ids),
        'mp_hero_selected': selected_mp, 'sol_hero_selected': selected, 'blast_hero_selected': selected,
        'is_fashion_show_sol': True, 'is_fashion_show_mp': True,
        'prior_settings': [{'category': r['category'], 'is_fashion_prior': bool(r['is_fashion_prior'])}
                           for r in priors if r['mode'] == 1 and r['category'] != 0]}


def response_fields(request, backend, token):
    name, fields = request.name, request.fields
    if name == 'CSHeroLoadHeroListReq':
        return load_fields(backend, token, request_fields=fields)
    if name == 'CSHeroGetHeroIDListReq':
        return {'result': 0, 'hero_ids': sorted(BASES)}
    if name == 'CSHeroGrowLineRewardViewReq':
        with backend.connection() as connection:
            backend._authorize(connection, token)
        hero_id = int(fields.get('hero_id', 0))
        if hero_id not in BASES:
            return {'result': error_code('HeroUnknownHeroId')}
        # HeroServer caches this preview separately from progression and grants.
        # Native growth reward configuration has not been recovered locally.
        return {'result': 0, 'hero_id': hero_id, 'rewards': []}
    if name == 'CSHeroEquipFashionReq':
        return equip_hero(backend, token, fields.get('hero_id', 0), fields.get('new_fashions', []))
    if name == 'CSHeroSelectAccessoryReq':
        return select_accessory(backend, token, fields)
    if name == 'CSHeroChangeAccessoryReadStatReq':
        return _mark(backend, token, fields, 'is_read')
    if name == 'CSHeroChangeAccessoryPlayStatReq':
        return _mark(backend, token, fields, 'is_play')
    if name == 'CSHeroGetBadgeShowReq':
        return _badge_show(backend, token, fields)
    if name == 'CSHeroSetBadgeShowReq':
        return _badge_show(backend, token, fields, True)
    if name == 'CSHeroChangeFashionPriorReq':
        return _prior(backend, token, fields)
    if name == 'CSHeroGetSelectedHeroReq':
        if fields.get('player_id') and int(fields['player_id']) != backend.native_identity(token)['native_id']:
            return {'result': error_code('HeroUnknownHeroId')}
        selected = load_fields(backend, token)['sol_hero_selected']
        return {'result': 0, 'hero_selected': hero_records(backend, token, [selected])[0],
                'mode': fields.get('mode', 0), 'reborn_boss_type': fields.get('reborn_boss_type', 0)}
    return None
