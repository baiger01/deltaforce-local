"""Installed battle-pass queries and atomic transactions for the local save.

Native C++ reflection independently binds the catalog's serialized fields.
Dates are a persisted local diagnostic window.
"""

import json
from pathlib import Path
import time

from .core import DomainError, fail
from .client_errors import error_code, inventory_error
from . import mandel, premium_shop


PROTOCOL = Path(__file__).resolve().parent.parent / 'protocol'
CATALOG = json.loads((PROTOCOL / 'battle_pass_catalog.json').read_text(encoding='utf-8'))
SEASON_ID = CATALOG['latest_installed_season_id']
SEASON = next(row for row in CATALOG['seasons'] if row['season_id'] == SEASON_ID)
LEVELS = {row['level']: row for row in CATALOG['levels'] if row['season_id'] == SEASON_ID}
PACK = next(row for row in CATALOG['packs'] if row['season_id'] == SEASON_ID)
SUPPORTED_REQUESTS = frozenset({
    'CSBattlePassGetInfoReq', 'CSBattlePassBpGetSeasonIdReq', 'CSBattlePassBpCountryPriceReq',
    'CSBattlePassBuyReq', 'CSBattlePassBuyLevelReq', 'CSBattlePassBuyPackReq',
    'CSBattlePassBuyClueReq', 'CSBattlePassReceiveClueRewardReq',
    'CSBattlePassReceiveArchiveRewardReq', 'CSBattlePassUseExprCardReq',
    'CSBattlePassUseUnlockCardReq',
})
PURCHASE_REQUESTS = frozenset({'CSBattlePassBuyReq', 'CSBattlePassBuyLevelReq', 'CSBattlePassBuyPackReq'})
QUERY_REQUESTS = frozenset({'CSBattlePassGetInfoReq', 'CSBattlePassBpGetSeasonIdReq',
                          'CSBattlePassBpCountryPriceReq'})
SCHEMA = """
CREATE TABLE IF NOT EXISTS native_lobby_battle_pass (
 player_id TEXT NOT NULL REFERENCES players(id), season_id INTEGER NOT NULL,
 level INTEGER NOT NULL CHECK(level BETWEEN 1 AND 180),
 pay_type INTEGER NOT NULL CHECK(pay_type IN (0,2,3,4)),
 curr_expr INTEGER NOT NULL DEFAULT 0, week_expr INTEGER NOT NULL DEFAULT 0,
 bought_packs_json TEXT NOT NULL DEFAULT '[]', c_time INTEGER NOT NULL, m_time INTEGER NOT NULL,
 PRIMARY KEY(player_id,season_id));
CREATE TABLE IF NOT EXISTS native_lobby_battle_pass_grants (
 player_id TEXT NOT NULL REFERENCES players(id), season_id INTEGER NOT NULL,
 level INTEGER NOT NULL, tier TEXT NOT NULL, slot INTEGER NOT NULL,
 item_id INTEGER NOT NULL, quantity INTEGER NOT NULL CHECK(quantity>0),
 PRIMARY KEY(player_id,season_id,level,tier,slot));
"""


def mutations_enabled():
    return (CATALOG['mapping_status'] == 'verified_by_native_reflection_and_serialization'
            and CATALOG.get('mutations_enabled') is True)


def _state(connection, player_id):
    row = connection.execute('SELECT * FROM native_lobby_battle_pass '
        'WHERE player_id=? AND season_id=?', (player_id, SEASON_ID)).fetchone()
    if row is None:
        now = int(time.time())
        connection.execute('INSERT INTO native_lobby_battle_pass '
            '(player_id,season_id,level,pay_type,c_time,m_time) VALUES (?,?,1,0,?,?)',
            (player_id, SEASON_ID, now, now))
        row = connection.execute('SELECT * FROM native_lobby_battle_pass '
            'WHERE player_id=? AND season_id=?', (player_id, SEASON_ID)).fetchone()
    return dict(row)


def info(state):
    start, end = state['c_time'] - 86400, state['c_time'] + 365 * 86400
    bought = json.loads(state['bought_packs_json'])
    return {'has_bought': state['pay_type'] != 0,
        'season_info': {'season_id': SEASON_ID, 'season_name': '', 'start_time': start,
                        'end_time': end, 'svr_switch_end_time': end},
        'main_line': {'level_info': {'curr_level': state['level'],
            'curr_expr': state['curr_expr'], 'level_max_expr': SEASON['level_expr'],
            'week_expr': state['week_expr'], 'week_expr_limit': SEASON['week_expr_limit'],
            'week_start_time': premium_shop.week_start(), 'max_expr_limit': SEASON['max_expr_limit']},
            'in_bonus_time': False, 'bonus_rate': 1.0, 'bonus_start_time': 0, 'bonus_end_time': 0},
        'archives': [], 'pack': {'valid_time': start <= int(time.time()) < end,
            'pack_id': PACK['pack_id'], 'has_bought': PACK['pack_id'] in bought,
            'start_time': start, 'end_time': end, 'level': PACK['level'],
            'bought_pack_list': bought},
        'm_time': state['m_time'], 'c_time': state['c_time'],
        'type': state['pay_type'], 'previous_season_type': 0, 'traces': []}


def prices():
    result = {'result': 0}
    for category in ('level', 'sol', 'mp', 'universal'):
        result[category + '_price'] = SEASON[category + '_price']
        result[category + '_original_price'] = SEASON[category + '_price']
    result.update(pack_price=PACK['price'], pack_original_price=PACK['original_price'])
    return result


def _charge(connection, player_id, fields, expected, changes):
    bound = int(fields.get('binded_delta_coin') or 0)
    unbound = int(fields.get('unbinded_delta_coin') or 0)
    if min(bound, unbound) < 0 or bound + unbound != expected or expected <= 0:
        fail('BattlePassInvalidPrice', 'Quote does not match the selected local battle-pass offer')
    for currency, amount in ((17888808889, bound), (17888808888, unbound)):
        if amount:
            changes['currency_changes'].append(
                premium_shop.currency_change(connection, player_id, currency, -amount))


def _warehouse_grant(backend, connection, player_id, item, metadata, changes):
    length, width = metadata['length'], metadata['width']
    stack_limit = metadata['max_stack_count']
    if not 1 <= length <= 9 or not 1 <= width <= 40 or not 1 <= stack_limit <= 1000:
        fail('BattlePassPropFailed', 'Warehouse reward layout has not been recovered')
    occupied = set()
    for row in connection.execute('SELECT x,y,length,width FROM native_lobby_props '
            'WHERE player_id=? AND grid_page_id=2', (player_id,)):
        occupied.update((x, y) for x in range(row['x'], row['x'] + row['length'])
                        for y in range(row['y'], row['y'] + row['width']))
    remaining = item['num']
    while remaining:
        position = next(((x, y) for y in range(41 - width) for x in range(10 - length)
            if all((cx, cy) not in occupied for cx in range(x, x + length)
                   for cy in range(y, y + width))), None)
        if position is None:
            fail('WAREHOUSE_FULL', 'No warehouse space for the battle-pass reward')
        x, y = position
        occupied.update((cx, cy) for cx in range(x, x + length) for cy in range(y, y + width))
        count = min(remaining, stack_limit)
        gid = backend._next_native_prop_gid(connection)
        if gid >= 2**63 - 1:
            fail('BattlePassPropFailed', 'Local prop identifier range exhausted')
        connection.execute('INSERT INTO native_lobby_props VALUES (?,?,?,?,?,?,?,?,?)',
            (gid, player_id, item['id'], count, 2, x, y, length, width))
        backend._ensure_weapon_parts(connection, player_id)
        loc = {'pos': 2, 'start_x': x, 'start_y': y, 'x': length,
               'y': width, 'space_id': 0, 'rotate': False}
        from .local_commerce import item_condition_fields
        state = backend._container_prop(connection, player_id, {
            'gid': gid, 'template_id': item['id'], 'quantity': count, 'grid_page_id': 2,
            'x': x, 'y': y, 'length': length, 'width': width})
        changes['deposit_changes'].append({'change_type': 1, 'delta': count, 'dest': loc,
            'prop': {'id': item['id'], 'gid': gid, 'num': count, 'position': 2,
                     'length': length, 'width': width, 'loc': loc,
                     **item_condition_fields(item['id'], components=state.get('components'),
                                             weapon=state.get('weapon'))}})
        remaining -= count


def _grant_rewards(backend, connection, player_id, state, changes):
    from .weapon_pendants import PENDANTS
    tiers = ['free']
    if state['pay_type']:
        tiers.append('universal')
    if state['pay_type'] in (2, 4):
        tiers.append('sol')
    if state['pay_type'] in (3, 4):
        tiers.append('mp')
    for level in range(1, state['level'] + 1):
        for tier in tiers:
            for item in LEVELS[level]['rewards'][tier]:
                inserted = connection.execute('INSERT OR IGNORE INTO native_lobby_battle_pass_grants '
                    'VALUES (?,?,?,?,?,?,?)', (player_id, SEASON_ID, level, tier, item['slot'],
                                             item['id'], item['num'])).rowcount
                if not inserted:
                    continue
                metadata = premium_shop.ITEMS.get(str(item['id']))
                if metadata is None:
                    fail('BattlePassPropFailed', 'Battle-pass reward metadata is unavailable')
                if (metadata.get('length') and not metadata.get('is_currency')
                        and item['id'] not in mandel.BRICKS and item['id'] not in PENDANTS):
                    _warehouse_grant(backend, connection, player_id, item, metadata, changes)
                else:
                    change = {'currency_changes': [], 'prop_changes': []}
                    premium_shop.grant(connection, player_id, [item], change)
                    changes['currency_changes'].extend(change['currency_changes'])
                    changes['collection_changes'].extend(change['prop_changes'])


def _purchase(backend, connection, player_id, state, name, fields, changes):
    if not mutations_enabled():
        fail('BattlePassInvalidReqParams', 'Battle-pass price and reward associations are not independently verified')
    if int(time.time()) >= state['c_time'] + 365 * 86400:
        fail('BattlePassInvalidSeason', 'The persisted local diagnostic season has ended')
    if name == 'CSBattlePassBuyReq':
        pay_type, previous = int(fields.get('buy_type') or 0), state['pay_type']
        if pay_type not in (2, 3, 4):
            fail('BattlePassInvalidReqParams', 'Unsupported installed battle-pass membership')
        if previous == pay_type or previous == 4:
            fail('BattlePassRepeatPurchase', 'This battle-pass membership is already owned')
        if previous and (previous not in (2, 3) or pay_type != 4):
            fail('BattlePassInvalidReqParams', 'Only the native universal upgrade is supported')
        key = {2: 'sol_price', 3: 'mp_price', 4: 'universal_price'}
        cost = SEASON[key[pay_type]] - (SEASON[key[previous]] if previous else 0)
        _charge(connection, player_id, fields, cost, changes)
        state['pay_type'] = pay_type
    else:
        if name == 'CSBattlePassBuyPackReq':
            pack_id = int(fields.get('pack_id') or 0)
            if pack_id != PACK['pack_id']:
                fail('BattlePassPackIsNull', 'Pack is not part of the selected installed season')
            bought = json.loads(state['bought_packs_json'])
            if pack_id in bought:
                fail('BattlePassPackRepeatPurchase', 'The battle-pass pack was already purchased')
            increment, cost = PACK['level'], PACK['price']
        else:
            increment = int(fields.get('level') or 0)
            cost = increment * SEASON['level_price']
        if increment <= 0 or state['level'] + increment > max(LEVELS):
            fail('BattlePassMaxExprLimit', 'Requested levels exceed the installed reward table')
        _charge(connection, player_id, fields, cost, changes)
        state['level'] += increment
        if name == 'CSBattlePassBuyPackReq':
            state['bought_packs_json'] = json.dumps([*bought, pack_id])
    _grant_rewards(backend, connection, player_id, state, changes)
    state['m_time'] = int(time.time())
    connection.execute('UPDATE native_lobby_battle_pass SET level=?,pay_type=?,bought_packs_json=?,m_time=? '
        'WHERE player_id=? AND season_id=?', (state['level'], state['pay_type'],
         state['bought_packs_json'], state['m_time'], player_id, SEASON_ID))


def response_fields(request, backend, token, *, changes=None):
    """Return native fields; expose committed notification changes separately."""
    name, fields = request.name, request.fields
    if name not in SUPPORTED_REQUESTS:
        return None
    try:
        if name == 'CSBattlePassGetInfoReq' and int(fields.get('get_info_type') or 0) not in (0, 1):
            fail('BattlePassInvalidReqParams', 'Unrecognized native battle-pass query type')
        if name not in QUERY_REQUESTS and name not in PURCHASE_REQUESTS:
            fail('BattlePassInvalidReqParams', 'Current-season clue or card configuration is not recovered')
        committed = {'currency_changes': [], 'collection_changes': [], 'deposit_changes': []}
        with backend.connection() as connection:
            connection.execute('BEGIN IMMEDIATE')
            player_id = backend._authorize(connection, token)
            state = _state(connection, player_id)
            if name in PURCHASE_REQUESTS:
                _purchase(backend, connection, player_id, state, name, fields, committed)
                result = {'result': 0, 'info': info(state)}
            elif name == 'CSBattlePassGetInfoReq':
                result = {'result': 0, 'info': info(state), 'season_id': SEASON_ID}
            elif name == 'CSBattlePassBpGetSeasonIdReq':
                result = {'result': 0, 'season_id': SEASON_ID}
            else:
                result = prices()
            connection.commit()
        if changes is not None and name in PURCHASE_REQUESTS:
            changes.update(committed)
        return result
    except (ValueError, TypeError):
        return {'result': error_code('BattlePassInvalidReqParams')}
    except DomainError as error:
        return {'result': error_code(error.code) if error.code.startswith('BattlePass') else inventory_error(error)}
