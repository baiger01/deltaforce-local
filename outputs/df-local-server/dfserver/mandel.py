"""Mandel item and prize-pool links recovered from the installed client."""

import json
from pathlib import Path
import struct
import secrets
import time

from . import gun_skins


CATALOG = json.loads((Path(__file__).resolve().parent.parent /
                     'protocol/mandel_box_catalog.json').read_text(encoding='utf-8'))
BRICKS = {row['item_id']: row for row in CATALOG['bricks']}
BOXES = {row['fields']['470']: row['fields'] for row in CATALOG['boxes']}
GROUPS = {}
REWARDS = {}
for row in CATALOG['groups']:
    GROUPS.setdefault(row['fields']['563'], []).append(row['fields'])
for row in CATALOG['rewards']:
    REWARDS.setdefault(row['fields']['3973'], []).append(row['fields'])


def migrate_keys(connection, player_id=None):
    # MandelDrawOnly.lua 0.5 reads GetCollectionPropById(GetKeyID()), not a currency balance.
    for key_id in {row['key_id'] for row in CATALOG['store_lotteries']}:
        scope = ' AND player_id=?' if player_id is not None else ''
        values = (key_id, player_id) if player_id is not None else (key_id,)
        connection.execute('INSERT INTO native_lobby_collection_props(player_id,template_id,quantity) '
            'SELECT player_id,currency_id,amount FROM native_lobby_currencies '
            'WHERE currency_id=? AND amount>0' + scope + ' '
            'ON CONFLICT(player_id,template_id) DO UPDATE SET quantity=quantity+excluded.quantity', values)
        connection.execute('DELETE FROM native_lobby_currencies WHERE currency_id=?' + scope, values)


def float_bits(value):
    return struct.unpack('<f', struct.pack('<I', value))[0]


def shop_config():
    now = int(time.time())
    return {'result': 0,
            'lottery_item_descs': [
                {'lottery_id': row['lottery_id'], 'lottery_type': row['lottery_type'],
                 'mandel_item_id': str(row['item_id']), 'lottery_key_id': row['key_id'],
                 'begin_time': now - 86400, 'end_time': now + 365 * 86400}
                for row in CATALOG['store_lotteries']],
            'special_item_list': [
                {key: row[key] for key in ('present_item_id', 'currency_type', 'price',
                                           'buy_item_id', 'present_num')}
                for row in CATALOG['key_offers']]}


def eligible_groups(box_id, owned=()):
    groups = []
    for group in GROUPS.get(box_id, []):
        prizes = [row for row in REWARDS.get(group['570'], [])
                  if row['3967'] and row['3982'] in gun_skins.SKINS
                  and (gun_skins.SKINS[row['3982']]['is_mystical'] or row['3982'] not in owned)]
        if group['562'] and group['577'] > 0 and prizes:
            groups.append((group, prizes))
    return groups


def box_info(box_id, owned=(), open_count=0, since_core=0):
    box = BOXES.get(box_id)
    if box is None or box_id not in {row['box_id'] for row in BRICKS.values()}:
        return None
    groups = []
    eligible = {group['570']: prizes for group, prizes in eligible_groups(box_id, owned)}
    total = sum(group['577'] for group in GROUPS.get(box_id, []) if group['570'] in eligible)
    forced = next((group['570'] for group in GROUPS.get(box_id, [])
                   if group['570'] in eligible and group['567'] and group['582']
                   and since_core + 1 >= group['582']), None)
    for group in GROUPS.get(box_id, []):
        active = eligible.get(group['570'], [])
        group_probability = group['577'] / total if active and total else 0
        if forced is not None:
            group_probability = int(group['570'] == forced)
        prizes = []
        for row in REWARDS.get(group['570'], []):
            prop = {'id': row['3982'], 'gid': 0, 'num': row['3977']}
            prizes.append({'prop_id': prop['id'], 'num': prop['num'],
                           'num_id': row['3978'], 'active_flag': bool(row['3967']),
                           'restore_flag': bool(row['3983']), 'prop_info': prop,
                           'real_prob': group_probability / len(active) if row in active else 0,
                           'prob_showed': float_bits(row['3981'])})
        groups.append({'group_id': group['570'], 'active_flag': bool(group['562']),
                       'indep_prob': group['571'], 'prob': group['577'],
                       'restore_flag': bool(group['578']), 'core_flag': bool(group['567']),
                       'real_prob': group_probability,
                       'time_assured': max(1, group['582'] - since_core) if group['582'] else 0,
                       'prop_list': prizes})
    return {'box_id': box_id, 'type': box['489'], 'show_id1': box['485'],
            'show_id2': box['486'], 'group_list': groups, 'open_count': open_count}


def box_response(backend, token, fields):
    with backend.connection() as connection:
        player_id = backend._authorize(connection, token)
        owned = {row[0] for row in connection.execute(
            'SELECT skin_id FROM native_lobby_gun_skins WHERE player_id=? AND gid=0', (player_id,))}
        infos = []
        for value in fields.get('id_list', []):
            box_id = int(value)
            state = connection.execute('SELECT open_count,since_core FROM native_lobby_lottery_state '
                'WHERE player_id=? AND box_id=?', (player_id, box_id)).fetchone()
            info = box_info(box_id, owned, *(state if state else (0, 0)))
            if info:
                infos.append(info)
        records = [json.loads(row[0]) for row in connection.execute(
            'SELECT record_json FROM native_lobby_lottery_history WHERE player_id=? '
            'ORDER BY id DESC LIMIT 100', (player_id,))]
    return {'result': 0, 'info_list': infos, 'open_lottery_records': records}


def draw(backend, token, fields):
    from .core import fail

    boxes = fields.get('box_list') or []
    if len(boxes) != 1:
        fail('INVALID_ARGUMENT', 'Expected one client Mandel box')
    item = boxes[0]
    box_id, brick_id = int(item.get('box_id') or 0), int(item.get('opened_prop_id') or 0)
    count = int(item.get('num') or 0)
    brick = BRICKS.get(brick_id)
    store = next((row for row in CATALOG['store_lotteries'] if row['item_id'] == brick_id), None)
    if (not brick or not store or brick['box_id'] != box_id or not 1 <= count <= 10
            or int(item.get('opened_prop_num') or 0) != count
            or int(item.get('opened_prop_gid') or 0)):
        fail('INVALID_ARGUMENT', 'Draw does not match the client brick and box')
    with backend.connection() as connection:
        connection.execute('BEGIN IMMEDIATE')
        player_id = backend._authorize(connection, token)
        stack = connection.execute('SELECT quantity FROM native_lobby_collection_props '
            'WHERE player_id=? AND template_id=?', (player_id, brick_id)).fetchone()
        keys = connection.execute('SELECT quantity FROM native_lobby_collection_props '
            'WHERE player_id=? AND template_id=?', (player_id, store['key_id'])).fetchone()
        if not stack or stack[0] < count or not keys or keys[0] < count:
            fail('INSUFFICIENT_PROPS', 'Not enough owned bricks and keys')
        owned = {row[0] for row in connection.execute(
            'SELECT skin_id FROM native_lobby_gun_skins WHERE player_id=? AND gid=0', (player_id,))}
        pools = eligible_groups(box_id, owned)
        if not pools:
            fail('INVALID_EQUIPMENT', 'No recovered client prizes remain in this box')
        state = connection.execute('SELECT open_count,since_core FROM native_lobby_lottery_state '
            'WHERE player_id=? AND box_id=?', (player_id, box_id)).fetchone()
        opened, since_core = tuple(state) if state else (0, 0)
        changes, rewards = [], []
        next_gid = backend._next_native_prop_gid(connection)
        if next_gid + count >= 2**63:
            fail('INVALID_ARGUMENT', 'Skin instance identifier limit reached')
        for _ in range(count):
            forced = next(((group, prizes) for group, prizes in pools
                if group['567'] and group['582'] and since_core + 1 >= group['582']), None)
            if forced:
                group, prizes = forced
            else:
                ticket = secrets.randbelow(sum(group['577'] for group, _ in pools))
                for group, prizes in pools:
                    ticket -= group['577']
                    if ticket < 0:
                        break
            # Client exports omit per-prize runtime weights; local draws are uniform within a group.
            prize = prizes[secrets.randbelow(len(prizes))]
            skin_id = prize['3982']
            skin = gun_skins.SKINS[skin_id]
            gid = next_gid if skin['is_mystical'] else 0
            if gid:
                next_gid += 1
            # Zero is the client's explicit sentinel for its own default AppearanceID lookup.
            mystical = {'appearance': {'id': 0, 'seed': 0}} if gid else None
            connection.execute('INSERT OR IGNORE INTO native_lobby_gun_skins VALUES (?,?,?,?)',
                (player_id, skin_id, gid, json.dumps(mystical) if mystical else None))
            prop = {'id': skin_id, 'gid': gid, 'num': prize['3977']}
            if mystical:
                prop['mystical_skin_data'] = mystical
            rewards.append(prop)
            changes.append({'change_type': 1, 'delta': prop['num'], 'prop': prop})
            opened += 1
            since_core = 0 if group['567'] else since_core + 1
        for item_id, before in ((brick_id, stack[0]), (store['key_id'], keys[0])):
            remaining = before - count
            if remaining:
                connection.execute('UPDATE native_lobby_collection_props SET quantity=? '
                    'WHERE player_id=? AND template_id=?', (remaining, player_id, item_id))
            else:
                connection.execute('DELETE FROM native_lobby_collection_props '
                    'WHERE player_id=? AND template_id=?', (player_id, item_id))
            changes.append({'change_type': 3 if remaining else 2, 'delta': -count,
                            'prop': {'id': item_id, 'gid': 0, 'num': remaining}})
        connection.execute('INSERT INTO native_lobby_lottery_state VALUES (?,?,?,?) '
            'ON CONFLICT(player_id,box_id) DO UPDATE SET open_count=excluded.open_count,'
            'since_core=excluded.since_core', (player_id, box_id, opened, since_core))
        record = {'open_time': int(time.time()), 'add_props': rewards,
                  'del_props': [{'id': brick_id, 'gid': 0, 'num': count}],
                  'lottery_type': store['lottery_type'], 'lottery_id': store['lottery_id'], 'num': count}
        connection.execute('INSERT INTO native_lobby_lottery_history(player_id,box_id,record_json) '
            'VALUES (?,?,?)', (player_id, box_id, json.dumps(record)))
        connection.commit()
    return {'result': 0, 'accept_open_num': count, 'data_change': {'prop_changes': changes}}


def purchase(backend, token, fields):
    from .core import fail
    from .local_commerce import stock_catalog, _price

    if fields.get('is_open_directly'):
        return {'result': 1, 'is_open_directly': True}
    items = fields.get('buy_props') or []
    if not 1 <= len(items) <= 2:
        fail('INVALID_ARGUMENT', 'Unsupported Mandel purchase shape')
    debits, grants, gifts = {}, {}, {}
    seen = set()
    for item in items:
        item_id = int(item.get('item_id') or 0)
        count = int(item.get('num') or 0)
        if item_id in seen or not 1 <= count <= 1000 or int(item.get('price_substitute') or 0):
            fail('INVALID_ARGUMENT', 'Invalid Mandel purchase quantity or quote')
        seen.add(item_id)
        offer = next((row for row in CATALOG['key_offers']
                      if row['present_item_id'] == item_id), None)
        if offer:
            currency = offer['currency_type']
            total = offer['price'] * count
            # The wire request names the gift key; the paid product is the experience card.
            product = offer['buy_item_id']
            gifts[item_id] = count * offer['present_num']
            quote = total
        elif item_id in BRICKS:
            currency = 17888808887
            quote = _price(stock_catalog()[item_id])
            total = quote * count
            product = item_id
        else:
            fail('INVALID_ARGUMENT', 'Unknown client Mandel item')
        if (int(item.get('currency_type') or 0) != currency
                or int(item.get('price') or 0) != quote):
            fail('INVALID_ARGUMENT', 'Mandel purchase does not match the current offer')
        debits[currency] = debits.get(currency, 0) + total
        grants[product] = grants.get(product, 0) + count
    for item_id, quantity in gifts.items():
        grants[item_id] = grants.get(item_id, 0) + quantity

    with backend.connection() as connection:
        connection.execute('BEGIN IMMEDIATE')
        player_id = backend._authorize(connection, token)
        currency_changes, prop_changes = [], []
        for currency, delta in [(key, -value) for key, value in debits.items()]:
            balance = connection.execute('SELECT amount FROM native_lobby_currencies '
                'WHERE player_id=? AND currency_id=?', (player_id, currency)).fetchone()
            current = (balance[0] if balance else 0) + delta
            if current < 0:
                fail('INSUFFICIENT_FUNDS', 'Not enough local currency')
            if current >= 2**63:
                fail('INVALID_ARGUMENT', 'Currency balance is too large')
            connection.execute('INSERT INTO native_lobby_currencies VALUES (?,?,?) '
                'ON CONFLICT(player_id,currency_id) DO UPDATE SET amount=excluded.amount',
                (player_id, currency, current))
            currency_changes.append({'currency_id': currency, 'delta': delta, 'current_num': current})
        for item_id, quantity in grants.items():
            balance = connection.execute('SELECT quantity FROM native_lobby_collection_props '
                'WHERE player_id=? AND template_id=?', (player_id, item_id)).fetchone()
            current = (balance[0] if balance else 0) + quantity
            if current >= 2**31:
                fail('INVALID_ARGUMENT', 'Collection stack is too large')
            connection.execute('INSERT INTO native_lobby_collection_props VALUES (?,?,?) '
                'ON CONFLICT(player_id,template_id) DO UPDATE SET quantity=excluded.quantity',
                (player_id, item_id, current))
            prop_changes.append({'change_type': 1, 'delta': quantity,
                                 'prop': {'id': item_id, 'gid': 0, 'num': current}})
        connection.commit()
    return {'result': 0, 'is_open_directly': False,
            'change': {'currency_changes': currency_changes, 'prop_changes': prop_changes}}


def response_fields(request, backend, token):
    if request.name == 'CSShopNewGetConfigReq':
        return shop_config()
    if request.name == 'CSShopGetGameItemConfigReq':
        # CollectionServer copies Name verbatim; an override destroys client localization.
        return {'descs': []}
    if request.name == 'CSGetBoxInfoReq':
        return box_response(backend, token, request.fields)
    if request.name in ('CSShopBuyLotteryItemReq', 'CSLotteryBlindBoxDrawReq'):
        from .core import DomainError
        from .client_errors import inventory_error
        try:
            return (draw if request.name == 'CSLotteryBlindBoxDrawReq' else purchase)(
                backend, token, request.fields)
        except (ValueError, TypeError):
            return {'result': 14026}
        except DomainError as error:
            return {'result': inventory_error(error)}
    return None
