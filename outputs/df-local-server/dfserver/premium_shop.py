"""Native premium-store contracts backed by installed tables and local saves."""

from collections import defaultdict
from datetime import datetime
import json
from pathlib import Path
import secrets
import time

from . import gun_skins, hero_customization, mandel
from .core import DomainError, fail
from .client_errors import inventory_error


PROTOCOL = Path(__file__).resolve().parent.parent / 'protocol'
CATALOG = json.loads((PROTOCOL / 'premium_shop_catalog.json').read_text(encoding='utf-8'))
ITEMS = json.loads((PROTOCOL / 'game_item_catalog.json').read_text(encoding='utf-8'))['rows']
RECOVERED_RECOMMENDATIONS = {r['tab_id']: r for r in CATALOG['recommendations']}
RECOMMENDATIONS = {r['tab_id']: r for r in CATALOG['recommendations'] if r['bundle_item_list']
    and (r['preview_asset'] or r['IamgeSourceSmall_CDN'])
    and all(not str(p['id']).startswith(('280', '281')) or p['id'] in gun_skins.SKINS
            for item in r['bundle_item_list'] for p in (item.get('item_list') or [item]))}
GIFTS = {r['goods_id']: r for r in CATALOG['gifts'] if (r['is_cash'] or r['currency_type']) and all(
    not ITEMS.get(str(p['id']), {}).get('length') or ITEMS[str(p['id'])]['is_currency']
    for p in r['bundle_item_list'])}
LOTTERIES = {r['lottery_id']: r for r in CATALOG['lotteries']}
PROMOTIONS = {r['tab_id']: r for r in CATALOG['recommendations'] if r['banner_type'] == 2
    and r['jump_to'] in {str(i) for i in (*LOTTERIES,
        *(row['lottery_id'] for row in mandel.CATALOG['store_lotteries']))}}
FASHIONS = {r['fashion_id']: r['hero_id'] for r in CATALOG['fashion_links']}
REWARDS = defaultdict(list)
for row in CATALOG['lottery_rewards']:
    REWARDS[row['lottery_id']].append(row)
SUPPORTED_REQUESTS = frozenset({
    'CSShopNewGetConfigReq', 'CSShopGetBuyRecordReq',
    'CSShopGetThemeBundleTimeConfigReq', 'CSShopGetLuckyNestConfigReq',
    'CSShopBuyHotRecommendationReq', 'CSShopBuyMallGiftReq',
    'CSShopGetLotteryInfoReq', 'CSShopOpenLotteryItemReq', 'CSHeroEquipFashionReq',
})
COLLECTION_RESPONSES = frozenset({
    'CSShopBuyLotteryItemRes', 'CSLotteryBlindBoxDrawRes',
    'CSShopBuyHotRecommendationRes', 'CSShopBuyMallGiftRes', 'CSShopOpenLotteryItemRes',
})


def timestamp(text):
    return int(datetime.strptime(text, '%Y-%m-%d %H:%M:%S').timestamp()) if text else 0


def bundle_items(rows):
    return [{**r, 'prop': {'id': r['id'], 'gid': 0, 'num': r['num']}} for r in rows]


def shop_config():
    result = mandel.shop_config()
    now = int(time.time())
    # Offline diagnostics expose recovered offers; live rotation is not available.
    result['hot_recommendation_descs'] = [{
        **{k: r[k] for k in ('tab_id', 'banner_type', 'bundle_currency_type',
                              'bundle_price', 'disbundle_price', 'SortIndex')},
        'bundle_item_list': bundle_items(r['bundle_item_list']),
        'online_time': now - 86400, 'offline_time': now + 365 * 86400,
        'jump_to': r['jump_to'],
        **{k: r[k] for k in ('IamgeSourceSmall_CDN', 'IamgeSourceBig_CDN',
                             'ImageSourceLogo_CDN_CN', 'ImageSourceLogo_CDN_EN')},
    } for r in (*RECOMMENDATIONS.values(), *PROMOTIONS.values())]
    result['mall_gift_descs'] = [{
        **{k: r[k] for k in ('goods_id', 'goods_type', 'Sortindex', 'currency_type',
            'price', 'price_pre_dis', 'is_cash', 'limit_type', 'limit_amount',
            'midas_product_id', 'google_item_id')},
        'bundle_item_list': bundle_items(r['bundle_item_list']),
        'online_time': timestamp(r['online_time_text']) or now - 86400,
        'offline_time': timestamp(r['offline_time_text']) or now + 365 * 86400,
    } for r in GIFTS.values()]
    result['lottery_item_descs'].extend({
        **{k: r[k] for k in ('lottery_id', 'lottery_type', 'lottery_key_id')},
        'begin_time': now - 86400, 'end_time': now + 365 * 86400,
        'SortIndex': len(LOTTERIES) - index,
    } for index, r in enumerate(LOTTERIES.values()))
    return result


def owned_wins(connection, player_id, lottery_id):
    draws = connection.execute('SELECT won_ids_json FROM native_lobby_staff_draws '
        'WHERE player_id=? AND lottery_id=? ORDER BY id', (player_id, lottery_id)).fetchall()
    legacy = {r['source_row_id']: r['num_id'] for r in REWARDS[lottery_id]}
    valid = {r['num_id'] for r in REWARDS[lottery_id]}
    wins = [item if item in valid else legacy.get(item)
            for draw in draws for item in json.loads(draw[0])]
    if any(item is None for item in wins):
        fail('INVALID_ARGUMENT', 'Stored reward number is outside its client pool')
    return wins, len(draws)


def pool(connection, player_id, lottery_id):
    lottery = LOTTERIES.get(lottery_id)
    if lottery is None:
        fail('INVALID_ARGUMENT', 'Unrecovered client staff lottery')
    rows = REWARDS[lottery_id]
    won, rounds = owned_wins(connection, player_id, lottery_id)
    remaining = [r for r in rows if r['num_id'] not in won]
    total = sum(r['raw_weight'] for r in remaining)
    return {'lottery_id': lottery_id, 'prop_num_ids': won,
        'cost_item_id': lottery['lottery_key_id'],
        'cost_num': rows[min(rounds, len(rows) - 1)]['raw_cost'] if remaining else 0,
        'lottery_rewards': [{'num_id': r['num_id'], 'props': r['props'],
            'prob': r['raw_weight'] / total if r in remaining and total else 0,
            'Is_great_reward': r['is_great_reward']} for r in rows]}


def records(backend, token):
    with backend.connection() as connection:
        player_id = backend._authorize(connection, token)
        result = {'result': 0, 'hot_recommendation_records': [], 'mall_gift_records': [],
                  'open_lottery_records': [], 'lottery_pool_info': []}
        recommendations, gifts = {}, {}
        for kind, offer_id, body in connection.execute('SELECT kind,offer_id,record_json '
                'FROM native_lobby_shop_records WHERE player_id=? ORDER BY id', (player_id,)):
            record = json.loads(body)
            if kind == 'recommendation':
                merged = recommendations.setdefault(offer_id,
                    {'tab_id': offer_id, 'banner_type': record['banner_type'], 'item_ids': []})
                merged['item_ids'].extend(record['item_ids'])
                offer = RECOVERED_RECOMMENDATIONS.get(offer_id)
                merged['is_sold_out'] = bool(offer) and set(merged['item_ids']) == {
                    r['id'] for r in offer['bundle_item_list']}
            elif kind == 'gift':
                offer = GIFTS.get(offer_id)
                if offer and offer['limit_type'] == 2 and record['buy_time'] < week_start():
                    continue
                merged = gifts.setdefault(offer_id, {**record, 'num': 0})
                merged['num'] += record['num']
                merged['buy_time'] = max(merged['buy_time'], record['buy_time'])
        result['hot_recommendation_records'] = list(recommendations.values())
        result['mall_gift_records'] = list(gifts.values())
        result['open_lottery_records'] = [json.loads(row[0]) for row in connection.execute(
            'SELECT record_json FROM native_lobby_staff_draws WHERE player_id=? '
            'ORDER BY id DESC LIMIT 100', (player_id,))]
        result['lottery_pool_info'] = [pool(connection, player_id, lid) for lid in LOTTERIES]
    return result


def week_start():
    now = datetime.now()
    return int(datetime(now.year, now.month, now.day).timestamp()) - now.weekday() * 86400


def quote(fields, currency, total):
    paid_currency, paid = int(fields.get('currency_type') or 0), int(fields.get('price') or 0)
    substitute = int(fields.get('currency_type_substitute') or 0)
    paid_sub = int(fields.get('price_substitute') or 0)
    if fields.get('replace_tickets') or paid < 0 or paid_sub < 0 or paid + paid_sub != total:
        fail('INVALID_ARGUMENT', 'Purchase does not match client quote')
    # StoreServer uses Coins as an equal-value substitute for Tickets.
    if paid_currency != currency or (paid_sub and (currency != 17888808889 or substitute != 17888808888)):
        fail('INVALID_ARGUMENT', 'Unsupported quote currency')
    debits = {paid_currency: paid} if paid else {}
    if paid_sub:
        debits[substitute] = paid_sub
    return debits


def currency_change(connection, player_id, currency, delta):
    before = connection.execute('SELECT amount FROM native_lobby_currencies '
        'WHERE player_id=? AND currency_id=?', (player_id, currency)).fetchone()
    current = (before[0] if before else 0) + delta
    if current < 0:
        fail('INSUFFICIENT_FUNDS', 'Not enough local currency')
    if current >= 2**63:
        fail('INVALID_ARGUMENT', 'Currency balance limit')
    connection.execute('INSERT INTO native_lobby_currencies VALUES (?,?,?) '
        'ON CONFLICT(player_id,currency_id) DO UPDATE SET amount=excluded.amount',
        (player_id, currency, current))
    return {'currency_id': currency, 'delta': delta, 'current_num': current}


def collection_change(connection, player_id, item_id, delta):
    before = connection.execute('SELECT quantity FROM native_lobby_collection_props '
        'WHERE player_id=? AND template_id=?', (player_id, item_id)).fetchone()
    current = (before[0] if before else 0) + delta
    if current < 0:
        fail('INSUFFICIENT_PROPS', 'Not enough owned collection items')
    if current >= 2**31:
        fail('INVALID_ARGUMENT', 'Collection stack limit')
    if current:
        connection.execute('INSERT INTO native_lobby_collection_props VALUES (?,?,?) '
            'ON CONFLICT(player_id,template_id) DO UPDATE SET quantity=excluded.quantity',
            (player_id, item_id, current))
    else:
        connection.execute('DELETE FROM native_lobby_collection_props '
            'WHERE player_id=? AND template_id=?', (player_id, item_id))
    return {'change_type': 1 if delta > 0 else (3 if current else 2), 'delta': delta,
            'prop': {'id': item_id, 'gid': 0, 'num': current}}


def grant(connection, player_id, items, changes):
    for item in items:
        item_id, count = item['id'], item['num']
        if ITEMS.get(str(item_id), {}).get('is_currency'):
            changes['currency_changes'].append(currency_change(connection, player_id, item_id, count))
        elif item_id in gun_skins.SKINS:
            skin = gun_skins.SKINS[item_id]
            if skin['is_mystical']:
                fail('INVALID_ARGUMENT', 'Premium offer requires an unrecovered unique skin grant')
            inserted = connection.execute('INSERT OR IGNORE INTO native_lobby_gun_skins '
                'VALUES (?,?,0,NULL)', (player_id, item_id)).rowcount
            if inserted:
                changes['prop_changes'].append({'change_type': 1, 'delta': count,
                    'prop': {'id': item_id, 'gid': 0, 'num': count}})
        else:
            if str(item_id).startswith(('280', '281')):
                fail('INVALID_EQUIPMENT', 'Weapon-skin ownership mapping is not recovered')
            changes['prop_changes'].append(collection_change(connection, player_id, item_id, count))


def buy(backend, token, fields, *, gift=False):
    offer_id = int(fields.get('goods_id' if gift else 'tab_id') or 0)
    offer = (GIFTS if gift else RECOMMENDATIONS).get(offer_id)
    if offer is None:
        fail('INVALID_ARGUMENT', 'Unknown installed premium offer')
    quantity = int(fields.get('num') or 0) if gift else 1
    if not 1 <= quantity <= 1000:
        fail('INVALID_ARGUMENT', 'Invalid premium purchase quantity')
    rows = offer['bundle_item_list']
    cash = bool(gift and offer['is_cash'])
    if gift:
        now = int(time.time())
        start, end = timestamp(offer['online_time_text']), timestamp(offer['offline_time_text'])
        if (start and now < start) or (end and now >= end):
            fail('INVALID_ARGUMENT', 'Gift is outside its client availability dates')
        if cash:
            # Local-only completion bypasses the external payment SDK. No order is submitted.
            if (not fields.get('is_cash_buy') or quantity != 1 or int(fields.get('price') or 0)
                    or int(fields.get('price_substitute') or 0) or fields.get('replace_tickets')):
                fail('INVALID_ARGUMENT', 'Invalid local cash-bundle trial request')
            cash_request = fields.get('CashBuyReq') or {}
            if cash_request.get('product_id') != offer['midas_product_id'] or cash_request.get('quantity') != 1:
                fail('INVALID_ARGUMENT', 'Cash product does not match client configuration')
            debits = {}
        else:
            if fields.get('is_cash_buy'):
                fail('INVALID_ARGUMENT', 'Offer is not a cash product')
            debits = quote(fields, offer['currency_type'], offer['price'] * quantity)
    else:
        ids = [int(value) for value in fields.get('item_ids', [])] or [r['id'] for r in rows]
        if (len(ids) != len(set(ids)) or int(fields.get('banner_type') or 0) != offer['banner_type']
                or not set(ids) <= {r['id'] for r in rows}):
            fail('INVALID_ARGUMENT', 'Invalid bundle selection')
        selected = [r for r in rows if r['id'] in ids]
        full_bundle = len(selected) == len(rows)
        rows = selected
    with backend.connection() as connection:
        connection.execute('BEGIN IMMEDIATE')
        player_id = backend._authorize(connection, token)
        previous = [json.loads(row[0]) for row in connection.execute(
            'SELECT record_json FROM native_lobby_shop_records '
            'WHERE player_id=? AND kind=? AND offer_id=?',
            (player_id, 'gift' if gift else 'recommendation', offer_id))]
        if gift:
            if offer['limit_amount']:
                # LimitType 2 is the native weekly key offer; other limits persist locally.
                start = week_start()
                used = sum(r['num'] for r in previous if offer['limit_type'] != 2 or r['buy_time'] >= start)
                if used + quantity > offer['limit_amount']:
                    fail('INVALID_ARGUMENT', 'Local offer purchase limit')
            record = {'goods_id': offer_id, 'num': quantity, 'buy_time': int(time.time())}
        else:
            owned_items = {r[0] for r in connection.execute('SELECT template_id FROM '
                'native_lobby_collection_props WHERE player_id=?', (player_id,))}
            owned_items.update(r[0] for r in connection.execute('SELECT skin_id FROM '
                'native_lobby_gun_skins WHERE player_id=?', (player_id,)))
            owned = {i for r in previous for i in r['item_ids']}
            owned.update(r['id'] for r in rows if all(p['id'] in owned_items for p in (
                r.get('item_list') or [r])))
            remaining = [r for r in rows if r['id'] not in owned]
            if not remaining or (not full_bundle and owned & set(ids)):
                fail('INVALID_ARGUMENT', 'Bundle selection was already owned')
            total = (offer['bundle_price'] if len(remaining) == len(offer['bundle_item_list'])
                else sum(r['dis_price'] for r in remaining)) if full_bundle else sum(r['price'] for r in rows)
            if not full_bundle and total <= 0:
                fail('INVALID_ARGUMENT', 'Unpriced standalone promotional item')
            debits = quote(fields, offer['bundle_currency_type'], total)
            rows = remaining
            record = {'tab_id': offer_id, 'banner_type': offer['banner_type'], 'item_ids': ids}
        grants = [dict(item, num=item['num'] * quantity) for r in rows
                  for item in (r.get('item_list') or [{'id': r['id'], 'num': r['num']}])]
        changes = {'currency_changes': [currency_change(connection, player_id, c, -n)
                                      for c, n in debits.items()], 'prop_changes': []}
        grant(connection, player_id, grants, changes)
        connection.execute('INSERT INTO native_lobby_shop_records '
            '(player_id,kind,offer_id,record_json) VALUES (?,?,?,?)',
            (player_id, 'gift' if gift else 'recommendation', offer_id, json.dumps(record)))
        connection.commit()
    return {'result': 0, 'change': changes, **({'is_cash_buy': False} if gift else {})}


def draw(backend, token, fields):
    lottery_id = int(fields.get('lottery_id') or 0)
    with backend.connection() as connection:
        connection.execute('BEGIN IMMEDIATE')
        player_id = backend._authorize(connection, token)
        info = pool(connection, player_id, lottery_id)
        won, rounds = owned_wins(connection, player_id, lottery_id)
        if info['cost_num'] <= 0 or int(fields.get('round') or 0) != rounds + 1:
            fail('INVALID_ARGUMENT', 'Closed pool or stale lottery round')
        key_id, cost = info['cost_item_id'], info['cost_num']
        changes = {'currency_changes': [], 'prop_changes': []}
        purchase = fields.get('buy_prop')
        if purchase:
            offer = next(r for r in mandel.CATALOG['key_offers'] if r['present_item_id'] == key_id)
            if int(purchase.get('item_id') or 0) != key_id or int(purchase.get('num') or 0) != cost:
                fail('INVALID_ARGUMENT', 'Research key does not match round cost')
            debits = quote(purchase, offer['currency_type'], offer['price'] * cost)
            changes['currency_changes'].extend(currency_change(connection, player_id, c, -n)
                                               for c, n in debits.items())
            grant(connection, player_id, [{'id': offer['buy_item_id'], 'num': cost},
                  {'id': key_id, 'num': cost * offer['present_num']}], changes)
        changes['prop_changes'].append(collection_change(connection, player_id, key_id, -cost))
        remaining = [r for r in REWARDS[lottery_id] if r['num_id'] not in won]
        ticket = secrets.randbelow(sum(r['raw_weight'] for r in remaining))
        for reward in remaining:
            ticket -= reward['raw_weight']
            if ticket < 0:
                break
        selected = remaining if reward['is_great_reward'] else [reward]
        grants = [p for r in selected for p in r['props']]
        grant(connection, player_id, grants, changes)
        record = {'open_time': int(time.time()), 'lottery_id': lottery_id, 'lottery_type': 3,
                  'num': 1, 'add_props': grants, 'del_props': [{'id': key_id, 'gid': 0, 'num': cost}]}
        connection.execute('INSERT INTO native_lobby_staff_draws '
            '(player_id,lottery_id,won_ids_json,record_json) VALUES (?,?,?,?)',
            (player_id, lottery_id, json.dumps([r['num_id'] for r in selected]), json.dumps(record)))
        info = pool(connection, player_id, lottery_id)
        connection.commit()
    return {'result': 0, 'change': changes, 'lottery_pool_info': info}


def hero_record(connection, player_id, hero_id, base_id):
    return hero_customization.hero_record(connection, player_id, hero_id, {hero_id: base_id})


def hero_records(backend, token, hero_ids=None):
    return hero_customization.hero_records(backend, token, hero_ids)


def equip(backend, token, fields):
    from .handshake_diagnostic import _candidate_operator_base_fashions
    return hero_customization.equip_hero(backend, token, int(fields.get('hero_id') or 0),
        fields.get('new_fashions') or [], _candidate_operator_base_fashions())


def response_fields(request, backend, token):
    name, fields = request.name, request.fields
    if name not in SUPPORTED_REQUESTS:
        return None
    try:
        if name == 'CSShopNewGetConfigReq':
            return shop_config()
        if name == 'CSShopGetBuyRecordReq':
            return records(backend, token)
        if name == 'CSShopGetThemeBundleTimeConfigReq':
            return {'theme_tab_list': [], 'bundle_list': []}
        if name == 'CSShopGetLuckyNestConfigReq':
            return {'result': 0}
        if name == 'CSShopBuyHotRecommendationReq':
            return buy(backend, token, fields)
        if name == 'CSShopBuyMallGiftReq':
            return buy(backend, token, fields, gift=True)
        if name == 'CSShopGetLotteryInfoReq':
            with backend.connection() as connection:
                player_id = backend._authorize(connection, token)
                selected = int(fields.get('lottery_id') or 0)
                ids = [selected] if selected else LOTTERIES
                return {'result': 0, 'lottery_pool_info': [pool(connection, player_id, lid) for lid in ids]}
        if name == 'CSShopOpenLotteryItemReq':
            return draw(backend, token, fields)
        if name == 'CSHeroEquipFashionReq':
            return equip(backend, token, fields)
    except (ValueError, TypeError):
        return {'result': 14026}
    except DomainError as error:
        return {'result': inventory_error(error)}
