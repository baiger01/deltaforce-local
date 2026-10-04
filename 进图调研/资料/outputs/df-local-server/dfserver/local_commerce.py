"""Owner-controlled stock and purchases for the local original-client trial."""

from functools import lru_cache
import json
from pathlib import Path
import time

from .core import DomainError


CURRENCY_ID = 17020000010
STOCK_COUNT = 9999
MANDEL_BRICK_PREFIX = '161100'
# Installed GameItem gives decoded Mandel bricks no initial guide price.
# The local market needs its own starting price before it can list them.
MANDEL_BRICK_LOCAL_PRICE = 20000
MANDEL_BRICK_PURCHASE_CURRENCY = 17888808887
MANDEL_KEY_ID = 32320000001
MANDEL_KEY_CURRENCY = 17888808888
VERSION = {'ver': 'local-stock-v1', 'load_time': 1}
# The original client rejected 4,325 of 4,326 guessed merchant rows during the
# first native trial. Keep only the one row it did not reject until Mall table
# exchange identifiers can be recovered from the installed build.
CONFIRMED_MALL_IDS = (18300000004,)
SUPPORTED_REQUESTS = frozenset({
    'CSMarketGetTypeListReq', 'CSAuctionGetTypeListReq',
    'CSMarketGetPlayerInfoReq', 'CSAuctionGetPlayerInfoReq',
    'CSMarketGetSaleListReq', 'CSAuctionGetSaleListReq',
    'CSAuctionGetSaleListBatchReq',
    'CSMallGetCfgVersionReq', 'CSMallGetMerchantsReq',
    'CSMallGetBuyGoodsReq', 'CSMarketBuyTReq',
    'CSAuctionBuyTReq', 'CSMallBuyReq',
    'CSAuctionAutoLoadGuidePriceReq',
    'CSAuctionGetGameItemSellPriceReq',
    'CSMallGetUnlockExchangeIdReq',
    'CSShopBuyLotteryItemReq',
    'CSShopGetGameItemConfigReq',
    'CSSerialCheapBuyReq',
})


@lru_cache(maxsize=1)
def stock_catalog():
    source = Path(__file__).resolve().parent.parent / 'protocol/game_item_catalog.json'
    rows = json.loads(source.read_text(encoding='utf-8'))['rows']
    return {int(item_id): row for item_id, row in rows.items()
            if (row.get('name_key') or int(item_id) in CONFIRMED_MALL_IDS)
            and not row['is_currency'] and not row['is_model_only']
            and (row['initial_guide_price'] > 0 or
                 item_id.startswith(MANDEL_BRICK_PREFIX))
            and 0 < row['length'] <= 9 and 0 < row['width'] <= 40}


@lru_cache(maxsize=1)
def equipment_slots():
    source = Path(__file__).resolve().parent.parent / 'protocol/deposit_slot_catalog.json'
    rows = json.loads(source.read_text(encoding='utf-8'))['rows']
    return {int(slot_id) for slot_id, row in rows.items()
            if 100 < int(slot_id) < 139
            and row['grid_length'] > 0 and row['grid_width'] > 0}


def _purchase_position(position):
    position = int(position or 0)
    if position in (0, 2):
        return 2
    if position not in equipment_slots():
        raise ValueError('Purchase targets an unavailable equipment slot')
    return position


def order_id(item_id):
    return 1000000000000 + item_id


def stock_row(item_id):
    row = stock_catalog().get(item_id)
    if row is None:
        raise ValueError('Item is not in the installed local stock catalogue')
    return row


def _price(row):
    if row['initial_guide_price'] > 0:
        return row['initial_guide_price']
    if row['id'].startswith(MANDEL_BRICK_PREFIX):
        return MANDEL_BRICK_LOCAL_PRICE
    raise ValueError('No local market price for item')


def _prop(item_id, row, count=1):
    return {'id': item_id, 'num': count,
            'length': row['length'], 'width': row['width'],
            **item_condition_fields(item_id)}


def item_condition_fields(item_id):
    """Only protective gear has wear; local purchases start in full condition."""
    item_id = str(item_id)
    if item_id.startswith('1105'):
        maximum = _armor_durability_catalog().get(item_id, 100)
        return {'health': maximum, 'health_max': maximum}
    elif item_id.startswith('1101'):
        # The installed helmet durability table has not been recovered yet.
        return {'health': 100, 'health_max': 100}
    return {}


@lru_cache(maxsize=1)
def _armor_durability_catalog():
    source = Path(__file__).resolve().parent.parent / 'protocol/armor_durability_catalog.json'
    return json.loads(source.read_text(encoding='utf-8'))['rows']


def _type(item_id, row, *, auction=False):
    fields = {'prop_id': item_id, 'show_prop_id': item_id,
              'cur_num': STOCK_COUNT, 'guide_price': _price(row),
              'min_price': _price(row), 'average_price': _price(row),
              'max_stack_num': row['max_stack_count'],
              'max_buy_num': min(STOCK_COUNT, 1000)}
    if auction:
        fields['guide_currency'] = CURRENCY_ID
    else:
        fields.update({'buy_currency_id': CURRENCY_ID,
                       'sell_currency_id': CURRENCY_ID})
    return fields


def _mall_prop(item_id, row):
    return {'prop_info': _prop(item_id, row), 'merchant_id': 1,
            'exchange_id': item_id, 'exchange_type': 1,
            'prices': [{'money_type': CURRENCY_ID, 'price': _price(row)}],
            'for_sale': True, 'unlock_lv': 1, 'exchange_num': 1,
            'step_size': 1}


def _auction_sale_detail(item_id, row):
    price = _price(row)
    return {'prop_id': item_id, 'show_prop_id': item_id,
            'guide_currency': CURRENCY_ID, 'guide_price': price,
            'average_price': price, 'auction_price': price,
            'price_range_begin': price, 'price_range_end': price,
            'price_step': 1, 'durability_lvl': 0,
            'sale_lists': [{'prop': _prop(item_id, row),
                            'selling_num': STOCK_COUNT, 'price': price,
                            'price_currency': CURRENCY_ID,
                            'order_id': order_id(item_id)}]}


def _change(purchase):
    props = []
    for move in purchase.get('displaced_props', []):
        before, after = move['before'], move['after']

        def location(row):
            position = row['grid_page_id']
            return {'pos': position, 'start_x': row['x'], 'start_y': row['y'],
                    'x': row['length'] if position == 2 else 1,
                    'y': row['width'] if position == 2 else 1,
                    'space_id': 0, 'rotate': False}

        props.append({'change_type': 5, 'src': location(before),
                      'dest': location(after), 'delta': after['quantity'],
                      'prop': {'id': after['template_id'], 'gid': after['gid'],
                               'num': after['quantity'],
                               'position': after['grid_page_id'],
                               'length': after['length'], 'width': after['width'],
                               **item_condition_fields(after['template_id']),
                               'loc': location(after)}})
    for row in purchase['props']:
        position = row['grid_page_id']
        loc = {'pos': position, 'start_x': row['x'], 'start_y': row['y'],
               'x': row['length'] if position == 2 else 1,
               'y': row['width'] if position == 2 else 1,
               'space_id': 0, 'rotate': False}
        prop = {'id': row['template_id'], 'gid': row['gid'],
                'num': row['quantity'], 'position': position,
                'length': row['length'], 'width': row['width'], 'loc': loc,
                **item_condition_fields(row['template_id'])}
        props.append({'prop': prop, 'change_type': 1,
                      'dest': loc, 'delta': row['quantity']})
    currencies = [{
        'currency_id': purchase['currency_id'],
        'delta': purchase['currency_delta'],
        'current_num': purchase['currency_current']}]
    if purchase.get('bonus_currency_change'):
        currencies.append(purchase['bonus_currency_change'])
    return {'prop_changes': props, 'currency_changes': currencies}


def _collection_purchase_change(purchase):
    """A Mandel brick is a collection prop, not a spatial deposit item."""
    brick = purchase['collection_prop']
    currencies = [{
        'currency_id': purchase['currency_id'],
        'delta': purchase['currency_delta'],
        'current_num': purchase['currency_current']}]
    if purchase.get('bonus_currency_change'):
        currencies.append(purchase['bonus_currency_change'])
    return {'prop_changes': [{
        'change_type': 1, 'delta': brick['delta'],
        'prop': {'id': brick['template_id'], 'gid': 0,
                 'num': brick['delta']}}],
        'currency_changes': currencies}


def response_fields(request, backend, local_session):
    """Return declared commerce response fields, or None for unrelated requests."""
    name = request.name
    fields = request.fields
    catalog = stock_catalog()
    now = int(time.time())
    if name in ('CSMarketGetTypeListReq', 'CSAuctionGetTypeListReq'):
        ids = [int(v) for v in fields.get('prop_ids', [])]
        prefixes = [str(v) for v in fields.get('prop_prefixes', [])]
        selected = ((item_id, row) for item_id, row in catalog.items()
                    if (not ids or item_id in ids)
                    and (not prefixes or any(str(item_id).startswith(p) for p in prefixes)))
        result = {'result': 0, 'type_lists': [
            _type(item_id, row, auction=name.startswith('CSAuction'))
            for item_id, row in selected],
            ('auction_zone' if name.startswith('CSAuction') else 'market_zone'): 1}
        if name == 'CSAuctionGetTypeListReq':
            result['tax_cfg'] = [{'tax_id': 0, 'percent': 0,
                                  'tax_rate_ten_thousand': 0}]
        return result
    if name == 'CSShopGetGameItemConfigReq':
        descs = [{'item_id': item_id, 'Name': '曼德尔砖',
                  'Quality': row['quality'],
                  'InitialGuidePrice': _price(row)}
                 for item_id, row in catalog.items()
                 if str(item_id).startswith(MANDEL_BRICK_PREFIX)]
        descs.append({'item_id': MANDEL_KEY_ID, 'Name': '量子密钥', 'Quality': 5})
        return {'descs': descs}
    if name == 'CSAuctionAutoLoadGuidePriceReq':
        return {'result': 0, 'finish': True,
                'new_sync_digest': VERSION['ver'],
                'price_list': [{'prop_id': item_id, 'price': _price(row)}
                               for item_id, row in catalog.items()],
                'past_stable_price': bool(fields.get('past_stable_price', False))}
    if name == 'CSAuctionGetGameItemSellPriceReq':
        ids = [int(value) for value in fields.get('prop_ids', [])]
        return {'result': 0, 'sell_props': [
            {'prop_id': item_id, 'sell_price': _price(catalog[item_id]),
             'sell_money': CURRENCY_ID, 'dynamic_price': _price(catalog[item_id]),
             'static_price': _price(catalog[item_id])}
            for item_id in ids if item_id in catalog]}
    if name == 'CSMarketGetPlayerInfoReq':
        return {'result': 0, 'is_open': True, 'max_rack_cnt': 100,
                'init_rack_cnt': 100, 'open_time': now - 86400,
                'close_time': now + 365 * 86400}
    if name == 'CSAuctionGetPlayerInfoReq':
        return {'result': 0, 'player_unlock_buy': True,
                'player_unlock_sell': True, 'max_rack_cnt': 100}
    if name == 'CSAuctionGetSaleListBatchReq':
        ids = [int(value) for value in fields.get('prop_ids', [])]
        ids.extend(int(info.get('prop_id') or 0) for info in fields.get('infos', []))
        return {'result': 0, 'auction_zone': 1,
                'sale_lists': [_auction_sale_detail(item_id, catalog[item_id])
                               for item_id in dict.fromkeys(ids) if item_id in catalog]}
    if name in ('CSMarketGetSaleListReq', 'CSAuctionGetSaleListReq'):
        info = fields.get('info', {})
        item_id = int(info.get('prop_id') or fields.get('prop_id') or 0)
        row = catalog.get(item_id)
        if row is None:
            return {'result': 0}
        price = _price(row)
        offer = {'prop': _prop(item_id, row), 'selling_num': STOCK_COUNT,
                 'price': price, 'order_id': order_id(item_id)}
        detail = {'prop_id': item_id, 'show_prop_id': item_id,
                  'guide_price': price, 'average_price': price,
                  'price_range_begin': price, 'price_range_end': price,
                  'price_step': 1}
        if name == 'CSMarketGetSaleListReq':
            offer.update({'buy_currency_id': CURRENCY_ID,
                          'sell_currency_id': CURRENCY_ID,
                          'valid_time': now, 'expire_time': now + 365 * 86400})
            detail.update({'sale_lists': [offer],
                           'sell_currency_id': CURRENCY_ID,
                           'buy_currency_id': CURRENCY_ID,
                           'curr_selling_total_num': STOCK_COUNT,
                           'open_time': now - 86400,
                           'close_time': now + 365 * 86400})
            return {'result': 0, 'sale_list_info': detail, 'market_zone': 1}
        return {'result': 0, 'sale_list_infos': [_auction_sale_detail(item_id, row)],
                'auction_zone': 1}
    if name == 'CSMallGetCfgVersionReq':
        return {'result': 0, 'version_info': VERSION}
    if name == 'CSMallGetMerchantsReq':
        return {'result': 0, 'merchants': [{'id': 1, 'vip_lvl': 1}],
                'version_info': VERSION}
    if name == 'CSMallGetUnlockExchangeIdReq':
        return {'result': 0, 'unlock_exchange_ids': list(CONFIRMED_MALL_IDS),
                'cur_round': 0}
    if name == 'CSMallGetBuyGoodsReq':
        start = max(0, int(fields.get('start_index', 0)))
        requested = int(fields.get('get_num', 0))
        ids = [item_id for item_id in CONFIRMED_MALL_IDS if item_id in catalog]
        count = min(requested, 1000) if requested > 0 else len(ids) - start
        goods = [_mall_prop(item_id, catalog[item_id])
                 for item_id in ids[start:start + count]]
        result = {'result': 0, 'buy_props': goods,
                  'is_finish': start + count >= len(ids),
                  'version_info': VERSION}
        if 'match_info' in fields:
            result['match_info'] = fields['match_info']
        return result
    if name == 'CSShopBuyLotteryItemReq':
        if fields.get('is_open_directly'):
            # A draw is a separate state mutation and is not implemented yet.
            return {'result': 1, 'is_open_directly': True}
        purchases = fields.get('buy_props', [])
        if len(purchases) != 2:
            raise ValueError('Unsupported local Mandel purchase shape')
        brick, key = purchases
        item_id = int(brick.get('item_id') or 0)
        count = int(brick.get('num') or 0)
        if (str(item_id)[:6] != MANDEL_BRICK_PREFIX or item_id not in catalog
                or count < 1 or count > 1000
                or int(brick.get('currency_type') or 0) != MANDEL_BRICK_PURCHASE_CURRENCY
                or int(brick.get('price') or 0) != _price(catalog[item_id])
                or int(key.get('item_id') or 0) != MANDEL_KEY_ID
                or int(key.get('num') or 0) != count
                or int(key.get('currency_type') or 0) != MANDEL_KEY_CURRENCY
                or int(key.get('price') or 0) != 0):
            raise ValueError('Mandel purchase does not match local offer')
        row = catalog[item_id]
        try:
            purchase = backend.native_lobby_collection_purchase(
                local_session, template_id=item_id, quantity=count,
                unit_price=_price(row), currency_id=MANDEL_BRICK_PURCHASE_CURRENCY,
                bonus_currency_id=MANDEL_KEY_ID,
                bonus_currency_amount=count)
        except DomainError:
            return {'result': 1}
        return {'result': 0, 'change': _collection_purchase_change(purchase),
                'is_open_directly': bool(fields.get('is_open_directly', False))}
    if name == 'CSSerialCheapBuyReq':
        entries = fields.get('buy_list', [])
        if len(entries) != 1:
            return {'result': 1, 'mall_fail_list': entries}
        entry = entries[0]
        mall = entry.get('mall_prop') or {}
        mall_prop = mall.get('prop_info') or {}
        auction = entry.get('auction_prop') or {}
        single = entry.get('single_auction_prop') or {}
        if mall_prop:
            item_id = int(mall_prop.get('id') or 0)
            count = int(mall_prop.get('num') or 0)
            prices = entry.get('mall_prices') or mall.get('prices') or []
            channel = 'mall'
            if len(prices) != 1:
                return {'result': 1, 'mall_fail_list': entries}
            currency_id = int(prices[0].get('money_type') or 0)
            quoted_price = int(prices[0].get('price') or 0)
            target_position = _purchase_position(mall_prop.get('position'))
        else:
            item_id = int(auction.get('prop_id') or single.get('prop_id') or 0)
            count = int(auction.get('total_num') or single.get('buy_num') or 0)
            currency_id = int(auction.get('currency') or single.get('currency') or 0)
            quoted_price = int(auction.get('price') or single.get('price') or 0)
            channel = 'auction'
            target_position = _purchase_position(single.get('to_pos'))
        row = catalog.get(item_id)
        if row is None or not 1 <= count <= 1000 or currency_id != CURRENCY_ID:
            return {'result': 1, ('mall_fail_list' if channel == 'mall'
                                  else 'auction_fail_list'): entries}
        unit_price = _price(row)
        if quoted_price not in (unit_price, unit_price * count):
            return {'result': 1, ('mall_fail_list' if channel == 'mall'
                                  else 'auction_fail_list'): entries}
        try:
            purchase = backend.native_lobby_purchase(
                local_session, template_id=item_id, quantity=count,
                unit_price=unit_price, currency_id=CURRENCY_ID,
                length=row['length'], width=row['width'],
                max_stack_count=row['max_stack_count'],
                target_position=target_position)
        except DomainError:
            return {'result': 1, ('mall_fail_list' if channel == 'mall'
                                  else 'auction_fail_list'): entries}
        return {'result': 0, ('mall_changes' if channel == 'mall'
                              else 'auction_changes'): _change(purchase),
                'is_underbuy': False, 'force_buy_channel': int(entry.get('channel') or 0)}
    if name in ('CSMarketBuyTReq', 'CSAuctionBuyTReq', 'CSMallBuyReq'):
        if name == 'CSMallBuyReq':
            mall_prop = fields.get('mall_prop', {})
            item_id = int(mall_prop.get('prop_info', {}).get('id') or 0)
            count = int(mall_prop.get('prop_info', {}).get('num') or 1)
        else:
            item_id = int(fields.get('prop_id') or 0)
            count = int(fields.get('buy_num') or 1)
        row = stock_row(item_id)
        price = _price(row)
        if name != 'CSMallBuyReq' and (int(fields.get('price') or 0) != price
                                       or int(fields.get('currency') or 0) != CURRENCY_ID
                                       or int(fields.get('order_id') or 0) != order_id(item_id)):
            raise ValueError('Purchase does not match the local offer')
        try:
            purchase = backend.native_lobby_purchase(
                local_session, template_id=item_id, quantity=count,
                unit_price=price, currency_id=CURRENCY_ID,
                length=row['length'], width=row['width'],
                max_stack_count=row['max_stack_count'])
        except DomainError:
            return {'result': 1}
        if name == 'CSMallBuyReq':
            return {'result': 0, 'prop_changes': _change(purchase),
                    'version_info': VERSION}
        bought = {'order_id': order_id(item_id),
                  'prop': _prop(item_id, row, count),
                  'show_prop_id': item_id,
                  'price_currency': CURRENCY_ID,
                  'price': price, 'buy_price': price,
                  'state': 1}
        if name == 'CSMarketBuyTReq':
            bought.update({'buy_currency_id': CURRENCY_ID,
                           'sell_currency_id': CURRENCY_ID})
        return {'result': 0, 'changes': _change(purchase),
                'orders': [bought]}
    return None
