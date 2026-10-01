"""Owner-controlled stock and purchases for the local original-client trial."""

from functools import lru_cache
import json
from pathlib import Path
import time

from .core import (POCKET_POSITION, BACKPACK_POSITION, CHEST_RIG_POSITION, SAFE_BOX_POSITION,
                   DomainError)
from .client_errors import error_code, inventory_error
from .weapon_components import default_components
from .weapon_ammo import magazine_capacity
from .melee_weapons import WEAPONS
from . import gun_skins, hero_customization, mandel, premium_shop, profile_cosmetics, weapon_pendants, battle_pass, native_settings, local_chat


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
    'CSMarketGetAndUpdatePreBuyOrderReq',
    'CSMallGetCfgVersionReq', 'CSMallGetMerchantsReq',
    'CSMallGetBuyGoodsReq', 'CSMarketBuyTReq',
    'CSMallGetMysteryShopItemsReq', 'CSMallGetLabelNo1ConfigReq',
    'CSMallGetRecycleGoodsReq', 'CSMallGetPlayerDailyLimitGoodsReq',
    'CSMallGetClickedExchangeIdReq',
    'CSAuctionBuyTReq', 'CSMallBuyReq',
    'CSAuctionAutoLoadGuidePriceReq',
    'CSAuctionGetGameItemSellPriceReq',
    'CSMallGetUnlockExchangeIdReq',
    'CSShopBuyLotteryItemReq',
    'CSShopGetGameItemConfigReq',
    'CSSerialCheapBuyReq',
    'CSMallSellReq',
    'CSWAssemblySkinInfoGetReq', 'CSWAssemblyApplySkinReq',
    'CSWAssemblyDepositPropUpdateReq',
    'CSCollectionLoadMysticalSkinPropsReq',
    'CSShopNewGetConfigReq', 'CSGetBoxInfoReq',
    'CSLotteryBlindBoxDrawReq',
}) | premium_shop.SUPPORTED_REQUESTS | profile_cosmetics.SUPPORTED_REQUESTS | hero_customization.SUPPORTED_REQUESTS | weapon_pendants.SUPPORTED_REQUESTS | battle_pass.SUPPORTED_REQUESTS | native_settings.SUPPORTED_REQUESTS | local_chat.SUPPORTED_REQUESTS


@lru_cache(maxsize=1)
def default_weapon_presets():
    source = Path(__file__).resolve().parent.parent / 'protocol/weapon_preset_catalog.json'
    rows = json.loads(source.read_text(encoding='utf-8'))[
        'default_preset_to_receiver']
    return {int(preset_id): receiver_id for preset_id, receiver_id in rows.items()}


@lru_cache(maxsize=1)
def installed_items():
    source = Path(__file__).resolve().parent.parent / 'protocol/game_item_catalog.json'
    return json.loads(source.read_text(encoding='utf-8'))['rows']


@lru_cache(maxsize=1)
def medicine_sale_ids():
    source = Path(__file__).resolve().parent.parent / 'protocol/medicine_sale_policy.json'
    policy = json.loads(source.read_text(encoding='utf-8'))
    injections = {int(item_id) for item_id in policy['injections']}
    subtypes = set(policy['regular_subtypes'])
    return frozenset(int(item_id) for item_id in installed_items()
                     if int(item_id) // 1000000000 == policy['medicine_main_type']
                     and ((int(item_id) // 10000000) % 100 in subtypes
                          or int(item_id) in injections))


@lru_cache(maxsize=1)
def priced_inventory_catalog():
    """Retain recycle pricing for owned items even when no longer purchasable."""
    rows = installed_items()
    mapped_guns = default_weapon_presets()
    return {int(item_id): row for item_id, row in rows.items()
            if (row.get('name_key') or int(item_id) in CONFIRMED_MALL_IDS)
            and (not item_id.startswith('100') or int(item_id) in mapped_guns)
            and not row['is_currency'] and not row['is_model_only']
            and (row['initial_guide_price'] > 0 or
                 item_id.startswith(MANDEL_BRICK_PREFIX))
            and 0 < row['length'] <= 9 and 0 < row['width'] <= 40}


@lru_cache(maxsize=1)
def stock_catalog():
    medicines = medicine_sale_ids()
    return {item_id: row for item_id, row in priced_inventory_catalog().items()
            if item_id // 1000000000 != 14 or item_id in medicines}


@lru_cache(maxsize=1)
def _browse_catalog():
    seen = set()
    rows = {}
    catalog = stock_catalog()
    complete_gun_names = {row['name_key'] for item_id, row in catalog.items()
                          if str(item_id).startswith('100')}
    for item_id, row in catalog.items():
        if (str(item_id).startswith('180')
                and row['name_key'] in complete_gun_names):
            continue
        signature = tuple((key, value) for key, value in row.items()
                          if key not in ('id', 'serialized_uexp_offset'))
        if signature not in seen:
            seen.add(signature)
            rows[item_id] = row
    return rows


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
    if position in (CHEST_RIG_POSITION, BACKPACK_POSITION, SAFE_BOX_POSITION, POCKET_POSITION):
        return position
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


def _delivered_stock(catalog, item_id):
    delivered_id = default_weapon_presets().get(item_id, item_id)
    return delivered_id, catalog[delivered_id]


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


def item_condition_fields(item_id, *, components=None, weapon=None, health=None):
    """Return item state used by the original client's inventory logic."""
    item_id = str(item_id)
    from .native_keycards import keycard_fields
    key_fields = keycard_fields(item_id, health)
    if key_fields:
        return key_fields
    if int(item_id) in WEAPONS:
        return {'weapon': dict(weapon) if weapon is not None else
                          {'skin_id': WEAPONS[int(item_id)], 'skin_gid': 0}}
    if (item_id.startswith(('1001', '1002', '1003', '1004',
                            '1005', '1006', '1007', '1008'))
            or int(item_id) in default_weapon_presets().values()):
        components = default_components(item_id) if components is None else components
        state = dict(weapon) if weapon is not None else {'load_bullets': []}
        capacity = magazine_capacity(components, int(item_id))
        if capacity is not None:
            state['magazine_capacity'] = capacity
        return {'components': components, 'weapon': state}
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


def _listing_durability(item_id):
    if str(item_id).startswith(('1101', '1105')):
        # AuctionServer.GetPropSaleInfo uses bucket 0 for a single full offer.
        return 0, 100
    return 0, 0


def _type(item_id, row, *, auction=False):
    fields = {'prop_id': item_id, 'show_prop_id': item_id,
              'cur_num': STOCK_COUNT, 'guide_price': _price(row),
              'min_price': _price(row), 'average_price': _price(row),
              'max_stack_num': row['max_stack_count'],
              'max_buy_num': min(STOCK_COUNT, 1000)}
    if auction:
        durability_lvl, durability_ratio = _listing_durability(item_id)
        fields.update({'guide_currency': CURRENCY_ID,
                       'durability_lvl': durability_lvl,
                       'durability_ratio': durability_ratio})
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


def _auction_sale_detail(item_id, row, now):
    price = _price(row)
    durability_lvl, durability_ratio = _listing_durability(item_id)
    return {'prop_id': item_id, 'show_prop_id': item_id,
            'guide_currency': CURRENCY_ID, 'guide_price': price,
            'average_price': price, 'auction_price': price,
            'price_range_begin': price, 'price_range_end': price,
            'price_step': 1, 'durability_lvl': durability_lvl,
            'durability_ratio': durability_ratio,
            'auction_vaild_time_begin': now - 86400,
            'auction_vaild_time_end': now + 365 * 86400,
            'sale_lists': [{'prop': _prop(item_id, row),
                            'selling_num': STOCK_COUNT, 'price': price,
                            'price_currency': CURRENCY_ID,
                            'order_id': order_id(item_id)}]}


def inventory_location(row):
    position = row['grid_page_id']
    if position == POCKET_POSITION:
        return {'pos': position, 'start_x': 0, 'start_y': 0,
                'x': row['width'], 'y': row['length'],
                'space_id': row['x'], 'rotate': False}
    if position in (CHEST_RIG_POSITION, BACKPACK_POSITION, SAFE_BOX_POSITION):
        space_width = row.get('space_width')
        if not space_width and row['y']:
            raise ValueError('Container coordinates require the equipped item layout')
        return {'pos': position, 'start_x': row['y'] % space_width if space_width else 0,
                'start_y': row['y'] // space_width if space_width else 0, 'x': row['width'],
                'y': row['length'], 'space_id': row['x'],
                'rotate': bool(row.get('rotated', False))}
    return {'pos': position, 'start_x': row['x'], 'start_y': row['y'],
            'x': row['length'] if position == 2 else 1,
            'y': row['width'] if position == 2 else 1,
            'space_id': 0, 'rotate': position == 2 and bool(row.get('rotated', False))}


def _change(purchase, backend, local_session):
    props = []
    owned = {row['gid']: row for row in backend.native_lobby_profile(local_session)['props']}

    for move in purchase.get('displaced_props', []):
        before, after = move['before'], move['after']
        props.append({'change_type': 5, 'src': inventory_location(before),
                      'dest': inventory_location(after), 'delta': after['quantity'],
                      'prop': {'id': after['template_id'], 'gid': after['gid'],
                               'num': after['quantity'],
                               'position': after['grid_page_id'],
                               'length': after['length'], 'width': after['width'],
                               **item_condition_fields(after['template_id'], components=after.get('components'), weapon=after.get('weapon'), health=after.get('health')),
                               'loc': inventory_location(after)}})
    for row in purchase['props']:
        row = owned[row['gid']]
        position = row['grid_page_id']
        loc = inventory_location(row)
        prop = {'id': row['template_id'], 'gid': row['gid'],
                'num': row['quantity'], 'position': position,
                'length': row['length'], 'width': row['width'], 'loc': loc,
                **item_condition_fields(row['template_id'], components=row.get('components'), weapon=row.get('weapon'), health=row.get('health'))}
        props.append({'prop': prop, 'change_type': 1,
                      'dest': loc, 'delta': row['quantity']})
    currencies = [{
        'currency_id': purchase['currency_id'],
        'delta': purchase['currency_delta'],
        'current_num': purchase['currency_current']}]
    if purchase.get('bonus_currency_change'):
        currencies.append(purchase['bonus_currency_change'])
    from .container_layouts import position_changes
    moves = purchase.get('displaced_props', []) + [
        {'before': None, 'after': row} for row in purchase['props']]
    changes = {'prop_changes': props, 'currency_changes': currencies}
    layouts = position_changes(owned.values(), moves)
    if layouts:
        changes['pos_changes'] = layouts
    return changes


def _sell_change(sale):
    changes = []
    for entry in sale['sold']:
        before = entry['before']
        remaining = entry['remaining']
        loc = inventory_location(before)
        prop = {'id': before['template_id'], 'gid': before['gid'],
                'num': remaining if remaining else before['quantity'],
                'position': before['grid_page_id'],
                'length': before['length'], 'width': before['width'],
                'loc': loc, **item_condition_fields(before['template_id'], components=before.get('components'), weapon=before.get('weapon'), health=before.get('health'))}
        changes.append({'change_type': 3 if remaining else 2,
                        'prop': prop, 'src': loc,
                        'dest': loc if remaining else {'pos': 0},
                        'delta': -entry['sold_quantity']})
    return {'prop_changes': changes, 'currency_changes': [{
        'currency_id': sale['currency_id'], 'delta': sale['currency_delta'],
        'current_num': sale['currency_current']}]}


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
    if request.name in native_settings.SUPPORTED_REQUESTS:
        return native_settings.response_fields(request, backend, local_session)
    if request.name in local_chat.SUPPORTED_REQUESTS:
        return local_chat.response_fields(request, backend, local_session)
    if request.name == 'CSWAssemblyDepositPropUpdateReq':
        from .weapon_assembly import response_fields as assembly_response
        return assembly_response(request, backend, local_session)
    if request.name in battle_pass.SUPPORTED_REQUESTS:
        return battle_pass.response_fields(request, backend, local_session)
    pendant = weapon_pendants.response_fields(request, backend, local_session)
    if pendant is not None:
        return pendant
    name = request.name
    fields = request.fields
    profile = profile_cosmetics.response_fields(request, backend, local_session)
    if profile is not None:
        return profile
    hero = hero_customization.response_fields(request, backend, local_session)
    if hero is not None:
        return hero
    premium = premium_shop.response_fields(request, backend, local_session)
    if premium is not None:
        return premium
    cosmetic = gun_skins.response_fields(request, backend, local_session)
    if cosmetic is not None:
        return cosmetic
    lottery = mandel.response_fields(request, backend, local_session)
    if lottery is not None:
        return lottery
    catalog = stock_catalog()
    now = int(time.time())
    if name in ('CSMarketGetTypeListReq', 'CSAuctionGetTypeListReq'):
        ids = [int(v) for v in fields.get('prop_ids', [])]
        prefixes = [str(v) for v in fields.get('prop_prefixes', [])]
        browse_rows = catalog if ids else _browse_catalog()
        selected = ((item_id, row) for item_id, row in browse_rows.items()
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
    if name == 'CSAuctionAutoLoadGuidePriceReq':
        return {'result': 0, 'finish': True,
                'new_sync_digest': VERSION['ver'],
                'price_list': [{'prop_id': item_id, 'price': _price(row)}
                               for item_id, row in catalog.items()],
                'past_stable_price': bool(fields.get('past_stable_price', False))}
    if name == 'CSAuctionGetGameItemSellPriceReq':
        recycle = priced_inventory_catalog()
        ids = [int(value) for value in fields.get('prop_ids', [])]
        return {'result': 0, 'sell_props': [
            {'prop_id': item_id, 'sell_price': _price(recycle[item_id]),
             'sell_money': CURRENCY_ID, 'dynamic_price': _price(recycle[item_id]),
             'static_price': _price(recycle[item_id])}
            for item_id in ids if item_id in recycle]}
    if name == 'CSMarketGetPlayerInfoReq':
        return {'result': 0, 'is_open': True, 'max_rack_cnt': 100,
                'init_rack_cnt': 100, 'open_time': now - 86400,
                'close_time': now + 365 * 86400}
    if name == 'CSMarketGetAndUpdatePreBuyOrderReq':
        return {'result': 0, 'orders': []}
    if name == 'CSAuctionGetPlayerInfoReq':
        return {'result': 0, 'player_unlock_buy': True,
                'player_unlock_sell': True, 'max_rack_cnt': 100}
    if name == 'CSAuctionGetSaleListBatchReq':
        ids = [int(value) for value in fields.get('prop_ids', [])]
        ids.extend(int(info.get('prop_id') or 0) for info in fields.get('infos', []))
        return {'result': 0, 'auction_zone': 1,
                'sale_lists': [_auction_sale_detail(item_id, catalog[item_id], now)
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
        return {'result': 0, 'sale_list_infos': [_auction_sale_detail(item_id, row, now)],
                'auction_zone': 1}
    if name == 'CSMallGetCfgVersionReq':
        return {'result': 0, 'version_info': VERSION}
    if name == 'CSMallGetMysteryShopItemsReq':
        return {'result': 0, 'items': [], 'is_closed': True,
                'count_down_seconds': 0}
    if name == 'CSMallGetLabelNo1ConfigReq':
        result = {'result': 0, 'cfg_list': [], 'next_get_time': now + 3600}
        if 'match_info' in fields:
            result['match_info'] = fields['match_info']
        return result
    if name == 'CSMallGetRecycleGoodsReq':
        result = {'result': 0, 'recyle_props': [], 'is_finish': True,
                  'version_info': VERSION}
        if 'match_info' in fields:
            result['match_info'] = fields['match_info']
        return result
    if name == 'CSMallGetPlayerDailyLimitGoodsReq':
        return {'result': 0, 'limit_items': [], 'version_info': VERSION}
    if name == 'CSMallGetClickedExchangeIdReq':
        result = {'result': 0, 'clicked_exchange_ids': []}
        if 'match_info' in fields:
            result['match_info'] = fields['match_info']
        return result
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
    if name == 'CSMallSellReq':
        recycle = priced_inventory_catalog()
        props = fields.get('sell_props') or []
        prices = fields.get('prices') or []
        if not 1 <= len(props) <= 32 or not 1 <= len(prices) <= 32:
            return {'result': error_code('DepositInvalidReq')}
        items = []
        price_limit = 0
        for prop in props:
            item_id = int(prop.get('id') or 0)
            quantity = int(prop.get('num') or 0)
            row = recycle.get(item_id)
            if row is None:
                return {'result': error_code('DepositPropDescNotFound')}
            if not 1 <= quantity <= 1000:
                return {'result': error_code('DepositInvalidReq')}
            items.append({'template_id': item_id,
                          'gid': int(prop.get('gid') or 0), 'quantity': quantity})
            price_limit += _price(row) * quantity
        if any(int(price.get('money_type') or 0) != CURRENCY_ID or
               int(price.get('price') or 0) < 0 for price in prices):
            return {'result': error_code('DepositInvalidReq')}
        total_price = sum(int(price.get('price') or 0) for price in prices)
        if total_price > price_limit:
            return {'result': error_code('DepositInvalidReq')}
        try:
            sale = backend.native_lobby_sell(
                local_session, items=items, currency_id=CURRENCY_ID,
                total_price=total_price)
        except DomainError as error:
            return {'result': inventory_error(error)}
        return {'result': 0, 'get_moneys': prices,
                'prop_changes': _sell_change(sale), 'version_info': VERSION}
    if name == 'CSSerialCheapBuyReq':
        entries = fields.get('buy_list', [])
        if any((entry.get('auction_prop') or {}).get('assemble_info')
               or (entry.get('single_auction_prop') or {}).get('assemble_info')
               or (entry.get('mall_prop') or {}).get('assemble_info') for entry in entries):
            from .weapon_assembly import purchase_response
            return purchase_response(request, backend, local_session)
        if 1 <= len(entries) <= 32 and all(
                int(entry.get('channel') or 0) == 2
                and bool(entry.get('single_auction_prop') or entry.get('auction_prop'))
                and int((entry.get('single_auction_prop') or {}).get('to_pos') or 0)
                in (0, 2, POCKET_POSITION, CHEST_RIG_POSITION, BACKPACK_POSITION, SAFE_BOX_POSITION)
                for entry in entries):
            items = []
            for entry in entries:
                offer = entry.get('single_auction_prop') or entry['auction_prop']
                item_id = int(offer.get('prop_id') or 0)
                count = int(offer.get('buy_num') or offer.get('total_num') or 0)
                row = catalog.get(item_id)
                if row is None or not 1 <= count <= 1000:
                    return {'result': 1, 'auction_fail_list': entries}
                unit_price = _price(row)
                if (int(offer.get('currency') or 0) != CURRENCY_ID
                        or int(offer.get('price') or 0)
                        not in (unit_price, unit_price * count)):
                    return {'result': 1, 'auction_fail_list': entries}
                delivered_id, delivered_row = _delivered_stock(catalog, item_id)
                items.append({'template_id': delivered_id, 'quantity': count,
                              'unit_price': unit_price,
                              'length': delivered_row['length'],
                              'width': delivered_row['width'],
                              'max_stack_count': delivered_row['max_stack_count'],
                              'target_position': _purchase_position(offer.get('to_pos'))})
            try:
                positions = {item['target_position'] for item in items}
                if positions == {2}:
                    purchase = backend.native_lobby_purchase_warehouse_batch(
                        local_session, items=items, currency_id=CURRENCY_ID)
                else:
                    purchase = backend.native_lobby_purchase_container_batch(
                        local_session, items=items, currency_id=CURRENCY_ID)
            except DomainError as error:
                return {'result': inventory_error(error), 'auction_fail_list': entries}
            return {'result': 0, 'auction_changes': _change(purchase, backend, local_session),
                    'is_underbuy': False, 'force_buy_channel': 2}
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
            return {'result': error_code('DepositInvalidReq'), ('mall_fail_list' if channel == 'mall'
                                  else 'auction_fail_list'): entries}
        delivered_id, delivered_row = _delivered_stock(catalog, item_id)
        try:
            item = {'template_id': delivered_id, 'quantity': count,
                    'unit_price': unit_price, 'length': delivered_row['length'],
                    'width': delivered_row['width'],
                    'max_stack_count': delivered_row['max_stack_count'],
                    'target_position': target_position}
            if target_position in (POCKET_POSITION, CHEST_RIG_POSITION,
                                   BACKPACK_POSITION, SAFE_BOX_POSITION):
                purchase = backend.native_lobby_purchase_container_batch(
                    local_session, items=[item], currency_id=CURRENCY_ID)
            else:
                purchase = backend.native_lobby_purchase(
                    local_session, **item, currency_id=CURRENCY_ID)
        except DomainError as error:
            return {'result': inventory_error(error), ('mall_fail_list' if channel == 'mall'
                                  else 'auction_fail_list'): entries}
        return {'result': 0, ('mall_changes' if channel == 'mall'
                              else 'auction_changes'): _change(purchase, backend, local_session),
                'is_underbuy': False, 'force_buy_channel': int(entry.get('channel') or 0)}
    if name in ('CSMarketBuyTReq', 'CSAuctionBuyTReq', 'CSMallBuyReq'):
        if name == 'CSMallBuyReq':
            mall_prop = fields.get('mall_prop', {})
            item_id = int(mall_prop.get('prop_info', {}).get('id') or 0)
            count = int(mall_prop.get('prop_info', {}).get('num') or 1)
        else:
            item_id = int(fields.get('prop_id') or 0)
            count = int(fields.get('buy_num') or 1)
        row = catalog.get(item_id)
        if row is None:
            return {'result': error_code('DepositPropDescNotFound')}
        price = _price(row)
        if name != 'CSMallBuyReq' and (int(fields.get('price') or 0) != price
                                       or int(fields.get('currency') or 0) != CURRENCY_ID
                                       or int(fields.get('order_id') or 0) != order_id(item_id)):
            raise ValueError('Purchase does not match the local offer')
        delivered_id, delivered_row = _delivered_stock(stock_catalog(), item_id)
        try:
            purchase = backend.native_lobby_purchase(
                local_session, template_id=delivered_id, quantity=count,
                unit_price=price, currency_id=CURRENCY_ID,
                length=delivered_row['length'], width=delivered_row['width'],
                max_stack_count=delivered_row['max_stack_count'])
        except DomainError as error:
            return {'result': inventory_error(error)}
        if name == 'CSMallBuyReq':
            return {'result': 0, 'prop_changes': _change(purchase, backend, local_session),
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
        return {'result': 0, 'changes': _change(purchase, backend, local_session),
                'orders': [bought]}
    return None
