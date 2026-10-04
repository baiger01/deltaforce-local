"""Recover native premium-store records from read-only client PAK exports."""

import json
from pathlib import Path
import re
import struct

from extract_cosmetic_catalogs import export, PAK, PROTOCOL


def string(value):
    if value == 0:
        return ''
    raw = bytes.fromhex(value)
    length = struct.unpack_from('<i', raw)[0]
    if length <= 0 or len(raw) != length + 4 or raw[-1:] != b'\0':
        raise ValueError('Expected a serialized client FString')
    return raw[4:-1].decode('utf-8')


def items(value, priced=False):
    result = []
    text = string(value)
    if not text:
        return result
    groups = re.findall(r'\{([^{}]+)\}', text) or [text]
    for group in groups:
        parts = group.split(',')
        ids = [int(part) for part in parts[0].split('-')]
        count = int(parts[1]) if len(parts) > 1 else 1
        item = {'id': ids[0], 'num': count}
        if priced:
            item.update(dis_price=int(parts[2]), price=int(parts[3]))
        if len(ids) > 1:
            item['item_list'] = [{'id': item_id, 'gid': 0, 'num': count} for item_id in ids]
        result.append(item)
    return result


def main():
    sources = {}
    tables = {}
    for name, entry in [('recommendations', 7142), ('gifts', 7156),
                        ('lotteries', 7152), ('lottery_rewards', 6774),
                        ('fashion_links', 6394), ('tabs', 7154)]:
        tables[name], sources[name] = export(entry)
    recommendations = []
    for row in tables['recommendations']:
        f = row['fields']
        recommendations.append({'tab_id': f[301], 'banner_type': f[259],
            'SortIndex': f[296],
            'bundle_currency_type': f[261], 'bundle_price': f[267],
            'disbundle_price': f[263], 'bundle_item_list': items(f[262], True),
            'jump_to': string(f[282]),
            'IamgeSourceSmall_CDN': string(f[274]),
            'IamgeSourceBig_CDN': string(f[272]),
            'ImageSourceLogo_CDN_CN': string(f[276]),
            'ImageSourceLogo_CDN_EN': string(f[277]),
            'preview_asset': string(f[273]), 'row': row['row'], 'offset': row['offset']})
    gifts = []
    for row in tables['gifts']:
        f = row['fields']
        gifts.append({'goods_id': f[77], 'goods_type': f[78], 'Sortindex': f[103],
            'currency_type': f[69], 'price': f[98], 'price_pre_dis': f[99],
            'is_cash': f[85], 'limit_type': f[89], 'limit_amount': f[88],
            'midas_product_id': string(f[73]),
            'google_item_id': string(f[74]),
            'bundle_item_list': items(f[86]), 'online_time_text': string(f[95]),
            'offline_time_text': string(f[94]), 'row': row['row'], 'offset': row['offset']})
    lotteries = [{'lottery_id': r['fields'][106], 'lottery_type': r['fields'][112],
                  'lottery_key_id': r['fields'][108], 'row': r['row'], 'offset': r['offset']}
                 for r in tables['lotteries'] if r['fields'][112] == 3]
    rewards = []
    for row in tables['lottery_rewards']:
        f = row['fields']
        rewards.append({'num_id': f[81], 'source_row_id': f[73],
            'lottery_id': f[78], 'sort_index': f[81],
            'raw_cost': f[69], 'raw_weight': f[72],
            'props': [{'id': int(value), 'gid': 0, 'num': 1}
                      for value in string(f[86]).split(',')],
            'preview_id': f[91], 'is_great_reward': bool(f[77]),
            'row': row['row'], 'offset': row['offset']})
    fashions = [{'fashion_id': r['fields'][112], 'hero_id': r['fields'][113],
                 'row': r['row'], 'offset': r['offset']} for r in tables['fashion_links']]
    tabs = [{'tab_id': r['fields'][18], 'name': string(r['fields'][35]),
             'row': r['row'], 'offset': r['offset']} for r in tables['tabs']]
    report = {'source_pak': PAK, 'sources': sources,
        'client_consumers': ['StoreServer.lua 0.0, 0.126, 0.146, 0.169.0',
            'StoreMallGiftItem.lua 0.1, 0.2', 'StoreRecommendItem.lua',
            'StoreLotteryProbDistributionItem.lua 0.1, 0.2',
            'StaffLotteryMainUI.lua 0.10, 0.26, 0.27', 'HeroHelperTool.lua 0.148'],
        'limitations': 'Encrypted name maps are unavailable. Costs and weights retain raw indices; local rotation and without-replacement draws are diagnostic policy, not a recovered live official schedule or probability service.',
        'recommendations': recommendations, 'gifts': gifts, 'lotteries': lotteries,
        'lottery_rewards': rewards, 'fashion_links': fashions, 'tabs': tabs}
    (PROTOCOL / 'premium_shop_catalog.json').write_text(
        json.dumps(report, ensure_ascii=True, indent=2) + '\n', encoding='utf-8')
    print({name: len(report[name]) for name in tables})


if __name__ == '__main__':
    main()
