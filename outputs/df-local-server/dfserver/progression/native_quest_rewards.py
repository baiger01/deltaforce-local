"""Atomic installed quest rewards with durable per-source-row receipts."""

import json

from dfserver.app.core import fail
from dfserver.progression import native_action_progress
from dfserver.progression import native_departments


SCHEMA = native_departments.SCHEMA + """
CREATE TABLE IF NOT EXISTS native_lobby_quest_reward_receipts (
 player_id TEXT NOT NULL REFERENCES players(id), quest_id INTEGER NOT NULL,
 reward_id INTEGER NOT NULL, reward_type INTEGER NOT NULL, item_id INTEGER NOT NULL,
 quantity INTEGER NOT NULL CHECK(quantity>0), granted_at INTEGER NOT NULL,
 receipt_json TEXT NOT NULL, PRIMARY KEY(player_id,quest_id,reward_id));
"""


def claim(backend, connection, player_id, quest, saved, now, changes):
    from dfserver.progression.native_quests import CATALOG, OBJECTIVE_CATALOG, COMPLETED, REWARDED, SOL_QUEST_TYPES, _data
    from dfserver.progression.native_safehouse import _grant_products, _snapshot
    from dfserver.commerce.premium_shop import ITEMS, currency_change, grant
    from dfserver.cosmetics import hero_customization

    if saved is None or saved['state'] != COMPLETED:
        fail('QuestAlreadyReward' if saved and saved['state'] == REWARDED else 'QuestNotCompleted',
             'Only this account\'s completed quest can be claimed once')
    if quest['QuestType'] not in SOL_QUEST_TYPES:
        fail('QuestCheckFailed', 'Specialised rewards require their own verified grant path')
    if len(quest['RewardList']) != len(set(quest['RewardList'])):
        fail('QuestRewardIDNotExist', 'Duplicate reward source row')
    rewards = {row['RewardID']: row for row in CATALOG['rewards']}
    kinds = OBJECTIVE_CATALOG['enums']['QuestRewardType']['values']
    inventory_before = _snapshot(backend, connection, player_id)
    changes.update(currency_changes=[], prop_changes=[], department_scores=[], quality_changes=[],
                   action_exp_changes=[])
    before = _data(quest['QuestID'], COMPLETED, saved)
    for reward_id in quest['RewardList']:
        reward = rewards.get(reward_id)
        if reward is None or type(reward['Number']) is not int or reward['Number'] <= 0:
            fail('QuestRewardIDNotExist', 'Reward source row or positive quantity is unavailable')
        if connection.execute('SELECT 1 FROM native_lobby_quest_reward_receipts '
                'WHERE player_id=? AND quest_id=? AND reward_id=?',
                (player_id, quest['QuestID'], reward_id)).fetchone():
            fail('QuestAlreadyReward', 'This source reward already has a durable receipt')
        item_id, count, kind = reward['ItemID'], reward['Number'], reward['Type']
        if kind == kinds['RewardProp']:
            if str(item_id) not in ITEMS:
                fail('QuestRewardPropFailed', 'Reward item is absent from the installed item table')
            receipt = _grant_products(backend, connection, player_id,
                [{'prop_id': item_id, 'num': count, 'bind_type': reward['bindType']}], preserve_binding=True)
        elif kind == kinds['RewardCurrency']:
            if not ITEMS.get(str(item_id), {}).get('is_currency'):
                fail('QuestAddCurrencyFailed', 'Reward does not name an installed currency')
            receipt = currency_change(connection, player_id, item_id, count)
            changes['currency_changes'].append(receipt)
        elif kind == kinds['RewardExp']:
            if item_id != OBJECTIVE_CATALOG['role_exp_item_id']:
                fail('QuestAddExpFailed', 'Reward is not the original role EXP template')
            previous = connection.execute('SELECT xp FROM players WHERE id=?', (player_id,)).fetchone()[0]
            if previous + count >= 2**63:
                fail('QuestAddExpFailed', 'Role EXP balance limit')
            try:
                action = native_action_progress.grant(connection, player_id, count, now=now)
            except ValueError as error:
                fail('QuestAddExpFailed', str(error))
            connection.execute('UPDATE players SET xp=xp+? WHERE id=?', (count, player_id))
            receipt = {'previous_exp': previous, 'exp': previous + count, 'add_exp': count,
                       'action_progress': action}
            changes['action_exp_changes'].append(action)
        elif kind == kinds['RewardQualityValue']:
            receipt = native_departments.grant_reward(connection, player_id, quest['QuestID'], reward)
            changes['department_scores'].append(receipt)
            changes['quality_changes'].append(native_departments.quality_change(receipt))
        elif kind in (kinds['RewardCollection'], kinds['RewardHero']):
            if str(item_id) not in ITEMS or ITEMS[str(item_id)].get('length'):
                fail('QuestRewardPropFailed', 'Collection reward lacks a verified nonphysical item mapping')
            if kind == kinds['RewardHero'] and not hero_customization.affected_heroes(item_id):
                fail('QuestRewardPropFailed', 'Hero reward has no original fashion/accessory relation')
            previous_count = len(changes['prop_changes'])
            grant(connection, player_id, [{'id': item_id, 'num': count}], changes)
            receipt = changes['prop_changes'][previous_count:]
        else:
            fail('QuestRewardPropFailed', 'This source reward type requires another verified grant path')
        connection.execute('INSERT INTO native_lobby_quest_reward_receipts VALUES (?,?,?,?,?,?,?,?)',
            (player_id, quest['QuestID'], reward_id, kind, item_id, count, now, json.dumps(receipt)))
    heroes = {hero for row in changes['prop_changes'] for hero in
              hero_customization.affected_heroes(row['prop']['id']) if row['delta'] > 0}
    if heroes:
        changes['hero_notification'] = {'heros': [hero_customization.hero_record(connection, player_id, hero)
                                                 for hero in sorted(heroes)]}
    connection.execute('UPDATE native_lobby_quest_progress SET state=?,reward_time=? '
        'WHERE player_id=? AND quest_id=?', (REWARDED, now, player_id, quest['QuestID']))
    record = dict(connection.execute('SELECT * FROM native_lobby_quest_progress '
        'WHERE player_id=? AND quest_id=?', (player_id, quest['QuestID'])).fetchone())
    changes['quest_notification'] = {'player_quests': [_data(quest['QuestID'], REWARDED, record)],
                                     'quest_data_pre': [before]}
    inventory_after = _snapshot(backend, connection, player_id)
    changes['inventory_moves'] = [{'before': inventory_before.get(gid), 'after': inventory_after.get(gid)}
        for gid in sorted(inventory_before.keys() | inventory_after.keys())
        if inventory_before.get(gid) != inventory_after.get(gid)]
    from dfserver.gateway.handshake_diagnostic import _native_inventory_changes
    deposit = _native_inventory_changes(changes['inventory_moves'])
    deposit['currency_changes'] = changes['currency_changes']
    return {'result': 0, 'quest_id': quest['QuestID'], 'quest_state': REWARDED,
            'is_send_prop_by_mail': False, 'is_currency_sent_by_mail': False,
            'is_collection_send_by_mail': False, 'deposit_change': deposit}
