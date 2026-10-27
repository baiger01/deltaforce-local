"""Evaluate accepted currency and level objectives from local account standing.

Original QuestObjectiveRow types 21/6 bind card/facility IDs and RequiredCount.
QuestObjectiveStruct copies server value and completion; the server evaluator
is unavailable. Comparing owned level >= RequiredCount is a local reconstruction,
not extracted server code. Reproducible witnesses and hashes are in
work/evidence/native-quest-standing-contract-20261019.json.
QuestStruct 0.8 only adds Type1 Submit to the native manual submission list.
Type2 Currency uses the actual wallet without spending. Evidence and remaining
server-evaluator limits: native-quest-cash-contract-20261020.json.
"""

import json

from dfserver.app.core import fail


def merge_notifications(*notifications):
    before, after = {}, {}
    for notification in notifications:
        if notification:
            for row in notification.get('quest_data_pre', []):
                before.setdefault(row['quest_id'], row)
            for row in notification.get('player_quests', []):
                after[row['quest_id']] = row
    return {'player_quests': list(after.values()), 'quest_data_pre': list(before.values())} if after else None


def refresh(connection, player_id, now, progress, *, only_currency=False):
    from dfserver.progression import native_quests as quests
    from dfserver.progression import native_departments
    from dfserver.progression import native_department_queries
    from dfserver.progression.native_safehouse_progress import UPGRADES, finish_due

    kinds = quests.OBJECTIVE_CATALOG['enums']['QuestObjectiveType']['values']
    reputation, facility, currency = (kinds['ReputationLevel'], kinds['UpgradeSafehouseDeviceLevel'],
                                    kinds['Currency'])
    standing_types = (currency,) if only_currency else (reputation, facility, currency)
    curve, notices = None, []
    if not only_currency:
        finish_due(connection, player_id, now)
    for quest_id, saved in list(progress.items()):
        quest = quests.QUESTS.get(quest_id)
        if (saved['state'] != quests.ACCEPTED or quest is None
                or quest['QuestType'] not in quests.SOL_QUEST_TYPES):
            continue
        if not any(quests.OBJECTIVES[value]['Type'] in standing_types
                   for value in quest['ObjectiveList']):
            continue
        objectives = quests._objective_states(quest, saved)
        previous = quests._data(quest_id, saved['state'], saved)
        for objective_id in quest['ObjectiveList']:
            source, owned = quests.OBJECTIVES[objective_id], objectives[objective_id]
            if source['Type'] not in standing_types:
                continue
            if (source['ConditionIDArray'] or source['PrerequestObjectiveID']
                    or source['IsComplexPropObjective'] or source['IsComplexWeaponObjective']):
                fail('QuestObjectiveConfigInvalid', 'Standing objective has an unrecovered additional predicate')
            ident = int(source['Param1'])
            if source['Type'] == reputation:
                if source['Param2'] or ident not in native_departments.DEPARTMENTS:
                    fail('QuestObjectiveConfigInvalid', 'Standing objective lacks an original card binding')
                if curve is None:
                    try:
                        curve = native_department_queries.reputation_curve()
                    except (OSError, ValueError, TypeError):
                        fail('QuestObjectiveConfigInvalid', 'A verified reputation curve is required')
                row = connection.execute('SELECT value FROM native_lobby_department_values '
                    'WHERE player_id=? AND quality_id=?', (player_id, ident)).fetchone()
                current_value = curve.level_for(row['value'] if row else 0)
            elif source['Type'] == facility:
                if source['Param2'] != str(source['RequiredCount']):
                    fail('QuestObjectiveConfigInvalid', 'Facility objective target disagrees with its source count')
                row = connection.execute('SELECT level FROM native_lobby_devices '
                    'WHERE player_id=? AND device_id=?', (player_id, ident)).fetchone()
                current_value = row['level'] if row else 0
                if current_value and (ident, current_value) not in UPGRADES:
                    fail('QuestObjectiveConfigInvalid', 'Saved facility level is outside the original table')
            else:
                from dfserver.commerce.premium_shop import ITEMS
                if source['Param2'] or source['ListParam'] or not ITEMS.get(str(ident), {}).get('is_currency'):
                    fail('QuestObjectiveConfigInvalid', 'Currency objective lacks its original wallet binding')
                row = connection.execute('SELECT amount FROM native_lobby_currencies '
                    'WHERE player_id=? AND currency_id=?', (player_id, ident)).fetchone()
                current_value = row['amount'] if row else 0
            owned.update(value=current_value, has_completed=current_value >= source['RequiredCount'])
        state = quests.COMPLETED if quests._finished(quest, objectives) else quests.ACCEPTED
        updated = dict(saved, state=state, complete_time=now if state == quests.COMPLETED else 0,
            objectives_json=json.dumps([objectives[value] for value in quest['ObjectiveList']]))
        after = quests._data(quest_id, state, updated)
        if after == previous:
            continue
        connection.execute('UPDATE native_lobby_quest_progress SET state=?,complete_time=?,objectives_json=? '
            'WHERE player_id=? AND quest_id=?',
            (state, updated['complete_time'], updated['objectives_json'], player_id, quest_id))
        progress[quest_id] = updated
        notices.append({'player_quests': [after], 'quest_data_pre': [previous]})
    return merge_notifications(*notices)
