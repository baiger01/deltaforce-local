"""Real installed mission acceptance and durable local quest progress."""
from dfserver._paths import SERVER_ROOT

import json
from pathlib import Path
import sqlite3
import time

from dfserver.gateway.client_errors import error_code
from dfserver.app.core import DomainError, fail
from dfserver.progression.native_quest_rewards import SCHEMA as REWARD_SCHEMA


CATALOG = json.loads((SERVER_ROOT /
                     'protocol/native_quest_catalog.json').read_text(encoding='utf-8'))
OBJECTIVE_CATALOG = json.loads((SERVER_ROOT /
                     'protocol/native_quest_objectives.json').read_text(encoding='utf-8'))
OBJECTIVES = {row['ObjectiveID']: row for row in OBJECTIVE_CATALOG['objectives']}
QUESTS = {row['QuestID']: row for row in CATALOG['quests']}
LINES = {row['RootQuestID']: row for row in CATALOG['lines']}
# common_pb.lua actual QuestState and QuestType assignments.
STATES = CATALOG['enums']['QuestState']['values']
LOCKED, UNREAD, UNACCEPTED, ACCEPTED, COMPLETED, REWARDED = (
    STATES[name] for name in ('Locked', 'Unread', 'Unaccepted', 'Accepted', 'Completed', 'Rewarded'))
SOL_QUEST_TYPES = frozenset(CATALOG['enums']['QuestType']['values'][name]
                            for name in ('Mission', 'Branch'))
SUPPORTED_REQUESTS = frozenset({'CSQuestAcceptReq', 'CSQuestGetPlayerDataReq',
                                'CSQuestGetAcceptedQuestsReq', 'CSQuestSubmitPropReq',
                                'CSQuestCompleteReq', 'CSQuestGetRewardReq', 'CSQuestGiveUpReq'})
SCHEMA = """
CREATE TABLE IF NOT EXISTS native_lobby_quest_progress (
 player_id TEXT NOT NULL REFERENCES players(id), quest_id INTEGER NOT NULL,
 state INTEGER NOT NULL CHECK(state BETWEEN 0 AND 8), accept_time INTEGER NOT NULL DEFAULT 0,
 reward_time INTEGER NOT NULL DEFAULT 0, complete_time INTEGER NOT NULL DEFAULT 0,
 objectives_json TEXT NOT NULL DEFAULT '[]', PRIMARY KEY(player_id,quest_id));
CREATE TABLE IF NOT EXISTS native_lobby_quest_completion_overrides (
 player_id TEXT NOT NULL REFERENCES players(id), quest_id INTEGER NOT NULL,
 previous_state INTEGER NOT NULL, previous_json TEXT NOT NULL, applied_at INTEGER NOT NULL,
 PRIMARY KEY(player_id,quest_id));
""" + REWARD_SCHEMA


def load_completion_config(path=None):
    path = Path(path) if path is not None else SERVER_ROOT / 'config/quest_completion.json'
    settings = json.loads(path.read_text(encoding='utf-8'))
    keys = {'enabled', 'complete_all', 'complete_quest_ids'}
    if not isinstance(settings, dict) or set(settings) != keys:
        raise ValueError('Quest completion configuration requires exactly: ' + ', '.join(sorted(keys)))
    if any(type(settings[key]) is not bool for key in ('enabled', 'complete_all')):
        raise ValueError('Quest completion switches must be JSON booleans')
    ids = settings['complete_quest_ids']
    if (not isinstance(ids, list) or any(type(value) is not int or value not in QUESTS for value in ids)
            or len(ids) != len(set(ids))):
        raise ValueError('Completion quest IDs must be unique installed quest IDs')
    return settings


def _apply_completion_config(connection, player_id, settings, level, progress, now):
    if not settings['enabled']:
        return None
    selected = sorted(QUESTS if settings['complete_all'] else settings['complete_quest_ids'])
    if (CATALOG['mapping_status'] != 'verified_by_native_reflection_and_serialization' or
            OBJECTIVE_CATALOG['mapping_status'] != 'verified_by_native_reflection_and_serialization'):
        fail('QuestObjectiveConfigInvalid', 'Original quest/objective bindings are unavailable')
    previous, completed = [], []
    for quest_id in selected:
        saved = progress.get(quest_id)
        state = saved['state'] if saved else _default_state(QUESTS[quest_id], level, progress, now)
        if state in (COMPLETED, REWARDED):
            continue
        previous.append(_data(quest_id, state, saved))
        existing = {row['quest_objective_id']: row for row in json.loads(
            saved['objectives_json'] if saved else '[]')}
        objectives = [{**existing.get(value, {'quest_objective_id': value,
                       'has_marked': False, 'spent_seconds': 0, 'choice': 0}),
                       'value': max(existing.get(value, {}).get('value', 0), OBJECTIVES[value]['RequiredCount']),
                       'has_completed': True}
                      for value in QUESTS[quest_id]['ObjectiveList']]
        connection.execute('INSERT OR IGNORE INTO native_lobby_quest_completion_overrides '
            '(player_id,quest_id,previous_state,previous_json,applied_at) VALUES (?,?,?,?,?)',
            (player_id, quest_id, state, json.dumps(previous[-1]), now))
        connection.execute('INSERT INTO native_lobby_quest_progress '
            '(player_id,quest_id,state,accept_time,complete_time,objectives_json) VALUES (?,?,?,?,?,?) '
            'ON CONFLICT(player_id,quest_id) DO UPDATE SET state=excluded.state, '
            'complete_time=excluded.complete_time,objectives_json=excluded.objectives_json',
            (player_id, quest_id, COMPLETED, saved['accept_time'] if saved else now,
             now, json.dumps(objectives)))
        record = dict(connection.execute('SELECT * FROM native_lobby_quest_progress '
            'WHERE player_id=? AND quest_id=?', (player_id, quest_id)).fetchone())
        progress[quest_id] = record
        completed.append(_data(quest_id, COMPLETED, record))
    return {'player_quests': completed, 'quest_data_pre': previous} if completed else None


def _progress(connection, player_id):
    return {row['quest_id']: dict(row) for row in connection.execute(
        'SELECT * FROM native_lobby_quest_progress WHERE player_id=?', (player_id,))}


def _lines(quest_id, visited=None):
    visited = set() if visited is None else visited
    if quest_id in visited:
        fail('QuestCheckFailed', 'Source quest prerequisite graph contains a cycle')
    if quest_id in LINES:
        return [LINES[quest_id]]
    visited = visited | {quest_id}
    result = []
    for predecessor in QUESTS[quest_id]['PreviousIDList']:
        result.extend(_lines(predecessor, visited))
    return result


def _eligible(quest, level, progress, now):
    if quest['QuestType'] not in SOL_QUEST_TYPES:
        fail('QuestCheckFailed', 'This specialised quest requires another verified acceptance path')
    if quest['ShowCondition'] or quest['QuestConditionIDArray'] or quest['SpecialType'] or quest['IsContract']:
        fail('QuestShowConditionNotOK', 'Source quest has an additional eligibility condition')
    if level < quest['AcceptRequiredLevel']:
        fail('QuestLevelNotEnough', 'Owned season level is below the source quest requirement')
    lines = _lines(quest['QuestID'])
    if not lines or any(line['SeasonId'] or level < line['OpenLevel'] for line in lines):
        fail('QuestLineNotOpen', 'Source mission line is not available to this local account')
    for line in lines:
        if any(progress.get(value, {}).get('state', LOCKED) < COMPLETED for value in line['OpenLimits']):
            fail('QuestLineNotOpen', 'Native quest-line completion limits are not satisfied')
    predecessors = [progress.get(value, {}) for value in quest['PreviousIDList']]
    if any(row.get('state', LOCKED) < REWARDED for row in predecessors):
        fail('QuestPreviousQuestIsNotCompleted', 'Every original prerequisite must have its reward claimed')
    reward_time = max((row.get('reward_time', 0) for row in predecessors), default=0)
    if reward_time > 0 and reward_time + quest['FrozenTimeAfterPreQuestReward'] * 60 > now:
        fail('QuestCheckFailed', 'Original post-prerequisite acceptance delay is active')


def _default_state(quest, level, progress, now):
    try:
        _eligible(quest, level, progress, now)
        return UNACCEPTED
    except DomainError:
        return LOCKED


def _data(quest_id, state, saved=None):
    saved = saved or {}
    return {'quest_id': quest_id, 'quest_state': state,
            'quest_accept_time': saved.get('accept_time', 0),
            'quest_objectives': json.loads(saved.get('objectives_json', '[]')),
            'quest_var': [], 'marked_objective_id': [], 'expire_time': 0,
            'enter_map_info': [], 'event_occur_info': [],
            'reward_time': saved.get('reward_time', 0), 'complete_time': saved.get('complete_time', 0)}


def _objective_states(quest, saved):
    records = json.loads(saved['objectives_json'])
    by_id = {row['quest_objective_id']: row for row in records}
    if len(by_id) != len(records) or set(by_id) != set(quest['ObjectiveList']):
        fail('QuestObjectiveConfigInvalid', 'Persisted objectives differ from the original quest')
    if any(value not in OBJECTIVES for value in by_id):
        fail('QuestObjectiveConfigInvalid', 'An objective is absent from the installed table')
    return by_id


def _finished(quest, objectives):
    required = [value for value in quest['ObjectiveList'] if OBJECTIVES[value]['ShouldMustBeCompleted']]
    if not required:
        required = quest['ObjectiveList']
    return bool(required) and all(objectives[value].get('has_completed') and
        objectives[value].get('value', 0) >= OBJECTIVES[value]['RequiredCount'] for value in required)


def _submit(connection, player_id, quest, objectives, fields):
    entries = fields.get('submit_list', [])
    if fields.get('submit_prop_list'):
        if entries or len(quest['ObjectiveList']) != 1:
            fail('QuestSubmitPropsNotValid', 'Legacy submissions require one unambiguous original objective')
        entries = [{'obj_id': quest['ObjectiveList'][0], 'submit_props': fields['submit_prop_list']}]
    if not entries:
        fail('QuestEmptyArgList', 'The submission contains no objective')
    seen_objectives, seen_props = set(), set()
    kinds = OBJECTIVE_CATALOG['enums']['QuestObjectiveType']['values']
    for entry in entries:
        objective_id = int(entry.get('obj_id') or 0)
        if objective_id in seen_objectives:
            fail('QuestRepeatedInReq', 'The same objective occurs twice in a submission')
        seen_objectives.add(objective_id)
        if objective_id not in objectives:
            fail('QuestObjectiveNotExist', 'Objective does not belong to this accepted quest')
        source, progress = OBJECTIVES[objective_id], objectives[objective_id]
        if progress.get('has_completed'):
            fail('QuestObjHasBeenFinished', 'This objective has already been submitted')
        if (source['ConditionIDArray'] or source['IsComplexPropObjective'] or
                source['IsComplexWeaponObjective'] or source['Type'] != kinds['Submit']):
            fail('QuestObjectiveConfigInvalid', 'This objective needs another source-bound submission predicate')
        predecessor = source['PrerequestObjectiveID']
        if predecessor and not objectives.get(predecessor, {}).get('has_completed'):
            fail('QuestNotCompleted', 'The original prerequisite objective has not been completed')
        target = int(source['Param1'])
        remaining = source['RequiredCount'] - int(progress.get('value', 0))
        props = entry.get('submit_props', [])
        if not props or remaining <= 0:
            fail('QuestEmptyArgList', 'The submission contains no required quantity')
        total = sum(int(prop.get('num') or 0) for prop in props)
        if any(int(prop.get('num') or 0) <= 0 for prop in props) or total > remaining:
            fail('QuestSubmitPropsNotValid', 'Submitted quantity must be positive and no more than the remaining requirement')
        if source['Type'] == kinds['Submit']:
            required_binding = int(source['Param2']) if source['Param2'] else -1
            for prop in props:
                gid, quantity = int(prop.get('gid') or 0), int(prop['num'])
                if not 0 < gid < 2**63:
                    fail('QuestSubmitPropsNotValid', 'Submitted instance is outside the local saved ID range')
                if gid in seen_props:
                    fail('QuestRepeatedInReq', 'A physical instance occurs more than once in the submission')
                seen_props.add(gid)
                owned = connection.execute('SELECT * FROM native_lobby_props WHERE player_id=? AND gid=?',
                                           (player_id, gid)).fetchone()
                if owned is not None:
                    from dfserver.inventory.native_warehouse_extensions import require_uninstalled_box
                    require_uninstalled_box(connection, player_id, gid)
                if (owned is None or owned['template_id'] != target or int(prop.get('id') or 0) != target or
                        (int(prop.get('position') or 0) not in (0, owned['grid_page_id']))):
                    fail('QuestCheckPropFailed', 'Submitted physical instance does not match owned source item')
                if quantity > owned['quantity']:
                    fail('QuestDepositPropNumNotEnough', 'Owned physical instance quantity is insufficient')
                from dfserver.inventory.native_prop_bindings import binding
                if required_binding >= 0 and binding(connection, gid)[0] != required_binding:
                    fail('QuestCheckPropFailed', 'Owned binding does not satisfy the original objective')
                if source['ListParam']:
                    from dfserver.weapons.weapon_components import ROWS
                    if (str(target) not in ROWS or OBJECTIVE_CATALOG.get('simple_submit_component_policy') !=
                            'require_each_ListParam_template_in_owned_weapon_tree'):
                        fail('QuestObjectiveConfigInvalid', 'Submission component predicate has no verified source')
                    equipped = {row[0] for row in connection.execute(
                        'SELECT template_id FROM native_lobby_weapon_parts WHERE weapon_gid=?', (gid,))}
                    if not set(source['ListParam']).issubset(equipped):
                        fail('QuestCheckPropFailed', 'Owned weapon lacks an original required component')
                if owned['grid_page_id'] in (107, 108, 109, 116):
                    fail('QuestSubmitPropsNotValid', 'Move carrying equipment to the warehouse before submitting it')
                if quantity == owned['quantity']:
                    connection.execute('DELETE FROM native_lobby_props WHERE player_id=? AND gid=?', (player_id, gid))
                else:
                    connection.execute('UPDATE native_lobby_props SET quantity=quantity-? WHERE player_id=? AND gid=?',
                                       (quantity, player_id, gid))
        progress['value'] = int(progress.get('value', 0)) + total
        progress['has_completed'] = progress['value'] >= source['RequiredCount']


def _mutate_progress(request, backend, connection, player_id, quest, saved, now, changes):
    if saved is None:
        fail('QuestNotAccepted', 'This local account has not accepted the quest')
    quest_id = quest['QuestID']
    if saved['state'] in (COMPLETED, REWARDED):
        if saved['state'] == COMPLETED and request.name == 'CSQuestCompleteReq':
            return {'result': 0, 'quest_id': quest_id, 'quest_state': COMPLETED}
        fail('QuestAlreadyCompleted', 'This quest has already been completed')
    if saved['state'] != ACCEPTED:
        fail('QuestStateInvalid', 'Only an accepted quest can receive ordinary progress')
    if quest['QuestType'] not in SOL_QUEST_TYPES:
        fail('QuestCheckFailed', 'Specialised quest progress requires its own verified path')
    objectives = _objective_states(quest, saved)
    before = _data(quest_id, saved['state'], saved)
    inventory_before, currencies_before = {}, {}
    if request.name == 'CSQuestSubmitPropReq':
        from dfserver.progression.native_safehouse import _snapshot
        inventory_before = _snapshot(backend, connection, player_id)
        currencies_before = dict(connection.execute('SELECT currency_id,amount FROM native_lobby_currencies '
                                                    'WHERE player_id=?', (player_id,)).fetchall())
        _submit(connection, player_id, quest, objectives, request.fields)
    complete = _finished(quest, objectives)
    if request.name == 'CSQuestCompleteReq' and not complete:
        fail('QuestNotCompleted', 'Persisted objective proof does not satisfy the original requirements')
    state = COMPLETED if complete else ACCEPTED
    connection.execute('UPDATE native_lobby_quest_progress SET state=?,complete_time=?,objectives_json=? '
        'WHERE player_id=? AND quest_id=?', (state, now if complete else 0,
        json.dumps([objectives[value] for value in quest['ObjectiveList']]), player_id, quest_id))
    after = _data(quest_id, state, dict(connection.execute('SELECT * FROM native_lobby_quest_progress '
        'WHERE player_id=? AND quest_id=?', (player_id, quest_id)).fetchone()))
    changes['quest_notification'] = {'player_quests': [after], 'quest_data_pre': [before]}
    if request.name == 'CSQuestSubmitPropReq':
        inventory_after = _snapshot(backend, connection, player_id)
        changes['inventory_moves'] = [{'before': inventory_before.get(gid), 'after': inventory_after.get(gid)}
            for gid in sorted(inventory_before.keys() | inventory_after.keys())
            if inventory_before.get(gid) != inventory_after.get(gid)]
        currencies_after = dict(connection.execute('SELECT currency_id,amount FROM native_lobby_currencies '
                                                   'WHERE player_id=?', (player_id,)).fetchall())
        changes['currency_changes'] = [{'currency_id': currency, 'delta': amount - currencies_before.get(currency, 0),
                                       'current_num': amount} for currency, amount in currencies_after.items()
                                       if amount != currencies_before.get(currency, 0)]
    result = {'result': 0, 'quest_id': quest_id, 'quest_state': state}
    if request.name == 'CSQuestSubmitPropReq':
        result['player_quest'] = after
    return result


def response_fields(request, backend, token, *, changes=None, diagnostic=None):
    if request.name not in SUPPORTED_REQUESTS:
        return None
    giving_up = request.name == 'CSQuestGiveUpReq'
    result_key = 'res' if giving_up else 'result'
    writing = request.name in ('CSQuestAcceptReq', 'CSQuestSubmitPropReq', 'CSQuestCompleteReq',
                               'CSQuestGetRewardReq', 'CSQuestGiveUpReq')
    applying = request.name == 'CSQuestGetPlayerDataReq' and backend.quest_completion['enabled']
    from dfserver.progression.native_quest_conditions import refresh, merge_notifications
    try:
        with backend.connection() as connection:
            connection.execute('BEGIN IMMEDIATE')
            player_id = backend._authorize(connection, token)
            row = connection.execute('SELECT level FROM native_lobby_levels WHERE player_id=?', (player_id,)).fetchone()
            level, now = row['level'] if row is not None else 1, int(time.time())
            progress = _progress(connection, player_id)
            notification = (_apply_completion_config(connection, player_id, backend.quest_completion,
                level, progress, now) if applying else None)
            override_count = len(notification['player_quests']) if notification else 0
            notification = merge_notifications(notification, refresh(connection, player_id, now, progress))
            if request.name == 'CSQuestGetAcceptedQuestsReq':
                # MatchServer.RequestAcceptedQuests forwards these exact records
                # and objectives to LuaAddSOLQuest during map preparation.
                result = {'result': 0, 'accepted_quests': [
                    _data(quest_id, ACCEPTED, progress[quest_id])
                    for quest_id, quest in QUESTS.items()
                    if quest['QuestType'] in SOL_QUEST_TYPES and quest_id in progress
                    and progress[quest_id]['state'] == ACCEPTED]}
                connection.commit()
                if changes is not None and notification:
                    changes['quest_notification'] = notification
                return result
            if not writing:
                result = {'result': 0, 'lobby_server_time': now,
                        'player_quests': [_data(quest_id, progress[quest_id]['state'], progress[quest_id])
                            if quest_id in progress else _data(quest_id, _default_state(quest, level, progress, now))
                            for quest_id, quest in QUESTS.items()]}
                connection.commit()
                if changes is not None and notification:
                    changes['quest_notification'] = notification
                    if override_count:
                        changes['quest_completion_override_count'] = override_count
                return result
            if CATALOG['mapping_status'] != 'verified_by_native_reflection_and_serialization':
                fail('QuestCheckFailed', 'Native quest bindings are unavailable')
            quest_id = int(request.fields.get('remove_quest_id' if giving_up else 'quest_id') or 0)
            quest = QUESTS.get(quest_id)
            if quest is None:
                fail('QuestNotExist', 'Quest ID is absent from the installed source table')
            saved = progress.get(quest_id)
            if request.name != 'CSQuestAcceptReq':
                committed = {}
                if request.name == 'CSQuestGetRewardReq':
                    from dfserver.progression.native_quest_rewards import claim
                    result = claim(backend, connection, player_id, quest, saved, now, committed)
                elif giving_up:
                    from dfserver.progression.native_quest_abandon import give_up
                    result = give_up(connection, player_id, quest, saved, now, committed)
                else:
                    result = _mutate_progress(request, backend, connection, player_id, quest, saved, now, committed)
                notification = merge_notifications(notification, committed.get('quest_notification'),
                    refresh(connection, player_id, now, _progress(connection, player_id)))
                if notification:
                    committed['quest_notification'] = notification
                connection.commit()
                if changes is not None:
                    changes.update(committed)
                return result
            state = saved['state'] if saved else _default_state(quest, level, progress, now)
            if state == ACCEPTED:
                fail('QuestAlreadyAccepted', 'This local player has already accepted the actual quest')
            if state in (COMPLETED, REWARDED):
                fail('QuestAlreadyCompleted', 'This local player has already finished the actual quest')
            _eligible(quest, level, progress, now)
            if saved and state not in (UNREAD, UNACCEPTED):
                fail('QuestStateInvalid', 'Persisted native quest state does not permit acceptance')
            previous = _data(quest_id, state, saved)
            objectives = [{'quest_objective_id': value, 'has_completed': False, 'value': 0,
                           'has_marked': False, 'spent_seconds': 0, 'choice': 0}
                          for value in quest['ObjectiveList']]
            connection.execute('INSERT INTO native_lobby_quest_progress '
                '(player_id,quest_id,state,accept_time,objectives_json) VALUES (?,?,?,?,?) '
                'ON CONFLICT(player_id,quest_id) DO UPDATE SET state=excluded.state, '
                'accept_time=excluded.accept_time,objectives_json=excluded.objectives_json',
                (player_id, quest_id, ACCEPTED, now, json.dumps(objectives)))
            saved = {'accept_time': now, 'objectives_json': json.dumps(objectives),
                     'reward_time': saved['reward_time'] if saved else 0,
                     'complete_time': saved['complete_time'] if saved else 0}
            notification = merge_notifications(notification,
                {'player_quests': [_data(quest_id, ACCEPTED, saved)], 'quest_data_pre': [previous]},
                refresh(connection, player_id, now, _progress(connection, player_id)))
            connection.commit()
        if changes is not None:
            changes['quest_notification'] = notification
        current_state = next(row['quest_state'] for row in notification['player_quests']
                             if row['quest_id'] == quest_id)
        return {'result': 0, 'quest_id': quest_id, 'quest_state': current_state}
    except DomainError as error:
        if diagnostic is not None:
            diagnostic['local_activity_error'] = {'code': error.code, 'message': error.message}
        mapped = {'INSUFFICIENT_FUNDS': 'QuestDepositPropNumNotEnough',
                  'WAREHOUSE_FULL': 'QuestRewardPropFailed',
                  'DepositExtensionOperInvalid': 'QuestSubmitPropsNotValid',
                  'SafehouseInvalidFormula': 'QuestRewardPropFailed'}
        return {result_key: error_code(error.code if error.code.startswith('Quest') else
                                       mapped.get(error.code, 'QuestFetchDBFailed'))}
    except (sqlite3.Error, ValueError, TypeError, KeyError) as error:
        if diagnostic is not None:
            diagnostic['local_activity_error'] = {'code': type(error).__name__, 'message': str(error)}
        return {result_key: error_code('QuestSaveDBFailed')}
