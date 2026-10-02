"""Real installed mission acceptance and durable local quest progress."""

import json
from pathlib import Path
import sqlite3
import time

from .client_errors import error_code
from .core import DomainError, fail


CATALOG = json.loads((Path(__file__).resolve().parent.parent /
                     'protocol/native_quest_catalog.json').read_text(encoding='utf-8'))
QUESTS = {row['QuestID']: row for row in CATALOG['quests']}
LINES = {row['RootQuestID']: row for row in CATALOG['lines']}
# common_pb.lua actual QuestState and QuestType assignments.
STATES = CATALOG['enums']['QuestState']['values']
LOCKED, UNREAD, UNACCEPTED, ACCEPTED, COMPLETED, REWARDED = (
    STATES[name] for name in ('Locked', 'Unread', 'Unaccepted', 'Accepted', 'Completed', 'Rewarded'))
MISSION = CATALOG['enums']['QuestType']['values']['Mission']
SUPPORTED_REQUESTS = frozenset({'CSQuestAcceptReq', 'CSQuestGetPlayerDataReq'})
SCHEMA = """
CREATE TABLE IF NOT EXISTS native_lobby_quest_progress (
 player_id TEXT NOT NULL REFERENCES players(id), quest_id INTEGER NOT NULL,
 state INTEGER NOT NULL CHECK(state BETWEEN 0 AND 8), accept_time INTEGER NOT NULL DEFAULT 0,
 reward_time INTEGER NOT NULL DEFAULT 0, complete_time INTEGER NOT NULL DEFAULT 0,
 objectives_json TEXT NOT NULL DEFAULT '[]', PRIMARY KEY(player_id,quest_id));
"""


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
    if quest['QuestType'] != MISSION:
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


def response_fields(request, backend, token, *, changes=None):
    if request.name not in SUPPORTED_REQUESTS:
        return None
    writing = request.name == 'CSQuestAcceptReq'
    try:
        with backend.connection() as connection:
            if writing:
                connection.execute('BEGIN IMMEDIATE')
            player_id = backend._authorize(connection, token)
            row = connection.execute('SELECT level FROM native_lobby_levels WHERE player_id=?', (player_id,)).fetchone()
            level, now = row['level'] if row is not None else 1, int(time.time())
            progress = _progress(connection, player_id)
            if not writing:
                return {'result': 0, 'lobby_server_time': now,
                        'player_quests': [_data(quest_id, progress[quest_id]['state'], progress[quest_id])
                            if quest_id in progress else _data(quest_id, _default_state(quest, level, progress, now))
                            for quest_id, quest in QUESTS.items()]}
            if CATALOG['mapping_status'] != 'verified_by_native_reflection_and_serialization':
                fail('QuestCheckFailed', 'Native quest bindings are unavailable')
            quest_id = int(request.fields.get('quest_id') or 0)
            quest = QUESTS.get(quest_id)
            if quest is None:
                fail('QuestNotExist', 'Quest ID is absent from the installed source table')
            saved = progress.get(quest_id)
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
            notification = {'player_quests': [_data(quest_id, ACCEPTED, saved)], 'quest_data_pre': [previous]}
            connection.commit()
        if changes is not None:
            changes['quest_notification'] = notification
        return {'result': 0, 'quest_id': quest_id, 'quest_state': ACCEPTED}
    except DomainError as error:
        return {'result': error_code(error.code if error.code.startswith('Quest') else 'QuestFetchDBFailed')}
    except (sqlite3.Error, ValueError, TypeError, KeyError):
        return {'result': error_code('QuestSaveDBFailed' if writing else 'QuestFetchDBFailed')}
