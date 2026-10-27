"""Source-bound abandonment of ordinary, manually accepted SOL quests.

QuestServer 0.35/0.35.0, QuestStruct 0.21 and QuestObjectiveStruct 0.5
define the request, state transition and progress reset. QuestDetailPanel
0.11 excludes automatically accepted quests. QuestConfig explicitly says
submitted items are not returned. Witnesses and original chunk hashes live in
work/evidence/native-quest-abandon-contract-20261020.json.
"""

import json

from dfserver.app.core import fail


def give_up(connection, player_id, quest, saved, now, changes):
    """Mutate within the caller's authorized transaction; it commits notices."""
    from dfserver.progression import native_quests as quests

    quest_id = quest['QuestID']
    if saved is None:
        fail('QuestNotAccepted', 'This local account has not accepted the quest')
    owned = connection.execute('SELECT * FROM native_lobby_quest_progress '
        'WHERE player_id=? AND quest_id=?', (player_id, quest_id)).fetchone()
    if owned is None:
        fail('QuestNotAccepted', 'This local account does not own the accepted quest')
    saved = dict(owned)
    if saved['state'] in (quests.COMPLETED, quests.REWARDED):
        fail('QuestAlreadyCompleted', 'A completed or rewarded quest cannot be abandoned')
    if saved['state'] != quests.ACCEPTED:
        fail('QuestStateInvalid', 'Only an accepted quest can be abandoned')
    if (quest['QuestType'] not in quests.SOL_QUEST_TYPES or quest['ShouldAutoAccept']
            or quest['IsContract'] or quest['SpecialType'] or quest['QuestLifeType']):
        fail('QuestCheckFailed', 'This quest requires another verified abandonment path')
    objectives = quests._objective_states(quest, saved)
    previous = quests._data(quest_id, saved['state'], saved)
    for objective in objectives.values():
        objective.update(value=0, has_completed=False)
    encoded = json.dumps([objectives[ident] for ident in quest['ObjectiveList']])
    updated = connection.execute('UPDATE native_lobby_quest_progress '
        'SET state=?,accept_time=0,objectives_json=? '
        'WHERE player_id=? AND quest_id=? AND state=?',
        (quests.UNACCEPTED, encoded, player_id, quest_id, quests.ACCEPTED))
    if updated.rowcount != 1:
        fail('QuestStateInvalid', 'The saved quest is no longer accepted')
    after = quests._data(quest_id, quests.UNACCEPTED,
                         dict(saved, state=quests.UNACCEPTED, accept_time=0, objectives_json=encoded))
    changes['quest_notification'] = {'player_quests': [after], 'quest_data_pre': [previous]}
    return {'res': 0, 'remove_quest_id': quest_id}
