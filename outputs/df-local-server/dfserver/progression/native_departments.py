"""Source-bound department reward balances; no inferred ID suffix mapping."""
from dfserver._paths import SERVER_ROOT

import json
from pathlib import Path

from dfserver.app.core import fail


CATALOG = json.loads((SERVER_ROOT /
                     'protocol/native_department_catalog.json').read_text(encoding='utf-8'))
DEPARTMENTS = {row['card_id']: row for row in CATALOG['departments']}
QUALITY_REWARDS = {(row['quest_id'], row['reward_id']): row for row in CATALOG['quality_rewards']}
SCHEMA = """
CREATE TABLE IF NOT EXISTS native_lobby_department_values (
 player_id TEXT NOT NULL REFERENCES players(id), quality_id INTEGER NOT NULL,
 value INTEGER NOT NULL CHECK(value>=0), PRIMARY KEY(player_id,quality_id));
"""


def grant_reward(connection, player_id, quest_id, reward):
    source = QUALITY_REWARDS.get((quest_id, reward['RewardID']))
    if (CATALOG['mapping_status'] != 'verified_source_relational_join' or source is None or
            (source['item_id'], source['amount']) != (reward['ItemID'], reward['Number']) or
            source['quality_id'] not in DEPARTMENTS):
        fail('QuestChangeQualityFailed', 'Reward has no verified quest-line/department relation')
    quality_id = source['quality_id']
    row = connection.execute('SELECT value FROM native_lobby_department_values '
                             'WHERE player_id=? AND quality_id=?', (player_id, quality_id)).fetchone()
    previous = row[0] if row else 0
    current = previous + reward['Number']
    if current >= 2**63:
        fail('QuestChangeQualityFailed', 'Department reward balance limit')
    connection.execute('INSERT INTO native_lobby_department_values VALUES (?,?,?) '
        'ON CONFLICT(player_id,quality_id) DO UPDATE SET value=excluded.value',
        (player_id, quality_id, current))
    return {'quality_id': quality_id, 'previous_value': previous, 'value': current}


def quality_change(receipt):
    from dfserver.progression.native_department_queries import reputation_curve
    try:
        curve = reputation_curve()
    except (OSError, ValueError, TypeError):
        fail('QuestChangeQualityFailed', 'A verified department reputation curve is required')
    return {'quality_id': receipt['quality_id'],
            'old_rep_val': receipt['previous_value'], 'new_rep_val': receipt['value'],
            'old_rep_lvl': curve.level_for(receipt['previous_value']),
            'new_rep_lvl': curve.level_for(receipt['value'])}
