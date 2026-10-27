"""Action XP from the installed SeasonLevel table, separate from account XP.

Original pakchunk2 entry 7084 at 50371705, SHA-256
16389ea97f300742cd11bf3e346f5480ac94dbf9b7549865ea8a1a8c8505bac9.
GrowthRoadServer.lua 0.15 returns row.Experience as the next-level cost;
0.22 identifies the zero-cost terminal level. SOLPathOfGrowthLevelUpPanel.lua
0.1/0.13 uses old_exp and seasonExp as within-level values. Original source
hashes, reflected field bindings and instruction witnesses are in the catalog.
"""
from dfserver._paths import SERVER_ROOT

from bisect import bisect_right
import json
from pathlib import Path
import time


CATALOG = json.loads((SERVER_ROOT /
                     'protocol/native_action_level_catalog.json').read_text(encoding='utf-8'))
SOURCE_SHA256 = '16389ea97f300742cd11bf3e346f5480ac94dbf9b7549865ea8a1a8c8505bac9'
LEVELS = CATALOG['levels']
if (CATALOG['mapping_status'] != 'verified_by_native_reflection_and_serialization'
        or CATALOG['source']['sha256'] != SOURCE_SHA256
        or [row['Level'] for row in LEVELS] != list(range(1, 61))
        or any(not row['Experience'].isascii() or not row['Experience'].isdecimal() for row in LEVELS)):
    raise ValueError('Verified installed action level curve is unavailable')
COSTS = tuple(int(row['Experience']) for row in LEVELS)
if any(cost <= 0 for cost in COSTS[:-1]) or COSTS[-1] != 0:
    raise ValueError('Original action level costs have changed')
FLOORS = tuple(sum(COSTS[:index]) for index in range(len(COSTS)))
MAX_LEVEL = len(COSTS)
MAX_EXP = 2**63 - 1
SCHEMA = """
CREATE TABLE IF NOT EXISTS native_lobby_action_progress (
 player_id TEXT PRIMARY KEY REFERENCES players(id), baseline_level INTEGER NOT NULL,
 baseline_total_exp INTEGER NOT NULL CHECK(baseline_total_exp>=0),
 earned_exp INTEGER NOT NULL CHECK(earned_exp>=0), initialized_at INTEGER NOT NULL,
 baseline_reason TEXT NOT NULL, source_sha256 TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS native_lobby_independent_level_baselines (
 player_id TEXT PRIMARY KEY REFERENCES players(id), account_level INTEGER NOT NULL,
 blast_level INTEGER NOT NULL, captured_at INTEGER NOT NULL, baseline_reason TEXT NOT NULL);
"""


def _owned_level(connection, player_id):
    row = connection.execute('SELECT level FROM native_lobby_levels WHERE player_id=?', (player_id,)).fetchone()
    level = row['level'] if row else 1
    if not 1 <= level <= MAX_LEVEL:
        raise ValueError('Saved action level is outside the installed source curve')
    return level


def _state(connection, player_id):
    level = _owned_level(connection, player_id)
    ledger = connection.execute('SELECT * FROM native_lobby_action_progress WHERE player_id=?',
                                (player_id,)).fetchone()
    if ledger is None:
        return level, FLOORS[level - 1], None
    if (ledger['source_sha256'] != SOURCE_SHA256 or not 1 <= ledger['baseline_level'] <= MAX_LEVEL
            or ledger['baseline_total_exp'] != FLOORS[ledger['baseline_level'] - 1]):
        raise ValueError('Saved action experience baseline does not match its original source')
    total = ledger['baseline_total_exp'] + ledger['earned_exp']
    if not 0 <= total <= MAX_EXP or bisect_right(FLOORS, total) != level:
        raise ValueError('Saved action experience and owned level disagree')
    return level, total, ledger


def profile_fields(connection, player_id):
    """Read action profile values without initializing or downgrading an account."""
    level, total, _ = _state(connection, player_id)
    return {'level': level, 'exp': total - FLOORS[level - 1], 'next_level_exp': COSTS[level - 1]}


def independent_profile_fields(connection, player_id, *, now=None):
    """Freeze the old local profile projection, not an official account XP curve.

    Older saves exposed one level in all three profile branches. Capture that
    presentation once so action rewards cannot raise independent account/blast
    levels. Existing action ledgers retain the pre-grant baseline for migration.
    No account/blast XP or thresholds have been recovered or are awarded here.
    """
    if not connection.in_transaction:
        raise ValueError('Independent level baseline requires a caller transaction')
    saved = connection.execute('SELECT * FROM native_lobby_independent_level_baselines WHERE player_id=?',
                               (player_id,)).fetchone()
    if saved is None:
        ledger = connection.execute('SELECT baseline_level FROM native_lobby_action_progress WHERE player_id=?',
                                    (player_id,)).fetchone()
        level = ledger['baseline_level'] if ledger else _owned_level(connection, player_id)
        connection.execute('INSERT INTO native_lobby_independent_level_baselines VALUES (?,?,?,?,?)',
            (player_id, level, level, int(time.time()) if now is None else int(now),
             'explicit_local_legacy_profile_projection'))
        saved = {'account_level': level, 'blast_level': level}
    return {'account_level': saved['account_level'], 'blast_level': saved['blast_level'],
            'account_exp': 0, 'blast_exp': 0, 'account_next_level_exp': 0, 'blast_next_level_exp': 0}


def grant(connection, player_id, amount, *, now=None):
    """Add real action XP inside the caller's reward transaction; never commit.

    Historical levels without an action ledger retain their owned level through
    an audited local floor. That baseline is recorded separately from earned XP
    and does not infer an official historical balance or change players.xp.
    """
    if not connection.in_transaction:
        raise ValueError('Action experience requires the caller reward transaction')
    if type(amount) is not int or not 0 < amount <= MAX_EXP:
        raise ValueError('Action experience reward must be a positive int64')
    old_level, old_total, ledger = _state(connection, player_id)
    independent_profile_fields(connection, player_id, now=now)
    total = old_total + amount
    if total > MAX_EXP:
        raise ValueError('Action experience cumulative balance limit')
    baseline_created = ledger is None
    if baseline_created:
        reason = 'level_one_zero_floor' if old_level == 1 else 'explicit_local_legacy_level_floor'
        connection.execute('INSERT INTO native_lobby_action_progress VALUES (?,?,?,?,?,?,?)',
            (player_id, old_level, old_total, 0, int(time.time()) if now is None else int(now),
             reason, SOURCE_SHA256))
    else:
        reason = ledger['baseline_reason']
    level = bisect_right(FLOORS, total)
    connection.execute('UPDATE native_lobby_action_progress SET earned_exp=earned_exp+? WHERE player_id=?',
                       (amount, player_id))
    connection.execute('INSERT INTO native_lobby_levels VALUES (?,?) '
        'ON CONFLICT(player_id) DO UPDATE SET level=excluded.level', (player_id, level))
    return {'old_level': old_level, 'level': level, 'old_exp': old_total - FLOORS[old_level - 1],
        'exp': total - FLOORS[level - 1], 'old_next_level_exp': COSTS[old_level - 1],
        'next_level_exp': COSTS[level - 1], 'old_total_exp': old_total, 'total_exp': total,
        'delta_exp': amount, 'baseline_created': baseline_created, 'baseline_reason': reason}


def notification_fields(player_id, receipt):
    """Build only the original action branch of CSAccountExpChangeNtf."""
    names = ('old_level', 'level', 'old_exp', 'exp', 'old_next_level_exp', 'next_level_exp',
             'old_total_exp', 'total_exp', 'delta_exp')
    return {'player_id': player_id, 'source': CATALOG['notification_source'],
            'change': {name: receipt[name] for name in names}}
