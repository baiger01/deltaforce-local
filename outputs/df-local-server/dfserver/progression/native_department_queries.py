"""Source-bound department query shapes and cumulative reputation calculation.

The five active card/line/merchant relations and image paths come from
native_department_catalog.json. RoleInfoServer.lua (SHA-256
a6221ddd4f16c4c77be62be552b78eb275f06f9710aed57c3ec529e543eb7503)
0.68 subtracts previous per-level scores from cumulative quality_value; 0.69
uses the number of RepLevelConfig rows as the maximum level. Numerical
observations and the explicitly marked first-level inference are kept in the
separate native_reputation_curve.json evidence file, not the client table join.

Card is_unlock follows a local policy: expose the related source quest line's
current open condition. QuestLineStruct 0.2 checks the owned season level and
all OpenLimits completions. That condition does not prove the official card
activation policy. Unlock timestamps and disable flags remain unavailable and
are omitted. Merchant vip_lvl is a separate value and is never used here.
"""
from dfserver._paths import SERVER_ROOT

from bisect import bisect_right
import json
from pathlib import Path
import sqlite3
from urllib.parse import urlsplit

from dfserver.gateway.client_errors import error_code
from dfserver.app.core import DomainError, fail
from dfserver.progression import native_departments
from dfserver.progression import native_quests


SUPPORTED_REQUESTS = frozenset({'CSAttrGetAllQualityReq', 'CSGetRoleQualityConfigReq',
                                'CSAttributeGetConfigReq'})
MAX_I64 = 2**63 - 1
VERIFIED_CURVE_STATUSES = frozenset({'verified_recorded_native_client_progress', 'verified_source_curve',
                                    'verified_by_native_reflection_and_serialization',
                                    'native_observations_and_primary_report_inference'})


class RepLevelCurve:
    """Validated per-level widths; direct injection requires caller verification.

    The last row sets the maximum level. Its known score is retained for the
    wire; an unknown terminal score is None and is omitted. Neither creates
    another level. Tests may inject explicitly synthetic data;
    production callers load the separate evidence file with its provenance.
    """

    def __init__(self, rows):
        if not isinstance(rows, (list, tuple)) or not rows:
            raise ValueError('A nonempty complete reputation curve is required')
        values, thresholds, total = [], [0], 0
        for expected, row in enumerate(rows, 1):
            if not isinstance(row, dict) or set(row) != {'level', 'score'}:
                raise ValueError('RepLevelConfig requires exactly level and score')
            level, score = row['level'], row['score']
            if type(level) is not int or level != expected:
                raise ValueError('Reputation levels must be unique and contiguous from 1')
            terminal_unknown = expected == len(rows) and score is None
            if not terminal_unknown and (type(score) is not int or not 0 <= score <= MAX_I64):
                raise ValueError('Reputation scores must be nonnegative signed i64 integers')
            values.append((level, score))
            if expected < len(rows):
                if score == 0:
                    raise ValueError('Every nonterminal reputation level needs a positive score')
                total += score
                if total > MAX_I64:
                    raise ValueError('Cumulative reputation thresholds exceed signed i64')
                thresholds.append(total)
        self._rows = tuple(values)
        self._thresholds = tuple(thresholds)

    @property
    def max_level(self):
        return len(self._rows)

    def level_for(self, cumulative_value):
        if type(cumulative_value) is not int or not 0 <= cumulative_value <= MAX_I64:
            raise ValueError('Cumulative reputation must be a nonnegative signed i64 integer')
        return bisect_right(self._thresholds, cumulative_value)

    def configs(self):
        return [{'level': level, **({'score': score} if score is not None else {})}
                for level, score in self._rows]


def _has_source_reference(value):
    if isinstance(value, dict):
        for key, child in value.items():
            if isinstance(child, str):
                if key.endswith('sha256') and len(child) == 64 and all(
                        character in '0123456789abcdefABCDEF' for character in child):
                    return True
                if key.endswith('url'):
                    url = urlsplit(child)
                    if url.scheme in ('http', 'https') and url.netloc:
                        return True
            if _has_source_reference(child):
                return True
    elif isinstance(value, list):
        return any(_has_source_reference(child) for child in value)
    return False


def _document_curve(document):
    if (not isinstance(document, dict) or document.get('mapping_status') not in VERIFIED_CURVE_STATUSES
            or not _has_source_reference(document.get('sources'))):
        raise ValueError('Reputation curve has no verified source marker and source references')
    rows = document.get('levels')
    if not isinstance(rows, list) or any(not isinstance(row, dict) or
            not {'level', 'score'} <= row.keys() or not row.keys() <= {'level', 'score', 'evidence'} or
            ('evidence' in row and not isinstance(row['evidence'], dict)) for row in rows):
        raise ValueError('Reputation evidence rows require level, score and optional evidence')
    curve = RepLevelCurve([{'level': row['level'], 'score': row['score']} for row in rows])
    terminal_unknown = rows[-1]['score'] is None
    marked_unknown = document.get('terminal_score_unrecovered', False)
    if type(marked_unknown) is not bool or terminal_unknown != marked_unknown:
        raise ValueError('An unrecovered terminal score requires an explicit matching marker')
    if 'max_level' in document and (type(document['max_level']) is not int
                                   or document['max_level'] != curve.max_level):
        raise ValueError('Declared maximum must equal the complete reputation curve length')
    return curve


def load_curve(path):
    """Read mapping_status, levels and sources; supply no fallback values.

    Unknown terminal scores additionally require terminal_score_unrecovered=true.
    Source references document verification; this loader does not authenticate
    the contents of external evidence.
    """
    return _document_curve(json.loads(Path(path).read_text(encoding='utf-8')))


def reputation_curve():
    """Load admitted numerical evidence, including its declared inference status."""
    path = SERVER_ROOT / 'protocol/native_reputation_curve.json'
    return load_curve(path)


def _resolve_curve(curve, curve_path):
    if curve is not None and curve_path is not None:
        raise ValueError('Supply either a reputation curve or its path')
    if curve_path is not None:
        return load_curve(curve_path)
    if isinstance(curve, RepLevelCurve):
        return curve
    if isinstance(curve, (list, tuple)):
        return RepLevelCurve(curve)
    return reputation_curve() if curve is None else _document_curve(curve)


def line_is_open(line, season_level, completed_quests):
    """Source quest-line condition used by the explicitly local card policy."""
    return (season_level >= line['OpenLevel']
            and all(quest_id in completed_quests for quest_id in line['OpenLimits']))


def _departments():
    catalog = native_departments.CATALOG
    if catalog['mapping_status'] != 'verified_source_relational_join':
        fail('AttrGetQualityFail', 'Original department relations are unavailable')
    rows = catalog['departments']
    if not rows or len({row['card_id'] for row in rows}) != len(rows):
        fail('AttrGetQualityFail', 'Original department relations are empty or ambiguous')
    for row in rows:
        line = native_quests.LINES.get(row['root_quest_id'])
        if line is None or line['QuestLineID'] != row['quest_line_id']:
            fail('AttrGetQualityFail', 'Department quest line no longer matches the source relation')
    return rows


def _configs():
    # RoleInfoServer 0.57.0 replaces name, img_path and sprite_path from its local
    # RoleQuality row. The unresolved FText is not decoded into a guessed name.
    # Per-card usage type/target bindings have not been recovered.
    return [{'quality_id': row['card_id'], 'name': '', 'quest_id': row['quest_line_id'],
             'img_path': row['ImgPath'], 'sprite_path': row['SpritePath'],
             'cover_img_path': row['CoverImgPath'], 'quality_usages': []}
            for row in _departments()]


def _cards(connection, player_id, curve):
    row = connection.execute('SELECT level FROM native_lobby_levels WHERE player_id=?',
                             (player_id,)).fetchone()
    season_level = row['level'] if row is not None else 1
    completed = {row['quest_id'] for row in connection.execute(
        'SELECT quest_id FROM native_lobby_quest_progress WHERE player_id=? AND state>=?',
        (player_id, native_quests.COMPLETED))}
    values = {row['quality_id']: row['value'] for row in connection.execute(
        'SELECT quality_id,value FROM native_lobby_department_values WHERE player_id=?',
        (player_id,))}
    return [{'card_id': row['card_id'], 'quality_value': values.get(row['card_id'], 0),
             'level': curve.level_for(values.get(row['card_id'], 0)),
             'is_unlock': line_is_open(native_quests.LINES[row['root_quest_id']],
                                       season_level, completed)}
            for row in _departments()]


def response_fields(request, backend, token, *, curve=None, curve_path=None, diagnostic=None):
    if request.name not in SUPPORTED_REQUESTS:
        return None
    try:
        with backend.connection() as connection:
            connection.execute('BEGIN')
            player_id = backend._authorize(connection, token)
            if request.name == 'CSGetRoleQualityConfigReq':
                return {'result': 0, 'configs': _configs()}
            try:
                verified_curve = _resolve_curve(curve, curve_path)
            except (OSError, ValueError, TypeError):
                fail('AttrCalAttrFail', 'A complete verified reputation curve is unavailable')
            if request.name == 'CSAttributeGetConfigReq':
                # PropertyServer.GetRoleLoad has native 15/50/70 fallbacks when
                # no matching load row exists. No unrecovered load rows are made up.
                return {'result': 0, 'load_configs': [],
                        'rep_level_configs': verified_curve.configs()}
            return {'result': 0, 'all_quality': _cards(connection, player_id, verified_curve)}
    except DomainError as error:
        if diagnostic is not None:
            diagnostic['local_department_error'] = {'code': error.code, 'message': error.message}
        name = error.code if error.code in ('AttrCalAttrFail', 'AttrGetQualityFail') else 'AttrGetQualityFail'
        return {'result': error_code(name)}
    except sqlite3.Error:
        return {'result': error_code('AttrGetQualityFail')}
    except (KeyError, ValueError, TypeError):
        return {'result': error_code('AttrCalAttrFail')}
