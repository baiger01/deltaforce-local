"""Return installed season metadata to the original lobby rank consumers."""
from dfserver._paths import SERVER_ROOT

from datetime import datetime, timedelta, timezone
import json
from pathlib import Path
import sqlite3
import time

from dfserver.gateway.client_errors import error_code
from dfserver.app.core import DomainError


CATALOG = json.loads((SERVER_ROOT /
                     'protocol/native_season_catalog.json').read_text(encoding='utf-8'))
SUPPORTED_REQUESTS = frozenset({'CSSeasonGetInfoReq'})
CN = timezone(timedelta(hours=8))


def timestamp(value):
    return int(datetime.strptime(value, '%Y-%m-%d %H:%M:%S').replace(tzinfo=CN).timestamp())


def current_row(now):
    rows = [row for row in CATALOG['ranking']
            if timestamp(row['StartTime']) <= now < timestamp(row['EndTime'])]
    if len(rows) != 1:
        raise ValueError('No unique active installed season')
    return rows[0]


def response_fields(request, backend, token):
    if request.name not in SUPPORTED_REQUESTS:
        return None
    try:
        identity = backend.native_identity(token)
        target = int(request.fields.get('player_id') or 0)
        if target and target != identity['native_id']:
            return {'result': error_code('PlayerInfoGetProfileFailed')}
        # RankingListServer.lua 0.30 @14864 sends the untouched mode=0 default
        # for SOL; cs_season_pb.lua root PCs 96-98 define its zero defaults.
        mode = request.fields.get('mode', 0)
        if mode != 0 and mode not in CATALOG['modes'].values():
            return {'result': error_code('SeasonInvalidSerial')}
        current = current_row(time.time())
        serial = int(request.fields.get('serial') or current['Index'])
        if not any(row['Index'] == serial for row in CATALOG['ranking']) or serial > current['Index']:
            return {'result': error_code('SeasonInvalidSerial')}
        state = backend.native_lobby_profile(token)
        next_rows = [row for row in CATALOG['ranking'] if row['Index'] == current['Index'] + 1]
        # This local save has no completed ranked matches or historical attendance.
        profile = {'serial': serial, 'level': state['level'] if serial == current['Index'] else 0,
                   'rank_summary': {'has_attended': False},
                   'mp_rank_summary': {'has_attended': False},
                   'peak_rank': {'has_attended': False},
                   'commander_summary': {'has_attended': False}, 'commander_extra': {}}
        return {'result': 0, 'cur_serial': current['Index'],
                'begin_serial': min(row['Index'] for row in CATALOG['ranking']),
                'prev_serial': 0, 'prev_commander_serial': 0, 'season_info': profile,
                'start_time': timestamp(current['StartTime']),
                'end_time': timestamp(current['EndTime']),
                'UIStartTime': timestamp(current['UIStartTime']),
                'UIEndTime': timestamp(current['UIEndTime']),
                'next_serial_start_time': timestamp(next_rows[0]['StartTime']) if next_rows else 0,
                'awards': [], 'mp_awards': [], 'mp_commander_awards': []}
    except DomainError:
        return {'result': error_code('ServerDisabled')}
    except sqlite3.Error:
        return {'result': error_code('SeasonGetDBFailed')}
    except (ValueError, TypeError):
        return {'result': error_code('SeasonInvalidSerial')}
