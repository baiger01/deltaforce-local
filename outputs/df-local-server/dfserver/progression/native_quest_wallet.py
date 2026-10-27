"""Refresh accepted cash objectives after the wallet transaction has committed.

This compares owned currency with installed Currency2 requirements as a local
policy. The official server evaluator is unavailable; source witnesses and
limits are recorded in native-quest-cash-contract-20261020.json.
While accepted, the value follows the uncapped wallet balance. Completed quests
retain their completion-time value after later spending. Both choices are local
policy; the official clamping, completion latching and reset rules are unknown.
"""

import sqlite3
import time

from dfserver.app.core import DomainError


def refresh_committed(backend, token, *, diagnostic=None):
    from dfserver.progression.native_quest_conditions import refresh
    from dfserver.progression.native_quests import _progress

    try:
        with backend.connection() as connection:
            connection.execute('BEGIN IMMEDIATE')
            player_id = backend._authorize(connection, token)
            notification = refresh(connection, player_id, int(time.time()),
                                   _progress(connection, player_id), only_currency=True)
            connection.commit()
        return notification
    except DomainError as error:
        if diagnostic is not None:
            diagnostic['local_wallet_quest_error'] = {'code': error.code, 'message': error.message}
    except (sqlite3.Error, ValueError, TypeError, KeyError, OverflowError) as error:
        if diagnostic is not None:
            diagnostic['local_wallet_quest_error'] = {'code': type(error).__name__, 'message': str(error)}
    # The purchase or sale already committed; a later query can retry derived state.
    return None
