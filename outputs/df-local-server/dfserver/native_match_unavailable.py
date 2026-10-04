"""Reply to the original match request when no local matching service exists.

TeamServer.lua callback 0.116.1 clears its timer and sending flag on failure.
MatchGateServiceInMaintenance is the original failure for this local state.
"""

import sqlite3

from .client_errors import error_code
from .core import DomainError


SUPPORTED_REQUESTS = frozenset({'CSRoomMatchStartAllocReq'})


def response_fields(request, backend, token):
    if request.name not in SUPPORTED_REQUESTS:
        return None
    try:
        with backend.connection() as connection:
            backend._authorize(connection, token)
        return {'result': error_code('MatchGateServiceInMaintenance')}
    except (DomainError, sqlite3.Error):
        return {'result': error_code('ServerDisabled')}
