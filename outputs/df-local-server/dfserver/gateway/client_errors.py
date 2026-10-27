"""Business result codes recovered from the installed client's error module."""
from dfserver._paths import SERVER_ROOT

from functools import lru_cache
import json
from pathlib import Path


@lru_cache(maxsize=1)
def _catalog():
    source = SERVER_ROOT / 'protocol/client_error_catalog.json'
    return json.loads(source.read_text(encoding='utf-8'))['rows']


def error_code(name):
    return _catalog()[name]['code']


def inventory_error(error):
    if error.code.startswith('Deposit') and error.code in _catalog():
        return error_code(error.code)
    names = {
        'WAREHOUSE_FULL': 'DepositSpaceNotEnough',
        'CHEST_RIG_FULL': 'DepositSpaceNotEnough',
        'BACKPACK_FULL': 'DepositSpaceNotEnough',
        'POCKET_FULL': 'DepositSpaceNotEnough',
        'SAFE_BOX_FULL': 'DepositSpaceNotEnough',
        'INSUFFICIENT_FUNDS': 'DepositCurrencyNotEnough',
        'INVALID_EQUIPMENT': 'DepositPropDescNotFound',
        'PROP_NOT_FOUND': 'DepositPropNotFound',
        'INSUFFICIENT_PROPS': 'DepositPropNotEnough',
        'INVALID_ARGUMENT': 'DepositInvalidReq',
        'POSITION_OCCUPIED': 'DepositSpaceHasOccupied',
    }
    return error_code(names.get(error.code, 'DepositInternalError'))
