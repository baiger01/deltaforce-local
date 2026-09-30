"""Default gun components recovered from the installed preset node table."""

from copy import deepcopy
import json
from pathlib import Path


SOURCE = Path(__file__).resolve().parent.parent / 'protocol/weapon_component_catalog.json'
ROWS = json.loads(SOURCE.read_text(encoding='utf-8'))['rows']
PRESETS = {row['preset_id']: int(receiver) for receiver, row in ROWS.items()}


def default_components(item_id):
    receiver = PRESETS.get(int(item_id), int(item_id))
    row = ROWS.get(str(receiver))
    return deepcopy(row['prop']['components']) if row else []
