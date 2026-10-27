"""Offline provenance of the SUBWORLD argument tested for the observed Dam.

The name comes from the saved official loading log, not an invented map enum.
Native4d08ce0 checks its own command-line FName fallback when the GP cache is
empty. An argument does not prove which World or map lookup will consume it.
Trial 1791359654337913800 consumed it before lobby entry. Production trial
launchers now reject this global override; this builder preserves source facts.
"""
import hashlib
import json
from pathlib import Path
import re

SOURCE_PINS = {
    '进图调研/证据/20261007-官服出生场景对照.json':
        'd6eba6d45391125f649e0bc6268eef28e468b72736ca5ee845a04c96941d8547',
    'work/evidence/map-entry-next-20261007/map-subworld-full.4d08ce0.asm.txt':
        '9a828050503708addbd6326b80a9f0b95cb5b9c17ab6eedce7eddbb05bf0f831',
}


def qualified_subworld_argument(root, map_id):
    if type(map_id) is not int or map_id != 2201:
        raise ValueError('The observed subworld argument is qualified only for Dam2201')
    root = Path(root).resolve(strict=True)
    pins = {}
    for relative, expected in SOURCE_PINS.items():
        path = (root / relative).resolve(strict=True)
        if not path.is_relative_to(root) or not 0 < path.stat().st_size <= 1024 * 1024:
            raise ValueError('Invalid native subworld argument source path or size')
        raw = path.read_bytes()
        if hashlib.sha256(raw).hexdigest() != expected:
            raise ValueError('Native subworld argument source identity changed')
        pins[relative] = expected
    record = json.loads((root / next(iter(SOURCE_PINS))).read_text('utf-8'))
    if (record.get('client_sha256') != '4254fbe66585f260f1f9dbfc5e302887842552e7baed8939e023160a5e250be0'
            or record.get('user_confirmed_spawn_and_movement') is not True):
        raise ValueError('Official loading-name observation is not qualified')
    states = record['typed_loading_context_log_states']
    ids = {row['MapID'] for row in states if 'MapID' in row}
    names = {row['CurLoadingMapName'] for row in states if 'CurLoadingMapName' in row}
    if ids != {map_id} or len(names) != 1:
        raise ValueError('Official map and subworld name are ambiguous')
    name, = names
    if type(name) is not str or not re.fullmatch(r'[A-Za-z0-9_]{1,128}', name):
        raise ValueError('Observed subworld name is not a single native argument identifier')
    relative = 'work/native_map_subworld_argument.py'
    pins[relative] = hashlib.sha256((root / relative).read_bytes()).hexdigest()
    if pins[relative] != hashlib.sha256(Path(__file__).read_bytes()).hexdigest():
        raise ValueError('Subworld argument builder was imported from another root')
    return {'argument': '-SUBWORLD=' + name, 'map_id': map_id, 'subworld_name': name,
        'source_pins': pins, 'runtime_lookup_effect_verified': False,
        'nonreplicated_map_type_overwritten': False, 'playable_map_verified': False}
