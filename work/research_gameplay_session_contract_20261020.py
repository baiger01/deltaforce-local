"""Record local match lifecycle contracts without launching a client or writing accounts."""
import argparse
import ast
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys


ROOT = Path(__file__).resolve().parent.parent
SERVER = 'outputs/df-local-server/dfserver/'
SOURCES = {
    SERVER + 'core.py': ('_container_prop',),
    SERVER + 'native_keycards.py': ('catalog', 'keycard_fields'),
    SERVER + 'weapon_components.py': (),
    SERVER + 'native_match_loadout.py': ('snapshot',),
    SERVER + 'native_match_materializer.py': ('_normalize', '_parts', 'materialize'),
    SERVER + 'legacy_ds_match_admission.py': ('issue', 'begin_joined_session'),
    SERVER + 'game_server_probe.py': ('issue_match_admission',),
    'work/portable_durable_world_runtime.py': ('install_runtime', 'prepare_room_namespace'),
    'work/portable_world_session.py': ('admit', 'commit_terminal', 'materialize_terminal'),
    'work/portable_movement_runtime.py': ('make_profile', '_reason_code'),
    'work/portable_movement_wire.py': ('accept_position',),
    'work/portable_movement_clock_epoch.py': ('accept_local_epoch', 'accept_packet_moves'),
    'work/portable_source_guard.py': (),
    SERVER + 'legacy_ds_movement.py': ('consume', 'accepted_position'),
    SERVER + 'legacy_ds_control_connection.py': (),
    'work/verify_local_provider_client.py': (),
    'outputs/df-local-server/protocol/portable-map-spawn/profile-carried-inventory.json': (),
    'outputs/df-local-server/protocol/local_map_board_candidates.json': (),
    'outputs/df-local-server/protocol/game_item_catalog.json': (),
    'outputs/df-local-server/protocol/deposit_slot_catalog.json': (),
    'outputs/df-local-server/protocol/native_keycard_catalog.json': (),
    'outputs/df-local-server/protocol/weapon_component_catalog.json': (),
}
LOBBY_SOURCES = {
    SERVER + 'app/core.py': ('_container_prop',),
    SERVER + 'inventory/native_prop_bindings.py': ('persisted_fields', 'set_binding'),
    SERVER + '_paths.py': (),
    SERVER + 'module_layout.json': (),
}


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def source_record(path, raw, symbols):
    record = {'path': str(path), 'sha256': sha(raw), 'symbols': []}
    if not symbols:
        return record
    tree = ast.parse(raw.decode('utf-8-sig'))
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and node.name in symbols:
            record['symbols'].append({'name': node.name, 'line': node.lineno,
                                      'end_line': node.end_lineno})
    if set(symbols) != {node['name'] for node in record['symbols']}:
        raise ValueError('A reviewed function moved or is absent: ' + str(path))
    return record


def compatibility_probe(map_root, python):
    # Synthetic local GID/account identities never enter a production database.
    code = '''
import json
from dfserver.native_match_materializer import _normalize
p = dict(gid=888, template_id=37110400001, quantity=1,
         grid_page_id=199997, x=1, y=0, length=1, width=1)
result = dict(synthetic=True, account_writes=False,
              probe_scope="non_receiver_root_binding_whitelist",
              baseline_accepted=bool(_normalize(p)))
try:
    _normalize(dict(p, bind_type=0, bind_player=17))
except ValueError as error:
    result.update(bound_item_accepted=False, rejection=str(error))
else:
    result['bound_item_accepted'] = True
    normalized = _normalize(dict(p, bind_type=0, bind_player=17))
    result['root_binding_fields_preserved'] = all(
        normalized[name] == value for name, value in
        (('bind_type', 0), ('bind_player', 17)))
    try:
        _normalize(dict(p, bind_type=0))
    except ValueError:
        result['incomplete_binding_rejected'] = True
    else:
        result['incomplete_binding_rejected'] = False
print(json.dumps(result))
'''
    env = dict(os.environ, PYTHONDONTWRITEBYTECODE='1',
               PYTHONPATH=os.pathsep.join(str(map_root / p) for p in
                   ('work', 'outputs/df-local-server', 'outputs/df-local-server/tests')))
    result = subprocess.run([str(python), '-B', '-c', code], cwd=map_root, env=env,
                            capture_output=True, text=True, encoding='utf-8',
                            errors='strict', timeout=60, check=True)
    return json.loads(result.stdout)


def collect(map_root, python):
    map_root = Path(map_root).resolve(strict=True)
    snapshots = {relative: (map_root / relative).read_bytes() for relative in SOURCES}
    profile_name = 'outputs/df-local-server/protocol/portable-map-spawn/profile-carried-inventory.json'
    profile = json.loads(snapshots[profile_name])
    records = {relative: source_record(map_root / relative, raw, SOURCES[relative])
               for relative, raw in snapshots.items()}
    lobby_snapshots = {relative: (ROOT / relative).read_bytes() for relative in LOBBY_SOURCES}
    lobby_records = {relative: source_record(ROOT / relative, raw, LOBBY_SOURCES[relative])
                     for relative, raw in lobby_snapshots.items()}
    compatibility = compatibility_probe(map_root, python)
    for relative, raw in snapshots.items():
        if (map_root / relative).read_bytes() != raw:
            raise ValueError('Active collaborator changed a reviewed source; rerun: ' + relative)
    for relative, raw in lobby_snapshots.items():
        if (ROOT / relative).read_bytes() != raw:
            raise ValueError('Lobby source changed during review; rerun: ' + relative)
    return {
        'kind': 'gameplay_session_integration_research_20261020',
        'observed_at_utc': datetime.now(timezone.utc).isoformat(),
        'map_checkout': str(map_root),
        'client_sha256': profile['client_sha256'],
        'process_access': False, 'client_launched': False, 'packets_sent': False,
        'account_database_opened': False, 'runtime_sources_modified': False,
        'sources_stable_during_review': True, 'sources': records,
        'lobby_sources': lobby_records,
        'current_profile': {key: profile.get(key) for key in
            ('diagnostic_only', 'map_id', 'owner_switch_runtime', 'inventory_ready_refresh',
             'skill_template_authority', 'fsm_replica_initialization',
             'level_visibility_runtime', 'movement_runtime')},
        'compatibility_probe': compatibility,
        'established_contracts': [
            'A single authenticated SQLite transaction freezes selected hero, suit and actual carried instances.',
            'The ticket carries immutable loadout bytes; runtime producers derive actor plans from that ticket.',
            'The admission snapshot does not reserve or transfer the carried account instances.',
            'Terminal materialization requires an existing immutable terminal on the same SQLite transaction.',
            'Materialization verifies carry-in against current account instances, then writes and reads back carry-out.',
            'An identical committed terminal returns its existing receipt without applying items twice.',
            'The production durable-world installer currently returns installed=False for missing authority providers.',
        ],
        'integration_gaps': [
            {'id': 'carried_instance_custody',
             'classification': 'missing_runtime_policy',
             'impact': 'Concurrent lobby edits to a carried GID conflict with eventual terminal application.',
             'required': 'Reserve or escrow carried roots and children with an account/match revision; release on qualified lifecycle transitions.'},
            {'id': 'latest_lobby_binding_schema',
             'classification': ('root_normalizer_accepts_binding_full_lifecycle_unverified'
                 if compatibility['bound_item_accepted'] else
                 'reproduced_cross_checkout_contract_mismatch'),
             'impact': ('The narrow ordinary-root normalizer probe accepts binding; this does not verify persisted root/ammunition roundtrip or native settlement.'
                 if compatibility['bound_item_accepted'] else
                 'A root item with bind_type/bind_player is rejected by the current match materializer.'),
             'required': 'Verify binding through projection, mutation, transaction persistence, readback and native settlement; preserve every source-supported instance feature.'},
            {'id': 'terminal_producer',
             'classification': 'missing_runtime_authority',
             'impact': 'A durable SQL helper does not establish that an actual server escape/death condition occurred.',
             'required': 'Bind server-owned death/exit conditions, timer, reason and retained instances before committing a terminal.'},
            {'id': 'map_and_mode_scope',
             'classification': 'explicit_diagnostic_scope',
             'impact': 'A Dam2201 diagnostic profile cannot validate six maps or SOL/MP/Trials interchangeably.',
             'required': 'Qualify each published map/mode and keep distinct MapID, MapConfigMapID, event IDs and exit IDs.'},
        ],
        'local_design_recommendations_not_official_server_recovery': [
            'Persist one match phase and one account reservation revision; transport reconnect must not create a second inventory owner.',
            'Use an idempotent command journal and committed outbox; network ACKs prove delivery only.',
            'Apply item, ammo, condition, keycard, money and task effects in the same qualified transaction before publishing settlement.',
            'Key durable custody and recovery by admission plus reservation revision; transport generation only fences network commands and delivery.',
            'A reconnect uses a new transport generation for the same reservation; crash recovery must not require an expired generation to release or settle custody.',
        ],
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--map-root', type=Path, required=True)
    parser.add_argument('--python', type=Path, default=Path(sys.executable))
    parser.add_argument('--output', type=Path, default=ROOT / 'work/evidence/gameplay-session-research-20261020-post-layout.json')
    args = parser.parse_args()
    output = args.output.resolve()
    if not output.is_relative_to((ROOT / 'work/evidence').resolve()):
        parser.error('Research output must remain in this chat\'s evidence directory')
    result = collect(args.map_root, args.python.resolve(strict=True))
    output.write_text(json.dumps(result, ensure_ascii=True, indent=2) + '\n', encoding='utf-8')
    print(json.dumps({'output': str(output), 'source_count': len(result['sources']),
                      'compatibility_probe': result['compatibility_probe']}, ensure_ascii=True))


if __name__ == '__main__':
    main()
