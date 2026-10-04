"""Extract bounded class/path/event evidence from a successful official match.

No packet decryption, process-memory inspection or full log-line export. Missing
log evidence must never be interpreted as a missing resource or AI implementation.
"""
import argparse
from collections import Counter
from datetime import datetime
import hashlib
import json
from pathlib import Path
import re

ROOT = Path(__file__).resolve().parent.parent
RULES = {
    'player_lifecycle': ('SpawnPlayer', 'CreatePlayer', 'PlayerPawn', 'Possess', 'OnPostConnectDS',
                         'OnDSNotifyAllPlayerReady', 'BeginPlay', 'InitPlayer'),
    'scene_loading': ('LevelStreaming', 'LoadMap:', 'WorldPartition', 'LoadLevel', 'StreamingReady',
                      'StartLevelPhysicsLoad', 'SeamlessTravel', 'LogStreaming:'),
    'ai_loading': ('AISystem', 'SpawnAI', 'AIController', 'BehaviorTree', 'NavMesh', 'LogAI:', 'NPC'),
    'replication': ('NetGUID', 'RepLayout', 'LogNetPackageMap:', 'LogNetSerialization:',
                    'UActorChannel', 'OnRep_', 'ReplicateActor'),
}


def safe_symbols(line):
    return {
        'categories': re.findall(r'\b(?:Lua|Log)[A-Za-z0-9_]+:', line),
        'function_names': re.findall(r'\b[A-Za-z][A-Za-z0-9_]+::[A-Za-z][A-Za-z0-9_]+', line),
        'asset_paths': re.findall(r'/Game/[A-Za-z0-9_./-]+', line),
        'script_paths': re.findall(r'/Script/[A-Za-z0-9_./]+', line),
    }


def collect(game_root, manifest):
    first = next(entry['client_wall_time'] for entry in manifest['stages']
                 if 'start_connect_requested' in entry.get('stage_names', []))
    datetime.strptime(first, '%Y.%m.%d-%H.%M.%S:%f')
    path = game_root / 'DeltaForce/Saved/Logs/DeltaForce.log'
    if path.stat().st_size > 128 * 1024 * 1024:
        raise ValueError('Client log exceeds the bounded analysis size')
    raw = path.read_bytes()
    text = raw.removeprefix(b'\xef\xbb\xbf').translate(bytes(v ^ 0x5c for v in range(256))).decode('utf-8', 'replace')
    groups = {name: {'matching_lines': 0, 'functions': Counter(), 'paths': Counter(),
                     'scripts': Counter(), 'categories': Counter(), 'samples': []} for name in RULES}
    flow_events, line_count, end = [], 0, None
    end_reason = 'snapshot_end'
    for line in text.splitlines():
        stamp = re.match(r'^\[(\d{4}\.\d{2}\.\d{2}-\d{2}\.\d{2}\.\d{2}:\d{3})\]', line)
        if not stamp:
            continue
        # Fixed-width native timestamps sort chronologically; avoid parsing
        # every line in a large live game log as a datetime.
        if stamp[1] < first:
            continue
        line_count += 1
        end = stamp[1]
        if 'UGameFlowGraph::OnLuaGameFlowEvent()' in line and len(flow_events) < 80:
            event = re.search(r'MdlName = ([A-Za-z0-9_]+), EventName = ([A-Za-z0-9_]+)', line)
            if event:
                flow_events.append({'client_wall_time': stamp[1], 'module': event[1], 'event': event[2]})
                # Keep this successful match separate from later matches in the
                # same running client, so their asset paths cannot be mixed.
                if event[1] == 'InGame' and event[2] == 'flowEvtOnClientQuit':
                    end_reason = 'first_match_client_quit'
                    break
                if (event[2] == 'flowEvtPreparationStartMatchSuccess' and
                        datetime.strptime(stamp[1], '%Y.%m.%d-%H.%M.%S:%f') -
                        datetime.strptime(first, '%Y.%m.%d-%H.%M.%S:%f')).total_seconds() > 30:
                    end_reason = 'next_match_start'
                    break
        matches = [name for name, markers in RULES.items() if any(marker in line for marker in markers)]
        if not matches:
            continue
        symbols = safe_symbols(line)
        for name in matches:
            group = groups[name]
            group['matching_lines'] += 1
            group['functions'].update(symbols['function_names'])
            group['paths'].update(symbols['asset_paths'])
            group['scripts'].update(symbols['script_paths'])
            group['categories'].update(symbols['categories'])
            if any(symbols.values()) and len(group['samples']) < 16:
                group['samples'].append({'client_wall_time': stamp[1], **symbols})
    return {
        'kind': 'official_match_runtime_loading_evidence',
        'client_log_relative_to_game_root': 'DeltaForce/Saved/Logs/DeltaForce.log',
        'client_log_sha256': hashlib.sha256(raw).hexdigest(),
        'window_start_client_wall_time': first, 'window_end_client_wall_time': end,
        'window_end_reason': end_reason,
        'window_line_count': line_count, 'game_files_modified': False,
        'raw_lines_exported': False, 'session_values_exported': False,
        'game_flow_events': flow_events,
        'groups': {name: {'matching_lines': group['matching_lines'],
                         'top_functions': group['functions'].most_common(30),
                         'asset_paths': group['paths'].most_common(80),
                         'script_paths': group['scripts'].most_common(30),
                         'categories': group['categories'].most_common(12),
                         'samples': group['samples']}
                   for name, group in groups.items()},
        'limitations': [
            'Counts describe log evidence, not complete network actor or asset inventories',
            'A loaded AI asset does not provide server-side AI code',
            'This does not reconstruct actor replication properties or game rules',
            'Missing log symbols do not prove that resources or features are absent'],
    }


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--game-root', type=Path, required=True)
    parser.add_argument('--capture-folder', type=Path, required=True)
    args = parser.parse_args()
    folder = args.capture_folder.resolve()
    if not folder.is_relative_to(ROOT / 'work/official-ds-captures'):
        parser.error('Use the local official capture directory')
    manifest = json.loads((folder / 'report.json').read_text(encoding='utf-8'))
    report = collect(args.game_root, manifest)
    output = folder / 'runtime-loading-evidence.json'
    output.write_text(json.dumps(report, indent=2) + '\n', encoding='utf-8')
    print(json.dumps({'output': str(output), 'window_lines': report['window_line_count'],
                      'groups': {name: {'matching_lines': group['matching_lines'],
                                        'unique_functions_exported': len(group['top_functions']),
                                        'unique_paths_exported': len(group['asset_paths'])}
                                 for name, group in report['groups'].items()}}, indent=2))
