"""Bounded read-only collection of fresh official loading/replication symbols.

This does not capture packets, read process memory, modify the game, or send
requests. Only names, paths, event names and counts are retained; never log lines
or account/session values. The original running executable is verified first.
"""
import argparse
from collections import Counter
from datetime import datetime, timezone
import json
from pathlib import Path
import time

from capture_official_ds import FreshLogTail, SOURCE_SHA, SDK_SHA, digest, verified_pids, save
from collect_official_runtime_loading import RULES, safe_symbols

ROOT = Path(__file__).resolve().parent.parent
STATUS = ROOT / 'work/official-runtime-watch-status.json'


class SymbolEvidence:
    def __init__(self):
        self.groups = {name: {'matching_lines': 0, 'functions': Counter(), 'paths': Counter(),
                             'scripts': Counter(), 'categories': Counter()} for name in RULES}
        self.line_count = 0

    def consume(self, line):
        self.line_count += 1
        matches = [name for name, markers in RULES.items() if any(marker in line for marker in markers)]
        if not matches:
            return
        symbols = safe_symbols(line)
        for name in matches:
            group = self.groups[name]
            group['matching_lines'] += 1
            for key, source, bound in (('functions', 'function_names', 200),
                                        ('paths', 'asset_paths', 200),
                                        ('scripts', 'script_paths', 60),
                                        ('categories', 'categories', 40)):
                for value in symbols[source]:
                    if value in group[key] or len(group[key]) < bound:
                        group[key][value] += 1

    def summary(self):
        return {'fresh_lines_seen': self.line_count, 'raw_lines_exported': False,
                'session_values_exported': False, 'actor_property_schemas_recovered': False,
                'server_ai_implementation_recovered': False,
                'groups': {name: {'matching_lines': group['matching_lines'],
                                 'functions': group['functions'].most_common(200),
                                 'asset_paths': group['paths'].most_common(200),
                                 'script_paths': group['scripts'].most_common(60),
                                 'categories': group['categories'].most_common(40)}
                           for name, group in self.groups.items()}}


def watch(game_root, duration):
    previous = json.loads(STATUS.read_text(encoding='utf-8')) if STATUS.exists() else None
    if previous and not previous.get('record_complete'):
        import psutil
        if psutil.pid_exists(previous.get('helper_pid', 0)):
            raise RuntimeError('An existing read-only watcher is still running')
    executable = game_root / 'DeltaForce/Binaries/Win64/DeltaForceClient-Win64-Shipping.exe'
    sdk = game_root / 'DeltaForce/Binaries/ThirdParty/WeGame/Win64/rail_api64.dll'
    if digest(executable) != SOURCE_SHA or digest(sdk) != SDK_SHA:
        raise ValueError('Original client/SDK version was not verified')
    if not verified_pids(executable):
        raise RuntimeError('The verified original game is not running')
    folder = ROOT / 'work/official-runtime-watch' / str(time.time_ns())
    folder.mkdir(parents=True)
    tail = FreshLogTail(game_root / 'DeltaForce/Saved/Logs/DeltaForce.log')
    evidence = SymbolEvidence()
    import os
    report = {'kind': 'read_only_official_runtime_symbol_watch', 'helper_pid': os.getpid(),
              'started_at_utc': datetime.now(timezone.utc).isoformat(),
              'requested_duration_seconds': duration, 'record_complete': False,
              'status': 'watching_fresh_official_logs', 'original_client_verified': True,
              'game_modified': False, 'process_memory_read': False, 'packet_capture_active': False,
              'network_requests_sent': False,
              'source_log_relative_to_game_root': 'DeltaForce/Saved/Logs/DeltaForce.log',
              'report_relative_to_project_root': folder.relative_to(ROOT).as_posix() + '/report.json'}

    def update():
        report.update(evidence.summary())
        report['elapsed_seconds'] = round(time.monotonic() - start, 2)
        save(folder / 'report.json', report)
        # Small status avoids copying the collected symbol lists for every check.
        save(STATUS, {key: report[key] for key in
                      ('kind', 'helper_pid', 'status', 'record_complete', 'requested_duration_seconds',
                       'elapsed_seconds', 'fresh_lines_seen', 'report_relative_to_project_root',
                       'packet_capture_active', 'game_modified', 'process_memory_read')})

    start, next_update = time.monotonic(), 0
    try:
        update()
        print(json.dumps({'status': report['status'], 'helper_pid': os.getpid(),
                          'duration_seconds': duration}), flush=True)
        while time.monotonic() - start < duration:
            for line in tail.poll():
                evidence.consume(line)
            now = time.monotonic()
            if now >= next_update:
                if not verified_pids(executable):
                    report['stop_reason'] = 'original_game_exited'
                    break
                update()
                next_update = now + 5
            time.sleep(0.25)
        else:
            report['stop_reason'] = 'bounded_collection_window_complete'
        report['status'] = 'completed'
    except Exception as error:
        report.update(status='failed', error=type(error).__name__)
        raise
    finally:
        report['record_complete'] = True
        report['finished_at_utc'] = datetime.now(timezone.utc).isoformat()
        update()


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--game-root', type=Path, required=True)
    parser.add_argument('--duration-seconds', type=int, default=1800)
    args = parser.parse_args()
    if not 60 <= args.duration_seconds <= 1800:
        parser.error('Duration must be 60..1800 seconds')
    watch(args.game_root.resolve(), args.duration_seconds)
