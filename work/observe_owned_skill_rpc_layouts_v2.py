"""Independent six-function observer; supports explicit active-trial snapshots."""
import argparse
import ctypes
import json
from pathlib import Path

import observe_owned_skill_rpc_layouts as previous
from skill_rpc_layout_readonly_scope_v2 import (ROOT, source_pins, private_function,
    export_existing_skill_rpc_layouts)


def select_trial_report(trial_report=None, *, active_trial_snapshot=None):
    if (trial_report is None) == (active_trial_snapshot is None):
        raise ValueError('Supply exactly one owned trial report or explicit active-trial snapshot')
    return Path(active_trial_snapshot if active_trial_snapshot is not None else trial_report)


def observe(game_root, trial_report=None, *, active_trial_snapshot=None):
    selected = select_trial_report(trial_report, active_trial_snapshot=active_trial_snapshot)
    scoped = private_function(previous.observe, source_pins=source_pins,
        export_existing_skill_rpc_layouts=export_existing_skill_rpc_layouts)
    result = scoped(game_root, selected)
    result.update(kind='owned_current_dfm_skill_existing_rpc_layouts_v2',
        trial_input_kind='explicit_active_trial_snapshot' if active_trial_snapshot is not None else 'owned_trial_report',
        function_layout_key_kind='weak_object_index_and_serial',
        serial_zero_proves_layout_absence=False, pointer_key_lookup_supported=False)
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--game-root', type=Path, required=True)
    inputs = parser.add_mutually_exclusive_group(required=True)
    inputs.add_argument('--trial-report', type=Path)
    inputs.add_argument('--active-trial-snapshot', type=Path)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--request-uac', action='store_true')
    args = parser.parse_args()
    selected = select_trial_report(args.trial_report, active_trial_snapshot=args.active_trial_snapshot)
    output = args.output.resolve()
    if output.exists() or not output.is_relative_to((ROOT/'work').resolve()):
        parser.error('Use an exclusive new project work output')
    previous.owned_trial_identity(json.loads(selected.read_bytes()), args.game_root)
    source_pins()
    if args.request_uac and not ctypes.windll.shell32.IsUserAnAdmin():
        option = '--active-trial-snapshot' if args.active_trial_snapshot is not None else '--trial-report'
        previous.request_elevation(['-B', str(Path(__file__).resolve()), '--game-root', str(args.game_root.resolve()),
            option, str(selected.resolve()), '--output', str(output)], output)
        report = json.loads(output.read_bytes())
    else:
        try:
            report = observe(args.game_root, args.trial_report, active_trial_snapshot=args.active_trial_snapshot)
        except Exception as error:
            report = dict(status='refused', reason=str(error), error_type=type(error).__name__,
                native_methods_invoked=False, process_memory_written=False, code_sampled=False,
                packets_sent=False, native_layouts_constructed=False, pointer_key_substituted=False)
        previous.write_exclusive_report(output, report)
    print(json.dumps(dict(status=report['status'], reason=report.get('reason'), output=str(output))))


if __name__ == '__main__':
    main()
