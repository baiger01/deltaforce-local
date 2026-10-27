"""Seal installed CallNumeral semantics against an immutable redacted log view."""
import argparse
import ast
from datetime import datetime
import hashlib
import json
from pathlib import Path
import re

import research_economy_game_ready_lua_v4 as installed


ROOT = Path(__file__).resolve().parents[1]
LOG_SHA = '2ad80296109ea6caa9fd7db5746f57c448eddeaf9fdcce5de72c9e7868ce229f'
TARGETS = {
    '@MatchServer.lua': '4ec5c8287762a75c40be937d8588c03e2e0465e3735a274d86485ead38008be9',
    '@cs_matchroom_editor_pb.lua': '848c4fe9ab46fdf6f73caaec27b1e6f0dcac2648ee8ca45b45827d24409a79e4',
    '@errcode_pb.lua': '0b656ef417f1b3c6c429ebdf8ce59c1450a5d466a0b788dbced43981222ea2a5',
    '@AssemblySquadPick.lua': '4ad78024f7833d8e18fa361eba80f78cffa8c9ff22174b9a5afd6d44d9dddc1a',
    '@ArmedForceServer_SOLLogic.lua': '940132a559b1e85a6930859e8073b2348e83335e037107029cffcb057d3958bc',
}
SECRET = re.compile(r'token|ticket|authorization|password|cookie|credential|commandline', re.I)
STAMP = re.compile(r'^\[(\d{4}\.\d{2}\.\d{2}-\d{2}\.\d{2}\.\d{2}:\d{3})\]')


def scalar(text):
    return ast.literal_eval(text)


def err_assignments(function):
    """Interpret scalar literal assignments only, without executing installed Lua."""
    regs = {}
    result = {}
    for line in function['listing']:
        load = re.fullmatch(r'\d+ LOADK\s+R(\d+) K\d+=(.+)', line)
        if load:
            regs[int(load[1])] = scalar(load[2])
        store = re.fullmatch(r'\d+ SETTABLE\s+R1 (K\d+=.+|R\d+) (K\d+=.+|R\d+)', line)
        if store:
            def value(operand):
                return regs[int(operand[1:])] if operand.startswith('R') else scalar(operand.split('=', 1)[1])
            name, number = value(store[1]), value(store[2])
            if not isinstance(name, str) or type(number) is not int or name in result:
                raise ValueError('Unexpected installed Err scalar assignment')
            result[name] = number
    if not function['listing'][-2].endswith("K7='Err' R1"):
        raise ValueError('The installed scalar table is not published as Err')
    return result


def log_view(path):
    raw = path.read_bytes()
    if hashlib.sha256(raw).hexdigest() != LOG_SHA:
        raise ValueError('Use the exact owned diagnostic snapshot, not a live log')
    payload = raw[3:] if raw.startswith(b'\xef\xbb\xbf') else raw
    lines = bytes(value ^ 0x5c for value in payload).decode('utf8', 'replace').splitlines()
    events, prepare_ids, ready_ids, recovery_ids = [], [], [], []
    for number, line in enumerate(lines, 1):
        if SECRET.search(line):
            continue
        stamp = STAMP.match(line)
        if not stamp:
            continue
        event = None
        values = {}
        if 'MatchServer:_OnCSPrepareJoinMatchNtf client_group' in line:
            event = 'prepare_received'
        elif 'MatchServer:OnCSPrepareJoinMatchNtf()' in line and 'player_id:' in line:
            ids = re.search(r'\(\).*?, (\d+), .*?player_id:, (\d+),', line)
            if ids:
                prepare_ids.append((ids[1], ids[2]))
        elif 'AssemblySquadPick:SetHeroReady' in line:
            event = 'squad_set_hero_ready'
        elif 'ArmedForceServer:ReqSolReady,' in line:
            ids = re.search(r'ReqSolReady, (\d+)', line)
            if ids:
                ready_ids.append(ids[1])
            event = 'sol_ready_requested'
        elif 'MatchServer:ReqMatchRoomCheckCallNumeral,' in line:
            ids = re.search(r'CallNumeral, (\d+), (\d+)', line)
            if ids:
                recovery_ids.append(ids[1])
                values['reason'] = int(ids[2])
                event = 'call_numeral_requested'
        elif 'fMatchRoomCheckCallNumeralRes,' in line:
            result = re.search(r'fMatchRoomCheckCallNumeralRes, (\d+)', line)
            if result:
                values['result'] = int(result[1])
                event = 'call_numeral_response'
        elif 'MatchServer:OnJoinMatchFailed, CSMatchRoomCheckCallNumeralRes,' in line:
            event = 'call_numeral_join_failed'
        elif 'BreakRunningFlow() Reason: MatchServer:OnJoinMatchFailed' in line:
            event = 'join_failure_breaks_loading'
        elif 'ReqReconnectMatch' in line:
            event = 'separate_reconnect_requested'
        if event:
            events.append(dict(log_line=number, timestamp_local=stamp[1], event=event, **values))
    prepare_events = [row for row in events if row['event'] == 'prepare_received']
    recovery_events = [row for row in events if row['event'] == 'call_numeral_requested']
    if len(prepare_ids) != 2 or len(ready_ids) != 2 or len(recovery_ids) != 1:
        raise ValueError('The scoped reentry log no longer has the expected observed sequence')
    if len(prepare_events) != 2 or len(recovery_events) != 1:
        raise ValueError('Missing observed Prepare or CallNumeral event')
    parse = lambda text: datetime.strptime(text, '%Y.%m.%d-%H.%M.%S:%f')
    return dict(private_log_sha256=LOG_SHA, private_log_bytes=len(raw),
        private_log_total_lines=len(lines), events=events,
        latest_prepare_to_reason2_seconds=(parse(recovery_events[0]['timestamp_local']) -
            parse(prepare_events[-1]['timestamp_local'])).total_seconds(),
        identity_comparisons=dict(prepare_room_equals_player=[room == player for room, player in prepare_ids],
            prepare_reuses_room=prepare_ids[0][0] == prepare_ids[1][0],
            prepare_reuses_player=prepare_ids[0][1] == prepare_ids[1][1],
            ready_room_matches_prepare=[room == prepare[0] for room, prepare in zip(ready_ids, prepare_ids)],
            recovery_room_matches_latest_prepare=[room == prepare_ids[-1][0] for room in recovery_ids]),
        private_identifiers_emitted=False, raw_log_lines_emitted=False)


def derive(snapshot):
    installed.TARGETS = TARGETS
    verified = installed.derive()
    sources = {row['source_name']: row for row in verified['sources']}
    functions = {name: {row['function_id']: row for row in source['functions']}
        for name, source in sources.items()}
    errors = err_assignments(functions['@errcode_pb.lua']['0'])
    required_errors = {'Succeed': 0, 'MatchCallNumeralFailed': 13007, 'MatchRoomCallNumeralFail': 144030}
    if any(errors.get(name) != value for name, value in required_errors.items()):
        raise ValueError('Installed CallNumeral Err mappings changed')
    picks = {
        '@MatchServer.lua': ('0.73', '0.73.0', '0.74', '0.74.0', '0.75', '0.75.0', '0.102'),
        '@AssemblySquadPick.lua': ('0.54',),
        '@ArmedForceServer_SOLLogic.lua': ('0.18',),
        '@cs_matchroom_editor_pb.lua': ('0.4', '0.5', '0.6', '0.7', '0.8', '0.9'),
    }
    selected = {name: [functions[name][key] for key in keys] for name, keys in picks.items()}
    prepare = functions['@MatchServer.lua']['0.104']
    selected['@MatchServer.lua'].append(dict(function_id=prepare['function_id'],
        first_line=prepare['first_line'], last_line=prepare['last_line'],
        listing=prepare['listing'][210:240], excerpt_only=True))
    consumer_path = ROOT / 'outputs/df-local-server/dfserver/handshake_diagnostic.py'
    consumer_raw = consumer_path.read_bytes()
    consumer_text = consumer_raw.decode('utf8')
    tree = ast.parse(consumer_text)
    handler = next(node for node in tree.body if isinstance(node, ast.FunctionDef)
        and node.name == '_candidate_local_match_call_numeral_response')
    lines = consumer_text.splitlines()
    handler_source = lines[handler.lineno - 1:handler.end_lineno]
    for literal in ('body = _local_match_integer(1, 0 if success else 1)',
            'except (ValueError, DomainError):', 'not active(handoff.ticket)'):
        if not any(literal in line for line in handler_source):
            raise ValueError('Current local generic response semantics changed')
    codec_path = ROOT / 'outputs/df-local-server/protocol/generated_codec_fields.json'
    codec_raw = codec_path.read_bytes()
    messages = json.loads(codec_raw)['messages']
    wanted = {'CSMatchRoomCallNumeralNtf', 'CSMatchRoomCheckCallNumeralReq',
        'CSMatchRoomCheckCallNumeralRes', 'CSMatchRoomReconnectReq'}
    message_rows = [row for row in messages if row.get('name') in wanted]
    server_path = snapshot / 'private-server-report.json'
    server_raw = server_path.read_bytes()
    admission = json.loads(server_raw)['handshake_probe']['native_control_probe']['local_match_admissions']
    counts = {key: admission[key] for key in ('active_ticket_count', 'issued_ticket_count',
        'authorized_login_count', 'denied_login_count')}
    return dict(kind='installed_call_numeral_reentry_audit_v1',
        scope=dict(process_access=False, client_launched=False, production_modified=False,
            lua_executed=False, installed_baseline_verified=True, hotfix_override_absence_proven=False),
        source_index_sha256=verified['source_index_sha256'],
        source_pins={str(consumer_path.relative_to(ROOT)): hashlib.sha256(consumer_raw).hexdigest(),
            str(codec_path.relative_to(ROOT)): hashlib.sha256(codec_raw).hexdigest(),
            'work/research_economy_call_numeral_reentry_v1.py': hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
            'work/research_economy_game_ready_lua_v4.py': hashlib.sha256(Path(installed.__file__).read_bytes()).hexdigest(),
            **verified['helper_source_pins']},
        installed_sources=[{key: value for key, value in row.items() if key != 'functions'}
            for row in verified['sources']], installed_function_evidence=selected,
        err_table=dict(published_name='Err', parsed_scalar_entries=len(errors),
            relevant_mappings=required_errors, names_with_value_one=[key for key, value in errors.items() if value == 1],
            enum_binding_for_response_result_proven=False),
        generated_message_fields=message_rows,
        current_local_handler=dict(path=str(consumer_path.relative_to(ROOT)),
            first_line=handler.lineno, last_line=handler.end_lineno, source=handler_source,
            failure_result=1, failure_is_local_generic_rejection=True,
            failure_preserves_distinct_cause=False, direct_hero_comparison=False),
        observed=log_view(snapshot / 'private-client-log.bin'),
        admission_snapshot=dict(sha256=hashlib.sha256(server_raw).hexdigest(), counts=counts),
        conclusions=[
            'The second Prepare was followed by SetHeroReady and ReqSolReady; it did not stall before the client Ready call.',
            'Observed reason 2 at 180.026 seconds is the installed Prepare watchdog, not CSMatchRoomReconnectReq.',
            'Both Ready room values and the recovery room value match their observed Prepare; IDs are deliberately omitted.',
            'The current local handler writes result 1 after any caught ValueError or DomainError; 1 does not identify a hero or official CallNumeral error.',
            'Installed Err.MatchRoomCallNumeralFail is 144030; the response result and request reason are plain unsigned scalar fields.',
            'A Ready handoff preflight failure latches local_match_handoff_failed; the subsequent recovery is passed prepared=False and cannot retry issuance.',
            'The immutable snapshot has admission counters but no per-request local_match_recovery_preflight_failed state; the precise rejected gate requires the business continuation progress record.',
        ],
        repair_boundary=dict(no_result_zero_without_valid_handoff=True,
            do_not_manufacture_second_ticket_in_watchdog=True,
            investigate_second_ready_preflight_or_gate_before_watchdog=True,
            normal_reconnect_is_separate_business_request=True,
            native_reconnect_or_hero_error_claimed=False))


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--snapshot', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    if args.output.exists() or not args.output.resolve().is_relative_to(ROOT / 'work/evidence'):
        parser.error('Use a fresh audit-only evidence path')
    report = derive(args.snapshot)
    raw = (json.dumps(report, sort_keys=True, indent=2) + '\n').encode('ascii')
    with args.output.open('xb') as stream:
        stream.write(raw)
    print(json.dumps(dict(path=str(args.output), sha256=hashlib.sha256(raw).hexdigest(),
        event_count=len(report['observed']['events']), admission_counts=report['admission_snapshot']['counts'],
        private_identifiers_emitted=False)))
