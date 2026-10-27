"""Extract bounded map-entry evidence without printing native session URLs."""
import argparse
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import re


ROOT = Path(__file__).resolve().parent.parent
XOR_TABLE = bytes(value ^ 0x5c for value in range(256))
BINDING_LOG_MARKERS = {
    'UGPNetConnection::HandleClientPlayer': 'connection_handle_client_player',
    'UGPNetConnection::HandleClientPlayer  Super': 'connection_base_binding_called',
    'IGPSeamlessConnectionInterface::HandleClientPlayer': 'seamless_handle_client_player',
    'IGPSeamlessConnectionInterface::HandleClientPlayer  Super': 'seamless_base_binding_allowed',
    'IGPSeamlessConnectionInterface::HandleClientPlayer  SeamlessTravel': 'seamless_binding_allowed',
    'IGPSeamlessConnectionInterface::HandleClientPlayer  SeamlessTravel with NetActorRemapping':
        'seamless_binding_allowed_with_remapping',
}


def probe_transport_progress(probe):
    def record(value):
        return value if isinstance(value, dict) else {}

    def counter(source, key):
        value = source.get(key)
        return value if type(value) is int and value >= 0 else None

    def flag(source, key):
        value = source.get(key)
        return value if type(value) is bool else None

    control = record(record(probe.get('handshake_probe')).get('native_control_probe'))
    bootstrap = record(probe.get('initial_actor_bootstrap'))
    # Older reports omit these fields. Missing observations must remain unknown.
    progress = {key: counter(control, key) for key in (
        'hello_consumed_peers', 'login_authorized_peers',
        'client_load_map_join_observed_count', 'initial_actor_channels_queued',
        'initial_actor_delivery_acks', 'initial_actor_channels_pending')}
    progress.update({key: counter(bootstrap, key) for key in (
        'configured_map_profiles', 'registered_sets', 'waiting_for_join')})
    progress.update({
        'control_enabled': flag(control, 'enabled'),
        'initial_actor_open_datagrams_sent': counter(probe, 'initial_actor_open_datagrams_sent'),
        'native_spawn_verified': flag(bootstrap, 'native_spawn_verified'),
        'qualification': 'Probe report observations; transport delivery does not prove native binding',
    })
    return progress


def inspect_entry(log_path, probe_path=None):
    raw = log_path.read_bytes()
    # The observed client writes UTF-8 BOM followed by XOR-0x5c text. The BOM
    # itself is not XOR encoded. Never emit full log lines or connection URLs.
    text = raw[3:].translate(XOR_TABLE).decode('utf-8', 'replace')
    states = []
    resolved = []
    events = []
    handoffs = []
    url_shapes = []
    connection_failures = []
    binding_events = {}
    patterns = {
        'start_connect_requested': 'real start connect ds!!!',
        'physics_ready': 'StartLevelPhysicsLoad, PhysicsReady=1',
        'level_streaming_ready': 'bLevelStreamingReady!',
        'post_connect_observed': 'UDFMIrisEnterSubsystem::OnPostConnectDS,',
        'connection_timeout': 'OnTimeout: flow SeamlessFlow_TravelToDS timeout',
        'native_connection_timeout': 'Connection TIMED OUT',
        'ordinary_entry_setting_loaded': 'Setting CVar [[Game.DisableDeviceSeamless:1]]',
        'connection_url_built': '[GetLevelUrlAsync] url = ',
        'empty_secret_key_supported': 'AppendSecretKeyToUrl secretKey is empty, skip append',
        'net_driver_initialized': 'NetDriver RecvMulti is not yet supported',
        'all_players_ready_observed': 'OnDSNotifyAllPlayerReady',
    }
    for line in text.splitlines():
        wall_time = re.match(r'\[([^\]]+)\]', line)
        wall_time = wall_time[1] if wall_time else None
        log_message = re.search(
            r'\]([A-Za-z][A-Za-z0-9_]*):\s+'
            r'(?:VeryVerbose|Verbose|Log|Display|Warning|Error):\s+(.*)$', line)
        if log_message:
            category, message = log_message.groups()
            name = BINDING_LOG_MARKERS.get(message.strip())
            if category == 'LogNet' and re.fullmatch(
                    r'Client received PlayerController=.+\. Num child connections=\d+\.', message):
                name = 'controller_actor_open_logged'
            elif category == 'LogNet' and re.fullmatch(r'\S+ setplayer \S+', message):
                name = 'base_player_association_logged'
            if name:
                event = binding_events.setdefault(name, {
                    'name': name, 'count': 0, 'first_wall_time': wall_time})
                event['count'] += 1
        # The native graph logs full connection URLs as ArgStr. Extract only
        # event names and timestamps; never copy that argument into evidence.
        if 'UGameFlowGraph::OnLuaGameFlowEvent()' in line:
            handoff = re.search(
                r'MdlName = (Preparation|Room), EventName = '
                r'(flowEvtPreparationStartMatchSuccess|flowEvtRoomStartMatchSuccess)', line)
            if handoff:
                handoffs.append({'wall_time': wall_time, 'module': handoff[1],
                                 'event': handoff[2]})
        if '[GetLevelUrlAsync] url = ' in line:
            url = line.split('[GetLevelUrlAsync] url = ', 1)[1].lstrip(', ')
            # Only parameter names and lengths are kept, including identity
            # and ticket fields. Their contents remain in the private log.
            shape = {name: len(value) for name, value in
                     re.findall(r'\?([A-Za-z0-9_]+)=([^?\s]*)', url)}
            if shape and shape not in url_shapes:
                url_shapes.append(shape)
        state = re.search(
            r'CheckIsEnableSeamless , (true|false), DeviceDisableDeviceSeamless, (true|false)', line)
        if state:
            values = {'seamless_enabled': state[1] == 'true',
                      'device_seamless_disabled': state[2] == 'true'}
            if not states or any(states[-1][key] != value for key, value in values.items()):
                states.append({'wall_time': wall_time, **values})
        address = re.search(r'\[OnDnsAsyncResloved\].*ip and port:, ([0-9.]+), (\d+)', line)
        if address and address[1] == '127.0.0.1':
            value = {'address': address[1], 'port': int(address[2])}
            if value not in resolved:
                resolved.append(value)
        if (re.search(r'\]LogNet:\s+Warning:\s+UNetConnection::Tick: Connection TIMED OUT', line)
                and 'PC:' in line and 'Owner:' in line):
            connection_failures.append({
                'wall_time': wall_time,
                'player_controller_missing': bool(re.search(r'\bPC:\s*NULL\b', line)),
                'owner_missing': bool(re.search(r'\bOwner:\s*NULL\b', line)),
                'unique_id_invalid': bool(re.search(r'\bUniqueId:\s*INVALID\b', line)),
            })
        for name, marker in patterns.items():
            if marker in line and not any(event['name'] == name for event in events):
                events.append({'name': name, 'wall_time': wall_time})
    report = {
        'observed_at_utc': datetime.now(timezone.utc).isoformat(),
        'kind': 'native_map_entry_stage_evidence',
        'client_log_relative_to_game_root': 'DeltaForce/Saved/Logs/DeltaForce.log',
        'client_log_sha256': hashlib.sha256(raw).hexdigest(),
        'effective_entry_states': states,
        'resolved_loopback_addresses': resolved,
        'first_stage_events': events,
        'native_game_flow_handoffs': handoffs,
        'connection_url_parameter_lengths': url_shapes,
        'connection_failure_states': connection_failures,
        'client_player_binding_events': list(binding_events.values()),
        'client_player_binding_qualification':
            'Absence is unknown: these native markers depend on log verbosity; '
            'binding logs do not prove possession or playable input',
        'playability_conclusion': 'Not inferred from loading or connection events',
    }
    if probe_path:
        probe_raw = probe_path.read_bytes()
        probe = json.loads(probe_raw)
        report['local_ds_probe'] = {
            'address': probe['address'], 'port': probe['port'],
            'listening': probe['listening'],
            'packet_count': len(probe['records']),
            # Older trials did not record accepts; unknown is not zero.
            'tcp_connections_accepted': probe.get('tcp_connections_accepted'),
            'gameplay_server_implemented': probe['gameplay_server_implemented'],
            'report_sha256': hashlib.sha256(probe_raw).hexdigest(),
            'transport_progress': probe_transport_progress(probe),
        }
    return report


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--game-root', type=Path, required=True)
    parser.add_argument('--trial-directory', type=Path)
    parser.add_argument('--output', type=Path)
    args = parser.parse_args()
    probe_path = (args.trial_directory / 'game-server-packets/report.json'
                  if args.trial_directory else None)
    report = inspect_entry(args.game_root / 'DeltaForce/Saved/Logs/DeltaForce.log', probe_path)
    rendered = json.dumps(report, ensure_ascii=False, indent=2) + '\n'
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(rendered, encoding='utf-8')
    print(rendered, end='')
