"""Reproduce a bounded, redacted review from already saved DS evidence only."""
import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def source(path):
    raw = (ROOT / path).read_bytes()
    return {'path': path, 'sha256': hashlib.sha256(raw).hexdigest()}


def load(path):
    return json.loads((ROOT / path).read_text(encoding='utf-8-sig'))


def main():
    trial = 'work/native-client-tests/1790952857916255400/game-server-packets/report.json'
    report = load(trial)
    control = report['handshake_probe']['native_control_probe']
    launch_path = 'outputs/native-account-provider/elevated-launch-observation.json'
    launch = load(launch_path)
    profile_path = 'outputs/df-local-server/protocol/native_ds_wire_profile.json'
    profile = load(profile_path)
    loading_path = 'work/evidence/iris-playable-loading-offline-anchors.json'
    loading = load(loading_path)
    set_path = 'work/evidence/native-post-join-set-actor-roots.json'
    native_set = load(set_path)
    order_path = 'work/evidence/native-actor-content-open-order-review.json'
    native_order = load(order_path)
    roots = [native_set['roots'][0], next(row for row in native_order['verified_fragments']
                                        if row['begin'] == '0x12861215')]
    verified = []
    for row in roots:
        for key, digest in (('code_relative_path', 'file_sha256'),
                            ('asm_relative_path', 'asm_sha256')):
            proof = source(row[key])
            if proof['sha256'] != row[digest]:
                raise ValueError('Saved native source digest changed')
        verified.append({key: row[key] for key in ('begin', 'end_exclusive', 'bytes',
                         'code_sha256', 'file_sha256', 'code_relative_path',
                         'asm_relative_path', 'asm_sha256')})
    exact_anchors = {
        'work/evidence/native-post-join-set-actor-roots.1286ed70.asm.txt': (
            '0x1286f2b0: test r12b, 1', '0x1286f2b4: jne 0x1286f341',
            '0x1286f2c4: call 0x12853830', '0x1286f2d8: lea rax, [rsi + 0xb8]',
            '0x1286f2e9: mov qword ptr [rax], rcx'),
        'work/evidence/native-post-join-receive-player-roots.12861215.asm.txt': (
            '0x1286142e: mov ebx, r13d', '0x128614c6: mov r8d, ebx',
            '0x128614cf: call qword ptr [rax + 0x308]',
            '0x128614e2: call qword ptr [rax + 0x310]',
            '0x128619c5: cmp qword ptr [rbp + 0xa0], r13',
            '0x128619cc: je 0x12861daa', '0x12861a33: call 0x12853830',
            '0x12861a5f: call qword ptr [r10 + 0x28]'),
    }
    for path, lines in exact_anchors.items():
        actual = (ROOT / path).read_text(encoding='utf-8').splitlines()
        if not all(line in actual for line in lines):
            raise ValueError('An exact instruction anchor changed')
    selected_keys = ('enabled', 'wire_codec_implemented',
        'client_load_map_join_observed_count', 'events', 'local_match_admissions',
        'initial_actor_open_transport_queue_implemented', 'initial_actor_channels_queued',
        'initial_actor_delivery_acks', 'initial_actor_channels_pending',
        'initial_actor_retries_exhausted', 'native_actor_resolution_verified',
        'native_actor_spawn_verified', 'actor_replication_implemented',
        'player_spawn_implemented', 'gameplay_server_implemented')
    evidence = {
        'kind': 'disk_only_ds_actor_bootstrap_and_ready_gap_review',
        'created_at_utc': datetime.now(timezone.utc).isoformat(),
        'scope': {'process_accessed': False, 'game_launched': False, 'uac': False,
                  'server_modified': False, 'identity_url_or_packet_payload_exported': False},
        'shipping_sha256': native_set['client_sha256'],
        'cache_manifest_sha256': native_set['manifest_sha256'],
        'sources': [source(path) for path in (trial, launch_path, profile_path,
                                            loading_path, set_path, order_path)],
        'historical_actual_trial': {
            'id': '1790952857916255400', 'qualified_as_current_running_trial': False,
            'listening_when_report_written': report['listening'],
            'native_control_datagrams_sent': report['native_control_datagrams_sent'],
            'initial_actor_open_datagrams_sent': report['initial_actor_open_datagrams_sent'],
            'control_summary_redacted': {key: control[key] for key in selected_keys},
            'interpretation': 'Two completed Hello/Login/Netspeed/Join control flows; '
                              'zero queued or sent initial Actor opens. End-state peer count '
                              'zero does not negate successful historical joins.'},
        'latest_launch_observation': {key: launch.get(key) for key in (
            'request_name', 'shell_execute_succeeded', 'windows_error',
            'requested_at_utc', 'completed_at_utc', 'ds_control_probe',
            'replication_metadata_export')},
        'welcome_mapping_qualification': {
            'source_profile': profile_path,
            'map_id': 2201,
            'meaning': 'Iris_Entry is the evidenced persistent world for the official Dam '
                       'session; Dam_Iris_Level1 is its selected gameplay configuration. '
                       'These names are not interchangeable class/archetype export definitions.',
            'native_acceptance': False},
        'reviewed_baseline_code': [
            {'path': 'outputs/df-local-server/dfserver/game_server_probe.py',
             'functions': ['queue_actor_open', '_receive_udp', '_send_control_retries'],
             'statement': 'Baseline public Actor producer is explicit and never called by '
                          'default; metadata export alone does not invoke it. Root is '
                          'implementing registered per-match manifests after this review.'},
            {'path': 'outputs/df-local-server/dfserver/legacy_ds_control_connection.py',
             'functions': ['_consume_new', 'handle', 'queue_actor_open', 'poll'],
             'statement': 'Join is committed by handle; queue requires admitted joined '
                          'ticket and explicit class/export/reference fields. poll only '
                          'sends Actor deliveries already present in actor_opens.'}],
        'safe_registration_hook': {
            'location': 'GameServerProbe._send_control_retries under self._lock, '
                        'after direct Join response send and before handshake.poll',
            'lock_is_non_reentrant': True,
            'do_not_call_public_queue_while_locked': True,
            'checks': ['Expire handshake before selecting peer',
                       'Bind immutable ticket identity plus player/room/map, not tuple alone',
                       'Use absolute monotonic for ticket expiry; relative time for handshake',
                       'Require current ticket_peers mapping and unique admitted joined peer',
                       'Stage complete manifest atomically before marking queue-once',
                       'Cancel expired or replaced binding; never rebind stale manifest',
                       'Recheck generation before send after releasing state lock',
                       'Record bounded static failure codes; never Cookie/URL/identity repr']},
        'empty_actor_open_base_replicator_proof': {
            'saved_roots_verified': verified,
            'exact_instruction_anchors': {key: list(value) for key, value in exact_anchors.items()},
            'conclusion': 'After an Actor was resolved, ordinary no-close Actor open calls '
                          'SetActor before InitActor and content loop. Base SetActor calls '
                          'FindOrCreateReplicator when its third flag is clear, storing '
                          'the shared pointer at ActorChannel+0xb8. Therefore no content '
                          'does not inherently prevent base replicator/cache construction.',
            'zero_bit_content': 'Body bit count zero jumps to cleanup before content-loop '
                                'FindOrCreateReplicator or replicator.ReceivedBunch.',
            'qualification': 'Game-specific virtual overrides, actual exported path/archetype '
                             'resolution and native receipt remain unverified. This does '
                             'not prove Pawn possession, Ready, or playable world.'},
        'formal_dam_loading_milestones': loading['loading_sequence'],
        'ordinary_loading_85_exact_gate_verified': False,
        'remaining_protocol_requirements': [
            'An explicit, evidence-backed per-match Actor bootstrap producer must invoke '
            'the queue on the admitted joined peer.',
            'Native GUID/class/CDO resolution and actual initial PC/Pawn/GameState creation '
            'must be observed before treating queued/sent bytes as client acceptance.',
            'Real class RepLayout metadata and supported property serialization are '
            'required for PC Pawn possession and initial replicated gameplay state.',
            'InfoInteract/NotifyEverythingReady/AllPlayerReady/GamePlayStateReady payload '
            'schemas remain separate from basic Hello-to-Join and Actor-open framing.',
            'Do not force loading percentage or reuse safehouse Pawn as gameplay spawn.'
        ],
        'native_acceptance': False, 'playable_map_implemented': False,
    }
    destination = ROOT / 'work/evidence/local-ds-bootstrap-ready-gap-review.json'
    destination.write_text(json.dumps(evidence, indent=2, ensure_ascii=False) + '\n', encoding='utf-8')
    print(json.dumps({'evidence': str(destination),
                      'sha256': hashlib.sha256(destination.read_bytes()).hexdigest(),
                      'native_saved_roots_verified': len(verified),
                      'instruction_anchors_verified': sum(map(len, exact_anchors.values())),
                      'process_accessed': False}))


if __name__ == '__main__':
    main()
