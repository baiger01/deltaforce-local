"""Bounded original-client test of our authenticated partial native provider."""
from datetime import datetime, timezone
from pathlib import Path
import argparse
import ctypes
import hashlib
import json
import os
import secrets
import shutil
import struct
import subprocess
import sys
import threading
import time
import traceback

import psutil
from client_resource_sampling import capture_resources
from client_module_snapshot import loaded_module_names
from local_game_paths import game_paths
from watch_client_log import follow as follow_client_log

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "outputs/df-local-server"))
from dfserver.core import Backend
from dfserver.http_api import create_server
from dfserver.protobuf_codec import ProtobufCodec
from dfserver.handshake_diagnostic import Server as HandshakeDiagnosticServer, State as HandshakeDiagnosticState
from dfserver.game_server_probe import GameServerProbe

SOURCE_GAME, SHADOW_GAME = game_paths()
if SOURCE_GAME == SHADOW_GAME:
    raise ValueError("The source game and independent test client must be different directories")
parser = argparse.ArgumentParser()
parser.add_argument("--entry", choices=("shipping", "bootstrap"), default="shipping")
parser.add_argument("--game-root", type=Path, default=SOURCE_GAME)
parser.add_argument("--wire-identity-probe", action="store_true")
parser.add_argument("--wire-auth-response-probe", action="store_true")
parser.add_argument("--wire-auth-identity-probe", action="store_true")
parser.add_argument("--wire-ready-probe", action="store_true")
parser.add_argument("--wire-ready-identity-probe", action="store_true")
parser.add_argument("--wire-business-login-probe", action="store_true")
parser.add_argument("--wire-business-bootstrap-probe", action="store_true")
parser.add_argument("--observation-seconds", type=int, default=1800)
parser.add_argument("--precreate-game-nick", action="store_true")
parser.add_argument("--game-server-probe", action="store_true",
                    help="Bounded local DS handoff; captures first TCP/UDP packets only")
parser.add_argument("--ds-handshake-probe", action="store_true",
                    help="Opt-in loopback plaintext challenge/ACK experiment; not a gameplay server")
parser.add_argument("--ds-packet-ack-probe", action="store_true",
                    help="Opt-in bounded empty packet ACK experiment; control channel remains unimplemented")
parser.add_argument("--ds-control-probe", action="store_true",
                    help="Opt-in source-backed Hello/Challenge exchange; no code reads")
parser.add_argument("--ds-control-profile", type=Path,
                    help="Explicit project-local control profile with hash-checked map evidence")
parser.add_argument("--replication-metadata-export", action="store_true",
                    help="Export bounded class/replication metadata once from the owned shadow lobby client")
parser.add_argument("--bootstrap-template-observation", action="store_true",
                    help="Collect fresh five-role template metadata without historical match files")
parser.add_argument("--ds-initial-actor-bootstrap", action="store_true",
                    help="Register one source-backed Pawn Actor-open after successful metadata export; spawn unverified")
parser.add_argument("--connection-binding-observation", action="store_true",
                    help="After Actor transport ACK, read typed connection/PlayerController binding pointers once")
parser.add_argument("--connection-rpc-layouts", action="store_true",
                    help="In the same post-Actor binding/class-cache observation, read existing scoped PC RPC layouts; no parameter values")
parser.add_argument("--connection-guid-mappings", action="store_true",
                    help="In the same post-association binding/class-cache observation, read only existing GUID2/4/6 associations")
parser.add_argument("--ds-initial-actor-associations", action="store_true",
                    help="Opt-in source-sealed ordinary PC/Pawn reference content after all Actor opens are ACKed")
parser.add_argument("--ds-human-player-state-fields", action="store_true",
                    help="Send the verified single-trial human PlayerState fields after possession")
parser.add_argument("--ds-human-player-state-fields-early", action="store_true",
                    help="Diagnostic: deliver the same verified fields before initial PC/Pawn associations")
parser.add_argument("--ds-transport-code-probe", action="store_true",
                    help="One bounded read of two verified transport functions after a local connection is observed")
parser.add_argument("--ds-connection-class-code-probe", action="store_true",
                    help="Bounded code trace from two verified connection class type records")
parser.add_argument("--ds-control-code-probe", action="store_true",
                    help="Read exact named control-bunch anchors once, then continue observing the client")
parser.add_argument("--ds-control-candidate-interval", action="store_true",
                    help="With the control profile, read only the fixed 13-function candidate interval")
parser.add_argument("--ds-control-field-helpers", action="store_true",
                    help="With the control profile, read only three verified control-field callees")
parser.add_argument("--ds-control-followup-code", action="store_true",
                    help="Read four fixed field continuations and the typed SendBunch entry in one trial")
parser.add_argument("--ds-control-sender-body", action="store_true",
                    help="Read the fixed sender wrapper and source-proved implementations")
parser.add_argument("--ds-image-code-cache", action="store_true",
                    help="Save private executable-section code for offline protocol analysis")
parser.add_argument('--updated-client-code-observation', action='store_true',
                    help='Isolated updated-build lobby code observation; no gameplay or old metadata readers')
parser.add_argument('--updated-client-metadata-observation', action='store_true',
                    help='Isolated updated-build class metadata observation; no gameplay or instance payloads')
parser.add_argument('--updated-client-transport-observation', action='store_true',
                    help='Updated-build handshake/packet experiment only; no control or Actor bootstrap')
parser.add_argument('--updated-minimum-actor-bootstrap', action='store_true',
                    help='Current source-derived minimum Actors with a live receiver check')
parser.add_argument("--stop-after-code-collection", action="store_true",
                    help="With --ds-control-code-probe, stop and restore after the read attempt")
parser.add_argument("--entry-code-probe", action="store_true",
                    help="Collect named entry code samples and finish the trial automatically")
parser.add_argument("--disable-device-seamless", action="store_true",
                    help="Use the native Game.DisableDeviceSeamless setting for this trial")
parser.add_argument("--disable-dynamic-address-switch", action="store_true",
                    help="Keep the shadow client's local DS endpoint fixed using its native CVar")
parser.add_argument("--enable-sol-map-entry-loading", action="store_true",
                    help="Use the native subworld-name lookup for this shadow map trial")
parser.add_argument("--use-qualified-subworld", action="store_true",
                    help="Pass the source-qualified Dam subworld name to the client's native fallback")
parser.add_argument("--native-username", help="Local username when the test database contains multiple accounts")
parser.add_argument("--portable-map-bootstrap", type=Path,
                    help="Use an explicit available-source Dam bootstrap diagnostic profile")
args = parser.parse_args()
CONTROL_PROFILE = ROOT / "outputs/df-local-server/protocol/native_ds_wire_profile.json"
if args.ds_control_profile is not None:
    if not args.ds_control_probe:
        parser.error("--ds-control-profile requires --ds-control-probe")
    CONTROL_PROFILE = args.ds_control_profile.resolve()
    if not CONTROL_PROFILE.is_relative_to(ROOT.resolve()) or not CONTROL_PROFILE.is_file():
        parser.error("--ds-control-profile must be an existing file inside the project")
if args.portable_map_bootstrap is not None:
    args.portable_map_bootstrap = args.portable_map_bootstrap.resolve(strict=True)
    if not (args.ds_control_probe and args.game_server_probe and args.bootstrap_template_observation) or args.ds_initial_actor_bootstrap:
        parser.error("Portable bootstrap requires control, server and template observation; use it separately from the archived bootstrap")
if args.bootstrap_template_observation and (not args.replication_metadata_export or
        args.ds_initial_actor_bootstrap or args.connection_binding_observation or
        args.connection_rpc_layouts or args.connection_guid_mappings):
    parser.error("--bootstrap-template-observation requires isolated replication metadata export")
GAME = args.game_root.resolve()
if GAME not in (SOURCE_GAME, SHADOW_GAME):
    parser.error('--game-root must be the installed client or its checked workspace shadow')
if not 30 <= args.observation_seconds <= 1800:
    parser.error("--observation-seconds must be between 30 and 1800")
if args.wire_auth_response_probe and not args.wire_identity_probe:
    parser.error("--wire-auth-response-probe requires --wire-identity-probe")
if args.wire_auth_identity_probe and not args.wire_auth_response_probe:
    parser.error("--wire-auth-identity-probe requires --wire-auth-response-probe")
if args.wire_ready_probe and not args.wire_auth_response_probe:
    parser.error("--wire-ready-probe requires --wire-auth-response-probe")
if args.wire_ready_identity_probe and not args.wire_ready_probe:
    parser.error("--wire-ready-identity-probe requires --wire-ready-probe")
if args.wire_business_login_probe and not (args.wire_auth_identity_probe and args.wire_ready_probe):
    parser.error("--wire-business-login-probe requires local auth and ready probes")
if args.wire_business_bootstrap_probe and not args.wire_business_login_probe:
    parser.error("--wire-business-bootstrap-probe requires --wire-business-login-probe")
if args.game_server_probe and not args.wire_business_bootstrap_probe:
    parser.error("--game-server-probe requires --wire-business-bootstrap-probe")
if args.use_qualified_subworld:
    parser.error('Startup SUBWORLD override is disabled: it applies before the lobby; use the native map-entry stage')
if args.ds_handshake_probe and not args.game_server_probe:
    parser.error("--ds-handshake-probe requires --game-server-probe")
if args.ds_packet_ack_probe and not args.ds_handshake_probe:
    parser.error("--ds-packet-ack-probe requires --ds-handshake-probe")
if args.ds_control_probe and (not args.ds_packet_ack_probe or GAME != SHADOW_GAME or
                            args.entry != "shipping"):
    parser.error("--ds-control-probe requires shipping shadow and packet transport probes")
if args.ds_control_probe and (args.ds_transport_code_probe or args.ds_connection_class_code_probe or
        args.ds_control_code_probe or args.ds_image_code_cache or args.entry_code_probe):
    parser.error("Native control exchange must run separately from code collection")
if args.ds_transport_code_probe and not args.game_server_probe:
    parser.error("--ds-transport-code-probe requires --game-server-probe")
if args.ds_connection_class_code_probe and not args.game_server_probe:
    parser.error("--ds-connection-class-code-probe requires --game-server-probe")
if args.ds_control_code_probe and not args.game_server_probe:
    parser.error("--ds-control-code-probe requires --game-server-probe")
if args.ds_control_candidate_interval and not args.ds_control_code_probe:
    parser.error("--ds-control-candidate-interval requires --ds-control-code-probe")
if args.ds_control_field_helpers and not args.ds_control_code_probe:
    parser.error("--ds-control-field-helpers requires --ds-control-code-probe")
if args.ds_control_field_helpers and args.ds_control_candidate_interval:
    parser.error("Choose only one fixed control-code read profile")
if args.ds_control_followup_code and not args.ds_control_code_probe:
    parser.error("--ds-control-followup-code requires --ds-control-code-probe")
if args.ds_control_followup_code and (args.ds_control_field_helpers or args.ds_control_candidate_interval):
    parser.error("Choose only one fixed control-code read profile")
if args.ds_control_sender_body and not args.ds_control_code_probe:
    parser.error("--ds-control-sender-body requires --ds-control-code-probe")
if args.ds_control_sender_body and (args.ds_control_followup_code or args.ds_control_field_helpers or args.ds_control_candidate_interval):
    parser.error("Choose only one fixed control-code read profile")
if args.ds_image_code_cache and (not args.game_server_probe or GAME != SHADOW_GAME or args.entry != "shipping"):
    parser.error("--ds-image-code-cache requires the shipping shadow client and local game-server profile")
if args.stop_after_code_collection and not (args.ds_control_code_probe or args.ds_image_code_cache):
    parser.error("--stop-after-code-collection requires control code collection or image code cache")
if sum((args.ds_transport_code_probe, args.ds_connection_class_code_probe,
        args.ds_control_code_probe, args.ds_image_code_cache)) > 1:
    parser.error("Choose only one DS code collection profile")
if (args.ds_control_code_probe or args.ds_image_code_cache) and args.entry_code_probe:
    parser.error("The control code profile cannot be combined with entry code collection")
if args.entry_code_probe and not args.game_server_probe:
    parser.error("--entry-code-probe requires --game-server-probe")
if args.disable_device_seamless and not args.game_server_probe:
    parser.error("--disable-device-seamless requires --game-server-probe")
if (args.disable_device_seamless or args.disable_dynamic_address_switch or args.enable_sol_map_entry_loading) and (GAME != SHADOW_GAME or args.entry != "shipping"):
    parser.error("Physical Engine overrides require the shipping shadow client")
if args.enable_sol_map_entry_loading and not args.ds_control_probe:
    parser.error("--enable-sol-map-entry-loading requires the native local DS control trial")
if args.disable_dynamic_address_switch and (not args.game_server_probe or
        GAME != SHADOW_GAME or args.entry != "shipping"):
    parser.error("--disable-dynamic-address-switch requires the shipping shadow and local DS probe")
if args.replication_metadata_export and (not args.game_server_probe or GAME != SHADOW_GAME or args.entry != "shipping"):
    parser.error("--replication-metadata-export requires the shipping shadow client and local game-server profile")
if args.replication_metadata_export and (args.ds_transport_code_probe or args.ds_connection_class_code_probe or
        args.ds_control_code_probe or args.ds_control_candidate_interval or args.ds_control_field_helpers or
        args.ds_control_followup_code or args.ds_control_sender_body or args.ds_image_code_cache or
        args.entry_code_probe or args.stop_after_code_collection):
    parser.error("Replication metadata export must run separately from program code collection")
if args.ds_initial_actor_bootstrap and (GAME != SHADOW_GAME or args.entry != "shipping" or
        not args.ds_control_probe or not args.replication_metadata_export):
    parser.error("--ds-initial-actor-bootstrap requires shipping shadow, native control and replication metadata export")
if args.ds_initial_actor_bootstrap and (args.ds_transport_code_probe or args.ds_connection_class_code_probe or
        args.ds_control_code_probe or args.ds_control_candidate_interval or args.ds_control_field_helpers or
        args.ds_control_followup_code or args.ds_control_sender_body or args.ds_image_code_cache or
        args.entry_code_probe or args.stop_after_code_collection):
    parser.error("Initial Actor bootstrap must run separately from program code collection")
if args.connection_binding_observation and not args.ds_initial_actor_bootstrap:
    parser.error("--connection-binding-observation requires --ds-initial-actor-bootstrap")
if args.connection_rpc_layouts and not (args.ds_initial_actor_bootstrap and args.connection_binding_observation):
    parser.error("--connection-rpc-layouts requires initial Actor bootstrap and binding/class-cache observation")
if args.connection_guid_mappings and not (
        args.ds_initial_actor_bootstrap and args.connection_binding_observation and args.ds_initial_actor_associations):
    parser.error("--connection-guid-mappings requires initial Actor bootstrap, associations and binding/class-cache observation")
if getattr(args, 'ds_initial_actor_associations', False) and not (
        args.ds_initial_actor_bootstrap and args.connection_binding_observation):
    parser.error("--ds-initial-actor-associations requires initial Actor bootstrap and binding observation")
if args.ds_human_player_state_fields and not args.ds_initial_actor_associations:
    parser.error("--ds-human-player-state-fields requires initial Actor associations")
if args.ds_human_player_state_fields_early and not args.ds_initial_actor_associations:
    parser.error("--ds-human-player-state-fields-early requires initial Actor associations")
if args.ds_human_player_state_fields and args.ds_human_player_state_fields_early:
    parser.error("Early and late human PlayerState diagnostics are mutually exclusive")
SDK = GAME / "DeltaForce/Binaries/ThirdParty/WeGame/Win64/rail_api64.dll"
if GAME == SHADOW_GAME and SDK.is_file() and os.path.samefile(
        SDK, SOURCE_GAME / SDK.relative_to(GAME)):
    parser.error('The shadow SDK must be an independent copy, not a hard link')
ENTRY = GAME / ("DeltaForce/Binaries/Win64/DeltaForceClient-Win64-Shipping.exe" if args.entry == "shipping" else "DeltaForceClient.exe")
STAGE = ROOT / "work/sdk-local-provider-stage"
SDK_SHA = "9d39a0f5af96d56f465060a582e21faf5c11d5cfdd4e221891d81c58cd7f1723"
ENTRY_SHA = "4254fbe66585f260f1f9dbfc5e302887842552e7baed8939e023160a5e250be0" if args.entry == "shipping" else "6d5f71f958dee483e126337d183849059ef904938e45dfdd0f3cda73e1eeb40b"
from updated_minimum_launch import qualify_launch as qualify_updated_launch
updated_code_observation = qualify_updated_launch(args, GAME, SHADOW_GAME)
if updated_code_observation is not None:
    ENTRY_SHA = updated_code_observation['client_sha256']
def load_control_trial_profile(profile_path, root, client_sha256, selected_map_id):
    """Validate the control profile before staging files or requesting UAC.

    Keep this pure preflight mirrored in the runner and UAC wrapper. Its tests
    execute only this function and the profile-loading statements.
    """
    try:
        profile = json.loads(Path(profile_path).read_text(encoding="utf-8"))
    except (OSError, UnicodeError, ValueError) as error:
        raise ValueError("Native control trial profile could not be read as JSON") from error
    if (not isinstance(profile, dict) or profile.get("client_sha256") != client_sha256 or
            type(profile.get("hello_net_version")) is not int or
            not 0 <= profile["hello_net_version"] < 1 << 32 or
            type(profile.get("maximum_packet_bytes")) is not int or
            not 1 <= profile["maximum_packet_bytes"] <= 1492):
        raise ValueError("Native control trial profile does not match this client")
    maps = profile.get("control_welcome_maps")
    if not isinstance(maps, dict) or not 1 <= len(maps) <= 64:
        raise ValueError("Native control profile requires bounded control_welcome_maps")
    for map_id, spec in maps.items():
        if (not isinstance(map_id, str) or not map_id.isascii() or
                not map_id.isdecimal() or len(map_id) > 10 or map_id != str(int(map_id)) or
                not 0 < int(map_id) < 1 << 32 or not isinstance(spec, dict)):
            raise ValueError("Native control profile contains an invalid Welcome map ID or entry")
        level = spec.get("level")
        if (not isinstance(level, str) or not level or len(level) > 256 or
                any(char in level for char in "?\0\r\n")):
            raise ValueError("Native control profile contains an invalid Welcome Level")
        for name in ("game", "redirect"):
            value = spec.get(name, "")
            if (not isinstance(value, str) or len(value) > 256 or
                    any(char in value for char in "\0\r\n")):
                raise ValueError("Native control profile contains an invalid Welcome string")
    if isinstance(selected_map_id, str):
        if not selected_map_id.isascii() or not selected_map_id.isdecimal():
            raise ValueError("Native control trial requires a positive selected DS map ID")
        # Reject oversized input before converting an environment-variable value.
        if len(selected_map_id) > 10:
            raise ValueError("Native control selected DS map ID is outside uint32")
        selected_map_id = int(selected_map_id)
    if type(selected_map_id) is not int or not 0 < selected_map_id < 1 << 32:
        raise ValueError("Native control trial requires a positive selected DS map ID")
    if str(selected_map_id) not in maps:
        raise ValueError("Selected DS map ID has no evidenced control_welcome_maps entry")
    relative = profile.get("welcome_map_evidence_relative_to_project_root")
    expected_hash = profile.get("welcome_map_evidence_sha256")
    from pathlib import PureWindowsPath
    if (not isinstance(relative, str) or not relative or
            PureWindowsPath(relative).drive or PureWindowsPath(relative).root or
            Path(relative).is_absolute()):
        raise ValueError("Welcome map evidence must use a relative path inside the project ROOT")
    if (not isinstance(expected_hash, str) or len(expected_hash) != 64 or
            any(char not in "0123456789abcdef" for char in expected_hash)):
        raise ValueError("Welcome map evidence requires a lowercase SHA256")
    root = Path(root).resolve()
    try:
        evidence = (root / relative.replace("\\", "/")).resolve()
        if not evidence.is_relative_to(root) or not evidence.is_file():
            raise ValueError("Welcome map evidence path escapes ROOT or is not a file")
        with evidence.open("rb") as stream:
            actual_hash = hashlib.file_digest(stream, "sha256").hexdigest()
    except OSError as error:
        raise ValueError("Welcome map evidence could not be read") from error
    if actual_hash != expected_hash:
        raise ValueError("Welcome map evidence SHA256 does not match the control profile")
    return profile


def updated_map_metadata_ready(mode, probe, *, attempted, seconds_left):
    """An actual new-build Join, with room for bounded collection and cleanup."""
    if (mode != 'updated_control_metadata_capture' or attempted is not False or
            type(seconds_left) not in (int, float) or seconds_left < 300):
        return False
    progress = probe.map_join_progress
    joined, active = progress.get('join_observed_count'), progress.get('active_joined_peers')
    return type(joined) is int and joined > 0 and type(active) is int and active > 0


def replication_metadata_collect_options(*, initial_actor_bootstrap, observation_seconds, elapsed_seconds):
    """Bound an explicit bootstrap scan while retaining time for trial cleanup."""
    if type(initial_actor_bootstrap) is not bool:
        raise ValueError("Metadata bootstrap budget requires an explicit boolean")
    if not initial_actor_bootstrap:
        return {}
    if (type(observation_seconds) is not int or not 30 <= observation_seconds <= 1800 or
            type(elapsed_seconds) not in (int, float) or
            not 0 <= elapsed_seconds <= observation_seconds):
        raise ValueError("Metadata bootstrap budget requires bounded observation timing")
    maximum_seconds = min(600, int(observation_seconds - elapsed_seconds - 60))
    if maximum_seconds < 10:
        raise ValueError("Metadata bootstrap scan requires ten seconds plus sixty seconds for cleanup")
    return {'bootstrap_registry_batch_retry': True, 'maximum_seconds': maximum_seconds}


def _replication_metadata_retry_due_once(report, elapsed_seconds, lobby_candidates, observation_seconds=900):
    """Allow one fresh scan after a transient change, in the same owned process."""
    if report.get('ds_initial_actor_bootstrap_progress', {}).get('stage') == 'ds_initial_actor_bootstrap_prepared':
        return False
    attempts = report.get('replication_metadata_export_attempts')
    if type(attempts) is not list or len(attempts) != 1 or type(attempts[0]) is not dict:
        return False
    last = attempts[0]
    identity = report.get('replication_metadata_export_identity')
    if type(identity) is not dict or lobby_candidates != {(identity.get('pid'), identity.get('created_at'))}:
        return False
    stable = report.get('replication_metadata_lobby_stability')
    if (type(stable) is not dict or stable.get('pid') != identity.get('pid') or
            stable.get('created_at') != identity.get('created_at')):
        return False
    transient_reasons = {
        'Selected metadata root identity changed after discovery',
        'Class descriptor name changed during discovery',
        'Target class Outer changed between template candidates',
        'Selected object class binding changed after discovery',
        'Selected class metadata path changed after discovery',
        'Class descriptor changed during the complete registry scan',
        'Named template candidate binding changed during discovery',
        # A template can load after its Class passed the first scan boundary.
        # Retry a complete scan once; never accept the inconsistent report.
        'Named template candidate is not bound to a selected UClass',
        'Named template candidate path changed during discovery',
        'Named template candidate Outer path changed during discovery',
        'Selected metadata virtual method binding changed',
        'Selected class key changed during driver table export',
        'Selected NetDriver key changed during table export',
        'Selected object class binding changed during table export',
    }

    def discarded_initialization_batch(context):
        # Only a fresh scan may recover this rejected batch. Never accept the
        # inconsistent report or relax the registry reader's identity checks.
        if (type(context) is not dict or set(context) != {
                'phase', 'index_range', 'first_changed_object_index',
                'changed_slot_count', 'changes', 'changes_truncated',
                'batch_records_yielded'} or
                context['phase'] != 'registry_batch_recheck' or
                context['changes_truncated'] is not False or
                context['batch_records_yielded'] is not False):
            return False
        bounds, count, changes = context['index_range'], context['changed_slot_count'], context['changes']
        if (type(bounds) is not list or len(bounds) != 2 or
                any(type(index) is not int for index in bounds) or
                not 0 <= bounds[0] < bounds[1] <= 1 << 31 or
                type(count) is not int or not 1 <= count <= 8 or
                type(changes) is not list or len(changes) != count or
                type(context['first_changed_object_index']) is not int):
            return False
        seen = set()
        before_serial = {'pointer_state': 'non_null', 'flag_state': 'not_excluded',
                         'serial_state': 'uninitialized'}
        after_serial = dict(before_serial, serial_state='initialized')
        before_publication = dict(before_serial, pointer_state='null')
        after_publication = before_serial
        for change in changes:
            if (type(change) is not dict or set(change) != {
                    'object_index', 'changed_fields', 'before', 'after'} or
                    type(change['object_index']) is not int or
                    not bounds[0] <= change['object_index'] < bounds[1] or
                    change['object_index'] in seen or
                    type(change['changed_fields']) is not list or
                    type(change['before']) is not dict or type(change['after']) is not dict):
                return False
            # A null slot can publish a fresh object while discovery runs.
            # This permits a complete fresh scan, never the discarded batch.
            serial_initialized = (change['changed_fields'] == ['serial'] and
                change['before'] == before_serial and change['after'] == after_serial)
            object_published = (change['changed_fields'] == ['object_pointer'] and
                change['before'] == before_publication and change['after'] == after_publication)
            if not (serial_initialized or object_published):
                return False
            seen.add(change['object_index'])
        return context['first_changed_object_index'] == changes[0]['object_index']

    transient = (last.get('error_type') == 'ValueError' and last.get('reason') in transient_reasons or
        last.get('error_type') == 'ObjectMetadataError' and
        last.get('reason') == 'object_slot_changed_during_metadata_read' and
        discarded_initialization_batch(last.get('failure_context')))
    finished = last.get('elapsed_seconds')
    stable_since = stable.get('since_elapsed_seconds')
    return (last.get('status') == 'metadata_export_refused' and
            transient and
            type(finished) in (int, float) and type(elapsed_seconds) in (int, float) and
            type(stable_since) in (int, float) and
            type(observation_seconds) in (int, float) and observation_seconds - elapsed_seconds >= 125 and
            0 <= finished <= stable_since <= elapsed_seconds - 20)


def replication_metadata_join_due(report, elapsed_seconds, candidates, join_progress, observation_seconds):
    """Collect once during a live Join, separately from the early lobby scan."""
    if report.get('replication_metadata_after_join_attempted'):
        return False
    identity = report.get('replication_metadata_export_identity')
    if type(identity) is not dict or candidates != {(identity.get('pid'), identity.get('created_at'))}:
        return False
    joined = join_progress.get('join_observed_count')
    active = join_progress.get('active_joined_peers')
    return (type(joined) is int and joined > 0 and type(active) is int and active == 1 and
            type(elapsed_seconds) in (int, float) and type(observation_seconds) in (int, float) and
            0 <= elapsed_seconds <= observation_seconds - 125)


"""Inline staged runner-only recovery; no process or native operations."""
def _initial_bootstrap_third_scan_due(report, elapsed_seconds, lobby_candidates, observation_seconds,
        *, initial_actor_bootstrap=False, source_recheck=None):
    import math
    from pathlib import PurePosixPath
    def number(value, low, high):
        return type(value) in (int,float) and math.isfinite(value) and low<=value<=high
    def integer(value, low, high):
        return type(value) is int and low<=value<=high
    def pins(value):
        return (type(value) is dict and 1<=len(value)<=512 and all(
            type(p) is str and 1<=len(p)<=1024 and p.isascii() and '\\' not in p and ':' not in p and
            str(PurePosixPath(p))==p and not PurePosixPath(p).is_absolute() and
            not any(part in ('.','..') for part in p.split('/')) and
            type(h) is str and len(h)==64 and all(c in '0123456789abcdef' for c in h)
            for p,h in value.items()))
    if (type(report) is not dict or initial_actor_bootstrap is not True or
            report.get('ds_initial_actor_bootstrap_requested') is not True or
            report.get('replication_metadata_export_requested') is not True or
            report.get('replication_metadata_export_trigger')!='owned_shipping_established_local_lobby_connection' or
            not number(observation_seconds,125,1800) or not number(elapsed_seconds,0,observation_seconds) or
            observation_seconds-elapsed_seconds<125):return False
    bootstrap=report.get('ds_initial_actor_bootstrap_progress')
    if (type(bootstrap) is not dict or bootstrap.get('stage')!='ds_initial_actor_bootstrap_rejected' or
            bootstrap.get('status')!='not_registered' or any(report.get(k) is not None and report.get(k) is not False
            for k in ('replication_metadata_after_actor_open_attempted','pc_restart_post_travel_request_queued'))):return False
    attempts=report.get('replication_metadata_export_attempts')
    if type(attempts) is not list or len(attempts)!=2 or any(type(row) is not dict for row in attempts):return False
    first,last=attempts
    if (not integer(first.get('attempt'),1,1) or not integer(last.get('attempt'),2,2) or
            first.get('status')!='metadata_export_refused' or first.get('error_type')!='ObjectMetadataError' or
            first.get('reason')!='object_slot_changed_during_metadata_read' or
            last.get('status')!='metadata_export_refused' or last.get('error_type')!='ObjectMetadataError' or
            last.get('reason')!='object_slot_not_live_or_identity_mismatch' or last.get('failure_context') is not None or
            not number(first.get('elapsed_seconds'),0,elapsed_seconds) or
            not number(last.get('elapsed_seconds'),first['elapsed_seconds'],elapsed_seconds)):return False
    identity=report.get('replication_metadata_export_identity');stable=report.get('replication_metadata_lobby_stability')
    if (type(identity) is not dict or set(identity)!={'pid','created_at'} or
            not integer(identity['pid'],1,0xffffffff) or not number(identity['created_at'],1,1e12) or
            type(lobby_candidates) is not set or lobby_candidates!={(identity['pid'],identity['created_at'])} or
            type(stable) is not dict or type(stable.get('pid')) is not int or stable['pid']!=identity['pid'] or
            type(stable.get('created_at')) not in (int,float) or stable['created_at']!=identity['created_at'] or
            not number(stable.get('since_elapsed_seconds'),last['elapsed_seconds'],elapsed_seconds-20)):return False
    trial=report.get('private_runtime_code_sample_directory')
    if type(trial) is not str or not trial.isascii():return False
    parts=trial.split('/')
    if (len(parts)!=3 or parts[:2]!=['work','native-client-tests'] or
            not parts[2].isdigit() or not 1<=len(parts[2])<=32 or
            first.get('directory')!=trial+'/replication-metadata' or
            last.get('directory')!=trial+'/replication-metadata-retry-2' or
            report.get('replication_metadata_export_directory')!=last['directory']):return False
    # Reuse the exact original initialization-batch qualification. No discarded
    # raw result, candidate, or original partial state is passed into the scan.
    original={**report,'replication_metadata_export_attempts':[first]}
    if not _replication_metadata_retry_due_once(original,elapsed_seconds,lobby_candidates,observation_seconds):return False
    collection=report.get('replication_metadata_export')
    if (type(collection) is not dict or collection.get('kind')!='existing_native_replication_metadata_export' or
            collection.get('client_sha256')!='4254fbe66585f260f1f9dbfc5e302887842552e7baed8939e023160a5e250be0' or
            type(collection.get('requested_pid')) is not int or collection['requested_pid']!=identity['pid'] or
            collection.get('observation_mode')!='replication_metadata' or
            any(collection.get(k)!=last[k] for k in ('status','error_type','reason')) or
            collection.get('failure_context') is not None or
            any(collection.get(k) is not False for k in ('game_modified','process_memory_written','native_getter_invoked',
                'credential_memory_read','player_property_values_read','snapshot_atomic','runtime_class_cache_recovered',
                'runtime_replication_layout_recovered')) or
            not integer(collection.get('maximum_duration_seconds'),10,600) or
            not number(collection.get('elapsed_seconds'),0,collection['maximum_duration_seconds']) or
            not integer(collection.get('read_calls'),1,2000000) or
            not integer(collection.get('attempted_read_bytes'),1,67108864)):return False
    phase=collection.get('collection_phase_diagnostics')
    completed=phase.get('completed_phases') if type(phase) is dict else None
    if (type(phase) is not dict or phase.get('last_phase')!='replication_metadata_observation' or
            type(completed) is not list or len(completed)!=1 or type(completed[0]) is not dict):return False
    preflight=completed[0]
    if (preflight.get('phase')!='source_preflight' or
            any(type(preflight.get(k)) is not int or preflight[k]!=0 for k in
                ('read_calls','read_bytes','cumulative_read_calls','cumulative_read_bytes')) or
            not number(preflight.get('start_elapsed_seconds'),0,collection['elapsed_seconds']) or
            not number(preflight.get('end_elapsed_seconds'),preflight['start_elapsed_seconds'],collection['elapsed_seconds']) or
            not number(preflight.get('elapsed_seconds'),0,collection['elapsed_seconds'])):return False
    progress=collection.get('registry_discovery_progress')
    if (type(progress) is not dict or progress.get('status')!='scanning_registry' or
            progress.get('collection_status')!='metadata_export_refused' or
            any(progress.get(k) is not False for k in ('range_exhausted','complete_global_inventory','snapshot_atomic')) or
            not integer(progress.get('selected_classes'),0,0) or
            not integer(progress.get('selected_template_candidates'),0,32) or
            not integer(progress.get('live_records_seen'),1,1000000) or
            not integer(progress.get('last_live_registry_index'),progress['live_records_seen']-1,999999) or
            not integer(progress.get('unique_class_descriptors_read'),1,32768) or
            type(progress.get('read_calls')) is not int or progress['read_calls']!=collection['read_calls'] or
            type(progress.get('attempted_read_bytes')) is not int or progress['attempted_read_bytes']!=collection['attempted_read_bytes'] or
            type(progress.get('maximum_duration_seconds')) is not int or
            progress['maximum_duration_seconds']!=collection['maximum_duration_seconds'] or
            not number(progress.get('elapsed_seconds'),0,collection['elapsed_seconds'])):return False
    batch=collection.get('bootstrap_registry_batch_retry')
    expected={'enabled':True,'mode':'replication_metadata','maximum_batch_attempts':2,
        'maximum_retried_batches_per_pass':8,'replacement_same_frozen_range_required':True,
        'replacement_initial_blob_matches_previous_checked_blob_required':True,
        'replacement_complete_double_read_required':True,'discarded_batch_records_merged':False,
        'unstable_slots_skipped':False,'selected_root_and_table_checks_unchanged':True,'deadline_extended':False,
        'completed_discovery_passes':0,'retried_batches_by_completed_pass':[],
        'retried_batches_in_completed_passes':0,'counts_cover_completed_passes_only':True}
    if type(batch) is not dict or any(type(batch.get(k)) is not type(v) or batch[k]!=v for k,v in expected.items()):return False
    original_pins=report.get('replication_metadata_source_pins')
    if not pins(original_pins) or not callable(source_recheck):return False
    try:current_pins=source_recheck()
    except Exception:return False
    return pins(current_pins) and current_pins==original_pins


def _discarded_initial_registry_scan_retry_due(report, elapsed_seconds, lobby_candidates,
        observation_seconds, *, initial_actor_bootstrap=False, source_recheck=None):
    """Spend only the unused second initial scan; never reuse rejected records.

    A registry slot mismatch need not mean safe publication: it can also be
    unloading or reuse. This predicate qualifies no old identity or old batch.
    Only a complete new scan can register Actors, through the existing guards.
    """
    import math
    from pathlib import PurePosixPath
    def number(value, lo, hi):
        return type(value) in (int, float) and math.isfinite(value) and lo <= value <= hi
    def integer(value, lo, hi):
        return type(value) is int and lo <= value <= hi
    if (type(report) is not dict or initial_actor_bootstrap is not True or
            report.get('ds_initial_actor_bootstrap_requested') is not True or
            report.get('replication_metadata_export_requested') is not True or
            report.get('replication_metadata_export_trigger') != 'owned_shipping_established_local_lobby_connection' or
            not number(observation_seconds,125,1800) or not number(elapsed_seconds,0,observation_seconds) or
            observation_seconds-elapsed_seconds < 125): return False
    bootstrap = report.get('ds_initial_actor_bootstrap_progress')
    if (type(bootstrap) is not dict or bootstrap.get('stage') != 'ds_initial_actor_bootstrap_rejected' or
            bootstrap.get('status') != 'not_registered' or any(report.get(key) not in (None, False)
            for key in ('replication_metadata_after_actor_open_attempted', 'pc_restart_post_travel_request_queued'))):
        return False
    attempts = report.get('replication_metadata_export_attempts')
    if type(attempts) is not list or len(attempts) != 1 or type(attempts[0]) is not dict: return False
    last = attempts[0]
    if (not integer(last.get('attempt'),1,1) or last.get('status') != 'metadata_export_refused' or
            last.get('error_type') != 'ObjectMetadataError' or
            last.get('reason') != 'object_slot_changed_during_metadata_read' or
            not number(last.get('elapsed_seconds'),0,elapsed_seconds)): return False
    identity = report.get('replication_metadata_export_identity')
    stable = report.get('replication_metadata_lobby_stability')
    if (type(identity) is not dict or set(identity) != {'pid','created_at'} or
            not integer(identity['pid'],1,0xffffffff) or not number(identity['created_at'],1,1e12) or
            type(lobby_candidates) is not set or lobby_candidates != {(identity['pid'],identity['created_at'])} or
            type(stable) is not dict or type(stable.get('pid')) is not int or stable['pid'] != identity['pid'] or
            type(stable.get('created_at')) not in (int,float) or stable['created_at'] != identity['created_at'] or
            not number(stable.get('since_elapsed_seconds'),last['elapsed_seconds'],elapsed_seconds-20)): return False
    trial = report.get('private_runtime_code_sample_directory')
    if type(trial) is not str or not trial.isascii(): return False
    parts = trial.split('/')
    if (len(parts) != 3 or parts[:2] != ['work','native-client-tests'] or not parts[2].isdigit() or
            not 1 <= len(parts[2]) <= 32 or last.get('directory') != trial+'/replication-metadata' or
            report.get('replication_metadata_export_directory') != last['directory']): return False
    collection = report.get('replication_metadata_export')
    if (type(collection) is not dict or collection.get('kind') != 'existing_native_replication_metadata_export' or
            collection.get('client_sha256') != '4254fbe66585f260f1f9dbfc5e302887842552e7baed8939e023160a5e250be0' or
            type(collection.get('requested_pid')) is not int or collection['requested_pid'] != identity['pid'] or
            collection.get('observation_mode') != 'replication_metadata' or any(collection.get(key) != last[key]
            for key in ('status','error_type','reason','failure_context')) or any(collection.get(key) is not False
            for key in ('game_modified','process_memory_written','native_getter_invoked','credential_memory_read',
                        'player_property_values_read','snapshot_atomic','runtime_class_cache_recovered',
                        'runtime_replication_layout_recovered')) or
            not integer(collection.get('maximum_duration_seconds'),10,600) or
            not number(collection.get('elapsed_seconds'),0,collection['maximum_duration_seconds']) or
            not integer(collection.get('read_calls'),1,2000000) or
            not integer(collection.get('attempted_read_bytes'),1,67108864)): return False
    context = last.get('failure_context')
    if (type(context) is not dict or set(context) != {'phase','index_range','first_changed_object_index',
            'changed_slot_count','changes','changes_truncated','batch_records_yielded'} or
            context['phase'] != 'registry_batch_recheck' or context['batch_records_yielded'] is not False or
            type(context['changes_truncated']) is not bool): return False
    bounds,count,changes = context['index_range'],context['changed_slot_count'],context['changes']
    if (type(bounds) is not list or len(bounds) != 2 or any(type(index) is not int for index in bounds) or
            not 0 <= bounds[0] < bounds[1] <= 1000000 or not integer(count,1,bounds[1]-bounds[0]) or
            type(changes) is not list or len(changes) != min(count,8) or
            context['changes_truncated'] is not (count > 8) or
            not integer(context['first_changed_object_index'],bounds[0],bounds[1]-1)): return False
    seen = set()
    for row in changes:
        if (type(row) is not dict or set(row) != {'object_index','changed_fields','before','after'} or
                not integer(row['object_index'],bounds[0],bounds[1]-1) or row['object_index'] in seen or
                type(row['changed_fields']) is not list or not 1 <= len(row['changed_fields']) <= 3 or
                any(type(field) is not str or field not in ('object_pointer','flags','serial')
                    for field in row['changed_fields']) or len(set(row['changed_fields'])) != len(row['changed_fields'])):
            return False
        for value in (row['before'],row['after']):
            if (type(value) is not dict or set(value) != {'pointer_state','flag_state','serial_state'} or
                    value['pointer_state'] not in ('null','non_null') or
                    value['flag_state'] not in ('excluded','not_excluded') or
                    value['serial_state'] not in ('uninitialized','initialized')): return False
        seen.add(row['object_index'])
    if changes[0]['object_index'] != context['first_changed_object_index']: return False
    progress = collection.get('registry_discovery_progress')
    if (type(progress) is not dict or progress.get('status') != 'scanning_registry' or
            progress.get('collection_status') != 'metadata_export_refused' or
            any(progress.get(key) is not False for key in ('range_exhausted','complete_global_inventory','snapshot_atomic')) or
            not integer(progress.get('selected_classes'),0,32) or
            not integer(progress.get('selected_template_candidates'),0,32) or
            progress.get('read_calls') != collection['read_calls'] or
            progress.get('attempted_read_bytes') != collection['attempted_read_bytes']): return False
    pins = report.get('replication_metadata_source_pins')
    if (type(pins) is not dict or not 1 <= len(pins) <= 512 or not callable(source_recheck) or any(
            type(path) is not str or not path.isascii() or not 1 <= len(path) <= 1024 or
            str(PurePosixPath(path)) != path or PurePosixPath(path).is_absolute() or
            ':' in path or chr(92) in path or any(part in ('.','..') for part in path.split('/')) or
            type(pin) is not str or len(pin) != 64 or any(char not in '0123456789abcdef' for char in pin)
            for path,pin in pins.items())): return False
    try: current = source_recheck()
    except Exception: return False
    return type(current) is dict and current == pins


def replication_metadata_retry_due(report, elapsed_seconds, lobby_candidates, observation_seconds=900,
        *, initial_actor_bootstrap=False, source_recheck=None):
    attempts=report.get('replication_metadata_export_attempts')
    if type(attempts) is list and len(attempts)==2:
        return _initial_bootstrap_third_scan_due(report,elapsed_seconds,lobby_candidates,observation_seconds,
            initial_actor_bootstrap=initial_actor_bootstrap,source_recheck=source_recheck)
    return (_replication_metadata_retry_due_once(report,elapsed_seconds,lobby_candidates,observation_seconds) or
        _discarded_initial_registry_scan_retry_due(report,elapsed_seconds,lobby_candidates,observation_seconds,
            initial_actor_bootstrap=initial_actor_bootstrap,source_recheck=source_recheck))


def collect_post_travel_metadata_refresh(collector, game_root, folder, *, previous, retry_progress,
        identity, options, original_started_at, source_recheck, owned_identity_recheck,
        completion_recheck, transport_recheck, trial_remaining_seconds, clock=time.monotonic):
    """Spend only unused attempt two and time left in the original 180s window."""
    from local_map_entry_completion import MapEntryCompletion
    from native_pc_restart_trial import post_travel_refresh_metadata_eligible
    import math
    callbacks = (collector, source_recheck, owned_identity_recheck, completion_recheck,
                 transport_recheck, trial_remaining_seconds, clock)
    if any(not callable(callback) for callback in callbacks) or type(identity) is not dict:
        raise ValueError('Current owned completion callbacks are required')
    pid, created_at = identity.get('pid'), identity.get('created_at')
    if not post_travel_refresh_metadata_eligible(previous, pid, created_at):
        raise ValueError('Only the source-qualified early-null snapshot can be refreshed')
    expected_options = ('connection_binding_only', 'connection_class_net_cache', 'connection_rpc_layouts',
        'connection_guid_mappings', 'reference_conditions', 'connection_first_player_state', 'connection_world_context')
    if type(options) is not dict or set(options) != set(expected_options) or any(options[key] is not True for key in expected_options):
        raise ValueError('The original complete association options are required')
    attempts = retry_progress.get('attempts') if type(retry_progress) is dict else None
    if (type(retry_progress) is not dict or type(retry_progress.get('maximum_attempts')) is not int or
            retry_progress['maximum_attempts'] != 2 or type(retry_progress.get('shared_maximum_seconds')) is not int or retry_progress['shared_maximum_seconds'] != 180 or
            retry_progress.get('partial_metadata_merged') is not False or type(attempts) is not list or
            len(attempts) != 1 or type(attempts[0]) is not dict or attempts[0].get('status') != 'metadata_export_complete'):
        raise ValueError('An unused original second attempt is required')
    if type(original_started_at) not in (int, float) or not math.isfinite(original_started_at):
        raise ValueError('The original post-Actor clock is required')
    completion = completion_recheck()
    if type(completion) is not MapEntryCompletion or completion.complete is not True:
        raise ValueError('Current ordered entry completion is required')
    expected_identity = (pid, created_at)
    original_options = dict(options)
    original_attempt = dict(attempts[0])
    def recheck():
        source_recheck()
        current_identity = owned_identity_recheck()
        if (type(current_identity) is not tuple or len(current_identity) != 2 or
                type(current_identity[0]) is not int or type(current_identity[1]) not in (int, float) or
                current_identity != expected_identity or completion_recheck() != completion):
            raise ValueError('Current owned process or completed request changed')
        transport = transport_recheck()
        if (type(transport) is not dict or type(transport.get('fully_delivered_sets')) is not int or
                transport['fully_delivered_sets'] < 1):
            raise ValueError('Current Actor and association transport ACKs are required')
        if options != original_options or retry_progress.get('attempts') != [original_attempt]:
            raise ValueError('Original metadata options or attempt accounting changed')
    def remaining(minimum=10):
        now, trial_left = clock(), trial_remaining_seconds()
        if (type(now) not in (int, float) or type(trial_left) not in (int, float) or
                not math.isfinite(now) or not math.isfinite(trial_left) or now < original_started_at):
            raise ValueError('A current finite shared clock is required')
        if now - original_started_at > 180 or trial_left < 0:
            raise ValueError('Fresh observation exceeded the original deadline')
        value = min(int(180 - (now - original_started_at)), int(trial_left))
        if value < minimum:
            raise ValueError('Original post-Actor or trial time exhausted')
        return value
    remaining()
    recheck()
    duration = remaining()  # source qualification consumes the same remaining time
    folder = Path(folder)
    folder.mkdir(exist_ok=False)
    fresh = collector(game_root, folder, pid=pid, created_at=created_at,
                      maximum_seconds=duration, **original_options)
    recheck()
    remaining(minimum=0)
    return fresh, folder, {'maximum_attempts': 2, 'attempts': [original_attempt,
        {'directory': folder.name, 'status': fresh.get('status'), 'reason': fresh.get('reason')}],
        'partial_metadata_merged': False, 'shared_maximum_seconds': 180,
        'entry_completion_authorized_fresh_read_only': True, 'fresh_maximum_seconds': duration}


def replication_metadata_source_pins(root, *, connection_binding=False, connection_rpc_layouts=False,
                                     connection_guid_mappings=False):
    """Seal only the metadata collector's explicit source modules before staging."""
    files = ("work/native_metadata_objects.py", "work/native_metadata_names.py", "work/native_metadata_paths.py",
             "work/native_replication_metadata_core.py", "work/export_native_replication_metadata.py",
             "outputs/df-local-server/dfserver/legacy_ds_class_net_cache.py", "work/native_post_actor_retry.py")
    if getattr(globals().get('args'), 'bootstrap_template_observation', False) is True:
        files += ("work/native_actor_interface_metadata.py", "work/native_actor_bootstrap.py")
    from server_source_layout import expand_server_sources
    files = expand_server_sources(root, files)
    result = {}
    try:
        for relative in files:
            with (Path(root) / relative).open("rb") as stream:
                result[relative] = hashlib.file_digest(stream, "sha256").hexdigest()
    except OSError as error:
        raise ValueError("Replication metadata collector sources are missing or unreadable") from error
    if connection_binding:
        from native_connection_binding import qualified_connection_binding_source_pins
        result.update(qualified_connection_binding_source_pins(root))
    if connection_rpc_layouts:
        relative = "work/evidence/map-entry-next-20261005/scoped-pc-rpc-layout-export-source.json"
        expected = "fbb9029fda3f4f6038aa83aaa0ce33593bda7e4b9a91ae9e2f7e9805de7245a3"
        try:
            with (Path(root) / relative).open("rb") as stream:
                actual = hashlib.file_digest(stream, "sha256").hexdigest()
        except OSError as error:
            raise ValueError("Scoped RPC layout source evidence is missing or unreadable") from error
        if actual != expected:
            raise ValueError("Scoped RPC layout source evidence identity changed")
        result[relative] = actual
    if connection_guid_mappings:
        from native_guid_object_metadata import guid_mapping_source_pins
        result.update(guid_mapping_source_pins(root))
        from native_loading_subworld_context import qualified_subworld_context_source_pins
        result.update(qualified_subworld_context_source_pins(root))
    return result


def initial_actor_bootstrap_source_pins(root):
    """Seal the explicit producer, transport and its pure wire dependencies."""
    files = ("work/native_actor_bootstrap.py",
        "work/native_initial_role_sources.py",
        "outputs/df-local-server/protocol/local_initial_role_sources.json",
        "work/native-client-tests/1791073668497579200/replication-metadata-after-actor-open/result.json",
        "work/native_pawn_spawn_policy.py",
        "outputs/df-local-server/protocol/local_pawn_spawn_policy.json",
        "work/official-interface-observations/1791043432995-pid243608/result.json",
        "work/evidence/native-spawn-role-and-connection-semantics.json",
        "outputs/df-local-server/dfserver/legacy_ds_game_spawn_flags.py",
        "outputs/df-local-server/dfserver/legacy_ds_actor_manifest.py",
        "outputs/df-local-server/dfserver/game_server_probe.py",
        "outputs/df-local-server/dfserver/handshake_diagnostic.py",
        "outputs/df-local-server/dfserver/legacy_ds_control_connection.py",
        "outputs/df-local-server/dfserver/legacy_ds_match_admission.py",
        "outputs/df-local-server/dfserver/legacy_ds_actor_bunch.py",
        "outputs/df-local-server/dfserver/legacy_ds_actor_open.py",
        "outputs/df-local-server/dfserver/legacy_ds_actor_content.py",
        "outputs/df-local-server/dfserver/legacy_ds_bit_archive.py",
        "outputs/df-local-server/dfserver/legacy_ds_guid_exports.py",
        "outputs/df-local-server/dfserver/legacy_ds_quantized_vector.py",
        "outputs/df-local-server/dfserver/legacy_ds_wire_codec.py",
        "outputs/df-local-server/dfserver/legacy_ds_control_fields.py",
        "outputs/df-local-server/dfserver/legacy_ds_actor_fields.py",
        "outputs/df-local-server/dfserver/legacy_ds_handshake_probe.py",
        "outputs/df-local-server/dfserver/legacy_ds_control_probe.py",
        "outputs/df-local-server/dfserver/legacy_ds_packet_ack_probe.py",
        "outputs/df-local-server/dfserver/legacy_ds_login_fields.py",
        "outputs/df-local-server/dfserver/legacy_ds_identity_field.py",
        "outputs/df-local-server/dfserver/unreal_handshake_payload.py",
        "work/evidence/native-player-class-and-iris-level-path-review.json",
        "work/evidence/native-engine-network-protocol-version-source-summary.json",
        "work/evidence/native-player-controller-base-tail-profile.json")
    from server_source_layout import expand_server_sources
    if getattr(globals().get('args'), 'ds_human_player_state_fields', False) is True:
        files += ('outputs/df-local-server/dfserver/legacy_ds_late_player_state_human_appearance.py',)
    if getattr(globals().get('args'), 'ds_human_player_state_fields_early', False) is True:
        files += ('outputs/df-local-server/dfserver/legacy_ds_early_player_state_human_appearance.py',
                  'outputs/df-local-server/dfserver/legacy_ds_late_player_state_human_appearance.py')
    root = Path(root).resolve()
    files = expand_server_sources(root, files)
    result = {}
    try:
        for relative in files:
            path = (root / relative).resolve()
            if not path.is_relative_to(root):
                raise ValueError("Initial Actor source is outside the project")
            with path.open("rb") as stream:
                result[relative] = hashlib.file_digest(stream, "sha256").hexdigest()
    except OSError as error:
        raise ValueError("Initial Actor bootstrap sources are missing or unreadable") from error
    from native_static_world_settings import qualified_static_world_settings_source_pins
    result.update(qualified_static_world_settings_source_pins(root))
    return result


def load_initial_actor_bootstrap_sources(root, source_pins, selected_map_id):
    """Only the sealed Dam level and source-backed protocol enum are supported."""
    if type(selected_map_id) is not int or selected_map_id != 2201:
        raise ValueError("Initial Actor bootstrap currently has level evidence only for map 2201")
    level_relative = "work/evidence/native-player-class-and-iris-level-path-review.json"
    version_relative = "work/evidence/native-engine-network-protocol-version-source-summary.json"
    pc_relative = "work/evidence/native-player-controller-base-tail-profile.json"
    expected = {level_relative: "b1a7abc074ccb7f23c1902b74c9246c9f5f69be1cb48244a5c856e7eb265ab1a",
                version_relative: "711ab323d69885e817e2ab00b5ac46151af1419ddacdfc9355e94b6d1f8f5da7",
                pc_relative: "7941c3a10556a232f20558e0a4b83b78659af902e1878ae5998b6ae3d71dddac"}
    documents = {}
    root = Path(root).resolve()
    try:
        for relative, digest in expected.items():
            path = (root / relative).resolve()
            if not path.is_relative_to(root):
                raise ValueError("Initial Actor evidence is outside the project")
            raw = path.read_bytes()
            if source_pins.get(relative) != digest or hashlib.sha256(raw).hexdigest() != digest:
                raise ValueError("Initial Actor evidence seal does not match")
            documents[relative] = json.loads(raw)
        level = documents[level_relative]["confirmed_iris_level"]["persistent_level_object_path"]
        version_document = documents[version_relative]
        version = version_document["source_backed_build_default"]
        qualification = version_document["qualification"]
        pc_document = documents[pc_relative]
        if (pc_document.get("kind") != "source_backed_base_player_controller_open_tail_profile" or
                pc_document.get("client_sha256") != version_document.get("client_sha256") or
                pc_document.get("hook_slot") != "0x3d8" or
                pc_document.get("hook_target_rva") != "0x12d4ddb0" or
                pc_document.get("tail_encoding") != "unaligned_raw_u8" or
                type(pc_document.get("local_player_index")) is not int or
                pc_document["local_player_index"] != 0):
            raise ValueError("PlayerController base tail evidence is invalid")
        if (type(level) is not str or not level.startswith("/Game/") or len(level) > 4096 or
                any(c.isspace() or ord(c) < 32 for c in level) or "\\" in level or
                version_document.get("client_sha256") != "4254fbe66585f260f1f9dbfc5e302887842552e7baed8939e023160a5e250be0" or
                type(version) is not int or not 5 <= version < 1 << 32 or
                qualification.get("source_backed_build_default13_proved") is not True or
                qualification.get("current_live_connection_instance_version_read") is not False):
            raise ValueError("Initial Actor level or constructor-version evidence is invalid")
    except (OSError, UnicodeError, KeyError, TypeError, json.JSONDecodeError) as error:
        raise ValueError("Initial Actor source evidence could not be validated") from error
    from native_pawn_spawn_policy import load_local_pawn_policy
    pawn_policy = load_local_pawn_policy(root, source_pins)
    role_config = "outputs/df-local-server/protocol/local_initial_role_sources.json"
    from native_initial_role_sources import load_initial_role_sources
    archived_roles = load_initial_role_sources(root, config_relative_path=role_config,
        config_sha256=source_pins[role_config])
    if any(source_pins.get(item.source_relative_path) != item.source_sha256
           for item in archived_roles.roles.values()):
        raise ValueError("Initial role archive is not in the sealed source set")
    return {"local_pawn_spawn_policy": pawn_policy,
            "initial_role_sources": {"config_relative_path": role_config,
                "config_sha256": source_pins[role_config]},
            "level_path": level, "level_source_relative_path": level_relative,
            "level_source_sha256": expected[level_relative],
            "version_source_relative_path": version_relative,
            "version_source_sha256": expected[version_relative],
            "connection_network_version": version, "archive_network_version": version,
            "runtime_connection_version_verified": False,
            "pc_tail_profile": {"client_sha256": pc_document["client_sha256"],
                "source_relative_path": pc_relative, "source_sha256": expected[pc_relative],
                "hook_target_rva": 0x12d4ddb0}}


"""Staged inline runner helpers; bounded source verification, no native access."""
def retained_current_bootstrap_sources(root, trial_root, *, additional_sources, bootstrap_progress,
        metadata_directory, metadata_report, metadata_identity, owned_identity):
    """Extend the original seal only with this caller's prepared Pawn source."""
    import math
    from pathlib import PurePosixPath
    def require(condition, reason):
        if not condition:
            raise ValueError(reason)
    require(type(additional_sources) is dict and len(additional_sources) <= 384,
        'retained_current_bootstrap_source_map_required')
    require(type(bootstrap_progress) is dict and
        bootstrap_progress.get('stage') == 'ds_initial_actor_bootstrap_prepared' and
        bootstrap_progress.get('status') == 'registered_for_future_local_ticket' and
        bootstrap_progress.get('role') == 'Pawn' and type(bootstrap_progress.get('map_id')) is int and
        bootstrap_progress['map_id'] == 2201, 'retained_current_bootstrap_not_prepared')
    require(type(metadata_identity) is dict and type(owned_identity) is tuple and len(owned_identity) == 2 and
        type(metadata_identity.get('pid')) is int and 1 <= metadata_identity['pid'] <= 0xffffffff and
        type(metadata_identity.get('created_at')) in (int, float) and
        math.isfinite(metadata_identity['created_at']) and metadata_identity['created_at'] > 0 and
        owned_identity == (metadata_identity['pid'], metadata_identity['created_at']),
        'retained_current_bootstrap_owner_identity_mismatch')
    base = Path(root).resolve(strict=True)
    trial = Path(trial_root).resolve(strict=True)
    require(trial.parent == base / 'work/native-client-tests' and trial.name.isascii() and
        trial.name.isdigit() and 1 <= len(trial.name) <= 32,
        'retained_current_bootstrap_trial_path_mismatch')
    require(type(metadata_directory) is str and 1 <= len(metadata_directory) <= 512 and
        metadata_directory.isascii() and '\\' not in metadata_directory and ':' not in metadata_directory and
        str(PurePosixPath(metadata_directory)) == metadata_directory and
        '..' not in PurePosixPath(metadata_directory).parts,
        'retained_current_bootstrap_metadata_path_mismatch')
    directory = base / metadata_directory
    require(directory.parent == trial and directory.name in ('replication-metadata', 'replication-metadata-retry-2', 'replication-metadata-retry-3'),
        'retained_current_bootstrap_metadata_path_mismatch')
    relative = metadata_directory + '/result.json'
    expected_hash = bootstrap_progress.get('metadata_report_sha256')
    require(bootstrap_progress.get('metadata_source_relative_path') == relative and
        type(expected_hash) is str and len(expected_hash) == 64 and
        all(char in '0123456789abcdef' for char in expected_hash),
        'retained_current_bootstrap_source_identity_mismatch')
    path = directory / 'result.json'
    require(path.resolve(strict=True) == path and path.stat().st_size <= 32 * 1024 * 1024,
        'retained_current_bootstrap_source_path_or_size_mismatch')
    raw = path.read_bytes()
    require(hashlib.sha256(raw).hexdigest() == expected_hash,
        'retained_current_bootstrap_source_hash_changed')
    try:
        document = json.loads(raw)
    except (ValueError, UnicodeError):
        raise ValueError('retained_current_bootstrap_source_document_mismatch') from None
    require(type(metadata_report) is dict and type(document) is dict and document == metadata_report and
        document.get('kind') == 'existing_native_replication_metadata_export' and
        document.get('status') == 'metadata_export_complete' and
        document.get('client_sha256') == '4254fbe66585f260f1f9dbfc5e302887842552e7baed8939e023160a5e250be0' and
        type(document.get('requested_pid')) is int and document['requested_pid'] == metadata_identity['pid'] and
        document.get('game_modified') is False and document.get('process_memory_written') is False and
        document.get('native_getter_invoked') is False,
        'retained_current_bootstrap_source_document_mismatch')
    current_identity = document.get('collection_process_identity')
    require(type(current_identity) is dict and type(current_identity.get('pid')) is int and
        current_identity['pid'] == metadata_identity['pid'] and
        type(current_identity.get('created_at')) in (int, float) and
        math.isfinite(current_identity['created_at']) and current_identity['created_at'] > 0 and
        current_identity['created_at'] == metadata_identity['created_at'] and
        current_identity.get('client_sha256') == document['client_sha256'] and
        current_identity.get('executable_and_creation_time_rechecked') is True and
        current_identity.get('loaded_module_rechecked') is True,
        'retained_current_bootstrap_source_process_identity_mismatch')
    require(relative not in additional_sources or additional_sources[relative] == expected_hash,
        'retained_current_bootstrap_source_namespace_collision')
    result = {**additional_sources, relative: expected_hash}
    require(len(result) <= 384, 'retained_current_bootstrap_source_map_required')
    require(path.read_bytes() == raw, 'retained_current_bootstrap_source_hash_changed')
    return result


def automatic_appearance_pre_start_failure(phase, error):
    """Fixed phase/reason tokens only; do not publish exception values."""
    phases = frozenset(('observer_identity_preparation', 'retained_current_bootstrap_source_preparation',
        'retained_original_owner_preparation', 'automatic_observer_start', 'retained_queue_start',
        'retained_queue_poll', 'automatic_observer_poll'))
    reasons = frozenset(('retained_current_bootstrap_source_map_required',
        'retained_current_bootstrap_not_prepared', 'retained_current_bootstrap_owner_identity_mismatch',
        'retained_current_bootstrap_trial_path_mismatch', 'retained_current_bootstrap_metadata_path_mismatch',
        'retained_current_bootstrap_source_identity_mismatch', 'retained_current_bootstrap_source_path_or_size_mismatch',
        'retained_current_bootstrap_source_hash_changed', 'retained_current_bootstrap_source_document_mismatch',
        'retained_current_bootstrap_source_process_identity_mismatch',
        'retained_current_bootstrap_source_namespace_collision',
        'source_qualified_typed_current_pawn_manifest_required', 'runtime_source_seal_required',
        'frozen_dependencies_changed', 'executing_module_source_pin_required',
        'executing_module_source_changed', 'executing_code_path_changed',
        'executing_code_differs_from_sealed_source', 'bounded_compiled_source_cache_required',
        'retained_source_namespace_collision',
        'active_local_owner_required', 'one_current_registered_owner_required',
        'current_profile_and_transport_required', 'exact_owned_pawn_association_required',
        'complete_actor_namespace_required', 'current_joined_owner_required'))
    if type(error) is not ValueError or phase not in phases:
        return None
    token = str(error)
    return {'phase': phase, 'reason': token if token in reasons else 'controlled_value_error',
        'diagnostic_only': True, 'model_verified': False}


def prepare_initial_actor_bootstrap(root, metadata_folder, probe, source_pins, sources, max_packet_bytes,
                                    *, association_source_pins=None):
    """Register Pawn and independently qualified optional initial roles.

    Current metadata has priority. Roles not yet loaded may use an explicitly
    sealed same-build archive; its identities are validated inside that report.
    PlayerController still requires its observed base open hook. This stages
    creation only; it does not implement possession or initial properties.
    """
    if initial_actor_bootstrap_source_pins(root) != source_pins:
        raise ValueError("Initial Actor bootstrap source identity changed")
    path = (Path(metadata_folder) / "result.json").resolve()
    if not path.is_relative_to(Path(root).resolve()) or path.stat().st_size > 32 * 1024 * 1024:
        raise ValueError("Initial Actor metadata source is outside the bounded project report")
    raw = path.read_bytes()
    source_hash = hashlib.sha256(raw).hexdigest()
    from native_actor_bootstrap import (build_pawn_actor_bootstrap, build_initial_actor_bootstrap,
                                        QualifiedPCTailProfile)
    from native_initial_role_sources import load_initial_role_sources, select_initial_role_source
    archived_roles = load_initial_role_sources(root, **sources["initial_role_sources"])
    # Control uses channel 0. The native 2026-10-03 trial rejected our Pawn
    # on channel 1 because that channel already belongs to Voice. These are
    # distinct local Actor allocations, not class IDs or replication handles.
    # Evidence: work/evidence/native-actor-channel-one-voice-collision.json.
    actor_channels = {"PlayerController": 2, "GameState": 3, "Pawn": 4}
    from native_initial_associations import load_optional_pawn_diagnostic_spawn_location
    pawn_location, pawn_location_info = load_optional_pawn_diagnostic_spawn_location(root, association_source_pins)
    if pawn_location_info is not None and (
            pawn_location_info.get('selected_map_id') != 2201 or
            pawn_location_info.get('subworld_name') != 'Dam_Iris_Level1'):
        raise ValueError('Pawn diagnostic position does not match the prepared Dam SubWorld')
    pawn_arguments = dict(
        source_relative_path=path.relative_to(Path(root).resolve()).as_posix(), source_sha256=source_hash,
        level_path=sources["level_path"],
        level_source_relative_path=sources["level_source_relative_path"],
        level_source_sha256=sources["level_source_sha256"],
        package_guid=3, class_guid=5, archetype_guid=7,
        level_package_guid=25, level_outer_guid=9, level_guid=11,
        actor_guid=2, channel_index=actor_channels["Pawn"], channel_sequence=1023,
        connection_network_version=sources["connection_network_version"],
        archive_network_version=sources["archive_network_version"],
        max_packet_bytes=max_packet_bytes, references_resolvable=True,
        **({'location': pawn_location} if pawn_location is not None else {}))
    prepared = build_pawn_actor_bootstrap(raw, **pawn_arguments)
    optional, rejected, role_sources = {}, {}, {}
    additional = {}
    if association_source_pins is not None:
        from native_additional_initial_roles import prepare_additional_initial_roles
        common = {key: value for key, value in pawn_arguments.items() if key not in (
            'source_relative_path', 'source_sha256', 'package_guid', 'class_guid',
            'archetype_guid', 'actor_guid', 'channel_index', 'location')}
        additional = prepare_additional_initial_roles(root, association_source_pins, common_arguments=common)
        actor_channels.update({role: item.manifest.channel_index for role, item in additional.items()})
    for role, guid_set in (("PlayerController", (13, 15, 17, 4)),
                           ("GameState", (19, 21, 23, 6))):
        try:
            tail = ({"local_player_index": 0,
                     "pc_tail_profile": QualifiedPCTailProfile(**sources["pc_tail_profile"])}
                    if role == "PlayerController" else {})
            factory_arguments = dict(level_path=sources["level_path"],
                level_source_relative_path=sources["level_source_relative_path"],
                level_source_sha256=sources["level_source_sha256"],
                package_guid=guid_set[0], class_guid=guid_set[1], archetype_guid=guid_set[2],
                level_package_guid=25, level_outer_guid=9, level_guid=11,
                actor_guid=guid_set[3], channel_index=actor_channels[role],
                channel_sequence=1023, connection_network_version=sources["connection_network_version"],
                archive_network_version=sources["archive_network_version"],
                max_packet_bytes=max_packet_bytes, references_resolvable=True, **tail)
            selected = select_initial_role_source(raw, role=role,
                current_source_relative_path=path.relative_to(Path(root).resolve()).as_posix(),
                current_source_sha256=source_hash, factory_arguments=factory_arguments,
                archive_sources=archived_roles)
            optional[role] = selected.bootstrap
            role_sources[role] = {"relative_path": selected.source_relative_path,
                "sha256": selected.source_sha256, "provenance": selected.provenance}
        except ValueError as error:
            if role in archived_roles.roles:
                raise ValueError("Configured initial " + role + " could not be qualified") from error
            rejected[role] = str(error)[:256]
    if (initial_actor_bootstrap_source_pins(root) != source_pins or
            path.read_bytes() != raw):
        raise ValueError("Initial Actor bootstrap sources changed during preparation")
    roles = ([role for role in ("PlayerController", "GameState") if role in optional] +
             list(additional) + ["Pawn"])
    staged = [optional[role] for role in ("PlayerController", "GameState") if role in optional]
    staged += list(additional.values()) + [prepared]
    from native_pawn_spawn_policy import build_local_pawn_resolver
    resolver = build_local_pawn_resolver(root, source_pins, raw, pawn_arguments,
                                       sources["local_pawn_spawn_policy"])
    manifests = tuple(item.manifest for item in staged)
    association_summary = None
    ping_summary = None
    startup_summary = None
    start_play_summary = None
    restart_summary = None
    view_target_summary = None
    if association_source_pins is not None:
        from native_initial_associations import build_initial_actor_associations
        contents, association_summary = build_initial_actor_associations(root, manifests, association_source_pins)
        from native_pc_ping_profile import install_pc_ping_profile
        ping_summary = install_pc_ping_profile(root, probe, manifests, association_source_pins)
        from native_pc_startup_profile import install_pc_startup_profile
        startup_summary = install_pc_startup_profile(root, probe, manifests, association_source_pins)
        from native_game_state_start_profile import install_game_state_start_profile
        start_play_summary = install_game_state_start_profile(root, probe, manifests, association_source_pins)
        from native_pc_restart_trial import install_pc_restart_profile
        restart_summary = install_pc_restart_profile(root, probe, manifests, association_source_pins)
        from native_pc_view_target_profile import install_pc_view_target_profile
        view_target_summary = install_pc_view_target_profile(root, probe, manifests, association_source_pins)
        from native_static_world_settings import build_static_world_settings_manifest
        world_settings = build_static_world_settings_manifest(root, source_pins, manifests)
        manifests += (world_settings,)
        roles.append('WorldSettings')
        actor_channels['WorldSettings'] = world_settings.channel_index
        if args.ds_human_player_state_fields_early:
            # Validate the fixed content before publishing map readiness.
            # Profile and ordering policy must be installed atomically.
            current_content, current_summary = load_trial_content(root, enabled=True)
            if current_content != human_ps_content or current_summary != human_ps_summary:
                raise ValueError('Human PlayerState trial sources changed after preflight')
            early_status = probe.set_initial_actor_manifests_with_early_player_state_human_appearance_diagnostic(
                2201, manifests, resolver=resolver, post_open_actor_contents=contents,
                content=current_content, source_pins=current_summary['source_pins'])
        else:
            probe.set_initial_actor_manifests(2201, manifests, resolver=resolver,
                                             post_open_actor_contents=contents)
    else:
        probe.set_initial_actor_manifests(2201, manifests, resolver=resolver)
    return {"stage": "ds_initial_actor_bootstrap_prepared", "status": "registered_for_future_local_ticket",
            "role": "Pawn", "map_id": 2201, "metadata_report_sha256": source_hash,
            "game_spawn_flags_resolution": "after_exact_local_ticket_join",
            "pawn_state_origin": "local_server_configuration_not_official_packet_values",
            "roles": roles, "initial_actor_manifest_count": len(manifests),
            "actor_channel_indices": {role: actor_channels[role] for role in roles},
            "optional_role_sources": role_sources,
            "initial_actor_associations": association_summary,
            **({'human_ps_early_fields': {'status': early_status,
                 'diagnostic_only': True, 'native_acceptance_verified': False,
                 'model_verified': False}} if args.ds_human_player_state_fields_early else {}),
            "pc_ping_receiver": ping_summary,
            "pc_startup_rpc_receiver": startup_summary,
            "game_state_start_profile": start_play_summary,
            "pc_restart_profile": restart_summary,
            "pc_view_target_profile": view_target_summary,
            **({'pawn_diagnostic_spawn_location': pawn_location_info}
               if pawn_location_info is not None else {}),
            "optional_role_rejections": rejected, "send_order_gameplay_verified": False,
            "metadata_source_relative_path": path.relative_to(Path(root).resolve()).as_posix(),
            "connection_network_version": sources["connection_network_version"],
            "archive_network_version": sources["archive_network_version"],
            "runtime_connection_version_verified": False,
            "references_resolvable_is_caller_precondition": True,
            "conservative_packet_bytes": prepared.preflight.conservative_packet_bytes,
            "native_spawn_verified": False, "playable_map_verified": False}


association_source_pins = None
human_ps_content = None
human_ps_summary = None
if args.ds_human_player_state_fields or args.ds_human_player_state_fields_early:
    if int(os.environ.get('DF_LOCAL_DS_MAP_ID', '0')) != 2201:
        parser.error("--ds-human-player-state-fields is limited to the verified Dam trial")
    from native_player_state_human_trial_profile import load_trial_content
    human_ps_content, human_ps_summary = load_trial_content(ROOT, enabled=True)
if getattr(args, 'ds_initial_actor_associations', False):
    try:
        from native_initial_associations import qualified_initial_association_source_pins
        association_source_pins = qualified_initial_association_source_pins(ROOT)
    except ValueError as error:
        parser.error(str(error))

metadata_source_pins = None
if args.replication_metadata_export:
    try:
        metadata_source_pins = replication_metadata_source_pins(
            ROOT, connection_binding=args.connection_binding_observation,
            **({"connection_rpc_layouts": True}
               if getattr(args, 'connection_rpc_layouts', False) else {}),
            **({"connection_guid_mappings": True}
               if getattr(args, 'connection_guid_mappings', False) else {}))
    except ValueError as error:
        parser.error(str(error))
bootstrap_source_pins = None
bootstrap_sources = None
if args.ds_initial_actor_bootstrap:
    try:
        bootstrap_source_pins = initial_actor_bootstrap_source_pins(ROOT)
        bootstrap_sources = load_initial_actor_bootstrap_sources(
            ROOT, bootstrap_source_pins, int(os.environ.get("DF_LOCAL_DS_MAP_ID", "0")))
    except ValueError as error:
        parser.error(str(error))

control_profile = None
portable_plan = None
updated_minimum_plan = None
if args.updated_minimum_actor_bootstrap:
    from updated_map_bootstrap import load_plan as load_updated_minimum_plan
    updated_minimum_plan = load_updated_minimum_plan(ROOT)
if args.portable_map_bootstrap is not None:
    from portable_map_bootstrap import load_plan
    portable_plan = load_plan(ROOT, args.portable_map_bootstrap)
if args.ds_control_probe:
    try:
        control_profile = portable_plan.control if portable_plan is not None else load_control_trial_profile(
            CONTROL_PROFILE,
            ROOT, ENTRY_SHA, os.environ.get("DF_LOCAL_DS_MAP_ID"))
    except ValueError as error:
        parser.error(str(error))
CLIENTS = {"deltaforceclient.exe", "deltaforceclient-win64-shipping.exe"}
PLATFORMS = {"wegame.exe", "tgp.exe", "tgp_daemon.exe", "wegame_launcher.exe", "delta_force_launcher.exe"}
TEST_ROOT = ROOT / "work/native-client-tests" / str(time.time_ns())
TEST_ROOT.mkdir(parents=True)
EVENTS = TEST_ROOT / "events.jsonl"
REPORT = ROOT / "outputs/native-account-provider/client-observation.json"
if REPORT.exists():
    previous = json.loads(REPORT.read_text(encoding="utf-8"))
    assert previous.get("record_complete") and previous.get("original_sdk_restored")
    archive = REPORT.with_name("client-observation-" + str(time.time_ns()) + ".json")
    archive.write_text(REPORT.read_text(encoding="utf-8"), encoding="utf-8")


def digest(path):
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def snapshot():
    return [{"pid":p.pid,"parent_pid":p.info["ppid"],"name":p.info["name"].lower(),"created_at":p.info["create_time"]}
            for p in psutil.process_iter(["pid","ppid","name","create_time"])
            if (p.info["name"] or "").lower() in CLIENTS | PLATFORMS]


class TestBackend(Backend):
    identity_queries = 0
    def native_identity(self, token):
        self.identity_queries += 1
        return super().native_identity(token)


assert not snapshot(), "An existing game/platform session will not be touched"
assert digest(SDK) == SDK_SHA and digest(ENTRY) == ENTRY_SHA
validated = json.loads((ROOT / "outputs/native-account-provider/validation.json").read_text(encoding="utf-8"))
assert validated["local_account_consumed_by_native_provider"]
build = json.loads((STAGE / "build-record.json").read_text(encoding="utf-8"))
provider_sha = digest(STAGE / "rail_api64.dll")
assert provider_sha == build["provider_sha256"] and build["sdk_metadata_sha256"] == SDK_SHA
assert validated["provider_sha256"] == provider_sha
assert validated["provider_source_sha256"] == digest(ROOT / "outputs/native-account-provider/provider.c")
ALIAS = SDK.with_name("df_sdk_original.dll")
NEXT = SDK.with_name("df_observer_next.dll")
CONFIG = SDK.with_name("df_sdk_observer_logpath.txt")
BOOTSTRAP = SDK.with_name("df_local_identity_bootstrap.bin")
for path in (ALIAS,NEXT,CONFIG,BOOTSTRAP):
    assert path.parent.resolve() == SDK.parent.resolve() and not path.exists()
profile_db = ROOT / "work/native-test-account/save.sqlite3"
assert profile_db.exists(), "The preserved local test account is missing"
backend = TestBackend(profile_db, ROOT / "outputs/df-local-server/definitions.json")
with backend.connection() as connection:
    connection.execute("BEGIN IMMEDIATE")
    if args.native_username:
        account = connection.execute(
            "SELECT player_id FROM accounts WHERE username_key=?",
            (args.native_username.strip().casefold(),)).fetchone()
        assert account is not None, "The selected local account is missing"
    else:
        accounts = connection.execute("SELECT player_id FROM accounts").fetchall()
        assert len(accounts) == 1, "Specify --native-username when the local test database has multiple accounts"
        account = accounts[0]
    registered = backend._new_session(connection, account["player_id"])
    connection.commit()
if args.precreate_game_nick and not backend.native_identity(registered["session"])["game_registered"]:
    backend.register_game_nick(registered["session"],
                               "DL" + secrets.token_hex(5).upper())
item_catalog = json.loads((ROOT / "outputs/df-local-server/protocol/game_item_catalog.json").read_text(encoding="utf-8"))["rows"]
existing_lobby_profile = backend.native_lobby_profile(registered["session"])
if not existing_lobby_profile["props"]:
    # The installed client explicitly rejects 17020000011 as removed bound cash.
    currency_ids = [int(item_id) for item_id, row in item_catalog.items()
                    if row["is_currency"] and item_id != "17020000011"]
    requested_items = [15080050142] * 20 + [15080050006] * 20
    base_gid = backend.native_identity(registered["session"])["native_id"]
    props = [{"gid": base_gid + index + 1, "template_id": item_id,
              "quantity": 1, "grid_page_id": 2, "x": index % 9, "y": index // 9,
              "length": item_catalog[str(item_id)]["length"],
              "width": item_catalog[str(item_id)]["width"]}
             for index, item_id in enumerate(requested_items)]
    backend.set_native_lobby_profile(registered["session"], level=60,
                                     currencies={currency_id: 10_000_000 for currency_id in currency_ids},
                                     props=props)
    with backend.connection() as connection:
        connection.execute("UPDATE players SET money=? WHERE id=?",
                           (10_000_000, account["player_id"]))
        connection.commit()
native_lobby_profile = backend.native_lobby_profile(registered["session"])
assert native_lobby_profile["level"] == 60
assert len(native_lobby_profile["props"]) >= 40
assert len(native_lobby_profile["currencies"]) >= 14
server = create_server(backend, ProtobufCodec(ROOT / "outputs/df-local-server/protocol/recovered_telemetry.pb"), port=0)
server_thread = threading.Thread(target=server.serve_forever,kwargs={"poll_interval":.01},daemon=True)
server_thread.start()
token = registered["session"].encode("ascii")
bootstrap_bytes = struct.pack("<4sHHHH",b"DFLC",1,server.server_port,len(token),0) + token
report = {"observed_at_utc":datetime.now(timezone.utc).isoformat(),"entry":str(ENTRY.relative_to(GAME)),
    "updated_client_code_observation":updated_code_observation,
    "test_game_root":str(GAME),"client_shadow_mode":GAME == SHADOW_GAME,
    "arguments":["--rail_no_need_launch_platform", "-ip=127.0.0.1:65010"],"source_game_code_modified":False,
    "local_identity_provider_substituted":False,"original_sdk_boolean_forced":False,
    "official_identity_supplied":False,"licensing_interfaces_implemented":False,
    "enforcement_components_modified":False,"provider_sha256":provider_sha,
    "process_observations":[],"sdk_events":[],"platform_fallback_observed":False,
    "original_sdk_restored":False,"original_client_local_game_connection_observed":False,
    "original_lobby_compatible":False,"scoped_cleanup":[],
    "process_load_observations":[],"authorization_process_observations":[],
    "observation_limit_seconds":args.observation_seconds if args.wire_business_bootstrap_probe else (90 if args.wire_auth_response_probe else 180),"resource_samples":[],
    "test_entry_kind":args.entry,"test_helper_is_admin":bool(ctypes.windll.shell32.IsUserAnAdmin()),
    "disable_device_seamless_requested":args.disable_device_seamless,
    "disable_dynamic_address_switch_requested":args.disable_dynamic_address_switch,
    "enable_sol_map_entry_loading_requested":args.enable_sol_map_entry_loading,
    "bounded_client_code_diagnostic_opt_in":bool(args.ds_transport_code_probe or
        args.ds_connection_class_code_probe or args.ds_control_code_probe or
        args.ds_image_code_cache or args.entry_code_probe),
    "wire_identity_probe_requested":args.wire_identity_probe,
    "wire_auth_response_probe_requested":args.wire_auth_response_probe,
    "wire_auth_identity_probe_requested":args.wire_auth_identity_probe,
    "wire_ready_probe_requested":args.wire_ready_probe,
    "wire_ready_identity_probe_requested":args.wire_ready_identity_probe,
    "wire_business_login_probe_requested":args.wire_business_login_probe,
    "wire_business_bootstrap_probe_requested":args.wire_business_bootstrap_probe,
    "game_server_probe_requested":args.game_server_probe,
    "experimental_ds_handshake_probe_requested":args.ds_handshake_probe,
    "experimental_ds_packet_ack_probe_requested":args.ds_packet_ack_probe,
    "experimental_ds_control_probe_requested":args.ds_control_probe,
    "control_profile_path":str(CONTROL_PROFILE) if args.ds_control_probe else None,
    "control_profile_sha256":digest(CONTROL_PROFILE) if args.ds_control_probe else None,
    "replication_metadata_export_requested":args.replication_metadata_export,
    "connection_rpc_layouts_requested":args.connection_rpc_layouts,
    "connection_guid_mappings_requested":args.connection_guid_mappings,
    "replication_metadata_source_pins":metadata_source_pins,
    "bootstrap_template_observation_requested":args.bootstrap_template_observation,
    "ds_initial_actor_bootstrap_requested":args.ds_initial_actor_bootstrap,
    "ds_initial_actor_associations_requested":args.ds_initial_actor_associations,
    "ds_human_player_state_fields_early_requested":args.ds_human_player_state_fields_early,
    "initial_actor_association_source_pins":association_source_pins,
    "initial_actor_bootstrap_source_pins":bootstrap_source_pins,
    "initial_actor_bootstrap_sources":bootstrap_sources,
    "bounded_named_transport_code_probe_requested":args.ds_transport_code_probe,
    "bounded_connection_class_code_probe_requested":args.ds_connection_class_code_probe,
    "bounded_native_control_code_probe_requested":args.ds_control_code_probe,
    "bounded_control_candidate_interval_requested":args.ds_control_candidate_interval,
    "bounded_control_field_helpers_requested":args.ds_control_field_helpers,
    "bounded_control_followup_code_requested":args.ds_control_followup_code,
    "bounded_control_sender_body_requested":args.ds_control_sender_body,
    "private_image_code_cache_requested":args.ds_image_code_cache,
    "stop_after_code_collection_requested":args.stop_after_code_collection,
    "game_nick_precreated_for_lobby_trial":args.precreate_game_nick,
    "preserved_test_account": True,
    "local_level": native_lobby_profile["level"],
    "local_currency_count": len(native_lobby_profile["currencies"]),
    "local_warehouse_prop_count": len(native_lobby_profile["props"]),
    "local_safehouse_device_count": len(native_lobby_profile["devices"]),
    "private_runtime_code_sample_directory":TEST_ROOT.relative_to(ROOT).as_posix(),
    "resources_are_discrete_samples_not_continuous_peaks":True}
if args.use_qualified_subworld:
    from native_map_subworld_argument import qualified_subworld_argument
    report['native_subworld_override'] = qualified_subworld_argument(ROOT, int(os.environ.get('DF_LOCAL_DS_MAP_ID', '0')))
    report['arguments'].append(report['native_subworld_override']['argument'])
engine_overrides = []
if args.disable_device_seamless:
    # The client's CheckIsEnableSeamless reads this native CVar and selects
    # its existing ordinary-entry branch. This is a launch-only experiment;
    # it does not edit the executable, Lua chunks, or installed game config.
    # ExecCmds was present in the shipping command line but did not change
    # the native CVar in trial 1790761462524830400. Use the Engine config
    # override instead, and verify its effective value in the client log.
    # Request the startup ConsoleVariables override. The saved report from
    # trial 1790762016717801900 did not establish its effective runtime value;
    # presence in the command line alone is not evidence of application.
    engine_overrides.append("[ConsoleVariables]:Game.DisableDeviceSeamless=1")
if args.disable_dynamic_address_switch:
    # Native registration and the Tick -> socket switch -> handshake reset path:
    # work/evidence/native-dynamic-address-switch-cvar.json. A fixed local DS
    # does not need dynamic address migration; verify application in the log.
    engine_overrides.append("[ConsoleVariables]:dualChannel.EnableSwitchIpAddressDynamic=0")
if args.enable_sol_map_entry_loading:
    engine_overrides.append("[SystemSettings]:r.Loading.EnableSOLMapEntryLoading=1")
if engine_overrides:
    # UE combines properties for one config category in one comma-separated
    # override, so both options survive the Engine command-line lookup.
    report["arguments"].append("-ini:Engine:" + ",".join(engine_overrides))


def save():
    report["local_identity_service_queries"] = backend.identity_queries
    pending_report = REPORT.with_suffix(".json.tmp")
    with pending_report.open('w', encoding='utf-8') as stream:
        stream.write(json.dumps(report, ensure_ascii=False, indent=2) + '\n')
        stream.flush()
        os.fsync(stream.fileno())
    os.replace(pending_report, REPORT)


def control_collection_summary(collection, elapsed_seconds, stop_after_collection):
    """Describe the read result separately from the client's observation lifetime."""
    functions = collection.get("functions", [])
    succeeded = sum(item.get("read_succeeded") is True for item in functions)
    failed = len(functions) - succeeded
    status = collection.get("status", "unknown")
    if status == "code_cache_complete" and collection.get("complete") is True:
        outcome = "success"
    elif status == "bounded_read_attempt_complete" and functions and not failed:
        outcome = "success"
    elif status == "bounded_read_attempt_complete" and succeeded:
        outcome = "partial_failure"
    else:
        outcome = "failure"
    return {"stage": "native_control_code_collection_completed",
            "collection_status": status, "collection_outcome": outcome,
            "function_reads_succeeded": succeeded, "function_reads_failed": failed,
            "elapsed_seconds": elapsed_seconds,
            "observation_action": "stop" if stop_after_collection else "continue",
            "observation_reason": ("explicit_stop_after_code_collection" if stop_after_collection
                                   else "code_collection_complete_observation_continues")}


def collect_control_followup(game, folder):
    """Combine two fixed readers; failures cannot disappear in an empty result."""
    from read_native_control_continuations import collect as collect_continuations
    from read_native_sender_code import collect as collect_sender
    result = {"kind": "bounded_control_followup_collection", "functions": [],
              "collections": {}, "maximum_reads": 6, "maximum_code_bytes": 10570,
              "game_modified": False, "process_memory_written": False,
              "native_control_message_accepted": False, "playable_map_verified": False}
    complete = True
    for name, collector in (("continuations", collect_continuations), ("sender", collect_sender)):
        destination = folder / name
        destination.mkdir()
        try:
            collection = collector(game, destination)
        except Exception as error:
            collection = {"status": "bounded_read_failed", "error_type": type(error).__name__}
        result["collections"][name] = collection
        functions = collection.get("functions", [])
        result["functions"].extend(dict(entry, collection_profile=name) for entry in functions)
        if collection.get("status") != "bounded_read_attempt_complete" or not functions:
            complete = False
            result["functions"].append({"name": name + ".attempt", "read_succeeded": False,
                                       "read_refused_reason": collection.get("status", "unknown")})
    result["status"] = "bounded_read_attempt_complete" if complete else "bounded_read_failed"
    (folder / "result.json").write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
    return result


renamed = installed = config_written = bootstrap_written = False
engine_ini_override = None
automatic_appearance_observer = None
portable_gameplay_observer = None
automatic_appearance_pre_start_refusal = None
retained_fashion_trial = None
pc_restart_appearance_owner = None
pc_restart_appearance_process = None
owned = {}
child = None
wire_server = wire_thread = wire_state = game_server_probe = None
updated_minimum_receiver = updated_minimum_source_lease = None
client_log_thread = None
client_log_stop, client_log_ready = threading.Event(), threading.Event()
try:
    save()
    # Optional diagnostics run in an isolated REPO interpreter. They inherit
    # this already elevated helper token and cannot delay Restart/UDP handling.
    if (args.ds_human_player_state_fields_early and args.ds_initial_actor_associations
            and GAME == SHADOW_GAME and (ROOT / 'work/native-appearance-observer-config.json').is_file()):
        try:
            from native_local_trial_appearance_observer import AutomaticAppearanceObserver
            automatic_appearance_observer = AutomaticAppearanceObserver(ROOT, GAME, TEST_ROOT)
            report['automatic_appearance_observer'] = dict(automatic_appearance_observer.state)
        except Exception as error:
            report['automatic_appearance_observer'] = {'status': 'refused',
                'error_type': type(error).__name__, 'model_verified': False}
        save()
    if args.disable_device_seamless or args.disable_dynamic_address_switch or args.enable_sol_map_entry_loading:
        helper_path = ROOT / "work/native_engine_ini_override.py"
        expected_helper_sha = os.environ.get("DF_LOCAL_SHADOW_ENGINE_INI_SOURCE_SHA256")
        if expected_helper_sha is not None and digest(helper_path) != expected_helper_sha:
            raise RuntimeError("Shadow Engine override source changed before launch")
        from native_engine_ini_override import ShadowEngineIniOverride, capture_engine_ini_precondition
        expected_ini = os.environ.get("DF_LOCAL_SHADOW_ENGINE_INI_PRECONDITION")
        expected_ini = (json.loads(expected_ini) if expected_ini is not None else
            capture_engine_ini_precondition(SOURCE_GAME, SHADOW_GAME,
                disable_device_seamless=args.disable_device_seamless,
                disable_dynamic_address_switch=args.disable_dynamic_address_switch,
                enable_sol_map_entry_loading=args.enable_sol_map_entry_loading))
        engine_ini_override = ShadowEngineIniOverride(SOURCE_GAME, SHADOW_GAME,
            TEST_ROOT / "engine-consolevariables-backup", expected_precondition=expected_ini,
            disable_device_seamless=args.disable_device_seamless,
            disable_dynamic_address_switch=args.disable_dynamic_address_switch,
            enable_sol_map_entry_loading=args.enable_sol_map_entry_loading)
        report["shadow_engine_ini_override"] = engine_ini_override.apply()
        save()
    if args.game_server_probe:
        game_server_probe = GameServerProbe(TEST_ROOT / "game-server-packets",
                                          handshake_probe=args.ds_handshake_probe,
                                          packet_ack_probe=args.ds_packet_ack_probe,
                                          control_probe=args.ds_control_probe,
                                          require_initial_actor_profile=args.ds_initial_actor_bootstrap or portable_plan is not None or updated_minimum_plan is not None,
                                          expected_net_version=(control_profile["hello_net_version"]
                                              if control_profile else None),
                                          control_max_packet_bytes=(control_profile["maximum_packet_bytes"]
                                              if control_profile else 1024),
                                          control_welcome_maps=({int(map_id): spec for map_id, spec in
                                              control_profile["control_welcome_maps"].items()}
                                              if control_profile else None),
                                          # Keep the initial Actor exchange and its retries in
                                          # the same bounded record set as the handshake.
                                          max_packets=(256 if args.ds_initial_actor_bootstrap or portable_plan is not None or updated_minimum_plan is not None else
                                              64 if args.ds_packet_ack_probe else 16)).start()
        report["game_server_probe_port"] = game_server_probe.port
        if portable_plan is not None:
            from portable_map_bootstrap import load_plan
            current_plan = load_plan(ROOT, args.portable_map_bootstrap)
            if current_plan.sources != portable_plan.sources:
                raise ValueError('Portable map sources changed before registration')
            report['portable_map_bootstrap'] = current_plan.install(game_server_probe)
            portable_plan = current_plan
        save()
    if args.wire_identity_probe:
        local_identity = backend.native_identity(registered["session"])
        wire_state = HandshakeDiagnosticState(TEST_ROOT / "wire-identity-diagnostic.json")
        wire_server = HandshakeDiagnosticServer(("127.0.0.1", 65010), wire_state, None, True,
            expected_identity={"token":registered["session"],
                               "native_id":local_identity["native_id"],
                               "username":local_identity["username"],
                               "game_nick":local_identity["game_nick"],
                               "game_registered":local_identity["game_registered"]},
            response_probe=args.wire_auth_response_probe,
            ready_probe=args.wire_ready_probe,
            ready_identity_probe=args.wire_ready_identity_probe,
            auth_identity_probe=args.wire_auth_identity_probe,
            business_login_probe=args.wire_business_login_probe,
            business_bootstrap_probe=args.wire_business_bootstrap_probe,
            backend=backend, local_session=registered["session"],
            continuation_seconds=args.observation_seconds + 60,
            game_server_probe=game_server_probe)
        wire_thread = threading.Thread(target=wire_server.serve_forever,
            kwargs={"poll_interval":.05}, daemon=True)
        wire_thread.start()
        wire_state.update(listening=True, address="127.0.0.1", port=65010)
    shutil.copyfile(STAGE / "rail_api64.dll", NEXT)
    assert digest(NEXT) == provider_sha
    os.replace(SDK, ALIAS)
    renamed = True
    os.replace(NEXT, SDK)
    installed = True
    CONFIG.write_text(str(EVENTS.resolve()) + "\n",encoding="utf-8")
    config_written = True
    BOOTSTRAP.write_bytes(bootstrap_bytes)
    bootstrap_written = True
    report["local_identity_provider_substituted"] = True
    save()
    began = time.time()
    start = time.monotonic()
    report["resource_samples"].append(capture_resources(0, "before_start", owned))
    env = os.environ.copy()
    env["DF_SDK_OBSERVER_LOG"] = str(EVENTS)
    # Bounded code-only diagnostics for fixed, named client functions.
    # The DLL accepts no arbitrary range or protected-process read.
    env["DF_LOCAL_CODE_TRACE_DIR"] = str(TEST_ROOT)
    if args.entry_code_probe:
        # Fixed named entry functions, runtime-proven implementations included.
        # At most 9141 entry/DS code bytes; vtable class candidates remain unverified.
        # The shipping hash pins their registration RVAs; no object data is read.
        env["DF_LOCAL_ENTRY_CODE_TRACE"] = "1"
    client_log_path = GAME / "DeltaForce/Saved/Logs/DeltaForce.log"
    client_alert_path = TEST_ROOT / "client-alerts.log"
    report["client_log_capture"] = {"source": str(client_log_path), "path": str(client_alert_path)}
    entry_completion_observer = None
    if getattr(args, 'ds_initial_actor_associations', False):
        from local_map_entry_completion import MapEntryCompletionObserver
        entry_completion_observer = MapEntryCompletionObserver('Dam_Iris_Level1')

    def capture_client_log():
        try:
            report["client_log_alert_count"] = follow_client_log(
                client_log_path, client_alert_path, args.observation_seconds + 30,
                stop=client_log_stop, ready=client_log_ready, observer=entry_completion_observer)
        except Exception as error:
            report["client_log_capture_error"] = type(error).__name__
            client_log_ready.set()

    client_log_thread = threading.Thread(target=capture_client_log, daemon=True)
    client_log_thread.start()
    if not client_log_ready.wait(5) or report.get("client_log_capture_error"):
        raise RuntimeError("Client log capture did not initialize")
    child = subprocess.Popen([str(ENTRY),*report["arguments"]],cwd=ENTRY.parent,env=env,
        stdin=subprocess.DEVNULL,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
    report["root_pid"] = child.pid
    try: owned[child.pid] = psutil.Process(child.pid).create_time()
    except psutil.NoSuchProcess: pass
    print(json.dumps({"stage":"original_client_started","pid":child.pid}),flush=True)
    seen = set()
    load_seen = set()
    authorization_seen = set()
    socket_evidence_captured = False
    resource_evidence_captured = False
    keybox_probe_digest = None
    keybox_probe_attempts = 0
    keybox_probe_next_at = 30
    post_actor_metadata_started_at = None
    for iteration in range((report["observation_limit_seconds"] + 15) // 1 + 1):
        report["resource_samples"].append(capture_resources(time.monotonic()-start, "iteration_start", owned))
        for auth in psutil.process_iter(["pid", "name", "create_time"]):
            if (auth.info["name"] or "").lower() != "consent.exe" or auth.info["create_time"] < began:
                continue
            auth_key = (auth.pid, auth.info["create_time"])
            if auth_key not in authorization_seen:
                authorization_seen.add(auth_key)
                report["authorization_process_observations"].append({
                    "pid":auth.pid,"created_at":auth.info["create_time"],
                    "elapsed_seconds":round(time.monotonic()-start,2)})
        current = snapshot()
        metadata_lobby_candidates = set()
        metadata_owned_candidates = set()
        for item in current:
            if item["created_at"] < began - 1 or (item["pid"] not in owned and item["parent_pid"] not in owned):
                continue
            owned[item["pid"]] = item["created_at"]
            key = (item["pid"],item["created_at"])
            if key not in seen:
                seen.add(key)
                report["process_observations"].append({"elapsed_seconds":round(time.monotonic()-start,2),**item})
            if item["name"] in PLATFORMS: report["platform_fallback_observed"] = True
            if item["name"] in CLIENTS:
                try:
                    process = psutil.Process(item["pid"])
                    if (args.replication_metadata_export and item["name"] == "deltaforceclient-win64-shipping.exe"
                            and Path(process.exe()).resolve() == ENTRY.resolve()
                            and abs(process.create_time() - owned[item["pid"]]) <= .01):
                        metadata_owned_candidates.add((item["pid"], owned[item["pid"]]))
                    sample = {"pid":process.pid,"elapsed_seconds":round(time.monotonic()-start,2)}
                    try:
                        sample["status"] = process.status()
                        sample["threads"] = process.num_threads()
                        sample["cpu_seconds"] = round(sum(process.cpu_times()[:2]),3)
                        sample["working_set_bytes"] = process.memory_info().rss
                        sample["loaded_modules"] = loaded_module_names(process.pid)
                    except psutil.AccessDenied:
                        sample["process_inspection_limit"] = "AccessDenied"
                    except OSError as error:
                        sample["process_inspection_limit"] = "ModuleSnapshotUnavailable"
                        sample["module_snapshot_winerror"] = getattr(error, "winerror", None)
                    load_key = (process.pid,tuple(sample.get("loaded_modules",[])),sample.get("threads"))
                    if load_key not in load_seen:
                        load_seen.add(load_key)
                        report["process_load_observations"].append(sample)
                    for connection in psutil.Process(item["pid"]).net_connections(kind="tcp"):
                        if connection.raddr and connection.raddr.ip == "127.0.0.1" and connection.raddr.port == 65010:
                            report["original_client_local_game_connection_observed"] = True
                            if (args.replication_metadata_export and item["name"] == "deltaforceclient-win64-shipping.exe"
                                    and connection.status == psutil.CONN_ESTABLISHED
                                    and Path(process.exe()).resolve() == ENTRY.resolve()
                                    and abs(process.create_time() - owned[item["pid"]]) <= .01):
                                metadata_lobby_candidates.add((item["pid"], owned[item["pid"]]))
                except (psutil.NoSuchProcess,psutil.AccessDenied) as error:
                    report["connection_observation_limit"] = type(error).__name__
        if EVENTS.exists():
            report["sdk_events"] = [json.loads(line) for line in EVENTS.read_text(encoding="utf-8").splitlines() if line.strip()]
        report["elapsed_seconds"] = round(time.monotonic()-start,2)
        if (updated_minimum_plan is not None and updated_minimum_source_lease is None and
                report['elapsed_seconds'] >= 5 and
                report['original_client_local_game_connection_observed']):
            from updated_map_receiver_guard import LiveReceiverGuard
            if updated_minimum_receiver is None:
                updated_minimum_receiver = LiveReceiverGuard(GAME, child.pid, owned[child.pid])
            if updated_minimum_receiver():
                updated_minimum_source_lease = updated_minimum_plan.install(game_server_probe,
                    receiver_guard=updated_minimum_receiver)
                report['updated_minimum_actor_bootstrap'] = dict(updated_minimum_plan.summary(),
                    status='registered_for_future_local_admission',
                    receiver=updated_minimum_receiver.last_observation)
                print(json.dumps(dict(stage='updated_minimum_actor_bootstrap_registered',
                    native_gameplay_acceptance=False)), flush=True)
                save()
            else:
                report['updated_minimum_actor_bootstrap'] = dict(status='waiting_for_live_receiver',
                    receiver=updated_minimum_receiver.last_observation,
                    native_gameplay_acceptance=False)
        updated_map_collection_due = False
        if (updated_code_observation is not None and game_server_probe is not None and
                updated_code_observation['mode'] == 'updated_control_metadata_capture' and
                not report.get('updated_code_collection_attempted')):
            updated_map_collection_due = updated_map_metadata_ready(updated_code_observation['mode'],
                game_server_probe, attempted=False,
                seconds_left=report['observation_limit_seconds']-report['elapsed_seconds'])
        if (updated_map_collection_due or
                updated_code_observation is not None and not args.updated_client_transport_observation
                and report['elapsed_seconds'] >= 30
                and report['original_client_local_game_connection_observed']
                and not report.get('updated_code_collection_attempted')):
            report['updated_code_collection_attempted'] = True
            try:
                if args.updated_client_metadata_observation:
                    from observe_updated_client_metadata import collect as collect_updated_code
                    updated_cache_root = ROOT/'work/native-client-tests'
                else:
                    from snapshot_updated_client_code import collect as collect_updated_code
                    updated_cache_root = ROOT/'work/native-code-cache'
                if qualify_updated_launch(args, GAME, SHADOW_GAME) != updated_code_observation:
                    raise ValueError('Updated code observation sources changed after authorization')
                updated_process = psutil.Process(child.pid)
                if (child.pid not in owned or child.poll() is not None or
                        updated_process.create_time() != owned[child.pid] or
                        Path(updated_process.exe()).resolve() != ENTRY.resolve()):
                    raise RuntimeError('Updated code observation lost its owned process')
                updated_folder = updated_cache_root/str(time.time_ns())
                report['updated_code_observation_directory'] = updated_folder.relative_to(ROOT).as_posix()
                report['updated_code_collection'] = collect_updated_code(
                    GAME, updated_folder, child.pid, owned[child.pid])
            except (OSError, RuntimeError, ValueError) as error:
                report['updated_code_collection'] = dict(status='updated_code_observation_failed',
                    error_type=type(error).__name__, native_protocol_compatibility_verified=False)
            report['observation_stop_reason'] = ('updated_map_metadata_observation_finished'
                if updated_map_collection_due else 'updated_metadata_observation_finished'
                if args.updated_client_metadata_observation else 'updated_code_observation_finished')
            save()
            print(json.dumps(dict(stage=report['observation_stop_reason'],
                status=report['updated_code_collection']['status'],
                native_protocol_compatibility_verified=False)), flush=True)
            break
        auxiliary_client_verified = False
        if (os.environ.get("DF_LOCAL_SOCKET_EVIDENCE") == "1"
                or os.environ.get("DF_LOCAL_RESOURCE_EVIDENCE") == "1"):
            # The incoming helpers are optional. Keep their fixed reads scoped
            # to this trial's original, identity-checked Shipping shadow PID.
            try:
                auxiliary_process = psutil.Process(child.pid)
                auxiliary_client_verified = (
                    args.entry == "shipping" and GAME == SHADOW_GAME
                    and child.pid in owned and child.poll() is None
                    and abs(auxiliary_process.create_time() - owned[child.pid]) <= .01
                    and Path(auxiliary_process.exe()).resolve() == ENTRY.resolve())
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                pass
            if not auxiliary_client_verified:
                report["readonly_auxiliary_skip_reason"] = "owned_shipping_shadow_identity_not_verified"
        if (auxiliary_client_verified and os.environ.get("DF_LOCAL_RESOURCE_EVIDENCE") == "1"
                and not resource_evidence_captured and report["elapsed_seconds"] >= 30
                and child.poll() is None):
            resource_evidence_captured = True
            probe = ROOT / "work/probe_live_resource_implementations.py"
            registration_probe = ROOT / "work/probe_live_resource_loader.py"
            evidence_path = TEST_ROOT / "resource-implementations-readonly.json"
            record = {"path": str(evidence_path), "elapsed_seconds": report["elapsed_seconds"]}
            try:
                record["probe_sha256"] = digest(probe)
                if record["probe_sha256"] != os.environ.get("DF_LOCAL_RESOURCE_PROBE_SHA256"):
                    raise RuntimeError("Resource witness changed after authorization")
                record["registration_sha256"] = digest(registration_probe)
                if record["registration_sha256"] != os.environ.get("DF_LOCAL_RESOURCE_REGISTRATION_SHA256"):
                    raise RuntimeError("Resource registration witness changed after authorization")
                with evidence_path.with_suffix(".txt").open("w", encoding="utf-8") as output:
                    evidence = subprocess.run([sys.executable, str(probe),
                        "--pid", str(child.pid), "--output", str(evidence_path)],
                        stdout=output, stderr=subprocess.STDOUT, timeout=15)
                record["returncode"] = evidence.returncode
            except (OSError, RuntimeError, subprocess.TimeoutExpired) as error:
                record["error"] = type(error).__name__
            report["resource_loader_readonly_evidence"] = record
        if (auxiliary_client_verified and os.environ.get("DF_LOCAL_SOCKET_EVIDENCE") == "1"
                and not socket_evidence_captured and report["elapsed_seconds"] >= 30
                and child.poll() is None):
            socket_evidence_captured = True
            with (TEST_ROOT / "socket-helper-readonly.txt").open("w", encoding="utf-8") as output:
                evidence = subprocess.run([sys.executable, str(ROOT / "work/probe_gunsmith_native.py"),
                    str(ENTRY), "--pid", str(child.pid), "--rva",
                    "0x60b2d40", "0x60b5430", "0x60b2ce0", "0x60b5330",
                    "0xd3a9930", "0xe2c560", "0xd3c66e0"],
                    stdout=output, stderr=subprocess.STDOUT, timeout=10)
            report["socket_helper_readonly_evidence"] = {"returncode": evidence.returncode,
                "path": str(TEST_ROOT / "socket-helper-readonly.txt")}
        if (auxiliary_client_verified and os.environ.get("DF_LOCAL_SOCKET_EVIDENCE") == "1"
                and keybox_probe_attempts < 8 and report["elapsed_seconds"] >= keybox_probe_next_at
                and child.poll() is None):
            keybox_probe_next_at = report["elapsed_seconds"] + 30
            probe = ROOT / "work/probe_live_keybox_registration.py"
            current_digest = digest(probe)
            if current_digest != keybox_probe_digest:
                keybox_probe_digest = current_digest
                suffix = "" if keybox_probe_attempts == 0 else f'-{int(report["elapsed_seconds"])}'
                keybox_probe_attempts += 1
                evidence_path = TEST_ROOT / f"keybox-registration-readonly{suffix}.json"
                with evidence_path.with_suffix(".txt").open("w", encoding="utf-8") as output:
                    evidence = subprocess.run([sys.executable, str(probe),
                        "--pid", str(child.pid), "--output", str(evidence_path)],
                        stdout=output, stderr=subprocess.STDOUT, timeout=15)
                record = {"returncode": evidence.returncode, "path": str(evidence_path),
                          "probe_sha256": current_digest, "elapsed_seconds": report["elapsed_seconds"]}
                report["keybox_registration_readonly_evidence"] = record
                report.setdefault("keybox_registration_readonly_captures", []).append(record)
        if len(metadata_lobby_candidates) == 1:
            stable_pid, stable_created_at = next(iter(metadata_lobby_candidates))
            stable = report.get("replication_metadata_lobby_stability", {})
            if (stable.get("pid"), stable.get("created_at")) != (stable_pid, stable_created_at):
                report["replication_metadata_lobby_stability"] = {
                    "pid": stable_pid, "created_at": stable_created_at,
                    "since_elapsed_seconds": report["elapsed_seconds"]}
        else:
            report.pop("replication_metadata_lobby_stability", None)
        if (args.replication_metadata_export and report["elapsed_seconds"] >= 20
                and metadata_lobby_candidates and (not report.get("replication_metadata_export_attempted") or
                    replication_metadata_retry_due(report, report["elapsed_seconds"], metadata_lobby_candidates,
                                                   args.observation_seconds,
                                                   initial_actor_bootstrap=args.ds_initial_actor_bootstrap,
                                                   source_recheck=lambda: replication_metadata_source_pins(
                                                       ROOT, connection_binding=args.connection_binding_observation,
                                                       **({"connection_rpc_layouts": True}
                                                          if getattr(args, 'connection_rpc_layouts', False) else {}),
                                                       **({"connection_guid_mappings": True}
                                                          if getattr(args, 'connection_guid_mappings', False) else {}))))):
            attempt_number = len(report.get("replication_metadata_export_attempts", [])) + 1
            report["replication_metadata_export_attempted"] = True
            report["replication_metadata_export_trigger"] = "owned_shipping_established_local_lobby_connection"
            metadata_folder = TEST_ROOT / ("replication-metadata" if attempt_number == 1 else
                                          "replication-metadata-retry-2" if attempt_number == 2 else
                                          "replication-metadata-retry-3")
            report["replication_metadata_export_directory"] = metadata_folder.relative_to(ROOT).as_posix()
            try:
                if len(metadata_lobby_candidates) != 1:
                    raise RuntimeError("Unique owned lobby Shipping process required for metadata export")
                if replication_metadata_source_pins(ROOT, connection_binding=args.connection_binding_observation,
                        **({"connection_rpc_layouts": True}
                           if getattr(args, 'connection_rpc_layouts', False) else {}),
                        **({"connection_guid_mappings": True}
                           if getattr(args, 'connection_guid_mappings', False) else {})) != metadata_source_pins:
                    raise RuntimeError("Replication metadata collector source identity changed")
                metadata_pid, metadata_created_at = next(iter(metadata_lobby_candidates))
                previous_identity = report.get("replication_metadata_export_identity")
                if (previous_identity is not None and previous_identity !=
                        {"pid": metadata_pid, "created_at": metadata_created_at}):
                    raise RuntimeError("Owned Shipping process identity changed before metadata retry")
                report["replication_metadata_export_identity"] = {
                    "pid": metadata_pid, "created_at": metadata_created_at}
                from export_native_replication_metadata import collect as collect_replication_metadata
                metadata_folder.mkdir()
                report["replication_metadata_export"] = collect_replication_metadata(
                    GAME, metadata_folder, pid=metadata_pid, created_at=metadata_created_at,
                    **({'bootstrap_templates_only': True} if args.bootstrap_template_observation else {}),
                    **replication_metadata_collect_options(
                        initial_actor_bootstrap=args.ds_initial_actor_bootstrap,
                        observation_seconds=args.observation_seconds,
                        elapsed_seconds=time.monotonic()-start))
                if replication_metadata_source_pins(ROOT, connection_binding=args.connection_binding_observation,
                        **({"connection_rpc_layouts": True}
                           if getattr(args, 'connection_rpc_layouts', False) else {}),
                        **({"connection_guid_mappings": True}
                           if getattr(args, 'connection_guid_mappings', False) else {})) != metadata_source_pins:
                    raise RuntimeError("Replication metadata collector source identity changed during export")
            except Exception as error:
                report["replication_metadata_export"] = {
                    "status": "replication_metadata_export_failed", "error_type": type(error).__name__,
                    "game_modified": False, "process_memory_written": False, "playable_map_verified": False}
                if metadata_folder.is_dir() and not (metadata_folder / "result.json").exists():
                    (metadata_folder / "result.json").write_text(
                        json.dumps(report["replication_metadata_export"], indent=2) + "\n", encoding="utf-8")
            collection = report["replication_metadata_export"]
            # Stability must be observed after this attempt, not accumulated while
            # the collector blocked this loop. A later disconnect resets it again.
            report.pop("replication_metadata_lobby_stability", None)
            report.setdefault("replication_metadata_export_attempts", []).append({
                "attempt": attempt_number, "status": collection.get("status"),
                "error_type": collection.get("error_type"), "reason": collection.get("reason"),
                "failure_context": collection.get("failure_context"),
                "elapsed_seconds": round(time.monotonic()-start, 2),
                "directory": report["replication_metadata_export_directory"]})
            metadata_progress = {"stage": "replication_metadata_export_completed",
                "collection_status": report["replication_metadata_export"].get("status", "unknown"),
                "elapsed_seconds": round(time.monotonic()-start, 2),
                "directory": report["replication_metadata_export_directory"],
                "attempt": attempt_number,
                "reason": collection.get("reason"),
                "maximum_attempts": 3 if attempt_number == 3 else 2,
                "observation_action": "continue", "playable_map_verified": False}
            report["replication_metadata_export_progress"] = metadata_progress
            if args.ds_initial_actor_bootstrap:
                try:
                    if report["replication_metadata_export"].get("status") != "metadata_export_complete":
                        raise ValueError("Initial Actor bootstrap requires a complete metadata report")
                    if replication_metadata_source_pins(ROOT, connection_binding=args.connection_binding_observation,
                            **({"connection_rpc_layouts": True}
                               if getattr(args, 'connection_rpc_layouts', False) else {}),
                            **({"connection_guid_mappings": True}
                               if getattr(args, 'connection_guid_mappings', False) else {})) != metadata_source_pins:
                        raise ValueError("Metadata collector source identity changed before Actor preparation")
                    actor_progress = prepare_initial_actor_bootstrap(ROOT, metadata_folder,
                        game_server_probe, bootstrap_source_pins, bootstrap_sources,
                        control_profile["maximum_packet_bytes"],
                        **({"association_source_pins": association_source_pins}
                           if getattr(args, 'ds_initial_actor_associations', False) else {}))
                except Exception as error:
                    actor_progress = {"stage": "ds_initial_actor_bootstrap_rejected",
                        "status": "not_registered", "error_type": type(error).__name__,
                        "reason": str(error)[:256] if isinstance(error, ValueError) else "Initial Actor preparation failed",
                        "native_spawn_verified": False, "playable_map_verified": False}
                report["ds_initial_actor_bootstrap_progress"] = actor_progress
                print(json.dumps(actor_progress, ensure_ascii=False), flush=True)
            save()
            print(json.dumps(metadata_progress, ensure_ascii=False), flush=True)
        if (args.replication_metadata_export and args.ds_control_probe and
                not args.ds_initial_actor_bootstrap and game_server_probe is not None):
            join_progress = game_server_probe.map_join_progress
            if replication_metadata_join_due(report, time.monotonic() - start,
                    metadata_owned_candidates, join_progress, args.observation_seconds):
                report["replication_metadata_after_join_attempted"] = True
                identity = report["replication_metadata_export_identity"]
                join_folder = TEST_ROOT / "replication-metadata-after-join"
                directory = join_folder.relative_to(ROOT).as_posix()
                report["replication_metadata_after_join_directory"] = directory
                report["replication_metadata_after_join_started"] = {
                    "elapsed_seconds": round(time.monotonic() - start, 2), **join_progress}
                save()
                try:
                    if replication_metadata_source_pins(ROOT) != metadata_source_pins:
                        raise RuntimeError("Metadata collector source identity changed before Join export")
                    from export_native_replication_metadata import collect as collect_replication_metadata
                    join_folder.mkdir()
                    collection = collect_replication_metadata(
                        GAME, join_folder, pid=identity["pid"], created_at=identity["created_at"])
                    if replication_metadata_source_pins(ROOT) != metadata_source_pins:
                        raise RuntimeError("Metadata collector source identity changed during Join export")
                except Exception as error:
                    collection = {"status": "replication_metadata_export_failed",
                        "error_type": type(error).__name__, "game_modified": False,
                        "process_memory_written": False, "playable_map_verified": False}
                    if join_folder.is_dir() and not (join_folder / "result.json").exists():
                        (join_folder / "result.json").write_text(
                            json.dumps(collection, indent=2) + "\n", encoding="utf-8")
                report["replication_metadata_after_join"] = collection
                progress = {"stage": "replication_metadata_after_join_completed",
                    "collection_status": collection.get("status", "unknown"),
                    "elapsed_seconds": round(time.monotonic() - start, 2), "directory": directory,
                    "join_at_start": join_progress, "join_at_finish": game_server_probe.map_join_progress,
                    "snapshot_atomic": False, "observation_action": "continue",
                    "playable_map_verified": False}
                report["replication_metadata_after_join_progress"] = progress
                save()
                print(json.dumps(progress, ensure_ascii=False), flush=True)
        if (args.ds_initial_actor_bootstrap and game_server_probe is not None and
                report.get("ds_initial_actor_bootstrap_progress", {}).get("stage") ==
                    "ds_initial_actor_bootstrap_prepared" and
                not report.get("replication_metadata_after_actor_open_attempted")):
            association_observation = getattr(args, 'ds_initial_actor_associations', False)
            actor_transport = (
                game_server_probe.actor_transport_delivery_progress(require_post_open_contents=True)
                if association_observation else game_server_probe.actor_transport_progress)
            identity = report.get("replication_metadata_export_identity", {})
            expected_actor_count = report["ds_initial_actor_bootstrap_progress"].get("initial_actor_manifest_count", 1)
            if (type(expected_actor_count) is int and 1 <= expected_actor_count <= 6 and
                    type(actor_transport.get("fully_delivered_sets")) is int and
                    actor_transport["fully_delivered_sets"] >= 1 and
                    (association_observation or (
                        actor_transport.get("datagrams_sent", 0) >= expected_actor_count and
                        actor_transport.get("delivery_acks", 0) >= expected_actor_count)) and
                    (identity.get("pid"), identity.get("created_at")) in metadata_owned_candidates):
                report["replication_metadata_after_actor_open_attempted"] = True
                report["replication_metadata_after_actor_open_trigger"] = (
                    "metadata_after_actor_and_association_transport_ack" if association_observation
                    else "metadata_after_actor_transport_ack")
                after_folder = TEST_ROOT / "replication-metadata-after-actor-open"
                report["replication_metadata_after_actor_open_directory"] = after_folder.relative_to(ROOT).as_posix()
                try:
                    if (replication_metadata_source_pins(ROOT, connection_binding=args.connection_binding_observation,
                            **({"connection_rpc_layouts": True}
                               if getattr(args, 'connection_rpc_layouts', False) else {}),
                            **({"connection_guid_mappings": True}
                               if getattr(args, 'connection_guid_mappings', False) else {})) != metadata_source_pins or
                            initial_actor_bootstrap_source_pins(ROOT) != bootstrap_source_pins):
                        raise RuntimeError("Metadata or initial Actor sources changed before post-transport export")
                    if (getattr(args, 'ds_initial_actor_associations', False) and
                            qualified_initial_association_source_pins(ROOT) != association_source_pins):
                        raise RuntimeError("Association receiver sources changed before post-transport export")
                    from export_native_replication_metadata import collect as collect_replication_metadata
                    after_folder.mkdir()
                    after_options = dict(
                        **({"connection_binding_only": True, "connection_class_net_cache": True}
                           if args.connection_binding_observation else {}),
                        **({"connection_rpc_layouts": True}
                           if getattr(args, 'connection_rpc_layouts', False) else {}),
                        **({"connection_guid_mappings": True}
                           if getattr(args, 'connection_guid_mappings', False) else {}),
                        **({"reference_conditions": True, "connection_first_player_state": True}
                           if getattr(args, 'ds_initial_actor_associations', False) else {}),
                        **({"connection_world_context": True}
                           if getattr(args, 'ds_initial_actor_associations', False) and
                              getattr(args, 'connection_guid_mappings', False) else {}))
                    if association_observation:
                        from native_post_actor_retry import collect_post_actor_metadata
                        def recheck_post_actor_retry_sources():
                            if (replication_metadata_source_pins(ROOT, connection_binding=args.connection_binding_observation,
                                    **({'connection_rpc_layouts': True} if getattr(args, 'connection_rpc_layouts', False) else {}),
                                    **({'connection_guid_mappings': True} if getattr(args, 'connection_guid_mappings', False) else {})) != metadata_source_pins or
                                    initial_actor_bootstrap_source_pins(ROOT) != bootstrap_source_pins):
                                raise RuntimeError('Original post-Actor source seals changed before fresh retry')
                            if (getattr(args, 'ds_initial_actor_associations', False) and
                                    qualified_initial_association_source_pins(ROOT) != association_source_pins):
                                raise RuntimeError('Original association source seal changed before fresh retry')
                        post_actor_metadata_started_at = time.monotonic()
                        result, after_folder, retry_progress = collect_post_actor_metadata(
                            collect_replication_metadata, GAME, after_folder,
                            pid=identity["pid"], created_at=identity["created_at"], options=after_options,
                            source_recheck=recheck_post_actor_retry_sources)
                        report["replication_metadata_after_actor_open"] = result
                        report["replication_metadata_after_actor_open_directory"] = after_folder.relative_to(ROOT).as_posix()
                        report["replication_metadata_after_actor_open_retry"] = retry_progress
                    else:
                        report["replication_metadata_after_actor_open"] = collect_replication_metadata(
                            GAME, after_folder, pid=identity["pid"], created_at=identity["created_at"], **after_options)
                    if (replication_metadata_source_pins(ROOT, connection_binding=args.connection_binding_observation,
                            **({"connection_rpc_layouts": True}
                               if getattr(args, 'connection_rpc_layouts', False) else {}),
                            **({"connection_guid_mappings": True}
                               if getattr(args, 'connection_guid_mappings', False) else {})) != metadata_source_pins or
                            initial_actor_bootstrap_source_pins(ROOT) != bootstrap_source_pins):
                        raise RuntimeError("Metadata or initial Actor sources changed during post-transport export")
                    if (getattr(args, 'ds_initial_actor_associations', False) and
                            qualified_initial_association_source_pins(ROOT) != association_source_pins):
                        raise RuntimeError("Association receiver sources changed during post-transport export")
                except Exception as error:
                    report["replication_metadata_after_actor_open"] = {
                        "status": "replication_metadata_export_failed", "error_type": type(error).__name__,
                        "game_modified": False, "process_memory_written": False,
                        "native_spawn_verified": False, "playable_map_verified": False}
                    if after_folder.is_dir() and not (after_folder / "result.json").exists():
                        (after_folder / "result.json").write_text(
                            json.dumps(report["replication_metadata_after_actor_open"], indent=2) + "\n", encoding="utf-8")
                after_progress = {"stage": "ds_initial_actor_metadata_export_completed",
                    "phase": report["replication_metadata_after_actor_open_trigger"],
                    "collection_status": report["replication_metadata_after_actor_open"].get("status", "unknown"),
                    "elapsed_seconds": round(time.monotonic()-start, 2),
                    "directory": report["replication_metadata_after_actor_open_directory"],
                    "read_tables_after_transport_ack": report["replication_metadata_after_actor_open"].get(
                        "driver_tables_read", False),
                    "connection_class_net_cache_requested": args.connection_binding_observation,
                    "connection_class_net_cache_scope": report["replication_metadata_after_actor_open"].get(
                        "connection_class_net_cache_scope"),
                    "connection_rpc_layouts_requested": getattr(args, 'connection_rpc_layouts', False),
                    "connection_guid_mappings_requested": getattr(args, 'connection_guid_mappings', False),
                    "connection_guid_mapping_observation_status": report["replication_metadata_after_actor_open"].get(
                        "connection_guid_mapping_observation", {}).get("status", "not_observed"),
                    "connection_binding_gate_observation_status": report["replication_metadata_after_actor_open"].get(
                        "connection_binding_gate_observation", {}).get("status", "not_observed"),
                    "first_player_state_observation_status": report["replication_metadata_after_actor_open"].get(
                        "first_player_state_observation", {}).get("status", "not_observed"),
                    "rpc_function_layout_exports": report["replication_metadata_after_actor_open"].get(
                        "rpc_function_layout_exports", 0),
                    "rpc_parameter_values_read": False,
                    "rpc_parameter_codec_recovered": False,
                    "connection_binding_observation": args.connection_binding_observation,
                    "transport_ack_is_not_spawn_proof": True,
                    "association_transport_ack_required": association_observation,
                    "transport_ack_is_not_reference_assignment_proof": True,
                    "native_reference_assignment_verified": False, "possession_verified": False,
                    "observation_action": "continue", "native_spawn_verified": False,
                    "playable_map_verified": False}
                report["replication_metadata_after_actor_open_progress"] = after_progress
                save()
                print(json.dumps(after_progress, ensure_ascii=False), flush=True)
        if (entry_completion_observer is not None and game_server_probe is not None and
                not report.get('pc_restart_post_travel_request_queued')):
            from native_pc_restart_trial import restart_associations_verified
            completion = entry_completion_observer.snapshot()
            identity = report.get('replication_metadata_export_identity', {})
            after_metadata = report.get('replication_metadata_after_actor_open', {})
            current_owned = (identity.get('pid'), identity.get('created_at')) in metadata_owned_candidates
            references_observed = restart_associations_verified(
                after_metadata, identity.get('pid'), identity.get('created_at'))
            from native_pc_restart_trial import post_travel_refresh_metadata_eligible
            if (getattr(args, 'ds_initial_actor_associations', False) and completion.complete and current_owned and
                    not references_observed and not report.get('post_travel_metadata_refresh_attempted') and
                    post_actor_metadata_started_at is not None and
                    type(report.get('replication_metadata_after_actor_open_retry')) is dict and
                    type(report['replication_metadata_after_actor_open_retry'].get('attempts')) is list and
                    len(report['replication_metadata_after_actor_open_retry']['attempts']) == 1 and
                    post_travel_refresh_metadata_eligible(after_metadata, identity.get('pid'), identity.get('created_at'))):
                report['post_travel_metadata_refresh_attempted'] = True
                refresh_folder = TEST_ROOT / 'replication-metadata-after-actor-open-retry-2'
                try:
                    def recheck_refresh_owned_identity():
                        process = psutil.Process(identity['pid'])
                        if Path(process.exe()).resolve() != ENTRY.resolve() or process.create_time() != identity['created_at']:
                            raise ValueError('Original owned Shipping identity changed before metadata refresh')
                        return process.pid, process.create_time()
                    fresh, refresh_folder, refresh_progress = collect_post_travel_metadata_refresh(
                        collect_replication_metadata, GAME, refresh_folder, previous=after_metadata,
                        retry_progress=report.get('replication_metadata_after_actor_open_retry', {}),
                        identity=identity, options=after_options, original_started_at=post_actor_metadata_started_at,
                        source_recheck=recheck_post_actor_retry_sources,
                        owned_identity_recheck=recheck_refresh_owned_identity,
                        completion_recheck=entry_completion_observer.snapshot,
                        transport_recheck=lambda: game_server_probe.actor_transport_delivery_progress(require_post_open_contents=True),
                        trial_remaining_seconds=lambda: args.observation_seconds - (time.monotonic() - start) - 60)
                    report['replication_metadata_after_actor_open'] = fresh
                    report['replication_metadata_after_actor_open_directory'] = refresh_folder.relative_to(ROOT).as_posix()
                    report['replication_metadata_after_actor_open_retry'] = refresh_progress
                    report['post_travel_metadata_refresh'] = {'stage': 'post_travel_metadata_refresh_completed',
                        'status': fresh.get('status'), 'maximum_attempts': 2,
                        'partial_metadata_merged': False, 'shared_maximum_seconds': 180,
                        'native_possession_verified': False, 'playable_map_verified': False}
                except Exception as error:
                    report['replication_metadata_after_actor_open'] = {'status': 'metadata_refresh_refused',
                        'error_type': type(error).__name__, 'game_modified': False, 'process_memory_written': False,
                        'native_possession_verified': False, 'playable_map_verified': False}
                    report['post_travel_metadata_refresh'] = {'stage': 'post_travel_metadata_refresh_refused',
                        'error_type': type(error).__name__, 'maximum_attempts': 2, 'partial_metadata_merged': False,
                        'native_possession_verified': False, 'playable_map_verified': False}
                after_metadata = report['replication_metadata_after_actor_open']
                completion = entry_completion_observer.snapshot()
                references_observed = restart_associations_verified(after_metadata, identity.get('pid'), identity.get('created_at'))
                save()
                print(json.dumps(report['post_travel_metadata_refresh']), flush=True)
            gate_observation = {'stage': 'pc_restart_post_travel_gate',
                'entry_completion_observed': completion.complete,
                'current_owned_process': current_owned,
                'typed_references_observed': references_observed,
                'native_possession_verified': False, 'playable_map_verified': False}
            if report.get('pc_restart_post_travel_gate') != gate_observation:
                report['pc_restart_post_travel_gate'] = gate_observation
                print(json.dumps(gate_observation), flush=True)
            if completion.complete and current_owned and references_observed:
                if qualified_initial_association_source_pins(ROOT) != association_source_pins:
                    raise RuntimeError('Restart sources changed after trial sealing')
                restart_owner_sink = []
                requested = game_server_probe.request_pc_restart(2201, observer_owner_sink=restart_owner_sink)
                report['pc_restart_post_travel_progress'] = {
                    'stage': 'pc_restart_post_travel_request', 'status': requested,
                    'map_id': 2201, 'entry_completion_observed': True,
                    'typed_references_observed': True,
                    'possession_verified': False, 'playable_map_verified': False}
                if requested in ('queued', 'already_requested'):
                    if len(restart_owner_sink) != 1:
                        raise ValueError('One current Restart observer owner is required')
                    pc_restart_appearance_owner = restart_owner_sink[0]
                    pc_restart_appearance_process = (identity['pid'], identity['created_at'])
                    report['pc_restart_post_travel_request_queued'] = True
                    save()
                    print(json.dumps(report['pc_restart_post_travel_progress']), flush=True)
        if automatic_appearance_observer is not None:
            retained_source_error_type = None
            observer_phase = 'observer_identity_preparation'
            pre_start_attempt_owner = None
            pre_start_refused = (automatic_appearance_pre_start_refusal is not None and
                automatic_appearance_pre_start_refusal[0] is pc_restart_appearance_owner and
                automatic_appearance_pre_start_refusal[1] == pc_restart_appearance_process)
            try:
                observer_identity = report.get('replication_metadata_export_identity', {})
                observer_owned = (observer_identity.get('pid'), observer_identity.get('created_at'))
                restart_delivery = {'status': 'waiting', 'waiting_for': ('current_owned_process',)}
                if (report.get('pc_restart_post_travel_request_queued') is True and
                        observer_owned in metadata_owned_candidates and
                        not automatic_appearance_observer.attempted and not pre_start_refused):
                    if game_server_probe is not None and pc_restart_appearance_process == observer_owned:
                        restart_delivery = game_server_probe.pc_restart_observer_delivery_gate(
                            2201, owner=pc_restart_appearance_owner)
                    restart_gate = {'stage': 'automatic_appearance_restart_delivery_gate', **restart_delivery}
                    if report.get('automatic_appearance_restart_delivery_gate') != restart_gate:
                        report['automatic_appearance_restart_delivery_gate'] = restart_gate
                        save()
                        print(json.dumps(restart_gate), flush=True)
                if (report.get('pc_restart_post_travel_request_queued') is True and
                        observer_owned in metadata_owned_candidates and
                        pc_restart_appearance_process == observer_owned and
                        restart_delivery.get('status') == 'ready' and
                        not automatic_appearance_observer.attempted and not pre_start_refused):
                    # One preparation per exact Restart owner/process. A failed
                    # source preflight must not run again every monitor tick.
                    pre_start_attempt_owner = (pc_restart_appearance_owner, observer_owned)
                    helper_identity = psutil.Process(os.getpid())
                    retained_prepared = None
                    if automatic_appearance_observer.config.get('retain_original_fashion_worker', False):
                        from dfserver.legacy_ds_fashion_retained_trial import prepare_retained_trial, RetainedTrialQueue, RetainedSourcePreflightError
                        retained_source_error_type = RetainedSourcePreflightError
                        observer_phase = 'retained_current_bootstrap_source_preparation'
                        retained_sources = retained_current_bootstrap_sources(ROOT, TEST_ROOT,
                            additional_sources={**bootstrap_source_pins, **association_source_pins},
                            bootstrap_progress=report.get('ds_initial_actor_bootstrap_progress'),
                            metadata_directory=report.get('replication_metadata_export_directory'),
                            metadata_report=report.get('replication_metadata_export'),
                            metadata_identity=observer_identity, owned_identity=observer_owned)
                        observer_phase = 'retained_original_owner_preparation'
                        retained_prepared = prepare_retained_trial(game_server_probe, 2201, base_root=ROOT,
                            repository_root=automatic_appearance_observer.config['repository_root'],
                            additional_sources=retained_sources)
                    observer_phase = 'automatic_observer_start'
                    automatic_appearance_observer.start(pid=observer_identity['pid'],
                        created_at=observer_identity['created_at'], parent_pid=os.getpid(),
                        parent_created_at=helper_identity.create_time(), restart_queued=True,
                        gate=report.get('pc_restart_post_travel_gate'), owned_identity=observer_owned,
                        **({'retained_owner_anchor': retained_prepared.anchor} if retained_prepared is not None else {}))
                    if retained_prepared is not None and automatic_appearance_observer.state.get('status') == 'running':
                        observer_phase = 'retained_queue_start'
                        retained_fashion_trial = RetainedTrialQueue(automatic_appearance_observer,
                            game_server_probe, retained_prepared).start()
                if retained_fashion_trial is not None:
                    observer_phase = 'retained_queue_poll'
                    retained_summary = retained_fashion_trial.summary()
                    if report.get('retained_fashion_delivery') != retained_summary:
                        report['retained_fashion_delivery'] = retained_summary
                        save()
                        print(json.dumps({'stage': 'retained_fashion_delivery',
                            'status': retained_summary.get('status'), 'phase': retained_summary.get('phase'),
                            'model_verified': False}), flush=True)
                observer_phase = 'automatic_observer_poll'
                observer_state = (dict(automatic_appearance_pre_start_refusal[2]) if pre_start_refused
                                  else automatic_appearance_observer.poll())
            except Exception as error:
                observer_state = {'status': 'refused', 'error_type': type(error).__name__,
                    'model_verified': False}
                before_start_failure = automatic_appearance_pre_start_failure(observer_phase, error)
                if before_start_failure is not None:
                    observer_state['controlled_preparation_failure'] = before_start_failure
                if retained_source_error_type is not None and type(error) is retained_source_error_type:
                    observer_state['pre_native_source_failure'] = error.safe_diagnostics()
                if pre_start_attempt_owner is not None and not automatic_appearance_observer.attempted:
                    retry = {'status': 'refused', 'phase': observer_phase,
                        'error_type': type(error).__name__, 'attempts': 1, 'maximum_attempts': 1,
                        'reason': (before_start_failure['reason'] if before_start_failure is not None
                                   else 'controlled_pre_start_exception'),
                        'retry_requires': 'new_owned_restart', 'model_verified': False}
                    observer_state['pre_start_retry'] = retry
                    automatic_appearance_pre_start_refusal = (*pre_start_attempt_owner, dict(observer_state))
                    # Keep this terminal pre-start outcome even when normal
                    # observer cleanup later reports its unstarted state.
                    report['automatic_appearance_pre_start_retry'] = retry
            if report.get('automatic_appearance_observer') != observer_state:
                report['automatic_appearance_observer'] = observer_state
                save()
                print(json.dumps({'stage': 'automatic_appearance_observer',
                    'status': observer_state.get('status'), 'model_verified': False}), flush=True)
        if (args.ds_human_player_state_fields and human_ps_content is not None and game_server_probe is not None and
                report.get('pc_restart_post_travel_request_queued') and
                not report.get('human_ps_late_fields_queued') and
                not report.get('human_ps_late_fields_refused')):
            # The dedicated PS outbox waits for reliable restart delivery and
            # the same Pawn possession ACK. Initial actor namespaces stay intact.
            try:
                if initial_actor_bootstrap_source_pins(ROOT) != bootstrap_source_pins:
                    raise ValueError('Human PlayerState sender sources changed after preflight')
                current_content, current_summary = load_trial_content(ROOT, enabled=True)
                if current_content != human_ps_content or current_summary != human_ps_summary:
                    raise ValueError('Human PlayerState trial sources changed after preflight')
                requested = game_server_probe.queue_late_player_state_human_appearance_diagnostic(
                    2201, content=human_ps_content, source_pins=human_ps_summary['source_pins'])
            except (ValueError, OSError):
                # Changed sources, another operator or a stale ticket refuse
                # this optional diagnostic without ending the running game.
                requested = 'refused'
                report['human_ps_late_fields_refused'] = True
            observation = {'stage': 'human_ps_late_fields_request',
                'status': requested, 'map_id': 2201,
                'field_names': human_ps_summary['field_names'],
                'native_acceptance_verified': False, 'model_verified': False}
            if report.get('human_ps_late_fields_progress') != observation:
                report['human_ps_late_fields_progress'] = observation
                save()
                print(json.dumps(observation), flush=True)
            if requested in ('queued', 'already_queued'):
                report['human_ps_late_fields_queued'] = True
                save()
        if ((args.ds_transport_code_probe or args.ds_connection_class_code_probe or args.ds_control_code_probe or args.ds_image_code_cache) and game_server_probe
                and (game_server_probe.records or
                     (report["elapsed_seconds"] >= 20 and report["original_client_local_game_connection_observed"]))
                and not report.get("bounded_named_transport_collection_attempted")):
            report["bounded_named_transport_collection_attempted"] = True
            report["bounded_named_transport_collection_trigger"] = (
                "local_udp_observed" if game_server_probe.records else "local_lobby_connection_observed")
            transport_folder = (ROOT / "work/native-code-cache" / str(time.time_ns()) if args.ds_image_code_cache else TEST_ROOT / ("ds-native-control-code" if args.ds_control_code_probe else
                                            "ds-connection-class-code" if args.ds_connection_class_code_probe
                                            else "ds-named-transport"))
            if not args.ds_image_code_cache:
                transport_folder.mkdir()
            try:
                if args.ds_image_code_cache:
                    from snapshot_native_image_code import collect as collect_image_code
                    from snapshot_native_image_code import verified_pids as image_code_pids
                    image_pids = image_code_pids(ENTRY)
                    if len(image_pids) != 1:
                        raise RuntimeError("Unique shadow process required for private code cache")
                    image_process = psutil.Process(image_pids[0])
                    report["private_image_code_cache_path"] = str(transport_folder)
                    report["bounded_named_transport_collection"] = collect_image_code(
                        GAME, transport_folder, image_process.pid, image_process.create_time())
                elif args.ds_control_code_probe:
                    if args.ds_control_sender_body:
                        from read_native_sender_body import collect as collect_sender_body
                        report["bounded_named_transport_collection"] = collect_sender_body(GAME, transport_folder)
                    elif args.ds_control_followup_code:
                        report["bounded_named_transport_collection"] = collect_control_followup(GAME, transport_folder)
                    else:
                        from read_native_control_code import collect as collect_native_control_code
                        report["bounded_named_transport_collection"] = collect_native_control_code(
                            GAME, transport_folder, candidate_interval=args.ds_control_candidate_interval,
                            field_helpers=args.ds_control_field_helpers)
                elif args.ds_connection_class_code_probe:
                    from read_ds_connection_class_code import collect as collect_connection_class_code
                    report["bounded_named_transport_collection"] = collect_connection_class_code(GAME, transport_folder)
                else:
                    from read_named_ds_transport_code import collect as collect_named_transport_code
                    report["bounded_named_transport_collection"] = collect_named_transport_code(
                        GAME, transport_folder, implementation_code=True, wait_seconds=0)
            except Exception as error:
                report["bounded_named_transport_collection"] = {
                    "status": "bounded_read_failed", "error_type": type(error).__name__,
                    "game_modified": False, "process_memory_written": False}
            if args.ds_control_code_probe or args.ds_image_code_cache:
                summary = control_collection_summary(
                    report["bounded_named_transport_collection"],
                    round(time.monotonic()-start, 2), args.stop_after_code_collection)
                report["native_control_code_collection_progress"] = summary
                save()
                print(json.dumps(summary, ensure_ascii=False), flush=True)
                if args.stop_after_code_collection:
                    report["observation_stop_reason"] = "explicit_stop_after_code_collection"
                    save()
                    break
        report["root_exit_code"] = child.poll()
        report["resource_samples"].append(capture_resources(time.monotonic()-start, "iteration_end", owned))
        save()
        if args.entry_code_probe:
            expected_samples = {"entry-game-flow-binding.dfcode":578,
                "entry-seamless-enabled-binding.dfcode":47, "entry-new-loading-binding.dfcode":47,
                "entry-game-flow-handler.dfcode":1078, "entry-new-loading-invoker.dfcode":16,
                "entry-seamless-invoker.dfcode":16, "entry-new-loading-implementation.dfcode":194,
                "entry-seamless-implementation.dfcode":1445,
                "ds-notify-handshake-binding.dfcode":16, "ds-cookie-getter.dfcode":85,
                "ds-challenge-sequence.dfcode":217, "ds-reset-challenge.dfcode":129,
                "ds-class-registration.dfcode":84, "ds-binding-finalizer.dfcode":84,
                "ds-init-from-connectionless.dfcode":16, "ds-passed-challenge.dfcode":157,
                "ds-restarted-match.dfcode":96, "ds-set-driver.dfcode":16,
                "ds-restart-handshake.dfcode":48,
                "ds-init-implementation.dfcode":163, "ds-driver-implementation.dfcode":302,
                "ds-restart-implementation.dfcode":108, "ds-vtable-slot13-candidate.dfcode":16,
                "ds-vtable-slot4-candidate.dfcode":1069, "ds-vtable-slot5-candidate.dfcode":294,
                "ds-vtable-slot14-candidate.dfcode":599,
                "ds-handshake-parser.dfcode":759, "ds-challenge-response.dfcode":797,
                "ds-handshake-ack.dfcode":613, "ds-handler-dtor-candidate.dfcode":52}
            if all((TEST_ROOT / name).is_file() and (TEST_ROOT / name).stat().st_size == size + 32
                   for name, size in expected_samples.items()):
                report["entry_code_samples_complete"] = True
                report["observation_stop_reason"] = "named_entry_code_samples_complete"
                break
        if report["platform_fallback_observed"] or any(e["event"].startswith("unsupported_") for e in report["sdk_events"]):
            report["observation_stop_reason"] = "platform_fallback_or_unsupported_sdk_event"
            break
        if (wire_state and not args.wire_business_bootstrap_probe
                and any(r.get("post_response_command") == 0x4013
                        for r in wire_state.data["records"])):
            report["observation_stop_reason"] = "wire_identity_response_observed"
            break
        if updated_minimum_source_lease is not None and game_server_probe is not None:
            if report.get('updated_minimum_restart_request') not in ('queued', 'already_requested'):
                report['updated_minimum_restart_request'] = game_server_probe.request_pc_restart(2201)
        if portable_plan is not None and game_server_probe is not None:
            # This requests the existing ticket/generation-gated restart. The
            # transport itself still waits for delivered readiness and exports.
            if report.get('portable_restart_request') not in ('queued', 'already_requested'):
                report['portable_restart_request'] = game_server_probe.request_pc_restart(2201)
            # This full delivery recheck rebuilds every content plan under the
            # game-server lock (~1 s), stalling UDP receive. Its only consumer
            # is the one-time metadata gate below, so stop once that started.
            if not report.get('portable_extended_metadata_attempted'):
                delivery = game_server_probe.actor_transport_delivery_progress(require_post_open_contents=True)
                try:
                    transport_report = json.loads((TEST_ROOT / 'game-server-packets/report.json').read_bytes())
                    gameplay_control = transport_report.get('handshake_probe', {}).get('native_control_probe', {})
                except (OSError, ValueError):
                    gameplay_control = {}
                if (delivery.get('fully_delivered_sets', 0) == 1 and
                        gameplay_control.get('pc_possession_rpc_acknowledgements', 0) > 0 and
                        gameplay_control.get('pc_hud_delivery_acks', 0) > 0):
                    report['portable_extended_metadata_attempted'] = True
                    report['portable_map_bootstrap'] = portable_plan.summary()
                    report['portable_after_open_metadata_attempted'] = True
                    report['portable_runtime_observation_attempted'] = True
                    report['portable_gameplay_metadata_attempted'] = True
                    save()
                    try:
                        if len(metadata_owned_candidates) != 1:
                            raise ValueError('Portable observation requires one owned Shipping process')
                        if load_plan(ROOT, args.portable_map_bootstrap).sources != portable_plan.sources:
                            raise ValueError('Portable sources changed before gameplay metadata observation')
                        from portable_gameplay_observers import GameplayObservationProcess
                        sample_pid, sample_created = next(iter(metadata_owned_candidates))
                        portable_gameplay_observer = GameplayObservationProcess(
                            ROOT, GAME, REPORT, TEST_ROOT, args.portable_map_bootstrap,
                            source_pins=portable_plan.sources,
                            process_identity=dict(pid=sample_pid, created_at=sample_created))
                        report['portable_extended_metadata'] = portable_gameplay_observer.start(
                            game_server_probe.single_delivered_loadout_snapshot())
                    except Exception as error:
                        report['portable_extended_metadata'] = dict(status='refused',
                            error_type=type(error).__name__, reason=str(error), process_memory_written=False)
                    save()
                    print(json.dumps({'stage': 'portable_extended_metadata',
                        **report['portable_extended_metadata']}), flush=True)
            if portable_gameplay_observer is not None:
                state = portable_gameplay_observer.poll()
                if state != report.get('portable_extended_metadata'):
                    report['portable_extended_metadata'] = state
                    for source, target in (('owned-gameplay-metadata', 'portable_gameplay_metadata'),
                            ('portable-runtime-after-possession', 'portable_runtime_observation'),
                            ('portable-after-open-templates', 'portable_after_open_metadata')):
                        if source in state.get('results', {}):
                            report[target] = state['results'][source]
                    save()
                    print(json.dumps({'stage': 'portable_extended_metadata', **state}), flush=True)
        if time.monotonic()-start >= report["observation_limit_seconds"]:
            report["observation_stop_reason"] = "observation_limit_reached"
            break
        if iteration >= 15 and child.poll() is not None and not any(p["pid"] in owned for p in current):
            report["observation_stop_reason"] = "owned_client_processes_exited"
            break
        time.sleep(1.5)
except Exception as error:
    report["test_error"] = {"type":type(error).__name__,"windows_error":getattr(error,"winerror",None),
        "frames": [{"file":Path(frame.filename).name,"function":frame.name,"line":frame.lineno}
                   for frame in traceback.extract_tb(error.__traceback__)]}
    report["observation_stop_reason"] = "test_error"
finally:
    report.setdefault("observation_stop_reason", "observation_loop_finished")
    if portable_gameplay_observer is not None:
        try:
            report['portable_extended_metadata'] = portable_gameplay_observer.close()
        except Exception as error:
            report['portable_extended_metadata_cleanup'] = dict(status='refused',
                error_type=type(error).__name__, game_termination_requested=False)
    if automatic_appearance_observer is not None:
        try:
            report['automatic_appearance_observer'] = automatic_appearance_observer.close()
        except Exception as error:
            report['automatic_appearance_observer_cleanup'] = {'status': 'refused',
                'error_type': type(error).__name__, 'game_termination_requested': False}
    if child:
        if any(e["event"].startswith("unsupported_") for e in report["sdk_events"]):
            # Give the provider's named stop time to finish before bounded cleanup.
            try: child.wait(timeout=2)
            except subprocess.TimeoutExpired: pass
        report["root_exit_code_before_cleanup"] = child.poll()
    for pid, created_at in reversed(list(owned.items())):
        try:
            process = psutil.Process(pid)
            if abs(process.create_time()-created_at) > .01: continue
            process.terminate()
            report["scoped_cleanup"].append({"pid":pid,"termination_requested":True})
        except (psutil.NoSuchProcess,psutil.AccessDenied) as error:
            report["scoped_cleanup"].append({"pid":pid,"result":type(error).__name__})
    client_log_stop.set()
    if client_log_thread:
        client_log_thread.join(timeout=2)
    try:
        for attempt in range(20):
            try:
                if renamed:
                    assert digest(ALIAS) == SDK_SHA
                    if installed: assert digest(SDK) == provider_sha
                    os.replace(ALIAS,SDK)
                    renamed = installed = False
                report["original_sdk_restored"] = digest(SDK) == SDK_SHA
                if NEXT.exists():
                    assert digest(NEXT) == provider_sha
                    NEXT.unlink()
                if config_written:
                    assert CONFIG.read_text(encoding="utf-8") == str(EVENTS.resolve()) + "\n"
                    CONFIG.unlink(); config_written = False
                if bootstrap_written:
                    assert BOOTSTRAP.read_bytes() == bootstrap_bytes
                    BOOTSTRAP.unlink(); bootstrap_written = False
                report["restore_retry_count"] = attempt
                if report["original_sdk_restored"] and "restore_last_error" in report:
                    report["restore_transient_error"] = report.pop("restore_last_error")
                break
            except OSError as error:
                report["restore_last_error"] = {"type":type(error).__name__,"windows_error":getattr(error,"winerror",None)}
                save()
                time.sleep(1)
    finally:
        # A refused SDK restore must not prevent independent shadow INI cleanup.
        if engine_ini_override is not None:
            try:
                report["shadow_engine_ini_override"] = engine_ini_override.restore()
            except Exception as error:
                report["shadow_engine_ini_override"] = dict(engine_ini_override.report,
                    restore_error_type=type(error).__name__)
    if wire_server:
        wire_server.shutdown(); wire_server.server_close(); wire_thread.join(timeout=2)
        wire_state.update(listening=False, stopped_at_utc=datetime.now(timezone.utc).isoformat())
        report["wire_identity_probe_records"] = wire_state.data["records"]
    if game_server_probe:
        game_server_probe.close()
        report["game_server_probe_packet_count"] = len(game_server_probe.records)
        report["game_server_probe_transports"] = sorted({
            item["transport"] for item in game_server_probe.records})
    if updated_minimum_source_lease is not None:
        updated_minimum_source_lease.close()
    if updated_minimum_receiver is not None:
        report['updated_minimum_last_receiver_check'] = updated_minimum_receiver.last_observation
        updated_minimum_receiver.close()
    server.shutdown(); server.server_close(); server_thread.join(timeout=2)
    if EVENTS.exists():
        report["sdk_events"] = [json.loads(line) for line in EVENTS.read_text(encoding="utf-8").splitlines() if line.strip()]
    report["remaining_test_processes"] = [p for p in snapshot() if p["pid"] in owned and abs(p["created_at"]-owned[p["pid"]]) < .01]
    if child:
        report["root_exit_code"] = child.poll()
        report["root_termination_requested_by_test"] = any(
            p["pid"] == child.pid and p.get("termination_requested") for p in report["scoped_cleanup"])
    report["original_client_sdk_initialization_observed"] = any(e["event"] == "initialize_exit" and e["result"] is True for e in report["sdk_events"])
    report["original_client_player_id_requested"] = any(e["event"] == "player_id_returned" for e in report["sdk_events"])
    report["original_client_consumed_local_identity"] = any(e["event"] == "local_identity_authorized" and e["result"] is True for e in report["sdk_events"])
    report["original_client_local_catalog_callback_entered"] = any(e["event"] == "local_dlc_catalog_ready_dispatch" for e in report["sdk_events"])
    report["original_client_local_catalog_callback_returned"] = any(e["event"] == "local_dlc_catalog_ready_callback_returned" for e in report["sdk_events"])
    report["original_client_local_expansion_callback_entered"] = any(e["event"] == "local_expansion_catalog_list_dispatch" for e in report["sdk_events"])
    report["original_client_local_expansion_callback_returned"] = any(e["event"] == "local_expansion_catalog_list_callback_returned" for e in report["sdk_events"])
    report["original_client_local_zone_address_read_observed"] = any(e["event"] == "local_zone_addresses_returned" and e["result"] is True for e in report["sdk_events"])
    report["original_client_local_zone_language_read_observed"] = any(e["event"] == "local_zone_languages_returned" and e["result"] is True for e in report["sdk_events"])
    report["original_client_local_account_info_read_observed"] = any(e["event"] == "local_account_info_returned" and e["result"] is True for e in report["sdk_events"])
    report["original_client_local_account_login_callback_entered"] = any(e["event"] == "local_account_login_dispatch" for e in report["sdk_events"])
    report["original_client_local_account_login_callback_returned"] = any(e["event"] == "local_account_login_callback_returned" for e in report["sdk_events"])
    samples = report["resource_samples"]
    report["resource_sample_summary"] = {
        "sample_count":len(samples),
        "minimum_observed_physical_available_bytes":min((s["physical_available_bytes"] for s in samples),default=None),
        "maximum_observed_system_commit_bytes":max((s["system_commit_bytes"] for s in samples if "system_commit_bytes" in s),default=None),
        "maximum_observed_commit_fraction":max((s["system_commit_bytes"] / s["system_commit_limit_bytes"] for s in samples if s.get("system_commit_limit_bytes")),default=None),
        "system_commit_peak_since_boot_is_not_a_test_peak":True,
    }
    report["record_complete"] = True
    save()
    print(json.dumps(report,ensure_ascii=False,indent=2),flush=True)
    assert report["original_sdk_restored"], "Restore required before further game work"
    assert (engine_ini_override is None or report["shadow_engine_ini_override"].get("status") in
            ("restored_exact_original_bytes", "no_override_was_applied")), \
        "Exact shadow Engine.ini restoration required before further game work"
    assert not report.get("test_error"), "Native trial failed; see its recorded error"
