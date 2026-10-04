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

import psutil
from client_resource_sampling import capture_resources
from local_game_paths import game_paths

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
parser.add_argument("--observation-seconds", type=int, default=180)
parser.add_argument("--precreate-game-nick", action="store_true")
parser.add_argument("--game-server-probe", action="store_true",
                    help="Bounded local DS handoff; captures first TCP/UDP packets only")
parser.add_argument("--ds-handshake-probe", action="store_true",
                    help="Opt-in loopback plaintext challenge/ACK experiment; not a gameplay server")
parser.add_argument("--ds-packet-ack-probe", action="store_true",
                    help="Opt-in bounded empty packet ACK experiment; control channel remains unimplemented")
parser.add_argument("--ds-control-probe", action="store_true",
                    help="Opt-in source-backed Hello/Challenge exchange; no code reads")
parser.add_argument("--replication-metadata-export", action="store_true",
                    help="Export bounded class/replication metadata once from the owned shadow lobby client")
parser.add_argument("--ds-initial-actor-bootstrap", action="store_true",
                    help="Register one source-backed Pawn Actor-open after successful metadata export; spawn unverified")
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
parser.add_argument("--stop-after-code-collection", action="store_true",
                    help="With --ds-control-code-probe, stop and restore after the read attempt")
parser.add_argument("--entry-code-probe", action="store_true",
                    help="Collect named entry code samples and finish the trial automatically")
parser.add_argument("--disable-device-seamless", action="store_true",
                    help="Use the native Game.DisableDeviceSeamless setting for this trial")
parser.add_argument("--disable-dynamic-address-switch", action="store_true",
                    help="Keep the shadow client's local DS endpoint fixed using its native CVar")
parser.add_argument("--native-username", help="Local username when the test database contains multiple accounts")
args = parser.parse_args()
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
SDK = GAME / "DeltaForce/Binaries/ThirdParty/WeGame/Win64/rail_api64.dll"
if GAME == SHADOW_GAME and SDK.is_file() and os.path.samefile(
        SDK, SOURCE_GAME / SDK.relative_to(GAME)):
    parser.error('The shadow SDK must be an independent copy, not a hard link')
ENTRY = GAME / ("DeltaForce/Binaries/Win64/DeltaForceClient-Win64-Shipping.exe" if args.entry == "shipping" else "DeltaForceClient.exe")
STAGE = ROOT / "work/sdk-local-provider-stage"
SDK_SHA = "9d39a0f5af96d56f465060a582e21faf5c11d5cfdd4e221891d81c58cd7f1723"
ENTRY_SHA = "4254fbe66585f260f1f9dbfc5e302887842552e7baed8939e023160a5e250be0" if args.entry == "shipping" else "6d5f71f958dee483e126337d183849059ef904938e45dfdd0f3cda73e1eeb40b"
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


def replication_metadata_retry_due(report, elapsed_seconds, lobby_candidates, observation_seconds=900):
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
    finished = last.get('elapsed_seconds')
    stable_since = stable.get('since_elapsed_seconds')
    return (last.get('status') == 'metadata_export_refused' and
            last.get('error_type') == 'ValueError' and last.get('reason') in transient_reasons and
            type(finished) in (int, float) and type(elapsed_seconds) in (int, float) and
            type(stable_since) in (int, float) and
            type(observation_seconds) in (int, float) and observation_seconds - elapsed_seconds >= 125 and
            0 <= finished <= stable_since <= elapsed_seconds - 20)


def replication_metadata_source_pins(root):
    """Seal only the metadata collector's explicit source modules before staging."""
    files = ("work/native_metadata_objects.py", "work/native_metadata_names.py", "work/native_metadata_paths.py",
             "work/native_replication_metadata_core.py", "work/export_native_replication_metadata.py",
             "outputs/df-local-server/dfserver/legacy_ds_class_net_cache.py")
    result = {}
    try:
        for relative in files:
            with (Path(root) / relative).open("rb") as stream:
                result[relative] = hashlib.file_digest(stream, "sha256").hexdigest()
    except OSError as error:
        raise ValueError("Replication metadata collector sources are missing or unreadable") from error
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
    root = Path(root).resolve()
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


def prepare_initial_actor_bootstrap(root, metadata_folder, probe, source_pins, sources, max_packet_bytes):
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
        max_packet_bytes=max_packet_bytes, references_resolvable=True)
    prepared = build_pawn_actor_bootstrap(raw, **pawn_arguments)
    optional, rejected, role_sources = {}, {}, {}
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
    roles = [role for role in ("PlayerController", "GameState") if role in optional] + ["Pawn"]
    staged = [optional[role] for role in roles if role != "Pawn"] + [prepared]
    from native_pawn_spawn_policy import build_local_pawn_resolver
    resolver = build_local_pawn_resolver(root, source_pins, raw, pawn_arguments,
                                       sources["local_pawn_spawn_policy"])
    probe.set_initial_actor_manifests(2201, tuple(item.manifest for item in staged), resolver=resolver)
    return {"stage": "ds_initial_actor_bootstrap_prepared", "status": "registered_for_future_local_ticket",
            "role": "Pawn", "map_id": 2201, "metadata_report_sha256": source_hash,
            "game_spawn_flags_resolution": "after_exact_local_ticket_join",
            "pawn_state_origin": "local_server_configuration_not_official_packet_values",
            "roles": roles, "initial_actor_manifest_count": len(staged),
            "actor_channel_indices": {role: actor_channels[role] for role in roles},
            "optional_role_sources": role_sources,
            "optional_role_rejections": rejected, "send_order_gameplay_verified": False,
            "metadata_source_relative_path": path.relative_to(Path(root).resolve()).as_posix(),
            "connection_network_version": sources["connection_network_version"],
            "archive_network_version": sources["archive_network_version"],
            "runtime_connection_version_verified": False,
            "references_resolvable_is_caller_precondition": True,
            "conservative_packet_bytes": prepared.preflight.conservative_packet_bytes,
            "native_spawn_verified": False, "playable_map_verified": False}


metadata_source_pins = None
if args.replication_metadata_export:
    try:
        metadata_source_pins = replication_metadata_source_pins(ROOT)
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
if args.ds_control_probe:
    try:
        control_profile = load_control_trial_profile(
            ROOT / "outputs/df-local-server/protocol/native_ds_wire_profile.json",
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
    "replication_metadata_export_requested":args.replication_metadata_export,
    "replication_metadata_source_pins":metadata_source_pins,
    "ds_initial_actor_bootstrap_requested":args.ds_initial_actor_bootstrap,
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
if engine_overrides:
    # UE combines properties for one config category in one comma-separated
    # override, so both options survive the Engine command-line lookup.
    report["arguments"].append("-ini:Engine:" + ",".join(engine_overrides))


def save():
    report["local_identity_service_queries"] = backend.identity_queries
    REPORT.write_text(json.dumps(report,ensure_ascii=False,indent=2) + "\n",encoding="utf-8")


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
owned = {}
child = None
wire_server = wire_thread = wire_state = game_server_probe = None
try:
    save()
    if args.game_server_probe:
        game_server_probe = GameServerProbe(TEST_ROOT / "game-server-packets",
                                          handshake_probe=args.ds_handshake_probe,
                                          packet_ack_probe=args.ds_packet_ack_probe,
                                          control_probe=args.ds_control_probe,
                                          expected_net_version=(control_profile["hello_net_version"]
                                              if control_profile else None),
                                          control_max_packet_bytes=(control_profile["maximum_packet_bytes"]
                                              if control_profile else 1024),
                                          control_welcome_maps=({int(map_id): spec for map_id, spec in
                                              control_profile["control_welcome_maps"].items()}
                                              if control_profile else None),
                                          # Keep the initial Actor exchange and its retries in
                                          # the same bounded record set as the handshake.
                                          max_packets=(256 if args.ds_initial_actor_bootstrap else
                                              64 if args.ds_packet_ack_probe else 16)).start()
        report["game_server_probe_port"] = game_server_probe.port
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
    child = subprocess.Popen([str(ENTRY),*report["arguments"]],cwd=ENTRY.parent,env=env,
        stdin=subprocess.DEVNULL,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
    report["root_pid"] = child.pid
    try: owned[child.pid] = psutil.Process(child.pid).create_time()
    except psutil.NoSuchProcess: pass
    print(json.dumps({"stage":"original_client_started","pid":child.pid}),flush=True)
    seen = set()
    load_seen = set()
    authorization_seen = set()
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
                        modules = {Path(m.path).name.lower() for m in process.memory_maps(grouped=True)}
                        sample["loaded_modules"] = sorted(modules)
                    except psutil.AccessDenied:
                        sample["process_inspection_limit"] = "AccessDenied"
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
                                                   args.observation_seconds))):
            attempt_number = len(report.get("replication_metadata_export_attempts", [])) + 1
            report["replication_metadata_export_attempted"] = True
            report["replication_metadata_export_trigger"] = "owned_shipping_established_local_lobby_connection"
            metadata_folder = TEST_ROOT / ("replication-metadata" if attempt_number == 1 else
                                          "replication-metadata-retry-2")
            report["replication_metadata_export_directory"] = metadata_folder.relative_to(ROOT).as_posix()
            try:
                if len(metadata_lobby_candidates) != 1:
                    raise RuntimeError("Unique owned lobby Shipping process required for metadata export")
                if replication_metadata_source_pins(ROOT) != metadata_source_pins:
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
                    GAME, metadata_folder, pid=metadata_pid, created_at=metadata_created_at)
                if replication_metadata_source_pins(ROOT) != metadata_source_pins:
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
                "elapsed_seconds": round(time.monotonic()-start, 2),
                "directory": report["replication_metadata_export_directory"]})
            metadata_progress = {"stage": "replication_metadata_export_completed",
                "collection_status": report["replication_metadata_export"].get("status", "unknown"),
                "elapsed_seconds": round(time.monotonic()-start, 2),
                "directory": report["replication_metadata_export_directory"],
                "attempt": attempt_number,
                "reason": collection.get("reason"),
                "maximum_attempts": 2,
                "observation_action": "continue", "playable_map_verified": False}
            report["replication_metadata_export_progress"] = metadata_progress
            if args.ds_initial_actor_bootstrap:
                try:
                    if report["replication_metadata_export"].get("status") != "metadata_export_complete":
                        raise ValueError("Initial Actor bootstrap requires a complete metadata report")
                    if replication_metadata_source_pins(ROOT) != metadata_source_pins:
                        raise ValueError("Metadata collector source identity changed before Actor preparation")
                    actor_progress = prepare_initial_actor_bootstrap(ROOT, metadata_folder,
                        game_server_probe, bootstrap_source_pins, bootstrap_sources,
                        control_profile["maximum_packet_bytes"])
                except Exception as error:
                    actor_progress = {"stage": "ds_initial_actor_bootstrap_rejected",
                        "status": "not_registered", "error_type": type(error).__name__,
                        "reason": str(error)[:256] if isinstance(error, ValueError) else "Initial Actor preparation failed",
                        "native_spawn_verified": False, "playable_map_verified": False}
                report["ds_initial_actor_bootstrap_progress"] = actor_progress
                print(json.dumps(actor_progress, ensure_ascii=False), flush=True)
            save()
            print(json.dumps(metadata_progress, ensure_ascii=False), flush=True)
        if (args.ds_initial_actor_bootstrap and game_server_probe is not None and
                report.get("ds_initial_actor_bootstrap_progress", {}).get("stage") ==
                    "ds_initial_actor_bootstrap_prepared" and
                not report.get("replication_metadata_after_actor_open_attempted")):
            actor_transport = game_server_probe.actor_transport_progress
            identity = report.get("replication_metadata_export_identity", {})
            expected_actor_count = report["ds_initial_actor_bootstrap_progress"].get("initial_actor_manifest_count", 1)
            if (type(expected_actor_count) is int and 1 <= expected_actor_count <= 3 and
                    type(actor_transport.get("fully_delivered_sets")) is int and
                    actor_transport["fully_delivered_sets"] >= 1 and
                    actor_transport.get("datagrams_sent", 0) >= expected_actor_count and
                    actor_transport.get("delivery_acks", 0) >= expected_actor_count and
                    (identity.get("pid"), identity.get("created_at")) in metadata_owned_candidates):
                report["replication_metadata_after_actor_open_attempted"] = True
                report["replication_metadata_after_actor_open_trigger"] = "metadata_after_actor_transport_ack"
                after_folder = TEST_ROOT / "replication-metadata-after-actor-open"
                report["replication_metadata_after_actor_open_directory"] = after_folder.relative_to(ROOT).as_posix()
                try:
                    if (replication_metadata_source_pins(ROOT) != metadata_source_pins or
                            initial_actor_bootstrap_source_pins(ROOT) != bootstrap_source_pins):
                        raise RuntimeError("Metadata or initial Actor sources changed before post-transport export")
                    from export_native_replication_metadata import collect as collect_replication_metadata
                    after_folder.mkdir()
                    report["replication_metadata_after_actor_open"] = collect_replication_metadata(
                        GAME, after_folder, pid=identity["pid"], created_at=identity["created_at"])
                    if (replication_metadata_source_pins(ROOT) != metadata_source_pins or
                            initial_actor_bootstrap_source_pins(ROOT) != bootstrap_source_pins):
                        raise RuntimeError("Metadata or initial Actor sources changed during post-transport export")
                except Exception as error:
                    report["replication_metadata_after_actor_open"] = {
                        "status": "replication_metadata_export_failed", "error_type": type(error).__name__,
                        "game_modified": False, "process_memory_written": False,
                        "native_spawn_verified": False, "playable_map_verified": False}
                    if after_folder.is_dir() and not (after_folder / "result.json").exists():
                        (after_folder / "result.json").write_text(
                            json.dumps(report["replication_metadata_after_actor_open"], indent=2) + "\n", encoding="utf-8")
                after_progress = {"stage": "ds_initial_actor_metadata_export_completed",
                    "phase": "metadata_after_actor_transport_ack",
                    "collection_status": report["replication_metadata_after_actor_open"].get("status", "unknown"),
                    "elapsed_seconds": round(time.monotonic()-start, 2),
                    "directory": report["replication_metadata_after_actor_open_directory"],
                    "read_tables_after_transport_ack": True, "transport_ack_is_not_spawn_proof": True,
                    "observation_action": "continue", "native_spawn_verified": False,
                    "playable_map_verified": False}
                report["replication_metadata_after_actor_open_progress"] = after_progress
                save()
                print(json.dumps(after_progress, ensure_ascii=False), flush=True)
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
        if time.monotonic()-start >= report["observation_limit_seconds"]:
            report["observation_stop_reason"] = "observation_limit_reached"
            break
        if iteration >= 15 and child.poll() is not None and not any(p["pid"] in owned for p in current):
            report["observation_stop_reason"] = "owned_client_processes_exited"
            break
        time.sleep(1.5)
except Exception as error:
    report["test_error"] = {"type":type(error).__name__,"windows_error":getattr(error,"winerror",None)}
    report["observation_stop_reason"] = "test_error"
finally:
    report.setdefault("observation_stop_reason", "observation_loop_finished")
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
    if wire_server:
        wire_server.shutdown(); wire_server.server_close(); wire_thread.join(timeout=2)
        wire_state.update(listening=False, stopped_at_utc=datetime.now(timezone.utc).isoformat())
        report["wire_identity_probe_records"] = wire_state.data["records"]
    if game_server_probe:
        game_server_probe.close()
        report["game_server_probe_packet_count"] = len(game_server_probe.records)
        report["game_server_probe_transports"] = sorted({
            item["transport"] for item in game_server_probe.records})
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
