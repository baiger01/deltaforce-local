"""One bounded native trial through normal Windows UAC; never operates its UI."""
from pathlib import Path
from datetime import datetime, timezone
import argparse
import contextlib
import ctypes as C
from ctypes import wintypes as W
import hashlib
import json
import os
import runpy
import subprocess
import sys
import time
from local_game_paths import game_paths, project_path

ROOT = Path(__file__).resolve().parent.parent
RUNNER = ROOT / "work/verify_local_provider_client.py"
REPORT = ROOT / "outputs/native-account-provider/elevated-launch-observation.json"
CONTROL_PROFILE = ROOT / "outputs/df-local-server/protocol/native_ds_wire_profile.json"
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



parser = argparse.ArgumentParser()
parser.add_argument("--entry", choices=("shipping", "bootstrap"), default="shipping")
parser.add_argument("--wire-identity-probe", action="store_true")
parser.add_argument("--wire-auth-response-probe", action="store_true")
parser.add_argument("--wire-auth-identity-probe", action="store_true")
parser.add_argument("--wire-ready-probe", action="store_true")
parser.add_argument("--wire-ready-identity-probe", action="store_true")
parser.add_argument("--wire-business-login-probe", action="store_true")
parser.add_argument("--wire-business-bootstrap-probe", action="store_true")
parser.add_argument("--game-server-probe", action="store_true")
parser.add_argument("--ds-handshake-probe", action="store_true")
parser.add_argument("--ds-packet-ack-probe", action="store_true")
parser.add_argument("--ds-control-probe", action="store_true",
                    help="Native Hello/Challenge exchange; no program code collection")
parser.add_argument("--replication-metadata-export", action="store_true",
                    help="Export bounded class/replication metadata once from the owned shadow lobby client")
parser.add_argument("--ds-initial-actor-bootstrap", action="store_true",
                    help="Register one source-backed Pawn Actor-open after metadata export; spawn unverified")
parser.add_argument("--ds-transport-code-probe", action="store_true")
parser.add_argument("--ds-connection-class-code-probe", action="store_true")
parser.add_argument("--ds-control-code-probe", action="store_true")
parser.add_argument("--ds-control-candidate-interval", action="store_true",
                    help="Read only the fixed candidate interval with the control collection profile")
parser.add_argument("--ds-control-field-helpers", action="store_true",
                    help="Read only three verified direct control-field callees")
parser.add_argument("--ds-control-followup-code", action="store_true",
                    help="Read four fixed field continuations and the typed SendBunch entry in one trial")
parser.add_argument("--ds-control-sender-body", action="store_true",
                    help="Read the fixed sender wrapper and source-proved implementations")
parser.add_argument("--ds-image-code-cache", action="store_true",
                    help="Save private executable-section code for offline protocol analysis")
parser.add_argument("--stop-after-code-collection", action="store_true",
                    help="With --ds-control-code-probe, stop and restore after the read attempt")
parser.add_argument("--entry-code-probe", action="store_true",
                    help="Read named entry functions, then stop and restore the test files")
parser.add_argument("--ds-join-after-ready", action="store_true")
parser.add_argument("--disable-device-seamless", action="store_true",
                    help="Diagnostic trial using the client's own non-seamless entry setting")
parser.add_argument("--disable-dynamic-address-switch", action="store_true",
                    help="Keep the shipping shadow client's local DS endpoint fixed")
parser.add_argument("--ds-map-id", type=int)
parser.add_argument("--observation-seconds", type=int, default=720)
parser.add_argument("--precreate-game-nick", action="store_true")
parser.add_argument("--native-username")
parser.add_argument("--source-game", type=Path)
parser.add_argument("--shadow-game", type=Path)
parser.add_argument("--game-root", type=Path)
parser.add_argument("--map-board-catalog", type=Path)
parser.add_argument("--worker", action="store_true")
parser.add_argument("--request", type=Path)
args = parser.parse_args()
args.source_game, args.shadow_game = game_paths(args.source_game, args.shadow_game)
if args.game_root is not None:
    args.game_root = project_path(args.game_root, args.source_game)
if args.map_board_catalog is not None:
    args.map_board_catalog = args.map_board_catalog.resolve()
    if not args.map_board_catalog.is_file():
        parser.error("--map-board-catalog must name an existing file")
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
if args.ds_control_probe and (not args.ds_packet_ack_probe or args.entry != "shipping" or
        args.game_root is None or args.game_root.resolve() != args.shadow_game.resolve()):
    parser.error("--ds-control-probe requires shipping shadow and packet transport probes")
if args.ds_control_probe and (args.ds_transport_code_probe or args.ds_connection_class_code_probe or
        args.ds_control_code_probe or args.ds_image_code_cache or args.entry_code_probe):
    parser.error("Native control exchange must run separately from code collection")
if args.ds_control_probe and not args.ds_join_after_ready:
    parser.error("Native control exchange requires --ds-join-after-ready; otherwise no local match handoff is sent")
if args.ds_control_probe and not args.disable_device_seamless:
    parser.error("This native control trial requires --disable-device-seamless for the recovered ordinary entry path")
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
if args.ds_image_code_cache and (not args.game_server_probe or args.game_root is None or args.game_root.resolve() != args.shadow_game.resolve() or args.entry != "shipping"):
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
if args.ds_join_after_ready and not args.game_server_probe:
    parser.error("--ds-join-after-ready requires --game-server-probe")
if args.disable_device_seamless and not args.game_server_probe:
    parser.error("--disable-device-seamless requires --game-server-probe")
if args.disable_dynamic_address_switch and (not args.game_server_probe or args.game_root is None or
        args.game_root.resolve() != args.shadow_game.resolve() or args.entry != "shipping"):
    parser.error("--disable-dynamic-address-switch requires the shipping shadow and local DS probe")
if args.ds_map_id is not None and (not args.game_server_probe or
                                   not 1 <= args.ds_map_id < 1 << 32):
    parser.error("--ds-map-id requires a game-server probe and a positive map ID")
if args.replication_metadata_export and (not args.game_server_probe or args.game_root is None or
        args.game_root.resolve() != args.shadow_game.resolve() or args.entry != "shipping"):
    parser.error("--replication-metadata-export requires the shipping shadow client and local game-server profile")
if args.replication_metadata_export and (args.ds_transport_code_probe or args.ds_connection_class_code_probe or
        args.ds_control_code_probe or args.ds_control_candidate_interval or args.ds_control_field_helpers or
        args.ds_control_followup_code or args.ds_control_sender_body or args.ds_image_code_cache or
        args.entry_code_probe or args.stop_after_code_collection):
    parser.error("Replication metadata export must run separately from program code collection")
if args.ds_initial_actor_bootstrap and (args.game_root is None or
        args.game_root.resolve() != args.shadow_game.resolve() or args.entry != "shipping" or
        not args.ds_control_probe or not args.replication_metadata_export):
    parser.error("--ds-initial-actor-bootstrap requires shipping shadow, native control and replication metadata export")
if args.ds_initial_actor_bootstrap and (args.ds_transport_code_probe or args.ds_connection_class_code_probe or
        args.ds_control_code_probe or args.ds_control_candidate_interval or args.ds_control_field_helpers or
        args.ds_control_followup_code or args.ds_control_sender_body or args.ds_image_code_cache or
        args.entry_code_probe or args.stop_after_code_collection):
    parser.error("Initial Actor bootstrap must run separately from program code collection")
selected_game = args.game_root or args.source_game
if selected_game not in (args.source_game, args.shadow_game):
    parser.error("--game-root must match --source-game or --shadow-game before authorization")
for root in (args.source_game, args.shadow_game):
    if not root.is_dir():
        parser.error("Game paths must exist; provide --source-game and --shadow-game for this machine")
for relative in ("DeltaForce/Binaries/Win64/DeltaForceClient-Win64-Shipping.exe",
                 "DeltaForce/Binaries/ThirdParty/WeGame/Win64/rail_api64.dll"):
    if not (selected_game / relative).is_file():
        parser.error("The selected client is missing a required executable or SDK")

def digest(path):
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


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


def launch_exit_status(report):
    """A launch is successful only when its monitored worker exits cleanly."""
    if (report.get("shell_execute_succeeded") is not True or
            report.get("helper_process_handle_available") is not True):
        return 1
    exit_code = report.get("helper_exit_code")
    return 0 if type(exit_code) is int and exit_code == 0 else 1


def forward_control_collection_progress(report, log_path, report_path):
    """Relay the runner's bounded completion event before the worker exits."""
    if "native_control_code_collection_progress" in report:
        return
    try:
        with log_path.open("r", encoding="utf-8") as stream:
            lines = stream.read(64 * 1024).splitlines()
    except OSError:
        return
    for line in lines:
        try:
            event = json.loads(line)
        except json.JSONDecodeError:
            continue
        if isinstance(event, dict) and event.get("stage") == "native_control_code_collection_completed":
            report["native_control_code_collection_progress"] = event
            report_path.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
            print(json.dumps(event, ensure_ascii=False), flush=True)
            return


def forward_replication_metadata_progress(report, log_path, report_path):
    """Relay only the export summary; never print metadata addresses or labels."""
    if "replication_metadata_export_progress" in report:
        return
    try:
        with log_path.open("r", encoding="utf-8") as stream:
            lines = stream.read(64 * 1024).splitlines()
    except OSError:
        return
    for line in lines:
        try:
            event = json.loads(line)
        except json.JSONDecodeError:
            continue
        if isinstance(event, dict) and event.get("stage") == "replication_metadata_export_completed":
            report["replication_metadata_export_progress"] = event
            report_path.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
            print(json.dumps(event, ensure_ascii=False), flush=True)
            return


def forward_initial_actor_bootstrap_progress(report, log_path, report_path):
    """Relay a prepared/rejected summary, never raw class metadata or identity."""
    try:
        with log_path.open("r", encoding="utf-8") as stream:
            lines = stream.read(64 * 1024).splitlines()
    except OSError:
        return
    for line in lines:
        try:
            event = json.loads(line)
        except json.JSONDecodeError:
            continue
        if not isinstance(event, dict):
            continue
        stage = event.get("stage")
        if stage in ("ds_initial_actor_bootstrap_prepared", "ds_initial_actor_bootstrap_rejected"):
            key = "ds_initial_actor_bootstrap_progress"
        elif stage == "ds_initial_actor_metadata_export_completed":
            key = "replication_metadata_after_actor_open_progress"
        else:
            continue
        if key not in report:
            report[key] = event
            report_path.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
            print(json.dumps(event, ensure_ascii=False), flush=True)


metadata_source_pins = None
if args.replication_metadata_export:
    try:
        metadata_source_pins = replication_metadata_source_pins(ROOT)
    except ValueError as error:
        parser.error(str(error))

control_profile = None
if args.ds_control_probe:
    selected_ds_map_id = (args.ds_map_id if args.ds_map_id is not None
                          else os.environ.get("DF_LOCAL_DS_MAP_ID"))
    try:
        control_profile = load_control_trial_profile(
            CONTROL_PROFILE, ROOT,
            "4254fbe66585f260f1f9dbfc5e302887842552e7baed8939e023160a5e250be0",
            selected_ds_map_id)
    except ValueError as error:
        parser.error(str(error))
    # Seal and forward the effective map even when it came from the environment;
    # the elevated worker must not depend on inherited environment variables.
    args.ds_map_id = int(selected_ds_map_id)

bootstrap_source_pins = None
bootstrap_sources = None
if args.ds_initial_actor_bootstrap:
    try:
        bootstrap_source_pins = initial_actor_bootstrap_source_pins(ROOT)
        bootstrap_sources = load_initial_actor_bootstrap_sources(ROOT, bootstrap_source_pins, args.ds_map_id)
    except ValueError as error:
        parser.error(str(error))

if args.worker:
    assert C.windll.shell32.IsUserAnAdmin(), "Windows elevation was not granted"
    assert args.request and args.request.parent.resolve() == (ROOT / "work/elevated-native-trials").resolve()
    request = json.loads(args.request.read_text(encoding="utf-8"))
    assert request["entry"] == args.entry and request["wire_identity_probe"] == args.wire_identity_probe
    assert request["wire_auth_response_probe"] == args.wire_auth_response_probe
    assert request["wire_auth_identity_probe"] == args.wire_auth_identity_probe
    assert request["wire_ready_probe"] == args.wire_ready_probe
    assert request["wire_ready_identity_probe"] == args.wire_ready_identity_probe
    assert request["wire_business_login_probe"] == args.wire_business_login_probe
    assert request["wire_business_bootstrap_probe"] == args.wire_business_bootstrap_probe
    assert request["game_server_probe"] == args.game_server_probe
    assert request["ds_handshake_probe"] == args.ds_handshake_probe
    assert request["ds_packet_ack_probe"] == args.ds_packet_ack_probe
    assert type(request["ds_control_probe"]) is bool
    assert request["ds_control_probe"] == args.ds_control_probe
    assert type(request["replication_metadata_export"]) is bool
    assert request["replication_metadata_export"] == args.replication_metadata_export
    assert request["replication_metadata_source_pins"] == metadata_source_pins
    assert type(request["ds_initial_actor_bootstrap"]) is bool
    assert request["ds_initial_actor_bootstrap"] == args.ds_initial_actor_bootstrap
    assert request["initial_actor_bootstrap_source_pins"] == bootstrap_source_pins
    assert request["initial_actor_bootstrap_sources"] == bootstrap_sources
    if args.ds_control_probe:
        assert request["control_profile_sha256"] == digest(CONTROL_PROFILE)
    assert request["ds_transport_code_probe"] == args.ds_transport_code_probe
    assert request["ds_connection_class_code_probe"] == args.ds_connection_class_code_probe
    assert request["ds_control_code_probe"] == args.ds_control_code_probe
    assert type(request["ds_control_candidate_interval"]) is bool
    assert request["ds_control_candidate_interval"] == args.ds_control_candidate_interval
    assert type(request["ds_control_field_helpers"]) is bool
    assert request["ds_control_field_helpers"] == args.ds_control_field_helpers
    assert type(request["ds_control_followup_code"]) is bool
    assert request["ds_control_followup_code"] == args.ds_control_followup_code
    assert type(request["ds_control_sender_body"]) is bool
    assert request["ds_control_sender_body"] == args.ds_control_sender_body
    assert type(request["ds_image_code_cache"]) is bool
    assert request["ds_image_code_cache"] == args.ds_image_code_cache
    assert type(request["stop_after_code_collection"]) is bool
    assert request["stop_after_code_collection"] == args.stop_after_code_collection
    assert request["entry_code_probe"] == args.entry_code_probe
    assert request["ds_join_after_ready"] == args.ds_join_after_ready
    assert request["disable_device_seamless"] == args.disable_device_seamless
    assert request["disable_dynamic_address_switch"] == args.disable_dynamic_address_switch
    assert request["ds_map_id"] == args.ds_map_id
    assert request["observation_seconds"] == args.observation_seconds
    assert request["precreate_game_nick"] == args.precreate_game_nick
    assert request["native_username"] == args.native_username
    assert request["source_game"] == str(args.source_game.resolve())
    assert request["shadow_game"] == str(args.shadow_game.resolve())
    assert request["game_root"] == str((args.game_root or args.source_game).resolve())
    assert request["map_board_catalog"] == (str(args.map_board_catalog) if args.map_board_catalog else None)
    assert request["runner_sha256"] == digest(RUNNER)
    assert request["wrapper_sha256"] == digest(Path(__file__))
    assert type(request["socket_helper_readonly_evidence"]) is bool
    if args.ds_connection_class_code_probe:
        assert request["class_reader_sha256"] == digest(ROOT / "work/read_ds_connection_class_code.py")
    if args.ds_control_code_probe:
        assert request["control_reader_sha256"] == digest(ROOT / "work/read_native_control_code.py")
    if args.ds_control_followup_code:
        assert request["control_followup_reader_sha256"] == digest(ROOT / "work/read_native_control_continuations.py")
        assert request["sender_reader_sha256"] == digest(ROOT / "work/read_native_sender_code.py")
    if args.ds_control_sender_body:
        assert request["sender_body_reader_sha256"] == digest(ROOT / "work/read_native_sender_body.py")
    if args.ds_image_code_cache:
        assert request["image_code_reader_sha256"] == digest(ROOT / "work/snapshot_native_image_code.py")
        from snapshot_native_image_code import validate_plan as validate_image_code_plan
        validate_image_code_plan(args.game_root)
    log = args.request.with_suffix(".log")
    os.environ["DF_LOCAL_SOURCE_GAME"] = request["source_game"]
    os.environ["DF_LOCAL_SHADOW_GAME"] = request["shadow_game"]
    if request["socket_helper_readonly_evidence"]:
        os.environ["DF_LOCAL_SOCKET_EVIDENCE"] = "1"
    else:
        os.environ.pop("DF_LOCAL_SOCKET_EVIDENCE", None)
    os.environ["DF_LOCAL_DS_JOIN_PROBE_AFTER_READY"] = (
        "1" if request["ds_join_after_ready"] else "0")
    if request["map_board_catalog"]:
        os.environ.pop("DF_LOCAL_MAP_ID_PROBE", None)
        os.environ["DF_LOCAL_MAP_BOARD_CATALOG"] = request["map_board_catalog"]
    if request["ds_map_id"] is not None:
        os.environ["DF_LOCAL_DS_MAP_ID"] = str(request["ds_map_id"])
    sys.argv = [str(RUNNER), "--entry", args.entry,
                "--game-root", request["game_root"],
                "--observation-seconds", str(args.observation_seconds)]
    if args.wire_identity_probe:
        sys.argv.append("--wire-identity-probe")
    if args.wire_auth_response_probe:
        sys.argv.append("--wire-auth-response-probe")
    if args.wire_auth_identity_probe:
        sys.argv.append("--wire-auth-identity-probe")
    if args.wire_ready_probe:
        sys.argv.append("--wire-ready-probe")
    if args.wire_ready_identity_probe:
        sys.argv.append("--wire-ready-identity-probe")
    if args.wire_business_login_probe:
        sys.argv.append("--wire-business-login-probe")
    if args.wire_business_bootstrap_probe:
        sys.argv.append("--wire-business-bootstrap-probe")
    if args.game_server_probe:
        sys.argv.append("--game-server-probe")
    if args.ds_handshake_probe:
        sys.argv.append("--ds-handshake-probe")
    if args.ds_packet_ack_probe:
        sys.argv.append("--ds-packet-ack-probe")
    if args.ds_control_probe:
        sys.argv.append("--ds-control-probe")
    if args.replication_metadata_export:
        sys.argv.append("--replication-metadata-export")
    if args.ds_initial_actor_bootstrap:
        sys.argv.append("--ds-initial-actor-bootstrap")
    if args.ds_transport_code_probe:
        sys.argv.append("--ds-transport-code-probe")
    if args.ds_connection_class_code_probe:
        sys.argv.append("--ds-connection-class-code-probe")
    if args.ds_control_code_probe:
        sys.argv.append("--ds-control-code-probe")
    if args.ds_control_candidate_interval:
        sys.argv.append("--ds-control-candidate-interval")
    if args.ds_control_field_helpers:
        sys.argv.append("--ds-control-field-helpers")
    if args.ds_control_followup_code:
        sys.argv.append("--ds-control-followup-code")
    if args.ds_control_sender_body:
        sys.argv.append("--ds-control-sender-body")
    if args.ds_image_code_cache:
        sys.argv.append("--ds-image-code-cache")
    if args.stop_after_code_collection:
        sys.argv.append("--stop-after-code-collection")
    if args.entry_code_probe:
        sys.argv.append("--entry-code-probe")
    if args.disable_device_seamless:
        sys.argv.append("--disable-device-seamless")
    if args.disable_dynamic_address_switch:
        sys.argv.append("--disable-dynamic-address-switch")
    if args.precreate_game_nick:
        sys.argv.append("--precreate-game-nick")
    if args.native_username:
        sys.argv.extend(("--native-username", args.native_username))
    with log.open("w", encoding="utf-8", buffering=1) as stream:
        with contextlib.redirect_stdout(stream), contextlib.redirect_stderr(stream):
            runpy.run_path(str(RUNNER), run_name="__main__")
    raise SystemExit(0)

folder = ROOT / "work/elevated-native-trials"
folder.mkdir(exist_ok=True)
request_path = folder / (str(time.time_ns()) + ".json")
request = {"requested_at_utc":datetime.now(timezone.utc).isoformat(), "entry":args.entry,
           "wire_identity_probe":args.wire_identity_probe,
           "wire_auth_response_probe":args.wire_auth_response_probe,
           "wire_auth_identity_probe":args.wire_auth_identity_probe,
           "wire_ready_probe":args.wire_ready_probe,
           "wire_ready_identity_probe":args.wire_ready_identity_probe,
           "wire_business_login_probe":args.wire_business_login_probe,
           "wire_business_bootstrap_probe":args.wire_business_bootstrap_probe,
           "game_server_probe":args.game_server_probe,
           "ds_handshake_probe":args.ds_handshake_probe,
           "ds_packet_ack_probe":args.ds_packet_ack_probe,
           "ds_control_probe":args.ds_control_probe,
           "replication_metadata_export":args.replication_metadata_export,
           "replication_metadata_source_pins":metadata_source_pins,
           "ds_initial_actor_bootstrap":args.ds_initial_actor_bootstrap,
           "initial_actor_bootstrap_source_pins":bootstrap_source_pins,
           "initial_actor_bootstrap_sources":bootstrap_sources,
           "control_profile_sha256":digest(CONTROL_PROFILE) if args.ds_control_probe else None,
           "ds_transport_code_probe":args.ds_transport_code_probe,
           "ds_connection_class_code_probe":args.ds_connection_class_code_probe,
           "ds_control_code_probe":args.ds_control_code_probe,
           "ds_control_candidate_interval":args.ds_control_candidate_interval,
           "ds_control_field_helpers":args.ds_control_field_helpers,
           "ds_control_followup_code":args.ds_control_followup_code,
           "ds_control_sender_body":args.ds_control_sender_body,
           "ds_image_code_cache":args.ds_image_code_cache,
           "stop_after_code_collection":args.stop_after_code_collection,
           "entry_code_probe":args.entry_code_probe,
           "ds_join_after_ready":args.ds_join_after_ready,
           "disable_device_seamless":args.disable_device_seamless,
           "disable_dynamic_address_switch":args.disable_dynamic_address_switch,
           "ds_map_id":args.ds_map_id,
           "observation_seconds":args.observation_seconds,
           "precreate_game_nick":args.precreate_game_nick,
           "native_username":args.native_username,
           "source_game":str(args.source_game.resolve()),
           "shadow_game":str(args.shadow_game.resolve()),
           "game_root":str((args.game_root or args.source_game).resolve()),
           "map_board_catalog":str(args.map_board_catalog) if args.map_board_catalog else None,
           "runner_sha256":digest(RUNNER), "wrapper_sha256":digest(Path(__file__)),
           "class_reader_sha256":digest(ROOT / "work/read_ds_connection_class_code.py")
               if args.ds_connection_class_code_probe else None,
           "control_reader_sha256":digest(ROOT / "work/read_native_control_code.py")
               if args.ds_control_code_probe else None,
           "control_followup_reader_sha256":digest(ROOT / "work/read_native_control_continuations.py")
               if args.ds_control_followup_code else None,
           "sender_reader_sha256":digest(ROOT / "work/read_native_sender_code.py")
               if args.ds_control_followup_code else None,
           "sender_body_reader_sha256":digest(ROOT / "work/read_native_sender_body.py")
               if args.ds_control_sender_body else None,
           "image_code_reader_sha256":digest(ROOT / "work/snapshot_native_image_code.py")
               if args.ds_image_code_cache else None,
           "normal_windows_uac":True, "authorization_window_operated_by_tool":False,
           "socket_helper_readonly_evidence":os.environ.get("DF_LOCAL_SOCKET_EVIDENCE") == "1"}
request_path.write_text(json.dumps(request, indent=2) + "\n", encoding="utf-8")

class ShellInfo(C.Structure):
    _fields_ = [("cbSize",W.DWORD),("fMask",W.ULONG),("hwnd",W.HWND),("lpVerb",W.LPCWSTR),
        ("lpFile",W.LPCWSTR),("lpParameters",W.LPCWSTR),("lpDirectory",W.LPCWSTR),("nShow",C.c_int),
        ("hInstApp",W.HINSTANCE),("lpIDList",C.c_void_p),("lpClass",W.LPCWSTR),("hkeyClass",W.HKEY),
        ("dwHotKey",W.DWORD),("hIcon",W.HANDLE),("hProcess",W.HANDLE)]

shell = C.WinDLL("shell32", use_last_error=True).ShellExecuteExW
shell.argtypes = [C.POINTER(ShellInfo)]; shell.restype = W.BOOL
kernel = C.WinDLL("kernel32", use_last_error=True)
kernel.GetProcessId.argtypes = [W.HANDLE]; kernel.GetProcessId.restype = W.DWORD
kernel.WaitForSingleObject.argtypes = [W.HANDLE,W.DWORD]; kernel.WaitForSingleObject.restype = W.DWORD
kernel.GetExitCodeProcess.argtypes = [W.HANDLE,C.POINTER(W.DWORD)]; kernel.GetExitCodeProcess.restype = W.BOOL
kernel.CloseHandle.argtypes = [W.HANDLE]; kernel.CloseHandle.restype = W.BOOL
user = C.WinDLL("user32", use_last_error=True)
user.GetForegroundWindow.argtypes = []; user.GetForegroundWindow.restype = W.HWND

report = dict(request)
report["request_name"] = request_path.name
if REPORT.exists():
    previous = json.loads(REPORT.read_text(encoding="utf-8"))
    assert previous.get("completed_at_utc"), "An earlier elevated trial has not completed"
    REPORT.with_name("elevated-launch-observation-" + str(time.time_ns()) + ".json").write_text(
        REPORT.read_text(encoding="utf-8"), encoding="utf-8")
REPORT.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
info = ShellInfo(); info.cbSize = C.sizeof(info); info.fMask = 0x140
info.hwnd = user.GetForegroundWindow()
info.lpVerb = "runas"; info.lpFile = sys.executable
parameters = [str(Path(__file__).resolve()), "--worker", "--entry", args.entry,
              "--request", str(request_path),
              "--source-game", str(args.source_game.resolve()),
              "--shadow-game", str(args.shadow_game.resolve()),
              "--game-root", str((args.game_root or args.source_game).resolve()),
              "--observation-seconds", str(args.observation_seconds)]
if args.map_board_catalog:
    parameters.extend(("--map-board-catalog", str(args.map_board_catalog)))
if args.wire_identity_probe:
    parameters.append("--wire-identity-probe")
if args.wire_auth_response_probe:
    parameters.append("--wire-auth-response-probe")
if args.wire_auth_identity_probe:
    parameters.append("--wire-auth-identity-probe")
if args.wire_ready_probe:
    parameters.append("--wire-ready-probe")
if args.wire_ready_identity_probe:
    parameters.append("--wire-ready-identity-probe")
if args.wire_business_login_probe:
    parameters.append("--wire-business-login-probe")
if args.wire_business_bootstrap_probe:
    parameters.append("--wire-business-bootstrap-probe")
if args.game_server_probe:
    parameters.append("--game-server-probe")
if args.ds_handshake_probe:
    parameters.append("--ds-handshake-probe")
if args.ds_packet_ack_probe:
    parameters.append("--ds-packet-ack-probe")
if args.ds_control_probe:
    parameters.append("--ds-control-probe")
if args.replication_metadata_export:
    parameters.append("--replication-metadata-export")
if args.ds_initial_actor_bootstrap:
    parameters.append("--ds-initial-actor-bootstrap")
if args.ds_transport_code_probe:
    parameters.append("--ds-transport-code-probe")
if args.ds_connection_class_code_probe:
    parameters.append("--ds-connection-class-code-probe")
if args.ds_control_code_probe:
    parameters.append("--ds-control-code-probe")
if args.ds_control_candidate_interval:
    parameters.append("--ds-control-candidate-interval")
if args.ds_control_field_helpers:
    parameters.append("--ds-control-field-helpers")
if args.ds_control_followup_code:
    parameters.append("--ds-control-followup-code")
if args.ds_control_sender_body:
    parameters.append("--ds-control-sender-body")
if args.ds_image_code_cache:
    parameters.append("--ds-image-code-cache")
if args.stop_after_code_collection:
    parameters.append("--stop-after-code-collection")
if args.entry_code_probe:
    parameters.append("--entry-code-probe")
if args.ds_join_after_ready:
    parameters.append("--ds-join-after-ready")
if args.disable_device_seamless:
    parameters.append("--disable-device-seamless")
if args.disable_dynamic_address_switch:
    parameters.append("--disable-dynamic-address-switch")
if args.ds_map_id is not None:
    parameters.extend(("--ds-map-id", str(args.ds_map_id)))
if args.precreate_game_nick:
    parameters.append("--precreate-game-nick")
if args.native_username:
    parameters.extend(("--native-username", args.native_username))
info.lpParameters = subprocess.list2cmdline(parameters)
info.lpDirectory = str(ROOT); info.nShow = 0
print("Requesting one bounded test through Windows UAC.", flush=True)
success = shell(C.byref(info))
report["shell_execute_succeeded"] = bool(success)
report["helper_process_handle_available"] = bool(info.hProcess)
if success and info.hProcess:
    report["helper_pid"] = kernel.GetProcessId(info.hProcess)
    REPORT.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({"helper_pid":report["helper_pid"],"entry":args.entry}), flush=True)
    try:
        while kernel.WaitForSingleObject(info.hProcess, 1000) == 258:
            if args.ds_control_code_probe or args.ds_image_code_cache:
                forward_control_collection_progress(report, request_path.with_suffix(".log"), REPORT)
            if args.replication_metadata_export:
                forward_replication_metadata_progress(report, request_path.with_suffix(".log"), REPORT)
            if args.ds_initial_actor_bootstrap:
                forward_initial_actor_bootstrap_progress(report, request_path.with_suffix(".log"), REPORT)
        if args.ds_control_code_probe or args.ds_image_code_cache:
            forward_control_collection_progress(report, request_path.with_suffix(".log"), REPORT)
        if args.replication_metadata_export:
            forward_replication_metadata_progress(report, request_path.with_suffix(".log"), REPORT)
        if args.ds_initial_actor_bootstrap:
            forward_initial_actor_bootstrap_progress(report, request_path.with_suffix(".log"), REPORT)
        exit_code = W.DWORD()
        assert kernel.GetExitCodeProcess(info.hProcess, C.byref(exit_code))
        report["helper_exit_code"] = exit_code.value
    finally:
        kernel.CloseHandle(info.hProcess)
elif not success:
    report["windows_error"] = C.get_last_error()
else:
    report["launch_error"] = "missing_helper_process_handle"
report["completed_at_utc"] = datetime.now(timezone.utc).isoformat()
report["wrapper_exit_code"] = launch_exit_status(report)
REPORT.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
print(json.dumps(report, indent=2), flush=True)
raise SystemExit(report["wrapper_exit_code"])
