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
from watch_client_log import follow as follow_client_log

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "outputs/df-local-server"))
from dfserver.core import Backend
from dfserver.http_api import create_server
from dfserver.protobuf_codec import ProtobufCodec
from dfserver.handshake_diagnostic import Server as HandshakeDiagnosticServer, State as HandshakeDiagnosticState

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
SDK = GAME / "DeltaForce/Binaries/ThirdParty/WeGame/Win64/rail_api64.dll"
if GAME == SHADOW_GAME and SDK.is_file() and os.path.samefile(
        SDK, SOURCE_GAME / SDK.relative_to(GAME)):
    parser.error('The shadow SDK must be an independent copy, not a hard link')
ENTRY = GAME / ("DeltaForce/Binaries/Win64/DeltaForceClient-Win64-Shipping.exe" if args.entry == "shipping" else "DeltaForceClient.exe")
STAGE = ROOT / "work/sdk-local-provider-stage"
SDK_SHA = "9d39a0f5af96d56f465060a582e21faf5c11d5cfdd4e221891d81c58cd7f1723"
ENTRY_SHA = "4254fbe66585f260f1f9dbfc5e302887842552e7baed8939e023160a5e250be0" if args.entry == "shipping" else "6d5f71f958dee483e126337d183849059ef904938e45dfdd0f3cda73e1eeb40b"
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
    "bounded_client_code_diagnostic_opt_in":True,
    "wire_identity_probe_requested":args.wire_identity_probe,
    "wire_auth_response_probe_requested":args.wire_auth_response_probe,
    "wire_auth_identity_probe_requested":args.wire_auth_identity_probe,
    "wire_ready_probe_requested":args.wire_ready_probe,
    "wire_ready_identity_probe_requested":args.wire_ready_identity_probe,
    "wire_business_login_probe_requested":args.wire_business_login_probe,
    "wire_business_bootstrap_probe_requested":args.wire_business_bootstrap_probe,
    "game_nick_precreated_for_lobby_trial":args.precreate_game_nick,
    "preserved_test_account": True,
    "local_level": native_lobby_profile["level"],
    "local_currency_count": len(native_lobby_profile["currencies"]),
    "local_warehouse_prop_count": len(native_lobby_profile["props"]),
    "local_safehouse_device_count": len(native_lobby_profile["devices"]),
    "private_runtime_code_sample_directory":TEST_ROOT.relative_to(ROOT).as_posix(),
    "resources_are_discrete_samples_not_continuous_peaks":True}


def save():
    report["local_identity_service_queries"] = backend.identity_queries
    pending_report = REPORT.with_suffix(".json.tmp")
    pending_report.write_text(json.dumps(report,ensure_ascii=False,indent=2) + "\n",encoding="utf-8")
    os.replace(pending_report, REPORT)


renamed = installed = config_written = bootstrap_written = False
owned = {}
child = None
wire_server = wire_thread = wire_state = None
client_log_thread = None
client_log_stop, client_log_ready = threading.Event(), threading.Event()
try:
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
            continuation_seconds=args.observation_seconds + 60)
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
    # Bounded code-only diagnostics for the two runtime-proven SDK caller
    # ranges. The DLL accepts no arbitrary range or protected-process read.
    env["DF_LOCAL_CODE_TRACE_DIR"] = str(TEST_ROOT)
    client_log_path = GAME / 'DeltaForce/Saved/Logs/DeltaForce.log'
    client_alert_path = TEST_ROOT / 'client-alerts.log'
    report['client_log_capture'] = {'source': str(client_log_path), 'path': str(client_alert_path)}

    def capture_client_log():
        try:
            report['client_log_alert_count'] = follow_client_log(
                client_log_path, client_alert_path, args.observation_seconds + 30,
                stop=client_log_stop, ready=client_log_ready)
        except Exception as error:
            report['client_log_capture_error'] = type(error).__name__
            client_log_ready.set()

    client_log_thread = threading.Thread(target=capture_client_log, daemon=True)
    client_log_thread.start()
    if not client_log_ready.wait(5) or report.get('client_log_capture_error'):
        raise RuntimeError('Client log capture did not initialize')
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
                    sample = {"pid":process.pid,"elapsed_seconds":round(time.monotonic()-start,2)}
                    try:
                        sample["status"] = process.status()
                        sample["threads"] = process.num_threads()
                        sample["cpu_seconds"] = round(sum(process.cpu_times()[:2]),3)
                        sample["working_set_bytes"] = process.memory_info().rss
                    except psutil.AccessDenied:
                        sample["process_inspection_limit"] = "AccessDenied"
                    load_key = (process.pid,tuple(sample.get("loaded_modules",[])),sample.get("threads"))
                    if load_key not in load_seen:
                        load_seen.add(load_key)
                        report["process_load_observations"].append(sample)
                    for connection in psutil.Process(item["pid"]).net_connections(kind="tcp"):
                        if connection.raddr and connection.raddr.ip == "127.0.0.1" and connection.raddr.port == 65010:
                            report["original_client_local_game_connection_observed"] = True
                except (psutil.NoSuchProcess,psutil.AccessDenied) as error:
                    report["connection_observation_limit"] = type(error).__name__
        if EVENTS.exists():
            report["sdk_events"] = [json.loads(line) for line in EVENTS.read_text(encoding="utf-8").splitlines() if line.strip()]
        report["elapsed_seconds"] = round(time.monotonic()-start,2)
        if (os.environ.get('DF_LOCAL_RESOURCE_EVIDENCE') == '1'
                and not resource_evidence_captured and report['elapsed_seconds'] >= 30
                and child.poll() is None):
            resource_evidence_captured = True
            probe = ROOT / 'work/probe_live_resource_implementations.py'
            registration_probe = ROOT / 'work/probe_live_resource_loader.py'
            evidence_path = TEST_ROOT / 'resource-implementations-readonly.json'
            record = {'path': str(evidence_path), 'elapsed_seconds': report['elapsed_seconds']}
            try:
                record['probe_sha256'] = digest(probe)
                if record['probe_sha256'] != os.environ.get('DF_LOCAL_RESOURCE_PROBE_SHA256'):
                    raise RuntimeError('Resource witness changed after authorization')
                record['registration_sha256'] = digest(registration_probe)
                if record['registration_sha256'] != os.environ.get('DF_LOCAL_RESOURCE_REGISTRATION_SHA256'):
                    raise RuntimeError('Resource registration witness changed after authorization')
                with evidence_path.with_suffix('.txt').open('w', encoding='utf-8') as output:
                    evidence = subprocess.run([sys.executable, str(probe),
                        '--pid', str(child.pid), '--output', str(evidence_path)],
                        stdout=output, stderr=subprocess.STDOUT, timeout=15)
                record['returncode'] = evidence.returncode
            except (OSError, RuntimeError, subprocess.TimeoutExpired) as error:
                record['error'] = type(error).__name__
            report['resource_loader_readonly_evidence'] = record
        if (os.environ.get('DF_LOCAL_SOCKET_EVIDENCE') == '1'
                and not socket_evidence_captured and report['elapsed_seconds'] >= 30
                and child.poll() is None):
            socket_evidence_captured = True
            with (TEST_ROOT / 'socket-helper-readonly.txt').open('w', encoding='utf-8') as output:
                evidence = subprocess.run([sys.executable, str(ROOT / 'work/probe_gunsmith_native.py'),
                    str(ENTRY), '--pid', str(child.pid), '--rva',
                    '0x60b2d40', '0x60b5430', '0x60b2ce0', '0x60b5330',
                    '0xd3a9930', '0xe2c560', '0xd3c66e0'],
                    stdout=output, stderr=subprocess.STDOUT, timeout=10)
            report['socket_helper_readonly_evidence'] = {'returncode': evidence.returncode,
                'path': str(TEST_ROOT / 'socket-helper-readonly.txt')}
        if (os.environ.get('DF_LOCAL_SOCKET_EVIDENCE') == '1'
                and keybox_probe_attempts < 8 and report['elapsed_seconds'] >= keybox_probe_next_at
                and child.poll() is None):
            keybox_probe_next_at = report['elapsed_seconds'] + 30
            probe = ROOT / 'work/probe_live_keybox_registration.py'
            current_digest = digest(probe)
            if current_digest != keybox_probe_digest:
                keybox_probe_digest = current_digest
                suffix = '' if keybox_probe_attempts == 0 else f'-{int(report["elapsed_seconds"])}'
                keybox_probe_attempts += 1
                evidence_path = TEST_ROOT / f'keybox-registration-readonly{suffix}.json'
                with evidence_path.with_suffix('.txt').open('w', encoding='utf-8') as output:
                    evidence = subprocess.run([sys.executable, str(probe),
                        '--pid', str(child.pid), '--output', str(evidence_path)],
                        stdout=output, stderr=subprocess.STDOUT, timeout=15)
                record = {'returncode': evidence.returncode, 'path': str(evidence_path),
                          'probe_sha256': current_digest, 'elapsed_seconds': report['elapsed_seconds']}
                report['keybox_registration_readonly_evidence'] = record
                report.setdefault('keybox_registration_readonly_captures', []).append(record)
        report["root_exit_code"] = child.poll()
        report["resource_samples"].append(capture_resources(time.monotonic()-start, "iteration_end", owned))
        save()
        if report["platform_fallback_observed"] or any(e["event"].startswith("unsupported_") for e in report["sdk_events"]): break
        if (wire_state and not args.wire_business_bootstrap_probe
                and any(r.get("post_response_command") == 0x4013
                        for r in wire_state.data["records"])): break
        if time.monotonic()-start >= report["observation_limit_seconds"]: break
        if iteration >= 15 and child.poll() is not None and not any(p["pid"] in owned for p in current): break
        time.sleep(1.5)
except Exception as error:
    report["test_error"] = {"type":type(error).__name__,"windows_error":getattr(error,"winerror",None)}
finally:
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
