"""Release only our source and scoped metadata after restoration checks."""
from datetime import datetime,timezone
from pathlib import Path
import ast
import hashlib
import json
import os
import shutil
import zipfile
from urllib.request import urlopen,Request
from urllib.error import HTTPError
import psutil
from local_game_paths import game_paths

ROOT = Path(__file__).resolve().parent.parent
OUT = ROOT / "outputs/native-account-provider"
STAGE = ROOT / "work/sdk-local-provider-stage"
GAME, _ = game_paths()
EXPECTED = {
    "DeltaForceClient.exe":"6d5f71f958dee483e126337d183849059ef904938e45dfdd0f3cda73e1eeb40b",
    "DeltaForce/Binaries/Win64/DeltaForceClient-Win64-Shipping.exe":"4254fbe66585f260f1f9dbfc5e302887842552e7baed8939e023160a5e250be0",
    "DeltaForce/Binaries/ThirdParty/WeGame/Win64/rail_api64.dll":"9d39a0f5af96d56f465060a582e21faf5c11d5cfdd4e221891d81c58cd7f1723",
    "DeltaForce/Binaries/Win64/GCloud.dll":"340288515cb1db59592481c066cb2aa23c53b823661d8b585be7f68d7d9c847b",
    "DeltaForce/Binaries/Win64/DeltaForceClient-Win64-ShippingBase.dll":"c0bf7a6f64fceeb98d32fd2d8be7856e5a9fa8a5a89f272f83095c412e29bdb5",
}
def digest(path):
    with path.open("rb") as stream:
        return hashlib.file_digest(stream,"sha256").hexdigest()

hashes = {name:digest(GAME / name) for name in EXPECTED}
assert hashes == EXPECTED
sdk_dir = GAME / "DeltaForce/Binaries/ThirdParty/WeGame/Win64"
temporary_names = ("df_sdk_original.dll","df_observer_next.dll","df_sdk_observer_logpath.txt",
                   "df_local_no_platform.flag","df_local_identity_bootstrap.bin")
assert not any((sdk_dir / name).exists() for name in temporary_names)
assert not (STAGE / "df_local_identity_bootstrap.bin").exists()
build = json.loads((STAGE / "build-record.json").read_text(encoding="utf-8"))
validation = json.loads((OUT / "validation.json").read_text(encoding="utf-8"))
assert build["provider_sha256"] == validation["provider_sha256"] == digest(STAGE / "rail_api64.dll")
assert build["provider_source_sha256"] == validation["provider_source_sha256"] == digest(OUT / "provider.c")
assert validation["local_account_consumed_by_native_provider"] and validation["unexpected_identity_change_clears_state"]
client = json.loads((OUT / "client-observation.json").read_text(encoding="utf-8"))
assert client["record_complete"] and client["original_sdk_restored"]
history = [client] + [json.loads(p.read_text(encoding="utf-8")) for p in sorted(OUT.glob("client-observation-*.json"))]
def observed_event(record, name):
    return any(e["event"] == name and e["result"] is True for e in record.get("sdk_events", []))
identity_observed = any(observed_event(record, "local_identity_authorized") and
    observed_event(record, "initialize_exit") for record in history)
latest_build_tested = client["provider_sha256"] == build["provider_sha256"]
latest_initialized = latest_build_tested and observed_event(client, "initialize_exit")
callback_returned = latest_build_tested and observed_event(client, "local_dlc_catalog_ready_callback_returned")
callback_observed = any(observed_event(record, "local_dlc_catalog_ready_callback_returned") for record in history)
expansion_callback_observed = any(observed_event(record, "local_expansion_catalog_list_callback_returned") for record in history)
zone_addresses_observed = any(observed_event(record, "local_zone_addresses_returned") for record in history)
zone_languages_observed = any(observed_event(record, "local_zone_languages_returned") for record in history)
account_info_observed = any(observed_event(record, "local_account_info_returned") for record in history)
account_callback_observed = any(observed_event(record, "local_account_login_callback_returned") for record in history)
with urlopen("http://127.0.0.1:8877/healthz",timeout=3) as response:
    health = json.load(response)
assert health.get("native_identity_version") == 1 and health.get("game_compatibility_verified") is False
denied = None
try:
    urlopen(Request("http://127.0.0.1:8877/api/local/native-identity",data=b"{}",
                    headers={"Content-Type":"application/json"}),timeout=3)
except HTTPError as error:
    denied = error.code
assert denied == 401
now = datetime.now(timezone.utc).isoformat()
process_names = {"deltaforceclient.exe","deltaforceclient-win64-shipping.exe","wegame.exe"}
running = [p.info for p in psutil.process_iter(["pid","name"]) if (p.info["name"] or "").lower() in process_names]
post = {"checked_at_utc":now,"original_hashes_verified":hashes,"original_sdk_restored":True,
        "temporary_provider_files_remaining":[],"game_or_platform_processes_at_check":running,
        "local_service_health":health,"unauthenticated_identity_http_status":denied,
        "native_provider_validation_complete":True,"original_client_consumed_local_identity":identity_observed,
        "latest_provider_build_tested":latest_build_tested,
        "latest_provider_original_client_initialized":latest_initialized,
        "latest_provider_local_catalog_callback_returned":callback_returned,
        "original_client_catalog_callback_returned_observed":callback_observed,
        "original_client_expansion_callback_returned_observed":expansion_callback_observed,
        "original_client_local_zone_address_read_observed":zone_addresses_observed,
        "original_client_local_zone_language_read_observed":zone_languages_observed,
        "original_client_local_account_info_read_observed":account_info_observed,
        "original_client_local_account_login_callback_returned_observed":account_callback_observed,
        "original_lobby_compatible":False,"windows_authorization_window_confirmation_pending":False}
launch = json.loads((OUT / "elevated-launch-observation.json").read_text(encoding="utf-8"))
post["latest_windows_launch_error"] = launch.get("windows_error")
post["current_QQ_compatibility_build_original_client_test_complete"] = latest_build_tested
(OUT / "post-test-checks.json").write_text(json.dumps(post,indent=2)+"\n",encoding="utf-8")
shutil.copyfile(STAGE / "build-record.json",OUT / "build-record.json")
backend_record_path = ROOT / "outputs/df-local-server/validation.json"
backend_record = json.loads(backend_record_path.read_text(encoding="utf-8"))
assert backend_record["automated_test_count"] == backend_record["automated_tests_passed"] == 153
backend_record["native_identity_provider_validation"] = "../native-account-provider/validation.json"
backend_record["latest_native_identity_service_observation"] = {"observed_at_utc":now,
    "address":"http://127.0.0.1:8877/","health":health,"unauthenticated_identity_http_status":denied,
    "database_upgrade":"private online backup checked; all 11 prior table row counts preserved; integrity check passed",
    "original_client_identity_adapter_initialization_observed":identity_observed,
    "latest_provider_original_client_initialized":latest_initialized,
    "original_client_game_gateway_connected":client.get("original_client_local_game_connection_observed",False),
        "original_client_adapter_verified":False,"status_is_a_time_bounded_observation":True}
backend_record["latest_native_identity_service_observation"]["original_client_catalog_callback_returned_observed"] = callback_observed
backend_record["latest_native_identity_service_observation"]["original_client_local_zone_address_read_observed"] = zone_addresses_observed
backend_record["latest_native_identity_service_observation"]["original_client_local_account_info_read_observed"] = account_info_observed
backend_record["latest_native_identity_service_observation"]["original_client_local_account_login_callback_returned_observed"] = account_callback_observed
backend_record_path.write_text(json.dumps(backend_record,ensure_ascii=False,indent=2)+"\n",encoding="utf-8")
files = [OUT / name for name in ("README.md","provider.c","build_provider.py","verify_provider.py",
        "verify_event_abi.py","build-record.json","validation.json","event-abi-validation.json",
        "account-type-abi.json","optional-content-abi.json","system-interface-abi.json",
        "expansion-content-abi.json","zone-helper-abi.json","zone-server-abi.json","trace_interface_abi.py",
        "local-account-interface-abi.json","local-account-info-abi.json","trace_local_account_info_abi.py",
        "client-observation.json","startup-control.json","startup-exit-observation.json",
        "resource-exit-diagnostics.json","latest-client-log-observation.json",
        "connection-investigation.json","login-contract-ledger.json","client-callback-locations.json","login-code-analysis.json",
        "client-login-semantics.json",
        "elevated-launch-observation.json","post-test-checks.json")]
files.extend(sorted(OUT.glob("client-observation-*.json")))
files.extend(sorted(OUT.glob("elevated-launch-observation-*.json")))
files.extend(sorted(OUT.glob("client-log-observation-*.json")))
for path in files:
    assert path.suffix in {".md",".c",".py",".json"}
    text = path.read_text(encoding="utf-8")
    if path.suffix == ".py": ast.parse(text)
    if path.suffix == ".json": json.loads(text)
archive = ROOT / "outputs/native-account-provider-source.zip"
with zipfile.ZipFile(archive,"w",compression=zipfile.ZIP_DEFLATED) as package:
    for path in files:
        package.write(path,"native-account-provider/" + path.name)
    abi = ROOT / "outputs/sdk-call-observer/identity-abi.json"
    package.write(abi,"sdk-call-observer/identity-abi.json")
with zipfile.ZipFile(archive) as package:
    assert package.testzip() is None
    assert all(not name.endswith((".dll",".exe",".sqlite3",".etl",".pcapng")) for name in package.namelist())
manifest = {"created_at_utc":now,"archive":archive.name,"archive_sha256":digest(archive),
    "source_files":{path.name:digest(path) for path in files},
    "abi_metadata_sha256":digest(abi),"contains_vendor_binary":False,
    "contains_account_database_or_session":False,"original_lobby_compatible":False}
(OUT / "source-manifest.json").write_text(json.dumps(manifest,indent=2)+"\n",encoding="utf-8")
print(json.dumps({"source_archive":archive.name,"source_files":len(files)+1,
      "original_game_hashes_unchanged":True,"game_or_platform_processes":running,
      "native_identity_service_live":True,"original_lobby_compatible":False},indent=2))
