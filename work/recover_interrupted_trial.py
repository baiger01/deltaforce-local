"""Restore the verified original SDK after an interrupted native trial.

This only acts when the original backup and installed test provider both match
their recorded SHA-256 hashes and no game process is running.
"""

import argparse
import hashlib
import json
import os
from pathlib import Path
from datetime import datetime, timezone

import psutil


ORIGINAL_SHA256 = "9d39a0f5af96d56f465060a582e21faf5c11d5cfdd4e221891d81c58cd7f1723"
GAME_NAMES = {"deltaforceclient.exe", "deltaforceclient-win64-shipping.exe"}
SDK_RELATIVE = Path("DeltaForce/Binaries/ThirdParty/WeGame/Win64/rail_api64.dll")


def sha256(path):
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--game-root", type=Path, required=True)
    parser.add_argument("--test-root", type=Path, required=True)
    parser.add_argument("--provider-dll", type=Path, required=True)
    parser.add_argument("--project-root", type=Path)
    args = parser.parse_args()

    live = [(p.pid, p.info["name"]) for p in psutil.process_iter(["name"])
            if (p.info["name"] or "").lower() in GAME_NAMES]
    if live:
        raise RuntimeError(f"Game still running: {live}")

    sdk = (args.game_root.resolve() / SDK_RELATIVE)
    backup = sdk.with_name("df_sdk_original.dll")
    config = sdk.with_name("df_sdk_observer_logpath.txt")
    bootstrap = sdk.with_name("df_local_identity_bootstrap.bin")
    test_root = args.test_root.resolve()
    provider = args.provider_dll.resolve()
    if not sdk.is_file() or not provider.is_file():
        raise RuntimeError("SDK or known test provider is missing")
    if backup.is_file():
        if sha256(backup) != ORIGINAL_SHA256 or sha256(sdk) != sha256(provider):
            raise RuntimeError("SDK hashes do not match the recorded native trial")
        if config.is_file() and config.read_text(encoding="utf-8") != str(test_root / "events.jsonl") + "\n":
            raise RuntimeError("Observer config belongs to another trial")
        if not bootstrap.is_file() or bootstrap.stat().st_size != 55:
            raise RuntimeError("Native trial bootstrap is missing or unexpected")
        os.replace(backup, sdk)
        if sha256(sdk) != ORIGINAL_SHA256:
            raise RuntimeError("Original SDK replacement did not verify")
        config.unlink(missing_ok=True)
        bootstrap.unlink()
    elif sha256(sdk) != ORIGINAL_SHA256 or config.exists() or bootstrap.exists():
        raise RuntimeError("The original SDK is not cleanly restored")

    if args.project_root:
        root = args.project_root.resolve()
        client_path = root / "outputs/native-account-provider/client-observation.json"
        elevated_path = root / "outputs/native-account-provider/elevated-launch-observation.json"
        client = json.loads(client_path.read_text(encoding="utf-8"))
        elevated = json.loads(elevated_path.read_text(encoding="utf-8"))
        if root / client.get("private_runtime_code_sample_directory", "") != test_root:
            raise RuntimeError("Client report belongs to another native trial")
        helper_pid = elevated.get("helper_pid")
        if helper_pid and psutil.pid_exists(helper_pid):
            raise RuntimeError("Elevated trial helper is still running")
        timestamp = datetime.now(timezone.utc).isoformat()
        client.update(original_sdk_restored=True, record_complete=True,
                      observation_interrupted=True, recovered_after_interruption_at_utc=timestamp)
        elevated.update(completed_at_utc=timestamp, helper_process_exited_without_report=True,
                        original_sdk_restored_by_recovery=True)
        client_path.write_text(json.dumps(client, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
        elevated_path.write_text(json.dumps(elevated, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
        print("interrupted_reports_marked=true")
    print("original_sdk_restored=true")
    print("trial_sidecars_removed=true")


if __name__ == "__main__":
    main()
