"""Observe an untouched client start; never alters files or enforcement state."""
from datetime import datetime, timezone
from pathlib import Path
import hashlib
import json
import subprocess
import time
import psutil

ROOT = Path(__file__).resolve().parent.parent
GAME = Path("D:/三角洲/WeGameApps/rail_apps/DeltaForce(2001918)")
ENTRY = GAME / "DeltaForce/Binaries/Win64/DeltaForceClient-Win64-Shipping.exe"
SDK = GAME / "DeltaForce/Binaries/ThirdParty/WeGame/Win64/rail_api64.dll"
NAMES = {"deltaforceclient.exe", "deltaforceclient-win64-shipping.exe", "wegame.exe", "tgp.exe", "tgp_daemon.exe", "wegame_launcher.exe"}
REPORT = ROOT / "outputs/native-account-provider/startup-control.json"

def digest(path):
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()

def snapshot():
    return [p.info for p in psutil.process_iter(["pid", "ppid", "name", "create_time"])
            if (p.info["name"] or "").lower() in NAMES]

assert not snapshot()
assert digest(SDK) == "9d39a0f5af96d56f465060a582e21faf5c11d5cfdd4e221891d81c58cd7f1723"
assert digest(ENTRY) == "4254fbe66585f260f1f9dbfc5e302887842552e7baed8939e023160a5e250be0"
assert not any(SDK.with_name(name).exists() for name in ("df_sdk_original.dll", "df_local_identity_bootstrap.bin", "df_sdk_observer_logpath.txt"))
report = {"started_at_utc":datetime.now(timezone.utc).isoformat(), "game_files_modified":False,
          "arguments":["--rail_no_need_launch_platform", "-ip=127.0.0.1:65010"],
          "samples":[], "scoped_cleanup":[], "sdk_loaded":False, "platform_started":False}
owned = {}
began = time.time()
started = time.monotonic()
child = subprocess.Popen([str(ENTRY), *report["arguments"]], cwd=ENTRY.parent,
                         stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
owned[child.pid] = psutil.Process(child.pid).create_time()
try:
    seen = set()
    while time.monotonic() - started < 45:
        for row in snapshot():
            if row["create_time"] < began - 1 or (row["pid"] not in owned and row["ppid"] not in owned):
                continue
            owned[row["pid"]] = row["create_time"]
            sample = {**row, "elapsed_seconds":round(time.monotonic()-started,2)}
            if row["name"].lower() in NAMES - {"deltaforceclient.exe", "deltaforceclient-win64-shipping.exe"}:
                report["platform_started"] = True
            try:
                process = psutil.Process(row["pid"])
                sample["threads"] = process.num_threads()
                sample["cpu_seconds"] = round(sum(process.cpu_times()[:2]),3)
                sample["loaded_modules"] = sorted({Path(m.path).name.lower() for m in process.memory_maps(grouped=True)})
                if "rail_api64.dll" in sample["loaded_modules"]:
                    report["sdk_loaded"] = True
            except (psutil.AccessDenied, psutil.NoSuchProcess) as error:
                sample["inspection_limit"] = type(error).__name__
            key = (row["pid"],sample.get("threads"),tuple(sample.get("loaded_modules",[])))
            if key not in seen:
                report["samples"].append(sample)
                seen.add(key)
        if report["platform_started"] or report["sdk_loaded"]:
            break
        if child.poll() is not None and not any(p["pid"] in owned for p in snapshot()):
            break
        time.sleep(1.5)
finally:
    report["elapsed_seconds"] = round(time.monotonic()-started,2)
    report["root_exit_code_before_cleanup"] = child.poll()
    for pid, created in reversed(list(owned.items())):
        try:
            process = psutil.Process(pid)
            if abs(process.create_time()-created) > .01:
                continue
            process.terminate()
            try:
                process.wait(timeout=5)
                report["scoped_cleanup"].append({"pid":pid,"exited":True})
            except psutil.TimeoutExpired:
                report["scoped_cleanup"].append({"pid":pid,"exited":False})
        except (psutil.AccessDenied, psutil.NoSuchProcess) as error:
            report["scoped_cleanup"].append({"pid":pid,"result":type(error).__name__})
    report["original_sdk_unchanged"] = digest(SDK) == "9d39a0f5af96d56f465060a582e21faf5c11d5cfdd4e221891d81c58cd7f1723"
    report["remaining_owned_processes"] = [p["pid"] for p in snapshot() if p["pid"] in owned and abs(p["create_time"]-owned[p["pid"]]) < .01]
    REPORT.write_text(json.dumps(report,ensure_ascii=False,indent=2)+"\n",encoding="utf-8")
    print(json.dumps({key:report[key] for key in ("elapsed_seconds","sdk_loaded","platform_started","original_sdk_unchanged","remaining_owned_processes")}),flush=True)
