"""Bounded, passive capture of fresh official DS endpoints through normal UAC.

No game launch, game-file write, process-memory access, traffic redirection or
network request. Pktmon normally uses a dummy loopback filter until a fresh DS
endpoint appears. An opt-in prearm mode scopes UDP to up to six recently logged
DS hosts before the next connection, avoiding late filter installation.
Private ETL/PCAP files stay local. Reports never include tickets or URL values.
"""
from __future__ import annotations

import argparse
import codecs
import ctypes as C
from ctypes import wintypes as W
from datetime import datetime, timezone
import hashlib
import importlib.util
import ipaddress
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import time

ROOT = Path(__file__).resolve().parent.parent
STATUS = ROOT / "work/official-ds-capture-status.json"
CAPTURE_ROOT = ROOT / "work/official-ds-captures"
SOURCE_SHA = "4254fbe66585f260f1f9dbfc5e302887842552e7baed8939e023160a5e250be0"
SDK_SHA = "9d39a0f5af96d56f465060a582e21faf5c11d5cfdd4e221891d81c58cd7f1723"
XOR_TABLE = bytes(value ^ 0x5c for value in range(256))
STAGES = {
    "start_connect_requested": "real start connect ds!!!",
    "physics_ready": "StartLevelPhysicsLoad, PhysicsReady=1",
    "streaming_ready": "bLevelStreamingReady!",
    "connection_url_built": "[GetLevelUrlAsync] url = ",
    "net_driver_initialized": "NetDriver RecvMulti is not yet supported",
    "post_connect": "UDFMIrisEnterSubsystem::OnPostConnectDS,",
    "all_players_ready": "OnDSNotifyAllPlayerReady",
    "entry_timeout": "OnTimeout: flow SeamlessFlow_TravelToDS timeout",
}


def utc_now():
    return datetime.now(timezone.utc).isoformat()


def digest(path):
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def save(path, value):
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_text(json.dumps(value, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    temporary.replace(path)


def endpoint_from_line(line):
    # Ordinary DNS, lobby URLs and even URL query values cannot arm a filter.
    if "LuaSMatch:" not in line:
        return None
    match = None
    if "[GetLevelUrlAsync] url = " in line:
        part = line.split("[GetLevelUrlAsync] url = ", 1)[1].lstrip(", ")
        match = re.match(r"([0-9.]+):(\d+)(?:\?|\s|$)", part)
    elif "[OnDnsAsyncResloved]" in line and "ip and port:" in line:
        match = re.search(r"ip and port:\s*,?\s*([0-9.]+)\s*,\s*(\d+)\b", line)
    if not match:
        return None
    try:
        address = ipaddress.IPv4Address(match[1])
        port = int(match[2])
    except (ValueError, ipaddress.AddressValueError):
        return None
    if not address.is_global or address.is_multicast or not 1024 <= port <= 65535:
        return None
    return str(address), port


def safe_line_evidence(line):
    stamp = re.match(r"\[([^\]]+)\]", line)
    result = {"observed_at_utc": utc_now(), "client_wall_time": stamp[1] if stamp else None}
    names = [name for name, marker in STAGES.items() if marker in line]
    if names:
        result["stage_names"] = names
    if "[GetLevelUrlAsync] url = " in line:
        result["url_parameter_lengths"] = {
            name: len(value) for name, value in re.findall(r"\?([A-Za-z0-9_]+)=([^?\s]*)", line)
        }
    return result if len(result) > 2 else None


def recent_ds_hosts(path, *, max_hosts=6, max_bytes=32 * 1024 * 1024):
    """Read only DS host names from a bounded tail; never return query values."""
    if not 1 <= max_hosts <= 6 or not 1 <= max_bytes <= 32 * 1024 * 1024:
        raise ValueError("Invalid recent DS log bound")
    with path.open("rb") as stream:
        size = os.fstat(stream.fileno()).st_size
        offset = max(0, size - max_bytes)
        stream.seek(offset)
        raw = stream.read(max_bytes)
    text = raw.removeprefix(b"\xef\xbb\xbf").translate(XOR_TABLE).decode("utf-8", "replace")
    lines = text.splitlines()
    if offset:
        lines = lines[1:]  # A truncated first line must not arm any host.
    hosts = []
    for line in reversed(lines):
        endpoint = endpoint_from_line(line)
        if endpoint and endpoint[0] not in hosts:
            hosts.append(endpoint[0])
            if len(hosts) >= max_hosts:
                break
    return hosts, {"source_relative_to_game_root": "DeltaForce/Saved/Logs/DeltaForce.log",
                   "inspected_bytes": len(raw), "tail_sha256": hashlib.sha256(raw).hexdigest(),
                   "source_offset": offset, "query_values_exported": False}


class FreshLogTail:
    def __init__(self, path):
        self.path = path
        self.offset = path.stat().st_size if path.exists() else 0
        self.identity = path.stat().st_ino if path.exists() else None
        with path.open("rb") if path.exists() else _empty_stream() as stream:
            self.prefix = stream.read(64)
        self.decoder = codecs.getincrementaldecoder("utf-8")("replace")
        self.pending = ""

    def poll(self):
        try:
            stat = self.path.stat()
            with self.path.open("rb") as stream:
                prefix = stream.read(64)
                changed = (stat.st_ino != self.identity or stat.st_size < self.offset or
                           (len(self.prefix) == 64 and len(prefix) == 64 and prefix != self.prefix))
                if changed:
                    self.offset = 0
                    self.decoder.reset()
                    self.pending = ""
                self.identity, self.prefix = stat.st_ino, prefix
                stream.seek(self.offset)
                raw = stream.read(1024 * 1024)
        except FileNotFoundError:
            return []
        if not raw:
            return []
        start = self.offset
        self.offset += len(raw)
        if start == 0:
            raw = raw.removeprefix(b"\xef\xbb\xbf")
        decoded = self.pending + self.decoder.decode(raw.translate(XOR_TABLE))
        lines = decoded.split("\n")
        self.pending = lines.pop()
        return [line.rstrip("\r") for line in lines]


def _empty_stream():
    import io
    return io.BytesIO()


def capture_utilities():
    path = ROOT / "outputs/df-local-server/tools/capture_gateway.py"
    spec = importlib.util.spec_from_file_location("official_capture_utilities", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def verified_pids(executable):
    import psutil
    expected = os.path.normcase(str(executable.resolve()))
    found = []
    for process in psutil.process_iter(["pid", "name", "exe"]):
        if (process.info["name"] or "").lower() != executable.name.lower():
            continue
        path = process.info["exe"]
        if path and os.path.normcase(str(Path(path).resolve())) == expected:
            found.append(process.info["pid"])
    return sorted(found)


def owned_capture(util, pktmon, etl, names):
    status = util.run([pktmon, "status"]).stdout
    match = re.search(r"(?im)^\s*(?:日志文件|Log\s+file)\s*:\s*(.+\.etl)\s*$", status)
    if not match or Path(match[1].strip()).resolve() != etl.resolve():
        raise RuntimeError("Capture session changed; no other session was stopped")
    filters = util.run([pktmon, "filter", "list"]).stdout
    current = set(re.findall(r"(?m)^\s*\d+\s+(\S+)", filters))
    if current != set(names):
        raise RuntimeError("Capture filters changed; other filters were left untouched")


def worker(request_path):
    if not C.windll.shell32.IsUserAnAdmin():
        raise RuntimeError("Windows capture authorization was not granted")
    if request_path.parent.resolve() != CAPTURE_ROOT.resolve():
        raise ValueError("Request must be inside this capture directory")
    request = json.loads(request_path.read_text(encoding="utf-8"))
    if request["helper_sha256"] != digest(Path(__file__)):
        raise ValueError("Capture helper changed after preparation")
    game_root = Path(request["game_root"])
    executable = game_root / "DeltaForce/Binaries/Win64/DeltaForceClient-Win64-Shipping.exe"
    sdk = game_root / "DeltaForce/Binaries/ThirdParty/WeGame/Win64/rail_api64.dll"
    if digest(executable) != SOURCE_SHA or digest(sdk) != SDK_SHA:
        raise ValueError("Original installed client version was not verified")
    folder = request_path.with_suffix("")
    folder.mkdir()
    etl, pcap = folder / "official-ds.etl", folder / "official-ds.pcapng"
    log = FreshLogTail(game_root / "DeltaForce/Saved/Logs/DeltaForce.log")
    report = {"kind": "passive_official_ds_capture", "helper_pid": os.getpid(),
              "started_at_utc": utc_now(), "status": "preflight", "game_modified": False,
              "process_memory_read": False, "network_requests_sent": False,
              "original_client_verified": True, "capture_export_succeeded": False,
              "packet_capture_started": False, "record_complete": False,
              "request_name": request_path.name, "report_path": str(folder / "report.json"),
              "requested_wait_seconds": request["wait_seconds"],
              "requested_ds_capture_seconds": request["capture_seconds"],
              "matched_endpoints": [], "stages": [], "verified_official_pids": []}

    def update():
        report["updated_at_utc"] = utc_now()
        save(folder / "report.json", report)
        save(STATUS, report)

    util = capture_utilities()
    pktmon = str(Path(os.environ["SystemRoot"]) / "System32/pktmon.exe")
    names, started, first_endpoint, ready_at = [], False, None, None
    seen_evidence = set()
    update()
    try:
        prearmed_hosts = []
        if request.get("prearm_recent_ds"):
            if not verified_pids(executable):
                raise RuntimeError("Prearming requires the verified original game to be running")
            prearmed_hosts, provenance = recent_ds_hosts(
                game_root / "DeltaForce/Saved/Logs/DeltaForce.log")
            if not prearmed_hosts:
                raise RuntimeError("No recent official DS hosts were found; capture was not broadened")
            report.update(prearmed_ds_hosts=prearmed_hosts, prearm_log_evidence=provenance,
                          prearm_scope="UDP only, recent DS hosts; ports may vary")
        util.ensure_pktmon_idle(util.run([pktmon, "status"]).stdout)
        filters = util.run([pktmon, "filter", "list"]).stdout
        if re.search(r"(?m)^\s*[1-9][0-9]*\s+", filters):
            raise RuntimeError("Existing Pktmon filters were left untouched")
        if prearmed_hosts:
            for host in prearmed_hosts:
                name = f"DFOfficialDS_{os.getpid()}_{len(names)}"
                util.run([pktmon, "filter", "add", name, "-i", host, "-t", "UDP"])
                names.append(name)
        else:
            dummy = f"DFOfficialDS_{os.getpid()}_0"
            util.run([pktmon, "filter", "add", dummy, "-i", "127.0.0.1", "-p", "9", "-t", "UDP"])
            names.append(dummy)
        util.run([pktmon, "start", "--capture", "--comp", "nics", "--pkt-size", "0",
                  "--file-name", str(etl), "--file-size", "64", "--log-mode", "circular"])
        started = True
        report.update(status="armed_waiting_for_official_game", packet_capture_started=True,
                      filters_armed_at_utc=utc_now())
        update()
        start = time.monotonic()
        next_process_check, next_report = 0, 0
        while True:
            now = time.monotonic()
            if now >= next_process_check:
                report["verified_official_pids"] = verified_pids(executable)
                next_process_check = now + 0.5
                if first_endpoint is None:
                    report["status"] = ("waiting_for_match" if report["verified_official_pids"]
                                        else "armed_waiting_for_official_game")
            lines = log.poll()
            if report["verified_official_pids"]:
                for line in lines:
                    evidence = safe_line_evidence(line)
                    if evidence:
                        key = (evidence.get("client_wall_time"), tuple(evidence.get("stage_names", [])))
                        if key not in seen_evidence and len(report["stages"]) < 300:
                            report["stages"].append(evidence)
                            seen_evidence.add(key)
                        if "start_connect_requested" in evidence.get("stage_names", []):
                            ready_at = None
                        if first_endpoint is not None and "all_players_ready" in evidence.get("stage_names", []):
                            ready_at = now
                    endpoint = endpoint_from_line(line)
                    if endpoint and list(endpoint) not in report["matched_endpoints"]:
                        already_armed = endpoint[0] in prearmed_hosts
                        if not already_armed:
                            if len(names) >= 12:
                                raise RuntimeError("Endpoint bound exceeded; stopping this capture")
                            name = f"DFOfficialDS_{os.getpid()}_{len(names)}"
                            util.run([pktmon, "filter", "add", name, "-i", endpoint[0],
                                      "-p", str(endpoint[1]), "-t", "UDP"])
                            names.append(name)
                        report["matched_endpoints"].append(list(endpoint))
                        report.setdefault("endpoint_filter_coverage", []).append(
                            {"endpoint": list(endpoint), "prearmed_before_fresh_connection": already_armed,
                             "observed_at_utc": utc_now()})
                        if not already_armed:
                            report.setdefault("first_endpoint_filter_added_at_utc", utc_now())
                        first_endpoint = first_endpoint or time.monotonic()
                        report["status"] = "capturing_ds_udp"
                        update()
            if first_endpoint is None and now - start >= request["wait_seconds"]:
                report["stop_reason"] = "no_fresh_official_ds_endpoint_before_deadline"
                break
            if first_endpoint is not None and (now - first_endpoint >= request["capture_seconds"] or
                                              ready_at is not None and now - ready_at >= 10):
                report["stop_reason"] = "ds_capture_window_complete"
                break
            if now >= next_report:
                report["elapsed_seconds"] = round(now - start, 2)
                update()
                next_report = now + 1
            time.sleep(0.05)
    except (OSError, RuntimeError, ValueError) as error:
        report["error"] = str(error)
        report["status"] = "failed"
    finally:
        if started:
            try:
                owned_capture(util, pktmon, etl, names)
                util.run([pktmon, "stop"])
                util.ensure_pktmon_idle(util.run([pktmon, "status"]).stdout)
                report["pktmon_stop_confirmed"] = True
                for name in reversed(names):
                    util.run([pktmon, "filter", "remove", name])
                report["scoped_filters_removed"] = len(names)
                util.run([pktmon, "etl2pcap", str(etl), "--out", str(pcap)])
                report["capture_export_succeeded"] = True
                report["pcapng_path"] = str(pcap)
                report["pcapng_sha256"] = digest(pcap)
                report["pcapng_bytes"] = pcap.stat().st_size
            except (OSError, RuntimeError, ValueError) as error:
                report["cleanup_error"] = str(error)
                report["status"] = "cleanup_needs_attention"
        elif names:
            for name in reversed(names):
                util.run([pktmon, "filter", "remove", name], check=False)
        report["finished_at_utc"] = utc_now()
        report["record_complete"] = True
        if report["status"] not in ("failed", "cleanup_needs_attention"):
            report["status"] = "capture_exported"
        update()


def launch(args):
    CAPTURE_ROOT.mkdir(parents=True, exist_ok=True)
    previous = json.loads(STATUS.read_text(encoding="utf-8")) if STATUS.exists() else None
    if previous and not previous.get("record_complete"):
        raise RuntimeError("An earlier capture is not complete; it was left untouched")
    request = {"requested_at_utc": utc_now(), "game_root": str(args.game_root.resolve()),
               "helper_sha256": digest(Path(__file__)), "wait_seconds": args.wait_seconds,
               "capture_seconds": args.capture_seconds, "prearm_recent_ds": args.prearm_recent_ds}
    path = CAPTURE_ROOT / (str(time.time_ns()) + ".json")
    save(path, request)
    save(STATUS, {"status": "awaiting_windows_authorization", "request_name": path.name,
                  "requested_at_utc": request["requested_at_utc"], "record_complete": False})

    class ShellInfo(C.Structure):
        _fields_ = [("cbSize", W.DWORD), ("fMask", W.ULONG), ("hwnd", W.HWND),
                    ("lpVerb", W.LPCWSTR), ("lpFile", W.LPCWSTR), ("lpParameters", W.LPCWSTR),
                    ("lpDirectory", W.LPCWSTR), ("nShow", C.c_int), ("hInstApp", W.HINSTANCE),
                    ("lpIDList", C.c_void_p), ("lpClass", W.LPCWSTR), ("hkeyClass", W.HKEY),
                    ("dwHotKey", W.DWORD), ("hIcon", W.HANDLE), ("hProcess", W.HANDLE)]

    shell = C.WinDLL("shell32", use_last_error=True).ShellExecuteExW
    shell.argtypes, shell.restype = [C.POINTER(ShellInfo)], W.BOOL
    kernel = C.WinDLL("kernel32", use_last_error=True)
    kernel.WaitForSingleObject.argtypes, kernel.WaitForSingleObject.restype = [W.HANDLE, W.DWORD], W.DWORD
    kernel.GetProcessId.argtypes, kernel.GetProcessId.restype = [W.HANDLE], W.DWORD
    kernel.GetExitCodeProcess.argtypes = [W.HANDLE, C.POINTER(W.DWORD)]
    kernel.GetExitCodeProcess.restype = W.BOOL
    kernel.CloseHandle.argtypes = [W.HANDLE]
    info = ShellInfo()
    info.cbSize, info.fMask = C.sizeof(info), 0x140
    info.lpVerb, info.lpFile = "runas", sys.executable
    info.lpParameters = subprocess.list2cmdline([str(Path(__file__).resolve()), "--worker", str(path)])
    info.lpDirectory, info.nShow = str(ROOT), 0
    print("Requesting passive DS capture through Windows UAC", flush=True)
    if not shell(C.byref(info)):
        save(STATUS, {"status": "authorization_failed", "windows_error": C.get_last_error(),
                      "request_name": path.name, "record_complete": True})
        return 1
    if not info.hProcess:
        raise RuntimeError("Capture helper process handle unavailable")
    print(json.dumps({"helper_pid": kernel.GetProcessId(info.hProcess)}), flush=True)
    try:
        while kernel.WaitForSingleObject(info.hProcess, 1000) == 258:
            pass
        exit_code = W.DWORD()
        if not kernel.GetExitCodeProcess(info.hProcess, C.byref(exit_code)):
            raise C.WinError(C.get_last_error())
    finally:
        kernel.CloseHandle(info.hProcess)
    report = json.loads(STATUS.read_text(encoding="utf-8"))
    if not report.get("record_complete"):
        report.update(status="helper_failed", helper_exit_code=exit_code.value, record_complete=True)
        save(STATUS, report)
    print(json.dumps({key: report.get(key) for key in
                      ("status", "record_complete", "capture_export_succeeded", "pktmon_stop_confirmed")}), flush=True)
    return 0 if report.get("capture_export_succeeded") else 1


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--game-root", type=Path)
    parser.add_argument("--wait-seconds", type=int, default=1200)
    parser.add_argument("--capture-seconds", type=int, default=75)
    parser.add_argument("--prearm-recent-ds", action="store_true",
                        help="Prearm UDP filters for up to six recent DS hosts before the next match")
    parser.add_argument("--worker", type=Path)
    args = parser.parse_args()
    if args.worker:
        worker(args.worker.resolve())
        return 0
    if args.game_root is None or not 60 <= args.wait_seconds <= 1800 or not 15 <= args.capture_seconds <= 180:
        parser.error("Provide game root, wait 60..1800 and capture 15..180 seconds")
    return launch(args)


if __name__ == "__main__":
    raise SystemExit(main())
