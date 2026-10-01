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
parser = argparse.ArgumentParser()
parser.add_argument("--entry", choices=("shipping", "bootstrap"), default="shipping")
parser.add_argument("--wire-identity-probe", action="store_true")
parser.add_argument("--wire-auth-response-probe", action="store_true")
parser.add_argument("--wire-auth-identity-probe", action="store_true")
parser.add_argument("--wire-ready-probe", action="store_true")
parser.add_argument("--wire-ready-identity-probe", action="store_true")
parser.add_argument("--wire-business-login-probe", action="store_true")
parser.add_argument("--wire-business-bootstrap-probe", action="store_true")
parser.add_argument("--observation-seconds", type=int, default=720)
parser.add_argument("--precreate-game-nick", action="store_true")
parser.add_argument("--native-username")
parser.add_argument("--source-game", type=Path)
parser.add_argument("--shadow-game", type=Path)
parser.add_argument("--game-root", type=Path)
parser.add_argument("--worker", action="store_true")
parser.add_argument("--request", type=Path)
args = parser.parse_args()
args.source_game, args.shadow_game = game_paths(args.source_game, args.shadow_game)
if args.game_root is not None:
    args.game_root = project_path(args.game_root, args.source_game)
if not 30 <= args.observation_seconds <= 720:
    parser.error("--observation-seconds must be between 30 and 720")
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

def digest(path):
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()

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
    assert request["observation_seconds"] == args.observation_seconds
    assert request["precreate_game_nick"] == args.precreate_game_nick
    assert request["native_username"] == args.native_username
    assert request["source_game"] == str(args.source_game.resolve())
    assert request["shadow_game"] == str(args.shadow_game.resolve())
    assert request["game_root"] == str((args.game_root or args.source_game).resolve())
    assert request["runner_sha256"] == digest(RUNNER)
    assert request["wrapper_sha256"] == digest(Path(__file__))
    log = args.request.with_suffix(".log")
    os.environ["DF_LOCAL_SOURCE_GAME"] = request["source_game"]
    os.environ["DF_LOCAL_SHADOW_GAME"] = request["shadow_game"]
    if request.get('socket_helper_readonly_evidence'):
        os.environ['DF_LOCAL_SOCKET_EVIDENCE'] = '1'
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
           "observation_seconds":args.observation_seconds,
           "precreate_game_nick":args.precreate_game_nick,
           "native_username":args.native_username,
           "source_game":str(args.source_game.resolve()),
           "shadow_game":str(args.shadow_game.resolve()),
           "game_root":str((args.game_root or args.source_game).resolve()),
           "runner_sha256":digest(RUNNER), "wrapper_sha256":digest(Path(__file__)),
           "normal_windows_uac":True, "authorization_window_operated_by_tool":False,
           "socket_helper_readonly_evidence":os.environ.get('DF_LOCAL_SOCKET_EVIDENCE') == '1'}
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

report = dict(request)
report["request_name"] = request_path.name
if REPORT.exists():
    previous = json.loads(REPORT.read_text(encoding="utf-8"))
    assert previous.get("completed_at_utc"), "An earlier elevated trial has not completed"
    REPORT.with_name("elevated-launch-observation-" + str(time.time_ns()) + ".json").write_text(
        REPORT.read_text(encoding="utf-8"), encoding="utf-8")
REPORT.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
info = ShellInfo(); info.cbSize = C.sizeof(info); info.fMask = 0x140
info.lpVerb = "runas"; info.lpFile = sys.executable
parameters = [str(Path(__file__).resolve()), "--worker", "--entry", args.entry,
              "--request", str(request_path),
              "--source-game", str(args.source_game.resolve()),
              "--shadow-game", str(args.shadow_game.resolve()),
              "--game-root", str((args.game_root or args.source_game).resolve()),
              "--observation-seconds", str(args.observation_seconds)]
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
if args.precreate_game_nick:
    parameters.append("--precreate-game-nick")
if args.native_username:
    parameters.extend(("--native-username", args.native_username))
info.lpParameters = subprocess.list2cmdline(parameters)
info.lpDirectory = str(ROOT); info.nShow = 0
print("Requesting one bounded test through Windows UAC.", flush=True)
success = shell(C.byref(info))
report["shell_execute_succeeded"] = bool(success)
if success and info.hProcess:
    report["helper_pid"] = kernel.GetProcessId(info.hProcess)
    REPORT.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({"helper_pid":report["helper_pid"],"entry":args.entry}), flush=True)
    try:
        while kernel.WaitForSingleObject(info.hProcess, 1000) == 258:
            pass
        exit_code = W.DWORD()
        assert kernel.GetExitCodeProcess(info.hProcess, C.byref(exit_code))
        report["helper_exit_code"] = exit_code.value
    finally:
        kernel.CloseHandle(info.hProcess)
elif not success:
    report["windows_error"] = C.get_last_error()
report["completed_at_utc"] = datetime.now(timezone.utc).isoformat()
REPORT.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
print(json.dumps(report, indent=2), flush=True)
