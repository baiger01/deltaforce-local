"""Diagnostic only: follow the shadow client log and keep weapon/switch/entry lines.

Reads the XOR-0x5C encoded DeltaForce.log the same way as watch_client_log.py,
writes a focused trace, and prints a per-weapon summary at the end. It never
writes to the game, the account database, or any process.
"""
import argparse
from collections import Counter, defaultdict
import json
from pathlib import Path
import re
import sys
import time

# Weapon lifecycle, switching, first-person view, possession, dropped RPCs,
# match entry and Lua errors. Noise (data tables, pak mounts) is excluded.
KEEP = re.compile(
    r"LogWeapon(Manager|Life|Mesh|MeshProxy|Appearance|Anim|PAnim|State|FSM|Replicate|Hud|Zoom)\b"
    r"|EmptyHand|WeaponMelee|SwitchToTargetWeapon|AddSwitchFrame|OnAddFrame|RecordFppClientWeapon"
    r"|DoRepWeaponList|OnAddWeapon|AddWeaponDesc|Active Weapon|Switch to Weapon|is ignored as"
    r"|No owning connection|absorbing remote function|ServerSet\w+"
    r"|OnRep_Pawn|AcknowledgePossession|OnUnPossess|ClientRestart|SwitchToDSClientPlayer"
    r"|SerializeNewActor\|.*(Weapon|EmptyHand|Character|PlayerController)"
    r"|WaitingConnectDS|TravelToDS|OnPostConnectDS|ConnectionTimeout|NetworkFailure|ConnectionLost"
    r"|LUA:ERROR|stack traceback|HudManager is null|Character Owner is different"
    r"|ReqSolReady|StartReconnectingNtf|_OnRelayConnected",
)
NOISE = re.compile(r"GameCoreDataTable|LogPakFile|DataTableSystemManager|LogMetaRuntime|LogMetaStatistics")
WEAPON = re.compile(r"\[(?:Client|Standalone)\|[^|\]]*\|(\d+)\|(Fpp|Tpp|None)\][^{]*\{Guid: (\d+), Id: (\d+)"
                    r"[^}]*WeaponName: ([A-Za-z0-9_]+)")
COLLAPSE = re.compile(r"HudManager is null|Character Owner is different")


def follow(source, target, duration_seconds, *, stop_file=None):
    target.parent.mkdir(parents=True, exist_ok=True)
    identity, position, pending = None, 0, b""
    deadline = time.monotonic() + duration_seconds
    counts, weapons, collapsed = Counter(), defaultdict(set), Counter()
    with target.open("w", encoding="utf-8") as output:
        def emit(raw):
            line = raw.decode("utf-8", "replace").rstrip("\r")
            if NOISE.search(line) or not KEEP.search(line):
                return
            for match in WEAPON.finditer(line):
                identity_id, view, guid, item_id, name = match.groups()
                weapons[(identity_id, guid, item_id, name.rsplit("_C_", 1)[0])].add(view)
            key = COLLAPSE.search(line)
            if key:
                collapsed[key.group(0)] += 1
                if collapsed[key.group(0)] > 3:
                    return
            for token in ("AddSwitchFrame", "can switch weapon check failed", "No owning connection",
                          "absorbing remote function", "LUA:ERROR", "RecordFppClientWeapon",
                          "OP_Start", "OP_ActivatePending", "OnRep_Pawn", "AcknowledgePossession"):
                if token in line:
                    counts[token] += 1
            output.write(line[:900] + "\n")
            output.flush()

        while time.monotonic() < deadline and not (stop_file and stop_file.exists()):
            try:
                stat = source.stat()
            except FileNotFoundError:
                stat = None
            if stat is not None:
                current = (stat.st_dev, stat.st_ino, stat.st_ctime_ns)
                if current != identity or stat.st_size < position:
                    identity, position, pending = current, 0, b""
                with source.open("rb") as stream:
                    stream.seek(position)
                    encoded = stream.read()
                    position = stream.tell()
                if position == len(encoded) and encoded.startswith(b"\xef\xbb\xbf"):
                    encoded = encoded[3:]
                pending += bytes(value ^ 0x5C if value not in (10, 13) else value for value in encoded)
                *complete, pending = pending.split(b"\n")
                for raw in complete:
                    emit(raw)
            time.sleep(1)
        if pending:
            emit(pending)
    summary = {
        "kind": "weapon_switch_trace_summary",
        "diagnostic_only": True,
        "trace": str(target),
        "event_counts": dict(counts),
        "collapsed_repeats": dict(collapsed),
        "weapons": [dict(identity=i, guid=g, item_id=t, name=n, views=sorted(v))
                    for (i, g, t, n), v in sorted(weapons.items())],
    }
    target.with_suffix(".summary.json").write_text(
        json.dumps(summary, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    return summary


def main():
    sys.stdout.reconfigure(encoding="utf-8", errors="backslashreplace")
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--duration-seconds", type=int, default=1860)
    parser.add_argument("--stop-file", type=Path)
    args = parser.parse_args()
    print(json.dumps(follow(args.source, args.output, args.duration_seconds,
                            stop_file=args.stop_file), ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
