"""Create a portable, version-specific source/state bundle without vendor files."""

from datetime import datetime, timezone
from pathlib import Path
import hashlib
import json
import sqlite3
import tempfile
import zipfile


ROOT = Path(__file__).resolve().parent.parent
OUT = ROOT / "outputs/transfer"
DB_FILES = (
    "outputs/df-local-server/data/local.sqlite3",
    "work/native-test-account/save.sqlite3",
)
WORK_TOOLS = (
    "local_game_paths.py", "create_local_client_shadow.py",
    "run_native_elevated_trial.py", "verify_local_provider_client.py",
    "client_resource_sampling.py", "recover_interrupted_trial.py",
    "build_migration_bundle.py", "verify_migration_bundle.py",
    "explore_game_item.py", "extract_game_item_catalog.py",
    "extract_operator_avatar_catalog.py", "extract_prop_slot_config.py",
    "extract_prop_slot_catalog.py", "extract_armor_durability_catalog.py",
    "probe_pak_payload_lua.py", "probe_character_asset_rows.py",
    "oodle_payload_reader.py", "lua53_reader.py",
)
EVIDENCE = (
    "character_avatar_tables/1.101.37117.36.10_WindowsNoEditor_37127_P.pak.entry-227.uasset",
    "character_avatar_tables/1.101.37117.36.10_WindowsNoEditor_37127_P.pak.entry-228.uexp",
    "character_avatar_tables/1.101.37117.36.524_WindowsNoEditor_37641_P.pak.entry-115.uasset",
    "character_avatar_tables/1.101.37117.36.524_WindowsNoEditor_37641_P.pak.next_entry",
    "prop_slot_config/PropSlotConfig.uasset", "prop_slot_config/PropSlotConfig.uexp",
    "armor_tables/BodyArmorFunction.entry-48.bin",
    "armor_tables/BodyArmorFunction.entry-49.bin",
)


def digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def files_to_copy() -> list[Path]:
    selected = [ROOT / name for name in (
        "MIGRATION.md", "DATA_PROVENANCE.md", "CURRENT_STATE.md", "PACKAGE_CONTENTS.md",
        "outputs/df-local-server/README.md", "outputs/df-local-server/definitions.json",
        "outputs/df-local-server/requirements-optional.txt", "outputs/df-local-server/demo.py",
        "outputs/df-local-server/open-local-entrance.cmd", "outputs/df-local-server/start.cmd",
        "outputs/df-local-server/local-account.cmd", "outputs/df-local-server/probe-connection.cmd",
        "outputs/df-local-server/character_asset_findings.md",
        "outputs/df-local-server/operator_asset_catalog.md",
        "outputs/df-local-server/operator-roster-repair.md",
        "outputs/df-local-server/lobby-repair-status.md",
        "outputs/df-local-server/mandel-lottery-chain.md",
        "outputs/sdk-call-observer/identity-abi.json",
        "work/sdk-local-provider-stage/rail_api64.dll",
        "work/sdk-local-provider-stage/build-record.json",
    )]
    for subfolder in ("dfserver", "tests", "tools"):
        folder = ROOT / "outputs/df-local-server" / subfolder
        selected.extend(path for path in folder.rglob("*") if path.is_file()
                        and "__pycache__" not in path.parts and path.suffix not in (".pyc", ".log"))
    selected.extend(path for path in (ROOT / "outputs/df-local-server/protocol").iterdir()
                    if path.is_file() and path.suffix in (".json", ".md", ".pb")
                    and path.name not in ("gateway_capture_analysis.json",
                                          "address_activation_evidence.json", "status.json"))
    provider = ROOT / "outputs/native-account-provider"
    selected.extend(path for path in provider.iterdir() if path.is_file()
                    and (path.name in ("provider.c", "build_provider.py", "verify_provider.py",
                                             "verify_event_abi.py", "validation.json", "build-record.json")
                         or path.name.endswith("-abi.json")))
    selected.extend(ROOT / "work" / name for name in WORK_TOOLS)
    selected.extend(ROOT / "work/evidence" / name for name in EVIDENCE)
    by_name = {path.relative_to(ROOT).as_posix(): path for path in selected}
    for name, path in by_name.items():
        if not path.is_file() or not path.resolve().is_relative_to(ROOT.resolve()):
            raise FileNotFoundError(name)
    return [by_name[name] for name in sorted(by_name)]


def snapshot_database(source: Path, destination: Path) -> None:
    with sqlite3.connect(source) as current, sqlite3.connect(destination) as snapshot:
        current.backup(snapshot)
        if snapshot.execute("PRAGMA integrity_check").fetchone()[0] != "ok":
            raise ValueError(f"Invalid SQLite snapshot: {source.name}")


def main() -> None:
    OUT.mkdir(parents=True, exist_ok=True)
    archive = OUT / "deltaforce-local-transfer-20260929.zip"
    entries = files_to_copy()
    manifest = {"format_version": 1,
                "created_at_utc": datetime.now(timezone.utc).isoformat(),
                "archive_root": "deltaforce-local", "game_directory_default": "../game",
                "shadow_directory_default": "../shadow", "game_included": False,
                "files": {}}
    with tempfile.TemporaryDirectory(prefix="deltaforce-transfer-") as temporary:
        temp = Path(temporary)
        snapshots = {}
        for relative in DB_FILES:
            target = temp / Path(relative).name
            snapshot_database(ROOT / relative, target)
            snapshots[relative] = target
        with zipfile.ZipFile(archive, "w", compression=zipfile.ZIP_DEFLATED,
                             compresslevel=6, allowZip64=True) as output:
            for path in entries + [snapshots[name] for name in DB_FILES]:
                relative = next((name for name, staged in snapshots.items() if staged == path),
                                None) or path.relative_to(ROOT).as_posix()
                if Path(relative).is_absolute() or ".." in Path(relative).parts:
                    raise ValueError(f"Unsafe package entry: {relative}")
                data = path.read_bytes()
                manifest["files"][relative] = {"size": len(data), "sha256": digest(data)}
                output.writestr("deltaforce-local/" + relative, data)
            output.writestr("deltaforce-local/MANIFEST.json",
                            json.dumps(manifest, ensure_ascii=False, indent=2).encode("utf-8") + b"\n")
    with zipfile.ZipFile(archive) as package:
        if package.testzip() is not None:
            raise ValueError("ZIP CRC verification failed")
        if len(package.namelist()) != len(manifest["files"]) + 1:
            raise ValueError("Unexpected ZIP entry count")
    archive_hash = hashlib.sha256(archive.read_bytes()).hexdigest()
    archive.with_suffix(".sha256").write_text(f"{archive_hash}  {archive.name}\n", encoding="ascii")
    print(json.dumps({"archive": str(archive), "sha256": archive_hash,
                      "files": len(manifest["files"]), "size_bytes": archive.stat().st_size},
                     ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
