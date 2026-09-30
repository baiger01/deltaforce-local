"""Verify the contents of an extracted deltaforce-local transfer bundle."""

from pathlib import Path
import argparse
import hashlib
import json
import sqlite3


def digest(path: Path) -> str:
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def verify(root: Path) -> dict:
    root = root.resolve()
    manifest = json.loads((root / "MANIFEST.json").read_text(encoding="utf-8"))
    if manifest.get("archive_root") != "deltaforce-local":
        raise ValueError("Unexpected archive root")
    files = manifest["files"]
    for relative, expected in files.items():
        if Path(relative).is_absolute() or "\\" in relative or ".." in Path(relative).parts:
            raise ValueError(f"Unsafe manifest path: {relative}")
        target = (root / relative).resolve()
        if not target.is_relative_to(root) or not target.is_file():
            raise FileNotFoundError(relative)
        if target.stat().st_size != expected["size"] or digest(target) != expected["sha256"]:
            raise ValueError(f"File changed: {relative}")
    databases = (
        "outputs/df-local-server/data/local.sqlite3",
        "work/native-test-account/save.sqlite3",
    )
    for relative in databases:
        uri = (root / relative).as_uri() + "?mode=ro"
        with sqlite3.connect(uri, uri=True) as connection:
            if connection.execute("PRAGMA integrity_check").fetchone()[0] != "ok":
                raise ValueError(f"SQLite integrity check failed: {relative}")
    return {"files_verified": len(files), "databases_verified": len(databases),
            "archive_root": manifest["archive_root"], "status": "ok"}


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("root", type=Path, nargs="?", default=Path(__file__).resolve().parent.parent)
    print(json.dumps(verify(parser.parse_args().root), ensure_ascii=False, indent=2))
