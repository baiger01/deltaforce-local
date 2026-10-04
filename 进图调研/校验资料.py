"""Verify this public reference snapshot without executing its source files."""
import hashlib
import json
from pathlib import Path

root = Path(__file__).resolve().parent
manifest = json.loads((root / '公开资料清单.json').read_text(encoding='utf-8'))
failures = []
for row in manifest['files']:
    path = (root / row['relative_path']).resolve()
    if not path.is_relative_to(root) or not path.is_file():
        failures.append(row['relative_path'])
        continue
    with path.open('rb') as stream:
        actual = hashlib.file_digest(stream, 'sha256').hexdigest()
    if actual != row['sha256'] or path.stat().st_size != row['size_bytes']:
        failures.append(row['relative_path'])
print(json.dumps({'files': len(manifest['files']), 'ok': not failures,
                  'failures': failures}, ensure_ascii=False))
raise SystemExit(1 if failures else 0)
