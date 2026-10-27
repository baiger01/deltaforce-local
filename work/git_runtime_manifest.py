"""Collect and verify Git handoff dependencies without publishing account state."""
import argparse
import hashlib
import json
from pathlib import Path, PurePosixPath
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
MANIFEST = 'work/git-runtime-manifest.json'
PRIVATE_PARTS = {'native-test-account', 'data', '__pycache__', '.git', '.venv'}
PRIVATE_SUFFIXES = {'.sqlite', '.sqlite3', '.db', '.log', '.jsonl', '.pem', '.key', '.dll', '.exe', '.pyc'}


def relative_file(root, name):
    path = PurePosixPath(name)
    if (not isinstance(name, str) or path.is_absolute() or ':' in name or '\\' in name or
            any(part in ('', '.', '..') for part in name.split('/')) or
            any(part in PRIVATE_PARTS for part in path.parts) or path.suffix in PRIVATE_SUFFIXES or
            path.name == '.env' or path.name.startswith('.env.')):
        raise ValueError('Only project-relative non-account handoff files are allowed')
    target = (root/name).resolve(strict=True)
    if not target.is_relative_to(root.resolve()) or not target.is_file():
        raise ValueError('Handoff file escapes the repository')
    return target


def make_manifest(root, names):
    root = Path(root).resolve(strict=True)
    files = {}
    for name in sorted(set(names)):
        target = relative_file(root, name)
        with target.open('rb') as stream:
            digest = hashlib.file_digest(stream, 'sha256').hexdigest()
        files[name] = dict(bytes=target.stat().st_size, sha256=digest)
    return dict(kind='git_runtime_and_research_dependency_manifest', format_version=1,
        files=files, vendor_installation_included=False, account_databases_included=False,
        executable_provider_must_be_built_on_destination=True)


def verify(root, report):
    if report.get('kind') != 'git_runtime_and_research_dependency_manifest':
        raise ValueError('Unexpected handoff manifest')
    root = Path(root).resolve(strict=True)
    total = 0
    for name, expected in report['files'].items():
        target = relative_file(root, name)
        with target.open('rb') as stream:
            digest = hashlib.file_digest(stream, 'sha256').hexdigest()
        if target.stat().st_size != expected['bytes'] or digest != expected['sha256']:
            raise ValueError('Handoff SHA256 mismatch: '+name)
        total += expected['bytes']
    return dict(files_verified=len(report['files']), bytes_verified=total)


def collect_dependency_paths():
    opened = set()

    def audit(event, arguments):
        if event != 'open' or not isinstance(arguments[0], (str, bytes)):
            return
        try:
            target = Path(arguments[0]).resolve()
        except (OSError, TypeError, ValueError):
            return
        if target.is_relative_to(ROOT) and target.is_file() and '__pycache__' not in target.parts:
            opened.add(target.relative_to(ROOT).as_posix())

    sys.addaudithook(audit)
    sys.path[:0] = [str(ROOT/'work'), str(ROOT/'outputs/df-local-server')]
    from updated_map_bootstrap import load_plan
    current = load_plan()
    opened.update(current.sources)
    from portable_map_bootstrap import load_plan as historical_plan
    historical = historical_plan(ROOT, ROOT/'outputs/df-local-server/protocol/portable-map-spawn/profile-carried-inventory.json')
    opened.update(historical.sources)
    from updated_transport_observation import source_pins
    from local_game_paths import game_paths
    opened.update(source_pins(control_profile=ROOT/'outputs/df-local-server/protocol/native_ds_control_profile_79fb7b10.json',
                             shadow=game_paths()[1]))
    from observe_updated_client_metadata import source_pins as metadata_pins
    opened.update(metadata_pins())
    # Preserve both observed executable-code inputs used by offline source research.
    for capture in ('1792259162856698600', '1792785456045583200'):
        folder = ROOT/'work/native-code-cache'/capture
        opened.update(p.relative_to(ROOT).as_posix() for p in folder.iterdir()
                      if p.is_file() and (p.name == 'manifest.json' or p.suffix == '.code'))
    for pattern in ('research_updated*.json', 'evidence/updated*.json'):
        opened.update(p.relative_to(ROOT).as_posix() for p in (ROOT/'work').glob(pattern) if p.is_file())
    opened.add('work/git_runtime_manifest.py')
    return opened - {MANIFEST}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    modes = parser.add_mutually_exclusive_group(required=True)
    modes.add_argument('--write', action='store_true')
    modes.add_argument('--verify', action='store_true')
    modes.add_argument('--stage', action='store_true')
    args = parser.parse_args()
    target = ROOT/MANIFEST
    if args.write:
        report = make_manifest(ROOT, collect_dependency_paths())
        target.write_text(json.dumps(report, sort_keys=True, indent=2)+'\n', encoding='ascii')
    else:
        report = json.loads(target.read_bytes())
    result = verify(ROOT, report)
    if args.stage:
        paths = [*report['files'], MANIFEST]
        subprocess.run(['git', 'add', '-f', '--pathspec-from-file=-', '--pathspec-file-nul'],
            input=b'\0'.join(name.encode('utf-8') for name in paths)+b'\0', cwd=ROOT, check=True)
    print(json.dumps(dict(result, manifest=MANIFEST, staged=args.stage)))


if __name__ == '__main__':
    main()
