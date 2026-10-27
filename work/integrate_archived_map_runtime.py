"""Preview and explicitly apply the retired map runtime to the canonical layout."""
import argparse
import ast
from collections import Counter
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import tempfile
import zipfile

import reorganize_server_packages as organization

ROOT = Path(__file__).resolve().parent.parent
OLD = ROOT.parent / '_archive/deltaforce-map-appearance-20261022/files'
SERVER = 'outputs/df-local-server/'
PACKAGE = SERVER + 'dfserver/'
BASE = '933aa3ca0f8392b76827012684ed4d659f10433c'
OUT = ROOT / 'work/evidence/map-runtime-integration-20261022'
SEEDS = ('work/portable_map_bootstrap.py', 'work/verify_local_provider_client.py',
         'work/run_native_elevated_trial.py', PACKAGE + 'game_server_probe.py')
SHARED_WORK = {'native_actor_bootstrap', 'export_native_replication_metadata',
               'native_metadata_objects', 'snapshot_native_image_code',
               'verify_local_provider_client', 'run_native_elevated_trial'}


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def imports(relative):
    tree = ast.parse((OLD / relative).read_text(encoding='utf-8-sig'))
    names = []
    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom):
            name = node.module or ''
            if node.level == 1 and relative.startswith(PACKAGE):
                name = 'dfserver.' + name
            names.append(name)
            if name == 'dfserver':
                names.extend('dfserver.' + alias.name for alias in node.names)
        elif isinstance(node, ast.Import):
            names.extend(alias.name for alias in node.names)
    for name in names:
        parts = name.split('.')
        if len(parts) > 1 and parts[0] == 'dfserver':
            nested = SERVER + name.replace('.', '/') + '.py'
            if (OLD / nested).is_file():
                yield nested
            else:
                yield PACKAGE + parts[1] + '.py'
        elif (OLD / 'work' / (parts[0] + '.py')).is_file():
            yield 'work/' + parts[0] + '.py'


def closure():
    seen, queue = set(), list(SEEDS)
    while queue:
        relative = queue.pop()
        if relative in seen or not (OLD / relative).is_file():
            continue
        seen.add(relative)
        queue.extend(imports(relative))
    return sorted(seen)


def group(name):
    if name.startswith('native_match_') or name == 'legacy_ds_local_map_rules':
        return 'match'
    if any(part in name for part in ('_rpc', '_receipt', '_transport', '_level_visibility',
                                     '_owner_switch', '_movement', '_ping_receiver')):
        return 'transport/native'
    return 'replication'


def git_base(relative):
    result = subprocess.run(['git', 'show', BASE + ':' + relative], cwd=ROOT,
                            capture_output=True)
    return result.stdout if result.returncode == 0 else None


def merge(current, base, archived):
    if current == base:
        return archived, 0
    if archived == base:
        return current, 0
    with tempfile.TemporaryDirectory(prefix='df-map-merge-') as directory:
        paths = [Path(directory) / name for name in ('current', 'base', 'archive')]
        for path, raw in zip(paths, (current, base, archived)):
            path.write_bytes(raw.replace(b'\r\n', b'\n'))
        result = subprocess.run(['git', 'merge-file', '-p', '--diff3',
                                 *(str(path) for path in paths)], capture_output=True)
        if result.returncode < 0 or result.returncode > 127:
            raise ValueError('Three-way merge failed')
        return result.stdout, result.returncode


def resolve_reviewed_conflicts(relative, raw):
    """Explicit choices after inspecting all 18 shared-source conflict blocks."""
    choices = {
        'handshake_diagnostic': ('current', 'both', 'both', 'current', 'current', 'both', 'current'),
        'run_native_elevated_trial': ('pins', 'both'),
        'verify_local_provider_client': ('current', 'both', 'join_helper', 'pins',
                                         'both', 'control_profile', 'current'),
        'export_native_replication_metadata': ('metadata_signature', 'metadata_pins'),
    }
    name = Path(relative).stem
    if name not in choices:
        return raw, 1
    blocks = list(re.finditer(rb'^<<<<<<<[^\n]*\n(.*?)^\|\|\|\|\|\|\|[^\n]*\n.*?^=======\n(.*?)^>>>>>>>[^\n]*\n',
                             raw, re.M | re.S))
    if len(blocks) != len(choices[name]):
        raise ValueError('Reviewed conflict inventory changed: ' + relative)
    for block, choice in reversed(list(zip(blocks, choices[name]))):
        current, archived = block.group(1), block.group(2)
        if choice == 'current':
            selected = current
        elif choice == 'both':
            selected = current + archived
        elif choice == 'pins':
            selected = archived + (b'    from server_source_layout import expand_server_sources\n'
                                   b'    files = expand_server_sources(root, files)\n')
        elif choice == 'join_helper':
            selected = current[:current.rindex(b'def replication_metadata_source_pins')] + archived
        elif choice == 'control_profile':
            selected = archived.replace(b'ROOT / "outputs/df-local-server/protocol/native_ds_wire_profile.json"',
                                        b'CONTROL_PROFILE')
        elif choice == 'metadata_signature':
            selected = archived + b'    from server_source_layout import expand_server_sources\n'
        elif choice == 'metadata_pins':
            selected = archived.replace(b'for relative in dependencies}',
                                        b'for relative in expand_server_sources(ROOT, dependencies)}')
        else:
            raise ValueError('Unknown reviewed resolution')
        raw = raw[:block.start()] + selected + raw[block.end():]
    return raw, 0


def prepare():
    manifest_path = ROOT / PACKAGE / 'module_layout.json'
    manifest = json.loads(manifest_path.read_text(encoding='utf-8'))
    layout = manifest['modules']
    files = closure()
    mapping = {name: row['canonical'] for name, row in layout.items()}
    for relative in files:
        name = Path(relative).stem
        if relative.startswith(PACKAGE) and name not in mapping:
            mapping[name] = 'dfserver.' + group(name).replace('/', '.') + '.' + name
    organization.MAPPING.update(mapping)
    changes, audit = {}, []
    for relative in files:
        name = Path(relative).stem
        server = relative.startswith(PACKAGE)
        archived = (OLD / relative).read_bytes()
        if server:
            # Business/account implementations remain canonical. Only the gateway
            # and native map stack are candidates for a three-way merge.
            selected = name.startswith('legacy_ds_') or name in {
                'game_server_probe', 'handshake_diagnostic',
                'native_match_loadout', 'native_match_materializer'}
            if not selected:
                continue
            target = SERVER + mapping[name].replace('.', '/') + '.py'
            candidate = organization.migrated_source(archived)
        else:
            target = relative
            candidate = archived
        path = ROOT / target
        current = path.read_bytes() if path.is_file() else None
        code = 0
        if current is not None:
            if not server and name not in SHARED_WORK:
                continue
            base = git_base(relative)
            if base is None:
                if current.replace(b'\r\n', b'\n') != candidate.replace(b'\r\n', b'\n'):
                    raise ValueError('No common source for existing file: ' + target)
                continue
            if server:
                base = organization.migrated_source(base)
            candidate, code = merge(current, base, candidate)
            if code:
                candidate, code = resolve_reviewed_conflicts(relative, candidate)
        if current == candidate:
            continue
        if not code:
            compile(candidate, target, 'exec')
        changes[target] = candidate
        audit.append(dict(source=relative, target=target, source_sha256=digest(archived),
                          before_sha256=digest(current) if current else None,
                          candidate_sha256=digest(candidate), conflicts=code))
        if server and name not in layout:
            alias = PACKAGE + name + '.py'
            changes[alias] = organization.shim(name, mapping[name])
            layout[name] = dict(canonical=mapping[name], source=target[len(SERVER):],
                                before_sha256=digest(archived), after_sha256=digest(candidate))
    changes[PACKAGE + 'module_layout.json'] = (json.dumps(manifest, ensure_ascii=False, indent=2) + '\n').encode()
    return files, changes, audit


def restore_profile_sources():
    """Copy exact data sources, refusing to replace different canonical data."""
    queue = []
    for name in ('portable-map-bootstrap', 'portable-map-spawn', 'local-map-rules'):
        queue.extend((path.relative_to(OLD).as_posix(), None)
                     for path in (OLD / SERVER / 'protocol' / name).glob('*.json'))
    queue.extend((path.relative_to(OLD).as_posix(), None)
                 for path in (OLD / 'work/evidence/map-system-audit-20261018').glob('*.json'))
    seen, records, conflicts = set(), [], []

    def references(value):
        if isinstance(value, dict):
            for path_key, hash_key in (('relative_path', 'sha256'),
                                       ('path', 'sha256'),
                                       ('source_relative_path', 'source_sha256'),
                                       ('parser_source', 'source_sha256'),
                                       ('output', 'decoded_sha256')):
                if isinstance(value.get(path_key), str) and isinstance(value.get(hash_key), str):
                    yield value[path_key], value[hash_key]
            for key, relative in value.items():
                if isinstance(key, str) and key.endswith('_path') and isinstance(relative, str):
                    expected = value.get(key[:-5] + '_sha256')
                    if isinstance(expected, str) and re.fullmatch('[0-9a-f]{64}', expected):
                        yield relative, expected
            for key, item in value.items():
                if isinstance(key, str) and '/' in key and isinstance(item, str) and re.fullmatch('[0-9a-f]{64}', item):
                    yield key, item
                yield from references(item)
        elif isinstance(value, list):
            for item in value:
                yield from references(item)

    def constant(node, values):
        if isinstance(node, ast.Constant):
            return node.value
        if isinstance(node, ast.Name):
            return values[node.id]
        if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
            return constant(node.left, values) + constant(node.right, values)
        if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Div):
            left, right = constant(node.left, values), constant(node.right, values)
            if isinstance(left, str) and isinstance(right, str):
                return (left.rstrip('/') + '/' if left else '') + right
            raise ValueError('Nonliteral source path')
        if isinstance(node, (ast.List, ast.Tuple)):
            return [constant(item, values) for item in node.elts]
        if isinstance(node, ast.Dict):
            return {constant(k, values): constant(v, values) for k, v in zip(node.keys, node.values)}
        raise ValueError('Nonliteral source expression')

    for relative in closure():
        values = {'ROOT': ''}
        for node in ast.parse((OLD / relative).read_bytes()).body:
            if isinstance(node, ast.Assign):
                try:
                    value = constant(node.value, values)
                except (ValueError, KeyError, TypeError):
                    continue
                for target in node.targets:
                    if isinstance(target, ast.Name):
                        values[target.id] = value
                queue.extend(references(value))
                if isinstance(value, dict):
                    prefixes = [v for v in values.values() if isinstance(v, str) and
                                v.startswith('work/') and v.endswith('/')]
                    for key, expected in value.items():
                        if (isinstance(key, str) and '/' not in key and isinstance(expected, str) and
                                re.fullmatch('[0-9a-f]{64}', expected)):
                            for prefix in prefixes:
                                if (OLD / (prefix + key)).is_file():
                                    queue.append((prefix + key, expected))
        for key, relative in values.items():
            if isinstance(relative, str) and relative.startswith('work/'):
                if (OLD / relative).is_file() and Path(relative).suffix in ('.json', '.bin'):
                    queue.append((relative, None))
                for suffix in ('_SHA', '_SHA256'):
                    expected = values.get(key + suffix)
                    if isinstance(expected, str) and re.fullmatch('[0-9a-f]{64}', expected):
                        queue.append((relative, expected))

    while queue:
        relative, expected = queue.pop(0)
        relative = relative.replace('\\', '/')
        if relative in seen:
            continue
        path = OLD / relative
        if (Path(relative).is_absolute() or '..' in Path(relative).parts or
                not path.resolve().is_relative_to(OLD.resolve()) or
                path.suffix not in ('.json', '.bin', '.txt', '.lua', '.py', '.cs', '.uasset', '.uexp', '.ubulk')):
            continue
        if not path.is_file():
            conflicts.append(dict(path=relative, reason='missing_archived_source'))
            continue
        raw = path.read_bytes()
        if expected and digest(raw) != expected:
            conflicts.append(dict(path=relative, reason='archived_hash_mismatch'))
            continue
        seen.add(relative)
        target = ROOT / relative
        if target.exists() and target.read_bytes() != raw:
            conflicts.append(dict(path=relative, reason='canonical_differs',
                                  source_sha256=digest(raw), canonical_sha256=digest(target.read_bytes())))
        elif not target.exists():
            if path.suffix == '.py' and expected is None:
                conflicts.append(dict(path=relative, reason='source_requires_code_review'))
            else:
                if path.suffix == '.py':
                    # These are hash-pinned collectors retained as evidence;
                    # parsing does not import or execute them.
                    compile(raw, relative, 'exec')
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_bytes(raw)
                records.append(dict(path=relative, sha256=digest(raw), bytes=len(raw)))
        if path.suffix == '.json':
            queue.extend(references(json.loads(raw)))
    previous = OUT / 'data-import.json'
    if previous.is_file():
        prior = json.loads(previous.read_bytes())
        indexed = {row['path']: row for row in prior['files']}
        indexed.update({row['path']: row for row in records})
        cumulative = list(indexed.values())
    else:
        cumulative = records
    report = dict(kind='canonical_map_runtime_data_import', files=cumulative, conflicts=conflicts,
                  account_database_copied=False, executable_dll_copied=False)
    OUT.mkdir(parents=True, exist_ok=True)
    (OUT / 'data-import.json').write_text(json.dumps(report, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')
    print(json.dumps(dict(copied=len(records), bytes=sum(r['bytes'] for r in records),
                         cumulative_files=len(cumulative),
                         historical_reference_limits=dict(Counter(r['reason'] for r in conflicts))), indent=2))


def qualify_canonical_catalogs():
    """Retain current data after equality or exact admitted-mode comparison."""
    names = ('hero_customization_catalog', 'operator_asset_catalog',
             'game_item_catalog', 'local_map_board_candidates')
    pins, records = {}, []
    for name in names:
        relative = SERVER + 'protocol/' + name + '.json'
        before, after = (OLD / relative).read_bytes(), (ROOT / relative).read_bytes()
        a, b = json.loads(before), json.loads(after)
        if name == 'local_map_board_candidates':
            if any(not any(all(candidate.get(k) == v for k, v in row.items())
                           for candidate in b['operations']) for row in a['operations']):
                raise ValueError('An archived admitted map operation was changed')
            reason = 'archived_admitted_operations_preserved_with_sourced_difficulty_expansion'
        else:
            if a != b:
                raise ValueError('Canonical catalogue content changed: ' + relative)
            reason = 'parsed_json_identical_only_serialization_differs'
        pins[relative] = digest(after)
        records.append(dict(path=relative, archive_sha256=digest(before),
                            canonical_sha256=digest(after), qualification=reason))

    def update(value):
        if isinstance(value, dict):
            if value.get('relative_path') in pins and 'sha256' in value:
                value['sha256'] = pins[value['relative_path']]
            for child in value.values():
                update(child)
        elif isinstance(value, list):
            for child in value:
                update(child)

    changed = []
    for path in (ROOT / SERVER / 'protocol/portable-map-spawn').glob('profile*.json'):
        raw = path.read_bytes()
        config = json.loads(raw)
        update(config)
        result = (json.dumps(config, ensure_ascii=True, indent=2) + '\n').encode()
        if result != raw:
            path.write_bytes(result)
            changed.append(path.relative_to(ROOT).as_posix())
    (OUT / 'canonical-catalog-qualification.json').write_text(
        json.dumps(dict(catalogs=records, profiles=changed), ensure_ascii=False, indent=2) + '\n', encoding='utf-8')
    print(json.dumps(dict(qualified_catalogs=len(records), profiles=changed)))


def align_identical_catalog_bytes():
    changes = []
    for source in (OLD / SERVER / 'protocol').glob('*.json'):
        relative = source.relative_to(OLD)
        target = ROOT / relative
        if not target.is_file():
            continue
        old, current = source.read_bytes(), target.read_bytes()
        if old != current and json.loads(old) == json.loads(current):
            changes.append((relative.as_posix(), current, old))
    backup = OUT / 'identical-catalog-format-before.zip'
    if backup.exists():
        raise ValueError('Catalogue format backup already exists')
    with zipfile.ZipFile(backup, 'x', compression=zipfile.ZIP_DEFLATED) as saved:
        for relative, current, _ in changes:
            saved.writestr(relative, current)
    for relative, _, old in changes:
        (ROOT / relative).write_bytes(old)
    (OUT / 'identical-catalog-format.json').write_text(json.dumps(dict(
        parsed_data_unchanged=True, files=[dict(path=p, before_sha256=digest(b),
        after_sha256=digest(a)) for p,b,a in changes]), indent=2) + '\n', encoding='utf-8')
    print(json.dumps(dict(parsed_data_unchanged=True, aligned=len(changes))))


def restore_fsm_source_snapshots():
    folder = 'work/evidence/model-init-chain-20261018/fsm-source-snapshot-1792385022786009500/'
    files = ((folder + 'fsm_readonly_scope.py', folder + 'fsm_readonly_scope.py',
              '1bc3bfca9f232e2d240615fa17f6ef8a5bb73866c55c3bc6fd4f3b9bd64be2e7'),
             (folder + 'observe_owned_fsm_metadata.py', folder + 'observe_owned_fsm_metadata.py',
              '5bac0947fa9a06b0eb8312060c765f956dcd6740a0ef6529d1dd94ee941651c3'),
             ('work/export_native_replication_metadata.py', folder + 'export_native_replication_metadata.py',
              '1885b6ccc86dc5dd049ac22abc3ca7f2d7f9cee9c6eced8f430fd1f893ba3b89'))
    for source, target, expected in files:
        raw = (OLD / source).read_bytes()
        if digest(raw) != expected:
            raise ValueError('Historical collector snapshot changed: ' + source)
        path = ROOT / target
        if path.exists() and path.read_bytes() != raw:
            raise ValueError('Historical collector snapshot target differs')
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(raw)
    for name in ('owned-fsm-metadata.json', 'owned-fsm-layout-followup-exclusive.json'):
        report = ROOT / 'work/native-client-tests/1792385022786009500' / name
        for relative, expected in json.loads(report.read_bytes())['source_pins'].items():
            path = ROOT / relative
            if relative.endswith('.py') and not path.exists():
                raw = (OLD / relative).read_bytes()
                if digest(raw) != expected:
                    raise ValueError('Historical observation collector differs: ' + relative)
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_bytes(raw)
    print(json.dumps(dict(historical_collector_snapshots=len(files), executed=False)))


def restore_admitted_profile_sources():
    import sys
    sys.path.insert(0, str(ROOT / SERVER))
    from portable_map_bootstrap import load_plan
    plan = load_plan(ROOT, ROOT / SERVER / 'protocol/portable-map-spawn/profile-carried-inventory.json')
    records = []
    for relative, expected in plan.sources.items():
        target = ROOT / relative
        if target.exists():
            if digest(target.read_bytes()) != expected:
                raise ValueError('Current admitted profile seal differs: ' + relative)
            continue
        source = OLD / relative
        if os.name == 'nt':
            source = Path('\\\\?\\' + str(source))
        if (not target.resolve().is_relative_to(ROOT) or
                source.suffix in ('.dll', '.exe', '.sqlite3') or
                not source.is_file()):
            raise ValueError('Admitted profile source is unavailable: ' + relative)
        raw = source.read_bytes()
        if digest(raw) != expected:
            raise ValueError('Admitted archive source seal differs: ' + relative)
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(raw)
        records.append(dict(path=relative, sha256=expected, bytes=len(raw)))
    (OUT / 'admitted-profile-source-import.json').write_text(
        json.dumps(dict(files=records, checked_sources=len(plan.sources)), indent=2) + '\n', encoding='utf-8')
    print(json.dumps(dict(imported=len(records), checked_sources=len(plan.sources))))


def organize_reference_modules():
    manifest_path = ROOT / PACKAGE / 'module_layout.json'
    manifest = json.loads(manifest_path.read_bytes())
    layout = manifest['modules']
    names = ('legacy_ds_actor_receive', 'legacy_ds_fname_string',
             'legacy_ds_late_fashion_name', 'legacy_ds_pc_ping')
    organization.MAPPING.update({k:v['canonical'] for k,v in layout.items()})
    organization.MAPPING.update({name: 'dfserver.replication.' + name for name in names})
    for name in names:
        canonical = organization.MAPPING[name]
        relative = SERVER + canonical.replace('.', '/') + '.py'
        source = ROOT / PACKAGE / (name + '.py')
        raw = source.read_bytes()
        migrated = organization.migrated_source(raw)
        target = ROOT / relative
        if target.exists():
            raise ValueError('Reference implementation already exists: ' + relative)
        target.write_bytes(migrated)
        source.write_bytes(organization.shim(name, canonical))
        layout[name] = dict(canonical=canonical, source=relative[len(SERVER):],
                            before_sha256=digest(raw), after_sha256=digest(migrated))
    manifest_path.write_text(json.dumps(manifest, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')
    print(json.dumps(dict(reference_modules_organized=len(names))))


def restore_runtime_tests():
    candidates = sorted(path for path in (OLD / SERVER / 'tests').glob('test_*.py')
                        if path.name.startswith(('test_legacy_ds', 'test_game_server', 'test_native_match',
                                                 'test_admitted_actor')))
    records = []
    for source in candidates:
        relative = source.relative_to(OLD).as_posix()
        target = ROOT / relative
        raw = source.read_bytes()
        before = target.read_bytes() if target.exists() else None
        if before == raw:
            continue
        if before is not None:
            base = git_base(relative)
            if base is None:
                raise ValueError('Existing test has no merge base: ' + relative)
            raw, conflicts = merge(before, base, raw)
            if conflicts:
                raise ValueError('Runtime test needs manual resolution: ' + relative)
        compile(raw, relative, 'exec')
        target.write_bytes(raw)
        records.append(dict(path=relative, source_sha256=digest(source.read_bytes()),
                            before_sha256=digest(before) if before else None, after_sha256=digest(raw)))
    (OUT / 'runtime-test-import.json').write_text(json.dumps(dict(files=records), indent=2) + '\n', encoding='utf-8')
    print(json.dumps(dict(runtime_tests_imported=len(records))))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--apply', action='store_true')
    parser.add_argument('--restore-profile-sources', action='store_true')
    parser.add_argument('--qualify-canonical-catalogs', action='store_true')
    parser.add_argument('--align-identical-catalog-bytes', action='store_true')
    parser.add_argument('--restore-fsm-source-snapshots', action='store_true')
    parser.add_argument('--restore-admitted-profile-sources', action='store_true')
    parser.add_argument('--organize-reference-modules', action='store_true')
    parser.add_argument('--restore-runtime-tests', action='store_true')
    args = parser.parse_args()
    if args.restore_runtime_tests:
        restore_runtime_tests()
        return
    if args.organize_reference_modules:
        organize_reference_modules()
        return
    if args.restore_admitted_profile_sources:
        restore_admitted_profile_sources()
        return
    if args.restore_fsm_source_snapshots:
        restore_fsm_source_snapshots()
        return
    if args.align_identical_catalog_bytes:
        align_identical_catalog_bytes()
        return
    if args.qualify_canonical_catalogs:
        qualify_canonical_catalogs()
        return
    if args.restore_profile_sources:
        restore_profile_sources()
        return
    files, changes, audit = prepare()
    OUT.mkdir(parents=True, exist_ok=True)
    conflicts = [row for row in audit if row['conflicts']]
    for row in conflicts:
        target = OUT / 'conflicts' / row['target']
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(changes[row['target']])
    report = dict(kind='canonical_map_runtime_import_audit', base=BASE,
                  canonical_root=str(ROOT), archive_root=str(OLD),
                  import_graph_count=len(files), files=audit,
                  account_database_copied=False, executable_dll_copied=False)
    (OUT / 'preview.json').write_text(json.dumps(report, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')
    print(json.dumps(dict(import_graph_count=len(files), candidate_files=len(audit),
                         new_files=sum(row['before_sha256'] is None for row in audit),
                         conflicts=[dict(path=r['target'], count=r['conflicts']) for r in conflicts]), indent=2))
    if not args.apply:
        return
    if conflicts:
        raise ValueError('Resolve the previewed shared-source conflicts before applying')
    backup = OUT / 'canonical-before.zip'
    if backup.exists():
        raise ValueError('Refusing to replace the canonical pre-integration backup')
    for row in audit:
        path = ROOT / row['target']
        actual = digest(path.read_bytes()) if path.exists() else None
        if actual != row['before_sha256']:
            raise ValueError('Canonical source changed after preview: ' + row['target'])
    with zipfile.ZipFile(backup, 'x', compression=zipfile.ZIP_DEFLATED) as saved:
        for relative in changes:
            path = ROOT / relative
            if path.is_file():
                saved.writestr(relative, path.read_bytes())
    for relative, raw in changes.items():
        path = ROOT / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(raw)
    (OUT / 'applied.json').write_text(json.dumps(report, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')
    print(json.dumps(dict(applied=len(changes), canonical_only=True)))


if __name__ == '__main__':
    main()
