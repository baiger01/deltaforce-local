"""Bounded current PAK network configuration search; no process or runtime edits."""
import argparse
import hashlib
import json
from pathlib import Path

from research_updated_cooked_declarations import SHADOW, CLIENT_SHA, MAX_PAKS
from research_updated_metadata_roots import ROOT, sha

TOKENS = ('netdriverdefinitions', 'netconnectionclassname', 'channeldefinitions',
    'packagemapclass', 'gpnetdriver', 'actorchannel', 'gameengine')


def selected_lines(raw):
    if len(raw) > 8*1024*1024:
        raise ValueError('Network config exceeds research byte bound')
    text = raw.decode('utf-16' if raw.startswith((b'\xff\xfe', b'\xfe\xff')) else 'utf-8-sig')
    section, result = '', []
    for number, line in enumerate(text.splitlines(), 1):
        stripped = line.strip()
        if stripped.startswith('[') and stripped.endswith(']'):
            section = stripped[1:-1]
        elif stripped and not stripped.startswith((';', '#')) and '=' in stripped:
            key, value = stripped.split('=', 1)
            if any(token in key.lower() or token in value.lower() for token in TOKENS):
                result.append(dict(line=number, section=section, key=key, value=value))
    return result


def derive():
    from recover_economy_pak_access import pak_footer, validate_index, directory_index, entry_offset, decode_entry
    from research_updated_content_resources import access
    from scan_weapon_tables import parse_entry
    import oodle_payload_reader
    current = SHADOW/'DeltaForce/Binaries/Win64/DeltaForceClient-Win64-Shipping.exe'
    with current.open('rb') as stream:
        if hashlib.file_digest(stream, 'sha256').hexdigest() != CLIENT_SHA:
            raise ValueError('Exact current executable identity required')
    oodle_payload_reader.PATH = SHADOW/'DeltaForce/Binaries/Win64/oo2core_8_win64.dll'
    candidates, provenance = access()
    paths = sorted((SHADOW/'DeltaForce/Content/Paks').glob('*.pak'))
    if not 1 <= len(paths) <= MAX_PAKS:
        raise ValueError('Bounded complete PAK directory required')
    reports, configs, config_like = [], [], []
    for path in paths:
        footer = pak_footer(path)
        clear = key = None
        for candidate in candidates:
            valid, clear, key = validate_index(path, footer, {footer['guid']: candidate})
            if clear is not None:
                break
        if clear is None or not valid.get('index_sha1_valid'):
            raise ValueError('Current PAK index hash invalid: '+path.name)
        details, entries, encoded = directory_index(path, footer, clear, key)
        selected = [(name, location) for name, location in entries if name.lower().endswith('.ini')]
        config_like.extend(dict(archive=path.name, path=name) for name, _ in entries
            if '/config/' in name.lower() and not name.lower().endswith(('.uasset', '.uexp', '.ubulk', '.lua', '.luac', '.ini')))
        if len(selected) > 512 or len(config_like) > 2048:
            raise ValueError('Current config index search exceeds local bound')
        with path.open('rb') as stream:
            for name, location in selected:
                pos = entry_offset(encoded, location)
                entry = parse_entry(stream, pos, footer['offset'], variant='observed_permutation')
                if not 0 <= entry['uncompressed'] <= 8*1024*1024:
                    configs.append(dict(archive=path.name, path=name, entry_offset=pos,
                        decoded_bytes=entry['uncompressed'], text_decoded=False,
                        reason='Outside local8MiB byte bound', selected_network_lines=[]))
                    continue
                raw, valid_payload = decode_entry(stream, pos, entry, footer['methods'], key)
                if not valid_payload:
                    raise ValueError('Current config payload SHA1 invalid')
                try:
                    lines = selected_lines(raw)
                    text_decoded = True
                except UnicodeError:
                    lines, text_decoded = [], False
                configs.append(dict(archive=path.name, path=name, entry_offset=pos,
                    decoded_bytes=len(raw), decoded_sha256=sha(raw), archive_payload_sha1_valid=True,
                    text_decoded=text_decoded, selected_network_lines=lines))
        reports.append(dict(archive=path.name, footer_sha256=valid['footer_sha256'],
            decoded_index_sha256=valid['decoded_index_sha256'], index_sha1_valid=True,
            secondary_indices=details.get('secondary_indices', [])))
    saved = []
    folder = SHADOW/'DeltaForce/Saved/Config/WindowsClient'
    for name in ('Engine.ini', 'Game.ini'):
        path = folder/name
        if path.exists():
            raw = path.read_bytes()
            saved.append(dict(path=path.as_posix(), sha256=sha(raw), bytes=len(raw),
                selected_network_lines=selected_lines(raw), current_runtime_memory_observed=False))
    helpers = [Path(__file__), ROOT/'work/research_updated_cooked_declarations.py',
        ROOT/'work/research_updated_content_resources.py', ROOT/'work/recover_economy_pak_access.py',
        ROOT/'work/scan_weapon_tables.py', ROOT/'work/oodle_payload_reader.py']
    return dict(kind='current_immutable_network_config_inventory', client_sha256=CLIENT_SHA,
        source_pins={p.relative_to(ROOT).as_posix():sha(p.read_bytes()) for p in helpers},
        archive_count=len(paths), complete_current_pak_index_search=True, archives=reports,
        ini_payloads=configs, other_config_paths=config_like, saved_config_files=saved,
        asset_access_candidate_provenance=provenance, asset_access_keys_disclosed=False,
        runtime_class_selection_proved=False, process_opened=False, native_engine_function_called=False,
        runtime_files_changed=False, native_acceptance_verified=False)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    target = args.output.resolve()
    if target.exists() or target.parent != ROOT/'work' or not target.name.startswith('research_'):
        parser.error('Fresh work/research_ report required')
    report = derive()
    raw = (json.dumps(report, ensure_ascii=True, indent=2)+'\n').encode('ascii')
    with target.open('xb') as stream:
        stream.write(raw)
    print(json.dumps(dict(output=str(target), sha256=sha(raw), archives=report['archive_count'],
        ini_payloads=len(report['ini_payloads']), other_config_paths=len(report['other_config_paths']))))
