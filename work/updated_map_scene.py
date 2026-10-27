"""Current packaged World/Level ownership for the minimum source Actor plan."""
import argparse
import hashlib
import json
from pathlib import Path, PureWindowsPath

from build_updated_minimum_actor_profile import (
    ROOT, COOKED_PATH, COOKED_SHA256, CURRENT_CLIENT_SHA256, _read, _document,
)
from research_updated_map_rule_sources import MemoryPackage

DIRECTORY_PATH = 'work/evidence/current-entry-map-paths-79fb7b10.json'
DIRECTORY_SHA256 = '7a2893581dbffd00e647653d70ee69162dbba6e85ce3826930a0aba8076c8250'
EXTRACTION_PATH = 'work/evidence/current-entry-map-extracted-79fb7b10.json'
EXTRACTION_SHA256 = 'fcaad269391e5a97243ffe8c306a6bf5e4defe2b49c6341ddeec713451f30726'
ENTRY_STEM = '../../../DeltaForce/Content/Maps/Iris_Entry/Iris_Entry'
REPORT_PINS = {DIRECTORY_PATH: DIRECTORY_SHA256, EXTRACTION_PATH: EXTRACTION_SHA256,
               COOKED_PATH: COOKED_SHA256}


def _extracted_path(row):
    return PureWindowsPath(row['output']).as_posix()


def scene_sources(root=ROOT):
    root = Path(root).resolve(strict=True)
    blobs = {path: _read(root, path) for path in REPORT_PINS}
    extraction = _document(blobs[EXTRACTION_PATH], EXTRACTION_SHA256)
    for archive in extraction['archives']:
        for row in archive['matches']:
            relative = _extracted_path(row)
            blobs[relative] = _read(root, relative)
    return blobs


def derive_scene(blobs):
    docs = {path: _document(blobs.get(path), digest) for path, digest in REPORT_PINS.items()}
    cooked = docs[COOKED_PATH]
    if cooked['client_sha256'] != CURRENT_CLIENT_SHA256 or cooked['complete_directory_search'] is not True:
        raise ValueError('Exact current full resource-directory qualification is required')
    previous = {r['archive']: r for r in cooked['archives']}
    directories = docs[DIRECTORY_PATH]['archives']
    if len(directories) != len(previous) or {r['archive'] for r in directories} != set(previous):
        raise ValueError('Current complete archive inventory disagrees')
    candidates = {}
    for archive in directories:
        row, expected = archive['validation'], previous[archive['archive']]
        if (row['index_sha1_valid'] is not True or row['decoded_index_sha256'] != expected['decoded_index_sha256'] or
                row['footer_sha256'] != expected['footer_sha256']):
            raise ValueError('Current archive index differs from its build-bound source')
        for match in archive['matches']:
            if match['asset'] in (ENTRY_STEM+'.umap', ENTRY_STEM+'.uexp'):
                if match['asset'] in candidates:
                    raise ValueError('Entry scene has multiple archive candidates')
                candidates[match['asset']] = (archive['archive'], match)
    if set(candidates) != {ENTRY_STEM+'.umap', ENTRY_STEM+'.uexp'}:
        raise ValueError('Current entry scene companion is incomplete')
    payloads, pins = {}, dict(REPORT_PINS)
    for archive in docs[EXTRACTION_PATH]['archives']:
        for row in archive['matches']:
            name, witness = candidates[row['asset']]
            if (archive['archive'] != name or row['entry_offset'] != witness['entry_offset'] or
                    row['archive_payload_sha1_valid'] is not True):
                raise ValueError('Current entry scene extraction provenance disagrees')
            relative = _extracted_path(row)
            raw = blobs.get(relative)
            if (type(raw) is not bytes or len(raw) != row['decoded_bytes'] or
                    hashlib.sha256(raw).hexdigest() != row['decoded_sha256']):
                raise ValueError('Current entry scene payload SHA256 mismatch')
            pins[relative] = row['decoded_sha256']
            payloads[row['asset']] = raw
    pkg = MemoryPackage(payloads[ENTRY_STEM+'.umap'], payloads[ENTRY_STEM+'.uexp'])
    worlds = [e for e in pkg.exports if e['outer_index'] == 0 and pkg.object(e['class_index']) == 'World']
    if len(worlds) != 1:
        raise ValueError('Unique current cooked root World required')
    world = worlds[0]
    levels = [e for e in pkg.exports if e['outer_index'] == world['index'] and pkg.object(e['class_index']) == 'Level']
    if len(levels) != 1:
        raise ValueError('Unique current cooked World-owned Level required')
    level = levels[0]
    return dict(kind='current_packaged_entry_scene_context', client_sha256=CURRENT_CLIENT_SHA256,
        package_path=pkg.package_path, world_export=world, level_export=level,
        level_path=pkg.package_path+'.'+world['name']+':'+level['name'],
        verified_archive_count=len(directories), selected_asset_candidates_unique=True,
        source_pins=dict(sorted(pins.items())), runtime_world_origin_observed=False,
        runtime_level_resolution_verified=False, native_acceptance_verified=False,
        scope='All current packaged directory candidates; runtime plugins and live replacements remain separate')


def scene_context(root=ROOT):
    return derive_scene(scene_sources(root))


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', required=True, type=Path)
    args = parser.parse_args()
    target = args.output.resolve()
    if target.parent != ROOT/'work/evidence' or target.exists():
        parser.error('A fresh work/evidence file is required')
    result = scene_context()
    raw = (json.dumps(result, sort_keys=True, indent=2)+'\n').encode('ascii')
    with target.open('xb') as stream:
        stream.write(raw)
    print(json.dumps(dict(output=str(target), sha256=hashlib.sha256(raw).hexdigest(), level=result['level_path'])))
