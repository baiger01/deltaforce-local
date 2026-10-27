"""Resolve current cooked suit rows without historical FName/ownership guesses."""
import hashlib
from pathlib import Path, PureWindowsPath

from build_updated_minimum_actor_profile import (
    ROOT, COOKED_PATH, COOKED_SHA256, CURRENT_CLIENT_SHA256, _read, _document,
)
from extract_operator_avatar_catalog import value, view
from portable_player_appearance import avatar_ids_for_selection
from research_updated_map_rule_sources import fields_table

EXTRACTION_PATH = 'work/evidence/current-entry-appearance-assets-79fb7b10.json'
EXTRACTION_SHA256 = '684390a883ea15332d4f8e7df21ec5995ea4dce0ab53ddfc1b34e1837edb352e'
REPORT_PINS = {EXTRACTION_PATH: EXTRACTION_SHA256, COOKED_PATH: COOKED_SHA256}
FASHION = '../../../DeltaForce/Content/R13N/Common/Base/DataTables/Hero/HeroFashionData'
AVATAR = '../../../DeltaForce/Content/R13N/Common/PC/DataTables/CharacterAvatarData'


def appearance_sources(root=ROOT):
    root = Path(root).resolve(strict=True)
    blobs = {path: _read(root, path) for path in REPORT_PINS}
    report = _document(blobs[EXTRACTION_PATH], EXTRACTION_SHA256)
    for archive in report['archives']:
        for row in archive['matches']:
            relative = PureWindowsPath(row['output']).as_posix()
            blobs[relative] = _read(root, relative)
    return blobs


def _avatar_value(data, tag, names):
    return view(data, tag, names) if tag['name'] in ('FPP', 'TPP') else value(data, tag, names)


def derive_appearance(blobs):
    docs = {path: _document(blobs.get(path), digest) for path, digest in REPORT_PINS.items()}
    cooked = docs[COOKED_PATH]
    if cooked['client_sha256'] != CURRENT_CLIENT_SHA256 or cooked['complete_directory_search'] is not True:
        raise ValueError('Current build-bound archive directory required')
    expected = {row['archive']: row for row in cooked['archives']}
    archives = docs[EXTRACTION_PATH]['archives']
    if len(archives) != len(expected) or {a['archive'] for a in archives} != set(expected):
        raise ValueError('Current complete archive inventory disagrees')
    payloads, pins = {}, dict(REPORT_PINS)
    for archive in archives:
        validation, witness = archive['validation'], expected[archive['archive']]
        if (validation['index_sha1_valid'] is not True or
                validation['decoded_index_sha256'] != witness['decoded_index_sha256'] or
                validation['footer_sha256'] != witness['footer_sha256']):
            raise ValueError('Appearance archive differs from current build-bound source')
        for row in archive['matches']:
            asset = row['asset']
            if asset in payloads:
                raise ValueError('Appearance asset has multiple packaged candidates')
            relative = PureWindowsPath(row['output']).as_posix()
            raw = blobs.get(relative)
            if (row['archive_payload_sha1_valid'] is not True or type(raw) is not bytes or
                    len(raw) != row['decoded_bytes'] or
                    hashlib.sha256(raw).hexdigest() != row['decoded_sha256']):
                raise ValueError('Current appearance payload SHA256 mismatch')
            payloads[asset] = raw
            pins[relative] = row['decoded_sha256']
    for stem in (FASHION, AVATAR):
        if any(stem + suffix not in payloads for suffix in ('.uasset', '.uexp')):
            raise ValueError('Current appearance table companion missing')
    fashion = fields_table(payloads[FASHION+'.uasset'], payloads[FASHION+'.uexp'],
        selected_fields={'FashionID', 'BelongedHeroID', 'IsDefUnlock', 'IsDefEquip'})
    avatars = fields_table(payloads[AVATAR+'.uasset'], payloads[AVATAR+'.uexp'],
        selected_fields={'CharacterTag', 'SkinId', 'FPP', 'TPP'}, decoder=_avatar_value)
    suits = []
    for key, row in fashion['rows'].items():
        fields = row['fields']
        if fields['FashionID'] != key or not key.isascii() or not key.isdecimal():
            raise ValueError('Current numeric FashionID does not match its typed row key')
        hero = fields['BelongedHeroID']
        if type(hero) is not int or not 0 < hero < 1 << 63:
            raise ValueError('Current suit has no explicit numeric operator ownership')
        suits.append(dict(id=int(key), hero_id=hero,
            source_table=fashion['table'], source_row=key,
            serialized_uexp_offset=row['serialized_uexp_offset']))
    rows = {key: dict(id=key, character_tag=row['fields']['CharacterTag'],
        views={v: row['fields'].get(v, {}) for v in ('FPP', 'TPP')},
        source_table=avatars['table'], source_row=key,
        serialized_uexp_offset=row['serialized_uexp_offset']) for key, row in avatars['rows'].items()}
    return dict(kind='current_cooked_admission_appearance', client_sha256=CURRENT_CLIENT_SHA256,
        verified_archive_count=len(archives), fashion_row_count=fashion['row_count'],
        avatar_row_count=avatars['row_count'], hero_catalog=dict(fashions=suits),
        avatar_catalog=dict(rows=rows), unmapped_fashion_ids=sorted(str(s['id']) for s in suits
            if str(s['id']) not in rows), source_pins=dict(sorted(pins.items())),
        native_application_verified=False,
        team_policy='Explicit local selection is shown to both teams; no original team-priority claim')


def appearance_context(root=ROOT):
    result = derive_appearance(appearance_sources(root))
    for path in ('work/updated_player_appearance.py', 'work/portable_player_appearance.py',
                 'work/research_updated_map_rule_sources.py', 'work/extract_operator_avatar_catalog.py',
                 'work/parse_economy_installed_tables.py'):
        result['source_pins'][path] = hashlib.sha256(_read(root, path)).hexdigest()
    return result


def avatar_ids(current, hero_id, fashion_id):
    if current.get('client_sha256') != CURRENT_CLIENT_SHA256:
        raise ValueError('Current cooked appearance context required')
    return avatar_ids_for_selection(hero_id, fashion_id,
        current['hero_catalog'], current['avatar_catalog'])
