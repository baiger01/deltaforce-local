"""Bounded current PAK class/CDO records, never live metadata or wire handles.

All archive directories are independently hash checked. Candidate historical
asset-access constants are accepted only after a current index hash matches.
Only the four requested Blueprint packages are decoded, in memory. This writes
one new research report and does not import a runtime profile or open a process.
"""
import argparse
import hashlib
import json
import math
from pathlib import Path
import re
import struct

from bundle_asset_locations_package import package
from extract_operator_avatar_catalog import fname, tags

ROOT = Path(__file__).resolve().parent.parent
CLIENT_SHA = '79fb7b105170141ed863331d36833a73062e66bf5291b2364fe3a64c18336203'
SHADOW = Path('F:/deltaforce-local-shadow-build-79fb7b10')
STEMS = ('BP_DFMPlayerController', 'BP_DFMCharacter', 'BP_GameState_PVPVE', 'BP_SOLPlayerState')
PATTERN = re.compile(r'/(?:'+ '|'.join(STEMS) +r')\.(?:uasset|uexp)$')
MAX_HEADER = 8*1024*1024
MAX_PAYLOAD = 16*1024*1024
MAX_EXPORT = 8*1024*1024
MAX_PAKS = 512


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def _tag_value(payload, tag, names, reference):
    at, end, size, kind = tag['value_start'], tag['end'], tag['size'], tag['kind']
    if kind == 'ObjectProperty' and size == 4:
        index, = struct.unpack_from('<i', payload, at)
        return dict(package_index=index, reference=reference(index))
    formats = {'IntProperty': ('i', 4), 'UInt32Property': ('I', 4),
        'Int64Property': ('q', 8), 'UInt64Property': ('Q', 8), 'FloatProperty': ('f', 4)}
    if kind in formats and formats[kind][1] == size:
        value, = struct.unpack_from('<'+formats[kind][0], payload, at)
        if type(value) is float and not math.isfinite(value):
            raise ValueError('Nonfinite cooked scalar')
        return value
    if kind in ('NameProperty', 'EnumProperty', 'ByteProperty') and size == 8:
        return dict(serialized_name=fname(payload, at, names), numeric_enum_value_recovered=False)
    if kind == 'BoolProperty' and size == 0:
        # The bool is immediately after the common 24-byte tag header.
        value = payload[tag['start']+24]
        if value not in (0, 1):
            raise ValueError('Invalid cooked bool')
        return bool(value)
    if kind == 'StructProperty' and tag['meta'] in (['Vector'], ['Rotator']) and size == 12:
        value = struct.unpack_from('<3f', payload, at)
        if not all(math.isfinite(x) for x in value):
            raise ValueError('Nonfinite cooked vector')
        return list(value)
    return dict(value_decoded=False, bytes=end-at, sha256=sha(payload[at:end]))


def parse_package(header, payload, stem):
    if (type(header) is not bytes or type(payload) is not bytes or
            not 45 <= len(header) <= MAX_HEADER or not 4 <= len(payload) <= MAX_PAYLOAD):
        raise ValueError('Bounded immutable package/companion bytes required')
    meta = package(header)
    if meta is None or meta['own_paths'] != [next((p for p in meta['own_paths']
            if p.rsplit('/', 1)[-1] == stem), None)]:
        raise ValueError('Exact unambiguous own Blueprint package required')
    names = meta['names']
    summary = 41+struct.unpack_from('<i', header, 20)[0]*20
    ec, eo, ic, io, depends = struct.unpack_from('<5i', header, summary+16)
    if (not 1 <= ec <= 4096 or not 0 <= ic <= 4096 or
            eo-io != ic*28 or depends-eo != ec*104):
        raise ValueError('Bounded observed package table extents required')
    imports = [dict(index=-i-1, name=r['object'], outer_index=r['outer'],
        class_name=r['class'], class_package=r['class_package']) for i, r in enumerate(meta['imports'])]
    exports, previous = [], len(header)
    for i in range(ec):
        at = eo+i*104
        cls, sup, template, outer = struct.unpack_from('<4i', header, at)
        flags, size, absolute = struct.unpack_from('<Iqq', header, at+24)
        if not 0 <= size <= MAX_EXPORT or absolute != previous:
            raise ValueError('Complete sequential bounded export extents required')
        previous = absolute+size
        exports.append(dict(index=i+1, name=fname(header, at+16, names),
            class_index=cls, super_index=sup, template_index=template, outer_index=outer,
            serialized_object_flags=hex(flags), uasset_record_offset=at,
            serialized_uexp_offset=absolute-len(header), serialized_bytes=size))
    if previous-len(header) != len(payload)-4 or payload[-4:] != bytes.fromhex('c1832a9e'):
        raise ValueError('Companion must cover every export and only its package terminator')

    def record(index):
        if type(index) is not int or not -ic <= index <= ec:
            raise ValueError('Package reference is outside its import/export tables')
        return imports[-index-1] if index < 0 else exports[index-1] if index else None

    def reference(index, seen=()):
        if not index:
            return []
        if index in seen or len(seen) >= 64:
            raise ValueError('Cyclic or oversized package reference chain')
        row = record(index)
        outer = reference(row['outer_index'], (*seen, index))
        return outer+[row['name']] if outer or index < 0 else [meta['own_paths'][0], row['name']]

    for row in (*imports, *exports):
        reference(row['index'])
    for row in exports:
        for key in ('class_index', 'super_index', 'template_index'):
            record(row[key])
        seen, sup = {row['index']}, row['super_index']
        while sup > 0:
            if sup in seen or len(seen) >= 64:
                raise ValueError('Cyclic or oversized exported superclass chain')
            seen.add(sup); sup = record(sup)['super_index']
        row.update(object_reference=reference(row['index']),
            class_reference=reference(row['class_index']),
            super_reference=reference(row['super_index']),
            template_reference=reference(row['template_index']))

    selected_class = [r for r in exports if r['name'] == stem+'_C' and r['outer_index'] == 0]
    selected_cdo = [r for r in exports if r['name'] == 'Default__'+stem+'_C' and r['outer_index'] == 0]
    if len(selected_class) != 1 or len(selected_cdo) != 1:
        raise ValueError('Exactly one root generated class and named CDO required')
    klass, cdo = selected_class[0], selected_cdo[0]
    if (klass['class_reference'] != ['/Script/Engine', 'BlueprintGeneratedClass'] or
            cdo['class_index'] != klass['index'] or not int(cdo['serialized_object_flags'], 16)&0x10):
        raise ValueError('Serialized generated class/CDO type or CDO flag mismatch')

    def properties(row):
        at, size = row['serialized_uexp_offset'], row['serialized_bytes']
        raw = payload[at:at+size]
        try:
            decoded, end = tags(payload, at, names, at+size)
        except (ValueError, struct.error, UnicodeError) as error:
            return dict(tagged_property_prefix_decoded=False,
                parse_error=str(error), export_sha256=sha(raw), unparsed_export_bytes=size)
        return dict(tagged_property_prefix_decoded=True, export_sha256=sha(raw),
            property_terminator_end=end, remaining_export_bytes=at+size-end,
            remaining_export_sha256=sha(payload[end:at+size]),
            **(dict(remaining_export_bytes_hex=payload[end:at+size].hex())
               if row is klass and at+size-end <= 4096 else {}),
            tagged_properties=[dict(tag, value=_tag_value(payload, tag, names, reference),
                serialized_tag_sha256=sha(payload[tag['start']:tag['end']])) for tag in decoded])

    for row in (klass, cdo):
        row.update(properties(row))
    functions = [dict(r, **properties(r)) for r in exports
        if r['class_reference'] == ['/Script/CoreUObject', 'Function']]
    property_exports = [r for r in exports if r['class_reference'] and
        r['class_reference'][-1].endswith('Property')]
    return dict(package_path=meta['own_paths'][0], uasset_sha256=sha(header), uexp_sha256=sha(payload),
        serialized_names=names,
        custom_versions=[dict(guid_bytes_hex=header[24+i*20:40+i*20].hex(),
            value=struct.unpack_from('<i', header, 40+i*20)[0])
            for i in range(struct.unpack_from('<i', header, 20)[0])],
        import_count=ic, export_count=ec, name_count=len(names), imports=imports, exports=exports,
        class_export=klass, cdo_export=cdo, function_exports=functions,
        separate_property_exports=property_exports,
        relevant_name_tokens=[n for n in names if any(s.lower() in n.lower() for s in (
            'role', 'Replicated', 'MapID', 'RoomId', 'Uin', 'HeroId', 'AvatarId', 'NetRepActor',
            'Controller', 'PlayerState', 'Seamless', 'FieldOfView', 'Match', 'Abseil'))],
        cooked_tag_values_are_not_complete_reflected_declarations=True,
        class_native_serialization_tail_decoded=False, runtime_cached_cdo_pointer_observed=False,
        runtime_vtable_or_interface_adjustment_observed=False, numeric_wire_handles_recovered=False)


def derive(shadow):
    from recover_economy_pak_access import (pak_footer, validate_index, directory_index, entry_offset, decode_entry)
    from research_updated_content_resources import access
    from scan_weapon_tables import parse_entry
    import oodle_payload_reader
    executable = shadow/'DeltaForce/Binaries/Win64/DeltaForceClient-Win64-Shipping.exe'
    with executable.open('rb') as stream:
        if hashlib.file_digest(stream, 'sha256').hexdigest() != CLIENT_SHA:
            raise ValueError('Exact current shadow executable required')
    oodle_payload_reader.PATH = shadow/'DeltaForce/Binaries/Win64/oo2core_8_win64.dll'
    candidates, provenance = access()
    archives = sorted((shadow/'DeltaForce/Content/Paks').glob('*.pak'))
    if not 1 <= len(archives) <= MAX_PAKS:
        raise ValueError('Bounded complete shadow PAK directory required')
    reports, packages = [], []
    for path in archives:
        footer = pak_footer(path)
        clear = key = None
        for candidate in candidates:
            valid, clear, key = validate_index(path, footer, {footer['guid']: candidate})
            if clear is not None:
                break
        if clear is None or valid.get('index_sha1_valid') is not True:
            raise ValueError('Current archive index unqualified: '+path.name)
        details, files, encoded = directory_index(path, footer, clear, key)
        selected = [(name, location) for name, location in files if PATTERN.search(name)]
        decoded, matches = {}, []
        with path.open('rb') as stream:
            for name, location in selected:
                pos = entry_offset(encoded, location)
                entry = parse_entry(stream, pos, footer['offset'], variant='observed_permutation')
                if not 0 < entry['uncompressed'] <= MAX_PAYLOAD:
                    raise ValueError('Selected package exceeds decoded asset budget')
                raw, payload_valid = decode_entry(stream, pos, entry, footer['methods'], key)
                if not payload_valid:
                    raise ValueError('Current selected payload SHA1 mismatch')
                if name in decoded:
                    raise ValueError('Duplicate selected archive entry')
                decoded[name] = raw
                matches.append(dict(asset=name, entry_offset=pos, decoded_bytes=len(raw),
                    decoded_sha256=sha(raw), archive_payload_sha1_valid=True))
        for name in sorted(n for n in decoded if n.endswith('.uasset')):
            companion = name[:-7]+'.uexp'
            if companion not in decoded:
                raise ValueError('Selected package companion absent from same current archive')
            stem = Path(name).stem
            packages.append(dict(archive=path.name, archive_uasset=name,
                archive_uexp=companion, **parse_package(decoded[name], decoded[companion], stem)))
        if len(decoded) != 2*sum(n.endswith('.uasset') for n in decoded):
            raise ValueError('Unpaired selected companion')
        reports.append(dict(archive=path.name, archive_bytes=path.stat().st_size,
            footer_sha256=valid['footer_sha256'], index_sha1_valid=True,
            decoded_index_sha256=valid['decoded_index_sha256'],
            secondary_indices=details.get('secondary_indices', []), matches=matches))
    by_stem = {stem: [p for p in packages if p['package_path'].rsplit('/', 1)[-1] == stem] for stem in STEMS}
    if any(not rows for rows in by_stem.values()):
        raise ValueError('A requested current Blueprint package was not found')
    helpers = [Path(__file__), ROOT/'work/research_updated_cooked_declarations_test.py',
        ROOT/'work/research_updated_content_resources.py', ROOT/'work/recover_economy_pak_access.py',
        ROOT/'work/scan_weapon_tables.py', ROOT/'work/oodle_payload_reader.py',
        ROOT/'work/bundle_asset_locations_package.py', ROOT/'work/extract_operator_avatar_catalog.py']
    return dict(kind='current_cooked_blueprint_declaration_boundary', client_sha256=CLIENT_SHA,
        source_pins={p.relative_to(ROOT).as_posix(): sha(p.read_bytes()) for p in helpers},
        archive_count=len(archives), complete_directory_search=True, archives=reports,
        asset_access_candidate_provenance=provenance, asset_access_keys_disclosed=False,
        requested_variant_counts={k:len(v) for k,v in by_stem.items()}, packages=packages,
        runtime_metadata_read=False, native_engine_function_called=False, client_launched=False,
        runtime_files_changed=False, native_acceptance_verified=False)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--shadow', type=Path, default=SHADOW)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    output = args.output.resolve()
    if output.exists() or output.parent != ROOT/'work' or not output.name.startswith('research_'):
        parser.error('One fresh work/research_ report path required')
    result = derive(args.shadow.resolve())
    raw = (json.dumps(result, indent=2, ensure_ascii=True)+'\n').encode('ascii')
    with output.open('xb') as stream:
        stream.write(raw)
    print(json.dumps(dict(output=str(output), sha256=sha(raw), packages=len(result['packages']),
        archives=result['archive_count'], variants=result['requested_variant_counts'])))
