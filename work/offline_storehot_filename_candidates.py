"""Derive twelve filename candidates from pinned native rows and root strings.

No process access, native conversion, game-file writes, archive scans or asset edits.
"""

import argparse
import hashlib
import json
from pathlib import Path
import re

import probe_live_package_filename_headers as source


ROOT = source.prior.ROOT
ROW_CAPTURE = ROOT / 'work/evidence/live-storehot-image-rows-v2-20261005-private.json'
ROW_CAPTURE_SHA = 'fa383f30d94154ff6ce8fcb978c32d55f2a2f72dd8352461bc27563fc5f5a671'
CATALOG = ROOT / 'outputs/df-local-server/protocol/premium_shop_catalog.json'
CATALOG_SHA = '77372a31b2bf36ad8ba0da7540b736d809c14060321a98cecc8efca7663ec51b'
MATCH_CONTRACT = ROOT / 'work/evidence/package-root-match-contract-20261005.json'
MATCH_CONTRACT_SHA = 'a5d057e1ee48336990d97de7bbdad7c9e22b20ddb369f9e02cfb80d55b42055c'
SOURCE_TABS = (10101004, 10101008, 10101019, 10102002)
FIELDS = (('small', 'IamgeSourceSmall', 160, 'preview_asset'),
          ('big', 'IamgeSourceBig', 176, 'native_big_asset'),
          ('logo', 'ImageSourceLogo', 192, 'native_logo_asset'))
TABLE_PATH = '/Game/R13N/Common/Base/DataTables/StoreHotRecommendation'
OBJECT_PATTERN = re.compile(r"Texture2D'(?P<package>/[^'.]+)\.(?P<object>[^/'\.]+)'")


def pinned_json(path, digest, maximum):
    path = Path(path)
    if not path.is_file() or not 0 < path.stat().st_size <= maximum:
        raise ValueError('bounded_existing_offline_source_required')
    raw = path.read_bytes()
    if hashlib.sha256(raw).hexdigest() != digest:
        raise ValueError('offline_source_full_hash_changed: ' + path.name)
    return json.loads(raw)


def derive():
    roots = pinned_json(source.STRING_CAPTURE, source.STRING_CAPTURE_SHA, 65536)
    rows = pinned_json(ROW_CAPTURE, ROW_CAPTURE_SHA, 8 * 1024 * 1024)
    catalog = pinned_json(CATALOG, CATALOG_SHA, 8 * 1024 * 1024)
    match_contract = pinned_json(MATCH_CONTRACT, MATCH_CONTRACT_SHA, 65536)
    if (match_contract['native_pe_sha256'] != source.prior.SOURCE_PE
            or not match_contract['original_compare_extent']['original_full_PE_sha_verified']
            or match_contract['contract']['converter_R8D'] != 1
            or match_contract['contract']['mode_1_return_true_iff'] != 'bounded comparator EAX == 0'
            or match_contract['functions']['matcher']['cfg']['bytes'] != 213
            or match_contract['functions']['bounded_comparator']['cfg']['bytes'] != 165
            or match_contract['process_accessed'] or match_contract['native_called']):
        raise ValueError('qualified_offline_root_match_contract_required')
    if (roots['native_pe_sha256'] != source.prior.SOURCE_PE
            or roots['source_capture_sha256'] != source.ACCESSOR_CAPTURE_SHA
            or not roots['headers_characters_and_slot_rechecked']
            or not roots['character_pointer_contract_proven'] or roots['dynamic_root_array_read']):
        raise ValueError('qualified_stable_root_text_source_required')
    source.verify_converter(bytes.fromhex(roots['fixed_code']['PackageFilenameRoots']['bytes']))
    source.verify_getter(bytes.fromhex(roots['fixed_code']['PackageFilenameRootStateGetter']['bytes']))
    if bytes.fromhex(roots['fixed_code']['FStringCharacterAccessorPrefix']['bytes']) != source.ACCESSOR_LEAF_BYTES:
        raise ValueError('qualified_root_text_accessor_required')
    values = {}
    for name, header_rva in source.HEADERS.items():
        string = roots['strings'][name]
        if string['header']['rva'] != header_rva:
            raise ValueError('root_text_field_location_changed')
        pointer, count, maximum, size = source.bounded_header(header_rva, bytes.fromhex(string['header']['bytes']))
        raw = bytes.fromhex(string['bytes'])
        value = source.decode_utf16(raw, count)
        if (value != string['value'] or hashlib.sha256(raw).hexdigest() != string['sha256']
                or (count, maximum) != (string['count'], string['maximum'])):
            raise ValueError('root_text_body_changed')
        values[name] = value
    if (rows['native_pe_sha256'] != source.prior.SOURCE_PE
            or rows['target_configuration'] != 'StoreHotRecommendation'
            or rows['outer_names'] != [TABLE_PATH]
            or not rows['source_rowstruct_owner_verified']
            or not rows['runtime_RowStruct_identity_verified']
            or rows['missing_target_TabIds'] or rows['duplicate_target_TabIds']):
        raise ValueError('qualified_runtime_source_rows_required')
    entries = []
    for tab_id in SOURCE_TABS:
        native = [row for row in rows['rows'] if row['TabId'] == tab_id]
        exported = [row for row in catalog['recommendations'] if row['tab_id'] == tab_id]
        if len(native) != 1 or len(exported) != 1:
            raise ValueError('unique_native_and_catalog_TabId_required')
        native, exported = native[0], exported[0]
        for role, field, offset, catalog_field in FIELDS:
            item = native['fields'][field]
            value = item['value']
            if item['status'] != 'captured' or value != exported[catalog_field]:
                raise ValueError('exact_native_catalog_image_value_required')
            parsed = OBJECT_PATTERN.fullmatch(value)
            if parsed is None:
                raise ValueError('source_Texture2D_object_syntax_required')
            package, object_name = parsed.group('package', 'object')
            root = values['first_root']
            if not root or not package.startswith(root):
                raise ValueError('candidate_requires_literal_observed_first_root_prefix')
            root_units = root.encode('utf-16-le')
            if (roots['strings']['first_root']['count'] - 1 != len(root_units) // 2
                    or package.encode('utf-16-le')[:len(root_units)] != root_units):
                raise ValueError('source_root_match_equal_UTF16_unit_condition_required')
            candidate = values['first_prefix'] + package[len(root):] + values['extension']
            entries.append(dict(source_tab_id=tab_id, role=role, native_field=field,
                                native_field_offset=offset, native_row_name=native['row_name'],
                                catalog_export_row=exported['row'], catalog_source_offset=exported['offset'],
                                source_qualified_object=value, syntactic_package_path=package,
                                source_object_name=object_name, observed_root=root,
                                observed_replacement_prefix=values['first_prefix'],
                                observed_extension=values['extension'],
                                root_match_condition_source_proven=True,
                                root_match_mode=1, root_match_compare_units=len(root_units) // 2,
                                root_match_compare_result=0, root_match_result=True,
                                root_match_ASCII_table_branch_taken=False,
                                native_predicate_package_argument_observed=False,
                                relative_filename_candidate=candidate, native_filename_observed=False,
                                physical_archive_entry_resolved=False, texture_loaded=False))
    return dict(native_pe_sha256=source.prior.SOURCE_PE,
                sources={'native_rows': dict(path=str(ROW_CAPTURE), sha256=ROW_CAPTURE_SHA,
                         selected_table_outer=TABLE_PATH),
                         'catalog': dict(path=str(CATALOG), sha256=CATALOG_SHA),
                         'root_strings': dict(path=str(source.STRING_CAPTURE), sha256=source.STRING_CAPTURE_SHA,
                         captured_at_utc=roots['captured_at_utc']),
                         'root_match_contract': dict(path=str(MATCH_CONTRACT), sha256=MATCH_CONTRACT_SHA)},
                observed_fixed_strings=values, candidate_count=len(entries), candidates=entries,
                derivation='Syntactic source package, literal observed first-root prefix slicing, '
                           'observed replacement prefix and extension; offline candidate only',
                unresolved=['Append109ed8b0 and output-move d632b0 implementations',
                            'Native SetPath parsing and actual conversion result',
                            'Physical archive entry, texture resolution and rendered image'],
                native_called=False, process_accessed=False, physical_filename_observed=False)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path)
    args = parser.parse_args()
    result = derive()
    if args.output is None:
        print(json.dumps(result, indent=2))
    else:
        output = args.output.resolve()
        evidence = (ROOT / 'work/evidence').resolve()
        if not output.is_relative_to(evidence) or output == evidence or output.exists():
            raise ValueError('new_project_evidence_output_required')
        with output.open('x', encoding='utf-8') as stream:
            stream.write(json.dumps(result, indent=2) + '\n')
        print(json.dumps({'candidate_count': result['candidate_count'], 'output': str(output),
                          'physical_filename_observed': False}))


if __name__ == '__main__':
    main()
