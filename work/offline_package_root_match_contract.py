"""Qualify saved root-match code and its already captured bounded comparator.

Only immutable saved reports and two exact original-PE metadata records are read.
No process access, native calls, character-pointer follows or archive scans.
"""

import argparse
import hashlib
import json
from pathlib import Path
import struct

import offline_package_filename_roots_cfg as cfg
import probe_live_package_filename_headers as source


MATCH_CAPTURE = source.prior.ROOT / 'work/evidence/live-package-filename-root-match-bundle-20261005-private.json'
MATCH_CAPTURE_SHA = '946c20e5f0934a6280a649d051cc20d9957479fc8b797b310ecfc6277607dce3'
MATCH_SHA = '259513b3fe666c50661ec8f7e89d41da54b3cfb4dc4071242954a92de4df37ef'
COMPARE_CAPTURE = source.prior.ROOT / 'work/evidence/live-package-compare-bundle-20261005-private.json'
COMPARE_CAPTURE_SHA = 'a412582d25d1bfa12d727a735a8e16a1afd4083299e7986c7c7646ad70f47120'
COMPARE_SPAN_RVA = 0x10a137d0
COMPARE_SPAN_SHA = 'e25a9f37dd2f0049d09b5ba3ed0d4c047e15dbe674ef04682c19c0c3ebf9fba0'
COMPARE_RVA = 0x10a139d0
COMPARE_SIZE = 165
COMPARE_SHA = '144f75637264e8caedea8a34ae9dafa4958c1856c33b537ed3a63f9e620ebf35'
COMPARE_EDGE = (0x109f8849, bytes.fromhex('e882b10100'))
COMPARE_PDATA_OFFSET = 510233880
COMPARE_PDATA_BYTES = bytes.fromhex('d039a110753aa11058dee21b')
COMPARE_PDATA_SHA = '9b5eef473c4c31f72f52f55e1d1df89e6a505c77c8c172535887ed111137eb15'
COMPARE_UNWIND_OFFSET = 467849816
COMPARE_UNWIND_BYTES = bytes.fromhex('010f06000f7403000a64020005340100')
COMPARE_UNWIND_SHA = '77705a89aa2f1549da76a3c97bbe061f19df1c037b09638fbe0cc2fc137a11a8'


def pinned_report(path, digest):
    path = Path(path)
    if not path.is_file() or not 0 < path.stat().st_size <= 65536:
        raise ValueError('bounded_existing_saved_report_required')
    raw = path.read_bytes()
    if hashlib.sha256(raw).hexdigest() != digest:
        raise ValueError('saved_root_match_report_full_hash_changed')
    report = json.loads(raw)
    if report['native_pe_sha256'] != source.prior.SOURCE_PE:
        raise ValueError('saved_root_match_PE_source_changed')
    return report


def span(block, rva, size, digest):
    code = bytes.fromhex(block['bytes'])
    if ((block['rva'], block['size'], block['sha256']) != (rva, size, digest)
            or len(code) != size or hashlib.sha256(code).hexdigest() != digest):
        raise ValueError('saved_root_match_code_span_changed')
    return code


def qualify_saved_code():
    match = pinned_report(MATCH_CAPTURE, MATCH_CAPTURE_SHA)
    compare = pinned_report(COMPARE_CAPTURE, COMPARE_CAPTURE_SHA)
    if (match['source_capture_sha256'] != source.STRING_CAPTURE_SHA
            or not match['fresh_converter_full_span_verified']
            or not match['fresh_match_edges_and_R8D1_verified']
            or not match['source_extents_verified'] or not match['process_creation_rechecked']):
        raise ValueError('qualified_complete_converter_match_source_required')
    converter = span(match['fixed_code']['PackageFilenameRoots'], source.prior.ROOTS_TARGET_RVA,
                     source.prior.ROOTS_TARGET_SIZE, source.prior.ROOT_STATE_SOURCE_SHA)
    source.verify_converter(converter)
    source.verify_match_edges(converter)
    matcher = span(match['fixed_code']['PackageRootMatchHelper'], source.MATCH_RVA,
                   source.MATCH_SIZE, MATCH_SHA)
    site, witness = COMPARE_EDGE
    actual = matcher[site - source.MATCH_RVA:site - source.MATCH_RVA + len(witness)]
    if actual != witness or site + 5 + struct.unpack_from('<i', actual, 1)[0] != COMPARE_RVA:
        raise ValueError('direct_root_match_compare_edge_changed')
    if (compare['source_capture_sha256'] != '5f4d2c18050a5ea11969ccd8fd18289522aa5339e9eb9794ae79f66942294e3b'
            or not compare['fresh_direct_calls_verified'] or not compare['process_creation_rechecked']):
        raise ValueError('qualified_saved_compare_source_required')
    saved = span(compare['fixed_code']['CacheFStringCompare'], COMPARE_SPAN_RVA, 1024,
                 COMPARE_SPAN_SHA)
    offset = COMPARE_RVA - COMPARE_SPAN_RVA
    comparator = saved[offset:offset + COMPARE_SIZE]
    if hashlib.sha256(comparator).hexdigest() != COMPARE_SHA:
        raise ValueError('complete_bounded_root_compare_slice_changed')
    functions = {}
    for name, data, rva in (('matcher', matcher, source.MATCH_RVA),
                            ('bounded_comparator', comparator, COMPARE_RVA)):
        instructions, graph = cfg.decode_cfg(data, rva)
        if graph['instructions'] != graph['reachable_instructions']:
            raise ValueError('root_match_function_has_unreachable_instruction')
        functions[name] = dict(sha256=hashlib.sha256(data).hexdigest(), cfg=graph,
                              instructions=[dict(rva=hex(i.address), bytes=i.bytes.hex(),
                              mnemonic=i.mnemonic, operands=i.op_str) for i in instructions])
    return dict(native_pe_sha256=source.prior.SOURCE_PE,
                sources={'matcher_capture': dict(path=str(MATCH_CAPTURE), sha256=MATCH_CAPTURE_SHA),
                         'bounded_compare_capture': dict(path=str(COMPARE_CAPTURE), sha256=COMPARE_CAPTURE_SHA)},
                functions=functions, compare_direct_edge=dict(site=hex(site), bytes=witness.hex(),
                target=hex(COMPARE_RVA)),
                contract={'converter_R8D': 1, 'root_count_includes_terminal_NUL': True,
                          'compare_unit_count': 'root.Count - 1; root.Count == 0 gives zero',
                          'positive_root_length_required': True,
                          'mode_1_return_true_iff': 'bounded comparator EAX == 0',
                          'compare_units': 'UTF16', 'equal_unit_branch': 'No lookup table access',
                          'ASCII_unequal_unit_branch': 'Map both bytes using module RVA1aae7310, compare mapped values',
                          'non_ASCII_unequal_unit_branch': 'Return raw UTF16 input minus root',
                          'zero_unit_branch': 'Return zero on equal NUL units',
                          'no_external_comparator_calls': not functions['bounded_comparator']['cfg']['direct_calls'],
                          'ASCII_mapping_table_captured': False,
                          'enum_symbolic_name_proven': False},
                process_accessed=False, native_called=False, physical_filename_observed=False)


def qualify_original_extent(original_pe):
    with Path(original_pe).open('rb') as stream:
        if hashlib.file_digest(stream, 'sha256').hexdigest() != source.prior.SOURCE_PE:
            raise ValueError('original_source_executable_sha256_mismatch')
        source.verify_match_extent(original_pe)
        stream.seek(COMPARE_PDATA_OFFSET)
        pdata = stream.read(len(COMPARE_PDATA_BYTES))
        stream.seek(COMPARE_UNWIND_OFFSET)
        unwind = stream.read(len(COMPARE_UNWIND_BYTES))
    if (pdata != COMPARE_PDATA_BYTES or hashlib.sha256(pdata).hexdigest() != COMPARE_PDATA_SHA
            or struct.unpack('<III', pdata) != (COMPARE_RVA, COMPARE_RVA + COMPARE_SIZE, 0x1be2de58)
            or unwind != COMPARE_UNWIND_BYTES or hashlib.sha256(unwind).hexdigest() != COMPARE_UNWIND_SHA):
        raise ValueError('exact_original_root_compare_extent_changed')
    return dict(begin_rva=hex(COMPARE_RVA), end_exclusive_rva=hex(COMPARE_RVA + COMPARE_SIZE),
                bytes=COMPARE_SIZE, pdata_file_offset=COMPARE_PDATA_OFFSET,
                pdata_bytes=pdata.hex(), pdata_sha256=COMPARE_PDATA_SHA,
                unwind_file_offset=COMPARE_UNWIND_OFFSET, unwind_bytes=unwind.hex(),
                unwind_sha256=COMPARE_UNWIND_SHA, original_full_PE_sha_verified=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--original-pe', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    result = qualify_saved_code()
    result['original_compare_extent'] = qualify_original_extent(args.original_pe)
    output = args.output.resolve()
    evidence = (source.prior.ROOT / 'work/evidence').resolve()
    if not output.is_relative_to(evidence) or output.exists():
        raise ValueError('new_project_evidence_output_required')
    with output.open('x', encoding='utf-8') as stream:
        stream.write(json.dumps(result, indent=2) + '\n')
    print(json.dumps({'output': str(output), 'sha256': hashlib.sha256(output.read_bytes()).hexdigest(),
                      'matcher_instructions': result['functions']['matcher']['cfg']['instructions'],
                      'comparator_instructions': result['functions']['bounded_comparator']['cfg']['instructions'],
                      'process_accessed': False}))


if __name__ == '__main__':
    main()
