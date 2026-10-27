"""Plan source-bound missing shadow CDN caches; --execute only creates new files.

Requires the pinned original resource catalog and independently reviewed native
contract. Never writes the source installation, overwrites existing caches,
follows redirects, fabricates source paths, or inserts native image headers.
"""

import argparse
from concurrent.futures import ThreadPoolExecutor
import copy
import ctypes
from datetime import datetime, timezone
import hashlib
import http.client
import io
import json
import os
from pathlib import Path
import stat
import struct
import threading
import time
import uuid
import zlib

import check_bundle_cdn_resources as source


MANIFEST_SHA256 = '581ba0890e345a9a507f45ffd27b521a91535039e25b6659849081bf5a4509d3'
CRC_PROOF_SHA256 = '579c74538b3979e664c41bd7cbd2e06280bfd0b9518fe6c773bf67114ec620dc'
CRC_TABLE_SHA256 = '0053f121cdcaf9f510a940ba891fb2bccd41487953c5a4c0048c4a3ccdec782e'
NATIVE_CONTRACT_SHA256 = '8febd6264ddfd10ce30cc2ba5f177c6f1f1be6daf77f662810a6392301454e2c'
NATIVE_PAYLOAD_CONTROL_SHA256 = '153932f767a37e6cd24e8dc4ec812994c4e3d14ca5c34179f5b5b9c7c4395a15'
CODEC_SHA256 = 'fc923f9bbbf185ca6e853de0e3ebbc81c839323e6e161cd0f75058c60a2b05a6'
MAX_BYTES = 8 * 1024 * 1024
KNOWN_FIELDS = {272: 'cdn_big', 274: 'cdn_small', 276: 'cdn_logo_cn', 277: 'cdn_logo_en'}
OBSERVED_STANDARD_PNG = {
    'Resource/Store/C=CDABC4C963DA9D3B22869F4C22928085E81C11491534E3C6FFFCE64BCA5089271C6428D67B1D1C1DC3BDB6E678A19CBF9711668FA865990DD92CA5DDBF5D94AD.PNG': {
        'size': 11077506, 'sha256': '5ad810632f411765f1f958cb0ed5c003aa6cac9612ebdad7d9e98fb594405c64',
        'width': 3456, 'height': 1920, 'png_stream_bytes': 9086122},
    'Resource/Store/C=69DB3063DD2DBB10E969574E5C10A48F29F0176D659EA23B9FA3717F574D107DBC123F5E969317C39B27A5917EC85EA7AD9561FDA37BA0786A55FC11A68CCE76.PNG': {
        'size': 439995, 'sha256': 'c3cbdc91cf2797c04a471bb79273f12270b456d32ad969147700809ce6c1f3cb',
        'width': 640, 'height': 320, 'png_stream_bytes': 328847},
}


def body_limit_for_source(original):
    return max(MAX_BYTES, OBSERVED_STANDARD_PNG.get(original, {}).get('size', 0))


def crc_table():
    table = []
    for index in range(256):
        value = index << 24
        for _ in range(8):
            value = ((value << 1) ^ (0x04c11db7 if value & 0x80000000 else 0)) & 0xffffffff
        table.append(value)
    return tuple(table)


CRC_TABLE = crc_table()


def cache_basename(original):
    if not isinstance(original, str) or not source.RESOURCE_RE.fullmatch(original):
        raise ValueError('cache_key_requires_exact_full_original_source_reference')
    suffix = original.rsplit('/', 1)[-1].partition('=')[2]
    value = 0
    for byte in suffix.upper().encode('utf-16le'):
        value = (value >> 8) ^ CRC_TABLE[(value ^ byte) & 255]
    return 'C=' + str(value if value < 0x80000000 else value - 0x100000000)


def _block_bytes(block, rva, size, digest):
    if not isinstance(block, dict) or (block.get('rva'), block.get('size'), block.get('sha256')) != (rva, size, digest):
        raise ValueError('native_fixed_span_contract_mismatch')
    try:
        raw = bytes.fromhex(block['bytes'])
    except (KeyError, TypeError, ValueError):
        raise ValueError('native_fixed_span_bytes_invalid') from None
    if len(raw) != size or hashlib.sha256(raw).hexdigest() != digest:
        raise ValueError('native_fixed_span_sha256_mismatch')
    return raw


def verify_crc(proof, digest):
    if digest != CRC_PROOF_SHA256 or proof.get('native_pe_sha256') != source.EXPECTED_PE:
        raise ValueError('native_CRC_proof_input_not_pinned')
    block = proof.get('image_crc_table', {})
    raw = _block_bytes(block, 0x1d59ba40, 1024, CRC_TABLE_SHA256)
    if raw != struct.pack('<256I', *CRC_TABLE) or block.get('matches_original_pe_table') is not True:
        raise ValueError('native_CRC_table_not_the_source_proven_polynomial')
    for key, rva, value in (('disk_hash_branch_byte', 0x1ca2e143, 1),
                            ('disk_manager_override_byte', 0x1db47a60, 0)):
        scalar = proof.get(key, {})
        if (scalar.get('rva'), scalar.get('size'), scalar.get('value'), scalar.get('value_recheck')) != (rva, 1, value, value) or scalar.get('stable') is not True:
            raise ValueError('native_cache_branch_not_source_verified')
    _block_bytes(proof.get('image_processing_helpers', {}).get('Disk_BasenameHash'), 0xd61370, 512,
                 'f05a55f757700051f21c514f7fb0db1d3970b444b76d678a6031135ddc6cbf92')
    return True


def _reparse(info):
    return stat.S_ISLNK(info.st_mode) or bool(getattr(info, 'st_file_attributes', 0) & 0x400)


def _check_ancestors(path):
    for part in [*reversed(path.parents), path]:
        try:
            info = part.lstat()
        except FileNotFoundError:
            continue
        if _reparse(info):
            raise ValueError('symlink_or_reparse_path_is_not_a_repair_target')


def safe_roots(installed, shadow):
    installed, shadow = Path(os.path.abspath(installed)), Path(os.path.abspath(shadow))
    _check_ancestors(installed)
    _check_ancestors(shadow)
    if not installed.is_dir() or not shadow.is_dir():
        raise ValueError('explicit_existing_source_and_shadow_roots_required')
    installed, shadow = installed.resolve(), shadow.resolve()
    if installed.is_relative_to(shadow) or shadow.is_relative_to(installed):
        raise ValueError('source_and_shadow_roots_must_be_separate')
    return installed, shadow


def _target_state(shadow, target):
    shadow, target = Path(shadow), Path(target)
    if not target.is_absolute() or not target.is_relative_to(shadow):
        raise ValueError('cache_target_outside_explicit_shadow_root')
    relative = target.relative_to(shadow)
    if (relative.parts[:4] != ('DeltaForce', 'Saved', 'Cdn', 'G')
            or not source.re.fullmatch(r'C=-?[0-9]{1,10}', target.name)
            or not source._prefix('/'.join(relative.parts[3:-1]))):
        raise ValueError('cache_target_is_not_an_explicit_CDN_tree_path')
    _check_ancestors(target)
    try:
        info = target.lstat()
    except FileNotFoundError:
        return 'missing'
    if not stat.S_ISREG(info.st_mode):
        raise ValueError('existing_cache_target_is_not_a_regular_file')
    return 'existing_preserved'


def plan_targets(source_plan, installed, shadow, *, crc_verified, expected_counts=(219, 199)):
    installed, shadow = safe_roots(installed, shadow)
    if (crc_verified is not True or source_plan.get('native_url_composition_verified') is not True
            or source_plan.get('source_manifest_sha256') != MANIFEST_SHA256
            or source_plan.get('source_pe_sha256') != source.EXPECTED_PE):
        raise ValueError('repair_plan_requires_pinned_source_composition_and_CRC')
    root = source_plan.get('configuration_fields', {}).get(source.ROOT_FIELD)
    if root != 'G/CN':
        raise ValueError('repair_only_supports_observed_source_root')
    rows, targets, by_source, by_destination = [], [], {}, {}
    for source_row in source_plan.get('rows', []):
        row = {key: source_row[key] for key in ('table', 'row', 'row_offset', 'tab_id', 'goods_id') if key in source_row}
        row['resources'] = []
        for resource in source_row['resources']:
            item = {key: resource[key] for key in ('role', 'source_field_index', 'status')}
            if resource['status'] == 'candidate_urls_ready':
                original = resource.get('source_relative_path')
                if not isinstance(original, str) or not source.RESOURCE_RE.fullmatch(original):
                    raise ValueError('repair_requires_original_full_Resource_reference')
                if original not in by_source:
                    target = shadow / 'DeltaForce/Saved/Cdn' / root / original.rpartition('/')[0] / cache_basename(original)
                    if target in by_destination and by_destination[target] != original:
                        raise ValueError('distinct_source_references_collide_at_one_cache_target')
                    by_destination[target] = original
                    by_source[original] = len(targets)
                    targets.append({'id': len(targets), 'source_relative_path': original,
                                    'cache_relative_path': target.relative_to(shadow).as_posix(),
                                    'cache_basename': target.name, 'eligible': False,
                                    'status': _target_state(shadow, target), 'url': None,
                                    '_cache_path': target, '_shadow_root': shadow})
                index = by_source[original]
                item.update(target_id=index, source_relative_path=original)
                if KNOWN_FIELDS.get(item['source_field_index']) == item['role']:
                    targets[index]['eligible'] = True
                    item['status'] = 'confirmed_source_consumer'
                else:
                    item['status'] = 'unknown_source_consumer_excluded'
            row['resources'].append(item)
        rows.append(row)
    if (len(rows), len(targets)) != expected_counts:
        raise ValueError('pinned_source_manifest_row_or_distinct_path_count_changed')
    return {'schema_version': 1, 'mode': 'plan', 'source_manifest_sha256': MANIFEST_SHA256,
            'source_pe_sha256': source.EXPECTED_PE, 'rows': rows, 'targets': targets,
            'configuration_fields': source_plan['configuration_fields'], 'source_CRC_verified': True,
            'native_request_formula_verified': False, 'request_count': 0,
            'native_resource_binding_and_rendering_verified': False,
            'scope': 'Only original full source paths; unknown field roles are retained and excluded from automatic repair'}


def validate_native_contract(contract, digest):
    if (digest != NATIVE_CONTRACT_SHA256 or contract.get('schema_version') != 1
            or contract.get('source_pe_sha256') != source.EXPECTED_PE
            or contract.get('status') != 'source_and_rechecked_configuration_witnesses_verified'):
        raise ValueError('native_resource_contract_digest_not_pinned')
    config = contract.get('configuration', {})
    if config != {'default_base': 'https://cdn.df.qq.com', 'pc_base': 'https://repo.df.qq.com',
                  'root': 'G/CN', 'selected_base_role': 'pc'}:
        raise ValueError('native_resource_configuration_contract_changed')
    flags = contract.get('proof_flags', {})
    if flags.get('source_url_processing_verified') is not True or flags.get('cache_read_filename_transform_verified') is not True:
        raise ValueError('native_resource_formula_not_verified')
    processing = contract.get('request_processing', {})
    expected = {'cache_key_uses_original_source': True, 'extension_gate': 0, 'quality_gate': 0,
                'quality_enum': 3, 'quality_integer': 7,
                'extensionless_rule': 'insert_quality_directory_before_original_basename',
                'literal_extension_rule': 'preserve_input', 'original_extension_case_preserved': True,
                'quality_table': [0, 5, 6, 7, 23, 39, 55, 56]}
    if any(processing.get(key) != value for key, value in expected.items()):
        raise ValueError('native_request_processing_contract_changed')
    naming = contract.get('cache_filename', {})
    if (naming.get('table_sha256') != CRC_TABLE_SHA256
            or hashlib.sha256(struct.pack('<256I', *CRC_TABLE)).hexdigest() != CRC_TABLE_SHA256
            or naming.get('initial_crc') != 0 or naming.get('final_xor') != 0):
        raise ValueError('native_cache_CRC_contract_changed')
    return config


def source_plan_from_manifest(manifest, digest, config):
    if digest != MANIFEST_SHA256 or manifest.get('schema_version') != 1 or not isinstance(manifest.get('entries'), list):
        raise ValueError('original_source_manifest_sha256_or_schema_changed')
    rows = []
    for entry in manifest['entries']:
        if entry.get('table') not in ('recommendations', 'gifts'):
            raise ValueError('unsupported_original_source_table')
        row = {key: entry[key] for key in ('table', 'row', 'row_offset', 'tab_id', 'goods_id') if key in entry}
        if any(type(row.get(key)) is not int or not 0 <= row[key] < 2 ** 63 for key in ('row', 'row_offset')):
            raise ValueError('invalid_original_source_row')
        row['resources'] = []
        for resource in entry['resources']:
            index, role, value = resource.get('source_field_index'), resource.get('role'), resource.get('value')
            if type(index) is not int or not 0 <= index < 65536 or not isinstance(role, str) or not source.ROLE_RE.fullmatch(role):
                raise ValueError('invalid_original_source_field')
            item = {'source_field_index': index, 'role': role}
            if resource.get('source_status') == 'empty_in_source' and value == '':
                item['status'] = 'empty_in_source'
            elif resource.get('source_status') != 'nonempty_verified':
                item['status'] = 'source_value_not_verified'
            elif resource.get('kind') != 'cdn_relative_reference' or not isinstance(value, str) or not source.RESOURCE_RE.fullmatch(value):
                item['status'] = 'not_full_source_cdn_reference'
            else:
                item.update(status='candidate_urls_ready', source_relative_path=value)
            row['resources'].append(item)
        rows.append(row)
    return {'rows': rows, 'source_manifest_sha256': digest, 'native_url_composition_verified': True,
            'source_pe_sha256': source.EXPECTED_PE,
            'configuration_fields': {source.DEFAULT_FIELD: config['default_base'],
                                     source.PC_FIELD: config['pc_base'], source.ROOT_FIELD: config['root']}}


def apply_native_contract(plan, contract, digest, *, branch='pc'):
    config = validate_native_contract(contract, digest)
    if branch not in ('pc', 'default'):
        raise ValueError('repair_requires_one_observed_source_base_branch')
    for target in plan['targets']:
        original = target['source_relative_path']
        if not source.RESOURCE_RE.fullmatch(original):
            raise ValueError('repair_target_is_not_an_original_source_reference')
        directory, _, basename = original.rpartition('/')
        processed = original if Path(basename).suffix else directory + '/7/' + basename
        target['processed_relative_path'] = processed
        target['url'] = config[branch + '_base'] + '/' + config['root'] + '/' + processed
        source._request_url(target['url'])
        target['branch_status'] = 'source_selected_in_snapshot' if branch == 'pc' else 'alternate_observed_base'
    plan.update(native_request_formula_verified=True, source_native_contract_sha256=digest,
                source_configuration_capture_sha256=contract['capture_provenance']['settings_capture_sha256'],
                source_code_capture_sha256=contract['capture_provenance']['code_capture_sha256'],
                selected_repair_base_role=branch,
                native_http_request_execution_verified=False, native_current_getter_result_verified=False,
                download_body_direct_cache_bytes_generally_verified=False)
    return plan


def _png_stream_end(body):
    at, seen_header, seen_data = 8, False, False
    while at + 12 <= len(body):
        length = struct.unpack_from('>I', body, at)[0]
        end = at + 12 + length
        if end > len(body):
            break
        kind, payload = body[at + 4:at + 8], body[at + 8:end - 4]
        if zlib.crc32(kind + payload) & 0xffffffff != struct.unpack_from('>I', body, end - 4)[0]:
            break
        if not seen_header:
            if kind != b'IHDR' or length != 13:
                break
            seen_header = True
        elif kind == b'IHDR':
            break
        seen_data |= kind == b'IDAT'
        if kind == b'IEND':
            return end if seen_header and seen_data and length == 0 else None
        at = end
    return None


def _png_complete(body):
    return _png_stream_end(body) == len(body)


def verify_native_payload_control(control, digest):
    observed = control.get('GET', {})
    bounded = control.get('bounded_native_payload_validation', {})
    expected = 'bdb3fbcb1b708ed3212ce2587a0edfe5d0810d714c7bf77b7f92170c480298eb'
    if (digest != NATIVE_PAYLOAD_CONTROL_SHA256
            or control.get('source_manifest_sha256') != MANIFEST_SHA256
            or control.get('source_native_contract_sha256') != NATIVE_CONTRACT_SHA256
            or control.get('payload_equals_observed_cache') is not True
            or control.get('cache_sha256_before') != expected or control.get('cache_sha256_after') != expected
            or observed.get('sha256') != expected or observed.get('http_status') != 200
            or observed.get('bytes') != 51807
            or bounded.get('matches_existing_bounded_decompression_sha256') is not True
            or bounded.get('decompressed_size') != 204800):
        raise ValueError('native_payload_control_is_not_the_pinned_existing_cache_byte_match')
    return True


def native_payload_decoder(installed):
    path = installed / 'DeltaForce/Binaries/Win64/oo2core_8_win64.dll'
    if not path.is_file() or _file_sha(path) != CODEC_SHA256:
        raise ValueError('original_pure_codec_sha256_changed_or_missing')
    try:
        import pefile
    except ImportError:
        raise ValueError('pefile_required_to_verify_original_pure_codec_dependencies') from None
    pe = pefile.PE(str(path), fast_load=True)
    try:
        pe.parse_data_directories(directories=[0, 1])
        imports = {entry.dll.decode('ascii').lower() for entry in pe.DIRECTORY_ENTRY_IMPORT}
        allowed = {'kernel32.dll', 'ntdll.dll', 'msvcrt.dll', 'ucrtbase.dll', 'advapi32.dll',
                   'vcruntime140.dll', 'vcruntime140_1.dll', 'user32.dll'}
        if pe.FILE_HEADER.Machine != 0x8664 or any(name not in allowed and not name.startswith('api-ms-win-') for name in imports):
            raise ValueError('original_pure_codec_architecture_or_dependencies_changed')
    finally:
        pe.close()
    if os.name != 'nt':
        raise ValueError('original_pure_codec_requires_Windows')
    library = ctypes.WinDLL(str(path), winmode=0x1000)
    fn = library.OodleLZ_Decompress
    fn.restype = ctypes.c_ssize_t
    fn.argtypes = [ctypes.c_void_p, ctypes.c_ssize_t, ctypes.c_void_p, ctypes.c_ssize_t,
                   ctypes.c_int, ctypes.c_int, ctypes.c_int, ctypes.c_void_p, ctypes.c_ssize_t,
                   ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p, ctypes.c_ssize_t, ctypes.c_int]
    lock = threading.Lock()
    def decode(payload, expected):
        if not isinstance(payload, bytes) or not 0 < len(payload) <= MAX_BYTES or type(expected) is not int or not 0 < expected <= MAX_BYTES:
            raise ValueError('native_payload_codec_input_or_output_size_outside_bound')
        compressed, decoded = ctypes.create_string_buffer(payload), ctypes.create_string_buffer(expected)
        with lock:
            written = fn(compressed, len(payload), decoded, expected, 1, 1, 0, None, 0, None, None, None, 0, 3)
        if written != expected:
            raise ValueError('native_payload_codec_returned_wrong_output_length')
        return decoded.raw
    return decode


def validate_image(body, *, native_decoder=None, native_payload_verified=False, original_source=None):
    approved = OBSERVED_STANDARD_PNG.get(original_source)
    bound = body_limit_for_source(original_source)
    if not isinstance(body, bytes) or not 0 < len(body) <= bound:
        raise ValueError('repair_payload_exceeds_byte_bound_or_is_empty')
    if approved and (len(body) != approved['size'] or hashlib.sha256(body).hexdigest() != approved['sha256']):
        raise ValueError('observed_standard_PNG_exact_source_body_pin_changed')
    if body.startswith(b'\x89PNG\r\n\x1a\n'):
        if len(body) > 40 and struct.unpack_from('<I', body, 8)[0] == 3:
            if native_payload_verified is not True or native_decoder is None:
                raise ValueError('native_payload_requires_existing_byte_match_proof_and_bounded_codec')
            version, width, height, expected, pixel_format, _, flag1, flag2 = struct.unpack_from('<8I', body, 8)
            if (not 0 < width <= 8192 or not 0 < height <= 8192 or not 0 < expected <= MAX_BYTES
                    or expected != ((width + 3) // 4) * ((height + 3) // 4) * 16
                    or (pixel_format, flag1, flag2) != (7, 1, 4)):
                raise ValueError('native_payload_header_outside_existing_observed_pattern_or_bound')
            decoded = native_decoder(body[40:], expected)
            if not isinstance(decoded, bytes) or len(decoded) != expected:
                raise ValueError('native_payload_did_not_decompress_to_exact_bounded_size')
            return {'format': 'native_serialized_image_with_png_signature',
                    'width_inferred_from_header': width, 'height_inferred_from_header': height,
                    'size': len(body), 'sha256': hashlib.sha256(body).hexdigest(),
                    'oodle_payload_offset': 40, 'bounded_oodle_decompression_verified': True,
                    'decompressed_size': expected, 'decompressed_sha256': hashlib.sha256(decoded).hexdigest(),
                    'header_field_semantics_native_verified': False,
                    'native_texture_decoding_or_rendering_verified': False}
        end = _png_stream_end(body)
        if end is None or (approved and end != approved['png_stream_bytes']) or (not approved and end != len(body)):
            raise ValueError('repair_PNG_structure_or_checksum_invalid')
        expected = 'PNG'
    elif body.startswith(b'\xff\xd8') and body.endswith(b'\xff\xd9'):
        expected = 'JPEG'
    else:
        raise ValueError('unknown_or_unproven_native_payload_format_not_written')
    try:
        from PIL import Image
    except ImportError:
        raise ValueError('Pillow_required_for_complete_image_payload_validation') from None
    try:
        with Image.open(io.BytesIO(body)) as image:
            if image.format != expected or not 0 < image.width <= 8192 or not 0 < image.height <= 8192 or image.width * image.height > 32 * 1024 * 1024:
                raise ValueError('repair_image_format_or_dimensions_outside_bound')
            width, height = image.size
            if approved and (width, height) != (approved['width'], approved['height']):
                raise ValueError('observed_standard_PNG_source_dimensions_changed')
            image.verify()
        with Image.open(io.BytesIO(body)) as image:
            image.load()
    except (OSError, SyntaxError, ValueError, Image.DecompressionBombError):
        raise ValueError('repair_image_body_did_not_fully_validate') from None
    metadata = {'format': expected, 'width': width, 'height': height,
                'size': len(body), 'sha256': hashlib.sha256(body).hexdigest()}
    if approved:
        metadata.update(observed_exact_source_body_pin_verified=True,
                        png_stream_bytes=approved['png_stream_bytes'],
                        original_png_trailing_bytes_preserved=len(body) - approved['png_stream_bytes'])
    return metadata


def publish_new_cache(shadow, target, body, *, native_decoder=None, native_payload_verified=False, original_source=None):
    metadata = validate_image(body, native_decoder=native_decoder, native_payload_verified=native_payload_verified,
                              original_source=original_source)
    if _target_state(shadow, target) == 'existing_preserved':
        return {'status': 'existing_preserved'}
    for parent in reversed(target.parent.parents):
        if parent == shadow or parent.is_relative_to(shadow):
            if not parent.exists():
                parent.mkdir(exist_ok=True)
            _check_ancestors(parent)
    if not target.parent.exists():
        target.parent.mkdir(exist_ok=True)
    _check_ancestors(target.parent)
    temporary = target.parent / ('.bundle-repair-' + uuid.uuid4().hex)
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, 'O_BINARY', 0) | getattr(os, 'O_NOFOLLOW', 0)
    created = False
    try:
        descriptor = os.open(temporary, flags, 0o600)
        created = True
        with os.fdopen(descriptor, 'wb') as handle:
            handle.write(body)
            handle.flush()
            os.fsync(handle.fileno())
        if _target_state(shadow, target) == 'existing_preserved':
            return {'status': 'existing_preserved'}
        try:
            os.link(temporary, target)
        except FileExistsError:
            return {'status': 'existing_preserved'}
        return {'status': 'created', **metadata}
    finally:
        if created:
            _check_ancestors(temporary)
            temporary.unlink()


def _phase_budget(connection, response, deadline):
    remaining = deadline - time.monotonic()
    if remaining <= 0:
        raise TimeoutError('repair_request_deadline_exceeded')
    connection.timeout = remaining
    for sock in (getattr(connection, 'sock', None),
                 getattr(getattr(getattr(response, 'fp', None), 'raw', None), '_sock', None)):
        if sock is not None:
            sock.settimeout(remaining)


def download_original(url, *, timeout=10, max_bytes=MAX_BYTES, connection_factory=None):
    host, path = source._request_url(url)
    approved_bound = MAX_BYTES
    for original in OBSERVED_STANDARD_PNG:
        if path == '/G/CN/' + original:
            approved_bound = body_limit_for_source(original)
    if type(timeout) not in (int, float) or not 0 < timeout <= 10 or type(max_bytes) is not int or not 0 < max_bytes <= approved_bound:
        raise ValueError('repair_request_timeout_or_byte_bound_invalid')
    response, connection, count = None, None, 0
    deadline = time.monotonic() + timeout
    try:
        connection = (connection_factory or http.client.HTTPSConnection)(host, timeout=timeout)
        _phase_budget(connection, None, deadline)
        if callable(getattr(connection, 'connect', None)):
            connection.connect()
        _phase_budget(connection, None, deadline)
        connection.request('GET', path, headers={'Connection': 'close', 'Accept-Encoding': 'identity'})
        _phase_budget(connection, None, deadline)
        response = connection.getresponse()
        _phase_budget(connection, response, deadline)
        status = response.status
        if type(status) is not int or not 100 <= status <= 599:
            return {'status': 'invalid_HTTP_status', 'bytes': 0}
        if 300 <= status < 400:
            from check_bundle_cdn_cache_controls import public_redirect_location
            getter = getattr(response, 'getheader', None)
            location = public_redirect_location(getter('Location'), url) if callable(getter) else {'location_status': 'not_observed'}
            return {'status': 'redirect_not_followed' if 'location' in location else 'redirect_rejected',
                    'http_status': status, 'bytes': 0, **location}
        if status != 200:
            return {'status': 'HTTP_response_body_not_read', 'http_status': status, 'bytes': 0}
        body = bytearray()
        while True:
            _phase_budget(connection, response, deadline)
            chunk = getattr(response, 'read1', response.read)(min(65536, max_bytes + 1 - count))
            count += len(chunk)
            if time.monotonic() >= deadline:
                return {'status': 'request_deadline_exceeded', 'http_status': 200, 'bytes': count}
            if count > max_bytes:
                return {'status': 'body_exceeds_bound', 'http_status': 200, 'bytes': count}
            if not chunk:
                return {'status': 'body_received', 'http_status': 200, 'bytes': count, '_body': bytes(body)}
            body.extend(chunk)
    except TimeoutError:
        return {'status': 'request_timeout', 'bytes': count}
    except (OSError, ValueError, http.client.HTTPException):
        return {'status': 'request_failed', 'bytes': count}
    finally:
        for item in (response, connection):
            if item is not None:
                try:
                    item.close()
                except OSError:
                    pass


def run_repair(plan, *, execute=False, downloader=None, workers=4, limit=None, native_decoder=None):
    if type(workers) is not int or not 1 <= workers <= 4 or limit is not None and (type(limit) is not int or not 1 <= limit <= 199):
        raise ValueError('repair_concurrency_or_limit_invalid')
    if execute and plan.get('native_request_formula_verified') is not True:
        raise ValueError('repair_execution_requires_reviewed_native_request_formula')
    targets = plan['targets']
    def process(target):
        row = {key: value for key, value in target.items() if not key.startswith('_')}
        if not target['eligible'] or not execute:
            return row
        try:
            state = _target_state(target['_shadow_root'], target['_cache_path'])
        except (ValueError, OSError):
            row['status'] = 'unsafe_or_unreadable_target_not_requested'
            return row
        if state == 'existing_preserved':
            row['status'] = state
            return row
        source._request_url(target['url'])
        observed = (downloader(target['url']) if downloader else
                    download_original(target['url'], max_bytes=body_limit_for_source(target['source_relative_path'])))
        row['GET'] = {key: value for key, value in observed.items() if key in ('status', 'http_status', 'bytes', 'location_status', 'location')}
        row['request_sent'] = True
        row['status'] = observed['status']
        if observed.get('status') == 'body_received':
            try:
                row.update(publish_new_cache(target['_shadow_root'], target['_cache_path'], observed['_body'],
                                             native_decoder=native_decoder,
                                             native_payload_verified=plan.get('native_payload_control_verified') is True,
                                             original_source=target['source_relative_path']))
            except ValueError:
                row['status'] = 'payload_or_target_validation_failed_not_written'
            except OSError:
                row['status'] = 'cache_publication_failed'
        return row
    eligible = [target['id'] for target in targets if target['eligible'] and target['status'] == 'missing']
    selected = set(eligible if limit is None else eligible[:limit])
    if execute:
        with ThreadPoolExecutor(max_workers=workers) as executor:
            completed = list(executor.map(process, [target for target in targets if target['id'] in selected]))
        by_id = {target['id']: target for target in completed}
    else:
        by_id = {}
    result = {key: copy.deepcopy(value) for key, value in plan.items() if key != 'targets'}
    result['targets'] = [by_id.get(target['id'], {key: value for key, value in target.items() if not key.startswith('_')}) for target in targets]
    result.update(mode='execute' if execute else 'plan', request_count=sum(bool(target.get('request_sent')) for target in result['targets']),
                  created_count=sum(target['status'] == 'created' for target in result['targets']),
                  existing_cache_overwritten=False, redirects_followed=False, authentication_sent=False,
                  source_installation_written=False, response_body_persisted_outside_new_cache=False)
    return result


def _file_sha(path):
    digest = hashlib.sha256()
    with path.open('rb') as handle:
        for chunk in iter(lambda: handle.read(4 * 1024 * 1024), b''):
            digest.update(chunk)
    return digest.hexdigest()


def build_parser():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--resources', type=Path, default=source.ROOT / 'outputs/df-local-server/protocol/premium_shop_resources.json')
    parser.add_argument('--native-contract', type=Path, default=source.ROOT / 'outputs/df-local-server/protocol/premium_shop_native_resource_contract.json')
    parser.add_argument('--native-payload-proof', type=Path,
                        default=source.ROOT / 'outputs/df-local-server/protocol/premium_shop_native_cache_control.json',
                        help='Pinned existing native-cache payload match; explicit paths retain the same digest gate')
    parser.add_argument('--game-root', type=Path, required=True)
    parser.add_argument('--shadow-root', type=Path, required=True)
    parser.add_argument('--execute', action='store_true')
    parser.add_argument('--branch', choices=('pc', 'default'), default='pc')
    parser.add_argument('--workers', type=int, default=4)
    parser.add_argument('--limit', type=int)
    parser.add_argument('--output', type=Path)
    return parser


def main():
    parser = build_parser()
    args = parser.parse_args()
    try:
        installed, shadow = safe_roots(args.game_root, args.shadow_root)
        pe = installed / 'DeltaForce/Binaries/Win64/DeltaForceClient-Win64-Shipping.exe'
        if not pe.is_file():
            raise ValueError('original_source_executable_missing')
        if _file_sha(pe) != source.EXPECTED_PE:
            raise ValueError('original_source_executable_sha256_changed')
        manifest, manifest_sha = source._load(args.resources, MAX_BYTES)
        if manifest_sha != MANIFEST_SHA256:
            raise ValueError('original_source_manifest_sha256_changed')
        contract, contract_sha = source._load(args.native_contract, MAX_BYTES)
        config = validate_native_contract(contract, contract_sha)
        original_plan = source_plan_from_manifest(manifest, manifest_sha, config)
        plan = plan_targets(original_plan, installed, shadow, crc_verified=True)
        plan = apply_native_contract(plan, contract, contract_sha, branch=args.branch)
        decoder = None
        if args.native_payload_proof:
            control, control_sha = source._load(args.native_payload_proof, MAX_BYTES)
            plan['native_payload_control_verified'] = verify_native_payload_control(control, control_sha)
            plan['source_native_payload_control_sha256'] = control_sha
            plan['original_pure_codec_sha256'] = CODEC_SHA256
            if args.execute:
                decoder = native_payload_decoder(installed)
        if args.output:
            output = Path(os.path.abspath(args.output))
            if not output.is_relative_to(source.EVIDENCE.resolve()):
                raise ValueError('repair_metadata_output_requires_private_work_evidence_directory')
            _check_ancestors(output)
            if output.exists():
                raise ValueError('repair_metadata_report_already_exists')
        started = datetime.now(timezone.utc).isoformat()
        result = run_repair(plan, execute=args.execute, workers=args.workers, limit=args.limit, native_decoder=decoder)
        result.update(started_at_utc=started, finished_at_utc=datetime.now(timezone.utc).isoformat(),
                      generator_sha256=_file_sha(Path(__file__)))
        text = json.dumps(result, indent=2) + '\n'
        if args.output:
            output.parent.mkdir(parents=True, exist_ok=True)
            with output.open('x', encoding='utf-8') as handle:
                handle.write(text)
            print(json.dumps({'report': output.name, 'mode': result['mode'], 'rows': len(result['rows']),
                              'targets': len(result['targets']), 'requests': result['request_count'],
                              'created': result['created_count']}))
        else:
            print(text, end='')
    except OSError:
        parser.error('repair_input_or_explicit_target_not_accessible')
    except ValueError as exc:
        parser.error(str(exc))


if __name__ == '__main__':
    main()
