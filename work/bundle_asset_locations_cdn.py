"""Read fixed source-proven CDN witnesses from files; never execute native code."""

import argparse
from collections import Counter
import hashlib
import json
from pathlib import Path
import re
import struct

from local_game_paths import game_paths, project_path


ROOT = Path(__file__).resolve().parents[1]
EXPECTED_PE = '4254fbe66585f260f1f9dbfc5e302887842552e7baed8939e023160a5e250be0'
PE_RELATIVE = 'DeltaForce/Binaries/Win64/DeltaForceClient-Win64-Shipping.exe'
WITNESSES = [
    (351150912, 'ascii', 'DefaultCDNUrl'),
    (351150928, 'ascii', 'CDNUrl_PC'),
    (351150944, 'ascii', 'CDNFallbackDomains'),
    (351150968, 'ascii', 'CDNFallbackDomains_PC'),
    (351160408, 'ascii', 'CDNRoot'),
    (412465720, 'utf-16le', 'yunkong.config'),
    (412467496, 'utf-16le', 'cdn.meta'),
    (412469784, 'utf-16le', 'cdnkey'),
    (412469800, 'utf-16le', 'Get CDNUrl = %s'),
    (412472336, 'utf-16le', 'Get CDNKey Failed! Do not find key named: cdnkey! %s'),
    (412472448, 'utf-16le', 'Get New CDNUrl From Maple: %s'),
    (362874168, 'ascii', 'ExtractCryptoJson'),
    (362874624, 'ascii', 'CryptoKeys'),
    (362874648, 'ascii', 'bUseDefaultCryptoIni'),
    (362874672, 'ascii', 'bEncryptIndex'),
    (362874688, 'ascii', 'PakEncryptSettings'),
]
CAPTURE_SPANS = {
    'MapleRow_GetCDNUrl_callback': (0xe07e90, 160),
    'AppRow_GetCDNUrl_callback': (0xe08030, 160),
    'AppSetting_GetCDNUrl_callback': (0xe082c0, 160),
    'IconManager_GetCDNUrl_callback': (0x11f0830, 160),
    'IconManager_GetFinalDiskPath_callback': (0x11f0850, 160),
    'CDNConfig_GetCDNUrl_callback': (0xd189650, 160),
    'FString_row_binding': (0xe01410, 512),
    'FString_static_binding': (0xdfded0, 512),
    'FString_manager_binding': (0x1162d70, 512),
}
CALLBACK_METHODS = {
    'MapleRow_GetCDNUrl_callback': (0xe07ea2, 0xdbcfb0),
    'AppRow_GetCDNUrl_callback': (0xe08042, 0xdbcd20),
    'AppSetting_GetCDNUrl_callback': (0xe082c9, 0xdbd170),
    'IconManager_GetCDNUrl_callback': (0x11f0842, 0x11e5c70),
    'IconManager_GetFinalDiskPath_callback': (0x11f0862, 0x11e6200),
    'CDNConfig_GetCDNUrl_callback': (0xd189660, 0xd61ec0),
}
PUBLIC_LOG = re.compile(
    rb'Get CDNUrl =|Get New CDNUrl From Maple:|PC CDNUrl IsEmpty|'
    rb'ReqCdnDownload:|OnReady_Internal: Begin download:|UDFCDNImage:|'
    rb'CDNDown (?:DownFailed|DownloadFile|DownloadResdet)|'
    rb'UCDNIconDownManager::(?:LoadDiskImage|DecodeImageData)|'
    rb'Init Maple succ, used url:|CDNInfo has not init yet!|'
    rb'CDN Config has not loaded yet!|Config File Hash Has Been Changed!|'
    rb'Meta File Is Empty! Decrypt Failed|Decrypt Config Failed Or Invalid Json Text!|'
    rb'cdn\.meta|yunkong\.config', re.I)
PRIVATE_LOG = re.compile(rb'authorization|session|ticket|token|password', re.I)


def digest_file(path):
    digest = hashlib.sha256()
    with path.open('rb') as handle:
        for block in iter(lambda: handle.read(4 * 1024 * 1024), b''):
            digest.update(block)
    return digest.hexdigest()


def fixed_pe_witnesses(path):
    digest = digest_file(path)
    if digest != EXPECTED_PE:
        raise ValueError('Native PE differs from the source-proven fixed witness version')
    rows = []
    with path.open('rb') as handle:
        for offset, encoding, value in WITNESSES:
            expected = value.encode(encoding) + bytes(2 if encoding == 'utf-16le' else 1)
            handle.seek(offset)
            data = handle.read(len(expected))
            if data != expected:
                raise ValueError(f'Fixed source text differs at PE offset {offset}')
            rows.append({'file_offset': offset, 'encoding': encoding, 'value': value,
                         'bytes_read': len(data), 'span_sha256': hashlib.sha256(data).hexdigest(),
                         'exact_text_and_termination_verified': True})
    return {'path': path.as_posix(), 'size': path.stat().st_size, 'sha256': digest,
            'fixed_string_witnesses': rows,
            'limit': 'Reflection/config/log names establish source routes, not their current values or native branch selection'}


def pak_footer(path):
    size = path.stat().st_size
    with path.open('rb') as handle:
        start = max(0, size - 512)
        handle.seek(start)
        tail = handle.read(512)
    marker = tail.rfind(struct.pack('<I', 0x5a6f12e1))
    if marker < 17 or marker + 44 > len(tail):
        raise ValueError('Unsupported fixed PAK footer')
    version, index_offset, index_size = struct.unpack_from('<Iqq', tail, marker + 4)
    if not 0 <= index_offset < size or not 0 < index_size <= size - index_offset:
        raise ValueError('PAK footer index bounds invalid')
    return {'path': path.as_posix(), 'size': size, 'pak_version': version,
            'tail_read_offset': start, 'tail_bytes_read': len(tail),
            'tail_sha256': hashlib.sha256(tail).hexdigest(), 'footer_magic_file_offset': start + marker,
            'key_guid_file_offset': start + marker - 17,
            'encryption_key_guid_hex': tail[marker - 17:marker - 1].hex(),
            'index_offset': index_offset, 'index_size': index_size,
            'index_encrypted': tail[marker - 1],
            'stored_index_sha1_hex': tail[marker + 24:marker + 44].hex(),
            'key_available_or_index_decryption_verified': False}


def public_log_witnesses(path):
    raw = path.read_bytes()
    bom = 3 if raw.startswith(b'\xef\xbb\xbf') else 0
    decoded = bytes(value ^ 0x5c for value in raw[bom:])
    result, count, offset = [], 0, bom
    for number, line in enumerate(decoded.splitlines(keepends=True), 1):
        match = PUBLIC_LOG.search(line)
        if match and not PRIVATE_LOG.search(line):
            count += 1
            if len(result) < 32:
                result.append({'decoded_line': number, 'raw_line_byte_offset': offset,
                               'raw_matched_text_byte_offset': offset + match.start(),
                               'value': line.decode('utf-8', 'replace').strip()[:1500]})
        offset += len(line)
    return {'path': path.as_posix(), 'snapshot_bytes': len(raw),
            'raw_snapshot_sha256': hashlib.sha256(raw).hexdigest(),
            'decode_basis': 'Existing native-log watcher XOR 0x5c after optional UTF-8 BOM',
            'decoded_pak_log_token_count': decoded.count(b'LogPakFile'),
            'public_config_diagnostic_line_count': count, 'public_config_witnesses': result,
            'complete_allowed_line_output': count <= 32}


def compare_fixed_capture(pe, capture_path):
    if capture_path.stat().st_size > 128 * 1024:
        raise ValueError('Fixed CDN capture exceeds the bounded report scope')
    capture = json.loads(capture_path.read_text(encoding='utf-8'))
    if capture.get('native_pe_sha256') != EXPECTED_PE or set(capture.get('fixed_code', {})) != set(CAPTURE_SPANS):
        raise ValueError('Fixed capture source or named span set differs from the captured CDN witness')
    if not all(capture.get('registrations', {}).get(name, {}).get('all_fields_verified') is True
               for name in ['MapleRow_GetCDNUrl', 'AppRow_GetCDNUrl', 'AppSetting_GetCDNUrl',
                            'IconManager_GetCDNUrl', 'IconManager_GetFinalDiskPath', 'CDNConfig_GetCDNUrl']):
        raise ValueError('Capture does not verify every source registration')
    with pe.open('rb') as handle:
        handle.seek(0x3c)
        pe_offset = struct.unpack('<I', handle.read(4))[0]
        handle.seek(pe_offset)
        header = handle.read(24)
        if header[:4] != b'PE\0\0':
            raise ValueError('Invalid native PE section header')
        section_count, optional_size = struct.unpack_from('<H', header, 6)[0], struct.unpack_from('<H', header, 20)[0]
        if not 0 < section_count <= 96:
            raise ValueError('Invalid native PE section count')
        handle.seek(pe_offset + 24 + optional_size)
        table = handle.read(section_count * 40)
        sections = []
        for index in range(section_count):
            at = index * 40
            _, rva, raw_size, raw_offset = struct.unpack_from('<4I', table, at + 8)
            sections.append({'name': table[at:at + 8].split(b'\0', 1)[0].decode('ascii'),
                             'rva': rva, 'raw_size': raw_size, 'raw_offset': raw_offset})
        rows = []
        for name, (rva, size) in CAPTURE_SPANS.items():
            block = capture['fixed_code'][name]
            if (block.get('rva'), block.get('size')) != (rva, size):
                raise ValueError(f'Fixed capture differs for {name}')
            live = bytes.fromhex(block['bytes'])
            if len(live) != size or hashlib.sha256(live).hexdigest() != block['sha256']:
                raise ValueError(f'Fixed capture hash or size differs for {name}')
            section = next((s for s in sections if s['rva'] <= rva and rva + size <= s['rva'] + s['raw_size']), None)
            if section is None:
                raise ValueError('Fixed code span has no bounded original file mapping')
            offset = section['raw_offset'] + rva - section['rva']
            handle.seek(offset)
            raw = handle.read(size)
            rows.append({'name': name, 'rva': rva, 'original_pe_file_offset': offset,
                         'section': section['name'], 'size': size,
                         'original_pe_span_sha256': hashlib.sha256(raw).hexdigest(),
                         'live_span_sha256': block['sha256'], 'live_identical_to_original_pe': live == raw,
                         'capture_instruction_count': len(block.get('instructions', []))})
    unchanged = all(r['live_identical_to_original_pe'] for r in rows)
    methods = []
    for name, (site, target) in CALLBACK_METHODS.items():
        block = capture['fixed_code'][name]
        code = bytes.fromhex(block['bytes'])
        call_offset = site - block['rva']
        if code[:6] != bytes.fromhex('40534883ec20') or code[call_offset] != 0xe8:
            continue
        actual_target = site + 5 + struct.unpack_from('<i', code, call_offset + 1)[0]
        if actual_target != target:
            continue
        suffix = bytes.fromhex('488bc34883c4205bc3')
        if code[call_offset + 5:call_offset + 5 + len(suffix)] != suffix:
            continue
        ret_offset = call_offset + 5 + len(suffix) - 1
        record = {'named_callback': name, 'callback_span_sha256': block['sha256'],
                  'direct_call_site_rva': site, 'direct_call_target_rva': target,
                  'caller_ret_rva': block['rva'] + ret_offset,
                  'call_e8_relative_target_verified': True,
                  'implementation_semantics_verified': False,
                  'suggested_bounded_code_prefix_bytes': 512 if name != 'CDNConfig_GetCDNUrl_callback' else 256}
        if name == 'CDNConfig_GetCDNUrl_callback' and code[6:13] == bytes.fromhex('4881c2b0000000'):
            record['source_field_offset_from_receiver'] = 0xb0
            record['field_basis'] = 'Callback ADD RDX,0xb0 before copy-helper call; receiver instance absolute address not established'
        methods.append(record)
    return {'capture_path': capture_path.as_posix(), 'capture_sha256': digest_file(capture_path),
            'pe_section_header_sha256': hashlib.sha256(table).hexdigest(),
            'spans': rows, 'all_live_spans_unchanged_from_original': unchanged,
            'source_proven_followup_code_or_inline_field_targets': methods,
            'analysis': ('These unchanged .std spans do not yield a meaningful CDN dispatch or field accessor. Apparent instructions in this nonsemantic decode cannot justify following branch/call targets.'
                         if unchanged else 'Some live spans differ from original PE bytes. This file comparison does not establish semantics or follow-up targets; independently analyze the changed saved code before extending capture.')}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--game-root', type=Path)
    parser.add_argument('--shadow-root', type=Path)
    parser.add_argument('--index-evidence', type=Path, help='Optional preserved all-PAK footer metadata JSON')
    parser.add_argument('--fixed-capture', type=Path, help='Optional existing named CDN code capture; file comparison only')
    parser.add_argument('--output', type=Path)
    args = parser.parse_args()
    installed, shadow = game_paths(args.game_root, args.shadow_root)
    output = project_path(args.output, ROOT / 'work/bundle_asset_locations_cdn.json')
    if any(output.is_relative_to(root) for root in [installed, shadow]):
        parser.error('Diagnostic output must be outside both game trees')
    pe = installed / PE_RELATIVE
    if not pe.is_file():
        parser.error('Source executable missing; provide --game-root for the captured native version')
    try:
        native = fixed_pe_witnesses(pe)
    except ValueError as exc:
        parser.error(str(exc))
    report = {'scope': 'Read-only file bytes and exact source filenames; no native execution, process access, hooks, requests, downloads or game writes',
              'native_source': native, 'fixed_pak_footer_witnesses': [], 'loose_source_files': [],
              'exact_source_filename_matches': [], 'native_log_snapshots': []}
    if args.fixed_capture:
        capture_path = project_path(args.fixed_capture, ROOT / 'work/evidence/live-cdn-loader-bundle-20261005-private.json')
        if not capture_path.is_file():
            parser.error('--fixed-capture is missing; supply an existing fixed CDN capture JSON')
        try:
            report['fixed_capture_comparison'] = compare_fixed_capture(pe, capture_path)
        except (ValueError, KeyError, TypeError) as exc:
            parser.error(f'Invalid fixed CDN capture: {exc}')
    for name in ['pak-0-0-pakchunk1-WindowsClient.pak', 'pak-0-0-pakchunk2-WindowsClient.pak']:
        path = installed / 'DeltaForce/Content/Paks' / name
        if path.is_file():
            report['fixed_pak_footer_witnesses'].append(pak_footer(path))
    for root, label in [(installed, 'installed'), (shadow, 'shadow')]:
        for relative in ['DeltaForce/Binaries/Win64/config.json',
                         'DeltaForce/Binaries/Win64/MSDKConfig.ini',
                         'DeltaForce/Saved/Config/WindowsClient/AppSetting.ini',
                         'DeltaForce/Saved/Dolphin/1.101.37117.36/filelist.json']:
            path = root / relative
            if not path.is_file():
                report['loose_source_files'].append({'tree': label, 'relative': relative, 'status': 'not_present'})
                continue
            raw = path.read_bytes()
            record = {'tree': label, 'relative': relative, 'size': len(raw),
                      'sha256': hashlib.sha256(raw).hexdigest()}
            if path.name == 'filelist.json':
                table = json.loads(raw)
                record['patch_urls'] = [{key: value for key, value in row.items() if key in ['url', 'curl', 'bkurl', 'bkcurl']}
                                        for row in table.get('filelist', [])]
                record['role'] = 'Dolphin patch endpoints; native image base not established'
            elif path.name == 'AppSetting.ini':
                record['empty_after_whitespace'] = not raw.strip()
            report['loose_source_files'].append(record)
        report['exact_source_filename_matches'].extend(
            {'tree': label, 'path': path.as_posix(), 'size': path.stat().st_size}
            for path in root.rglob('*') if path.is_file() and path.name in ['cdn.meta', 'yunkong.config'])
    for path in sorted((shadow / 'DeltaForce/Saved/Logs').glob('DeltaForce*.log')):
        try:
            report['native_log_snapshots'].append(public_log_witnesses(path))
        except FileNotFoundError:
            report['native_log_snapshots'].append({'path': path.as_posix(), 'status': 'rotated_before_read'})
    if args.index_evidence:
        path = project_path(args.index_evidence, ROOT / 'work/evidence/resource-asset-original-registry-index-metadata.json')
        if not path.is_file():
            parser.error('--index-evidence is missing; omit it or provide preserved footer metadata JSON')
        evidence = json.loads(path.read_text(encoding='utf-8'))
        guids = Counter(row['encryption_key_guid_hex'] for row in evidence['archives'])
        report['preserved_index_summary'] = {'path': path.as_posix(), 'sha256': digest_file(path),
            'archive_count': len(evidence['archives']), 'distinct_guid_count': len(guids),
            'zero_guid_count': guids.get('0' * 32, 0), 'versions': evidence['versions'],
            'index_encryption_flags': evidence['index_encryption_flags'],
            'coverage': 'Preserved footer metadata only; no PAK payload or directory decryption was attempted'}
    report['recovery_routes'] = [
        'Follow DefaultCDNUrl/CDNUrl_PC/CDNFallbackDomains/CDNFallbackDomains_PC in the actual App/Maple setting source; no values were recovered here.',
        'Follow source-proven cdn.meta/yunkong.config and Maple cdnkey routes; an actual config payload or captured public resulting URL is needed.',
        'Encrypted directory lookup needs the correct key for each footer GUID, followed by stored index SHA1 and directory-structure validation; no matching key is available in this report.',
    ]
    report['limits'] = ['A Maple directory-service hostname and Dolphin patch endpoints are not image CDN base proof.',
        'CryptoKeys/ExtractCryptoJson/PakEncryptSettings reflection names are packaging metadata and do not establish shipped key availability.',
        'Zero allowed log lines or absent exact loose filenames do not establish that native configuration or resources are globally absent.',
        'Log hashes identify the bytes read at that snapshot; running clients may append or rotate logs.']
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(report, ensure_ascii=True, indent=2) + '\n', encoding='utf-8')
    print(json.dumps({'output': output.as_posix(), 'fixed_pe_witness_count': len(native['fixed_string_witnesses']),
        'native_log_snapshot_count': len(report['native_log_snapshots']),
        'exact_loose_config_matches': len(report['exact_source_filename_matches'])}))


if __name__ == '__main__':
    main()
