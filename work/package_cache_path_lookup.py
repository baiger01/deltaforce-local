"""Disabled-by-default, bounded lookup of four source-pinned shop image families.

This module has no CLI, process APIs, launch, native call, or write operation.
An independently reviewed shadow adapter must provide read(address, size).
Only the native hash-chain lookup is reproduced; sparse allocation bits and
the final file/texture/brush loading result are not inferred.
"""

from dataclasses import dataclass
import hashlib
import json
from pathlib import Path
import struct

ROOT = Path(__file__).resolve().parent.parent
SOURCE_PE = '4254fbe66585f260f1f9dbfc5e302887842552e7baed8939e023160a5e250be0'
MODULE_SIZE = 0x1ff8f000
MAX_ADDRESS = 0x800000000000
MAX_TOTAL_READ = 2 * 1024 * 1024
MAX_SLOTS = 16384
MAX_HASH_SIZE = 32768
MAX_CHAIN = 64
MAX_COMPONENTS = 16
MAX_KEY_UNITS = 256
MAX_FILENAME_UNITS = 512
ROOT_SLOT = 0x1e34ee30
ALLOCATOR_SLOT = 0x1d59de58
ALLOCATOR_RVA = 0xd968d0
DELIMITER_SLOT = 0x1d5ad108
DELIMITER_RVA = 0x14ed0570
LOWER_RVA = 0x1aae7310
LOWER_OFFSET = 447637264
LOWER_SHA = 'fc5b9b2c32b0ecc0354c66f03e60790599a8fbae3511b2b60b2c0f7f27b6ceae'
CRC_RVA = 0x1d59ba40
CRC_SHA = '0053f121cdcaf9f510a940ba891fb2bccd41487953c5a4c0048c4a3ccdec782e'
CATALOG_PATH = 'outputs/df-local-server/protocol/premium_shop_catalog.json'
CATALOG_SHA = '77372a31b2bf36ad8ba0da7540b736d809c14060321a98cecc8efca7663ec51b'
EXPORT_SHA = 'bcf064ebee25d046e21712375adf8e68f80b71bedd9c5c65f1fcb6a6d771a1fc'
PATHS_SHA = 'bc68cc31ab890e4bac8d64ae5cb93da715eb63dcf730cbe3e2ce2d366ade085b'
SOURCE_ROWS = {10101004: (3, 4845), 10101008: (7, 11134),
               10101019: (18, 28768), 10102002: (39, 62600)}
IMAGE_FIELDS = ('preview_asset', 'native_big_asset', 'native_logo_asset')
SOURCE_FILES = (
    ('work/evidence/live-package-path-cache-bundle-20261005-private.json',
     'c6d1d36b83f9621dd982bc63fa90c72637e6cc896b6db3d6869515e0dd987f02'),
    ('work/evidence/live-package-child-map-bundle-20261005-private.json',
     '5f4d2c18050a5ea11969ccd8fd18289522aa5339e9eb9794ae79f66942294e3b'),
    ('work/evidence/live-package-compare-bundle-20261005-private.json',
     'a412582d25d1bfa12d727a735a8e16a1afd4083299e7986c7c7646ad70f47120'),
    ('work/evidence/live-cdn-image-request-crc-trial3-bundle-20261005-private.json',
     '579c74538b3979e664c41bd7cbd2e06280bfd0b9518fe6c773bf67114ec620dc'),
    ('work/native-client-tests/1790852498680017300/keybox-registration-readonly-185.json',
     '5d4acbe72d2ee450a31c8fcd29c9805947cab0531f727a70fa28744b65033182'),
)
CODE_PINS = {
    0x10ecd110: (1024, 'a577995db5aa053db3a4aca176bd0352d104530972184f531822d1ad0ad96635'),
    0x109f2ea0: (1024, 'abed5528848fa3c6ed260765b7572f5b7bc30e31b73de0a203c920e1e27bd95f'),
    0x10ecd9a0: (1024, '79a5418c4aaadd1b66e2ce28d7c11a4608bda702cbc4147dcef222d41b51dc47'),
    0xdb7b30: (1024, '029a56a4e81bc1c48fcd2e2960e1211dbc8d15e3e280d561ab69555e1760546c'),
    0x10a137d0: (1024, 'e25a9f37dd2f0049d09b5ba3ed0d4c047e15dbe674ef04682c19c0c3ebf9fba0'),
    0xd61370: (512, 'f05a55f757700051f21c514f7fb0db1d3970b444b76d678a6031135ddc6cbf92'),
}


@dataclass(frozen=True)
class SourcePath:
    tab_id: int
    field: str
    row: int
    offset: int
    reference: str

    def package(self):
        if not self.reference.startswith("Texture2D'") or not self.reference.endswith("'"):
            raise ValueError('source_image_reference_is_not_class_quoted_Texture2D')
        name = self.reference[10:-1]
        if not name.startswith('/Game/') or not name.isascii() or '\x00' in name:
            raise ValueError('source_image_reference_is_not_exact_ASCII_Game_path')
        # CheckPathValid strips at the first dot; no package alias is substituted.
        package, dot, _ = name.partition('.')
        if not dot or len([part for part in package.split('/') if part]) > MAX_COMPONENTS:
            raise ValueError('source_package_components_outside_bounded_contract')
        return package


@dataclass(frozen=True)
class Contract:
    blocks: tuple
    lower: bytes
    crc: bytes
    paths: tuple
    source_hashes: tuple
    catalog_sha256: str
    source_pe_sha256: str


def _paths_digest(paths):
    rows = sorted([[p.tab_id, p.field, p.row, p.offset, p.reference] for p in paths])
    return hashlib.sha256(json.dumps(rows, ensure_ascii=True,
                                    separators=(',', ':')).encode('ascii')).hexdigest()


def _json(root, relative, digest, limit=2 * 1024 * 1024):
    path = Path(root) / relative
    if not path.is_file() or not 0 < path.stat().st_size <= limit:
        raise ValueError('missing_bounded_package_cache_source: ' + relative)
    with path.open('rb') as source:
        raw = source.read(limit + 1)
    if len(raw) > limit or hashlib.sha256(raw).hexdigest() != digest:
        raise ValueError('package_cache_source_full_SHA_changed: ' + relative)
    return json.loads(raw)


def load_contract(original_pe, root=ROOT):
    """Verify preserved code, exact original static literals, and closed inputs."""
    reports = [_json(root, relative, digest) for relative, digest in SOURCE_FILES]
    if any(r.get('native_pe_sha256') != SOURCE_PE for r in reports):
        raise ValueError('package_cache_source_PE_changed')
    package, child, compare, crc, old = reports
    if (package.get('source_capture_sha256') !=
            '01f326632251d583a7db7eefa63929caceacc6ec9d7dc0a72612da1c97d35d09'
            or child.get('source_capture_sha256') != SOURCE_FILES[0][1]
            or compare.get('source_capture_sha256') != SOURCE_FILES[1][1]):
        raise ValueError('package_cache_source_chain_changed')
    candidates = [package['source_code'], *package['fixed_code'].values(),
                  child['fixed_code']['CacheChildMapFind'],
                  compare['fixed_code']['CacheFStringCompare'],
                  crc['image_processing_helpers']['Disk_BasenameHash']]
    blocks = []
    for block in candidates:
        rva = block['rva']
        data = bytes.fromhex(block['bytes'])
        if ((len(data), hashlib.sha256(data).hexdigest()) != CODE_PINS.get(rva)
                or block['size'] != len(data) or block['sha256'] != CODE_PINS[rva][1]):
            raise ValueError('package_cache_fixed_code_pin_changed')
        blocks.append((rva, data))
    if {rva for rva, _ in blocks} != set(CODE_PINS) or len(blocks) != len(CODE_PINS):
        raise ValueError('package_cache_source_code_coverage_changed')
    accessor = old['fixed_data']['datatable_content_data_accessor']
    allocation = old['config_map']
    if (accessor['rva'] != ALLOCATOR_SLOT or accessor['size'] != 8
            or bytes.fromhex(accessor['bytes']) != struct.pack('<Q', 0x140000000 + ALLOCATOR_RVA)
            or allocation['allocation_accessor_rva'] != ALLOCATOR_RVA
            or bytes.fromhex(allocation['allocation_accessor_code_hex'])[:4] != bytes.fromhex('488b01c3')):
        raise ValueError('package_cache_source_allocator_changed')
    blocks.append((ALLOCATOR_RVA, bytes.fromhex('488b01c3')))
    crc_block = crc['image_crc_table']
    crc_bytes = bytes.fromhex(crc_block['bytes'])
    if ((crc_block['rva'], crc_block['size'], crc_block['sha256']) != (CRC_RVA, 1024, CRC_SHA)
            or hashlib.sha256(crc_bytes).hexdigest() != CRC_SHA
            or crc_block.get('matches_original_pe_table') is not True):
        raise ValueError('package_cache_source_CRC_table_changed')
    with Path(original_pe).open('rb') as source:
        if hashlib.file_digest(source, 'sha256').hexdigest() != SOURCE_PE:
            raise ValueError('package_cache_original_PE_full_SHA_changed')
        source.seek(LOWER_OFFSET)
        lower = source.read(128)
    if hashlib.sha256(lower).hexdigest() != LOWER_SHA:
        raise ValueError('package_cache_source_ASCII_lower_table_changed')
    catalog = _json(root, CATALOG_PATH, CATALOG_SHA, 4 * 1024 * 1024)
    expected_source = {'entry': 7142, 'sha256': EXPORT_SHA, 'row_count': 158,
                       'name_map_available': False}
    if catalog['sources']['recommendations'] != expected_source:
        raise ValueError('package_cache_static_path_export_changed')
    rows = [row for row in catalog['recommendations'] if row['tab_id'] in SOURCE_ROWS]
    if len(rows) != 4 or {row['tab_id'] for row in rows} != set(SOURCE_ROWS):
        raise ValueError('package_cache_requires_exact_four_source_rows')
    paths = []
    for row in rows:
        if (row['row'], row['offset']) != SOURCE_ROWS[row['tab_id']]:
            raise ValueError('package_cache_static_path_source_coordinate_changed')
        for field in IMAGE_FIELDS:
            path = SourcePath(row['tab_id'], field, row['row'], row['offset'], row[field])
            path.package()
            paths.append(path)
    if _paths_digest(paths) != PATHS_SHA:
        raise ValueError('package_cache_closed_source_paths_changed')
    return Contract(tuple(blocks), lower, crc_bytes, tuple(paths), SOURCE_FILES,
                    CATALOG_SHA, SOURCE_PE)


def native_hash(text, table):
    """d61370 folds only ASCII a..z; hash both bytes of each UTF16 code unit."""
    crc = 0
    encoded = text.encode('utf-16le')
    for index in range(0, len(encoded), 2):
        unit = encoded[index] | encoded[index + 1] << 8
        if 97 <= unit <= 122:
            unit -= 32
        for value in (unit & 255, unit >> 8):
            crc = (crc >> 8) ^ table[(crc ^ value) & 255]
    return crc


def native_key_equal(units, target, lower):
    expected = tuple(target.encode('utf-16le'))
    expected = tuple(expected[i] | expected[i + 1] << 8 for i in range(0, len(expected), 2))
    if len(units) != len(expected):
        return False
    return all(a == b or (a < 128 and b < 128 and lower[a] == lower[b])
               for a, b in zip(units, expected))


class _Stop(ValueError):
    pass


def _address(address, size=1):
    if (type(address) is not int or type(size) is not int or size <= 0
            or address < 0x10000 or address + size > MAX_ADDRESS):
        raise _Stop('invalid_package_cache_pointer_or_range')
    return address


class Session:
    def __init__(self, read, base, contract, *, enabled=False):
        self.read = read
        self.base = base
        self.contract = contract
        self.enabled = enabled is True
        self.total = 0
        self.readset = []
        self.watched = {}

    def exact(self, address, size, role):
        _address(address, size)
        if size > 1024 or self.total + size > MAX_TOTAL_READ:
            raise _Stop('bounded_package_cache_read_budget_exceeded')
        self.total += size
        raw = self.read(address, size)
        if not isinstance(raw, bytes) or len(raw) != size:
            raise _Stop('short_package_cache_metadata_read')
        self.readset.append({'address': hex(address), 'size': size, 'role': role})
        return raw

    def watch(self, address, size, role):
        raw = self.exact(address, size, role)
        key = (address, size)
        if key in self.watched and self.watched[key] != raw:
            raise _Stop('package_cache_changed_during_capture')
        self.watched[key] = raw
        return raw

    def module(self, rva, size, role):
        if not 0 <= rva < rva + size <= MODULE_SIZE:
            raise _Stop('package_cache_module_scope_changed')
        return self.watch(self.base + rva, size, role)

    def verify(self):
        _address(self.base, MODULE_SIZE)
        contract = self.contract
        if (not isinstance(contract, Contract) or contract.source_pe_sha256 != SOURCE_PE
                or contract.catalog_sha256 != CATALOG_SHA or contract.source_hashes != SOURCE_FILES
                or len(contract.paths) != 12
                or _paths_digest(contract.paths) != PATHS_SHA
                or {(p.tab_id, p.field) for p in contract.paths} !=
                {(tab, field) for tab in SOURCE_ROWS for field in IMAGE_FIELDS}
                or any((p.row, p.offset) != SOURCE_ROWS[p.tab_id] for p in contract.paths)):
            raise _Stop('closed_source_package_cache_contract_required')
        for path in contract.paths:
            path.package()
        expected_code = set(CODE_PINS) | {ALLOCATOR_RVA}
        if len(contract.blocks) != len(expected_code) or {rva for rva, _ in contract.blocks} != expected_code:
            raise _Stop('package_cache_fixed_source_coverage_changed')
        for rva, expected in contract.blocks:
            if rva == ALLOCATOR_RVA:
                valid = expected == bytes.fromhex('488b01c3')
            else:
                valid = (len(expected), hashlib.sha256(expected).hexdigest()) == CODE_PINS[rva]
            if not valid or self.module(rva, len(expected), 'fixed_source_code') != expected:
                raise _Stop('fresh_package_cache_code_changed: ' + hex(rva))
        if (hashlib.sha256(contract.lower).hexdigest() != LOWER_SHA
                or self.module(LOWER_RVA, 128, 'ASCII_comparison_table') != contract.lower
                or hashlib.sha256(contract.crc).hexdigest() != CRC_SHA
                or self.module(CRC_RVA, 1024, 'CRC_table') != contract.crc):
            raise _Stop('fresh_package_cache_literal_table_changed')
        if self.module(ALLOCATOR_SLOT, 8, 'allocator_slot') != struct.pack('<Q', self.base + ALLOCATOR_RVA):
            raise _Stop('fresh_package_cache_allocator_slot_changed')
        if (self.module(DELIMITER_SLOT, 8, 'delimiter_slot') != struct.pack('<Q', self.base + DELIMITER_RVA)
                or self.module(DELIMITER_RVA, 4, 'delimiter_literal') != b'/\x00\x00\x00'):
            raise _Stop('fresh_package_cache_slash_split_changed')
        self.table = struct.unpack('<256I', contract.crc)

    def string_units(self, address, header, role, limit):
        pointer = struct.unpack_from('<Q', header)[0]
        count = struct.unpack_from('<i', header, 8)[0]
        if not 0 <= count <= limit:
            raise _Stop('bounded_package_cache_FString_count_exceeded')
        if not count:
            return ()
        raw = self.watch(_address(pointer, count * 2), count * 2, role)
        units = struct.unpack('<' + 'H' * count, raw)
        if units[-1] != 0 or 0 in units[:-1]:
            raise _Stop('package_cache_FString_termination_changed')
        return units[:-1]

    def child(self, node, component):
        if node & 7:
            raise _Stop('unaligned_package_cache_node')
        header = self.watch(_address(node, 0x50), 0x50, 'selected_node_child_map_header')
        slots = struct.unpack_from('<i', header, 8)[0]
        free = struct.unpack_from('<i', header, 0x34)[0]
        if not 0 <= free <= slots <= MAX_SLOTS:
            raise _Stop('bounded_package_cache_slot_count_changed')
        if slots == free:
            return None
        data = struct.unpack_from('<Q', header)[0]
        _address(data, slots * 32)
        hash_size = struct.unpack_from('<i', header, 0x48)[0]
        buckets = struct.unpack_from('<Q', header, 0x40)[0]
        if (not 0 < hash_size <= MAX_HASH_SIZE or hash_size & (hash_size - 1)
                or (not buckets and hash_size > 2)):
            raise _Stop('bounded_package_cache_hash_size_changed')
        buckets = buckets or node + 0x38
        index = native_hash(component, self.table) & (hash_size - 1)
        bucket = self.watch(_address(buckets, hash_size * 4) + index * 4, 4, 'selected_hash_bucket')
        slot = struct.unpack('<i', bucket)[0]
        visited = set()
        while slot != -1:
            if not 0 <= slot < slots or slot in visited or len(visited) >= MAX_CHAIN:
                raise _Stop('package_cache_hash_chain_bounds_or_cycle')
            visited.add(slot)
            entry = self.watch(data + slot * 32, 32, 'selected_hash_chain_key_and_child')
            units = self.string_units(data + slot * 32, entry[:16], 'selected_key_chars', MAX_KEY_UNITS)
            if native_key_equal(units, component, self.contract.lower):
                child = struct.unpack_from('<Q', entry, 0x10)[0]
                _address(child, 0x50)
                return child
            slot = struct.unpack_from('<i', entry, 0x18)[0]
        return None

    def lookup(self, root, source_path):
        package = source_path.package()
        node = root
        visited = set()
        components = [component for component in package.split('/') if component]
        for position, component in enumerate(components):
            if node in visited:
                raise _Stop('package_cache_child_node_cycle')
            visited.add(node)
            child = self.child(node, component)
            if child is None:
                return {'tab_id': source_path.tab_id, 'field': source_path.field,
                        'package': package, 'lookup_status': 'cache_key_missing',
                        'first_missing_component': position}
            node = child
        filename = self.watch(node + 0xa0, 16, 'selected_terminal_package_FString')
        units = self.string_units(node + 0xa0, filename, 'selected_terminal_package_chars', MAX_FILENAME_UNITS)
        raw = struct.pack('<' + 'H' * len(units), *units)
        try:
            name = raw.decode('utf-16le')
        except UnicodeDecodeError:
            raise _Stop('terminal_package_FString_invalid_UTF16') from None
        return {'tab_id': source_path.tab_id, 'field': source_path.field,
                'package': package, 'lookup_status': 'cached_terminal_node',
                'cached_package_filename': name,
                'native_length_exceeds_terminator': bool(units)}

    def capture(self):
        result = {'status': 'disabled', 'native_pe_sha256': SOURCE_PE,
                  'default_disabled': True, 'native_called': False,
                  'map_enumerated': False, 'independent_sparse_bits_verified': False,
                  'allocation_membership_certified': False,
                  'native_CheckPathValid_called': False, 'file_exists_verified': False,
                  'texture_or_brush_verified': False, 'captured_bytes': 0}
        if not self.enabled:
            return result
        result['status'] = 'skipped'
        try:
            self.verify()
            root_raw = self.module(ROOT_SLOT, 8, 'cache_root_pointer')
            root = struct.unpack('<Q', root_raw)[0]
            if root:
                _address(root, 0x50)
                rows = [self.lookup(root, path) for path in self.contract.paths]
            else:
                rows = [{'tab_id': p.tab_id, 'field': p.field, 'package': p.package(),
                         'lookup_status': 'cache_root_not_created'} for p in self.contract.paths]
            for (address, size), expected in tuple(self.watched.items()):
                if self.exact(address, size, 'stability_recheck') != expected:
                    raise _Stop('package_cache_changed_during_recheck')
            result.update(status='captured_hash_chain_metadata', paths=rows,
                          source_hashes=self.contract.source_hashes,
                          catalog_sha256=self.contract.catalog_sha256,
                          limitation='Only native hash-chain behavior was reproduced. Sparse allocation '
                          'membership is not certified; cache miss is not final CheckPathValid failure '
                          'and cache hit is not Texture2D or brush rendering success.')
        except (ValueError, KeyError, TypeError, struct.error) as error:
            result['reason'] = str(error)
        result.update(captured_bytes=self.total, reads=self.readset,
                      typed_heap_read=any(r['role'].startswith('selected_') for r in self.readset))
        return result


def capture(read, base, contract, *, enabled=False):
    return Session(read, base, contract, enabled=enabled).capture()
