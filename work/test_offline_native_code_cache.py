"""Disk-only integrity/coverage tests using a small synthetic cache."""
import copy
import hashlib
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import offline_native_code_cache as c


class Tests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.folder = self.root/'cache/sample'
        self.folder.mkdir(parents=True)
        code = b'a'*4096+b'fghij'
        self.plan = {'sections': [{'index': 0, 'rva': '0x1000', 'file_backed_code_bytes': 4101}],
            'maximum_RPM_bytes': 1048576, 'maximum_code_bytes': 4101,
            'known_sender_targets': [{'name': 'mock', 'rva': '0x1000', 'code_bytes': 4101,
                'expected_code_sha256': hashlib.sha256(code).hexdigest()}]}
        plan_path = self.root/'plan.json'
        plan_path.write_text(json.dumps(self.plan), encoding='utf-8')
        self.patches = [patch.object(c, 'CACHE_ROOT', self.root/'cache'),
            patch.object(c, 'PLAN', plan_path), patch.object(c, 'PLAN_SHA', hashlib.sha256(plan_path.read_bytes()).hexdigest())]
        for p in self.patches:
            p.start()
        self.manifest = {'kind': 'private_file_backed_executable_code_cache',
            'client_sha256': c.SOURCE_SHA, 'plan': self.plan, 'complete': True,
            'scope_coverage_complete': True, 'status': 'code_cache_complete',
            'snapshot_is_atomic': False, 'client_launched': False, 'elevation_requested': False,
            'process_memory_written': False, 'live_data_object_read': False,
            'original_game_modified': False, 'reconstructed_executable': False,
            'native_complete_decode_claimed': False,
            'saved_code_bytes': 4101, 'unavailable_bytes': 0, 'actual_RPM_count': 2, 'RPM_requested_bytes': 4101,
            'sections': [{'index': 0, 'rva': '0x1000', 'bytes': 4101,
                'available_bytes': 4101, 'unavailable_bytes': 0, 'blocks': []}],
            'known_sender_comparisons': [{'name': 'mock', 'rva': '0x1000', 'bytes': 4101,
                'available': True, 'expected_code_sha256': hashlib.sha256(code).hexdigest(),
                'cache_code_sha256': hashlib.sha256(code).hexdigest(),
                'matches_saved_native_sample': True, 'extra_live_reads': 0}]}
        for rva, data in ((0x1000, code[:4096]), (0x2000, code[4096:])):
            name = f'section_00_rva_{rva:08x}.code'
            (self.folder/name).write_bytes(data)
            self.manifest['sections'][0]['blocks'].append({'rva': hex(rva), 'bytes': len(data),
                'available': True, 'file': name, 'code_sha256': hashlib.sha256(data).hexdigest()})
        self.write_manifest()

    def write_manifest(self):
        (self.folder/'manifest.json').write_text(json.dumps(self.manifest), encoding='utf-8')

    def tearDown(self):
        for p in reversed(self.patches):
            p.stop()
        self.temp.cleanup()

    def test_reads_verified_cross_block_range(self):
        self.assertEqual(c.read_cached_code(self.folder, 0x1ffd, 5), b'aaafg')

    def test_manifest_external_SHA_pin(self):
        sha = hashlib.sha256((self.folder/'manifest.json').read_bytes()).hexdigest()
        self.assertEqual(c.read_cached_code(self.folder, 0x1000, 2, sha), b'aa')
        with self.assertRaises(ValueError):
            c.read_cached_code(self.folder, 0x1000, 2, '0'*64)

    def test_block_hash_tamper_rejected(self):
        (self.folder/self.manifest['sections'][0]['blocks'][0]['file']).write_bytes(b'ABCDE')
        with self.assertRaises(ValueError):
            c.read_cached_code(self.folder, 0x1000, 2)

    def test_malformed_manifest_coverage_accounting_rejected(self):
        for change in ('rva', 'bytes', 'available', 'file', 'code_sha256'):
            original = copy.deepcopy(self.manifest)
            self.manifest['sections'][0]['blocks'][0][change] = {
                'rva': '0x1001', 'bytes': 6, 'available': 1, 'file': '../outside', 'code_sha256': 'x'*64}[change]
            self.write_manifest()
            with self.assertRaises(ValueError):
                c.read_cached_code(self.folder, 0x1000, 2)
            self.manifest = original

    def test_missing_interval_fails_but_available_prefix_usable(self):
        block = self.manifest['sections'][0]['blocks'][1]
        block.clear()
        block.update(rva='0x2000', bytes=5, available=False, unavailable_reason='page_not_committed_executable_image')
        self.manifest.update(status='code_cache_partial', complete=False, scope_coverage_complete=False,
            saved_code_bytes=4096, unavailable_bytes=5, actual_RPM_count=1, RPM_requested_bytes=4096)
        self.manifest['sections'][0].update(available_bytes=4096, unavailable_bytes=5)
        self.manifest['known_sender_comparisons'][0].update(available=False, cache_code_sha256=None, matches_saved_native_sample=False)
        self.write_manifest()
        self.assertEqual(c.read_cached_code(self.folder, 0x1000, 2), b'aa')
        with self.assertRaises(ValueError):
            c.read_cached_code(self.folder, 0x1ffd, 5)

    def test_query_bounds(self):
        for rva, length in ((-1, 2), (0x1000, 8193), (0x1000, 0), (0x2004, 2), (True, 2)):
            with self.subTest(rva=rva, length=length), self.assertRaises(ValueError):
                c.read_cached_code(self.folder, rva, length)

    def test_failed_collection_rejected(self):
        self.manifest.update(status='code_cache_failed', complete=False)
        self.write_manifest()
        with self.assertRaises(ValueError):
            c.read_cached_code(self.folder, 0x1000, 2)

    def test_source_plan_tamper_rejected(self):
        c.PLAN.write_text('{}', encoding='utf-8')
        with self.assertRaises(ValueError):
            c.read_cached_code(self.folder, 0x1000, 2)


if __name__ == '__main__':
    unittest.main()
