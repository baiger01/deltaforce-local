import hashlib
from pathlib import Path
import tempfile
import unittest

from inspect_dam_world_settings import checked_payload, equivalent_companions


class CompanionEvidenceTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.root = Path(self.directory.name)

    def row(self, entry, data):
        name = f'entry-{entry}.uexp'
        (self.root / name).write_bytes(data)
        return {'entry': entry, 'kind': 'companion_candidate',
                'evidence_file': name, 'uncompressed_bytes': len(data),
                'payload_sha256': hashlib.sha256(data).hexdigest()}

    def test_duplicate_entries_need_identical_content(self):
        data = b'abcd\xc1\x83\x2a\x9e'
        rows = [self.row(2, data), self.row(9, data)]
        canonical, equivalent = equivalent_companions(self.root, rows, 4)
        self.assertEqual(canonical['entry'], 2)
        self.assertEqual([row['entry'] for row in equivalent], [2, 9])

    def test_distinct_same_size_bodies_are_ambiguous(self):
        rows = [self.row(2, b'abcd\xc1\x83\x2a\x9e'),
                self.row(9, b'efgh\xc1\x83\x2a\x9e')]
        with self.assertRaisesRegex(ValueError, 'ambiguous'):
            equivalent_companions(self.root, rows, 4)

    def test_modified_payload_is_rejected(self):
        row = self.row(2, b'abcd\xc1\x83\x2a\x9e')
        (self.root / row['evidence_file']).write_bytes(b'efgh\xc1\x83\x2a\x9e')
        with self.assertRaisesRegex(ValueError, 'hash or size'):
            checked_payload(self.root, row)

    def test_terminator_is_required(self):
        row = self.row(2, b'abcdwxyz')
        with self.assertRaisesRegex(ValueError, 'terminator'):
            equivalent_companions(self.root, [row], 4)

    def test_wrong_extent_is_rejected(self):
        row = self.row(2, b'abcd\xc1\x83\x2a\x9e')
        with self.assertRaisesRegex(ValueError, 'missing'):
            equivalent_companions(self.root, [row], 8)

    def test_evidence_cannot_leave_directory(self):
        row = self.row(2, b'abcd\xc1\x83\x2a\x9e')
        row['evidence_file'] = '../entry-2.uexp'
        with self.assertRaisesRegex(ValueError, 'leaves'):
            checked_payload(self.root, row)


if __name__ == '__main__':
    unittest.main()
