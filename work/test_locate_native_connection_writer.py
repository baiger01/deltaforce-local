"""Pure offline validation tests; no game, UAC, or process calls."""
import copy
import struct
import unittest
from unittest.mock import patch
import locate_native_connection_writer as writer


class ManifestTests(unittest.TestCase):
    def setUp(self):
        self.plan = {"sections": [{"index": 0, "rva": "0x1000", "file_backed_code_bytes": 12}],
                     "maximum_RPM_bytes": 8, "maximum_region_split_RPM_count": 3}
        self.manifest = {"kind": "private_file_backed_executable_code_cache",
            "status": "code_cache_complete", "complete": True, "scope_coverage_complete": True,
            "client_sha256": writer.SOURCE_SHA, "plan": self.plan, "process_memory_written": False,
            "live_data_object_read": False, "original_game_modified": False,
            "reconstructed_executable": False, "native_complete_decode_claimed": False,
            "sections": [{"index": 0, "rva": "0x1000", "bytes": 12, "available_bytes": 12,
                          "unavailable_bytes": 0, "blocks": [
                {"rva": "0x1000", "bytes": 8, "available": True, "code_sha256": "a"*64,
                 "file": "section_00_rva_00001000.code"},
                {"rva": "0x1008", "bytes": 4, "available": True, "code_sha256": "b"*64,
                 "file": "section_00_rva_00001008.code"}]}],
            "actual_RPM_count": 2, "RPM_requested_bytes": 12, "saved_code_bytes": 12,
            "unavailable_bytes": 0, "known_sender_comparisons": []}
        self.total = patch.object(writer, "TOTAL_BYTES", 12)
        self.known = patch.object(writer, "KNOWN_SENDERS", ())
        self.total.start()
        self.known.start()
        self.addCleanup(self.total.stop)
        self.addCleanup(self.known.stop)

    def test_complete_contiguous_fixture(self):
        self.assertEqual(len(writer.validate_manifest(self.manifest, self.plan)), 2)

    def test_failed_partial_and_unqualified_caches_rejected(self):
        for field, value in (("status", "code_cache_failed"), ("complete", False),
                             ("scope_coverage_complete", False), ("live_data_object_read", True),
                             ("reconstructed_executable", True)):
            with self.subTest(field=field):
                manifest = copy.deepcopy(self.manifest)
                manifest[field] = value
                with self.assertRaises(ValueError):
                    writer.validate_manifest(manifest, self.plan)

    def test_gap_bad_name_hash_unavailable_and_boolean_length_rejected(self):
        for field, value in (("rva", "0x1009"), ("file", "../escape.code"),
                             ("code_sha256", "z"*64), ("available", False), ("bytes", True)):
            with self.subTest(field=field):
                manifest = copy.deepcopy(self.manifest)
                manifest["sections"][0]["blocks"][1][field] = value
                with self.assertRaises(ValueError):
                    writer.validate_manifest(manifest, self.plan)

    def test_missing_chunk_and_bad_accounting_rejected(self):
        manifest = copy.deepcopy(self.manifest)
        manifest["sections"][0]["blocks"].pop()
        with self.assertRaises(ValueError):
            writer.validate_manifest(manifest, self.plan)
        for field, value in (("actual_RPM_count", 3), ("RPM_requested_bytes", 13),
                             ("saved_code_bytes", 11), ("unavailable_bytes", 1)):
            with self.subTest(field=field):
                manifest = copy.deepcopy(self.manifest)
                manifest[field] = value
                with self.assertRaises(ValueError):
                    writer.validate_manifest(manifest, self.plan)

    def test_known_native_sender_mismatch_rejected(self):
        with patch.object(writer, "KNOWN_SENDERS", (("sender", 0x1000, 4, "d"*64),)):
            manifest = copy.deepcopy(self.manifest)
            manifest["known_sender_comparisons"] = [{"name": "sender", "rva": "0x1000", "bytes": 4,
                "available": True, "extra_live_reads": 0, "matches_saved_native_sample": True,
                "expected_code_sha256": "d"*64, "cache_code_sha256": "e"*64}]
            with self.assertRaises(ValueError):
                writer.validate_manifest(manifest, self.plan)


class NativeBoundaryTests(unittest.TestCase):
    def lea(self, rva):
        return bytes.fromhex("488d0d")+struct.pack("<i", writer.TARGET_RVA-rva-7)

    def fake_cache(self, chunks):
        cache = object.__new__(writer.Cache)
        cache.blocks = [(rva, len(data), "", "") for rva, data in chunks]
        mapping = dict(chunks)
        cache.block = lambda row: mapping[row[0]]
        return cache

    def test_cross_chunk_lea_preserves_rex_candidate(self):
        root = 0x1000
        code = self.lea(root)+b"\xc3"
        cache = self.fake_cache([(root, code[:3]), (root+3, code[3:])])
        candidates = cache.exact_lea_candidates()
        self.assertIn({"rva": root, "bytes": code[:7].hex()}, candidates)
        decoded, limits = writer.reachable_instructions(code, root)
        self.assertEqual(decoded[root].mnemonic, "lea")
        self.assertEqual(limits, [])

    def test_gap_never_joins_chunks(self):
        root = 0x1000
        code = self.lea(root)
        cache = self.fake_cache([(root, code[:3]), (root+4, code[3:])])
        self.assertEqual(cache.exact_lea_candidates(), [])

    def test_lea_bytes_inside_mov_immediate_not_instruction(self):
        root = 0x1000
        code = bytes.fromhex("48b8")+self.lea(root+2)+b"\x00\xc3"
        candidates = self.fake_cache([(root, code)]).exact_lea_candidates()
        self.assertTrue(any(row["rva"] == root+2 for row in candidates))
        decoded, _ = writer.reachable_instructions(code, root)
        self.assertNotIn(root+2, decoded)

    def test_direct_branch_skips_data_and_reaches_exact_lea(self):
        root = 0x1000
        code = b"\xeb\x06"+b"\xcc"*6+self.lea(root+8)+b"\xc3"
        decoded, limits = writer.reachable_instructions(code, root)
        self.assertIn(root+8, decoded)
        self.assertNotIn(root+2, decoded)
        self.assertEqual(limits, [])

    def test_branch_to_middle_of_instruction_rejected(self):
        code = b"\x75\x03\x48\xb8"+b"\x90"*8+b"\xc3"
        with self.assertRaisesRegex(ValueError, "middle"):
            writer.reachable_instructions(code, 0x1000)

    def test_indirect_branch_is_limitation_not_guessed_target(self):
        decoded, limits = writer.reachable_instructions(b"\xff\xe0", 0x1000)
        self.assertEqual(list(decoded), [0x1000])
        self.assertEqual(limits[0]["reason"], "indirect_branch_not_followed")


if __name__ == "__main__":
    unittest.main()
