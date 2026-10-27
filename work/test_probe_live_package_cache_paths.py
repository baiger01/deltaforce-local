import unittest

import package_cache_path_lookup as paths
import probe_live_package_cache_paths as tool
from test_package_cache_path_lookup import fixture_contract


class PackageCacheAdapterScopeTests(unittest.TestCase):
    BASE = 0x140000000

    @classmethod
    def setUpClass(cls):
        cls.spans = tool.module_spans(fixture_contract())

    def test_only_exact_source_module_ranges_are_admitted(self):
        for rva, size in self.spans:
            tool.bounded_read_arguments(self.BASE + rva, size, self.BASE, self.spans, 0)
            with self.assertRaisesRegex(ValueError, 'not_source_qualified'):
                tool.bounded_read_arguments(self.BASE + rva + 1, size, self.BASE, self.spans, 0)
        for address, size in ((self.BASE, 4), (self.BASE + paths.ROOT_SLOT, 16),
                              (self.BASE - 1, 2), (self.BASE + paths.MODULE_SIZE - 1, 2)):
            with self.assertRaisesRegex(ValueError, 'not_source_qualified'):
                tool.bounded_read_arguments(address, size, self.BASE, self.spans, 0)

    def test_typed_external_provider_bounds_and_budget_are_enforced(self):
        tool.bounded_read_arguments(0x250000000, 80, self.BASE, self.spans, 0)
        for address, size, total in ((0, 80, 0), (paths.MAX_ADDRESS, 1, 0),
                                     (0x250000000, 0, 0), (0x250000000, 1025, 0),
                                     (0x250000000, 4, paths.MAX_TOTAL_READ - 3)):
            with self.subTest(address=address, size=size, total=total):
                with self.assertRaises(ValueError):
                    tool.bounded_read_arguments(address, size, self.BASE, self.spans, total)


if __name__ == '__main__':
    unittest.main()
