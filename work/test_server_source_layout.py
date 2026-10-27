"""Source pin expansion uses isolated files and never launches a client."""
import hashlib
import json
from pathlib import Path
import tempfile
import unittest

from server_source_layout import PACKAGE, SERVER, expand_server_sources


class ServerSourceLayoutTests(unittest.TestCase):
    def fixture(self, root):
        package = root / PACKAGE
        package.mkdir(parents=True)
        source = 'dfserver/replication/legacy_ds_class_net_cache.py'
        manifest = dict(kind='server_domain_module_layout_v1', modules={
            'legacy_ds_class_net_cache': dict(source=source, canonical=source[:-3].replace('/', '.'))})
        (package / 'module_layout.json').write_text(json.dumps(manifest), encoding='utf-8')
        legacy = PACKAGE + 'legacy_ds_class_net_cache.py'
        for name in (legacy, SERVER + source, PACKAGE + '_compat.py', PACKAGE + '_paths.py',
                     PACKAGE + '__init__.py', PACKAGE + 'replication/__init__.py',
                     'work/server_source_layout.py'):
            path = root / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text('fixture source\n', encoding='utf-8')
        return legacy, SERVER + source, manifest

    def test_legacy_checkout_without_layout_preserves_its_original_list(self):
        with tempfile.TemporaryDirectory() as folder:
            files = ('work/a.py', PACKAGE + 'legacy_ds_class_net_cache.py')
            self.assertEqual(expand_server_sources(folder, files), files)

    def test_canonical_implementation_and_mapping_are_sealed_with_legacy_entry(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            legacy, canonical, _ = self.fixture(root)
            files = expand_server_sources(root, (legacy,))
            self.assertEqual(len(files), len(set(files)))
            self.assertTrue({legacy, canonical, PACKAGE + '_compat.py', PACKAGE + '_paths.py',
                             PACKAGE + '__init__.py', PACKAGE + 'replication/__init__.py',
                             PACKAGE + 'module_layout.json', 'work/server_source_layout.py'} <= set(files))
            before = {name: hashlib.sha256((root / name).read_bytes()).hexdigest() for name in files}
            (root / canonical).write_text('changed implementation\n', encoding='utf-8')
            after = {name: hashlib.sha256((root / name).read_bytes()).hexdigest() for name in files}
            self.assertNotEqual(before, after)
            self.assertEqual(before[legacy], after[legacy])
            self.assertNotEqual(before[canonical], after[canonical])

    def test_unsafe_or_inconsistent_mapping_is_rejected(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            legacy, _, manifest = self.fixture(root)
            manifest['modules']['legacy_ds_class_net_cache']['source'] = '../outside.py'
            (root / PACKAGE / 'module_layout.json').write_text(json.dumps(manifest), encoding='utf-8')
            with self.assertRaisesRegex(ValueError, 'escapes'):
                expand_server_sources(root, (legacy,))

    def test_missing_manifest_does_not_silently_seal_only_compatibility_files(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            (root / PACKAGE / 'app').mkdir(parents=True)
            with self.assertRaisesRegex(ValueError, 'missing'):
                expand_server_sources(root, (PACKAGE + 'core.py',))


if __name__ == '__main__':
    unittest.main()
