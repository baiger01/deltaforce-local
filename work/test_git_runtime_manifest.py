"""A checkout manifest must be relative and preserve sealed bytes."""
import importlib
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest


class GitRuntimeManifestTests(unittest.TestCase):
    def module(self):
        spec = importlib.util.find_spec('git_runtime_manifest')
        self.assertIsNotNone(spec, 'Git handoff needs a verifiable dependency manifest')
        return importlib.import_module(spec.name)

    def test_verification_detects_missing_or_changed_bytes(self):
        module = self.module()
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            path = root/'source.py'
            path.write_bytes(b'qualified\r\n')
            report = module.make_manifest(root, ['source.py'])
            self.assertEqual(module.verify(root, report)['files_verified'], 1)
            path.write_bytes(b'qualified\n')
            with self.assertRaisesRegex(ValueError, 'SHA256'):
                module.verify(root, report)
            path.unlink()
            with self.assertRaises(FileNotFoundError):
                module.verify(root, report)

    def test_private_state_and_escaping_paths_are_refused(self):
        module = self.module()
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            for name in ('../escape.py', 'work/native-test-account/save.sqlite3',
                         'outputs/df-local-server/data/local.sqlite3', '.env', 'session.log'):
                with self.subTest(name=name), self.assertRaises(ValueError):
                    module.make_manifest(root, [name])


if __name__ == '__main__':
    unittest.main()
