"""Exercise legacy import identity, resource paths and supported CLI entry points."""
import importlib
import json
import os
from pathlib import Path
import subprocess
import sys
import unittest
from unittest.mock import patch

SERVER_ROOT = Path(__file__).resolve().parent.parent


class ServerLayoutTests(unittest.TestCase):
    def test_all_legacy_modules_alias_the_actual_implementation(self):
        layout = json.loads((SERVER_ROOT / 'dfserver/module_layout.json').read_text(encoding='utf-8'))
        actual = {path.stem for path in (SERVER_ROOT / 'dfserver').glob('*.py')
                  if not path.stem.startswith('_')}
        self.assertEqual(actual, set(layout['modules']) - {'__main__'})
        for name, row in layout['modules'].items():
            with self.subTest(module=name):
                old = importlib.import_module('dfserver.' + name)
                implementation = importlib.import_module(row['canonical'])
                self.assertIs(old, implementation)
                self.assertEqual(Path(implementation.__file__).resolve(),
                                 (SERVER_ROOT / row['source']).resolve())

    def test_legacy_private_and_global_patches_reach_the_implementation(self):
        from dfserver import core, handshake_diagnostic
        from dfserver.app import core as canonical_core
        from dfserver.gateway import handshake_diagnostic as canonical_gateway
        with patch('dfserver.core.NATIVE_PURCHASE_PACKING_STEPS', 17):
            self.assertEqual(canonical_core.NATIVE_PURCHASE_PACKING_STEPS, 17)
            self.assertEqual(core._native_purchase_placements.__globals__['NATIVE_PURCHASE_PACKING_STEPS'], 17)
        with patch('dfserver.handshake_diagnostic._candidate_local_map_board_catalog', return_value={}):
            self.assertEqual(canonical_gateway._candidate_local_map_board_catalog(), {})
            self.assertIs(handshake_diagnostic, canonical_gateway)

    def test_resource_roots_do_not_depend_on_implementation_depth(self):
        from dfserver._paths import CONFIG_ROOT, PACKAGE_ROOT, PROTOCOL_ROOT, SERVER_ROOT as actual_root, WEB_ROOT
        from dfserver import http_api, battle_pass
        self.assertEqual(actual_root, SERVER_ROOT)
        self.assertEqual(PACKAGE_ROOT, SERVER_ROOT / 'dfserver')
        self.assertEqual(CONFIG_ROOT, SERVER_ROOT / 'config')
        self.assertEqual(PROTOCOL_ROOT, SERVER_ROOT / 'protocol')
        self.assertEqual(http_api.UI_ROOT, WEB_ROOT)
        self.assertEqual(battle_pass.PROTOCOL, PROTOCOL_ROOT)
        for path in (actual_root / 'definitions.json', CONFIG_ROOT / 'quest_completion.json',
                     WEB_ROOT / 'index.html', PROTOCOL_ROOT / 'game_item_catalog.json'):
            self.assertTrue(path.is_file(), str(path))

    def test_supported_legacy_cli_help_exits_without_starting_services(self):
        env = dict(os.environ, PYTHONDONTWRITEBYTECODE='1', PYTHONPATH=str(SERVER_ROOT))
        for name in ('dfserver', 'dfserver.accounts', 'dfserver.entrance',
                     'dfserver.connection_probe', 'dfserver.handshake_diagnostic'):
            with self.subTest(module=name):
                result = subprocess.run([sys.executable, '-B', '-m', name, '--help'],
                                        cwd=SERVER_ROOT, env=env, capture_output=True,
                                        text=True, encoding='utf-8', timeout=30)
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertIn('usage:', result.stdout)


if __name__ == '__main__':
    unittest.main()
