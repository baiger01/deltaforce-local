"""Guard the canonical runtime entry points after retiring the map worktree."""
import importlib
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT / 'work'))


class CanonicalMapRuntimeTests(unittest.TestCase):
    def test_backend_supplies_the_actual_atomic_match_snapshot(self):
        from dfserver.core import Backend
        from dfserver.hero_customization import BASES
        with tempfile.TemporaryDirectory() as folder:
            backend = Backend(Path(folder) / 'save.sqlite3',
                              ROOT / 'outputs/df-local-server/definitions.json')
            token = backend.register('canonical_map', 'isolated-test-password')['session']
            backend.set_native_selected_hero(token, next(iter(BASES)))
            lobby = backend.native_lobby_profile(token)
            hero, fashion, raw = backend.native_match_snapshot(token)
            snapshot = json.loads(raw)
            self.assertEqual(hero, lobby['selected_hero_id'])
            self.assertEqual(snapshot['selected_hero_id'], hero)
            self.assertEqual(snapshot['selected_fashion_id'], fashion)
            self.assertIn('props', snapshot)
            self.assertIn('body_layouts', snapshot)

    def test_normal_launch_enables_the_lobby_and_map_runtime_together(self):
        from run_local_game import command, HISTORICAL_CLIENT
        with patch('run_local_game.client_build', return_value=HISTORICAL_CLIENT):
            args = command()
        self.assertIn('--game-server-probe', args)
        self.assertIn('--ds-control-probe', args)
        self.assertIn('--portable-map-bootstrap', args)
        self.assertEqual(args[args.index('--ds-map-id') + 1], '2201')
        self.assertEqual(args[args.index('--observation-seconds') + 1], '1800')

    def test_full_carried_profile_has_current_canonical_source_leases(self):
        from portable_map_bootstrap import load_plan
        from portable_source_guard import SourceGuard
        plan = load_plan(ROOT, ROOT / 'outputs/df-local-server/protocol/portable-map-spawn/profile-carried-inventory.json')
        try:
            guard = SourceGuard(ROOT, plan.sources)
            self.assertTrue(guard())
        finally:
            if 'guard' in locals():
                guard.close()
        self.assertIsNotNone(plan.admission_movement_factory)
        self.assertIsNotNone(plan.inventory_content_factory)
        self.assertIsNotNone(plan.admission_owner_switch_factory)

    def test_portable_runtime_and_admission_are_available_in_main(self):
        portable = importlib.import_module('portable_map_bootstrap')
        from dfserver.game_server_probe import GameServerProbe
        self.assertTrue(callable(portable.load_plan))
        self.assertTrue(callable(GameServerProbe.set_pc_restart_profile))
        self.assertTrue(callable(GameServerProbe.set_pc_startup_profile))
        self.assertTrue(Path(portable.__file__).resolve().is_relative_to(ROOT))

    def test_both_canonical_launchers_accept_portable_map_bootstrap(self):
        for name in ('run_native_elevated_trial.py', 'verify_local_provider_client.py'):
            with self.subTest(name=name):
                self.assertIn('--portable-map-bootstrap',
                              (ROOT / 'work' / name).read_text(encoding='utf-8'))


if __name__ == '__main__':
    unittest.main()
