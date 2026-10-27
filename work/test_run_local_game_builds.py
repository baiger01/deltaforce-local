from pathlib import Path
import unittest
from unittest.mock import patch

import run_local_game


class CanonicalBuildRoutingTests(unittest.TestCase):
    def command(self):
        return run_local_game.command(source_game=Path('F:/WeGameApps/rail_apps/DeltaForce(2001918)'),
            shadow_game=Path('F:/deltaforce-local-shadow-build-79fb7b10'))

    def test_current_client_uses_current_profile_without_historical_readers(self):
        args = self.command()
        self.assertIn('--updated-minimum-actor-bootstrap', args)
        self.assertIn('--updated-client-transport-observation', args)
        self.assertNotIn('--portable-map-bootstrap', args)
        self.assertNotIn('--replication-metadata-export', args)
        self.assertEqual(args[args.index('--observation-seconds')+1], '1800')

    def test_unknown_build_has_no_historical_fallback(self):
        with patch.object(run_local_game, 'client_build', return_value='0' * 64):
            with self.assertRaisesRegex(ValueError, 'Unsupported'):
                self.command()

    def test_historical_client_keeps_its_existing_full_profile(self):
        with patch.object(run_local_game, 'client_build', return_value=run_local_game.HISTORICAL_CLIENT):
            args = self.command()
        self.assertIn('--portable-map-bootstrap', args)
        self.assertNotIn('--updated-minimum-actor-bootstrap', args)


if __name__ == '__main__':
    unittest.main()
