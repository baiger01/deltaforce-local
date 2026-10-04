import tempfile
import unittest
from pathlib import Path

from dfserver import hero_customization as hero
from dfserver.client_errors import error_code
from dfserver.core import Backend, DomainError
from dfserver.handshake_diagnostic import _candidate_codec
from dfserver.local_commerce import SUPPORTED_REQUESTS, response_fields


ROOT = Path(__file__).resolve().parent.parent
QUERY = 'CSHeroGrowLineRewardViewReq'


class HeroGrowLineQueryTests(unittest.TestCase):
    def setUp(self):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.backend = Backend(Path(directory.name) / 'save.sqlite3', ROOT / 'definitions.json')
        self.token = self.backend.register('hero-growth-query', 'local-password-123')['session']
        self.codec = _candidate_codec()

    def request(self, hero_id):
        return self.codec.decode(self.codec.encode(QUERY, {'hero_id': hero_id}, sequence=91))

    def test_supported_native_query_roundtrips_all_current_heroes(self):
        self.assertIn(QUERY, hero.SUPPORTED_REQUESTS)
        self.assertIn(QUERY, SUPPORTED_REQUESTS)
        for hero_id in hero.BASES:
            with self.subTest(hero_id=hero_id):
                request = self.request(hero_id)
                result = response_fields(request, self.backend, self.token)
                self.assertEqual(result, {'result': 0, 'hero_id': hero_id, 'rewards': []})
                decoded = self.codec.decode(self.codec.response(request, result))
                self.assertEqual(decoded.name, 'CSHeroGrowLineRewardViewRes')
                self.assertEqual(decoded.sequence, 91)
                self.assertEqual(decoded.fields.get('result', 0), 0)
                self.assertEqual(int(decoded.fields['hero_id']), hero_id)
                self.assertEqual(decoded.fields.get('rewards', []), [])

    def test_unknown_or_omitted_hero_returns_native_error(self):
        for hero_id in (0, 88000000024, 88000000050):
            request = self.request(hero_id)
            result = hero.response_fields(request, self.backend, self.token)
            self.assertIsNotNone(result)
            self.assertEqual(result['result'], error_code('HeroUnknownHeroId'))
            self.codec.response(request, result)

    def test_query_requires_account_session(self):
        with self.assertRaises(DomainError) as raised:
            hero.response_fields(self.request(next(iter(hero.BASES))), self.backend, 'expired-local-session')
        self.assertEqual(raised.exception.code, 'UNAUTHORIZED')

    def test_preview_does_not_grant_or_modify_account_state(self):
        with self.backend.connection() as connection:
            before = list(connection.iterdump())
        result = hero.response_fields(self.request(next(iter(hero.BASES))), self.backend, self.token)
        self.assertIsNotNone(result)
        with self.backend.connection() as connection:
            self.assertEqual(list(connection.iterdump()), before)

    def test_reward_claim_remains_outside_query_scope(self):
        name = 'CSHeroGrowLineGetRewardsReq'
        request = self.codec.decode(self.codec.encode(name, {'hero_id': next(iter(hero.BASES))}, sequence=92))
        self.assertNotIn(name, hero.SUPPORTED_REQUESTS)
        self.assertIsNone(hero.response_fields(request, self.backend, self.token))


if __name__ == '__main__':
    unittest.main()
