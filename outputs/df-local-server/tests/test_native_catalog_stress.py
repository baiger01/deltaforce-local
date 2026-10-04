import os
from pathlib import Path
import subprocess
import sys
import unittest


ROOT = Path(__file__).resolve().parent.parent
WORKER = r'''
from pathlib import Path
import tempfile

from dfserver.core import Backend
from dfserver import hero_customization, premium_shop
from dfserver.handshake_diagnostic import (
    _candidate_codec, _candidate_local_collection_response_frames)
from dfserver.gcp_data import decode_data_frame, encode_data_frame

with tempfile.TemporaryDirectory() as folder:
    backend = Backend(Path(folder) / 'save.sqlite3', Path('definitions.json'))
    token = backend.register('catalog-notification-stress', 'local-password-123')['session']
    codec = _candidate_codec()
    key = b'0123456789abcdef'
    offers = []
    for row in (*premium_shop.RECOMMENDATIONS.values(), *premium_shop.GIFTS.values()):
        ids = [item['id'] for group in row['bundle_item_list']
               for item in (group.get('item_list') or [group])]
        if any(hero_customization.affected_heroes(item_id) for item_id in ids):
            offers.append(ids)
    assert len(offers) >= 64
    largest = 0
    for index, ids in enumerate(offers[:64]):
        with backend.connection() as connection:
            player = backend._authorize(connection, token)
            for item_id in set(ids):
                connection.execute('INSERT INTO native_lobby_collection_props VALUES (?,?,1) '
                    'ON CONFLICT(player_id,template_id) DO UPDATE SET quantity=1', (player, item_id))
            connection.commit()
        # Simulate the committed grant before exercising the actual outgoing dispatcher.
        fields = {'result': 0, 'change': {'prop_changes': [
            {'change_type': 1, 'delta': 1, 'prop': {'id': item_id, 'gid': 0, 'num': 1}}
            for item_id in set(ids)]}}
        body = codec.encode('CSShopBuyHotRecommendationRes', fields, sequence=index + 1)
        frame = encode_data_frame((body,), key, direction='server_to_client',
            opaque_flag=64, header_word4=12, header_word9=index + 1)
        frames = _candidate_local_collection_response_frames(frame, key, backend, token)
        replies = [codec.decode(decode_data_frame(f, key, direction='server_to_client',
            compression_method=1, max_output=1024 * 1024).messages[0]) for f in frames]
        assert [r.name for r in replies] == [
            'CSCollectionPropChangeNtf', 'CSHeroUnlockNtf', 'CSShopBuyHotRecommendationRes']
        assert replies[-1].sequence == index + 1
        assert replies[-1].fields['result'] == 0
        largest = max(largest, len(replies[1].fields['heros']))
    assert largest == 17
print('catalog_notifications=64; largest_hero_list=17')
'''


class NativeCatalogStressTests(unittest.TestCase):
    def test_consecutive_real_bundle_notifications_survive_encoding_and_decoding(self):
        env = dict(os.environ, PYTHONPATH=str(ROOT))
        result = subprocess.run([sys.executable, '-X', 'faulthandler', '-c', WORKER],
            cwd=ROOT, env=env, text=True, capture_output=True, timeout=120)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn('catalog_notifications=64; largest_hero_list=17', result.stdout)


if __name__ == '__main__':
    unittest.main()
