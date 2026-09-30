import tempfile
from pathlib import Path
import unittest

from dfserver.core import Backend, DomainError


ROOT = Path(__file__).resolve().parent.parent


class NativeContainerSyncTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.backend = Backend(Path(self.temporary.name) / 'save.sqlite3',
                               ROOT / 'definitions.json')
        self.token = self.backend.register('sync-test', 'local-password-123')['session']
        self.backend.set_native_lobby_profile(self.token, level=60, currencies={}, props=[
            self.prop(1001, 11070004001, 107),
            self.prop(1002, 14020000003, 2, quantity=3),
            self.prop(1003, 14020000003, 107001, x=1, y=0),
        ])

    @staticmethod
    def prop(gid, template_id, position, *, quantity=1, x=0, y=0):
        return {'gid': gid, 'template_id': template_id, 'quantity': quantity,
                'grid_page_id': position, 'x': x, 'y': y, 'length': 1, 'width': 1}

    @staticmethod
    def snapshot(gid, *, count=1, x=0, y=0, space=1):
        return {'pos': 107001, 'space': space, 'props': [{
            'id': 14020000003, 'gid': gid, 'num': count, 'position': 107001,
            'loc': {'pos': 107001, 'space_id': space, 'start_x': x,
                    'start_y': y, 'x': 1, 'y': 1, 'rotate': False}}]}

    def state(self):
        return {prop['gid']: prop for prop in self.backend.native_lobby_profile(self.token)['props']}

    def test_snapshot_moves_paid_item_and_evacuates_omitted_item_without_loss(self):
        snapshots = [self.snapshot(1002, count=3)]
        self.assertTrue(callable(getattr(self.backend, 'native_lobby_sync_body_containers', None)))
        self.backend.native_lobby_sync_body_containers(self.token, snapshots)
        state = self.state()
        self.assertEqual((state[1002]['grid_page_id'], state[1002]['x']), (107001, 1))
        self.assertEqual(state[1003]['grid_page_id'], 2)
        self.assertEqual(sum(p['quantity'] for p in state.values() if p['template_id'] == 14020000003), 4)
        self.backend.native_lobby_sync_body_containers(self.token, snapshots)
        self.assertEqual(self.state(), state)

    def test_snapshot_cannot_create_unowned_items_or_increase_quantity(self):
        self.assertTrue(callable(getattr(self.backend, 'native_lobby_sync_body_containers', None)))
        before = self.state()
        for gid, count in ((0, 1), (999999, 1), (1002, 4)):
            with self.assertRaises(DomainError):
                self.backend.native_lobby_sync_body_containers(
                    self.token, [self.snapshot(gid, count=count)])
            self.assertEqual(self.state(), before)

    def test_snapshot_splits_an_owned_stack_and_preserves_remaining_quantity(self):
        self.assertTrue(callable(getattr(self.backend, 'native_lobby_sync_body_containers', None)))
        self.backend.native_lobby_sync_body_containers(self.token, [
            self.snapshot(1002, count=1), self.snapshot(1002, count=1, space=2)])
        meds = [p for p in self.state().values() if p['template_id'] == 14020000003]
        self.assertEqual(sum(p['quantity'] for p in meds), 4)
        self.assertEqual(sum(p['quantity'] for p in meds if p['grid_page_id'] == 107001), 2)
        self.assertEqual(len({p['gid'] for p in meds}), len(meds))

    def test_snapshot_overlap_rolls_back_entire_batch(self):
        self.assertTrue(callable(getattr(self.backend, 'native_lobby_sync_body_containers', None)))
        before = self.state()
        overlap = self.snapshot(1002, count=1)
        overlap['props'].extend(self.snapshot(1003)['props'])
        with self.assertRaises(DomainError):
            self.backend.native_lobby_sync_body_containers(self.token, [overlap])
        self.assertEqual(self.state(), before)


class NativeBulletOperationTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.path = Path(self.temporary.name) / 'save.sqlite3'
        self.backend = Backend(self.path, ROOT / 'definitions.json')
        self.token = self.backend.register('ammo-test', 'local-password-123')['session']
        self.backend.set_native_lobby_profile(self.token, level=60, currencies={}, props=[
            {'gid': 2001, 'template_id': 18020000003, 'quantity': 1,
             'grid_page_id': 111, 'x': 0, 'y': 0, 'length': 4, 'width': 2},
            {'gid': 2002, 'template_id': 37190000001, 'quantity': 60,
             'grid_page_id': 199997, 'x': 1, 'y': 0, 'length': 1, 'width': 1},
        ])

    @staticmethod
    def command(*, op_type=1, count=17, bullet_gid=2002, bullet_id=37190000001):
        return {'op_type': op_type, 'bullet_id': bullet_id, 'bullet_gid': bullet_gid,
                'bullet_op_num': count, 'target_gun_rec_id': 18020000003,
                'target_gun_rec_gid': 2001}

    def state(self):
        return {prop['gid']: prop for prop in self.backend.native_lobby_profile(self.token)['props']}

    def operate(self, commands):
        self.assertTrue(callable(getattr(self.backend, 'native_lobby_operate_bullets', None)))
        return self.backend.native_lobby_operate_bullets(self.token, commands)

    def test_loading_conserves_ammo_and_survives_a_reopened_backend(self):
        self.operate([self.command()])
        state = self.state()
        self.assertEqual(state[2002]['quantity'], 43)
        self.assertEqual(state[2001]['weapon']['magazine_capacity'], 17)
        self.assertEqual(sum(p['num'] for p in state[2001]['weapon']['load_bullets']), 17)
        self.backend = Backend(self.path, ROOT / 'definitions.json')
        self.assertEqual(self.state(), state)

    def test_invalid_second_command_rolls_back_the_first_load(self):
        before = self.state()
        with self.assertRaises(DomainError):
            self.operate([self.command(count=10), self.command(count=8)])
        self.assertEqual(self.state(), before)

    def test_loading_rejects_incompatible_client_ammo(self):
        before = self.state()
        with self.assertRaises(DomainError):
            self.operate([self.command(bullet_id=37010100001)])
        self.assertEqual(self.state(), before)

    def test_unloading_returns_paid_ammo_without_duplicate_instance_ids(self):
        self.operate([self.command()])
        loaded = self.state()[2001]['weapon']['load_bullets'][0]
        self.operate([self.command(op_type=2, count=17, bullet_gid=loaded['gid'])])
        state = self.state()
        self.assertEqual(state[2001]['weapon']['load_bullets'], [])
        self.assertEqual(sum(p['quantity'] for p in state.values()
                             if p['template_id'] == 37190000001), 60)
        self.assertEqual(len(set(state)), len(state))


if __name__ == '__main__':
    unittest.main()
