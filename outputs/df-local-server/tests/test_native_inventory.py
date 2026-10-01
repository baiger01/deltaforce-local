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


class NativeContainerMoveTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.backend = Backend(Path(self.temporary.name) / 'save.sqlite3',
                               ROOT / 'definitions.json')
        self.token = self.backend.register('move-test', 'local-password-123')['session']
        self.backend.set_native_lobby_profile(self.token, level=60, currencies={}, props=[
            NativeContainerSyncTests.prop(1001, 11070005004, 107),
            NativeContainerSyncTests.prop(1002, 14020000003, 107001, x=5),
            NativeContainerSyncTests.prop(1003, 15080050006, 2),
        ])

    def state(self):
        return {p['gid']: p for p in self.backend.native_lobby_profile(self.token)['props']}

    def move(self, loc, *, target_gid=0):
        return self.backend.native_lobby_move_props(self.token, [{
            'prop_id': 15080050006, 'prop_gid': 1003, 'src_pos': 2,
            'target_pos': 107001, 'target_prop_gid': target_gid,
            'num': 1, 'spec_loc': {'pos': 107001, 'space_id': 5, **loc}}])

    def test_decoded_zero_coordinate_keeps_requested_chest_cell(self):
        # Native request 1821 carries start_x=1 and omits start_y=0.
        self.move({'start_x': 1, 'x': 1, 'y': 1})
        self.assertEqual((self.state()[1003]['x'], self.state()[1003]['y']), (5, 1))

    def test_decoded_zero_x_keeps_requested_chest_row(self):
        self.move({'start_y': 1, 'x': 1, 'y': 1})
        self.assertEqual((self.state()[1003]['x'], self.state()[1003]['y']), (5, 2))

    def test_explicit_occupied_cell_does_not_silently_choose_another_cell(self):
        before = self.state()
        with self.assertRaises(DomainError):
            self.move({'x': 1, 'y': 1})
        self.assertEqual(self.state(), before)

    def test_target_instance_swaps_both_items_and_survives_snapshot(self):
        # Native request 1903 identifies the occupied destination by gid.
        changes = self.move({'x': 1, 'y': 1}, target_gid=1002)
        state = self.state()
        self.assertEqual((state[1003]['grid_page_id'], state[1003]['x'], state[1003]['y']),
                         (107001, 5, 0))
        self.assertEqual((state[1002]['grid_page_id'], state[1002]['x'], state[1002]['y']),
                         (2, 0, 0))
        self.assertEqual({change['after']['gid'] for change in changes}, {1002, 1003})
        self.backend.native_lobby_sync_body_containers(self.token, [{
            'pos': 107001, 'space': 5, 'props': [{
                'id': 15080050006, 'gid': 1003, 'num': 1,
                'loc': {'pos': 107001, 'space_id': 5, 'x': 1, 'y': 1}}]}])
        self.assertEqual(self.state(), state)

    def test_same_container_swap_moves_both_items(self):
        self.backend.set_native_lobby_profile(self.token, level=60, currencies={}, props=[
            NativeContainerSyncTests.prop(1001, 11070005004, 107),
            NativeContainerSyncTests.prop(1002, 14020000003, 107001, x=5),
            NativeContainerSyncTests.prop(1003, 15080050006, 107001, x=2),
        ])
        changes = self.backend.native_lobby_move_props(self.token, [{
            'prop_id': 15080050006, 'prop_gid': 1003, 'src_pos': 107001,
            'target_pos': 107001, 'target_prop_gid': 1002,
            'num': 1, 'spec_loc': {'pos': 107001, 'space_id': 5, 'x': 1, 'y': 1}}])
        state = self.state()
        self.assertEqual((state[1002]['x'], state[1002]['y']), (2, 0))
        self.assertEqual((state[1003]['x'], state[1003]['y']), (5, 0))
        self.assertEqual(len(changes), 2)

    def test_rotated_item_keeps_client_orientation_after_move_and_sync(self):
        self.backend.set_native_lobby_profile(self.token, level=60, currencies={}, props=[
            NativeContainerSyncTests.prop(1001, 11070005004, 107),
            {**NativeContainerSyncTests.prop(1002, 14020000005, 107001, x=3),
             'length': 3, 'width': 1},
        ])
        with self.backend.connection() as connection:
            connection.execute('INSERT INTO native_lobby_prop_rotations VALUES (?,1)', (1002,))
            connection.commit()
        self.backend.native_lobby_move_props(self.token, [{
            'prop_id': 14020000005, 'prop_gid': 1002, 'src_pos': 107001,
            'target_pos': 107001, 'num': 1, 'spec_loc': {
                'pos': 107001, 'space_id': 1, 'x': 1, 'y': 3, 'rotate': True}}])
        state = self.state()
        self.assertEqual((state[1002]['x'], state[1002]['length'], state[1002]['width']), (1, 3, 1))
        self.assertTrue(state[1002]['rotated'])
        self.backend.native_lobby_sync_body_containers(self.token, [{
            'pos': 107001, 'space': 1, 'props': [{
                'id': 14020000005, 'gid': 1002, 'num': 1, 'loc': {
                    'pos': 107001, 'space_id': 1, 'x': 1, 'y': 3, 'rotate': True}}]}])
        self.assertEqual(self.state(), state)

    def test_swap_rejects_item_that_cannot_fit_the_source_without_side_effects(self):
        self.backend.set_native_lobby_profile(self.token, level=60, currencies={}, props=[
            NativeContainerSyncTests.prop(1001, 11070005004, 107),
            {**NativeContainerSyncTests.prop(1002, 14020000005, 107001, x=1),
             'length': 3, 'width': 1},
            NativeContainerSyncTests.prop(1003, 15080050006, 199997, x=1),
        ])
        with self.backend.connection() as connection:
            connection.execute('INSERT INTO native_lobby_prop_rotations VALUES (?,1)', (1002,))
            connection.commit()
        before = self.state()
        with self.assertRaises(DomainError):
            self.backend.native_lobby_move_props(self.token, [{
                'prop_id': 15080050006, 'prop_gid': 1003, 'src_pos': 199997,
                'target_pos': 107001, 'target_prop_gid': 1002, 'num': 1,
                'spec_loc': {'pos': 107001, 'space_id': 1, 'x': 1, 'y': 1}}])
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
