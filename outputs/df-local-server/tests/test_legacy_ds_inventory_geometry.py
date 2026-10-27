import unittest

from dfserver import legacy_ds_inventory_geometry as geometry


class InventoryGeometryTests(unittest.TestCase):
    def test_real_backpack_segments_use_ids_and_half_units(self):
        grids=geometry.grids_from_raw_layout('(2,2)(2,1)|(2,3)(-2,-4)')
        self.assertEqual([(g.grid_id,g.start_x,g.start_y,g.length,g.height,g.logic_half_unit_x,g.logic_half_unit_y)
            for g in grids],[(1,0,0,2,2,2,1),(2,0,0,2,3,-2,-4)])

    def test_pb_cpp_rotation_preserves_displayed_shape(self):
        value=geometry.location_from_business_location(dict(start_x=2,start_y=1,x=2,y=3,rotate=True,space_id=4))
        self.assertEqual((value.x,value.y,value.length,value.height,value.rotated,value.grid_index),(2,1,3,2,True,4))
        value=geometry.location_from_business_location(dict(start_x=0,start_y=0,x=2,y=2,rotate=True,space_id=0))
        self.assertEqual((value.rotated,value.grid_index),(False,1))

    def test_equipment_and_container_self_are_distinct(self):
        self.assertEqual(geometry.equipment_location().grid_index,1)
        self.assertEqual(geometry.container_self_location().grid_index,0)
        self.assertEqual((geometry.equipment_location().length,geometry.equipment_location().height),(1,1))

    def test_unknown_or_unrepresentable_coordinates_fail_closed(self):
        for raw in ('','(2,2)(128,0)','(0,2)(0,0)','garbage'):
            with self.assertRaises(ValueError):
                geometry.grids_from_raw_layout(raw)
        with self.assertRaises(ValueError):
            geometry.location_from_business_location(dict(start_x=0,start_y=0,x=1,y=1,rotate=False,space_id=2201))


if __name__=='__main__':
    unittest.main()
