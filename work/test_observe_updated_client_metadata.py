"""Class selection must not read ordinary instance names or state."""
import unittest
from unittest.mock import patch

from native_metadata_objects import ObjectRecord
from observe_updated_client_metadata import observe_classes


class Metadata:
    def __init__(self):
        self.rows = [ObjectRecord(0, 0x10000, 1, 0x10000),
                     ObjectRecord(1, 0x20000, 2, 0x10000),
                     ObjectRecord(2, 0x30000, 3, 0x20000)]
        self.names = {0x10000: 'Class', 0x20000: 'GPCharacter'}
        self.paths = {0x10000: '/Script/CoreUObject.Class',
                      0x20000: '/Script/GP.GPCharacter'}

    def records(self, **kwargs):
        kwargs['scan_metadata'].update(initial_range_exhausted=True)
        return iter(self.rows)

    def record(self, address):
        return next(row for row in self.rows if row.object_address == address)

    def class_pointer(self, address):
        return self.record(address).class_address

    def superclass(self, address):
        return 0

    def name(self, address):
        if address == 0x30000:
            raise AssertionError('An ordinary instance name must not be read')
        return self.names[address]

    def path(self, address):
        return self.paths[address]


class ClassObservationTests(unittest.TestCase):
    def test_descriptor_selection_does_not_read_instance_names(self):
        result = observe_classes(Metadata())
        self.assertEqual([row['name'] for row in result['selected_classes']], ['Class', 'GPCharacter'])
        self.assertFalse(result['native_protocol_compatibility_verified'])
        self.assertFalse(result['class_fields_or_replication_handles_exported'])

    def test_familiar_name_without_native_class_path_is_refused(self):
        reader = Metadata()
        reader.paths[0x10000] = '/Other.Class'
        with self.assertRaisesRegex(ValueError, 'singleton'):
            observe_classes(reader)

    def test_changed_selected_type_refuses_entire_observation(self):
        reader = Metadata()
        with patch.object(reader, 'class_pointer', return_value=0x40000):
            with self.assertRaisesRegex(ValueError, 'changed'):
                observe_classes(reader)

    def test_unselected_native_class_does_not_trigger_outer_path_walk(self):
        reader = Metadata()
        reader.rows += [ObjectRecord(3, 0x40000, 4, 0x10000),
                        ObjectRecord(4, 0x50000, 5, 0x40000)]
        reader.names[0x40000] = 'UnselectedClass'
        # No path or ordinary-instance name exists for these objects.
        result = observe_classes(reader)
        self.assertEqual(result['selected_class_count'], 2)

    def test_current_map_components_and_movement_descriptor_are_observed(self):
        reader = Metadata()
        labels = ('MapInfoSystem', 'MapInfoComponent', 'BlueprintPlunder', 'MovementReplicationActor')
        for index, label in enumerate(labels, 3):
            address = (index+1)*0x10000
            reader.rows.append(ObjectRecord(index, address, index+1, 0x10000))
            reader.names[address] = label
            reader.paths[address] = '/Script/DFMGameplay.'+label
        result = observe_classes(reader)
        selected = {row['name'] for row in result['selected_classes']}
        self.assertTrue(set(labels) <= selected)

    def test_ancestor_must_be_a_typed_descriptor_not_an_instance(self):
        reader = Metadata()
        with patch.object(reader, 'superclass', return_value=0x30000):
            with self.assertRaisesRegex(ValueError, 'descriptor'):
                observe_classes(reader, include_ancestors=True)

    def test_recycled_class_during_export_cannot_keep_the_original_label(self):
        reader = Metadata()
        def export(address):
            if address == 0x10000:
                reader.rows[1] = ObjectRecord(1, 0x20000, 99, 0x10000)
                reader.names[0x20000] = 'InstanceReplacement'
                reader.paths[0x20000] = '/Other.InstanceReplacement'
            return {'observed': True}
        with self.assertRaisesRegex(ValueError, 'changed'):
            observe_classes(reader, class_export=export)


if __name__ == '__main__':
    unittest.main()
