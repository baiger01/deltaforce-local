"""Independent metadata type regressions; literal snapshots, no native API."""
import unittest

from test_native_scalar_command_binding import (
    CLASS_ADDRESS, DRIVER_ADDRESS, bind, command, literal_report,
)


class ScalarBindingIdentityReviewTests(unittest.TestCase):
    def test_positive_literal_retains_exact_command_and_driver_identity(self):
        result = bind(literal_report())
        self.assertEqual((result.command_index, result.driver_address), (7, DRIVER_ADDRESS))
        self.assertEqual((result.descriptor_name, result.relative_handle, result.parent_index),
                         ('SyntheticBool', 731, 6))
        self.assertEqual(result.scalar_kind, 'bool')

    def test_same_value_float_export_addresses_cannot_alias_integer_identity(self):
        # These floats compare equal to the real integer root addresses. A
        # selection using Python equality alone used to qualify both records.
        for field, integer in (('class_address', CLASS_ADDRESS),
                               ('driver_address', DRIVER_ADDRESS)):
            report = literal_report()
            report['driver_class_exports'][0][field] = float(integer)
            self.assertEqual(report['driver_class_exports'][0][field], integer)
            with self.subTest(field=field), self.assertRaises(ValueError):
                bind(report)

    def test_noninteger_export_addresses_and_caller_driver_fail_closed(self):
        for field in ('class_address', 'driver_address'):
            for value in (True, False, None, 'not-a-pointer'):
                report = literal_report()
                report['driver_class_exports'][0][field] = value
                with self.subTest(field=field, value=value), self.assertRaises(ValueError):
                    bind(report)
        for value in (True, False, float(DRIVER_ADDRESS)):
            with self.subTest(driver_address=value), self.assertRaises(ValueError):
                bind(driver_address=value)

    def test_dispatch_opcode_must_fit_actual_native_unsigned_byte(self):
        for value in (-1, -256, 256, 65536, True, 3.0):
            report = literal_report()
            command(report)['dispatch_opcode'] = value
            with self.subTest(opcode=value), self.assertRaises(ValueError):
                bind(report)


if __name__ == '__main__':
    unittest.main()
