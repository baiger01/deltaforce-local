import importlib
import importlib.util
from types import SimpleNamespace
import unittest


class UpdatedMinimumLaunchTests(unittest.TestCase):
    def module(self):
        spec = importlib.util.find_spec('updated_minimum_launch')
        self.assertIsNotNone(spec, 'Minimum Actor mode needs an explicit launcher qualification')
        return importlib.import_module(spec.name)

    def test_actor_mode_requires_its_current_control_transport(self):
        module = self.module()
        for args in (SimpleNamespace(updated_minimum_actor_bootstrap=True),
                     SimpleNamespace(updated_minimum_actor_bootstrap=True,
                         updated_client_transport_observation=True, ds_control_probe=False)):
            with self.assertRaisesRegex(ValueError, 'current control'):
                module.qualify_launch(args, None, None)

    def test_actor_mode_flag_is_strictly_boolean(self):
        module = self.module()
        with self.assertRaises(ValueError):
            module.qualify_launch(SimpleNamespace(updated_minimum_actor_bootstrap='1'), None, None)


if __name__ == '__main__':
    unittest.main()
