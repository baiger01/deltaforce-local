"""Select the served entry profile without confusing it with dependencies."""
import hashlib
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import observe_owned_weapon_state as observer
from portable_map_bootstrap import PortableMapPlan, load_plan


class WeaponObserverProfileTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.root = Path(self.directory.name)
        self.addCleanup(patch.stopall)
        patch.object(observer, 'ROOT', self.root).start()
        self.pins = {}
        self.base = self.profile('profile.json')
        self.active = self.profile('profile-carried-inventory.json')

    def profile(self, name):
        relative = 'outputs/df-local-server/protocol/portable-map-spawn/' + name
        path = self.root / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        raw = json.dumps({'kind': 'portable_local_map_bootstrap_profile',
                          'name': name}).encode()
        path.write_bytes(raw)
        self.pins[relative] = hashlib.sha256(raw).hexdigest()
        return relative

    def report(self, **metadata):
        return {'portable_map_bootstrap': {'source_pins': self.pins, **metadata}}

    def test_explicit_entry_profile_disambiguates_its_base_dependency(self):
        self.assertEqual(observer._profile_path(self.report(profile_relative_path=self.active)),
                         (self.root / self.active).resolve())

    def test_explicit_profile_must_be_pinned(self):
        del self.pins[self.active]
        with self.assertRaisesRegex(ValueError, 'pinned'):
            observer._profile_path(self.report(profile_relative_path=self.active))

    def test_changed_explicit_profile_is_rejected(self):
        (self.root / self.active).write_bytes(b'{}')
        with self.assertRaisesRegex(ValueError, 'changed'):
            observer._profile_path(self.report(profile_relative_path=self.active))

    def test_explicit_profile_must_have_the_profile_kind(self):
        raw = b'{"kind": "unrelated"}'
        (self.root / self.active).write_bytes(raw)
        self.pins[self.active] = hashlib.sha256(raw).hexdigest()
        with self.assertRaises(ValueError):
            observer._profile_path(self.report(profile_relative_path=self.active))

    def test_explicit_profile_cannot_escape_root_or_use_an_alias(self):
        for relative in ('../profile.json', str((self.root / self.active).resolve()),
                         self.active.replace('/', '\\'),
                         self.active.replace('profile-carried', '../profile-carried')):
            with self.subTest(relative=relative), self.assertRaises(ValueError):
                observer._profile_path(self.report(profile_relative_path=relative))

    def test_invalid_explicit_identity_cannot_fall_back_to_a_dependency(self):
        del self.pins[self.active]
        for value in (None, '', 1):
            with self.subTest(value=value), self.assertRaises(ValueError):
                observer._profile_path(self.report(profile_relative_path=value))

    def test_legacy_report_with_only_one_profile_is_supported(self):
        del self.pins[self.base]
        self.assertEqual(observer._profile_path(self.report()),
                         (self.root / self.active).resolve())

    def test_legacy_ambiguous_report_remains_rejected(self):
        with self.assertRaisesRegex(ValueError, 'One exact'):
            observer._profile_path(self.report())


class PortableProfileIdentityTests(unittest.TestCase):
    def test_plan_summary_keeps_the_callers_actual_entry_profile(self):
        root = Path(__file__).resolve().parents[1]
        relative = 'outputs/df-local-server/protocol/portable-map-spawn/profile-carried-inventory.json'
        plan = load_plan(root, root / relative)
        report = {'portable_map_bootstrap': plan.summary()}
        self.assertEqual(report['portable_map_bootstrap'].get('profile_relative_path'), relative)
        self.assertEqual(observer._profile_path(report), (root / relative).resolve())


if __name__ == '__main__':
    unittest.main()
