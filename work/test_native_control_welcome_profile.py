"""Pure disk/profile checks; never import or run either native trial launcher."""
import argparse
import ast
import contextlib
import copy
import hashlib
import io
import json
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest


WORK = Path(__file__).resolve().parent
SOURCES = (WORK / 'run_native_elevated_trial.py', WORK / 'verify_local_provider_client.py')
CLIENT_SHA = '4254fbe66585f260f1f9dbfc5e302887842552e7baed8939e023160a5e250be0'


def isolated_profile_code(source):
    tree = ast.parse(source.read_text(encoding='utf-8'))
    function = next(node for node in tree.body if isinstance(node, ast.FunctionDef)
                    and node.name == 'load_control_trial_profile')
    gate = next(node for node in tree.body if isinstance(node, ast.If)
                and any(isinstance(child, ast.Call) and isinstance(child.func, ast.Name)
                        and child.func.id == 'load_control_trial_profile'
                        for child in ast.walk(node)))
    # Only the pure definition and profile-loading gate are compiled. No other
    # imports, argument parsing, Windows calls, SDK paths or trial code execute.
    isolated = ast.fix_missing_locations(ast.Module(body=[function], type_ignores=[]))
    scope = {'Path': Path, 'json': json, 'hashlib': hashlib}
    exec(compile(isolated, str(source), 'exec'), scope)
    gate_code = compile(ast.fix_missing_locations(ast.Module(body=[gate], type_ignores=[])),
                        str(source), 'exec')
    return tree, function, gate, scope['load_control_trial_profile'], gate_code


class WelcomeProfileTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.code = {source.name: isolated_profile_code(source) for source in SOURCES}

    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name) / 'project'
        self.root.mkdir()
        self.evidence = self.root / 'work/evidence/map.json'
        self.evidence.parent.mkdir(parents=True)
        self.evidence.write_bytes(b'{"evidence":"offline synthetic map proof"}\n')
        self.profile_path = self.root / 'profile.json'
        self.profile = {
            'client_sha256': CLIENT_SHA, 'hello_net_version': 1077088301,
            'maximum_packet_bytes': 1024,
            'control_welcome_maps': {'2201': {'level': 'Iris_Entry', 'game': '', 'redirect': ''}},
            'welcome_map_evidence_relative_to_project_root': 'work/evidence/map.json',
            'welcome_map_evidence_sha256': hashlib.sha256(self.evidence.read_bytes()).hexdigest(),
        }

    def validate(self, profile=None, selected=2201):
        profile = self.profile if profile is None else profile
        self.profile_path.write_text(json.dumps(profile), encoding='utf-8')
        return [entry[3](self.profile_path, self.root, CLIENT_SHA, selected)
                for entry in self.code.values()]

    def rejects(self, profile, message, selected=2201):
        self.profile_path.write_text(json.dumps(profile), encoding='utf-8')
        for name, entry in self.code.items():
            with self.subTest(launcher=name):
                with self.assertRaisesRegex(ValueError, message):
                    entry[3](self.profile_path, self.root, CLIENT_SHA, selected)

    def test_pure_validators_are_identical(self):
        functions = [ast.dump(entry[1], include_attributes=False) for entry in self.code.values()]
        self.assertEqual(functions[0], functions[1])

    def test_complete_profile_preserves_original_data(self):
        self.assertEqual(self.validate(), [self.profile, self.profile])

    def test_selected_map_accepts_cli_integer_and_env_decimal(self):
        self.assertEqual(self.validate(selected='2201'), [self.profile, self.profile])

    def test_no_selected_map_is_rejected(self):
        self.rejects(self.profile, 'positive selected DS map ID', selected=None)

    def test_selected_map_missing_from_profile_is_rejected(self):
        self.rejects(self.profile, 'no evidenced control_welcome_maps entry', selected=2202)

    def test_bad_selected_map_values_are_rejected(self):
        for selected in (True, 0, -1, 1 << 32, 'no-map', '-1', '', '1' * 5000):
            with self.subTest(value_type=type(selected).__name__, length=len(selected) if isinstance(selected, str) else 0):
                self.rejects(self.profile, 'DS map ID', selected=selected)

    def test_missing_or_empty_map_table_is_rejected(self):
        for maps in (None, {}, [], '2201'):
            profile = copy.deepcopy(self.profile)
            profile['control_welcome_maps'] = maps
            self.rejects(profile, 'bounded control_welcome_maps')
        profile = copy.deepcopy(self.profile)
        del profile['control_welcome_maps']
        self.rejects(profile, 'bounded control_welcome_maps')

    def test_too_many_maps_are_rejected(self):
        profile = copy.deepcopy(self.profile)
        profile['control_welcome_maps'] = {str(i + 1): {'level': 'Iris_Entry'} for i in range(65)}
        self.rejects(profile, 'bounded control_welcome_maps')

    def test_noncanonical_or_out_of_range_map_keys_are_rejected(self):
        for key in ('0', '-1', '02201', '４', '4294967296', '1' * 5000):
            profile = copy.deepcopy(self.profile)
            profile['control_welcome_maps'] = {key: {'level': 'Iris_Entry'}}
            self.rejects(profile, 'invalid Welcome map ID')

    def test_invalid_map_specs_are_rejected(self):
        for spec in (None, [], 'Iris_Entry'):
            profile = copy.deepcopy(self.profile)
            profile['control_welcome_maps']['2201'] = spec
            self.rejects(profile, 'invalid Welcome map ID or entry')

    def test_invalid_level_is_rejected(self):
        for level in (None, '', 123, 'a' * 257, 'Iris_Entry?Game=Other', 'a\0b', 'a\rb', 'a\nb'):
            profile = copy.deepcopy(self.profile)
            profile['control_welcome_maps']['2201']['level'] = level
            self.rejects(profile, 'invalid Welcome Level')

    def test_invalid_game_and_redirect_match_connection_limits(self):
        for field in ('game', 'redirect'):
            for value in (None, 123, 'a' * 257, 'a\0b', 'a\rb', 'a\nb'):
                profile = copy.deepcopy(self.profile)
                profile['control_welcome_maps']['2201'][field] = value
                self.rejects(profile, 'invalid Welcome string')

    def test_optional_empty_game_and_redirect_are_allowed(self):
        profile = copy.deepcopy(self.profile)
        profile['control_welcome_maps']['2201'] = {'level': 'Iris_Entry'}
        self.assertEqual(self.validate(profile), [profile, profile])

    def test_network_profile_type_and_bounds_remain_strict(self):
        for field, value in (('client_sha256', 'f' * 64), ('hello_net_version', True),
                             ('hello_net_version', 1 << 32), ('maximum_packet_bytes', True),
                             ('maximum_packet_bytes', 0), ('maximum_packet_bytes', 1493)):
            profile = copy.deepcopy(self.profile)
            profile[field] = value
            self.rejects(profile, 'does not match this client')

    def test_missing_evidence_fields_are_rejected(self):
        for field in ('welcome_map_evidence_relative_to_project_root', 'welcome_map_evidence_sha256'):
            profile = copy.deepcopy(self.profile)
            del profile[field]
            self.rejects(profile, 'Welcome map evidence')

    def test_evidence_hash_mismatch_is_rejected(self):
        profile = copy.deepcopy(self.profile)
        profile['welcome_map_evidence_sha256'] = '0' * 64
        self.rejects(profile, 'SHA256 does not match')

    def test_invalid_evidence_hash_is_rejected(self):
        for value in (None, 123, 'a' * 63, 'g' * 64, 'A' * 64):
            profile = copy.deepcopy(self.profile)
            profile['welcome_map_evidence_sha256'] = value
            self.rejects(profile, 'lowercase SHA256')

    def test_missing_evidence_file_and_directory_are_rejected(self):
        for relative in ('work/evidence/missing.json', 'work/evidence'):
            profile = copy.deepcopy(self.profile)
            profile['welcome_map_evidence_relative_to_project_root'] = relative
            self.rejects(profile, 'not a file')

    def test_absolute_and_windows_drive_paths_are_rejected(self):
        for relative in (str(self.evidence.resolve()), 'C:/outside.json', 'C:outside.json',
                         '\\\\server\\share\\proof.json', '/outside.json'):
            profile = copy.deepcopy(self.profile)
            profile['welcome_map_evidence_relative_to_project_root'] = relative
            self.rejects(profile, 'relative path inside the project ROOT')

    def test_parent_traversal_is_rejected_even_with_matching_hash(self):
        outside = self.root.parent / 'outside.json'
        outside.write_bytes(self.evidence.read_bytes())
        profile = copy.deepcopy(self.profile)
        profile['welcome_map_evidence_relative_to_project_root'] = '../outside.json'
        self.rejects(profile, 'escapes ROOT')

    def test_windows_relative_separators_are_project_relative(self):
        profile = copy.deepcopy(self.profile)
        profile['welcome_map_evidence_relative_to_project_root'] = 'work\\evidence\\map.json'
        self.assertEqual(self.validate(profile), [profile, profile])

    def test_bad_json_is_rejected_without_mutation(self):
        self.profile_path.write_bytes(b'{bad-json')
        for entry in self.code.values():
            with self.assertRaisesRegex(ValueError, 'read as JSON'):
                entry[3](self.profile_path, self.root, CLIENT_SHA, 2201)
        self.assertFalse((self.root / 'work/native-client-tests').exists())

    def test_real_profile_loading_gates_fail_before_any_test_directory_or_uac(self):
        profile = copy.deepcopy(self.profile)
        del profile['control_welcome_maps']
        self.profile_path.write_text(json.dumps(profile), encoding='utf-8')
        for name, entry in self.code.items():
            with self.subTest(launcher=name):
                tree, _, gate, validator, gate_code = entry
                errors = io.StringIO()
                scope = {'args': SimpleNamespace(ds_control_probe=True, ds_map_id=2201),
                         'load_control_trial_profile': validator,
                         'CONTROL_PROFILE': self.profile_path, 'ROOT': self.root,
                         'ENTRY_SHA': CLIENT_SHA, 'parser': argparse.ArgumentParser(),
                         'os': SimpleNamespace(environ={'DF_LOCAL_DS_MAP_ID': '2201'})}
                # Runner's fixed profile filename is reproduced in this temp ROOT.
                destination = self.root / 'outputs/df-local-server/protocol/native_ds_wire_profile.json'
                destination.parent.mkdir(parents=True, exist_ok=True)
                destination.write_bytes(self.profile_path.read_bytes())
                with contextlib.redirect_stderr(errors), self.assertRaises(SystemExit) as raised:
                    exec(gate_code, scope)
                self.assertEqual(raised.exception.code, 2)
                self.assertIn('bounded control_welcome_maps', errors.getvalue())
                self.assertNotIn('TEST_ROOT', scope)
                self.assertNotIn('request_path', scope)
                self.assertNotIn('shell', scope)
                self.assertFalse((self.root / 'work/native-client-tests').exists())
                self.assertFalse((self.root / 'work/elevated-native-trials').exists())
                if name == 'run_native_elevated_trial.py':
                    boundary = next(node for node in tree.body if isinstance(node, ast.If)
                                    and ast.unparse(node.test) == 'args.worker')
                else:
                    boundary = next(node for node in tree.body if isinstance(node, ast.Assign)
                                    and any(isinstance(target, ast.Name) and target.id == 'TEST_ROOT'
                                            for target in node.targets))
                self.assertLess(gate.lineno, boundary.lineno)

    def test_real_project_profile_passes_offline(self):
        root = WORK.parent
        path = root / 'outputs/df-local-server/protocol/native_ds_wire_profile.json'
        for entry in self.code.values():
            profile = entry[3](path, root, CLIENT_SHA, 2201)
            self.assertEqual(profile['control_welcome_maps']['2201']['level'], 'Iris_Entry')

    def test_wrapper_seals_environment_map_before_request_hops(self):
        self.profile_path.write_text(json.dumps(self.profile), encoding='utf-8')
        entry = self.code['run_native_elevated_trial.py']
        scope = {'args': SimpleNamespace(ds_control_probe=True, ds_map_id=None),
                 'load_control_trial_profile': entry[3], 'CONTROL_PROFILE': self.profile_path,
                 'ROOT': self.root, 'parser': argparse.ArgumentParser(),
                 'os': SimpleNamespace(environ={'DF_LOCAL_DS_MAP_ID': '2201'})}
        exec(entry[4], scope)
        self.assertEqual(scope['args'].ds_map_id, 2201)
        self.assertNotIn('request_path', scope)
        self.assertNotIn('shell', scope)


if __name__ == '__main__':
    unittest.main()
