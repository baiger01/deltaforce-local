import importlib.util
import json
import os
from pathlib import Path
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch


PROJECT = Path(__file__).resolve().parents[3]
WORK = PROJECT / 'work'
with patch.object(sys, 'path', [str(WORK), *sys.path]):
    spec = importlib.util.spec_from_file_location('live_keybox_probe', WORK / 'probe_live_keybox_registration.py')
    probe = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(probe)
CATALOG = json.loads((PROJECT / 'outputs/df-local-server/protocol/native_keycard_catalog.json').read_text(encoding='utf-8'))


class LiveKeyboxProbeTests(unittest.TestCase):
    def test_transfer_catalog_supplies_actual_reflection_without_ignored_evidence(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            target = root / 'outputs/df-local-server/protocol/native_keycard_catalog.json'
            target.parent.mkdir(parents=True)
            target.write_text(json.dumps(CATALOG), encoding='utf-8')
            with patch.object(probe, 'ROOT', root):
                proof, origin = probe.reflection_source()
            self.assertEqual(origin, 'outputs/df-local-server/protocol/native_keycard_catalog.json')
            self.assertEqual(proof['_source']['pe_sha256'], probe.EXPECTED_PE)
            self.assertEqual(proof['KeyBoxRow'][0]['properties'][1]['name'], 'ItemID')
            self.assertEqual(proof['KeyBoxRow'][0]['properties'][1]['member_offset'], 20)

    def test_missing_reflection_is_regenerated_from_source_without_substitute_fields(self):
        proof = {'_source': {'pe_sha256': CATALOG['native_pe_sha256']},
                 **{source['struct']: [source['native_registration']] for source in CATALOG['sources'].values()}}
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            calls = []

            def extract():
                calls.append(True)
                target = root / 'work/evidence/native-keycard-reflection-probe.json'
                target.parent.mkdir(parents=True)
                target.write_text(json.dumps(proof), encoding='utf-8')

            with patch.object(probe, 'ROOT', root), patch.dict(sys.modules, {
                    'probe_native_keycard_bindings': SimpleNamespace(main=extract)}):
                actual, origin = probe.reflection_source()
            self.assertEqual(calls, [True])
            self.assertEqual(actual, proof)
            self.assertEqual(origin, 'work/evidence/native-keycard-reflection-probe.json')

    def test_shadow_path_uses_the_environment_override(self):
        with tempfile.TemporaryDirectory() as directory:
            source, shadow = Path(directory) / 'installed', Path(directory) / 'independent'
            with patch.dict(os.environ, {'DF_LOCAL_SOURCE_GAME': str(source), 'DF_LOCAL_SHADOW_GAME': str(shadow)}):
                self.assertEqual(probe.game_paths()[1], shadow.resolve())

    def test_changed_source_hash_is_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            target = root / 'outputs/df-local-server/protocol/native_keycard_catalog.json'
            target.parent.mkdir(parents=True)
            target.write_text(json.dumps({**CATALOG, 'native_pe_sha256': 'unverified'}), encoding='utf-8')
            with patch.object(probe, 'ROOT', root), self.assertRaises(ValueError):
                probe.reflection_source()


if __name__ == '__main__':
    unittest.main()
