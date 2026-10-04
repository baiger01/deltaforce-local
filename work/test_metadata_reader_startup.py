"""Real subprocess startup failures and Windows helper lifecycle reporting."""
import io
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from contextlib import redirect_stdout
from types import SimpleNamespace
from unittest.mock import Mock, patch

import export_native_replication_metadata as export
import test_export_native_replication_metadata as fixtures


class StartupTests(unittest.TestCase):
    def test_parent_child_failure_is_not_reported_as_success_and_handle_is_closed(self):
        parent = fixtures.ElevationTests()
        with parent.mocked_parent() as env, patch.object(export, 'monitor_reader_exit', return_value={
                'status': 'metadata_reader_exited', 'exit_code': 1,
                'reader_result_status': None}):
            with self.assertRaisesRegex(RuntimeError, 'did not complete'):
                export.request_read_only_elevation(env.args)
            env.api.CloseHandle.assert_called_once_with(0x99)

    def test_import_failure_is_logged_before_reader_imports(self):
        with tempfile.TemporaryDirectory(prefix='reader-startup-test-', dir=export.ROOT / 'work') as temp:
            folder = Path(temp)
            result = subprocess.run([sys.executable, '-S', str(Path(export.__file__).resolve()),
                '--output', temp, '--elevated-source-pins', '{}'],
                capture_output=True, timeout=20)
            self.assertNotEqual(result.returncode, 0)
            startup = json.loads((folder / 'worker-startup.json').read_text(encoding='utf-8'))
            self.assertFalse(startup['process_memory_read'])
            self.assertIn('ModuleNotFoundError', (folder / 'worker-console.log').read_text(encoding='utf-8'))
            self.assertFalse((folder / 'result.json').exists())

    def test_argument_failure_has_console_and_preflight_result_without_process_read(self):
        with tempfile.TemporaryDirectory(prefix='reader-startup-test-', dir=export.ROOT / 'work') as temp:
            folder = Path(temp)
            result = subprocess.run([sys.executable, str(Path(export.__file__).resolve()),
                '--game-root', 'unused', '--output', temp, '--pid', '123', '--created-at', '1',
                '--elevated-source-pins', '{bad-json'], capture_output=True, timeout=20)
            self.assertEqual(result.returncode, 2)
            report = json.loads((folder / 'result.json').read_text(encoding='utf-8'))
            self.assertEqual(report['status'], 'metadata_reader_preflight_refused')
            self.assertFalse(report['process_memory_read'])
            self.assertIn('not valid JSON', (folder / 'worker-console.log').read_text(encoding='utf-8'))

    def test_parent_retains_process_handle_until_real_exit_and_records_ntstatus(self):
        def get_exit(handle, target):
            target._obj.value = 0xc0000142
            return True
        api = SimpleNamespace(WaitForSingleObject=Mock(side_effect=[0x102, 0]),
            GetExitCodeProcess=Mock(side_effect=get_exit))
        with tempfile.TemporaryDirectory() as temp, redirect_stdout(io.StringIO()):
            report = export.monitor_reader_exit(api, 99, temp, 777)
            saved = json.loads((Path(temp) / 'helper-exit.json').read_text(encoding='utf-8'))
        self.assertEqual(report, saved)
        self.assertEqual(report['exit_code_hex'], '0xc0000142')
        self.assertEqual(api.WaitForSingleObject.call_count, 2)
        self.assertFalse(report['result_file_exists'])

    def test_parent_wait_deadline_does_not_claim_exit(self):
        api = SimpleNamespace(WaitForSingleObject=Mock(return_value=0x102),
            GetExitCodeProcess=Mock())
        with tempfile.TemporaryDirectory() as temp, redirect_stdout(io.StringIO()), \
             patch.object(export.time, 'monotonic', side_effect=[0, 181, 181]):
            report = export.monitor_reader_exit(api, 99, temp, 777)
        self.assertEqual(report['status'], 'metadata_reader_still_running_after_deadline')
        self.assertIsNone(report['exit_code'])
        api.GetExitCodeProcess.assert_not_called()


if __name__ == '__main__':
    unittest.main()
