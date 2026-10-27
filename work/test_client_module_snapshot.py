import ctypes
import os
from pathlib import Path
import unittest
from unittest.mock import patch

from client_module_snapshot import ModuleEntry, loaded_module_names


class FakeAPI:
    def __init__(self, names, error=18):
        self.names = iter(names)
        self.error = error
        self.closed = []

    def CreateToolhelp32Snapshot(self, flags, pid):
        assert (flags, pid) == (0x18, 77)
        return 123

    def Module32FirstW(self, handle, entry):
        return self.Module32NextW(handle, entry)

    def Module32NextW(self, handle, entry):
        assert handle == 123
        try:
            name = next(self.names)
        except StopIteration:
            ctypes.set_last_error(self.error)
            return False
        record = ctypes.cast(entry, ctypes.POINTER(ModuleEntry)).contents
        assert record.dwSize == ctypes.sizeof(ModuleEntry)
        record.szModule = name
        return True

    def CloseHandle(self, handle):
        self.closed.append(handle)


class ModuleSnapshotTests(unittest.TestCase):
    def test_names_are_unique_and_snapshot_is_closed(self):
        api = FakeAPI(['CLIENT.exe', 'Kernel32.dll', 'kernel32.dll'])
        with patch('client_module_snapshot.windows_api', return_value=api):
            self.assertEqual(loaded_module_names(77), ['client.exe', 'kernel32.dll'])
        self.assertEqual(api.closed, [123])

    def test_enumeration_failure_is_not_reported_as_complete(self):
        api = FakeAPI(['CLIENT.exe'], error=5)
        with patch('client_module_snapshot.windows_api', return_value=api):
            with self.assertRaises(OSError):
                loaded_module_names(77)
        self.assertEqual(api.closed, [123])

    @unittest.skipUnless(os.name == 'nt', 'Windows module enumeration')
    def test_live_python_modules(self):
        names = loaded_module_names(os.getpid())
        self.assertIn('kernel32.dll', names)
        self.assertTrue(any(name.startswith('python') for name in names))

    def test_trial_does_not_use_memory_map_enumeration(self):
        source = Path(__file__).with_name('verify_local_provider_client.py').read_text(encoding='utf-8')
        self.assertNotIn('.memory_maps(', source)
        self.assertIn('loaded_module_names(process.pid)', source)


if __name__ == '__main__':
    unittest.main()
