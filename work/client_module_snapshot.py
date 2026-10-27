"""Read loaded module names without walking a client's entire address space."""

import ctypes as C
from ctypes import wintypes as W


class ModuleEntry(C.Structure):
    _fields_ = [
        ('dwSize', W.DWORD), ('th32ModuleID', W.DWORD),
        ('th32ProcessID', W.DWORD), ('GlblcntUsage', W.DWORD),
        ('ProccntUsage', W.DWORD), ('modBaseAddr', C.POINTER(C.c_byte)),
        ('modBaseSize', W.DWORD), ('hModule', W.HMODULE),
        ('szModule', W.WCHAR * 256), ('szExePath', W.WCHAR * 260),
    ]


def windows_api():
    api = C.WinDLL('kernel32', use_last_error=True)
    api.CreateToolhelp32Snapshot.argtypes = [W.DWORD, W.DWORD]
    api.CreateToolhelp32Snapshot.restype = W.HANDLE
    for name in ('Module32FirstW', 'Module32NextW'):
        method = getattr(api, name)
        method.argtypes = [W.HANDLE, C.POINTER(ModuleEntry)]
        method.restype = W.BOOL
    api.CloseHandle.argtypes = [W.HANDLE]
    api.CloseHandle.restype = W.BOOL
    return api


def loaded_module_names(pid):
    api = windows_api()
    snapshot = api.CreateToolhelp32Snapshot(0x18, pid)
    if not snapshot or snapshot == C.c_void_p(-1).value:
        raise C.WinError(C.get_last_error())
    try:
        entry = ModuleEntry()
        entry.dwSize = C.sizeof(entry)
        found = api.Module32FirstW(snapshot, C.byref(entry))
        names = set()
        count = 0
        while found:
            count += 1
            if count > 4096:
                raise OSError('Module snapshot exceeded its bound')
            names.add(entry.szModule.lower())
            found = api.Module32NextW(snapshot, C.byref(entry))
        if C.get_last_error() != 18:  # ERROR_NO_MORE_FILES
            raise C.WinError(C.get_last_error())
        return sorted(names)
    finally:
        api.CloseHandle(snapshot)
