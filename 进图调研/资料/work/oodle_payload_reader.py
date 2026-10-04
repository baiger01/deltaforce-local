"""Bounded asset decompression using the already-installed codec, not game SDKs.

No codec DLL is copied into deliverables. The original game is not launched.
ABI reference: CUE4Parse/Oodle.NET's OodleLZ_Decompress binding.
"""
from pathlib import Path
import ctypes
import hashlib
import json
import pefile
from local_game_paths import game_paths

PATH = game_paths()[0] / 'DeltaForce/Binaries/Win64/oo2core_8_win64.dll'
_function = None

def decode(data, size):
    global _function
    if not isinstance(data, bytes) or not 0 < size <= 4 * 1024 * 1024:
        raise ValueError('Invalid bounded codec input')
    if _function is None:
        # Inspect dependencies before loading only this pure compression codec.
        pe = pefile.PE(str(PATH), fast_load=True)
        pe.parse_data_directories(directories=[0, 1])
        imports = {entry.dll.decode('ascii').lower() for entry in pe.DIRECTORY_ENTRY_IMPORT}
        if pe.FILE_HEADER.Machine != 0x8664 or any(
                name not in {'kernel32.dll', 'ntdll.dll', 'msvcrt.dll', 'ucrtbase.dll', 'advapi32.dll',
                             'vcruntime140.dll', 'vcruntime140_1.dll', 'user32.dll'}
                and not name.startswith('api-ms-win-') for name in imports):
            raise ValueError('Unexpected codec architecture or dependencies')
        lib = ctypes.WinDLL(str(PATH), winmode=0x1000)
        fn = lib.OodleLZ_Decompress
        fn.restype = ctypes.c_ssize_t
        fn.argtypes = [ctypes.c_void_p, ctypes.c_ssize_t, ctypes.c_void_p, ctypes.c_ssize_t,
                       ctypes.c_int, ctypes.c_int, ctypes.c_int, ctypes.c_void_p, ctypes.c_ssize_t,
                       ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p, ctypes.c_ssize_t, ctypes.c_int]
        _function = fn
    source, output = ctypes.create_string_buffer(data), ctypes.create_string_buffer(size)
    written = _function(source, len(data), output, size, 1, 1, 0, None, 0, None, None, None, 0, 3)
    if written != size:
        raise ValueError('Codec output length mismatch')
    return output.raw

if __name__ == '__main__':
    archive = game_paths()[0] / 'DeltaForce/Content/Paks/1.101.37117.36.14_WindowsNoEditor_37131_P.pak'
    with archive.open('rb') as handle:
        header = handle.read(73)
        compressed = handle.read(2663 - 73)
    output = decode(compressed, 4805)
    print(json.dumps({'decoded_bytes': len(output), 'payload_sha1_matches': hashlib.sha1(output).digest() == header[45:65],
                      'compressed_sha1_matches': hashlib.sha1(compressed).digest() == header[45:65],
                      'lua53_signature': output.startswith(b'\x1bLua\x53'),
                      'codec_sha256': hashlib.sha256(PATH.read_bytes()).hexdigest(),
                      'game_launched': False, 'game_files_modified': False}))
