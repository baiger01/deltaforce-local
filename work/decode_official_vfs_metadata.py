"""Decode public launcher resource metadata independently; no original DLL execution."""
from pathlib import Path
import hashlib
import json
import struct
import zlib
from Crypto.Cipher import AES

ROOT = Path(__file__).resolve().parent.parent
source = ROOT / 'work/official-standalone-launcher/tpf_ui.vfs'
raw = source.read_bytes()
assert hashlib.sha256(raw).hexdigest() == 'e57d940078ce9ee1a841eb22fb9e7df1cb575e1ef777ea6abbcdf99338e184d9'
library = (ROOT / 'work/official-standalone-launcher/Tenio/VFS.dll').read_bytes()
assert hashlib.sha256(library).hexdigest() == '898ae160fcd123536aa7677b959fb0ac2aeeb697f562ae854ae56510330e7de9'
key_start = library.index(b'(VFS_DEFAULT_AES_KEY)')
key = library[key_start:key_start+21].ljust(32, b'\0')
assert raw[:4] == b'vfs ' and struct.unpack_from('<I', raw, 4)[0] == 2
file_offset = struct.unpack_from('<Q', raw, 0x20)[0]
file_bytes = struct.unpack_from('<I', raw, 0x28)[0]
name_offset = struct.unpack_from('<Q', raw, 0x2c)[0]
name_bytes = struct.unpack_from('<I', raw, 0x34)[0]
assert file_offset + file_bytes == name_offset
assert name_offset + name_bytes == len(raw)
def decrypt(cipher):
    assert 1 < len(cipher) <= 513 and len(cipher) % 16 == 1 and cipher[-1] < 16
    plain = AES.new(key, AES.MODE_ECB).decrypt(cipher[:-1])
    count = cipher[-1]
    if count:
        assert plain[-count:] == bytes(count)
        plain = plain[:-count]
    return plain

names = []
position = name_offset
while position < name_offset + name_bytes:
    size = struct.unpack_from('<H', raw, position)[0]
    position += 2
    assert position + size <= name_offset + name_bytes
    value = decrypt(raw[position:position+size]).decode('utf-8')
    names.append(value)
    position += size
assert position == len(raw)
files = []
position = file_offset
private = ROOT / 'work/evidence/official_vfs_metadata'
private.mkdir(exist_ok=True)
while position < name_offset:
    size, checksum = struct.unpack_from('<HI', raw, position)
    position += 6
    assert position + size <= name_offset
    plain = decrypt(raw[position:position+size])
    assert zlib.crc32(plain) == checksum
    assert len(plain) >= 29
    fields = struct.unpack_from('<IIIIQBI', plain)
    tail = plain[29:]
    name_index, logical_size, stored_size, attributes, data_offset, flag, other = fields
    assert name_index < len(names) and len(tail) == 16 and not any(tail)
    (private / f'file_{len(files):03d}.bin').write_bytes(plain)
    entry = {'record': len(files), 'name_index': name_index, 'name': names[name_index],
             'logical_size': logical_size, 'stored_size': stored_size,
             'attributes': attributes, 'data_offset': data_offset, 'flag': flag,
             'other': other, 'metadata_crc32_valid': True}
    if attributes & 0x10:
        assert logical_size == stored_size == 0
    else:
        assert data_offset + 16 + stored_size <= file_offset
        payload = raw[data_offset:data_offset + 16 + stored_size]
        assert payload[:4] == b'data'
        if attributes & 0x800:
            compressed_size = struct.unpack_from('<I', payload, 16)[0]
            assert compressed_size + 4 == stored_size
            decoder = zlib.decompressobj()
            content = decoder.decompress(payload[20:], logical_size + 1)
            assert len(content) == logical_size and decoder.eof
            assert not decoder.unused_data and not decoder.unconsumed_tail
        else:
            content = payload[16:]
            assert len(content) == logical_size
        (private / f'resource_{name_index:03d}.bin').write_bytes(content)
        entry.update({'payload_length_valid': True, 'payload_sha256': hashlib.sha256(content).hexdigest()})
    files.append(entry)
    position += size
assert position == name_offset
report = {'source_sha256': hashlib.sha256(raw).hexdigest(), 'file_offset': file_offset,
          'name_offset': name_offset, 'name_count': len(names), 'file_count': len(files),
          'names': names, 'files': files, 'all_metadata_crc32_valid': True,
          'all_cipher_lengths_and_zero_padding_valid': True, 'source_executed_or_modified': False}
(ROOT / 'work/evidence/official_vfs_metadata_validation.json').write_text(json.dumps(report, indent=2) + '\n', encoding='utf-8')
print(json.dumps({'name_count': len(names), 'metadata_count': len(files),
                  'extracted_file_count': sum(not (f['attributes'] & 0x10) for f in files),
                  'all_metadata_crc32_valid': True, 'all_payload_lengths_valid': True}, indent=2))
