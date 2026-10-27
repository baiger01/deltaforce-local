"""Derive installed PAK access in memory from the qualified offline native cache.

The report contains provenance and validation only. Registration constants and
derived keys are never serialized, printed, or accepted as command-line inputs.
"""
import argparse
import hashlib
import json
import mmap
from pathlib import Path
import re
import struct

from capstone import Cs, CS_ARCH_X86, CS_MODE_64
from capstone.x86_const import X86_OP_IMM, X86_OP_MEM, X86_OP_REG, X86_REG_RIP
from Crypto.Cipher import AES

from offline_received_packet_xrefs import ImmutableImage
from portable_native_code_cache import CodeCache

ROOT = Path(__file__).resolve().parent.parent
BOOT_FIRST, BOOT_END = 0x2f29650, 0x2f3ba83


def read_code(cache, first, end):
    return b''.join(cache.read(at, min(8192, end-at)) for at in range(first, end, 8192))


def native_keys(cache, image):
    """Evaluate constant stack construction; never execute client instructions."""
    raw = read_code(cache, BOOT_FIRST, BOOT_END)
    md = Cs(CS_ARCH_X86, CS_MODE_64)
    md.detail = True
    regs, memory, strings, pending, keys = {'rsp': 0x100000000}, {}, [], None, {}
    calls, ranges, literals = [], [], []

    def register(name):
        if name.startswith('e') and len(name) == 3:
            return 'r'+name[1:]
        if name.endswith('d') and name.startswith('r'):
            return name[:-1]
        return name

    def address(ins, operand):
        mem = operand.mem
        if mem.base == X86_REG_RIP:
            return ins.address+ins.size+mem.disp
        base = regs.get(register(ins.reg_name(mem.base)), 0) if mem.base else 0
        index = regs.get(register(ins.reg_name(mem.index)), 0) if mem.index else 0
        return base+index*mem.scale+mem.disp

    def value(ins, operand):
        if operand.type == X86_OP_IMM:
            return operand.imm
        if operand.type == X86_OP_REG:
            return regs.get(register(ins.reg_name(operand.reg)), 0)
        if operand.type == X86_OP_MEM:
            at = address(ins, operand)
            return int.from_bytes(bytes(memory.get(at+i, 0) for i in range(operand.size)), 'little')
        raise ValueError('Unsupported constant source')

    def assign(ins, operand, item):
        item &= (1 << (operand.size*8))-1
        if operand.type == X86_OP_REG:
            regs[register(ins.reg_name(operand.reg))] = item
        elif operand.type == X86_OP_MEM:
            at = address(ins, operand)
            if 0xffff0000 <= at <= 0x100010000:
                for i, byte in enumerate(item.to_bytes(operand.size, 'little')):
                    memory[at+i] = byte

    for ins in md.disasm(raw, BOOT_FIRST):
        ops = ins.operands
        if ins.mnemonic in ('mov', 'movaps', 'movdqa', 'movups', 'movdqu') and len(ops) == 2:
            assign(ins, ops[0], value(ins, ops[1]))
        elif ins.mnemonic == 'lea':
            assign(ins, ops[0], address(ins, ops[1]))
        elif ins.mnemonic in ('xor', 'sub', 'add') and len(ops) == 2 and ops[0].type == X86_OP_REG:
            left, right = value(ins, ops[0]), value(ins, ops[1])
            assign(ins, ops[0], left ^ right if ins.mnemonic == 'xor' else left-right if ins.mnemonic == 'sub' else left+right)
        elif ins.mnemonic == 'push':
            regs['rsp'] -= 8
        elif ins.mnemonic == 'call' and len(ops) == 1 and ops[0].type == X86_OP_IMM:
            target = ops[0].imm
            if target == 0xd60360:
                at, count = regs.get('r8', 0), regs.get('r9', 0)
                if 0 < at < 0x20000000 and 1 <= count <= 256:
                    for encoding, width in (('ascii', 1), ('utf-16-le', 2)):
                        try:
                            text = image.read(at, count*width).decode(encoding).rstrip('\0')
                        except (ValueError, UnicodeDecodeError):
                            continue
                        if text.isprintable():
                            strings.append(text)
                            literals.append(at)
            elif target == 0x151b710:
                at = regs.get('rdx', 0)
                if not all(at+i in memory for i in range(16)):
                    raise ValueError('Key range pointers were not reconstructed')
                begin, end = struct.unpack('<QQ', bytes(memory[at+i] for i in range(16)))
                if end-begin != 32 or not all(begin+i in memory for i in range(32)):
                    raise ValueError('Key range is not an initialized 32-byte stack constant')
                pending = bytes(memory[begin+i] for i in range(32))
                ranges.append(ins.address)
                regs['rax'] = regs.get('rcx', 0)
            elif target == 0x12454630:
                candidates = [item for item in strings if re.fullmatch('[0-9a-fA-F]{32}', item)]
                if pending is None or not candidates:
                    raise ValueError('Registration lacks a reconstructed GUID/key pair')
                guid_text = candidates[-1]
                guid = struct.pack('<4I', *(int(guid_text[i:i+8], 16) for i in range(0, 32, 8)))
                if guid in keys and keys[guid] != pending:
                    raise ValueError('Conflicting registered key')
                keys[guid] = pending
                calls.append(ins.address)
                pending, strings = None, []
    if len(calls) != 200 or len(ranges) != 200:
        raise ValueError('The complete expected static registration set was not reconstructed')
    default_raw = read_code(cache, 0x2f3ba90, 0x2f3bae6)
    default_parts = {}
    for ins in md.disasm(default_raw, 0x2f3ba90):
        if ins.mnemonic == 'mov' and len(ins.operands) == 2:
            destination, source = ins.operands
            if (destination.type == X86_OP_MEM and ins.reg_name(destination.mem.base) == 'rbp'
                    and destination.size == 4 and source.type == X86_OP_IMM
                    and destination.mem.disp in range(-0x30, -0x10, 4)):
                default_parts[destination.mem.disp] = struct.pack('<I', source.imm & 0xffffffff)
    if len(default_parts) != 8:
        raise ValueError('Default-key callback no longer constructs the exact 32-byte output')
    keys[bytes(16)] = b''.join(default_parts[at] for at in range(-0x30, -0x10, 4))
    return keys, dict(bootstrap_rva=hex(BOOT_FIRST), bootstrap_bytes=len(raw),
                     bootstrap_code_sha256=hashlib.sha256(raw).hexdigest(),
                     registration_calls=len(calls), key_array_constructions=len(ranges),
                     distinct_bootstrap_guids=len(keys)-1,
                     default_callback_rva='0x2f3ba90', default_callback_bytes=len(default_raw),
                     default_callback_code_sha256=hashlib.sha256(default_raw).hexdigest(),
                     default_callback_binding_rva='0x307760', default_callback_setter_rva='0x10b0f460',
                     registration_function_rva='0x12454630', array_copy_function_rva='0x151b710',
                     first_registration_call_rva=hex(calls[0]), last_registration_call_rva=hex(calls[-1]),
                     immutable_guid_literal_rva_count=len(set(literals)))


def pak_footer(path):
    with path.open('rb') as stream:
        stream.seek(-min(512, path.stat().st_size), 2)
        tail = stream.read()
    at = tail.rfind(struct.pack('<I', 0x5a6f12e1))
    if at < 17:
        raise ValueError('Qualified encrypted PAK footer absent')
    version, offset, size = struct.unpack_from('<IQQ', tail, at+4)
    return dict(version=version, offset=offset, size=size, sha1=tail[at+24:at+44],
                guid=tail[at-17:at-1], encrypted_index=bool(tail[at-1]),
                methods=[m[:-1].decode() for m in re.findall(rb'(?:Oodle|Zlib|Gzip|LZ4|Zstd)\x00', tail)],
                footer_sha256=hashlib.sha256(tail).hexdigest())


def derive_key(raw_key, guid):
    text = ''.join(f'{word:08X}' for word in struct.unpack('<4I', guid))
    digest = hashlib.sha1(text.encode('ascii')).digest()
    return bytes(byte ^ digest[i % 20] for i, byte in enumerate(raw_key))


def decrypt_block(data, key):
    if len(data) % 16:
        raise ValueError('Encrypted block alignment changed')
    decoded = AES.new(key, AES.MODE_ECB).decrypt(data)
    mask = hashlib.sha1(key).digest()[10]
    return decoded.translate(bytes(byte ^ mask for byte in range(256)))


def validate_index(path, footer, keys):
    public = {name: value for name, value in footer.items() if name not in ('guid', 'sha1')}
    public.update(pak=str(path), registered_guid_found=footer['guid'] in keys,
                  encryption_guid_is_zero=footer['guid'] == bytes(16))
    if footer['guid'] not in keys:
        return public, None, None
    if footer['size'] > 64*1024*1024:
        raise ValueError('Index exceeds the explicit 64 MiB bound')
    with path.open('rb') as stream:
        stream.seek(footer['offset'])
        cipher = stream.read((footer['size']+15)//16*16)
    key = derive_key(keys[footer['guid']], footer['guid'])
    clear = decrypt_block(cipher, key)[:footer['size']]
    public.update(index_sha1_valid=hashlib.sha1(clear).digest() == footer['sha1'],
                  encrypted_index_sha256=hashlib.sha256(cipher).hexdigest(),
                  decoded_index_sha256=hashlib.sha256(clear).hexdigest())
    if public['index_sha1_valid']:
        length = struct.unpack_from('<i', clear)[0]
        public['first_signed_int32'] = length
        if 0 < abs(length) < 4096:
            width = 1 if length > 0 else 2
            size = abs(length)*width
            public['mount_point'] = clear[4:4+size].decode('utf-8' if width == 1 else 'utf-16-le').rstrip('\0')
            public['entry_count'] = struct.unpack_from('<i', clear, 4+size)[0]
    return public, clear if public['index_sha1_valid'] else None, key


def fstring(data, at):
    length = struct.unpack_from('<i', data, at)[0]
    if not -1048576 <= length <= 1048576:
        raise ValueError('FString exceeds its bound')
    at += 4
    size = abs(length)*(1 if length >= 0 else 2)
    if at+size > len(data):
        raise ValueError('Truncated FString')
    return data[at:at+size].decode('utf-8' if length >= 0 else 'utf-16-le').rstrip('\0'), at+size


def installed_name_map(data):
    if data[:4] != b'\xc1\x83\x2a\x9e':
        raise ValueError('Unreal package magic absent')
    versions = struct.unpack_from('<i', data, 20)[0]
    if not 0 <= versions <= 1024:
        raise ValueError('Unreal custom version count exceeds bound')
    count, at = struct.unpack_from('<ii', data, 41+versions*20)
    if not 1 <= count <= 100000 or not 0 < at < len(data):
        raise ValueError('Unreal name map summary is outside bound')
    names = []
    for _ in range(count):
        name, at = fstring(data, at)
        names.append(name)
        at += 4
    return names


def installed_table_package_identity(data):
    from extract_operator_avatar_catalog import fname
    names = installed_name_map(data)
    versions = struct.unpack_from('<i', data, 20)[0]
    export_count, export_at, import_count, import_at = struct.unpack_from('<4i', data, 57+versions*20)
    if not 1 <= export_count <= 1024 or not 0 < export_at < len(data) or not 0 < import_at < len(data):
        raise ValueError('Unreal export/import summary is outside the identity bound')
    if export_count != 1:
        raise ValueError('A single root DataTable export is required for this identity reader')
    class_index, _, _, outer_index = struct.unpack_from('<4i', data, export_at)
    object_name = fname(data, export_at+16, names)
    if outer_index != 0 or not -import_count <= class_index < 0:
        raise ValueError('Root DataTable export/import association changed')
    class_name = fname(data, import_at+(-class_index-1)*28+20, names)
    if class_name != 'DataTable':
        raise ValueError('Root exported class is not DataTable')
    candidates = [name for name in names if name.startswith('/Game/') and name.endswith('/'+object_name)]
    if len(candidates) != 1:
        raise ValueError('A unique own-package path is required for the root table export')
    return dict(package_path=candidates[0], root_export_name=object_name,
                root_export_class=class_name, export_count=export_count,
                export_record_offset=export_at, import_record_offset=import_at+(-class_index-1)*28,
                root_export_metadata_sha256=hashlib.sha256(data[export_at:export_at+44]).hexdigest())


def directory_index(path, footer, clear, key):
    seed, count = struct.unpack_from('<Qi', clear)
    mount, at = fstring(clear, 12)
    sections = []
    for label in ('path_hash', 'full_directory'):
        exists = struct.unpack_from('<I', clear, at)[0]
        at += 4
        if exists not in (0, 1):
            raise ValueError('Unexpected secondary index presence flag')
        if exists:
            offset, size = struct.unpack_from('<QQ', clear, at)
            digest = clear[at+16:at+36]
            at += 36
            sections.append((label, offset, size, digest))
    encoded_size = struct.unpack_from('<I', clear, at)[0]
    at += 4
    encoded = clear[at:at+encoded_size]
    if len(encoded) != encoded_size:
        raise ValueError('Encoded entry array exceeds primary index')
    result = dict(mount_point=mount, entry_count=count, encoded_entry_bytes=encoded_size,
                  remaining_primary_bytes=len(clear)-at-encoded_size, secondary_indices=[])
    files = []
    with path.open('rb') as stream:
        for label, offset, size, digest in sections:
            if size > 128*1024*1024:
                raise ValueError('Secondary index exceeds bounded read')
            stream.seek(offset)
            raw = stream.read((size+15)//16*16)
            decoded = decrypt_block(raw, key)[:size] if footer['encrypted_index'] else raw[:size]
            valid = hashlib.sha1(decoded).digest() == digest
            result['secondary_indices'].append(dict(kind=label, offset=offset, bytes=size,
                sha1_valid=valid, decoded_sha256=hashlib.sha256(decoded).hexdigest()))
            if not valid:
                raise ValueError('Secondary index SHA1 mismatch')
            if label == 'full_directory':
                directories = struct.unpack_from('<I', decoded)[0]
                cursor = 4
                if directories > 1000000:
                    raise ValueError('Directory count exceeds explicit bound')
                for _ in range(directories):
                    directory, cursor = fstring(decoded, cursor)
                    members = struct.unpack_from('<I', decoded, cursor)[0]
                    cursor += 4
                    for _ in range(members):
                        name, cursor = fstring(decoded, cursor)
                        location = struct.unpack_from('<i', decoded, cursor)[0]
                        cursor += 4
                        files.append((mount+directory+name, location))
                result.update(directory_count=directories, directory_file_count=len(files),
                              remaining_directory_bytes=len(decoded)-cursor)
    return result, files, encoded


def entry_offset(encoded, at):
    bits = struct.unpack_from('<I', encoded, at)[0]
    at += 4
    if bits & 63 == 63:
        at += 4
    return struct.unpack_from('<I' if bits & 0x80000000 else '<Q', encoded, at)[0]


def decode_entry(stream, pos, entry, methods, key):
    from scan_weapon_tables import decode_oodle
    import lz4.block
    import zlib
    import zstandard
    if entry['uncompressed'] > 128*1024*1024:
        raise ValueError('Selected asset exceeds explicit 128 MiB bound')
    blocks, compressed = [], []
    extents = entry['blocks'] or [(entry['header_size'], entry['header_size']+entry['compressed'])]
    for first, end in extents:
        amount = end-first
        stream.seek(pos+first)
        data = stream.read((amount+15)//16*16 if entry['flags'] & 1 else amount)
        compressed.append(data if entry['method'] else data[:amount])
        if entry['flags'] & 1:
            data = decrypt_block(data, key)[:amount]
        expected = min(entry['block_size'], entry['uncompressed']-sum(map(len, blocks))) if entry['method'] else entry['uncompressed']
        method = methods[entry['method']-1] if entry['method'] else 'None'
        if method == 'None':
            block = data
        elif method == 'Oodle':
            block = decode_oodle(data, expected)
        elif method in ('Zlib', 'Gzip'):
            block = zlib.decompress(data, zlib.MAX_WBITS | 32)
        elif method == 'Zstd':
            block = zstandard.ZstdDecompressor().decompress(data, max_output_size=expected)
        elif method == 'LZ4':
            block = lz4.block.decompress(data, uncompressed_size=expected)
        else:
            raise ValueError('Unknown installed PAK compression method')
        if len(block) != expected:
            raise ValueError('Decoded block size differs from installed header')
        blocks.append(block)
    content = b''.join(blocks)
    if len(content) != entry['uncompressed']:
        raise ValueError('Decoded asset size differs from installed header')
    return content, hashlib.sha1(b''.join(compressed)).digest() == entry['sha1']


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--cache', type=Path, required=True)
    parser.add_argument('--manifest-sha256', required=True)
    parser.add_argument('--game-root', type=Path, required=True)
    parser.add_argument('--pak', type=Path, action='append', default=[])
    parser.add_argument('--pak-root', type=Path, action='append', default=[])
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--find', default='DataTableAssetInfo|SOLStartSpotTemplate|MapEconomy|DropPool|DropPoint|MapDrop|MapBoxData|MapAIData|MapLocationStruct|GameData/DataTable')
    parser.add_argument('--extract', help='Extract only exact selected verified directory paths matching this expression')
    parser.add_argument('--asset-output', type=Path)
    args = parser.parse_args()
    args.pak = sorted(set(args.pak+[path for folder in args.pak_root for path in folder.rglob('*.pak')]))
    if not args.pak:
        parser.error('Select installed PAK files or a bounded PAK root')
    if args.output.exists() or not args.output.resolve().is_relative_to(ROOT/'work/evidence'):
        parser.error('A fresh evidence output is required')
    cache = CodeCache(args.cache, args.manifest_sha256, args.game_root)
    if args.extract and (not args.asset_output or not args.asset_output.resolve().is_relative_to(ROOT/'work/evidence')):
        parser.error('Extraction requires an evidence asset-output directory')
    exe = args.game_root/cache.manifest['plan']['client_relative_to_game_root']
    with exe.open('rb') as stream, mmap.mmap(stream.fileno(), 0, access=mmap.ACCESS_READ) as data:
        keys, provenance = native_keys(cache, ImmutableImage(data))
    reports = []
    for path in args.pak:
        footer = pak_footer(path)
        public, clear, key = validate_index(path, footer, keys)
        if clear is not None:
            details, files, encoded = directory_index(path, footer, clear, key)
            public.update(details)
            public['matched_paths'] = [dict(path=name, encoded_offset=location)
                for name, location in files if re.search(args.find, name, re.IGNORECASE)]
            if args.extract:
                from scan_weapon_tables import parse_entry
                from extract_operator_avatar_catalog import name_map
                public['extracted_assets'] = []
                with path.open('rb') as stream:
                    for name, location in files:
                        if not re.search(args.extract, name, re.IGNORECASE):
                            continue
                        pos = entry_offset(encoded, location)
                        entry = parse_entry(stream, pos, footer['offset'], variant='observed_permutation')
                        content, compressed_hash_valid = decode_entry(stream, pos, entry, footer['methods'], key)
                        relative = Path(*[part for part in name.split('/') if part not in ('..', '.', '')])
                        target = args.asset_output/path.stem/relative
                        target.parent.mkdir(parents=True, exist_ok=True)
                        if target.exists():
                            if target.read_bytes() != content:
                                raise ValueError('Existing recovered asset differs from verified source')
                        else:
                            with target.open('xb') as destination:
                                destination.write(content)
                        record = dict(path=name, encoded_offset=location, physical_offset=pos,
                            bytes=len(content), encrypted=bool(entry['flags'] & 1),
                            compression=footer['methods'][entry['method']-1] if entry['method'] else 'None',
                            compressed_sha1_valid=compressed_hash_valid, decoded_sha256=hashlib.sha256(content).hexdigest(),
                            output=str(target), unreal_package_header=content.startswith(b'\xc1\x83\x2a\x9e'))
                        if record['unreal_package_header']:
                            try:
                                record['names'] = installed_name_map(content)
                            except ValueError as exc:
                                record['name_map_parse_error'] = str(exc)
                        public['extracted_assets'].append(record)
        reports.append(public)
    result = dict(kind='offline_installed_pak_access_validation',
                  client_sha256=cache.manifest['client_sha256'], cache_manifest_sha256=args.manifest_sha256,
                  process_access=False, client_launched=False, game_written=False, key_material_disclosed=False,
                  key_reconstruction=provenance,
                  derivation_rva='0x12453fc0', decrypt_callback_rva='0x12454370',
                  hash_function_rva='0x10b27930', aes_decrypt_rva='0x10ac7340',
                  path_search_expression=args.find, extract_expression=args.extract,
                  selected_pak_file_count=len(reports),
                  all_primary_indices_sha1_valid=all(report.get('index_sha1_valid', False) for report in reports),
                  all_secondary_indices_sha1_valid=all(section['sha1_valid'] for report in reports for section in report.get('secondary_indices', [])),
                  total_directory_file_count=sum(report.get('directory_file_count', 0) for report in reports),
                  paks=reports)
    encoded = (json.dumps(result, indent=2)+'\n').encode()
    with args.output.open('xb') as stream:
        stream.write(encoded)
    print(json.dumps(dict(output=str(args.output), sha256=hashlib.sha256(encoded).hexdigest(),
                          registered_guid_count=len(keys), validated_indices=sum(r.get('index_sha1_valid', False) for r in reports),
                          key_material_disclosed=False)))


if __name__ == '__main__':
    main()
