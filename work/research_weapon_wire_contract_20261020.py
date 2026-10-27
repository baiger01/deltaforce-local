"""Inspect bounded weapon declarations and saved native code without game access."""
import argparse
import ast
from datetime import datetime, timezone
import hashlib
import json
import mmap
from pathlib import Path
import struct
import sys

sys.dont_write_bytecode = True
PEER = Path('E:/新建文件夹/DSH/deltaforce-map-appearance')
GAME = Path('F:/WeGameApps/rail_apps/DeltaForce(2001918)')
MANIFEST_SHA = 'dfd5c279d7db45842cee2bbc485ac8bf3cab03e4249ef5fe36bc9e8d6cd14754'
sys.path.insert(0, str(PEER/'work'))
from capstone import Cs, CS_ARCH_X86, CS_MODE_64
from capstone.x86_const import X86_OP_MEM, X86_REG_RIP
from offline_received_packet_xrefs import ImmutableImage
from portable_native_code_cache import CodeCache
from analyze_portable_native_code import analyze


def digest(value):
    return hashlib.sha256(value).hexdigest()


def verify_saved(folder, cache, image):
    root = (Path(__file__).resolve().parent/'evidence/weapon-wire-research-20261020').resolve()
    if folder.resolve(strict=True) != root:
        raise ValueError('Only this research snapshot folder is supported')
    counts = dict(code_ranges=0, immutable_records=0)
    files = []

    def check(rva, size, expected, code=False):
        if code:
            raw = b''.join(cache.read(at, min(8192, rva+size-at))
                           for at in range(rva, rva+size, 8192))
        else:
            raw = image.read(rva, size)
        if digest(raw) != expected:
            raise ValueError('Research source changed at ' + hex(rva))
        counts['code_ranges' if code else 'immutable_records'] += 1

    def walk(value):
        if isinstance(value, list):
            for child in value:
                walk(child)
        elif isinstance(value, dict):
            if 'record_rva' in value and 'record_sha256' in value:
                size = 56 if 'native_gen_flags' in value else 72
                check(int(value['record_rva'], 0), size, value['record_sha256'])
            if 'function_params_rva' in value:
                check(int(value['function_params_rva'], 0), 80, value['function_params_sha256'])
                check(int(value['getter_rva'], 0), 128, value['getter_probe_sha256'], True)
            if 'rva' in value and 'sha256' in value and 'bytes' in value:
                check(int(value['rva'], 0), value['bytes'], value['sha256'], 'instructions' in value)
            if 'span_start' in value and 'code_sha256' in value:
                check(int(value['span_start'], 0), value['span_bytes'], value['code_sha256'], True)
            for child in value.values():
                if isinstance(child, (dict, list)):
                    walk(child)

    for path in sorted(folder.glob('gameplay-weapon-*.json')):
        raw = path.read_bytes()
        if len(raw) > 8*1024*1024:
            raise ValueError('Research snapshot exceeds bound')
        document = json.loads(raw)
        if (document['client_sha256'] != cache.manifest['client_sha256'] or
                document['cache_manifest_sha256'] != MANIFEST_SHA or
                any(document[name] is not False for name in
                    ('process_access', 'client_launched', 'packets_sent', 'account_database_opened'))):
            raise ValueError('Research snapshot has a different provenance')
        walk(document)
        files.append(dict(path=path.name, sha256=digest(raw)))
    if not files or not all(counts.values()):
        raise ValueError('No complete source snapshots to verify')
    return dict(kind='weapon_research_source_revalidation', verified_at_utc=datetime.now(timezone.utc).isoformat(),
                client_sha256=cache.manifest['client_sha256'], cache_manifest_sha256=MANIFEST_SHA,
                process_access=False, client_launched=False, account_database_opened=False,
                packets_sent=False, source_generator_versions_may_differ=True,
                verified_code_ranges=counts['code_ranges'], verified_immutable_records=counts['immutable_records'],
                files=files)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--struct-getter', type=lambda x: int(x, 0), action='append', default=[])
    parser.add_argument('--function', action='append', default=[], help='getter-RVA:function-name')
    parser.add_argument('--code', type=lambda x: int(x, 0), action='append', default=[])
    parser.add_argument('--size', type=int, default=160)
    parser.add_argument('--data', action='append', default=[], help='RVA:bounded-byte-count')
    parser.add_argument('--native-function', type=lambda x: int(x, 0), action='append', default=[])
    parser.add_argument('--literal', action='append', default=[])
    parser.add_argument('--verify-saved', type=Path)
    args = parser.parse_args()
    if not 1 <= args.size <= 8192 or sum(map(len, (args.struct_getter, args.function, args.code, args.data, args.native_function, args.literal))) > 48:
        parser.error('Use bounded offline queries')
    cache = CodeCache(PEER/'work/native-code-cache/1792259162856698600', MANIFEST_SHA, GAME)
    md = Cs(CS_ARCH_X86, CS_MODE_64)
    md.detail = True
    helper = PEER/'work/inspect_economy_uht_class_metadata.py'
    helper_raw = helper.read_bytes()
    result = dict(kind='offline_weapon_contract_research',
        observed_at_utc=datetime.now(timezone.utc).isoformat(),
        client_sha256=cache.manifest['client_sha256'], cache_manifest_sha256=MANIFEST_SHA,
        script_sha256=digest(Path(__file__).read_bytes()),
        declaration_helper_sha256=digest(helper_raw),
        process_access=False, packets_sent=False, client_launched=False,
        account_database_opened=False, game_methods_invoked=False, files_written=False,
        wire_layout_observed=False)
    with (GAME/cache.manifest['plan']['client_relative_to_game_root']).open('rb') as stream:
        with mmap.mmap(stream.fileno(), 0, access=mmap.ACCESS_READ) as mapped:
            image = ImmutableImage(mapped)
            if args.verify_saved:
                print(json.dumps(verify_saved(args.verify_saved, cache, image), ensure_ascii=True, indent=2))
                return
            env = dict(image=image, cache=cache, md=md, struct=struct, hashlib=hashlib)
            import capstone.x86_const as constants
            env.update(vars(constants))
            for node in ast.walk(ast.parse(helper_raw.decode('utf-8'))):
                if isinstance(node, ast.FunctionDef) and node.name in ('text', 'prop', 'function'):
                    exec(compile(ast.Module(body=[node], type_ignores=[]), str(helper), 'exec'), env)
            result['functions'] = [env['function'](int(value.split(':', 1)[0], 0), value.split(':', 1)[1])
                                   for value in args.function]
            result['structs'] = []
            for getter in args.struct_getter:
                candidates = []
                for ins in md.disasm(cache.read(getter, 128), getter):
                    if ins.mnemonic == 'ret':
                        break
                    if ins.mnemonic == 'lea' and len(ins.operands) == 2:
                        op = ins.operands[1]
                        if op.type == X86_OP_MEM and op.mem.base == X86_REG_RIP:
                            rva = ins.address+ins.size+op.mem.disp
                            if 0x1c000000 <= rva < 0x1d400000:
                                candidates.append(rva)
                if len(candidates) != 1:
                    raise ValueError('An unambiguous struct declaration getter is required')
                rva = candidates[0]
                raw = image.read(rva, 72)
                values = struct.unpack('<9Q', raw)
                count = values[7] & 0xffffffff
                if values[7] >> 32 != 0x45 or not 0 <= count <= 256:
                    raise ValueError('Unsupported struct declaration shape')
                pointers = struct.unpack('<'+'Q'*count, image.read(values[6]-image.image_base, count*8)) if count else ()
                result['structs'].append(dict(name=env['text'](values[3]), getter_rva=hex(getter),
                    record_rva=hex(rva), record_sha256=digest(raw), native_size=values[4],
                    alignment=values[5], property_record_count=count,
                    fields=[env['prop'](pointer) for pointer in pointers]))
            result['code'] = []
            for rva in args.code:
                raw = cache.read(rva, args.size)
                result['code'].append(dict(rva=hex(rva), bytes=len(raw), sha256=digest(raw),
                    instructions=[dict(rva=hex(ins.address), bytes=ins.bytes.hex(),
                                       mnemonic=ins.mnemonic, operands=ins.op_str) for ins in md.disasm(raw, rva)]))
            result['data'] = []
            for value in args.data:
                rva, count = (int(part, 0) for part in value.split(':', 1))
                if not 1 <= count <= 4096:
                    raise ValueError('Bounded immutable data query required')
                raw = image.read(rva, count)
                result['data'].append(dict(rva=hex(rva), bytes=count, sha256=digest(raw), hex=raw.hex()))
            native_targets = [rva for rva in args.native_function if image.containing(rva) is not None]
            result['native_requests_without_pdata'] = [hex(rva) for rva in args.native_function
                                                       if image.containing(rva) is None]
    if args.native_function or args.literal:
        result['native_analysis'] = analyze(cache.folder, MANIFEST_SHA, GAME, native_targets, args.literal, set())
    print(json.dumps(result, ensure_ascii=True, indent=2))


if __name__ == '__main__':
    main()
