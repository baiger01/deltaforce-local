"""Bounded offline disassembly/xrefs in an explicitly qualified private cache."""
import argparse
import hashlib
import json
import mmap
from pathlib import Path
import re
import struct

from capstone import Cs, CS_ARCH_X86, CS_MODE_64
from capstone.x86_const import X86_OP_IMM, X86_OP_MEM, X86_REG_RIP

from portable_native_code_cache import CodeCache
from offline_received_packet_xrefs import ImmutableImage, literal_candidates

ROOT = Path(__file__).resolve().parent.parent


def integer(value):
    return int(value, 0)


def function_fragments(image, target):
    def root(entry):
        seen = set()
        while image.unwind(entry)['unwind_flags'] & 4:
            if entry in seen or len(seen) >= 32:
                raise ValueError('Pdata unwind cycle or depth bound')
            seen.add(entry)
            entry = tuple(int(v, 16) for v in image.unwind(entry)['chained_entry'])
        return entry

    entry = image.containing(target)
    if entry is None:
        raise ValueError('No pdata entry for '+hex(target))
    first = root(entry)
    if image.containing(first[0]) != first:
        raise ValueError('Unwind root is not an immutable pdata entry')
    if not 0 < first[1]-first[0] <= 65536:
        raise ValueError('Pdata root exceeds the bounded function extent')
    fragments, index = [first], image.begins.index(first[0])+1
    while index < len(image.entries):
        following = image.entries[index]
        if following[0] != fragments[-1][1] or root(following) != first:
            break
        fragments.append(following)
        index += 1
        if len(fragments) > 256 or fragments[-1][1]-first[0] > 65536:
            raise ValueError('Contiguous function chain exceeds the read bound')
    if not first[0] <= target < fragments[-1][1]:
        raise ValueError('Target belongs to a noncontiguous cold fragment')
    return fragments


def analyze(folder, manifest_sha, game_root, targets, literals, call_targets, spans=(), member_offsets=()):
    cache = CodeCache(folder, manifest_sha, game_root)
    exe = Path(game_root)/cache.manifest['plan']['client_relative_to_game_root']
    md = Cs(CS_ARCH_X86, CS_MODE_64)
    md.detail = True
    with exe.open('rb') as stream, mmap.mmap(stream.fileno(), 0, access=mmap.ACCESS_READ) as data:
        image = ImmutableImage(data)

        def code(first, amount):
            return b''.join(cache.read(at, min(8192, first+amount-at))
                            for at in range(first, first+amount, 8192))

        def literal_at(rva):
            try:
                raw = image.read(rva, 256)
            except ValueError:
                return None
            for encoding, delimiter in (('ascii', b'\0'), ('utf-16-le', b'\0\0')):
                if encoding == 'utf-16-le':
                    end = next((i for i in range(0, len(raw)-1, 2) if raw[i:i+2] == delimiter), len(raw))
                else:
                    end = raw.find(delimiter)
                    if end < 0:
                        continue
                try:
                    text = raw[:end].decode(encoding)
                except UnicodeDecodeError:
                    continue
                if len(text) >= 3 and all(c.isprintable() for c in text):
                    return text
            return None

        functions = []
        ranges = []
        for target in targets:
            fragments = function_fragments(image, target)
            entry = fragments[0]
            ranges.append((target, entry[0], fragments[-1][1]-entry[0], fragments))
        for first, amount in spans:
            if not 0 < amount <= 16384:
                raise ValueError('A bounded explicit code span is required')
            entry = image.containing(first)
            ranges.append((first, first, amount, [entry] if entry else []))
        for target, first, amount, fragments in ranges:
            raw = code(first, amount)
            instructions = []
            for ins in md.disasm(raw, first):
                row = dict(rva=hex(ins.address), bytes=ins.bytes.hex(), mnemonic=ins.mnemonic,
                           operands=ins.op_str)
                if ins.mnemonic in ('call', 'jmp') and len(ins.operands) == 1 and ins.operands[0].type == X86_OP_IMM:
                    row['direct_target_rva'] = hex(ins.operands[0].imm)
                refs = []
                for operand in ins.operands:
                    if operand.type == X86_OP_MEM and operand.mem.base == X86_REG_RIP:
                        rva = ins.address+ins.size+operand.mem.disp
                        ref = dict(rva=hex(rva))
                        text = literal_at(rva)
                        if text:
                            ref['immutable_literal_candidate'] = text
                        refs.append(ref)
                if refs:
                    row['rip_references'] = refs
                instructions.append(row)
            covered = sum(len(bytes.fromhex(row['bytes'])) for row in instructions)
            functions.append(dict(requested_rva=hex(target), pdata=image.unwind(fragments[0]) if fragments else None,
                pdata_fragments=[image.unwind(entry) for entry in fragments],
                span_start=hex(first), span_bytes=amount, complete_native_function_claimed=False,
                code_sha256=hashlib.sha256(raw).hexdigest(), decoded_bytes=covered,
                linear_decode_covers_extent=covered == len(raw), instructions=instructions))

        literal_rvas, literal_locations = {}, []
        for literal in literals:
            for encoding in ('ascii', 'utf-16-le'):
                needle = literal.encode(encoding)+ (b'\0' if encoding == 'ascii' else b'\0\0')
                at = 0
                while True:
                    at = data.find(needle, at)
                    if at < 0:
                        break
                    for rva, size, raw, _ in image.sections:
                        if raw <= at < raw+size:
                            address = rva+at-raw
                            literal_rvas[address] = literal
                            literal_locations.append(dict(name=literal, encoding=encoding, rva=hex(address)))
                    at += len(needle)
        pointer_references = []
        for target, name in literal_rvas.items():
            needle, at = struct.pack('<Q', image.image_base+target), 0
            while True:
                at = data.find(needle, at)
                if at < 0:
                    break
                for base, size, backing, _ in image.sections:
                    if backing <= at < backing+size:
                        rva = base+at-backing
                        low = max(backing, at-16)
                        high = min(backing+size, at+40)
                        pointer_references.append(dict(literal=name, pointer_rva=hex(rva),
                            nearby_qwords=[hex(v[0]) for v in struct.iter_unpack('<Q', data[low:high])],
                            nearby_start_rva=hex(base+low-backing),
                            registration_record_verified=False))
                at += 8
        references, calls, members, checked = [], [], [], 0
        if literal_rvas or call_targets or member_offsets:
            for section in cache.manifest['sections']:
                previous = b''
                for block in section['blocks']:
                    if not block['available']:
                        previous = b''
                        continue
                    path = cache.folder/block['file']
                    raw = path.read_bytes()
                    if len(raw) != block['bytes'] or hashlib.sha256(raw).hexdigest() != block['code_sha256']:
                        raise ValueError('Offline search block changed')
                    checked += len(raw)
                    first = int(block['rva'], 16)-len(previous)
                    window = previous+raw
                    for at, target, encoded in literal_candidates(window, first, literal_rvas):
                        function = image.containing(at)
                        references.append(dict(instruction_rva=hex(at), literal=literal_rvas[target],
                            target_rva=hex(target), encoded=encoded.hex(),
                            pdata_function=hex(function[0]) if function else None,
                            instruction_boundary_verified=False))
                    for offset in member_offsets:
                        pattern = rb'[\x48-\x4f]\x8d[\x80-\xbf]'+re.escape(struct.pack('<I', offset))
                        for match in re.finditer(pattern, window):
                            at = first+match.start()
                            ins = next(md.disasm(match.group(), at, count=1), None)
                            if ins is None or ins.size != 7:
                                continue
                            function = image.containing(at)
                            members.append(dict(instruction_rva=hex(at), member_offset=hex(offset),
                                operands=ins.op_str, pdata_function=hex(function[0]) if function else None,
                                instruction_boundary_verified=False))
                    if call_targets:
                        for match in re.finditer(b'\xe8', window):
                            at = match.start()
                            if at+5 > len(window):
                                continue
                            target = first+at+5+struct.unpack_from('<i', window, at+1)[0]
                            if target in call_targets:
                                function = image.containing(first+at)
                                calls.append(dict(instruction_rva=hex(first+at), target_rva=hex(target),
                                    pdata_function=hex(function[0]) if function else None,
                                    instruction_boundary_verified=False))
                    previous = raw[-6:]
        return dict(kind='qualified_portable_offline_native_analysis',
            client_sha256=cache.manifest['client_sha256'], cache_manifest_sha256=manifest_sha,
            process_access=False, client_launched=False, code_section_bytes_checked=checked,
            functions=functions, immutable_literal_locations=literal_locations,
            immutable_pointer_candidates=pointer_references,
            literal_xref_candidates=references, direct_call_candidates=calls,
            member_lea_candidates=members,
            candidate_xrefs_are_not_execution_proof=True)


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--cache', type=Path, required=True)
    parser.add_argument('--manifest-sha256', required=True)
    parser.add_argument('--game-root', type=Path, required=True)
    parser.add_argument('--function', type=integer, action='append', default=[])
    parser.add_argument('--literal', action='append', default=[])
    parser.add_argument('--call-target', type=integer, action='append', default=[])
    parser.add_argument('--span', action='append', default=[])
    parser.add_argument('--member-offset', type=integer, action='append', default=[])
    parser.add_argument('--output', type=Path, required=True)
    opts = parser.parse_args()
    if max(len(opts.function), len(opts.literal), len(opts.call_target), len(opts.span), len(opts.member_offset)) > 32:
        parser.error('At most 32 explicit targets per category')
    if opts.output.exists() or not opts.output.resolve().is_relative_to(ROOT/'work/evidence'):
        parser.error('Use a new evidence output')
    result = analyze(opts.cache, opts.manifest_sha256, opts.game_root,
                     opts.function, opts.literal, set(opts.call_target),
                     [tuple(integer(v) for v in span.split(':')) for span in opts.span], opts.member_offset)
    opts.output.parent.mkdir(parents=True, exist_ok=True)
    raw = (json.dumps(result, indent=2, ensure_ascii=False)+'\n').encode('utf-8')
    with opts.output.open('xb') as output:
        output.write(raw)
    print(json.dumps(dict(path=str(opts.output), sha256=hashlib.sha256(raw).hexdigest(),
        functions=len(result['functions']), literal_xrefs=len(result['literal_xref_candidates']),
        call_candidates=len(result['direct_call_candidates']))))
