"""Bounded image-code trace rooted in two immutable named class records.

This reads no live object, virtual table, heap, account or session data. A
type-adapter table is inspected only in the pinned on-disk image. Its entries
are leads, not proof of the concrete connection's vtable or packet parser.
"""
from collections import deque
from datetime import datetime, timezone
import ctypes as C
import hashlib
import mmap
from pathlib import Path
import struct

import capstone
from capstone.x86 import X86_OP_IMM, X86_OP_MEM, X86_REG_RIP
import pefile
import psutil

from capture_official_ds import SOURCE_SHA, digest, verified_pids, save
from read_named_ds_transport_code import kernel, Module, Memory

CLASS_RECORDS = {
    'UGPNetConnection': (0x1ccd2bd8, 0x1622da80, 0x15e75f18, 0x5bf5c30, 0x2990),
    'UGPNetDriver': (0x1ccd2c08, 0x162aacf0, 0x15e765c8, 0x5c15910, 0x970),
}
MAX_FUNCTIONS = 24
MAX_TOTAL_BYTES = 65536
MAX_FUNCTION_BYTES = 8192
MAX_REFERENCE_DEPTH = 2
ADAPTER_TABLE_PREFIX_SLOTS = 6


class Image:
    def __init__(self, raw):
        self.raw = raw
        self.pe = pefile.PE(data=raw, fast_load=True)
        self.base = self.pe.OPTIONAL_HEADER.ImageBase
        directory = self.pe.OPTIONAL_HEADER.DATA_DIRECTORY[3]
        self.unwind_offset = self.pe.get_offset_from_rva(directory.VirtualAddress)
        self.unwind_count = directory.Size // 12

    def executable(self, rva, length=1):
        return length > 0 and any(s.Characteristics & 0x20000000 and
            s.VirtualAddress <= rva < rva + length <= s.VirtualAddress + s.Misc_VirtualSize
            for s in self.pe.sections)

    def data(self, rva, length):
        if not any(not s.Characteristics & 0x20000000 and
                s.VirtualAddress <= rva < rva + length <= s.VirtualAddress + s.SizeOfRawData
                for s in self.pe.sections):
            raise ValueError('Reference is not bounded immutable image data')
        offset = self.pe.get_offset_from_rva(rva)
        return self.raw[offset:offset + length]

    def entry(self, index):
        return struct.unpack_from('<III', self.raw, self.unwind_offset + index * 12)

    def span(self, rva):
        """Root .pdata and its exact chained continuations; no inferred length."""
        low, high = 0, self.unwind_count
        while low < high:
            middle = (low + high) // 2
            if self.entry(middle)[0] < rva:
                low = middle + 1
            else:
                high = middle
        if low == self.unwind_count or self.entry(low)[0] != rva:
            raise ValueError('Referenced address is not an unwind function root')
        root = self.entry(low)
        offset = self.pe.get_offset_from_rva(root[2])
        flags = self.raw[offset]
        if flags & 7 != 1 or flags >> 3 == 4:
            raise ValueError('Referenced address is an unwind continuation')
        end = root[1]
        fragments = [root[:2]]
        for index in range(low + 1, min(self.unwind_count, low + 32)):
            entry = self.entry(index)
            if entry[0] != end:
                break
            offset = self.pe.get_offset_from_rva(entry[2])
            flags, _, count, _ = struct.unpack_from('<4B', self.raw, offset)
            if flags & 7 != 1 or flags >> 3 != 4:
                break
            chain = offset + 4 + 4 * ((count + 1) // 2)
            if struct.unpack_from('<III', self.raw, chain) != root:
                break
            end = entry[1]
            fragments.append(entry[:2])
        if not rva < end <= rva + MAX_FUNCTION_BYTES or not self.executable(rva, end - rva):
            raise ValueError('Referenced function exceeds executable code bounds')
        return end - rva, fragments

    def class_roots(self):
        targets = []
        for name, (record, cell, label, callback, size) in CLASS_RECORDS.items():
            if struct.unpack('<3Q', self.data(record, 24)) != (self.base + cell, self.base + label, size):
                raise ValueError('Class registry record mismatch')
            if self.data(label, len(name) + 1) != name.encode('ascii') + b'\0':
                raise ValueError('Class registry name mismatch')
            if struct.unpack('<Q', self.data(cell, 8))[0] != self.base + callback:
                raise ValueError('Class registry callback mismatch')
            length, fragments = self.span(callback)
            if length != 84:
                raise ValueError('Named class callback boundary mismatch')
            targets.append((name + '.type_callback', callback, length, fragments, 0))
        return targets

    def adapter_prefix(self, instructions):
        """Recognize LEA reg,[RIP+table]; MOV [RAX],reg in the type callback.

        Only a fixed six-entry prefix is considered. Table size and method roles
        remain unknown; adjacent entries are not asserted to belong to a class.
        """
        for first, second in zip(instructions, instructions[1:]):
            a, b = first.operands, second.operands
            if (first.mnemonic == 'lea' and len(a) == 2 and a[1].type == X86_OP_MEM
                    and a[1].mem.base == X86_REG_RIP and second.mnemonic == 'mov'
                    and len(b) == 2 and b[0].type == X86_OP_MEM
                    and second.op_str.startswith('qword ptr [rax], ')
                    and a[0].reg == b[1].reg):
                table = first.address + first.size + a[1].mem.disp
                raw = self.data(table, ADAPTER_TABLE_PREFIX_SLOTS * 8)
                pointers = struct.unpack('<' + 'Q' * ADAPTER_TABLE_PREFIX_SLOTS, raw)
                entries = [(slot, va - self.base) for slot, va in enumerate(pointers)
                           if self.executable(va - self.base)]
                if len(entries) != ADAPTER_TABLE_PREFIX_SLOTS:
                    raise ValueError('Type adapter prefix contains non-code references')
                return table, entries
        return None


def collect(game_root, folder):
    executable = game_root / 'DeltaForce/Binaries/Win64/DeltaForceClient-Win64-Shipping.exe'
    if digest(executable) != SOURCE_SHA:
        raise ValueError('Client version hash mismatch')
    report = {'kind': 'bounded_named_connection_type_code_trace', 'client_sha256': SOURCE_SHA,
        'maximum_code_bytes': MAX_TOTAL_BYTES, 'maximum_functions': MAX_FUNCTIONS,
        'game_modified': False, 'process_memory_written': False, 'credential_memory_read': False,
        'live_object_or_vtable_read': False, 'functions': [], 'references': [], 'skipped': [],
        'concrete_received_raw_packet_identified': False,
        'observed_at_utc': datetime.now(timezone.utc).isoformat()}
    folder.mkdir(parents=True, exist_ok=True)
    pids = verified_pids(executable)
    if len(pids) != 1:
        report['status'] = 'original_process_not_unique'
        save(folder / 'result.json', report)
        return report
    api = kernel()
    handle = api.OpenProcess(0x1010, False, pids[0])
    if not handle:
        report.update(status='read_not_permitted', windows_error=C.get_last_error())
        save(folder / 'result.json', report)
        return report
    snapshot = api.CreateToolhelp32Snapshot(0x18, pids[0])
    try:
        item = Module()
        item.dwSize = C.sizeof(item)
        base, size = None, None
        if snapshot and snapshot != C.c_void_p(-1).value:
            ok = api.Module32FirstW(snapshot, C.byref(item))
            while ok:
                if Path(item.szExePath).resolve() == executable.resolve():
                    base, size = item.modBaseAddr, item.modBaseSize
                    break
                ok = api.Module32NextW(snapshot, C.byref(item))
        if base is None:
            raise RuntimeError('Verified executable module unavailable')
        started = psutil.Process(pids[0]).create_time()
        with executable.open('rb') as stream, mmap.mmap(stream.fileno(), 0, access=mmap.ACCESS_READ) as raw:
            image = Image(raw)
            plan = deque(image.class_roots())
            scheduled = {rva for _, rva, _, _, _ in plan}
            decoder = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
            decoder.detail = True
            used = 0

            def schedule(source, target, depth, reference_kind):
                edge = {'source_rva': hex(source), 'target_rva': hex(target), 'kind': reference_kind}
                report['references'].append(edge)
                if target in scheduled:
                    return
                if len(scheduled) >= MAX_FUNCTIONS or depth > MAX_REFERENCE_DEPTH:
                    edge['not_followed'] = 'graph_bound'
                    return
                try:
                    length, fragments = image.span(target)
                except ValueError as error:
                    edge['not_followed'] = str(error)
                    return
                scheduled.add(target)
                plan.append(('referenced_' + hex(target)[2:], target, length, fragments, depth))

            while plan:
                name, rva, length, fragments, depth = plan.popleft()
                if used + length > MAX_TOTAL_BYTES:
                    report['skipped'].append({'rva': hex(rva), 'reason': 'total_code_budget'})
                    continue
                if psutil.Process(pids[0]).create_time() != started:
                    raise RuntimeError('Original process identity changed')
                address, memory = base + rva, Memory()
                entry = {'name': name, 'rva': hex(rva), 'code_bytes': length,
                    'unwind_fragments': [[hex(a), hex(b)] for a, b in fragments], 'read_succeeded': False}
                valid = (image.executable(rva, length) and rva + length <= size and
                    api.VirtualQueryEx(handle, address, C.byref(memory), C.sizeof(memory)) == C.sizeof(memory) and
                    memory.State == 0x1000 and memory.Type == 0x1000000 and memory.AllocationBase == base and
                    memory.Protect & 0xff in (0x10, 0x20, 0x40, 0x80) and not memory.Protect & 0x100 and
                    address + length <= memory.BaseAddress + memory.RegionSize)
                if valid:
                    buffer, copied = (C.c_ubyte * length)(), C.c_size_t()
                    if api.ReadProcessMemory(handle, address, buffer, length, C.byref(copied)) and copied.value == length:
                        code = bytes(buffer)
                        used += length
                        instructions = list(decoder.disasm(code, rva))
                        entry.update(read_succeeded=True, code_sha256=hashlib.sha256(code).hexdigest(),
                            disassembled_bytes=sum(i.size for i in instructions))
                        (folder / (name + '.dfcode')).write_bytes(struct.pack('<4Q', 0x0000000145444344, rva, length, base) + code)
                        (folder / (name + '.asm.txt')).write_text('\n'.join(
                            f'{i.address:#x}: {i.mnemonic} {i.op_str}' for i in instructions) + '\n', encoding='utf-8')
                        if name.endswith('.type_callback'):
                            try:
                                adapter = image.adapter_prefix(instructions)
                                if adapter:
                                    table, entries = adapter
                                    entry['immutable_type_adapter_prefix_rva'] = hex(table)
                                    for slot, target in entries:
                                        schedule(rva, target, 0, 'type_adapter_prefix_slot_' + str(slot))
                            except ValueError as error:
                                entry['adapter_reference_not_followed'] = str(error)
                        elif depth < MAX_REFERENCE_DEPTH:
                            # Exact image-code operands only; never read indirect
                            # calls, runtime pointers or arbitrary address requests.
                            for ins in instructions:
                                if ins.mnemonic in ('call', 'jmp') and len(ins.operands) == 1 and ins.operands[0].type == X86_OP_IMM:
                                    target = ins.operands[0].imm
                                    if not rva <= target < rva + length and image.executable(target):
                                        schedule(ins.address, target, depth + 1, 'direct_' + ins.mnemonic)
                    else:
                        entry['windows_error'] = C.get_last_error()
                else:
                    entry['read_refused_reason'] = 'image_executable_page_guard_not_satisfied'
                report['functions'].append(entry)
                save(folder / 'result.json', report)
            report.update(status='bounded_read_attempt_complete', actual_code_bytes=used)
    finally:
        if snapshot and snapshot != C.c_void_p(-1).value:
            api.CloseHandle(snapshot)
        api.CloseHandle(handle)
    save(folder / 'result.json', report)
    return report
