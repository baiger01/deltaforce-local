"""Mock-address metadata exports only; no process, native call or game schema."""
import hashlib
import struct
import unittest

from native_replication_metadata_core import (
    MAX_ADDRESS, MAX_BUCKETS, MAX_HASH_CHAIN, MAX_LAYOUT_CMDS,
    MAX_LAYOUT_PARENTS, MAX_READ_BYTES, MAX_READ_CALLS, MAX_SINGLE_READ,
    MAX_TABLE_SLOTS, MetadataSession, export_cache_graph,
    export_existing_driver_class, export_replayout, lookup_weak_key_table,
)


KEY = struct.pack('<ii', 9, 3)
OTHER = struct.pack('<ii', 13, 3)  # Same xor/mask bucket as KEY for four buckets.
TABLE, DATA, BUCKETS = 0x30000, 0x40000, 0x50000


class MockMemory:
    def __init__(self):
        self.blocks = []
        self.calls = []
        self.responses = {}

    def add(self, address, raw):
        self.blocks.append((address, bytes(raw)))

    def respond(self, address, size, *responses):
        self.responses[(address, size)] = list(responses)

    def __call__(self, address, size):
        self.calls.append((address, size))
        queue = self.responses.get((address, size))
        if queue:
            response = queue.pop(0)
            if isinstance(response, BaseException):
                raise response
            return response
        for base, raw in reversed(self.blocks):
            if base <= address and address + size <= base + len(raw):
                return raw[address-base:address-base+size]
        raise ValueError('Unmapped mock bytes')


def weak_entry(key, value, next_index=-1, *, kind='cache', control=0x80000):
    if kind == 'cache':
        return struct.pack('<QQiI', int.from_bytes(key, 'little'), value, next_index, 0xaabbccdd)
    return struct.pack('<QQQiI', int.from_bytes(key, 'little'), value, control,
                       next_index, 0xaabbccdd)


def table(memory, entries=(), *, address=TABLE, data=DATA, buckets=4,
          bucket_storage=BUCKETS, bucket_index=0, free=0, capacity=None,
          kind='cache', key=KEY):
    count = len(entries)
    raw = bytearray(0x50)
    struct.pack_into('<Qii', raw, 0, data, count, count if capacity is None else capacity)
    struct.pack_into('<i', raw, 0x34, free)
    struct.pack_into('<Q', raw, 0x40, bucket_storage)
    struct.pack_into('<i', raw, 0x48, buckets)
    bucket_raw = bytearray(b'\xff'*max(0, buckets*4))
    if buckets > 0:
        low, high = struct.unpack('<II', key)
        struct.pack_into('<i', bucket_raw, ((low ^ high) & (buckets-1))*4, bucket_index)
    if bucket_storage:
        memory.add(bucket_storage, bucket_raw)
    elif 0 <= buckets <= 2:
        raw[0x38:0x38+len(bucket_raw)] = bucket_raw
    memory.add(address, raw)
    memory.add(data, b''.join(entries))
    return bytes(raw)


def cache_header(*, start=0, parent=0, key=KEY, storage=0x90000,
                 count=1, capacity=None):
    raw = bytearray(48)
    struct.pack_into('<I', raw, 0, start)
    struct.pack_into('<Q', raw, 8, parent)
    raw[0x10:0x18] = key
    struct.pack_into('<I', raw, 0x18, 0x12345678)
    struct.pack_into('<Qii', raw, 0x20, storage, count,
                     count if capacity is None else capacity)
    return bytes(raw)


def cache_entry(index, *, descriptor=0xa0000):
    raw = bytearray(b'\xa5'*32)
    struct.pack_into('<Q', raw, 0, descriptor)
    raw[8] = 0
    struct.pack_into('<II', raw, 0x10, index, 0)
    raw[0x18] = 0
    return bytes(raw)


def add_cache(memory, *, address=0x70000, start=0, parent=0, key=KEY,
              storage=0x90000, count=1, capacity=None):
    raw = cache_header(start=start, parent=parent, key=key, storage=storage,
                       count=count, capacity=capacity)
    memory.add(address, raw)
    memory.add(storage, b''.join(cache_entry(start+i) for i in range(max(0, count))))
    return raw


def command(*, data=-8, shadow=16, parent=0, gate=7):
    raw = bytearray(b'\xa5'*32)
    struct.pack_into('<ii', raw, 0xc, data, shadow)
    struct.pack_into('<H', raw, 0x16, parent)
    raw[0x1c] = gate
    return bytes(raw)


def add_layout(memory, *, address=0xb0000, parents=0xc0000, cmds=0xd0000,
               parent_count=1, cmd_count=2, parent_capacity=None, cmd_capacity=None):
    header = struct.pack('<QiiQii', parents, parent_count,
        parent_count if parent_capacity is None else parent_capacity,
        cmds, cmd_count, cmd_count if cmd_capacity is None else cmd_capacity)
    parent_raw = b'\xa5'*(max(0, parent_count)*64)
    cmd_raw = b''.join(command(data=-8+i, shadow=16+i, gate=i % 2)
                       for i in range(max(0, cmd_count)))
    memory.add(address+0x40, header)
    memory.add(parents, parent_raw)
    memory.add(cmds, cmd_raw)
    return header, parent_raw, cmd_raw


def full_driver(memory, *, driver=0x100000, manager=0x200000,
                cache_key=KEY, with_cache=True, with_layout=True):
    memory.add(driver+0x170, struct.pack('<Q', manager))
    if manager:
        entries = (weak_entry(KEY, 0x70000),) if with_cache else ()
        table(memory, entries, address=manager+8, data=0x210000,
              bucket_storage=0x220000, kind='cache')
    entries = (weak_entry(KEY, 0xb0000, kind='layout'),) if with_layout else ()
    table(memory, entries, address=driver+0x430, data=0x410000,
          bucket_storage=0x420000, kind='layout')
    if with_cache:
        add_cache(memory, address=0x71000, count=2, storage=0x91000, key=OTHER)
        add_cache(memory, address=0x70000, start=2, parent=0x71000, key=cache_key)
    if with_layout:
        add_layout(memory)
    return driver


class SessionTests(unittest.TestCase):
    def test_strict_budget_constructor_and_backend(self):
        for backend in (None, b'', 1):
            with self.subTest(backend=backend), self.assertRaises(ValueError):
                MetadataSession(backend)
        for kwargs in ({'max_bytes':True}, {'max_bytes':0}, {'max_bytes':MAX_READ_BYTES+1},
                       {'max_calls':True}, {'max_calls':0}, {'max_calls':MAX_READ_CALLS+1}):
            with self.subTest(kwargs=kwargs), self.assertRaises(ValueError):
                MetadataSession(lambda address, size: b'\0'*size, **kwargs)

    def test_invalid_ranges_and_oversized_read_never_reach_backend(self):
        memory = MockMemory()
        session = MetadataSession(memory)
        for address, size in ((0, 1), (0xffff, 1), (True, 1),
                (MAX_ADDRESS, 2), (MAX_ADDRESS+1, 1), (0x10000, True),
                (0x10000, 0), (0x10000, -1), (0x10000, MAX_SINGLE_READ+1)):
            with self.subTest(address=address, size=size), self.assertRaises(ValueError):
                session.read(address, size)
        self.assertEqual((session.calls, session.bytes_read, memory.calls), (0, 0, []))

    def test_failed_partial_mutable_or_long_reads_charge_attempt_budget(self):
        for response in (b'123', b'12345', bytearray(4), memoryview(b'1234'),
                         OSError('mock failure')):
            memory = MockMemory()
            memory.respond(0x10000, 4, response)
            session = MetadataSession(memory, max_bytes=4, max_calls=1)
            with self.subTest(response_type=type(response)):
                with self.assertRaises((ValueError, OSError)):
                    session.read(0x10000, 4)
                self.assertEqual((session.bytes_read, session.calls), (4, 1))
                with self.assertRaises(ValueError):
                    session.read(0x10000, 1)
                self.assertEqual(memory.calls, [(0x10000, 4)])

    def test_chunked_array_and_exact_byte_and_call_budget(self):
        memory = MockMemory()
        raw = bytes(range(256))*(MAX_SINGLE_READ//256*2) + b'abc'
        memory.add(0x10000, raw)
        session = MetadataSession(memory, max_bytes=len(raw), max_calls=3)
        self.assertEqual(session.array(0x10000, len(raw)), raw)
        self.assertEqual(memory.calls, [(0x10000,8192), (0x12000,8192), (0x14000,3)])
        with self.assertRaises(ValueError):
            session.read(0x10000, 1)
        self.assertEqual((session.bytes_read, session.calls), (len(raw), 3))

    def test_empty_array_allows_null_storage_but_not_bool_size(self):
        memory = MockMemory()
        session = MetadataSession(memory)
        self.assertEqual(session.array(0, 0), b'')
        for size in (False, 0.0):
            with self.subTest(size=size), self.assertRaises(ValueError):
                session.array(0, size)
        self.assertEqual(memory.calls, [])

    def test_stable_detects_changed_bytes_and_uses_shared_budget(self):
        memory = MockMemory()
        memory.respond(0x10000, 4, b'aaaa', b'aaab')
        session = MetadataSession(memory, max_bytes=8, max_calls=2)
        with self.assertRaisesRegex(ValueError, 'changed'):
            session.stable(0x10000, 4)
        self.assertEqual((session.bytes_read, session.calls), (8, 2))


class TableTests(unittest.TestCase):
    def lookup(self, memory, kind='cache', **kwargs):
        return lookup_weak_key_table(MetadataSession(memory), TABLE, KEY,
                                    value_kind=kind, **kwargs)

    def test_native_cache_stride_next_and_xor_bucket(self):
        memory = MockMemory()
        table(memory, (weak_entry(OTHER, 0x60000, 1), weak_entry(KEY, 0x70000)))
        result = self.lookup(memory)
        self.assertEqual(result, {'slot_index':1, 'value_address':0x70000})
        self.assertIn((BUCKETS+8,4), memory.calls)
        self.assertIn((DATA+24,24), memory.calls)
        self.assertNotIn((DATA+32,32), memory.calls)

    def test_native_layout_stride_shared_pair_and_next_offset(self):
        memory = MockMemory()
        table(memory, (weak_entry(OTHER, 0x60000, 1, kind='layout'),
                       weak_entry(KEY, 0x70000, kind='layout', control=0x88000)), kind='layout')
        self.assertEqual(self.lookup(memory, 'layout'),
            {'slot_index':1, 'value_address':0x70000, 'shared_control_address':0x88000})
        self.assertIn((DATA+32,32), memory.calls)
        self.assertFalse(any(address == 0x88000 for address, _ in memory.calls))

    def test_inline_one_and_two_buckets_are_supported_without_external_storage(self):
        for buckets in (1, 2):
            memory = MockMemory()
            table(memory, (weak_entry(KEY,0x70000),), buckets=buckets, bucket_storage=0)
            with self.subTest(buckets=buckets):
                self.assertEqual(self.lookup(memory)['value_address'],0x70000)
                self.assertIn((TABLE+0x38,4), memory.calls)
        memory = MockMemory()
        table(memory, (weak_entry(KEY,0x70000),), buckets=4, bucket_storage=0)
        with self.assertRaises(ValueError):
            self.lookup(memory)

    def test_wrong_keys_and_empty_table_return_missing_without_enumeration(self):
        memory = MockMemory()
        table(memory, (weak_entry(OTHER,0x60000),))
        self.assertIsNone(self.lookup(memory))
        empty = MockMemory()
        table(empty, (), data=0, buckets=0, bucket_storage=0)
        self.assertIsNone(self.lookup(empty))
        self.assertEqual(empty.calls, [(TABLE,0x50),(TABLE,0x50)])

    def test_exact_live_weak_key_required_before_read(self):
        for key in (b'', bytearray(KEY), struct.pack('<ii',-1,3),
                    struct.pack('<ii',9,0)):
            memory = MockMemory()
            with self.subTest(key=key), self.assertRaises(ValueError):
                lookup_weak_key_table(MetadataSession(memory), TABLE, key, value_kind='cache')
            self.assertEqual(memory.calls, [])
        with self.assertRaises(ValueError):
            lookup_weak_key_table(MetadataSession(MockMemory()),TABLE,KEY,value_kind='unknown')

    def test_unsigned_high_bit_serials_match_exact_native_key(self):
        # Native serial uses TEST/JE for zero and a raw dword comparison;
        # only the object index uses a signed negative check.
        for serial in (0x80000000,0xf1234567,0xffffffff):
            key = struct.pack('<iI',9,serial)
            for kind in ('cache','layout'):
                memory = MockMemory()
                table(memory,(weak_entry(key,0x70000,kind=kind),),kind=kind,key=key)
                with self.subTest(serial=serial,kind=kind):
                    result = lookup_weak_key_table(MetadataSession(memory),TABLE,key,value_kind=kind)
                    self.assertEqual(result['value_address'],0x70000)
                    low, high = struct.unpack('<II',key)
                    self.assertIn((BUCKETS+((low^high)&3)*4,4),memory.calls)

    def test_bad_sparse_counts_bucket_counts_and_storage_rejected(self):
        cases = ((8,-1), (8,MAX_TABLE_SLOTS+1), (12,-1), (0x34,2),
                 (0x48,0), (0x48,3), (0x48,MAX_BUCKETS+1))
        for offset, value in cases:
            memory = MockMemory()
            raw = bytearray(table(memory,(weak_entry(KEY,0x70000),)))
            struct.pack_into('<i',raw,offset,value)
            memory.add(TABLE,raw)
            with self.subTest(offset=offset,value=value), self.assertRaises(ValueError):
                self.lookup(memory)
        for data in (0, 0xffff, MAX_ADDRESS):
            memory = MockMemory()
            table(memory,(weak_entry(KEY,0x70000),),data=data)
            with self.subTest(data=data), self.assertRaises(ValueError):
                self.lookup(memory)

    def test_invalid_or_cyclic_chain_is_rejected(self):
        for next_index in (-2, 1, 0):
            memory = MockMemory()
            table(memory,(weak_entry(OTHER,0x70000,next_index),),buckets=1)
            with self.subTest(next_index=next_index), self.assertRaises(ValueError):
                self.lookup(memory)

    def test_exact_maximum_chain_can_terminate_without_matching_key(self):
        memory = MockMemory()
        entries = tuple(weak_entry(struct.pack('<ii',1000+i,3),0x70000,
            i+1 if i+1<MAX_HASH_CHAIN else -1) for i in range(MAX_HASH_CHAIN))
        table(memory,entries,buckets=1)
        self.assertIsNone(self.lookup(memory))
        self.assertEqual(sum(size==24 for _,size in memory.calls),MAX_HASH_CHAIN*2)

    def test_match_at_maximum_chain_and_over_budget_chain(self):
        memory = MockMemory()
        entries = tuple(weak_entry(KEY if i==MAX_HASH_CHAIN-1 else struct.pack('<ii',1000+i,3),
            0x70000,i+1 if i+1<MAX_HASH_CHAIN else -1) for i in range(MAX_HASH_CHAIN))
        table(memory,entries,buckets=1)
        self.assertEqual(self.lookup(memory)['slot_index'],MAX_HASH_CHAIN-1)
        longer = MockMemory()
        entries = tuple(weak_entry(struct.pack('<ii',1000+i,3),0x70000,
            i+1 if i<MAX_HASH_CHAIN else -1) for i in range(MAX_HASH_CHAIN+1))
        table(longer,entries,buckets=1)
        with self.assertRaises(ValueError):
            self.lookup(longer)
        self.assertFalse(any(address==DATA+MAX_HASH_CHAIN*24 for address,_ in longer.calls))

    def test_table_bucket_and_selected_entry_changes_rejected(self):
        for changed in ('header','bucket','item'):
            memory = MockMemory()
            old = table(memory,(weak_entry(KEY,0x70000),))
            if changed=='header':
                memory.respond(TABLE,0x50,old,old,old[:-1]+b'\x01')
            elif changed=='bucket':
                memory.respond(BUCKETS+8,4,struct.pack('<i',0),struct.pack('<i',-1))
            else:
                memory.respond(DATA,24,weak_entry(KEY,0x70000),weak_entry(KEY,0x71000))
            with self.subTest(changed=changed), self.assertRaisesRegex(ValueError,'changed'):
                self.lookup(memory)


class ExportTests(unittest.TestCase):
    def test_complete_inherited_cache_graph_reads_only_metadata(self):
        memory = MockMemory()
        add_cache(memory,address=0x71000,count=2,storage=0x91000,key=OTHER)
        add_cache(memory,start=2,parent=0x71000)
        graph = export_cache_graph(MetadataSession(memory),0x70000,expected_key=KEY)
        self.assertEqual(tuple(node.index_start for node in graph.nodes),(0,2))
        self.assertEqual(graph.exclusive_index_maximum,4)
        self.assertEqual(graph.require_compatible_descriptor(2).descriptor_address,0xa0000)
        self.assertFalse(any(address==0xa0000 for address,_ in memory.calls))

    def test_cache_invalid_storage_truncation_wrong_key_cycle_and_budget(self):
        for error in ('storage','truncated','key','cycle','budget'):
            memory = MockMemory()
            raw = add_cache(memory)
            session = MetadataSession(memory,max_calls=2 if error=='budget' else 100)
            if error=='storage':
                memory.add(0x70000,cache_header(storage=0))
            elif error=='truncated':
                memory.respond(0x90000,32,b'\0'*31)
            elif error=='key':
                memory.add(0x70000,cache_header(key=OTHER))
            elif error=='cycle':
                memory.add(0x70000,cache_header(parent=0x71000))
                add_cache(memory,address=0x71000,parent=0x70000,storage=0x91000)
            with self.subTest(error=error), self.assertRaises(ValueError):
                export_cache_graph(session,0x70000,expected_key=KEY)
            if error=='budget':
                self.assertEqual(len(memory.calls),2)

    def test_cache_headers_and_fields_changes_are_detected(self):
        for phase in ('header','entries'):
            memory = MockMemory()
            raw = add_cache(memory)
            if phase=='header':
                memory.respond(0x70000,48,raw,raw,cache_header(capacity=2))
            else:
                memory.respond(0x90000,32,cache_entry(0),cache_entry(0,descriptor=0xa1000))
            with self.subTest(phase=phase), self.assertRaisesRegex(ValueError,'changed'):
                export_cache_graph(MetadataSession(memory),0x70000)

    def test_layout_literal_offsets_are_metadata_not_wire_schema(self):
        memory = MockMemory()
        _,parent_raw,cmd_raw = add_layout(memory)
        result = export_replayout(MetadataSession(memory),0xb0000)
        self.assertEqual((result['parent_count'],result['command_count']),(1,2))
        self.assertEqual(result['parents_sha256'],hashlib.sha256(parent_raw).hexdigest())
        self.assertEqual(result['commands_sha256'],hashlib.sha256(cmd_raw).hexdigest())
        self.assertEqual(result['commands'][0],{
            'command_index':0,'descriptor_address':0xa5a5a5a5a5a5a5a5,
            'data_offset':-8,'shadow_offset':16,'relative_handle':0xa5a5,
            'parent_index':0,'dispatch_opcode':0,'dispatch_gate_byte':0,
            'record_sha256':hashlib.sha256(cmd_raw[:32]).hexdigest()})
        self.assertIs(result['parent_record_field_schema_recovered'],False)
        self.assertIs(result['property_serializer_schema_recovered'],False)

    def test_parent_descriptor_and_name_token_literal_native_offsets(self):
        memory = MockMemory()
        add_layout(memory,parent_count=2,cmd_count=0,cmds=0)
        # Only offsets0/+8 are established. Nonzero adjacent bytes prevent an
        # accidental reinterpretation of another Parent field or the64B stride.
        records = []
        for descriptor, token in ((0x12345000,bytes.fromhex('78563412efcdab89')),
                                  (0x76543000,bytes.fromhex('1032547698badcfe'))):
            raw = bytearray(b'\x5a'*64)
            struct.pack_into('<Q',raw,0,descriptor)
            raw[8:16] = token
            records.append(bytes(raw))
        memory.add(0xc0000,b''.join(records))
        result = export_replayout(MetadataSession(memory),0xb0000)
        self.assertEqual(result['parents'],[
            {'parent_index':0,'descriptor_address':0x12345000,
             'name_token':'78563412efcdab89',
             'record_sha256':hashlib.sha256(records[0]).hexdigest()},
            {'parent_index':1,'descriptor_address':0x76543000,
             'name_token':'1032547698badcfe',
             'record_sha256':hashlib.sha256(records[1]).hexdigest()}])
        self.assertEqual(result['commands'],[])
        self.assertFalse(any(address in (0x12345000,0x76543000)
                             for address,_ in memory.calls))
        self.assertIs(result['parent_record_field_schema_recovered'],False)

    def test_cmd_descriptor_relative_handle_and_special_opcode_literal_offsets(self):
        memory = MockMemory()
        add_layout(memory,parent_count=0,parents=0,cmd_count=3)
        records = []
        for descriptor, handle, parent, opcode in ((0x23456000,0x1234,0x4321,2),
                                                   (0x34567000,0xfedc,0xabcd,0x18)):
            raw = bytearray(b'\x5a'*32)
            struct.pack_into('<Q',raw,0,descriptor)
            struct.pack_into('<HH',raw,8,0x6789,0x9876)
            struct.pack_into('<iiHHI',raw,0xc,-123,456,handle,parent,0xabcdef01)
            raw[0x1c],raw[0x1d] = opcode,3
            records.append(bytes(raw))
        special = bytearray(32)
        special[0x1c] = 1  # Native builder: zero record, then specialOpcode1.
        records.append(bytes(special))
        memory.add(0xd0000,b''.join(records))
        result = export_replayout(MetadataSession(memory),0xb0000)
        self.assertEqual(tuple(item['descriptor_address'] for item in result['commands']),
                         (0x23456000,0x34567000,0))
        self.assertEqual(tuple(item['relative_handle'] for item in result['commands']),
                         (0x1234,0xfedc,0))
        self.assertEqual(tuple(item['parent_index'] for item in result['commands']),
                         (0x4321,0xabcd,0))
        self.assertEqual(tuple(item['dispatch_opcode'] for item in result['commands']),
                         (2,0x18,1))
        self.assertEqual(tuple(item['dispatch_gate_byte'] for item in result['commands']),
                         (2,0x18,1))
        self.assertEqual(tuple(item['record_sha256'] for item in result['commands']),
                         tuple(hashlib.sha256(raw).hexdigest() for raw in records))
        self.assertEqual(result['commands'][0]['data_offset'],-123)
        self.assertEqual(result['commands'][0]['shadow_offset'],456)
        self.assertTrue(all(address in (0xb0040,0xd0000) for address,_ in memory.calls))
        self.assertIs(result['property_serializer_schema_recovered'],False)

    def test_empty_layout_does_not_read_null_storage(self):
        memory = MockMemory()
        add_layout(memory,parent_count=0,cmd_count=0,parents=0,cmds=0)
        result = export_replayout(MetadataSession(memory),0xb0000)
        self.assertEqual(result['commands'],[])
        self.assertTrue(all(address==0xb0040 for address,_ in memory.calls))

    def test_layout_large_arrays_are_chunked_and_exactly_hashed(self):
        memory = MockMemory()
        _,parent_raw,cmd_raw = add_layout(memory,parent_count=129,cmd_count=257)
        result = export_replayout(MetadataSession(memory),0xb0000)
        self.assertEqual(result['parents_sha256'],hashlib.sha256(parent_raw).hexdigest())
        self.assertEqual(result['commands_sha256'],hashlib.sha256(cmd_raw).hexdigest())
        self.assertTrue(all(size<=MAX_SINGLE_READ for _,size in memory.calls))
        self.assertEqual(sum(address==0xd2000 for address,_ in memory.calls),2)

    def test_layout_bad_counts_storage_and_change_rejected(self):
        for error in ('negative_parent','negative_cmd','parent_limit','cmd_limit',
                      'parent_storage','cmd_storage','header_change','cmd_change'):
            memory = MockMemory()
            old,parents,cmds = add_layout(memory)
            if error in ('header_change','cmd_change'):
                if error=='header_change':
                    memory.respond(0xb0040,32,old,old,old[:-1]+b'\x01')
                else:
                    memory.respond(0xd0000,len(cmds),cmds,b'\0'*len(cmds))
            else:
                raw = bytearray(old)
                if error=='negative_parent': struct.pack_into('<i',raw,8,-1)
                elif error=='negative_cmd': struct.pack_into('<i',raw,24,-1)
                elif error=='parent_limit': struct.pack_into('<ii',raw,8,MAX_LAYOUT_PARENTS+1,MAX_LAYOUT_PARENTS+1)
                elif error=='cmd_limit': struct.pack_into('<ii',raw,24,MAX_LAYOUT_CMDS+1,MAX_LAYOUT_CMDS+1)
                elif error=='parent_storage': struct.pack_into('<Q',raw,0,0)
                elif error=='cmd_storage': struct.pack_into('<Q',raw,16,MAX_ADDRESS)
                memory.add(0xb0040,raw)
            with self.subTest(error=error), self.assertRaises(ValueError):
                export_replayout(MetadataSession(memory),0xb0000)

    def test_invalid_root_cannot_be_made_valid_by_adding_field_offset(self):
        memory = MockMemory()
        memory.add(0x10000,bytes(32))
        with self.subTest(root='layout'):
            with self.assertRaises(ValueError):
                export_replayout(MetadataSession(memory),0xffc0)
            self.assertEqual(memory.calls,[])
        driver_memory = MockMemory()
        driver_memory.add(0x10000,bytes(8))
        table(driver_memory,(),address=0x102c0,data=0,buckets=0,bucket_storage=0)
        with self.subTest(root='driver'):
            with self.assertRaises(ValueError):
                export_existing_driver_class(MetadataSession(driver_memory),0xfe90,KEY)
            self.assertEqual(driver_memory.calls,[])
        manager_memory = MockMemory()
        driver = full_driver(manager_memory,manager=0xfff8,
                             with_cache=False,with_layout=False)
        with self.subTest(root='manager'):
            with self.assertRaises(ValueError):
                export_existing_driver_class(MetadataSession(manager_memory),driver,KEY)
            self.assertEqual(manager_memory.calls,[(driver+0x170,8)])

    def test_complete_driver_existing_tables_cache_and_layout_chain(self):
        memory = MockMemory()
        driver = full_driver(memory)
        result = export_existing_driver_class(MetadataSession(memory),driver,KEY)
        self.assertEqual((result['cache_status'],result['layout_status']),
                         ('exported_existing','exported_existing'))
        self.assertEqual(result['exclusive_index_maximum'],4)
        self.assertEqual(tuple(node['index_start'] for node in result['cache_nodes']),(0,2))
        self.assertEqual(result['layout']['command_count'],2)
        self.assertIs(result['native_getter_invoked'],False)
        self.assertIs(result['snapshot_atomic'],False)
        self.assertIs(result['player_spawn_verified'],False)
        self.assertFalse(any(address in (0xa0000,0x80000) for address,_ in memory.calls))

    def test_missing_tables_do_not_allocate_or_invent_class_fields(self):
        memory = MockMemory()
        driver = full_driver(memory,manager=0,with_cache=False,with_layout=False)
        result = export_existing_driver_class(MetadataSession(memory),driver,KEY)
        self.assertEqual((result['cache_status'],result['layout_status']),('missing','missing'))
        self.assertNotIn('cache_nodes',result)
        self.assertNotIn('layout',result)
        self.assertEqual(len(memory.calls),4)

    def test_driver_wrong_cache_class_or_changed_manager_rejected(self):
        for error in ('wrong_class','manager_changed'):
            memory = MockMemory()
            driver = full_driver(memory,cache_key=OTHER if error=='wrong_class' else KEY)
            if error=='manager_changed':
                memory.respond(driver+0x170,8,struct.pack('<Q',0x200000),struct.pack('<Q',0x200100))
            with self.subTest(error=error), self.assertRaises(ValueError):
                export_existing_driver_class(MetadataSession(memory),driver,KEY)


if __name__=='__main__':
    unittest.main()
