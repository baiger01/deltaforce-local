"""Seal exact sequence-source and saved-fixture reviews; no live APIs."""
import hashlib
import io
import json
import mmap
from pathlib import Path
import struct
import sys
import unittest

from capstone import Cs, CS_ARCH_X86, CS_MODE_64
from offline_received_packet_xrefs import CLIENT, ROOT, SOURCE_SHA, ImmutableImage, validated_range
from offline_native_receive_fixture_check import Bits, physical_receive
import offline_native_code_cache as cache

MANIFEST_SHA = '0dc6c0bb1c4ac55f437f07fde93ac2575425d008892e1ff6e6cac9385e4568cf'
FOLDER = ROOT / 'work/native-code-cache/1790902501634810000'
EVIDENCE = ROOT / 'work/evidence'
SERVER = ROOT / 'outputs/df-local-server'
SOURCE_REPORTS = {
    'native-sequence-initialization-fragments.json': '6544bdec51eeb4d620260377766dd05d7c84f59747ac2cf1e3dc84dd12a82e5d',
    'native-sequence-initialization-lower.json': 'c19793a8f8e8de7f53e0cc07f95376c81104f9848eeb6d0b476b9c6d7c9c6231',
    'native-sequence-cookie-and-array-source.json': 'e36f4a5bc4e36346673fcb5d75f460c9cb354707982f27cad7ef061871a7a673',
    'native-sequence-cookie-parser-source.json': 'b9e9156a205f00063996f7018483f2059b5aa75f47383f68d8d5a4970b235636',
}


def sha(data):
    return hashlib.sha256(data).hexdigest()


def write_json(name, value):
    target = EVIDENCE / name
    target.write_bytes((json.dumps(value, ensure_ascii=False, indent=2) + '\n').encode('utf-8'))
    return {'path': target.relative_to(ROOT).as_posix(), 'sha256': sha(target.read_bytes())}


def source_review():
    cache.validate_manifest(FOLDER, MANIFEST_SHA)
    with CLIENT.open('rb') as stream:
        assert hashlib.file_digest(stream, 'sha256').hexdigest() == SOURCE_SHA
    rows, reports = {}, []
    with CLIENT.open('rb') as stream, mmap.mmap(stream.fileno(), 0, access=mmap.ACCESS_READ) as mapped:
        image = ImmutableImage(mapped)
        for name, expected in SOURCE_REPORTS.items():
            raw = (EVIDENCE / name).read_bytes()
            assert sha(raw) == expected, name
            report = json.loads(raw)
            assert report['client_sha256'] == SOURCE_SHA and report['manifest_sha256'] == MANIFEST_SHA
            reports.append({'path': 'work/evidence/' + name, 'sha256': expected})
            for row in report['roots']:
                if 'begin' not in row:
                    continue
                begin, end = int(row['begin'], 16), int(row['end_exclusive'], 16)
                metadata = image.unwind(image.containing(begin))
                assert metadata['metadata_sha256'] == row['metadata_sha256']
                file_bytes = (ROOT / row['code_relative_path']).read_bytes()
                magic, version, rva, count, base = struct.unpack('<4sIQQQ', file_bytes[:32])
                assert (magic, version, rva, count, base) == (b'DCDE', 1, begin, end-begin, image.image_base)
                code = file_bytes[32:]
                assert sha(file_bytes) == row['file_sha256'] and sha(code) == row['code_sha256']
                assert code == validated_range(FOLDER, begin, len(code), MANIFEST_SHA)
                assert sha((ROOT / row['asm_relative_path']).read_bytes()) == row['asm_sha256']
                rows[begin] = row
        table = image.read(0x1b1d63f0, 1536)
        assert sha(table) == '01cfc3b6010f959531a2e9fade712a98c777d26fd824c47e945741f293f14232'
        assert struct.unpack_from('<Q', table, 0x310)[0] == image.image_base + 0x12b93850
    ctor = validated_range(FOLDER, 0x12b87c00, 1895, MANIFEST_SHA)
    assert sha(ctor) == 'ffef21a5b2e2ecb14885df607d9e546ecdb71507dd2e3db0cdb8a44ccfcd0e10'
    joined = {}
    for name, begins in (('initializer', (0x12b93850, 0x12b9387b, 0x12b938c6, 0x12b93998, 0x12b9399d)),
                         ('fill_array', (0x10800d0, 0x10800f5, 0x108013b))):
        fragments = [rows[x] for x in begins]
        assert all(a['end_exclusive'] == b['begin'] for a, b in zip(fragments, fragments[1:]))
        first, end = begins[0], int(fragments[-1]['end_exclusive'], 16)
        joined[name] = {'begin': hex(first), 'end_exclusive': hex(end), 'bytes': end-first,
            'code_sha256': sha(validated_range(FOLDER, first, end-first, MANIFEST_SHA)),
            'fragments': [{key: x[key] for key in ('begin', 'end_exclusive', 'code_sha256',
                'metadata_sha256', 'code_relative_path', 'asm_relative_path')} for x in fragments]}
    # An exact called leaf prefix, with no pdata-derived full-function claim.
    notify = validated_range(FOLDER, 0x12b7a080, 128, MANIFEST_SHA)
    decoded = list(Cs(CS_ARCH_X86, CS_MODE_64).disasm(notify, 0x12b7a080))
    first_return = next(x for x in decoded if x.mnemonic == 'ret')
    used = first_return.address + first_return.size - 0x12b7a080
    notify = notify[:used]
    notify_path = EVIDENCE / 'native-cookie-sequence-notify-init.leaf.code'
    notify_path.write_bytes(notify)
    notify_asm = EVIDENCE / 'native-cookie-sequence-notify-init.leaf.asm.txt'
    notify_asm.write_bytes(('\n'.join(f'0x{x.address:x}: {x.mnemonic} {x.op_str}'
        for x in decoded if x.address <= first_return.address) + '\n').encode('utf-8'))
    result = {
        'kind': 'offline_native_cookie_to_sequence_initialization', 'client_sha256': SOURCE_SHA,
        'cache_manifest_sha256': MANIFEST_SHA, 'snapshot_is_atomic': False, 'source_reports': reports,
        'source_files_verified_against_cache_and_immutable_pdata': True,
        'native_sources': {**joined,
            'cookie_handler': {key: rows[0x12bb9b40][key] for key in ('begin', 'bytes', 'code_sha256', 'metadata_sha256', 'asm_relative_path')},
            'cookie_parser': {key: rows[0x12bc2a90][key] for key in ('begin', 'bytes', 'code_sha256', 'metadata_sha256', 'asm_relative_path')},
            'connection_ctor': {'rva': '0x12b87c00', 'bytes':1895, 'code_sha256': sha(ctor),
                'table_assignment': ['0x12b87c26 LEA 0x1b1d63f0', '0x12b87c2d MOV [this],table']},
            'notify_init_leaf_prefix': {'rva': '0x12b7a080', 'bytes_through_first_return': used,
                'code_sha256': sha(notify), 'path': notify_path.relative_to(ROOT).as_posix(),
                'asm_path': notify_asm.relative_to(ROOT).as_posix(), 'full_function_pdata_proven': False}},
        'vtable_binding': {'table_rva':'0x1b1d63f0', 'checked_bytes':1536, 'table_sha256':sha(table),
            'slot_byte_offset':'0x310', 'target_rva':'0x12b93850', 'live_dynamic_class_verified':False},
        'cookie_to_initializer': {
            'parser_call_rva':'0x12bb9cb3', 'cookie_destination':'[rbp+0xf]', 'cookie_bytes':20,
            'full_parser_bits_after_outer_flag':[194,354],
            'full_parser_fields':['1 bit', '1 bit', 'float32', '20 raw cookie bytes', 'extra20 bytes only at354 bits'],
            'gates':['Parser returns AL=1', '[handler+8]+8 typebyte is0', 'handler+10 statebyte <2',
                'parsed first bool=0', 'COMISS(timestamp,0) CF=1: negative or unordered NaN; ordered zero rejected', 'handler+9c is0',
                'handler+28 driver and driver+98 connection nonNULL'],
            'connection_chain':['[handler+0x28]', '[driver+0x98]'],
            'exact_call_rva':'0x12bb9ef3',
            'client_incoming_seed':'LE32(cookie[0:4]) &0x3fff, equivalent LE16(cookie[0:2]) &0x3fff',
            'client_outgoing_seed':'signextended LE16(cookie[2:4]) &0x3fff',
            'server_direction':'incoming=cseq=client_outgoing; outgoing=sseq=client_incoming',
            'not_account_or_QQ_type':True},
        'initializer_policy': {'arguments':['RCX connection','EDX incoming seed','R8D outgoing seed'],
            'gates':['connection+14cc == -1','selected thread-aware console-variable int >0'],
            'writes':{'14cc':'incoming-1','14d0':'outgoing','14d4':'outgoing-1','1bd0':'outgoing-1',
                '1524':'incoming&1023','1520':'outgoing&1023'},
            'incoming_reliable_array':'12b938fe ->10800d0 fills conn+1500 with (incoming&1023), count conn+1508',
            'outgoing_reliable_array':'12b93918 ->10800d0 fills conn+14f0 with (outgoing&1023), count conn+14f8',
            'notify_call':'12b9393f ->12b7a080, (incoming-1)&16383 and outgoing&16383',
            'first_server_received_Hello_reliable_wire_sequence':'((cseq&1023)+1)&1023',
            'first_server_sent_Challenge_reliable_wire_sequence':'((sseq&1023)+1)&1023',
            'retransmission':'Packet sequence may advance; retransmitted reliable bunch retains its original channel sequence',
            'signed_wire_reconstruction':'((wire-previous-512)&1023)-512+previous',
            'signed_reconstruction_source':'ReceivedPacket ordinary reliable path 12b9b9d0..12b9ba1a'},
        'qualification': {'cookie_cryptographic_verification_recovered_here':False,
            'runtime_initialization_gate_enabled_verified':False, 'native_control_message_accepted':False,
            'Welcome_Join_accepted':False,'playable_map':False,'game_launched':False,'process_accessed':False,
            'client_or_server_modified':False}
    }
    return write_json('native-cookie-sequence-initialization-semantics.json', result)


def codec_review():
    sys.path.insert(0, str(SERVER))
    from dfserver.legacy_ds_wire_codec import decode_observed_application, encode_observed_application
    from dfserver.legacy_ds_control_fields import decode_messages
    files = ['dfserver/legacy_ds_wire_codec.py', 'dfserver/legacy_ds_bit_archive.py',
             'tests/test_legacy_ds_wire_codec.py', 'tests/test_legacy_ds_bit_archive.py']
    source_hashes = {name: sha((SERVER/name).read_bytes()) for name in files}
    loader = unittest.TestLoader()
    suite = unittest.TestSuite([loader.discover(str(SERVER/'tests'), pattern=name)
        for name in ('test_legacy_ds_wire_codec.py','test_legacy_ds_bit_archive.py')])
    log = io.StringIO()
    tests = unittest.TextTestRunner(stream=log, verbosity=2).run(suite)
    assert tests.wasSuccessful()
    fixtures = ROOT / 'work/native-client-tests/1790831328076933800/game-server-packets'
    report_raw = (fixtures/'report.json').read_bytes()
    expected_report = '091c058c32f31f699a97509db079058499063423e450061b0af2eb59aba160b5'
    assert sha(report_raw) == expected_report
    records = {row['number']: row for row in json.loads(report_raw)['records']}
    rows = []
    for number in range(9,17):
        record = records[number]
        raw = (fixtures/record['private_packet_file']).read_bytes()
        assert sha(raw) == record['sha256'] and len(raw) == record['bytes'] and record['direction']=='received'
        packet = decode_observed_application(raw[8:], max_packet_bytes=1024, received_by_server=True)
        assert encode_observed_application(packet, max_packet_bytes=1024, received_by_server=True) == raw[8:]
        b = Bits(raw,65)
        header = b.read(32,'header')
        history = tuple(b.read(32,'history') for _ in range((header&15)+1))
        info, frame = b.read(1,'info'), b.read(8,'frame')
        assert (packet.sequence,packet.acknowledged_sequence,packet.history,packet.packet_info,packet.frame)==(
            header>>18,(header>>4)&16383,history,bool(info),frame)
        assert packet.consumed_bits == b.end-65
        bunches = []
        for bunch in packet.bunches:
            independent = physical_receive(raw,65,1024)
            assert independent['remaining_nontermination_bits']==0
            assert independent['payload_begin_udp_bit']==65+bunch.payload_start_bit
            assert independent['payload_hex']==bunch.payload.hex() and independent['payload_bit_count']==bunch.payload_bits
            assert tuple((m.message_id,m.fields) for m in decode_messages(bunch.payload))==((0,(1,1077088301,'')),)
            bunches.append({'header_start_core_bit':bunch.header_start_bit,
                'payload_start_core_bit':bunch.payload_start_bit,'payload_start_udp_bit':65+bunch.payload_start_bit,
                'payload_bits':bunch.payload_bits,'payload_sha256':sha(bunch.payload),
                'channel':bunch.channel_index,'channel_sequence':bunch.channel_sequence,
                'name_hardcoded_index':bunch.channel_name.hardcoded_index,
                'Hello_fields':{'message_id':0,'endian':1,'network_version_u32':1077088301,'string':''}})
        if not bunches:
            assert b.pos==b.end
        rows.append({'path':(fixtures/record['private_packet_file']).relative_to(ROOT).as_posix(),
            'bytes':len(raw),'sha256':sha(raw),'sequence':packet.sequence,'acknowledged_sequence':packet.acknowledged_sequence,
            'history':list(packet.history),'core_bits':packet.consumed_bits,'bunches':bunches,
            'remaining_nontermination_bits':0,'reencode_application_equal':True})
    assert source_hashes == {name:sha((SERVER/name).read_bytes()) for name in files}
    result = {'kind':'independent_offline_native_wire_codec_review','reviewed_source_hashes':source_hashes,
        'unit_tests':{'run':tests.testsRun,'passed':tests.wasSuccessful(), 'output':log.getvalue()},
        'fixtures_report_sha256':expected_report,'fixtures':rows,
        'packed_uint255_canonical_hex':'ff02',
        'conclusion':'Current ordinary bunch order matches recovered native code; all8 saved application datagrams fully parse and reencode byte-for-byte',
        'profile_qualifiers':{'routing_prefix_bytes':8,'routing_prefix_native_semantics_proven':False,
            'handler_bit_and_adjacent_double_terminators':'observed fixture envelope only',
            'max_packet_bytes_parameter':1024,'runtime_MaxPacket_setter_verified':False,
            'serialization_profile':'ordinary connection, no internal ACK, packed current channel/name, close reason >=7, no archive swap',
            'wire_network_version_from_Hello':1077088301,'connection_EngineNetVersion_enum_value_verified':False},
        'strict_local_policies':['history advertised9..16 rejected though native reads min(count,8)',
            'controlbit1 with open0/close0 rejected as noncanonical', 'string bound4096',
            'maximum32 bunches per packet','explicit MaxPacket1..1492',
            'canonical writer hardcoded name <=410; native reader accepts <605'],
        'qualification':{'native_control_message_accepted':False,'Welcome_Join_accepted':False,
            'playable_map':False,'game_launched':False,'process_accessed':False,'server_source_modified':False}}
    return write_json('native-wire-codec-cache-review.json',result)


if __name__ == '__main__':
    print(json.dumps({'sequence_evidence':source_review(),'wire_review':codec_review()}))
