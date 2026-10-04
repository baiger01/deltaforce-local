"""Seal bounded saved-code ACK evidence and integration review, never launch."""
import hashlib
import json
import mmap
import struct

from capstone import Cs, CS_ARCH_X86, CS_MODE_64
from capstone.x86_const import X86_OP_MEM, X86_REG_RIP
from offline_received_packet_xrefs import CLIENT, ROOT, SOURCE_SHA, ImmutableImage, validated_range
import offline_native_code_cache as cache

E = ROOT / 'work/evidence'
FOLDER = ROOT / 'work/native-code-cache/1790902501634810000'
PIN = '0dc6c0bb1c4ac55f437f07fde93ac2575425d008892e1ff6e6cac9385e4568cf'


def sha(data):
    return hashlib.sha256(data).hexdigest()


def main():
    cache.validate_manifest(FOLDER, PIN)
    with CLIENT.open('rb') as stream:
        assert hashlib.file_digest(stream, 'sha256').hexdigest() == SOURCE_SHA
    result = {'kind':'offline_native_reliable_control_delivery_review', 'client_sha256':SOURCE_SHA,
        'cache_manifest_sha256':PIN, 'snapshot_is_atomic':False, 'native_sources':[]}
    cs = Cs(CS_ARCH_X86,CS_MODE_64)
    cs.detail = True
    with CLIENT.open('rb') as stream, mmap.mmap(stream.fileno(),0,access=mmap.ACCESS_READ) as mapped:
        image = ImmutableImage(mapped)
        for root in (0x12b86f80,0x12b9a7f0,0x12b9a9f0):
            first = image.containing(root)
            assert first[0] == root
            cursor, fragments = root, []
            while len(fragments) < 16:
                row = image.containing(cursor)
                if row is None or row[0] != cursor:
                    break
                chain, seen = row, set()
                while image.unwind(chain)['unwind_flags'] & 4:
                    assert chain not in seen
                    seen.add(chain)
                    chain = tuple(int(x,16) for x in image.unwind(chain)['chained_entry'])
                    assert chain in image.entries
                if chain[0] != root:
                    break
                assert row[1]-root <= 4096
                fragments.append(image.unwind(row))
                cursor = row[1]
            code = validated_range(FOLDER,root,cursor-root,PIN)
            instructions = list(cs.disasm(code,root))
            assert instructions[-1].address + instructions[-1].size == cursor
            name = 'native-reliable-control-delivery.' + hex(root)[2:]
            code_path, asm_path = E/(name+'.dfcode'), E/(name+'.asm.txt')
            code_path.write_bytes(struct.pack('<4sIQQQ',b'DCDE',1,root,len(code),image.image_base)+code)
            asm_path.write_bytes(('\n'.join(f'0x{x.address:x}: {x.mnemonic} {x.op_str}' for x in instructions)+'\n').encode('utf-8'))
            literals=[]
            for ins in instructions:
                for op in ins.operands:
                    if op.type != X86_OP_MEM or op.mem.base != X86_REG_RIP:
                        continue
                    at=ins.address+ins.size+op.mem.disp
                    try:
                        text=image.read(at,256).decode('utf-16le',errors='ignore').split('\0')[0]
                    except ValueError:
                        continue
                    if 'Received ack' in text or 'Received nak' in text:
                        raw=(text+'\0').encode('utf-16le')
                        assert image.read(at,len(raw))==raw
                        literals.append({'xref_rva':hex(ins.address),'literal_rva':hex(at),
                            'text':text,'bytes':len(raw),'sha256':sha(raw)})
            result['native_sources'].append({'rva':hex(root),'end_exclusive':hex(cursor),'bytes':len(code),
                'code_sha256':sha(code),'file_sha256':sha(code_path.read_bytes()),
                'code_path':code_path.relative_to(ROOT).as_posix(),'asm_path':asm_path.relative_to(ROOT).as_posix(),
                'asm_sha256':sha(asm_path.read_bytes()),'fragments':fragments,'literals':literals})
        # Explicitly bounded leaf range; no pdata/full-function qualification.
        code=validated_range(FOLDER,0x12b911c0,113,PIN)
        leaf=E/'native-reliable-control-delivery.12b911c0.leaf.code'
        leaf.write_bytes(code)
        asm=E/'native-reliable-control-delivery.12b911c0.leaf.asm.txt'
        asm.write_bytes(('\n'.join(f'0x{x.address:x}: {x.mnemonic} {x.op_str}' for x in cs.disasm(code,0x12b911c0))+'\n').encode('utf-8'))
        result['native_sources'].append({'rva':'0x12b911c0','bytes':113,'code_sha256':sha(code),
            'path':leaf.relative_to(ROOT).as_posix(),'asm_path':asm.relative_to(ROOT).as_posix(),
            'full_function_pdata_proven':False})
    result['call_edges']=[{'caller':'ReceivedPacket','rva':'0x12b9b06e','target':'0x12b911c0'},
        {'caller':'ReceivedPacket','rva':'0x12b9b088','target':'0x12b86f80'}]
    result['call_edge_source']={'path':'work/evidence/native-receive-complete-fragments.12b9ac3e.asm.txt',
        'code_sha256':'5f95e25819ae5c1e95f20f5642a3bac9fd29d6ed4e796d9ba46cd69956e002d8'}
    result['native_ack_mapping']={
        'sequence_validation':'12b911c0..12b91230: incoming sequence advance in1..8191; ack cursor does not move backwards in14bit half range and must precede next unsent sequence',
        'ack_loop':'12b86f80..12b873f9: oldAck+1 to newAck inclusive, overflow beyond256 produces negative callbacks first',
        'history_word':'12b8722d..12b87230, distance>>5',
        'history_bit':'12b87229..12b8723c, mask1<<(distance&31), AND [header+wordIndex*4]',
        'distance_formula':'(newAck-sentPacketSequence)&0x3fff',
        'positive_call':'12b87394 ->12b9a7f0 (Received ack literal)',
        'negative_call':'12b8739b ->12b9a9f0',
        'new_ack_cursor_commit':'12b873d4 MOV [notify+254],newAck',
        'bit0':'Exactly acknowledged_sequence from this header, not any earlier packet',
        'outbox_delivery_rule':'For each recorded sentPacketSequence carrying that reliable bunch, distance<historyWords*32 and selected bit1 proves this copy ACKed; ack cursor advance or any unrelated bit alone does not prove it'}
    paths=['dfserver/legacy_ds_control_probe.py','dfserver/legacy_ds_packet_ack_probe.py',
        'dfserver/legacy_ds_wire_codec.py','dfserver/legacy_ds_handshake_probe.py','dfserver/game_server_probe.py']
    result['reviewed_files_at_audit_time']={x:sha((ROOT/'outputs/df-local-server'/x).read_bytes()) for x in paths}
    result['current_review_findings']=[
        {'path':paths[0],'lines':[79,83,127,129], 'finding':'ACK cursor updated without identifying corresponding history bits; cannot drive reliable outbox completion'},
        {'path':paths[0],'lines':[85,116,135], 'finding':'Every empty packet generates another empty reply; bidirectional ACK-only replies can loop and exhaust max_replies128'},
        {'path':paths[0],'lines':[95,120], 'finding':'Stable Challenge sequence/payload exists, but no independent pending outbox or retransmission timer'},
        {'path':paths[0],'lines':[88,92], 'finding':'Single-bunch restriction rejects legitimate multi-bunch packets; decode_messages already supports multiple supported messages per bunch'},
        {'path':paths[1],'lines':[94,101], 'finding':'ack_delta>=sent_delta is the correct upper rejection when out_sequence is next unsent; any history bit only supports some reply, not a particular Challenge'},
        {'path':paths[3],'lines':[77,89], 'finding':'Expiry occurs only on incoming handle; activity is coupled to returning a response and event prefix. Timer poll needs expiry even when idle and explicit consumed_valid_activity'}]
    result['minimal_state_machine']={
        'outbox_record':['fixed channelSequence','immutable encoded payload','message kind','first_sent_at','last_sent_at','attempts','sent_packet_sequences','delivered_by_header_ACK','superseded_by_valid_next_control'],
        'reliable_sequence':'Seed incoming/outgoing from cookie roles; first bunch seed+1 mod1024; each new bunch consumes one channel number, every retry keeps original number and payload',
        'stages':['echo_verified','Hello consumed ->Challenge pending','local admitted Login consumed ->Welcome pending',
            'Welcome ACK observed or later valid Netspeed/Join indicates semantic progress','Netspeed consumed','Join observed (not player spawned)'],
        'duplicate_Login':'Same accepted channelSequence+same bytes/hash is reACKed without another admission; reuses same Welcome. Same sequence with different payload rejected',
        'Challenge_supersession':'Valid admitted Login may end Challenge retries with separate superseded_by_valid_Login event; it is not a native packet header ACK',
        'Welcome_retries':'Use a caller-configured bounded retry interval; retry until exact recorded packet copy ACKed, explicitly superseded by valid next stage, session expiry or reply budget',
        'packet_transaction':'Decode complete packet and every bunch/message; use staged state in wire order; publish all state and positive delivery bit only after whole packet is consumed successfully',
        'multiple_messages':'Netspeed4 and Join9 can share one bunch; advance reliable sequence once per bunch, execute supported messages in order; no per-message channel increment',
        'ACK_only':'Consume history and inbound sequence without immediate empty reply merely because packet is empty; queued data/pending timer drives outbound traffic',
        'partial_minimum':'If unimplemented explicitly reject without ACK/partial state. For supported partial reassembly ACK only retained fragments; no Login/admission until final assembled payload parses fully',
        'partial_native_limits':'Existing3152byte NextBunch source requires matching reliability/contiguous reliable seq, byte alignment for nonfinal payload, no exports on final; no fragment field is a complete message',
        'unknown_payload':'Unsupported message/flags/field errors do not produce positive-delivery bit or authorization'}
    result['timer_integration']={
        'owner':'One UDP receive thread, same existing lock as handle, same monotonic now origin',
        'schedule':'On recv timeout and after received packet processing, call Handshake.poll(now); timeout already0.2s',
        'expiry_first':'Extract existing expiry to expire(now), invoke before handle and before poll; forget_peer deletes transport/control/outbox/queued fragments/binding',
        'no_self_activity':'Timer sends never modify verified_at or last_valid_activity_at; absolute session TTL never slides',
        'input_activity':'Explicit consumed_valid_activity independent of response presence and string event prefix; valid admitted controls/parsed ACK can count, invalid/unknown cannot',
        'generation_binding':'Peer tuple+verified handshake generation/cookie digest/local match admission. Expired/replaced generation drops queued output and releases binding to prevent cross-session delivery',
        'send_accounting':'Track packet sequence for each prepared attempt; distinguish send failure from actually submitted datagram; send failure is never ACK success',
        'retry_parameters':'Local policy explicit config, not recovered native retransmission timing'}
    result['qualification']={'native_Challenge_accepted':False,'native_Welcome_accepted':False,'Join_received':False,
        'Pawn_replicated':False,'playable_map':False,'process_accessed':False,'game_launched':False,
        'server_source_modified':False,'original_client_modified':False,
        'envelope':'8byte route/handler bit/double terminator remains observed fixture profile',
        'MaxPacket':'1024 caller profile, not universal native default'}
    out=E/'native-reliable-control-delivery-review.json'
    out.write_bytes((json.dumps(result,ensure_ascii=False,indent=2)+'\n').encode('utf-8'))
    json.loads(out.read_bytes())
    print(json.dumps({'path':out.relative_to(ROOT).as_posix(),'sha256':sha(out.read_bytes()),
        'native_sources':[(x['rva'],x.get('bytes'),x['code_sha256']) for x in result['native_sources']]}))


if __name__=='__main__':
    main()
