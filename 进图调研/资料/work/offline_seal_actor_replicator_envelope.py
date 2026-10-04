"""Seal only proven base replicator/field envelope edges from pinned disk cache."""
import hashlib
import json
import mmap
import struct
from capstone import Cs, CS_ARCH_X86, CS_MODE_64
from capstone.x86_const import X86_OP_MEM, X86_REG_RIP
from offline_received_packet_xrefs import CLIENT, ROOT, SOURCE_SHA, ImmutableImage, validated_range, sha
import offline_native_code_cache as cache

PIN = '0dc6c0bb1c4ac55f437f07fde93ac2575425d008892e1ff6e6cac9385e4568cf'
CACHE = ROOT / 'work/native-code-cache/1790902501634810000'
NAMES = ('native-actor-replicator-base-connection-create.json',
         'native-actor-content-parse-initial-roots.json',
         'native-actor-replicator-received-body-initial.json',
         'native-actor-replicator-field-envelope-initial.json',
         'native-actor-replicator-replayout-complete.json',
         'native-actor-replicator-replayout-handles-initial.json')


def main():
    folder, manifest, pin = cache.validate_manifest(CACHE, PIN)
    if not manifest['complete']:
        raise ValueError('Incomplete cache')
    cs = Cs(CS_ARCH_X86, CS_MODE_64)
    cs.detail = True
    sources, records, instructions, slots, logs = [], [], {}, [], []
    with CLIENT.open('rb') as stream:
        if hashlib.file_digest(stream, 'sha256').hexdigest() != SOURCE_SHA:
            raise ValueError('Wrong Shipping image')
        with mmap.mmap(stream.fileno(), 0, access=mmap.ACCESS_READ) as mapped:
            image = ImmutableImage(mapped)
            seen = set()
            for name in NAMES:
                path = ROOT / 'work/evidence' / name
                raw = path.read_bytes()
                src = json.loads(raw)
                if src['client_sha256'] != SOURCE_SHA or src['manifest_sha256'] != PIN:
                    raise ValueError('Source identity mismatch')
                sources.append({'path': path.relative_to(ROOT).as_posix(), 'sha256': sha(raw)})
                for row in src['roots']:
                    begin = int(row['begin'], 16)
                    if name == 'native-actor-content-parse-initial-roots.json' and begin != 0x12853830:
                        continue
                    if begin in seen:
                        continue
                    seen.add(begin)
                    raw_code = (ROOT / row['code_relative_path']).read_bytes()
                    if struct.unpack('<4sIQQQ', raw_code[:32]) != (
                            b'DCDE', 1, begin, row['bytes'], image.image_base):
                        raise ValueError('DCDE header mismatch')
                    code = raw_code[32:]
                    if (len(code) != row['bytes'] or sha(code) != row['code_sha256'] or
                            sha(raw_code) != row['file_sha256'] or
                            validated_range(folder, begin, len(code), PIN) != code or
                            sha((ROOT / row['asm_relative_path']).read_bytes()) != row['asm_sha256']):
                        raise ValueError('Source code/file/cache/asm SHA mismatch')
                    if any(row[k] != v for k, v in image.unwind(image.containing(begin)).items()):
                        raise ValueError('Source pdata/unwind mismatch')
                    decoded = list(cs.disasm(code, begin))
                    if sum(i.size for i in decoded) != len(code):
                        raise ValueError('Incomplete saved root decode')
                    instructions.update((i.address, i) for i in decoded)
                    records.append(dict(row, validation='header/file/code/cache/asm/pdata/full-decode'))
            # This straight-line ctor has no .pdata. Exact leaf stops at its first
            # RET, has no branch/call, and is established by a real source E8.
            leaf = validated_range(folder, 0x12876b00, 175, PIN)
            decoded = list(cs.disasm(leaf, 0x12876b00))
            if (image.containing(0x12876b00) is not None or sum(i.size for i in decoded) != 175 or
                    decoded[-1].mnemonic != 'ret' or any(
                    i.mnemonic.startswith('j') or i.mnemonic in ('call', 'ret') for i in decoded[:-1])):
                raise ValueError('Constructor no longer exact straight-line leaf')
            instructions.update((i.address, i) for i in decoded)
            leaf_path = ROOT / 'work/evidence/native-actor-replicator-constructor-leaf-12876b00.dfcode'
            leaf_blob = struct.pack('<4sIQQQ', b'DCDE', 1, 0x12876b00, 175, image.image_base)+leaf
            leaf_path.write_bytes(leaf_blob)
            leaf_proof = {'rva': '0x12876b00', 'bytes':175, 'code_sha256':sha(leaf),
                'file_sha256':sha(leaf_blob), 'relative_path':leaf_path.relative_to(ROOT).as_posix(),
                'source_call_rva':'0x12b8d6ef', 'no_containing_pdata':True,
                'boundary':'straight-line leaf ending explicit RET12876bae;no guessed unwind function'}
            for table, slot, target in ((0x1b1d63f0,0x328,0x12b8d6c0),
                                       (0x1b14f370,0x28,0x12891f60),
                                       (0x1b148470,0x70,0xe50ad0),
                                       (0x1b148470,0x78,0x10b4c190)):
                raw = image.read(table+slot,8)
                if struct.unpack('<Q',raw)[0]-image.image_base != target:
                    raise ValueError('Static slot mismatch')
                slots.append({'table_rva':hex(table),'slot':hex(slot),'target_rva':hex(target),
                              'bytes_hex':raw.hex(),'sha256':sha(raw)})
            for ins in instructions.values():
                if ins.mnemonic != 'lea':
                    continue
                for op in ins.operands:
                    if op.type != X86_OP_MEM or op.mem.base != X86_REG_RIP:
                        continue
                    target = ins.address+ins.size+op.mem.disp
                    try:
                        raw = image.read(target,768)
                    except ValueError:
                        continue
                    end = next((j for j in range(0,768,2) if raw[j:j+2] == b'\0\0'),None)
                    if end is None:
                        continue
                    try:
                        text = raw[:end].decode('utf-16-le')
                    except UnicodeDecodeError:
                        continue
                    if not any(w in text for w in ('ReceivedBunch','ReadFieldHeader','ReceiveProperties')):
                        continue
                    raw = raw[:end+2]
                    logs.append({'instruction_rva':hex(ins.address),'bytes_hex':ins.bytes.hex(),
                        'literal_rva':hex(target),'bytes':len(raw),'sha256':sha(raw),'utf16':text})

    expected = {
        0x12b8d6ef:('call','0x12876b00'),
        0x12876b04:('lea','rax, [rip + 0x88d8865]'),
        0x12876b0b:('mov','qword ptr [rcx], rax'),
        0x128921a0:('call','0x12db90d0'),
        0x128922aa:('call','0x12864bf0'),
        0x12892883:('call','0x12864bf0'),
        0x12864c3a:('je','0x128652a2'),
        0x12864fff:('call','qword ptr [r9 + 0x70]'),
        0x1286514c:('call','qword ptr [rax + 0x78]'),
        0x128653ca:('call','0x10b4cee0'),
        0x12db92b8:('call','qword ptr [rax + 0x78]'),
        0x12db9358:('call','0x12dbacf0'),
        0x12db9368:('je','0x12db93b7'),
        0x12dbb16b:('call','qword ptr [rax + 0x78]'),
    }
    anchors = []
    for rva, text in expected.items():
        ins = instructions[rva]
        if (ins.mnemonic,ins.op_str) != text:
            raise ValueError('Source edge changed at '+hex(rva))
        anchors.append({'rva':hex(rva),'bytes_hex':ins.bytes.hex(),'asm':ins.mnemonic+' '+ins.op_str})
    result = {
        'kind':'pinned_base_object_replicator_and_first_body_envelope',
        'client_sha256':SOURCE_SHA,'cache_manifest_sha256':pin,'sources':sources,
        'verified_fragments':records,'constructor_leaf':leaf_proof,'static_slots':slots,
        'exact_anchors':anchors,'exact_immutable_log_refs':logs,
        'base_allocation_chain':[
            'ActorChannel helper12853830 new-replicator branch calls connection.v328 at12853b52',
            'Base connection static1b1d63f0.v328=12b8d6c0;164byte complete root',
            '12b8d6da allocates0xf0;12b8d6ef calls12876b00 ctor;returns object through shared pair',
            '12876b04 LEA static1b14f370;12876b0b installs table',
            '1b14f370.v28=12891f60;3019byte complete root forReceivedBunch'],
        'first_body_flow':{
            'has_rep_layout_true':'128920bf nonzero gate→128921a0 ReceiveProperties12db90d0 before field loop;server receive branch rejects this flag',
            'has_rep_layout_false':'128920bf zero→12892227 skips property region',
            'field_first':'128922aa calls12864bf0 withsame bodyreader r14',
            'field_next':'12892883 calls12864bf0 again;1289289b returnsloop128922c4',
            'field_payload_dispatch':'field metadata distinguishes properties/custom delta/RPC;payload implementations remain class-dependent'},
        'normal_field_envelope':{
            'profile':'connection+0xb4 bit0=false;internalAck/exportgroup alternate excluded',
            'first':'bounded_uint RepIndex at current bit cursor via archive.v70;12864fe4..12864fff',
            'exclusive_maximum':'ClassNetCache dword[+0]+dword[+0x28]+1;runtime schema dependent,not a wire-supplied maximum',
            'lookup':'128650f7..12865134 traverses parent cache;index offset uses32byte field entries;unresolved cache still slices payload but client rejects/skips field elsewhere',
            'second':'packed_uint32 NumPayloadBits viaarchive.v78 at1286514c',
            'third':'exact NumPayloadBits slice via10b4cee0 at128653ca;no byte alignment',
            'end':'12864c2c/33/3a compares body cursor tobitcount andreturnsfalse;field loop ends atbody EOF,no dedicated RepIndex0 terminator',
            'zero_payload':'framing permits0 NumPayloadBits,but doesnot establish validproperty/RPC',
            'bounds':'native maxpayloadcvar*8 check128652bc..ce;normalconnection overbudget setsarchiveerror;local cap mustremainexplicit'},
        'normal_rep_layout_envelope':{
            'profile':'12db90d0 normal noninternalAck branch;full contiguous sixfragments747bytes through12db93bb',
            'first':'oneLSB bit at12db9163..12db91b1;when set anadditional rawu32 follows each packedhandle',
            'second':'first packeduint32 handle viaarchive.v78 at12db92b8;effective storedhandle islowu16 at12db9348/54',
            'third_if_option_true':'rawu32 at12db9303..12db9343 withnative endian alternative;no byte alignment',
            'body':'12db9358→ReceiveProperties_r12dbacf0;property-specific scalar/array operations dependonCmd tables',
            'next_handle':'12dbb16b v78;optional rawu32 at12dbb1a1..1e6;storeslowu16 at12dbb1f6',
            'terminator':'returned effectiveu16 handle mustbe0:12db9365/68;otherwiseexact Invalid property terminator handle log',
            'qualifier':'do not name optionalu32 CRC or reproduce checksum policywithout its exactsemantic proof;handles/commands are not yet recovered'},
        'can_continue_implementation':[
            'Purenormal-field framing canaccept caller-provided exactclass-cache exclusive maximum,RepIndex andopaque body.',
            'Keep hasRepLayout false foropaque field sequences until exactclass RepLayout commands/handles areavailable.',
            'Framing is not Pawn possession or OnRep_Pawn;need truePC/Pawn class metadata andproperty/RPC handles first.'],
        'unknowns':[
            'ActualgameConnection/replicator derived overrides were not observed;proof isbase static construction path.',
            'ExactshippingPC/Pawn ClassNetCache indexbase/count,field mapping andRepLayout Cmd/property handles.',
            'Propertyserializer/RPC schema,dynamicarray boundaries/objectrefs andready callback payloads.',
            'Actorworld resolution/nativeacceptance ofexplicitproducer bytes.'],
        'policy':{'process_accessed':False,'game_launched':False,'live_object_read':False,
                  'existing_codecs_or_connections_modified':False,'native_acceptance':False}}
    out = ROOT/'work/evidence/native-actor-replicator-first-body-envelope.json'
    out.write_text(json.dumps(result,ensure_ascii=False,indent=2)+'\n',encoding='utf-8')
    print(json.dumps({'evidence':out.relative_to(ROOT).as_posix(),'sha256':sha(out.read_bytes()),
                      'verified_fragments':len(records),'exact_anchors':len(anchors),'exact_logs':len(logs)}))


if __name__ == '__main__':
    main()
