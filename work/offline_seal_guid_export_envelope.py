"""Seal the bounded GUID export envelope evidence; no runtime access."""
import hashlib
import json
import struct
from offline_received_packet_xrefs import ROOT, SOURCE_SHA, sha

PIN = '0dc6c0bb1c4ac55f437f07fde93ac2575425d008892e1ff6e6cac9385e4568cf'
REPORTS = (
    'work/evidence/native-guid-export-receive-complete.json',
    'work/evidence/native-guid-export-follow-complete.json',
    'work/evidence/native-post-join-guid-transform-full-roots.json',
    'work/evidence/native-post-join-guid-transform-roots.json',
    'work/evidence/native-package-map-client-constructor.json',
    'work/evidence/native-guid-export-static-anchors.json',
    'work/evidence/native-guid-export-ack-complete.json',
    'work/evidence/native-guid-export-output-complete.json',
    'work/evidence/native-net-field-export-row.json',
)
RELATED = (
    'work/evidence/native-reliable-control-delivery-review.json',
    'work/evidence/native-wire-writer-summary.json',
    'work/evidence/native-string-field-109ea340-semantics.json',
    'work/evidence/native-post-join-actor-prerequisites.json',
    'work/native-client-tests/1790847786646593300/ds-native-control-code/UChannel.ReceivedRawBunch.implementation.asm.txt',
    'work/evidence/native-reliable-control-delivery.12b9a7f0.asm.txt',
    'work/evidence/native-reliable-control-delivery.12b9a9f0.asm.txt',
    'work/evidence/native-writer-cache-1790902501634810000/writer_log_root_12ba0af0.cfg.asm.txt',
)


def main():
    sources, native_roots = [], []
    for relative in REPORTS:
        raw = (ROOT / relative).read_bytes()
        report = json.loads(raw)
        if report.get('client_sha256') != SOURCE_SHA:
            raise ValueError(f'Wrong immutable identity: {relative}')
        if report.get('manifest_sha256', report.get('cache_manifest_sha256')) != PIN:
            raise ValueError(f'Wrong cached identity: {relative}')
        sources.append({'relative_path': relative, 'sha256': sha(raw)})
        for item in report.get('roots', []):
            if 'code_relative_path' not in item:
                continue
            encoded = (ROOT / item['code_relative_path']).read_bytes()
            magic, version, rva, length, base = struct.unpack('<4sIQQQ', encoded[:32])
            if (magic, version, rva, length, base) != (b'DCDE', 1, int(item['begin'], 16), item['bytes'], 0x140000000):
                raise ValueError(f'Invalid saved code header: {item["code_relative_path"]}')
            if len(encoded) != length + 32 or sha(encoded) != item['file_sha256'] or sha(encoded[32:]) != item['code_sha256']:
                raise ValueError('Saved code hash mismatch')
            if sha((ROOT / item['asm_relative_path']).read_bytes()) != item['asm_sha256']:
                raise ValueError('Saved disassembly hash mismatch')
            native_roots.append({'report': relative, **item})
    for relative in RELATED:
        sources.append({'relative_path': relative, 'sha256': sha((ROOT / relative).read_bytes())})
    result = {
        'kind': 'native_guid_export_envelope_and_delivery_evidence',
        'client_sha256': SOURCE_SHA, 'cache_manifest_sha256': PIN,
        'policy': {'saved_code_and_immutable_PE_only': True, 'process_accessed': False,
                   'game_launched': False, 'server_modified': False, 'native_acceptance': False},
        'sources': sources, 'validated_native_fragments': native_roots,
        'receive_entry': {
            'root': '12bc5540..12bc57be', 'complete_bytes': 638,
            'caller': '12868727 tests FInBunch+e5 bit0; 1286873e excludes conn+b4 bit0; 12868780 calls12bc5540',
            'reader_binding': 'FInBunch ctor1283e9b0/1283e9b7 writes vptr1b148470: v60=e50750 byte serializer, v78=10b4c190 packed u32',
            'same_bunch_suffix': '12868785 checks error; success12868789 JE128687ce. In-order reliable12868808/1286880e reaches12868922 call12867ac0 with original FInBunch and already-advanced+a8 cursor. No unconditional return after exports.',
            'qualification': 'Combined export prefix plus Actor-open suffix is supported by saved native control flow; exclude partial/out-of-order cases from the first integration.'
        },
        'false_branch_layout': [
            {'field': 'discriminator', 'width_bits': 1, 'value': False,
             'source': '12bc55c5..12bc55f7 reads one LSB bit; false enters12bc5571'},
            {'field': 'top_level_count', 'width_bits': 32, 'representation': 'raw signed int32 little endian, unaligned',
             'source': '12bc55b6 or12bc5624/12bc562a archive.v60(4); signed CMPcount,0x800/JLE at12bc563b/12bc5641',
             'native_count_rule': 'count>2048 sets error; count<=0 skips loop, including negative values',
             'local_restriction': '0..2048 only'},
            {'field': 'entries', 'repeat': 'top_level_count',
             'source': '12bc5703 initializes stackDepth0;12bc5713 calls12bbb3c0;12bc5718 aborts loop on archive error',
             'export_mode': '12bc558d/12bc5595 save and set GUIDCache+152=1;12bc576d restores prior value',
             'entry_layout': 'packed u32 GUID; if GUID0 return immediately without flags. Otherwise u8 flags. If flags bit0, recursively read outer reference, then FString path, then raw u32 checksum iff flags bit2. Flags0 has no path; excluded in restricted codec.'}
        ],
        'guid_node_anchors': {
            'packed_GUID': '12bbb459 archive.v78; GUID0 test12bbb469/12bbb46b returnsNULL at12bbc4f8 before flags',
            'flags_condition': '12bbb57b..12bbb598 flags byte exists if GUID1 or GUIDCache+152 true',
            'u8_flags': '12bbb5ab fast byte read or12bbb5c0 archive.v60(1)',
            'outer': '12bbb635 bit0 test;12bbb642 INCdepth;12bbb64f stackDepth;12bbb65a recursiveGUIDreader',
            'path': '12bbb672 call109ea340, after outer, with no alignment operation',
            'checksum': '12bbb677 testsflags4;12bbb692 rawu32 or12bbb6b3 v60(4)/12bbb6b8 endian serializer, after FString, no alignment',
            'depth': '12bbb3ee CMPdepth,16/12bbb3fb JLE;>16 errors before reading even nullGUID. Top depth0. A terminal null also counts as a call, so at most16 nonnull nodes depth0..15 then null depth16.',
            'checksum_validation_qualification': 'Nonzero received checksum checked under native policy at12bbba3e..12bbbae6; zero skips this comparison. Raw checksum decoding is not proof of object checksum validity.',
            'registration': '12bbbf0b callsGUIDCache registration12bc5a30;12bbbf24 resolves12bb73a0. Existing paths/outer mismatches and unresolved objects remain native validation gates.',
            'atomicity': 'Native begins export GUID bookkeeping at12bbb5da..12bbb628 before later path validation. Local atomic rollback is a stricter caller policy, not a claim that native cache updates are transactional.'
        },
        'restricted_codec': {
            'can_implement_now': True, 'network_integration_claimed': False,
            'accepted': 'false discriminator;0..2048 entries; caller-provided static odd GUID>=3; flags1 or5; explicit recursive outer nodes or null0; existing native FString codec; caller checksum u32 if flags5',
            'rejected': 'GUID1 special assignment; dynamic evenGUID; unproved flag bit1; flags0; negative counts; depth>16; true branch; invented GUID/path/CDO/checksum; unresolved dictionary conflicts',
            'suffix_boundary': 'Decoder returns exact bitcursor after counted export entries, not forced EOF, so remaining Actor-open suffix can be separately decoded.',
            'physical_success_only': 'No native UObject lookup, class inheritance, CDO existence, checksum match or spawn success is established by Python codec roundtrips.'
        },
        'true_branch': {
            'root': '12bc4e60..12bc553b', 'complete_bytes': 1755,
            'normal_connection_gate': '12bc4e75..12bc4e89 tests PackageMap+130 conn+b4 bit0; false setsarchiveerror12bc4ebe and returns. Thus current normal noninternalAck control path must reject discriminatortrue.',
            'conditional_layout': 'When internalAck gate is true: raw signed32 group-rowcount; each row packed32 groupID,1bit newGroupMetadata; if set FString groupPath, raw32 groupFieldCount; then12bab350 fieldrow.',
            'fieldrow': '12bab350..12bab4a6: rawu8 enabled; loading enabled is exactlybyte1; if enabled packed32 handle,rawu32 checksum, then name serialized accordingarchive+54: <9 v50 plus FString,<10 v50,>=10 helper10e05bc0.',
            'excluded_gap': 'No generic true-branch encoder implemented: existing group dictionary, native name serializer/versions and internalAck/replay lifecycle are not needed for restricted normal GUID exports.'
        },
        'writer_crosscheck': {
            'export_builder': '12bb3210..12bb39a8 createsFOutBunch,sets+f1 bit1 at12bb3320;12bb332e callsone-bit writer10b4ea60 withEDX0;rawcount reserve at12bb334d/3371;GUIDCache+152=1 at12bb33c1;12bb3433 GUIDwriter12bbc520;successful top-entry count increment12bb3816.',
            'count_finalizer': '12bb3ce0..12bb3f5c savescurrentbits,rewindsoutbunch+a0=0 at12bb3d72,writesfalsebit12bb3d79 thenraw32count12bb3db6,restoresendcursor12bb3dc0.',
            'recursive_writer': '12bbc5de packedGUID;12bbc5e4/5e6 GUID0return;flags12bbc720;recursiveouter12bbc7ab;FString12bbc8d9;optionalu32checksum12bbc970; mirrorsreadorder.'
        },
        'delivery_mapping': {
            'class_binding': 'Getter133916c0 generatedcallback133901e0 jumps12baa5e0;ctor12baa5f9 LEAvtable15a68ec0 and12baa684 writesobjectvptr. That tablev2a0=12bc15c0,v298=12bc57c0,v290=12bc58f0.',
            'commit': 'SendRawBunch12ba0fc0 testexports+f1 bit1→12ba0fd5 PackageMap.v2a0(PacketId=bunch+ec,bunch).12bc15c0 looks upbunch+f8 GUIDs inmap+2e8;12bc17e6 testsentry+4=-2;normalconn12bc1808 setsPacketId and12bc181d appendsGUID topendingmap+1e8. internalAck uses-1 immediately.',
            'ack': 'Native positivepacketcallback12b9a86b callsmap.v298=12bc57c0.12bc5852..12bc5862 entries with0<=storedPacketId<=ackedPacketId become-1 and leavepending.',
            'nak': 'Native negativecallback12b9aa72 callsmap.v290=12bc58f0.12bc5982 exactstoredPacketId==nakPacketId becomes-2 at12bc598b and leavespending,allowingre-export.',
            'state_sentinels': {'unacknowledged_or_retry': -2, 'delivered': -1, 'pending': 'nonnegative packetID'},
            'local_integration_rule': 'Reuse proven exact sent-packet history ACK rules; track each actually-sent copy carryingexports,keepfixed reliablechannelSequence/payload onretry,newpacketSequence percopy. A selected ACKbit forsuchcopy supportsdelivery; arbitraryhistory/cursor advance alone doesnot. PreserveGUID dictionary identity acrossretries.',
            'no_special_ACK_payload': 'These savedfunctions use packetdelivery callbacks; no separate GUIDregistration-success wiremessage is evidenced.',
            'ack_not_resolution': 'TransportACK provescopy delivery,notthatnativepathresolvedtoexpectedclass/CDO. Objectresolution and subsequent Actor-open remain separate acceptance gates.'
        },
        'remaining_exact_gaps': [
            'Build-specific class/CDO fullpath+outer dictionaries must come from verifiedlocalassets/registration; noneinventedhere.',
            'Nonzero checksumalgorithm andexpectedobjectvalues notderivedhere; flags5 callerdata staysunverifieduntilnativevalidation.',
            'Derived PlayerController/Pawn creation,replicationlayouts,possess/projectloadinggates stillrequired forplayablemap; GUIDcodec itselfdoesnotimplementthem.'
        ],
        'existing_host_route_only': 'Prioroffline-ds-implementation-research.json records no verified build-compatible native server/listen host; WITH_SERVER_CODE remainsunknown. This task didnot reopen host/source investigation.'
    }
    out = ROOT / 'work/evidence/native-guid-export-envelope.json'
    out.write_text(json.dumps(result, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')
    json.loads(out.read_text(encoding='utf-8'))
    print(json.dumps({'relative_path': out.relative_to(ROOT).as_posix(), 'sha256': sha(out.read_bytes()),
                      'validated_saved_fragments': len(native_roots), 'source_files': len(sources)}))


if __name__ == '__main__':
    main()
