"""Seal offline world interaction and terminal-result receiver evidence."""
import argparse
import hashlib
import json
import mmap
from pathlib import Path
import struct
import sys

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / 'outputs/df-local-server'))
import portable_match_end_values as match_end
from offline_received_packet_xrefs import ImmutableImage

BASE = 'work/evidence/map-system-audit-20261018/'
CLIENT = Path('F:/WeGameApps/rail_apps/DeltaForce(2001918)/DeltaForce/Binaries/Win64/DeltaForceClient-Win64-Shipping.exe')
EXACT = {
    'native-economy-playerexit-native-constructor-v1.json':
        'e6df9f86ca4f0525c841165ebed7d17557671eed52954f3e5fa7e18cb62bd3ca',
    'native-economy-playerexit-vtable-tail-v1.json':
        '3cd8e32aef65f6a3c93f784d4c729066db746550250e21b0e0ad6e93c59d9670',
    'native-economy-playerexit-cache-and-sequence-implementations-v1.json':
        'a416a58ef36a59321376b7751d17e3501fe03c182031e35c97e0a430971b0b82',
    'native-economy-playerexit-native-sequence-end-paths-v1.json':
        '637cd302fa7c67124e41482b26395849548a20acb2af31fc4ab81c78318c3dfb',
    'native-economy-playerexit-and-matchend-declarations-v1.json':
        '8b6770bdb85fb23acc16f8bce434adffe4976fd03d4af30d63258ee67577750e',
    'native-economy-playerexit-cutscene-param-fields-v1.json':
        '48aed11ef2a866e1a5297901583a2d1f431806bdbb0214c541103058f359d9d4',
    'native-economy-tag-serialize-and-end-delegate-v1.json':
        '5afd0921a60808438512a7357eab70c77eca704c11d98ffe9a1a90f564e7405f',
    'native-economy-gameplaytag-ops-vtable-probe-v1.json':
        '8ac2b717eef9a7ed00655aae54f6459f9a84940692761f05f259b4f7241fd781',
    'native-economy-world-rpc-struct-ops-records-v2.json':
        '6a01a8fa7b6e41dabbf90b8413088fd67c7f497e844a33563d40efe7c5cdf9c4',
}


def derive():
    pins = match_end.source_pins()
    sources = {}
    for name, expected in EXACT.items():
        raw = (ROOT / BASE / name).read_bytes()
        if hashlib.sha256(raw).hexdigest() != expected:
            raise ValueError('Changed world receiver source: ' + name)
        sources[name] = json.loads(raw)
        pins[BASE + name] = expected
    implementations = sources['native-economy-playerexit-cache-and-sequence-implementations-v1.json']
    sequence = next(row for row in implementations['functions'] if row['requested_rva'] == '0xb258aa0')
    instructions = {(row['rva'], row['mnemonic'], row['operands']) for row in sequence['instructions']}
    if not {('0xb258b83', 'call', '0x10ed0240'),
            ('0xb258b8a', 'je', '0xb258d2b'),
            ('0xb258d2b', 'xor', 'edx, edx'),
            ('0xb258d30', 'call', '0xb20de80'),
            ('0xb25a239', 'call', '0xb20de80')} <= instructions:
        raise ValueError('The native sequence failure completion path changed')
    end_doc = sources['native-economy-playerexit-native-sequence-end-paths-v1.json']
    end = next(row for row in end_doc['functions'] if row['requested_rva'] == '0xb20de80')
    end_anchors = {(row['rva'], row['mnemonic'], row['operands']) for row in end['instructions']}
    if not {('0xb20df74', 'lea', 'rcx, [rbx + 0x1360]'),
            ('0xb20df7d', 'call', '0xd96400'),
            ('0xb20e027', 'call', '0x10ed0240')} <= end_anchors:
        raise ValueError('The native completion broadcast ordering changed')
    with CLIENT.open('rb') as stream:
        if hashlib.file_digest(stream, 'sha256').hexdigest() != match_end.CLIENT_SHA256:
            raise ValueError('The installed immutable client changed')
        with mmap.mmap(stream.fileno(), 0, access=mmap.ACCESS_READ) as data:
            image = ImmutableImage(data)
            rva = 0x186ec3b8
            record = image.read(rva, 48)
            values = struct.unpack('<6Q', record)
            name = image.read(values[0] - image.image_base, 96).split(b'\0', 1)[0].decode('ascii')
            if name != 'ClientNotifyLocalPlayerExitSequenceEnd' or values[3] & 0xffffffff != 0x1b or values[4] >> 32 != 0x1360:
                raise ValueError('The actual sequence completion delegate declaration changed')
            completion = dict(property_record_rva=hex(rva), property_record_sha256=hashlib.sha256(record).hexdigest(),
                name=name, native_member_offset=0x1360, native_gen_flags='0x1b',
                property_flags=hex(values[2]), declared_in='/Script/DFMGameplay.DFMGameplayDelegates')
    config_relative = BASE + 'standalone-config-assets/pak-0-0-pakchunk1-WindowsClient/DeltaForce/Config/DefaultGameplayTags.ini'
    config = (ROOT / config_relative).read_bytes()
    if b'FastReplication=False' not in config:
        raise ValueError('The installed GameplayTag configuration changed')
    pins[config_relative] = hashlib.sha256(config).hexdigest()
    for relative in ('work/qualify_economy_world_wire_closure_v2.py',
            'work/portable_loot_box_codec.py', 'work/portable_finite_loot.py',
            'work/portable_loot_box_request.py'):
        pins[relative] = hashlib.sha256((ROOT / relative).read_bytes()).hexdigest()
    bodies = []
    for name in match_end.REASONS:
        block = match_end.build_match_over_content(match_end.CommittedTerminalResult(9, 17, 'a' * 64, name),
            admitted_room_id=9, admitted_player_id=17)
        bodies.append(dict(reason=name, native_value=match_end.REASONS[name],
            value_bits=block.payload_bit_count, value_bytes=len(block.payload),
            sha256=hashlib.sha256(block.payload).hexdigest(), diagnostic_identity_only=True))
    return dict(kind='economy_world_wire_closure_v2', client_sha256=match_end.CLIENT_SHA256,
        cache_manifest_sha256=match_end.MANIFEST_SHA256,
        process_access=False, client_launched=False, production_modified=False,
        native_packet_acceptance_verified=False, source_pins=pins,
        latest_capture=dict(path='work/native-client-tests/1792343957590810500',
            missing_world_report_is_absence_proof=False),
        match_end=dict(portable_receiver=match_end.schema_binding(), encoded_reason_cases=bodies,
            preconditions=['Persist actual authoritative terminal state and final inventory first',
                'Require the exact admitted room/player and current owning PlayerState channel',
                'Require current PS.Owner to resolve to the local PlayerController',
                'Bind retransmission to terminal-result identity; no duplicate settlement/rewards',
                'Record actual reliable ACK and subsequent native OnRep/Lua delegate before acceptance'],
            normal_notification='OnRep_PlayerMatchInfo b576e80 broadcasts DFMGameplayDelegates+b0 after owning-PC equality'),
        cutscene=dict(component_class='/Script/DFMGameplay.PlayerExitComponent', native_bytes=0x2c0,
            constructor_rva='0xb1f64a0', vtable_rva='0x17a8fcd0',
            cache_rpc=dict(name='CacheCutSceneParams', function_flags='0x1020cc0',
                function_params_rva='0x1d252940', parameter_struct='ExitCutSceneParams', parameter_native_bytes=88,
                exec_rva='0xd014c00', implementation_slot='0x418', implementation_rva='0xb203320',
                local_state_offset='0x228', receiver_forces_cache_flag_true_at='0x230',
                current_class_netcache_index_or_function_replayout_recovered=False),
            play_is_local=True, play_rva='0xb258090', sequence_rva='0xb258aa0', sequence_slot='0x478',
            completion_delegate=completion,
            failure_completion=dict(entry_rva='0xb258d2b', dispatch_rva='0xb20de80',
                broadcasts_before_playerexit_weak_reference_checks=True,
                reasons=['Unresolved PlayerExit weak reference', 'Unavailable CutSceneActor or CharacterOwner',
                    'Native low-memory sequence suppression'],
                does_not_imply_successful_extraction=True),
            media_invalid_branch_is_separate=True,
            remaining=['Actual current PlayerExitComponent existing ClassNetCache and function RepLayout',
                'Actual exit actor cutscene configuration if a visible successful extraction sequence is required',
                'Native execution observation of sequence completion and business GameSettlement transition']),
        gameplay_tag=dict(native_struct='FGameplayTag', native_bytes=8, tagname_offset=0,
            serializer_rva='0x12427940', manager_nonfast_mode_byte_offset='0x181',
            nonfast_branch_rva='0x12427e69', normal_branch_serializer='FArchive virtual+0x50 FName',
            installed_default_fast_replication=False, installed_config=config_relative,
            runtime_mode_observed=False, override_coverage_complete=False,
            no_network_dictionary_index_in_nonfast_branch=True,
            runtime_request_dispatch_qualified=False),
        item_move=dict(struct='FItemMoveCmd', native_bytes=328, cpp_ops_vtable='0x18867790',
            custom_net_serializer=False, ordinary_function_property_replication_required=True,
            rpc='InventoryManager.ServerProcessItemMoveCmd', existing_class_cache_index=45,
            exclusive_class_index_maximum=53, native_exec_rva='0xcfbc2c0', implementation_rva='0xbfc43f0',
            native_overwrites_cmd_owner_with_manager_owner_character=True,
            unresolved='Actual function RepLayout serial and normal field grammar; 328 native bytes are not wire bytes'),
        shortest_world_integration=[
            'Bind the source-qualified existing static SafeBox GUID on an actor channel; never respawn the cooked level actor',
            'Decode the existing one-object controller ServerOpenPickupBox index226 using portable_loot_box_request',
            'Validate current player ownership, native-world position distance and one finite authority box identity',
            'Project persistent per-box finite contents using portable_loot_box_codec; commit replication cursor only after actual ACK',
            'Close the real ItemMoveCmd function field schema before enabling client pickup/move dispatch',
            'Commit whole-GID/quantity transfers atomically using portable_finite_loot, then replicate source and destination revisions',
            'Apply extraction conditions to actual player/world state, persist terminal result and use PlayerState170/171 notification',
            'Project the stored result through source-qualified settlement EmptyNtf/fetch/clear lifecycle without duplicate grants'],
        ai_boundary=dict(resources_are_spawn_execution=False,
            available_base_class='/Game/BluePrints/Characters/AI/BP_DFMCharacter_AI.BP_DFMCharacter_AI_C',
            missing_official_template_is_not_blocking_local_policy=True,
            explicit_local_policy_must_select_actual_source_template_point_class=True,
            native_acceptance_required=['AI Pawn actual class/export and receiving layout',
                'Authoritative movement/health/damage/death reception',
                'Actual server behavior simulation and attack lifecycle',
                'Single finite death-drop transaction preserving original inventory GIDs'],
            static_dummy_is_combat_ai=False))


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    if args.output.exists() or not args.output.resolve().is_relative_to(ROOT / 'work/evidence'):
        parser.error('A fresh private evidence path is required')
    report = derive()
    raw = (json.dumps(report, indent=2, sort_keys=True) + '\n').encode('ascii')
    with args.output.open('xb') as stream:
        stream.write(raw)
    print(json.dumps(dict(path=str(args.output), sha256=hashlib.sha256(raw).hexdigest(),
        terminal_reason_cases=len(report['match_end']['encoded_reason_cases']),
        terminal_value_bits=report['match_end']['encoded_reason_cases'][0]['value_bits'])))
