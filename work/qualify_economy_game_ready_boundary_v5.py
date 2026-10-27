"""Seal the normal native seamless-finished RPC and inventory-ready limits."""
import argparse
import hashlib
import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / 'outputs/df-local-server'))
from dfserver.legacy_ds_bit_archive import BitReader
from dfserver.legacy_ds_wire_codec import decode_observed_application
BASE = 'work/evidence/map-system-audit-20261018/'
CLIENT_SHA = '4254fbe66585f260f1f9dbfc5e302887842552e7baed8939e023160a5e250be0'
CLASS = '/Game/BluePrints/Characters/BP_DFMPlayerController.BP_DFMPlayerController_C'
NAMES = (
    'native-economy-controller-game-ready-declarations-v4.json',
    'native-economy-seamlessfinish-normal-callers-v4.json',
    'native-economy-seamless-succeed-entry-gates-v4.json',
    'native-economy-game-ready-installed-lua-v4.json',
    'native-economy-game-ready-lua-xrefs-v4.json',
    'native-economy-game-ready-log-1792343957590810500-v4.json',
    'native-economy-ready-rpc-packet-receipt-1792343957590810500-v4.json',
)


def derive():
    docs, pins = {}, {}
    for relative in [BASE + name for name in NAMES] + [
            'work/native-client-tests/1792337436036819800/world-interaction-rpc-metadata.json',
            'work/native-client-tests/1792343957590810500/portable-runtime-after-possession.json']:
        raw = (ROOT / relative).read_bytes()
        docs[relative] = json.loads(raw)
        pins[relative] = hashlib.sha256(raw).hexdigest()
    old = docs['work/native-client-tests/1792337436036819800/world-interaction-rpc-metadata.json']
    owner, = [row for row in old['owners'] if row['scope'] == 'controller']
    current = docs['work/native-client-tests/1792343957590810500/portable-runtime-after-possession.json']['primary_controller_views'][0]['controller_replication_metadata']
    if owner['class_path'] != CLASS or current['class_asset_path'] != CLASS or current['exclusive_index_maximum'] != 245:
        raise ValueError('The actual current controller class binding changed')
    named = [row for node in owner['existing_driver_class']['cache_nodes'] for row in node['fields']
        if row.get('descriptor_name') == 'ServerNotifySeamlessFinish']
    observed = [row for node in current['cache_nodes'] for row in node['fields'] if row['rep_index'] == 225]
    if len(named) != 1 or len(observed) != 1 or any(
            (row['rep_index'], row['checksum'], row['descriptor_representation'], row['incompatible']) !=
            (225, 3802576422, 1, False) for row in named + observed):
        raise ValueError('The actual named/current ready RPC cache records changed')
    declaration = docs[BASE + NAMES[0]]['classes'][0]
    function, = [row for row in declaration['function_declarations'] if row['name'] == 'ServerNotifySeamlessFinish']
    if (function['function_flags'], function['native_param_bytes'], function['property_count']) != ('0x220cc0', 0, 0):
        raise ValueError('The normal reliable Server RPC signature changed')
    native = docs[BASE + NAMES[1]]
    anchors = {(row['rva'], row['mnemonic'], row['operands'])
        for body in native['functions'] for row in body['instructions']}
    if not {('0xd44887f', 'call', '0xced6130'),
            ('0xd448884', 'mov', 'byte ptr [r14 + 0xa51], 1'),
            ('0xd4292b7', 'call', '0xced6130')} <= anchors:
        raise ValueError('The normal seamless-finished native caller changed')
    gate = docs[BASE + NAMES[2]]
    gate_anchors = {(row['rva'], row['mnemonic'], row['operands'])
        for body in gate['functions'] for row in body['instructions']}
    if not {('0xd44ff4d', 'test', 'dl, dl'), ('0xd44ff4f', 'je', '0xd450048'),
            ('0xd45007e', 'call', '0xd4483d0')} <= gate_anchors:
        raise ValueError('The loading-flow-success gate changed')
    lua_xrefs = docs[BASE + NAMES[4]]
    if (lua_xrefs['indexed_chunks'] != 5707 or lua_xrefs['failures'] or
            lua_xrefs['counts'].get('parsed_and_hash_verified') != 5707):
        raise ValueError('The exact baseline Lua coverage is incomplete')
    log = docs[BASE + NAMES[5]]
    lines = log['samples']
    game, = [row for row in lines if row['line_number'] == 50576]
    ready, = [row for row in lines if row['line_number'] == 51044]
    if '01.21.18:539' not in game['text'] or '01.21.31:302' not in ready['text'] or 'ServerNotifySeamlessFinish!' not in ready['text']:
        raise ValueError('The same-trial normal Game/finished chronology changed')
    packet_report_path = 'work/native-client-tests/1792343957590810500/game-server-packets/report.json'
    packet_raw = (ROOT / packet_report_path).read_bytes()
    packet_report = json.loads(packet_raw)
    first_partial, = [row for row in packet_report['pc_restart_packet_capture']['records']
        if any(bunch['partial_initial'] for bunch in row['pc_bunches'])]
    packet_path = (ROOT / packet_report_path).parent / first_partial['private_packet_file']
    raw = packet_path.read_bytes()
    if hashlib.sha256(raw).hexdigest() != first_partial['sha256']:
        raise ValueError('The exact saved first partial datagram changed')
    decoded = decode_observed_application(raw[8:], max_packet_bytes=1024, received_by_server=True)
    partial, = [bunch for bunch in decoded.bunches if bunch.partial_initial and bunch.channel_index == 2]
    reader = BitReader(partial.payload, bit_count=partial.payload_bits)
    if (reader.read_bool(), reader.read_bool(), reader.read_packed_int(),
            reader.read_bounded_int(245), reader.read_packed_int()) != (False, True, 132312, 84, 132280):
        raise ValueError('The source-qualified first partial envelope changed')
    pins[packet_report_path] = hashlib.sha256(packet_raw).hexdigest()
    pins[packet_path.relative_to(ROOT).as_posix()] = first_partial['sha256']
    pins['work/qualify_economy_game_ready_boundary_v5.py'] = hashlib.sha256(Path(__file__).read_bytes()).hexdigest()
    return dict(kind='source_qualified_native_seamless_finished_inventory_refresh_boundary_v5',
        client_sha256=CLIENT_SHA, source_pins=pins,
        process_access=False, client_launched=False, production_modified=False,
        receiver=dict(class_path=CLASS, exclusive_index_maximum=245, function_index=225,
            function_name='ServerNotifySeamlessFinish', field_checksum=3802576422,
            function_flags='0x220cc0', reliable=True, server=True, parameter_bits=0,
            function_params_rva='0x1d1f0db0', event_wrapper_rva='0xced6130'),
        native_causality=dict(normal_loading_flow_success='0xd44fde0(result=0) -> 0xd4483d0',
            normal_rpc_call='0xd44887f -> 0xced6130', client_real_in_game_flag_write='0xd448884 byte PC+a51=1',
            new_finish_stage_alternative='0xd428e20 -> 0xd4292b7 -> 0xced6130',
            signal_is_seamless_loading_completion=True, signal_is_inventory_ui_completion=False),
        same_trial=dict(capture='1792343957590810500', initial_inventory_onrep_interval=['01:21:14.008','01:21:15.029'],
            initial_inventory_count=52, native_lobby_to_game_at='01:21:13.191',
            native_game_at='01:21:18.539', client_rpc_call_at='01:21:31.302',
            complete_received_rpc_225_saved=False, saved_capture_truncates_pc_reliable_partial=True,
            partial_first_sequence=57, partial_first_at='01:21:31.313380',
            first_partial_field_index=84, first_partial_field_name='ServerUpdateMultipleLevelsVisibility',
            first_partial_declared_field_bits=132280, first_partial_declared_actor_block_bits=132312,
            runtime_reassembly_failure_proven=False),
        lua_boundary=dict(check_server_enabled_accepts=['Game','LobbyToGame','GameSettlement'],
            baseline_game_state_only_publishes_local_event=True, baseline_lua_blocks_verified=5707,
            first_events_discarded_by_safehouse_flow_in_this_trial_proven=False,
            ordinary_game_enter_does_not_refetch_inventory=True,
            ordinary_inventory_ui_root_cause_proven=False),
        refresh_candidate=dict(trigger='Actual admitted ordered complete reliable empty function225 on current PC channel',
            callback='InventoryManager.OnRep_RepItemArray -> OnGameInventoryClientInitialize -> Lua inventory rebuild',
            values='One unchanged current original FastArray element; no new GID/count/features',
            ordering='Only after initial inventory stages actual ACK and exclusive current array revision',
            retransmission='Reuse identical content/key until ACK; commit cursor only on exact receipt',
            claims='Source-qualified candidate; not a verified Tab fix or inventory UI-ready acknowledgement'),
        excluded_ready_sources=['Elapsed delay', 'Transport packet ACK', 'ServerNotifyLoadingFinish index224 alone',
            'Log observation without an actual admitted RPC receipt', 'Incomplete PC partial fragment'],
        native_refresh_acceptance_verified=False)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    if args.output.exists() or not args.output.resolve().is_relative_to(ROOT / 'work/evidence'):
        parser.error('Use a fresh audit-only evidence path')
    report = derive()
    raw = (json.dumps(report, indent=2, sort_keys=True) + '\n').encode('ascii')
    with args.output.open('xb') as stream:
        stream.write(raw)
    print(json.dumps(dict(path=str(args.output), sha256=hashlib.sha256(raw).hexdigest())))
