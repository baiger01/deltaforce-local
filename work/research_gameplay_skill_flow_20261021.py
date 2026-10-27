"""Disk-only Rush skill production-flow evidence; writes only an explicit own output."""
import argparse
from datetime import datetime, timezone
import hashlib
import json
import mmap
from pathlib import Path
import sys

sys.dont_write_bytecode = True
OWN = Path(__file__).resolve().parent.parent
PEER = OWN.parent / 'deltaforce-map-appearance'
GAME = Path('F:/WeGameApps/rail_apps/DeltaForce(2001918)')
MANIFEST_SHA = 'dfd5c279d7db45842cee2bbc485ac8bf3cab03e4249ef5fe36bc9e8d6cd14754'
CLIENT_SHA = '4254fbe66585f260f1f9dbfc5e302887842552e7baed8939e023160a5e250be0'
E = 'work/evidence/'
A = E + 'skill-activation-authority-20261020-v1/'
C = E + 'skill-template-coverage-20261020-v2/'
F = E + 'skill-flow-research-20261020-v1/'
M = E + 'model-init-chain-20261018/'


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path)
    parser.add_argument('--verify', type=Path)
    parser.add_argument('--refresh-own-evidence', action='store_true')
    args = parser.parse_args()
    pins = {}

    def read(relative):
        path = PEER / relative
        raw = path.read_bytes()
        old = pins.get(relative)
        if old is not None and old['sha256'] != sha(raw):
            raise ValueError('Source changed during collection: ' + relative)
        pins[relative] = dict(sha256=sha(raw), bytes=len(raw),
                              mtime_ns=path.stat().st_mtime_ns)
        return raw

    def load(relative):
        return json.loads(read(relative))

    for name, expected in {
        'portable_native_code_cache.py': '2372b9603d6d6e12a3afc57ac1765f8aaca408d0c2794a8d81eaec3337fa399e',
        'analyze_portable_native_code.py': 'c08ed72d4969f43178de962b836a62fb472d23beb11ac01a7f7269f8792eeafd',
        'offline_received_packet_xrefs.py': '4151dd221d6ad09bd83cebdb2ab2016e688aa05624727488ac8fbfc5f500ed77',
        'snapshot_native_image_code.py': '62405c35a3839d5eb67cf2cdde41606d6a82f2501fd84d7b3671adec864e15ae',
    }.items():
        if sha(read('work/' + name)) != expected:
            raise ValueError('Pinned native helper changed: ' + name)
    sys.path.insert(0, str(PEER / 'work'))
    from analyze_portable_native_code import function_fragments
    from capstone import Cs, CS_ARCH_X86, CS_MODE_64
    from offline_received_packet_xrefs import ImmutableImage
    from portable_native_code_cache import CodeCache
    from parse_economy_installed_tables import parse_table, tag_value
    from recover_economy_pak_access import installed_name_map
    from extract_operator_avatar_catalog import property_tag

    for name in ('parse_economy_installed_tables.py', 'recover_economy_pak_access.py',
                 'extract_operator_avatar_catalog.py', 'skill_initial_state_values.py',
                 'portable_skill_entity_admission.py', 'skill_template_authority.py',
                 'skill_template_replication.py', 'portable_map_bootstrap.py',
                 'portable_movement_runtime.py', 'skill_trigger_behavior_codec.py'):
        read('work/' + name)
    read('outputs/df-local-server/dfserver/legacy_ds_control_connection.py')
    read('outputs/df-local-server/dfserver/legacy_ds_movement.py')
    graph = load(A + 'connected-skill-activation-source-v6.json')
    prior_check = []
    for relative, expected in graph['source_pins'].items():
        actual = sha(read(relative))
        prior_check.append(dict(path=relative, expected_sha256=expected,
                                actual_sha256=actual, matches=actual == expected))
    schema = load(M + 'native-skill-initial-state-wire-contract-v3.json')
    plan = schema['hero_plans']['88000000025']
    source_row = next(x for x in plan['source_row_plan'] if x['skill_id'] == 1009001)
    skill_table = load(M + 'native-vitals-skilldataconfig-actual-rows.json')
    skill_row = skill_table['rows']['1009001']
    expert_table = load(M + 'native-vitals-expertskilldata-actual-rows.json')
    hero_table = load(M + 'native-vitals-herodata-actual-rows.json')
    for table in (skill_table, expert_table, hero_table):
        for field in ('source_uasset', 'source_uexp'):
            path = table[field].replace('\\', '/')
            if sha(read(path)) != table[field + '_sha256']:
                raise ValueError('Extracted identity table changed: ' + path)
    coverage = load(C + 'all-schema-authority-coverage-v4.json')
    authored = next(x for x in coverage['class_execution'] if x.get('skill_id') == 1009001)
    hero_coverage = next(x for x in coverage['per_hero'] if x.get('hero_id') == 88000000025)
    catalog = load(C + 'configured-program-catalog-v3.json')
    package = next(x for x in catalog['packages'] if x['class_path'] == source_row['configured_template_class'])
    instance_catalog = load(A + 'instance-programs/configured-instance-program-catalog-v1.json')
    instance = next(x for x in instance_catalog['packages'] if x['class_path'] == source_row['configured_instance_class'])
    for item in (package, instance):
        for src in item['source_files']:
            if sha(read(src['relative_path'])) != src['sha256']:
                raise ValueError('Configured package changed')
        for field in ('bytecode', 'metadata'):
            if sha(read(item[field + '_path'])) != item[field + '_sha256']:
                raise ValueError('Configured package parser output changed')
    bytecode = load(package['bytecode_path'])
    asset = read(package['source_files'][0]['relative_path'])
    export = read(package['source_files'][1]['relative_path'])
    names = installed_name_map(asset)
    cdo = {}
    for prop in package['actual_cdo_properties']:
        if prop['name'] in ('SettingSOL', 'SettingMP', 'Mask2', 'Mask3'):
            tag = property_tag(export, prop['start'], names, len(export))
            cdo[prop['name']] = dict(serialized_uexp_offset=prop['value_start'],
                                    fields=tag_value(export, tag, names),
                                    value_sha256=sha(export[prop['value_start']:prop['end']]))
    charging = []
    root = F + 'charging-assets/pak-0-0-pakchunk2-WindowsClient/DeltaForce/Content/DataTables/'
    for name in ('Inventory/SlotCharing', 'BattleField/SlotCharingExtraTable', 'BattleField/SlotCharingByTagTable'):
        ap, ep = root + name + '.uasset', root + name + '.uexp'
        read(ap)
        read(ep)
        table = parse_table(PEER / ap, PEER / ep)
        selected = {}
        for row_name, row in table['rows'].items():
            fields = row['fields']
            relevant = fields.get('CdID') == 18 or any(
                x.get('key') == 18 for x in fields.get('SlotCharingMap', []))
            if relevant:
                scoped_fields = dict(fields)
                if 'SlotCharingMap' in scoped_fields:
                    scoped_fields['SlotCharingMap'] = [x for x in fields['SlotCharingMap'] if x['key'] == 18]
                selected[row_name] = dict(row, fields=scoped_fields)
        charging.append(dict(source_table=table['source_table'], total_rows=table['row_count'],
                             complete_row_coverage=table['complete_row_coverage'],
                             source_uasset=ap, source_uexp=ep,
                             source_uexp_sha256=table['source_uexp_sha256'], rows=selected))

    cache = CodeCache(PEER / 'work/native-code-cache/1792259162856698600', MANIFEST_SHA, GAME)
    exe = GAME / cache.manifest['plan']['client_relative_to_game_root']
    decoder = Cs(CS_ARCH_X86, CS_MODE_64)
    decoder.detail = True
    functions = []
    immutable_records = []
    with exe.open('rb') as stream, mmap.mmap(stream.fileno(), 0, access=mmap.ACCESS_READ) as raw:
        if sha(raw) != CLIENT_SHA:
            raise ValueError('Original installed executable changed')
        image = ImmutableImage(raw)
        requests = (0xCE936B0, 0xAB47D50, 0x4461D50, 0x7CB4630,
                    0x34CF1C0, 0x355E320, 0x7CBBAC0, 0x34D26F0,
                    0x7EBA5D0, 0x7F0CD80, 0x808B320)
        windows = ((0x44634CD, 0x4463514), (0x44642C8, 0x4464310),
                   (0xAB485E4, 0xAB485FE), (0x7CB4720, 0x7CB4750),
                   (0x7CBBD1D, 0x7CBBD31), (0x7EBA623, 0x7EBA62E),
                   (0x7F0CE22, 0x7F0CE32), (0x355E3C2, 0x355E4E0),
                   (0x355EE3E, 0x355EE86))
        for query in requests:
            fragments = function_fragments(image, query)
            first, end = fragments[0][0], fragments[-1][1]
            code = b''.join(cache.read(at, min(8192, end - at)) for at in range(first, end, 8192))
            decoded = list(decoder.disasm(code, first))
            if sum(ins.size for ins in decoded) != len(code):
                raise ValueError('Linear code decode incomplete at ' + hex(query))
            selected = []
            for ins in decoded:
                if len(code) <= 800 or any(lo <= ins.address < hi for lo, hi in windows):
                    selected.append(dict(rva=hex(ins.address), bytes=ins.bytes.hex(),
                                         mnemonic=ins.mnemonic, operands=ins.op_str))
            functions.append(dict(query=hex(query), start=hex(first), bytes=len(code),
                                  code_sha256=sha(code), pdata=[image.unwind(e) for e in fragments],
                                  linear_decode_complete=True, complete_semantics_claimed=False,
                                  selected_instructions=selected))
        for rva, size in ((0x186BDAD0, 16), (0x1830AB30, 16), (0x16661F78, 56),
                          (0x16FA18E0, 32), (0x16FB3958, 32), (0x16F2C908, 16)):
            data = image.read(rva, size)
            immutable_records.append(dict(rva=hex(rva), bytes=size, sha256=sha(data), raw_hex=data.hex()))
        setter = cache.read(0x5FC8700, 8)
        if setter != bytes.fromhex('c681160e000001c3'):
            raise ValueError('bWantsToRush native setter changed')

    control = read('outputs/df-local-server/dfserver/legacy_ds_control_connection.py').decode()
    lines = control.splitlines()
    start = next(i for i, line in enumerate(lines) if 'def _consume_admitted_actor_packet(' in line)
    end = next(i for i in range(start + 1, len(lines)) if lines[i].startswith('    def '))
    dispatch_source = '\n'.join(lines[start:end]) + '\n'
    callback_entries = []
    for f in bytecode['functions'][1:]:
        call = next((x['expression'] for x in f['bytecode']
                     if x['expression']['$type'].split(',')[0].endswith('EX_LocalFinalFunction')), None)
        if call:
            callback_entries.append(dict(name=f['name'], source_uexp=f['source_bytecode_matching_offsets'][0],
                                         uber_entry=call['Parameters'][0]['Value']))
    entries_by_name = {x['name']: x['uber_entry'] for x in callback_entries}
    uber = {x['memory_offset']: x['expression'] for x in bytecode['functions'][0]['bytecode']}
    task_sites = {x['source_memory_offset']: x['task_index'] for x in authored['tasks']}
    callback_routes = []
    for task in authored['tasks']:
        for event, callback in task['callback_bindings']:
            entry = entries_by_name[callback]
            target = entry
            seen = set()
            while target not in task_sites and target not in seen:
                seen.add(target)
                expr = uber[target]
                if not expr['$type'].split(',')[0].endswith('EX_Jump'):
                    break
                target = expr['CodeOffset']
            callback_routes.append(dict(source_task=task['task_index'], event=event,
                                        callback=callback, uber_entry=entry,
                                        resolved_uber_target=target,
                                        target_task=task_sites.get(target),
                                        target_kind=uber[target]['$type'].split(',')[0].rsplit('.', 1)[-1]))
    report = dict(
        kind='disk_only_actual_rush_skill_production_flow_20261021',
        as_of_utc=datetime.now(timezone.utc).isoformat(),
        scope=dict(process_access=False, native_methods_invoked=False, game_launched=False,
                   network_used=False, database_opened=False, peer_written=False,
                   original_game_written=False, gameplay_verified=False),
        client_sha256=CLIENT_SHA, cache_manifest_sha256=MANIFEST_SHA,
        helper_sha256=sha(Path(__file__).read_bytes()),
        selected=dict(hero_id=88000000025, expert_id=plan['expert_id'], skill_id=1009001,
                      selected_from_real_default_fixture=hero_coverage['unchanged_default_fixture'],
                      current_selected_player_observed=False, hero_source=plan['hero_row_source'],
                      expert_source=plan['expert_row_source'], source_row=source_row,
                      expert_row=expert_table['rows']['10010'], skill_row=skill_row,
                      instance_parent_class=instance['parent_class']),
        charging_tables=charging, cdo=cdo,
        authored=dict(tasks=authored['tasks'], collection_graph_edges=authored['graph_edges'],
                      graph_is_not_timing_or_runtime_execution=True,
                      common_configuration=json.loads(authored['common_configuration_json']),
                      callback_uber_entries=callback_entries,
                      syntax_callback_routes=callback_routes,
                      final_uber_jumps=[x for x in bytecode['functions'][0]['bytecode']
                                        if x['memory_offset'] >= 7091]),
        inherited_source_routes={k: graph[k] for k in ('runtime_task_route_source', 'charging_write_chain', 'rush_runtime')},
        execution_replication={k:v for k,v in graph['skill_execution_replication'].items()
                               if k not in ('captured_commands', 'captured_parents')},
        native_functions=functions, immutable_records=immutable_records,
        old_graph_pin_check=dict(count=len(prior_check), changed=[x for x in prior_check if not x['matches']]),
        current_receiver=dict(path='outputs/df-local-server/dfserver/legacy_ds_control_connection.py',
                              first_line=start+1, last_line=end, block_sha256=sha(dispatch_source.encode()),
                              source=dispatch_source, skill_consumer_present=False),
        source_pins=pins)
    # Check the same bytes again after the code/config work; a mixed snapshot is rejected.
    for relative, pin in pins.items():
        if sha((PEER / relative).read_bytes()) != pin['sha256']:
            raise ValueError('Source changed before evidence finalization: ' + relative)
    if args.verify:
        prior = json.loads(args.verify.read_bytes())
        for key in ('selected', 'charging_tables', 'cdo', 'authored', 'native_functions',
                    'immutable_records', 'current_receiver', 'source_pins'):
            if prior[key] != report[key]:
                raise ValueError('Replay mismatch: ' + key)
        print(json.dumps(dict(replay_matches=True, source_pin_count=len(pins),
                              old_graph_pins_changed=len(report['old_graph_pin_check']['changed']),
                              native_function_count=len(functions))))
    elif args.output:
        output = args.output.resolve()
        if output.parent != (OWN / 'work/evidence').resolve():
            raise ValueError('A fresh own work/evidence filename is required')
        if output.exists() and not (args.refresh_own_evidence and
                output.name == 'gameplay-skill-flow-research-20261021.json' and
                json.loads(output.read_bytes()).get('kind') == report['kind']):
            raise ValueError('Existing evidence requires explicit own-evidence refresh')
        data = (json.dumps(report, ensure_ascii=True, sort_keys=True, indent=2) + '\n').encode()
        with output.open('wb' if output.exists() else 'xb') as stream:
            stream.write(data)
        print(json.dumps(dict(output=str(output), sha256=sha(data), source_pin_count=len(pins),
                              old_graph_pins_changed=len(report['old_graph_pin_check']['changed']),
                              native_function_count=len(functions))))
    else:
        print(json.dumps(report, ensure_ascii=True, sort_keys=True, indent=2))


if __name__ == '__main__':
    main()
