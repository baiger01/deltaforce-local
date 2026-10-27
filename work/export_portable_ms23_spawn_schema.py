"""Export public static inputs for the one-participant MS23 allocator subset."""
import hashlib
import json
from pathlib import Path

from offline_spawn_ms23_one_participant import load_inputs, CATALOG, CATALOG_SHA

ROOT = Path(__file__).resolve().parent.parent
FOLDER = ROOT / 'work/evidence/map-system-audit-20261018'


def derive():
    table, catalog, rows, containers = load_inputs()
    sources = list(table['source_files']) + [dict(relative_path=CATALOG, sha256=CATALOG_SHA)]
    native_names = (
        'native-spawn-selection-base-rng.json', 'native-spawn-selection-fallback-seed.json',
        'native-spawn-selection-initializers.json', 'native-default-spawn-policy-bodies.json',
        'native-spawn-allocation-branches.json', 'native-spawn-template-container-priority-sort.json',
        'native-spawn-template-priority-comparator.json',
        'native-spawn-teamstart-playerstart-order-and-position.json',
        'native-spawn-playerstart-fixed-order-sort.json',
        'native-spawn-playerstart-fixed-order-comparator.json',
        'native-economy-actual-asset-mappings.json',
        'native-map-config-hotfix-search.json')
    native = {}
    for name in native_names:
        path = FOLDER / name
        raw = path.read_bytes()
        doc = json.loads(raw)
        sources.append(dict(relative_path=path.relative_to(ROOT).as_posix(),
                            sha256=hashlib.sha256(raw).hexdigest()))
        for function in doc.get('functions', []):
            for instruction in function['instructions']:
                native[instruction['rva']] = instruction
    # These are instruction boundaries decoded from the owned, sealed cache.
    expected = (
        (0xc4044c0, 'mov', 'qword ptr [rbx + 0xc8], rdx'),
        (0xc4044ed, 'mov', 'qword ptr [rbx + 0xd0], r9'),
        (0xc40451a, 'mov', 'qword ptr [rbx + 0xd8], r8'),
        (0xc404544, 'mov', 'qword ptr [rbx + 0xe0], rax'),
        (0xc41f893, 'ror', 'rax, 0x39'),
        (0xc41f8ab, 'ror', 'rcx, 0x13'),
        (0xc41fa06, 'call', '0xc41f820'),
        (0xc41fa0d, 'div', 'rbx'),
        (0x101ac57c, 'call', '0x10176010'),
        (0x101acc16, 'call', '0xc41f920'),
        (0x101acd76, 'call', '0xc41f920'),
        (0x101aa2b1, 'call', '0x10174e10'),
        (0x101a905e, 'call', '0xc41f920'),
        (0x101a908a, 'mov', 'dword ptr [rax + r12 + 0x38], edi'),
        (0x101a9179, 'call', '0xc41f920'),
        (0x1017afd2, 'setg', 'al'),
        (0x10185b45, 'cmp', 'byte ptr [rsi + 0x20], 0'),
        (0x10185b7e, 'jge', '0x10185b86'),
        (0x10185c79, 'call', '0xc41f920'),
        (0x10185c9b, 'mov', 'r15d, dword ptr [rax + rdx*4]'),
        (0x10185fbe, 'div', 'ecx'),
        (0xc4a81c2, 'call', '0xc441340'),
        (0xc44ac7c, 'call', '0x12549180'),
        (0xc44aca2, 'mulss', 'xmm6, xmm6'),
        (0xc44acca, 'addss', 'xmm8, xmm7'),
        (0xc44ace0, 'comiss', 'xmm2, xmm8'),
        (0xc44acea, 'seta', 'al'),
    )
    facts = []
    for rva, mnemonic, operands in expected:
        instruction = native[hex(rva)]
        assert (instruction['mnemonic'], instruction['operands']) == (mnemonic, operands)
        facts.append(dict(rva=hex(rva), mnemonic=mnemonic, operands=operands,
                          bytes=instruction['bytes']))
    return dict(kind='qualified_static_normal_MS23_one_participant_schema',
        client_sha256=catalog['source_client_sha256'], map_id=2201,
        map_name='Dam_Iris_Level1', template_table='/Game/DataTables/SOLStartSpotTemplateTable',
        equivalent_positive_template_rows=[dict(name=r['name'], weight=r['fields']['Weight'],
                                                source_offset=r['uexp_offset'],
                                                source_row_sha256=r['serialized_sha256']) for r in rows],
        effective_first_human_containers=containers, spawn_groups=catalog['spawn_groups'],
        limitations=dict(maximum_participants=1, map_level_1_supported=False,
                         exact_selected_template_row_name_qualified=False,
                         all_positive_rows_first_human_behavior_equivalent=True,
                         runtime_row_map_iteration='ascending_live_sparse_array_slots',
                         serialized_row_order_to_runtime_slots_qualified=False,
                         world_origin_must_be_explicit=True, final_collision_adjustment_applied=False,
                         native_hot_replacements_and_debug_seed_override_in_local_policy=False),
        native_instruction_facts=facts, source_files=sources)


if __name__ == '__main__':
    raw = (json.dumps(derive(), indent=2, sort_keys=True) + '\n').encode()
    target = ROOT / 'outputs/df-local-server/protocol/portable-map-spawn/ms23-spawn-schema.json'
    with target.open('xb') as stream:
        stream.write(raw)
    print(json.dumps(dict(path=target.relative_to(ROOT).as_posix(),
                          sha256=hashlib.sha256(raw).hexdigest(), bytes=len(raw))))
