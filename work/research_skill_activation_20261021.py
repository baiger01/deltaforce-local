"""Read-only first-activation, authored state listener and cooldown evidence."""
import argparse
from datetime import datetime, timezone
import hashlib
import json
import mmap
from pathlib import Path
import struct
import sys

sys.dont_write_bytecode = True
OWN = Path(__file__).resolve().parent.parent
PEER = OWN.parent / 'deltaforce-map-appearance'
GAME = Path('F:/WeGameApps/rail_apps/DeltaForce(2001918)')
MANIFEST_SHA = 'dfd5c279d7db45842cee2bbc485ac8bf3cab03e4249ef5fe36bc9e8d6cd14754'
CLIENT_SHA = '4254fbe66585f260f1f9dbfc5e302887842552e7baed8939e023160a5e250be0'
PREVIOUS = 'work/evidence/gameplay-skill-flow-reaudit-20261021.json'
ACTIVATION = 'work/evidence/skill-activation-authority-20261020-v1/'


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def derive():
    pins = {}

    def read(root, relative):
        path = root / relative
        raw = path.read_bytes()
        key = ('own:' if root == OWN else 'peer:') + relative
        pin = dict(sha256=sha(raw), bytes=len(raw))
        if key in pins and pins[key] != pin:
            raise ValueError('Source changed while collecting: ' + key)
        pins[key] = pin
        return raw

    expected_helpers = {
        'portable_native_code_cache.py': '2372b9603d6d6e12a3afc57ac1765f8aaca408d0c2794a8d81eaec3337fa399e',
        'analyze_portable_native_code.py': 'c08ed72d4969f43178de962b836a62fb472d23beb11ac01a7f7269f8792eeafd',
        'offline_received_packet_xrefs.py': '4151dd221d6ad09bd83cebdb2ab2016e688aa05624727488ac8fbfc5f500ed77',
        'snapshot_native_image_code.py': '62405c35a3839d5eb67cf2cdde41606d6a82f2501fd84d7b3671adec864e15ae',
    }
    for name, digest in expected_helpers.items():
        if sha(read(PEER, 'work/' + name)) != digest:
            raise ValueError('Pinned native helper changed: ' + name)
    prior = json.loads(read(OWN, PREVIOUS))
    for relative in (
            ACTIVATION + 'native-runtime-task-actual-effect-virtual-dispatch.json',
            ACTIVATION + 'native-runtime-task-start-effect-and-record-authority.json',
            ACTIVATION + 'native-current-skill-vtable-writer-and-cast-result-bodies.json'):
        read(PEER, relative)
    source_row = prior['selected']['source_row']
    # Requalify the actual authored source, rather than accepting the prior prose.
    for key, pin in prior['source_pins'].items():
        if ('skill-template-coverage-20261020-v2/' in key and
                ('configured-program-catalog-v3.json' in key or
                 'all-schema-authority-coverage-v4.json' in key)):
            if sha(read(PEER, key)) != pin['sha256']:
                raise ValueError('Authored catalog changed: ' + key)
    catalog = json.loads(read(PEER, 'work/evidence/skill-template-coverage-20261020-v2/'
                              'configured-program-catalog-v3.json'))
    package = next(p for p in catalog['packages']
                   if p['class_path'] == source_row['configured_template_class'])
    for source in package['source_files']:
        if sha(read(PEER, source['relative_path'])) != source['sha256']:
            raise ValueError('Authored package changed')
    for field in ('bytecode', 'metadata'):
        if sha(read(PEER, package[field + '_path'])) != package[field + '_sha256']:
            raise ValueError('Authored parser output changed')

    sys.path.insert(0, str(PEER / 'work'))
    from analyze_portable_native_code import analyze
    from offline_received_packet_xrefs import ImmutableImage
    from portable_native_code_cache import CodeCache
    cache = CodeCache(PEER / 'work/native-code-cache/1792259162856698600', MANIFEST_SHA, GAME)
    targets = [
        0x31CC820, 0x32DCCC0, 0x3417C40, 0x33A0550, 0x3323320,
        0x3495890, 0x33510C0, 0x339ED60, 0x3315EC0, 0x96FEFC0,
        0x33B1D90, 0x7D41F10, 0x7F1F340, 0x7F21880, 0x7D74B40,
        0x7F38260, 0x7ED1CC0, 0x7ED8600, 0x7D3B820, 0x7D54470,
        0x7D05F20, 0x7D062D0, 0x808F380, 0x7D5E080, 0x95C0970,
        0x351C0A0, 0x34F86F0, 0x34F6340, 0x351CF00, 0x355E320,
        0x34CF1C0, 0x34E1E80, 0x351E5D0, 0x34E4CA0,
        0x32E4160, 0x34DC8C0, 0x3560C00, 0x7F38F10,
    ]
    native = analyze(cache.folder, MANIFEST_SHA, GAME, targets, [], set())
    # Large functions keep every transfer and the exact windows supporting the text.
    windows = [
        (0x31D16B0, 0x31D1739), (0x31D1BD0, 0x31D1C9A),
        (0x32DD612, 0x32DD646), (0x34193CD, 0x34194C2),
        (0x3419D53, 0x3419DB2), (0x33A2A44, 0x33A2A61),
        (0x3324B23, 0x3324BBF), (0x3353151, 0x335328C),
        (0x3355A22, 0x3355A3F), (0x33A03A6, 0x33A040C),
        (0x3316C97, 0x3316D3F), (0x7D06720, 0x7D067E0),
    ]
    for function in native['functions']:
        if not function['linear_decode_covers_extent']:
            raise ValueError('Incomplete native decode: ' + function['requested_rva'])
        if function['span_bytes'] > 8192:
            function['instructions'] = [i for i in function['instructions']
                if i['mnemonic'] in ('call', 'jmp', 'ret') or
                any(lo <= int(i['rva'], 16) < hi for lo, hi in windows)]
            function['instruction_selection'] = 'all calls/jumps/returns and explicit supporting windows'
        else:
            function['instruction_selection'] = 'complete linear function'

    exe = GAME / cache.manifest['plan']['client_relative_to_game_root']
    records, bindings = [], []
    with exe.open('rb') as handle, mmap.mmap(handle.fileno(), 0, access=mmap.ACCESS_READ) as raw:
        if sha(raw) != CLIENT_SHA:
            raise ValueError('Pinned installed executable changed')
        image = ImmutableImage(raw)
        for owner, base, slots in (
                ('DFMSkill', 0x178BE048, (0x520, 0x7A8, 0x848)),
                ('DFMAbilityDataSystem', 0x16CD4D20, (0x2A0, 0x2A8, 0x2B8)),
                ('DFMAbilityLogicTemplate', 0x16F32BF8, (0x6C8, 0x6E0)),
                ('SkillSubsystem', 0x167F7B08, (0x6C0,))):
            for slot in slots:
                data = image.read(base + slot, 8)
                bindings.append(dict(owner=owner, vtable_rva=hex(base), slot=hex(slot),
                    slot_rva=hex(base + slot), target_rva=hex(struct.unpack('<Q', data)[0] - image.image_base),
                    bytes_hex=data.hex(), sha256=sha(data)))
        for rva, size in ((0x1CE05138, 48), (0x16DA48D8, 38),
                          (0x16FA18E0, 32), (0x16F332C0, 8)):
            data = image.read(rva, size)
            records.append(dict(rva=hex(rva), bytes=size, raw_hex=data.hex(), sha256=sha(data)))

    report = dict(
        kind='disk_only_first_activation_state_listener_and_cd_20261021',
        as_of_utc=datetime.now(timezone.utc).isoformat(),
        scope=dict(process_access=False, database_opened=False, network_used=False,
                   game_launched=False, native_game_methods_invoked=False,
                   original_game_written=False, peer_written=False, gameplay_verified=False),
        helper_sha256=sha(Path(__file__).read_bytes()), client_sha256=CLIENT_SHA,
        cache_manifest_sha256=MANIFEST_SHA,
        selected=dict(hero_id=88000000025, expert_id=10010, skill_id=1009001,
                      source_row=source_row, current_player_selection_observed=False),
        authored_entry=prior['authored']['tasks'][0],
        authored_cd=next(t for t in prior['authored']['tasks'] if t['factory_name'] == 'QA_AbilityCD'),
        bindings=bindings, immutable_records=records, native=native,
        facts=dict(
            authored_begin_label_is_task_name=True,
            state_listener_byte=1,
            listener_registration='7d41f10 -> 7f1f340 -> 7f21880; global skill=-1 uses template+700, positive entity uses entity+1f0',
            listener_dispatch='DFMAbilityDataSystem v2a0=7d74b40 -> 7f38260 -> actual context+18 weak template v6c8=7ed1cc0 -> 7d3b820/7d54470 -> 7d05f20/7d062d0 -> task v300/308',
            data_system_getter='32e4160 calls32fe140 then returns SkillSubsystem+370; it is not a SlotCharging getter',
            generic_command_route='3315ec0 -> actual DataSystem v2b8=3560c00 -> context+18 actual template v6e0=7f38f10; it selects template+660/entity+1a0 SkillBehaviorMap, not the state-listener +700/+1f0 map',
            activate_alternate_route='31d1c74 ->32e4160 ->31d1c87 ->34dc8c0 is a DataSystem branch; calling this a charging branch is not justified by its object type',
            field36_is_distinct='SkillSubsystem v6c0=34e4ca0 -> DataSystem v2a8=7d82990 -> 7f389a0; it is not the authored state-listener entry',
            first_activation_prefix='31cc820 -> 32dccc0 -> 3417c40 enter -> 33a0550 -> 3323320 -> 3495890 -> 33510c0 -> 339ed60 and 3315ec0(command0)',
            first_activation_to_consume_command_fully_closed=False,
            cooldown_nonpositive_uses_selected_duration=True,
            cooldown_duration_getter='34f86f0: slot+11c; optional valid owner+190 and nonzero slot+14 use 34f8380(slot+14) multiplier',
            cooldown_remaining_preserved_condition='351c0a0: nonpositive duration, valid old execution, old state byte+c=1, changed total Num+AmmoNum, old timer not finished -> 34f6340 remaining',
            cooldown_idempotence_condition='valid active old execution, same duration, old timer not finished, unchanged total Num+AmmoNum -> 351cb6d without new countdown record',
            cooldown_count_argument_is_independent=True,
            cooldown_numeric_mutation_precedes_timer_dedup=True,
            cooldown_new_record='351c3fc ->34c34f0; duration+14, end+20=duration+clock, delay+1c=end-configured_duration, configured_duration+10; 3554420 commits',
            effective_map_mode_tag_duration_observed=False,
            first_activation_and_authored_cd_debit_dedup_fully_closed=False),
        remaining=[
            'Exact producer/enqueue/consumer binding from first activation state changes to DataSystem ConsumeCommand_BS with listener byte 1; command0 -> generic v2b8 -> SkillBehaviorMap is independently closed and does not fill this gap.',
            'State enum 1 textual declaration and task policy conditions for every Rush task; BeginSkill is the authored task name, not native enum-name proof.',
            'First activation charging path versus authored RushCD call eligibility and transaction-level debit deduplication.',
            'Actual room mode/submode/map/tag override selection and duration multiplier; configured SOL 20 seconds alone is not an observed effective value.'
        ], source_pins=pins)
    for key, pin in pins.items():
        owner, relative = key.split(':', 1)
        if sha(((OWN if owner == 'own' else PEER) / relative).read_bytes()) != pin['sha256']:
            raise ValueError('Input changed before finalization: ' + key)
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument('--output', type=Path)
    group.add_argument('--verify', type=Path)
    args = parser.parse_args()
    report = derive()
    summary = dict(source_pin_count=len(report['source_pins']),
                   native_function_count=len(report['native']['functions']),
                   binding_count=len(report['bindings']),
                   first_activation_to_consume_command_fully_closed=False)
    if args.verify:
        previous = json.loads(args.verify.read_bytes())
        for key in report:
            if key != 'as_of_utc' and previous[key] != report[key]:
                raise ValueError('Replay mismatch: ' + key)
        print(json.dumps(dict(replay_matches=True, **summary)))
    else:
        output = args.output.resolve()
        if output.parent != (OWN / 'work/evidence').resolve() or output.exists():
            raise ValueError('Use a new own work/evidence output')
        data = (json.dumps(report, ensure_ascii=True, sort_keys=True, indent=2) + '\n').encode()
        with output.open('xb') as stream:
            stream.write(data)
        print(json.dumps(dict(output=str(output), sha256=sha(data), **summary)))


if __name__ == '__main__':
    main()
