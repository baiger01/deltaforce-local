"""Read-only reputation source discovery; never updates service/account data."""

import argparse
import ast
import hashlib
import json
import mmap
from pathlib import Path
import re
import struct
import zipfile

import pefile

from lua53_reader import Reader, listing, walk
from local_game_paths import game_paths


ROOT = Path(__file__).resolve().parent.parent


def scan_lua():
    selected = re.compile(r'rep.?level|rep.?score|rep.?config|reputation|role.?quality', re.I)
    records = []
    for path in sorted((ROOT / 'work/evidence/weapon_lua').glob('*.lua')):
        try:
            raw = path.read_bytes()
            root = Reader(raw, allow_client_format1=True).function()
        except (ValueError, IndexError, KeyError, UnicodeError):
            continue
        for function in walk(root):
            constants = [value for value in function['constants']
                         if isinstance(value, str) and selected.search(value)]
            if constants:
                records.append({'file': path.name, 'source': root['source'],
                                'sha256': hashlib.sha256(raw).hexdigest(),
                                'function': function['id'], 'constants': constants})
    output = ROOT / 'work/evidence/reputation-lua-source-search-20261019.json'
    output.write_text(json.dumps(records, ensure_ascii=True, indent=2) + '\n', encoding='utf-8')
    for record in records:
        print(record['file'], record['function'], repr(record['constants']))
    print('report', output)


def show_lua(path, ids):
    root = Reader(Path(path).read_bytes(), allow_client_format1=True).function()
    for function in walk(root):
        if function['id'] in ids:
            print(listing(function))


def native_reputation():
    path = game_paths()[0] / 'DeltaForce/Binaries/Win64/DeltaForceClient-Win64-Shipping.exe'
    with path.open('rb') as handle:
        header = handle.read(65536)
    pe = pefile.PE(data=header, fast_load=True)
    start = pe.DOS_HEADER.e_lfanew + 24 + pe.FILE_HEADER.SizeOfOptionalHeader
    sections = []
    for index in range(pe.FILE_HEADER.NumberOfSections):
        _, va, size, raw = struct.unpack_from('<4I', header, start + index * 40 + 8)
        sections.append((raw, size, pe.OPTIONAL_HEADER.ImageBase + va))
    with path.open('rb') as handle, mmap.mmap(handle.fileno(), 0, access=mmap.ACCESS_READ) as data:
        def raw_to_va(offset):
            return next((va + offset - raw for raw, size, va in sections if raw <= offset < raw + size), None)

        def va_to_raw(address):
            return next((raw + address - va for raw, size, va in sections if va <= address < va + size), None)

        def occurrences(needle, start=0, end=None):
            offset = data.find(needle, start, end or len(data))
            while offset >= 0:
                yield offset
                offset = data.find(needle, offset + 1, end or len(data))

        def string(address):
            offset = va_to_raw(address)
            if offset is None:
                return None
            raw = data[offset:offset + 128].split(b'\0')[0]
            return raw.decode('ascii') if raw and all(32 <= value < 127 for value in raw) else None

        report = {'native_pe_sha256': hashlib.sha256(data).hexdigest(), 'registrations': {}}
        for name in ('Reputation', 'ReputationChange', 'Reputationdescription', 'ReputationStar',
                     'RoleQuality', 'RoleQualityScene', 'RepLevelConfig'):
            result = []
            for string_offset in occurrences(name.encode() + b'\0'):
                pointer = raw_to_va(string_offset)
                if pointer is None:
                    continue
                for reference in occurrences(struct.pack('<Q', pointer)):
                    if reference % 8 or reference < 24:
                        continue
                    params_offset = reference - 24
                    params = struct.unpack_from('<9Q', data, params_offset)
                    count = params[7] & 0xffffffff
                    array = va_to_raw(params[6])
                    if params[7] >> 32 != 0x45 or not 0 < count < 200 or array is None:
                        continue
                    fields = []
                    for prop_pointer in struct.unpack_from('<' + 'Q' * count, data, array):
                        prop_offset = va_to_raw(prop_pointer)
                        if prop_offset is None:
                            break
                        values = struct.unpack_from('<5Q', data, prop_offset)
                        field_name = string(values[0])
                        if not field_name:
                            break
                        member = values[4] >> 32
                        descriptors = []
                        for desc in occurrences(struct.pack('<Q', values[0]), 413000000, 414000000):
                            if desc % 8:
                                continue
                            _, kind, offset = struct.unpack_from('<3Q', data, desc)
                            if offset == member and string(kind):
                                descriptors.append({'offset': desc, 'kind': string(kind)})
                        fields.append({'name': field_name, 'property_record_offset': prop_offset,
                                       'member_offset': member, 'gen_flags': values[3] & 0xffffffff,
                                       'descriptors': descriptors})
                    else:
                        result.append({'struct_params_offset': params_offset, 'size': params[4],
                                       'fields': list(reversed(fields))})
            report['registrations'][name] = result
            print(name, json.dumps(result), flush=True)
    output = ROOT / 'work/evidence/reputation-native-source-search-20261019.json'
    output.write_text(json.dumps(report, ensure_ascii=True, indent=2) + '\n', encoding='utf-8')
    print('report', output)


def typed_reputation():
    from inspect_department_tables import rows
    source = Path(__file__).with_name('inspect_season_tables.py')

    class ResearchOutput(ast.NodeTransformer):
        def visit_Constant(self, node):
            if node.value == 'work/evidence/season-table-candidates-20261006.json':
                return ast.copy_location(ast.Constant(
                    'work/evidence/reputation-typed-table-search-20261019.json'), node)
            return node

    tree = ResearchOutput().visit(ast.parse(source.read_text(encoding='utf-8')))
    ast.fix_missing_locations(tree)
    namespace = {'__file__': str(source), '__name__': 'reputation_table_research'}
    exec(compile(tree, str(source), 'exec'), namespace)
    namespace['TABLES'] = {
        'reputation': (0, 0, 'Reputation', 489439776, 413261072, 11),
        'reputation_change': (0, 0, 'ReputationChange', 489439616, 413297896, 2),
        'reputation_star': (0, 0, 'ReputationStar', 489439696, 413282128, 13),
    }
    namespace['rows'] = rows
    # The reused scanner accepts only its own optional output gate.
    import sys
    saved = sys.argv
    try:
        sys.argv = [saved[0]]
        namespace['main']()
    finally:
        sys.argv = saved


def witnesses():
    from extract_native_safehouse_catalog import installed_export
    sources = {}
    for name, entry, offset, ids in (
        ('RoleInfoServer.lua', 6929, 34949120,
         ('0.1', '0.58', '0.58.0', '0.65', '0.68', '0.69', '0.70')),
        ('ReputationBasicData.lua', 1842, 8585216, ('0', '0.1', '0.4', '0.5')),
        ('ReputationServer.lua', 6927, 34937402, ('0.1', '0.1.0')),
        ('PrestigeUsagePanel.lua', 6005, 28905472, ('0.11',)),
        ('cs_attribute_editor_pb.lua', 6656, 31989760, ('0.14', '0.15')),
        ('common_editor_pb.lua', 6644, 31649792, ('0.168', '0.169')),
    ):
        raw, source = installed_export(entry, offset, pak='pak-0-0-pakchunk1-WindowsClient.pak')
        root = Reader(raw, allow_client_format1=True).function()
        if root['source'] != '@' + name:
            raise ValueError('Source name witness differs: ' + name)
        functions = {fn['id']: fn for fn in walk(root)}
        sources[name] = {**source, 'source': root['source'], 'functions': {
            fn: {'constants': functions[fn]['constants'], 'listing': listing(functions[fn])}
            for fn in ids}}
    objective_path = ROOT / 'outputs/df-local-server/protocol/native_quest_objectives.json'
    objective_data = objective_path.read_bytes()
    objectives = json.loads(objective_data)
    bounds = [{key: row[key] for key in ('source_row', 'serialized_offset', 'ObjectiveID',
                                       'Type', 'Param1', 'RequiredCount')}
              for row in objectives['objectives'] if row['Type'] == 21]
    migration = ROOT.parent / 'deltaforce-local-transfer-20260929.zip'
    with zipfile.ZipFile(migration) as archive:
        config_mentions = [entry.filename for entry in archive.infolist()
            if entry.file_size < 20000000 and entry.filename.endswith(('.json', '.py', '.md', '.txt'))
            and re.search(rb'rep_level_configs|RepLevelConfig', archive.read(entry))]
        migration_source = {'file': str(migration), 'sha256': hashlib.sha256(migration.read_bytes()).hexdigest(),
                            'entry_count': len(archive.infolist()), 'config_mentions': config_mentions}
    capture_path = ROOT / 'work/native-client-tests/1790852498680017300/keybox-registration-readonly-185.json'
    capture_bytes = capture_path.read_bytes()
    old_capture = json.loads(capture_bytes)
    table_names = [entry['name'] for entry in old_capture['config_map']['entries']]
    raw, source = installed_export(6645, 31748096, pak='pak-0-0-pakchunk1-WindowsClient.pak')
    proto_lines = listing(Reader(raw, allow_client_format1=True).function()).splitlines()
    positions = [index for index, line in enumerate(proto_lines) if 'RepLevelConfig' in line]
    sources['common_pb.lua'] = {**source, 'source': '@common_pb.lua', 'function': '0',
        'record_declaration_instructions': proto_lines[min(positions):max(positions) + 2],
        'meaning': 'Declares only level/score integer fields. Zero values are protobuf defaults, '
            'not source-authentic curve rows.'}
    sweep_path = ROOT / 'work/evidence/reputation-all-readable-archive-search-20261019.log'
    sweep = None
    if sweep_path.exists():
        sweep_bytes = sweep_path.read_bytes()
        sweep_lines = sweep_bytes.decode('utf-8').splitlines()
        summary_positions = {parts[1]: (int(parts[3]), int(parts[4]))
                             for line in sweep_lines if line.startswith('SUMMARY ')
                             for parts in [line.split()]}
        swept = {name for name, (position, limit) in summary_positions.items() if position == limit}
        archives = {path.name for path in (game_paths()[0] / 'DeltaForce/Content/Paks').glob('*.pak')
                    if 'optional' not in path.name and 'uhd' not in path.name}
        sweep = {'file': str(sweep_path), 'sha256': hashlib.sha256(sweep_bytes).hexdigest(),
                 'completed_archive_count': len(swept), 'expected_archive_count': len(archives),
                 'complete': swept == archives, 'content_hits': [line for line in sweep_lines
                    if line.startswith('CONTENT_HIT ')],
                 'limits': ['Encrypted payloads are skipped.',
                            'Uncompressed payload size is capped at100000000 bytes.',
                            'Optional/UHD archives are excluded.']}
    quest_catalog_path = ROOT / 'outputs/df-local-server/protocol/native_quest_catalog.json'
    quest_catalog_bytes = quest_catalog_path.read_bytes()
    quest_catalog = json.loads(quest_catalog_bytes)
    referenced_rewards = {value for row in quest_catalog['quests'] for value in row['RewardList']}
    reward_groups = {}
    for row in quest_catalog['rewards']:
        if row['Type'] == 4:
            reward_groups.setdefault(str(row['ItemID']), []).append(row)
    reward_profile = {'catalog_sha256': hashlib.sha256(quest_catalog_bytes).hexdigest(),
        'source': quest_catalog['sources']['rewards'], 'reward_type': 4,
        'all_rows_referenced_by_quests': all(row['RewardID'] in referenced_rewards
                                           for rows in reward_groups.values() for row in rows),
        'items': {item: {'row_count': len(rows), 'number_total': sum(row['Number'] for row in rows),
                         'number_min': min(row['Number'] for row in rows),
                         'number_max': max(row['Number'] for row in rows)}
                  for item, rows in reward_groups.items()}}
    report = {
        'source_scope': 'Original installed client, read only; no native process used.',
        'department_curve_recovered': False,
        'department_max_level_recovered': False,
        'client_contract': {
            'request': 'CSAttributeGetConfigReq',
            'response': 'CSAttributeGetConfigRes',
            'response_repeated_field': 'rep_level_configs',
            'record_type': 'RepLevelConfig',
            'record_fields': ['level', 'score'],
            'max_level': 'length of rep_level_configs (RoleInfoServer 0.69)',
            'score_interpretation': 'Per-level increment; quality_value is cumulative. RoleInfoServer '
                '0.68 subtracts sum(score for level <= current level - 1) from quality_value.',
        },
        'rejected_substitutes': [{
            'table': 'Reputation', 'entry': 7036,
            'reason': 'Consumed by ReputationBasicData and CSGetReputationInfoReq, including '
                'score_limit, daily_award_score, star_score; department UI instead uses '
                'RoleInfoServer role quality / prestige methods.',
        }, {
            'table': 'ReputationStar', 'entry': 7040,
            'reason': 'Separate star_score / star_level behavior reputation reward data.',
        }],
        'minimum_configured_level_bound': {
            'lower_bound': max(row['RequiredCount'] for row in bounds),
            'meaning': 'Original Type21 department objectives require level4 for all five main cards. '
                'This bounds the maximum below by4; it does not establish the maximum or score curve.',
            'catalog_sha256': hashlib.sha256(objective_data).hexdigest(),
            'source': objectives['source'], 'records': bounds,
        },
        'migration_bundle_search': migration_source,
        'prior_offline_configuration_cache_names': {
            'file': str(capture_path), 'sha256': hashlib.sha256(capture_bytes).hexdigest(),
            'native_pe_sha256': old_capture['native_pe_sha256'], 'entry_count': len(table_names),
            'relevant_names': [name for name in table_names if re.search(
                r'RepLevel|Reputation|RoleQuality|Prestige', name, re.I)],
            'new_native_process_reads_used': False,
        },
        'readable_archive_search': sweep,
        'department_type4_reward_profile': reward_profile,
        'numeric_shape_candidate_warning': {
            'file': 'work/evidence/reputation-numeric-curve-shape-candidates-20261019.json',
            'entry6474_status': 'unbound diagnostic candidate; forbidden as permanent department mapping',
            'entry6474_second_column': [10, 60, 180, 500],
            'consistency_check': 'If these were per-level department widths, entry into Lv4 would '
                'need 250 points, while every entire-catalog Type4 department item total is 119 or less. '
                'This is inconsistent with those quest rewards alone; other score sources are not ruled out.',
            'competing_native_schema': 'MysticalSkinCombineBaseDataRow(Class,CombineConsumeNum)',
            'binding_limit': 'Associated UAsset6473 is encrypted. Static PE hexadecimal AES-key '
                'candidates including zero did not decode it; no live reads were attempted.',
        },
        'next_source_needed': 'A source-authentic CSAttributeGetConfigRes payload, or an original '
            'backend configuration/cache that contains RepLevelConfig records. No such payload '
            'was present in the searched local text evidence or original installation Saved tree.',
        'sources': sources,
    }
    output = ROOT / 'work/evidence/reputation-department-contract-witnesses-20261019.json'
    output.write_text(json.dumps(report, ensure_ascii=True, indent=2) + '\n', encoding='utf-8')
    print('report', output)


def schema_candidates(small_numeric=False):
    path = game_paths()[0] / 'DeltaForce/Binaries/Win64/DeltaForceClient-Win64-Shipping.exe'
    with path.open('rb') as handle:
        header = handle.read(65536)
    pe = pefile.PE(data=header, fast_load=True)
    start = pe.DOS_HEADER.e_lfanew + 24 + pe.FILE_HEADER.SizeOfOptionalHeader
    sections = []
    for index in range(pe.FILE_HEADER.NumberOfSections):
        _, va, size, raw = struct.unpack_from('<4I', header, start + index * 40 + 8)
        sections.append((raw, size, pe.OPTIONAL_HEADER.ImageBase + va))
    with path.open('rb') as handle, mmap.mmap(handle.fileno(), 0, access=mmap.ACCESS_READ) as data:
        def va_to_raw(address):
            return next((raw + address - va for raw, size, va in sections if va <= address < va + size), None)

        def string(address):
            offset = va_to_raw(address)
            if offset is None:
                return None
            raw = data[offset:offset + 128].split(b'\0')[0]
            return raw.decode('ascii') if raw and all(32 <= value < 127 for value in raw) else None

        rows = []
        seen = set()
        offset = data.find(b'\x45\0\0\0')
        total = 0
        while offset >= 0:
            position = offset - 60
            if position >= 0 and position % 8 == 0 and position + 72 <= len(data):
                params = struct.unpack_from('<9Q', data, position)
                count = params[7] & 0xffffffff
                array = va_to_raw(params[6])
                name = string(params[3])
                if (params[7] >> 32 == 0x45 and 0 < count < 200 and array is not None
                        and params[5] in (4, 8, 16) and 0 < params[4] < 65536
                        and name and re.fullmatch(r'[A-Za-z][A-Za-z0-9_]*', name)):
                    properties = []
                    for pointer in struct.unpack_from('<' + 'Q' * count, data, array):
                        prop = va_to_raw(pointer)
                        if prop is None:
                            break
                        values = struct.unpack_from('<5Q', data, prop)
                        prop_name = string(values[0])
                        if not prop_name or not re.fullmatch(r'[A-Za-z][A-Za-z0-9_]*', prop_name):
                            break
                        if values[4] >> 32:
                            properties.append({'name': prop_name, 'gen_flags': values[3] & 0xffffffff,
                                               'member_offset': values[4] >> 32,
                                               'property_record_offset': prop})
                    else:
                        if position not in seen:
                            total += 1
                            seen.add(position)
                            fields = [field['name'] for field in properties]
                            target = (' '.join(fields)).lower()
                            selected = (len(properties) == 2 and all(field['gen_flags'] in (3, 4, 7)
                                        for field in properties)) if small_numeric else (
                                    re.search(r'level|lvl|rank|index', target) and
                                    re.search(r'score|experience|exp|quality|prestige|reputation', target)
                                    or re.search(r'rolequality|replevel|attributelevel', name, re.I))
                            if selected:
                                record = {'struct': name, 'params_offset': position,
                                          'size': params[4], 'fields': list(reversed(properties))}
                                rows.append(record)
                                print(name, position, [field['name'] for field in record['fields']], flush=True)
            offset = data.find(b'\x45\0\0\0', offset + 1)
        report = {'native_pe_sha256': hashlib.sha256(data).hexdigest(),
                  'registrations_examined': total, 'candidates': rows}
    output = ROOT / ('work/evidence/reputation-small-numeric-native-schemas-20261019.json'
                     if small_numeric else 'work/evidence/reputation-all-native-schema-candidates-20261019.json')
    output.write_text(json.dumps(report, ensure_ascii=True, indent=2) + '\n', encoding='utf-8')
    print('report', output, 'registrations', total)


def archive_candidates(resume=False):
    import scan_weapon_tables as scanner
    import sys

    needles = (b'RepLevelConfig', b'rep_level_configs', b'repLevelConfigs', b'RepLevel',
               b'RoleQualityConfig', b'100002_DescriptionQuest', b'100002_DescriptionUsage',
               b'100002_UsageList', b'100001_DescriptionQuest')

    class LiteralSearch:
        @staticmethod
        def search(raw):
            return any(needle in raw for needle in needles)

    class RegexProxy:
        findall = staticmethod(re.findall)
        IGNORECASE = re.IGNORECASE

        @staticmethod
        def compile(pattern, flags=0):
            return LiteralSearch() if isinstance(pattern, bytes) else re.compile(pattern, flags)

    output = ROOT / 'work/evidence/reputation-all-readable-archive-search-20261019.log'

    class Tee:
        def __init__(self, stream, log):
            self.stream, self.log = stream, log

        def write(self, value):
            self.log.write(value)
            self.stream.write(value)

        def flush(self):
            self.log.flush()
            self.stream.flush()

    saved_args, saved_stdout = sys.argv, sys.stdout
    scanner.re = RegexProxy()
    try:
        base_args = [saved_args[0], '--asset-pattern', '$^',
                     '--content-pattern', 'literal_reputation_research_terms',
                     '--max-entries', '1000000', '--max-uncompressed', '100000000']
        if resume:
            prior = output.read_text(encoding='utf-8').splitlines()
            summary_positions = {parts[1]: (int(parts[3]), int(parts[4]))
                                 for line in prior if line.startswith('SUMMARY ')
                                 for parts in [line.split()]}
            remaining = [name for name, (position, limit) in summary_positions.items()
                         if position != limit]
        else:
            remaining = [None]
        with output.open('a' if resume else 'w', encoding='utf-8') as log:
            sys.stdout = Tee(saved_stdout, log)
            for name in remaining:
                sys.argv = base_args + (['--baseline', '--pak-name', name] if name else ['--all-baseline'])
                scanner.main()
    finally:
        sys.argv, sys.stdout = saved_args, saved_stdout
    print('report', output)


def numeric_curve_candidates():
    from explore_tagged_export import read_row
    from scan_weapon_tables import decode_content, parse_entry

    path = game_paths()[0] / 'DeltaForce/Content/Paks/pak-0-0-pakchunk2-WindowsClient.pak'
    candidates = []
    with path.open('rb') as handle:
        handle.seek(-512, 2)
        tail = handle.read(512)
        marker = tail.rfind(struct.pack('<I', 0x5a6f12e1))
        _, limit = struct.unpack_from('<IQ', tail, marker + 4)
        methods = [value[:-1].decode('ascii') for value in re.findall(
            rb'(?:Oodle|Zlib|Gzip|LZ4|Zstd)\x00', tail)]
        position = number = 0
        while position < limit:
            try:
                try:
                    entry = parse_entry(handle, position, limit)
                except (ValueError, struct.error):
                    entry = parse_entry(handle, position, limit, variant='observed_permutation')
            except (ValueError, struct.error):
                aligned = (position + 2047) // 2048 * 2048
                handle.seek(position)
                if aligned >= limit or handle.read(aligned - position) != bytes(aligned - position):
                    raise ValueError('Unexpected original archive boundary')
                position = aligned
                entry = parse_entry(handle, position, limit, variant='observed_permutation')
            number += 1
            if 64 < entry['uncompressed'] <= 2 * 1024 * 1024:
                raw = decode_content(handle, position, entry, methods)
                try:
                    if raw is None:
                        raise ValueError('Unreadable export')
                    root = 29 if struct.unpack_from('<i', raw, 37)[0] == 0 else 55
                    none, instance, prefix, count = struct.unpack_from('<iiii', raw, root)
                    if instance or prefix or not 4 <= count <= 256:
                        raise ValueError('Not a small multi-row numeric curve')
                    cursor, layout, rows, signatures = root + 16, {}, [], []
                    for index in range(count):
                        start = cursor
                        tags, cursor, layout = read_row(raw, cursor + 8, none, known_types=layout)
                        layout = dict(layout)
                        if len(tags) not in (2, 3) or any(tag['metadata_bytes'] or tag['size'] not in (4, 8)
                                                        for tag in tags[:2]):
                            raise ValueError('Not two plain numeric fields')
                        if len(tags) == 3 and (tags[2]['size'] != 8 or tags[2]['metadata_bytes']):
                            raise ValueError('Inherited row key differs')
                        signature = [(tag['field'], tag['kind'], tag['size']) for tag in tags]
                        if signatures and signatures[-1] != signature:
                            raise ValueError('Numeric field order differs')
                        signatures.append(signature)
                        rows.append({'source_row': index, 'serialized_offset': start,
                                     'first': int.from_bytes(raw[tags[0]['value_start']:tags[0]['end']],
                                                             'little', signed=True),
                                     'second': int.from_bytes(raw[tags[1]['value_start']:tags[1]['end']],
                                                              'little', signed=True)})
                    if raw[cursor:] != b'\xc1\x83\x2a\x9e':
                        raise ValueError('Numeric table trailer differs')
                    order = [key for key in ('first', 'second')
                             if [row[key] for row in rows] == list(range(1, count + 1))]
                    if order:
                        record = {'status': 'diagnostic_shape_candidate_only', 'pak': path.name,
                                  'entry': number, 'pak_offset': position,
                                  'sha256': hashlib.sha256(raw).hexdigest(),
                                  'sequential_columns': order, 'signature': signatures[0], 'rows': rows}
                        candidates.append(record)
                        print(number, position, count, order, rows[:6], flush=True)
                except (ValueError, struct.error, IndexError, KeyError):
                    pass
            position = entry['next_pos']
    output = ROOT / 'work/evidence/reputation-numeric-curve-shape-candidates-20261019.json'
    output.write_text(json.dumps({'status': 'diagnostic_shape_candidates_not_proven_department_data',
                                 'candidates': candidates}, ensure_ascii=True, indent=2) + '\n',
                      encoding='utf-8')
    print('report', output)


def candidate_header():
    from Crypto.Cipher import AES
    from extract_operator_avatar_catalog import name_map
    from scan_weapon_tables import parse_entry

    base = game_paths()[0]
    pak_path = base / 'DeltaForce/Content/Paks/pak-0-0-pakchunk2-WindowsClient.pak'
    selected = {}
    with pak_path.open('rb') as handle:
        handle.seek(-512, 2)
        tail = handle.read(512)
        marker = tail.rfind(struct.pack('<I', 0x5a6f12e1))
        _, limit = struct.unpack_from('<IQ', tail, marker + 4)
        position = number = 0
        while position < limit and number < 6475:
            try:
                try:
                    entry = parse_entry(handle, position, limit)
                except (ValueError, struct.error):
                    entry = parse_entry(handle, position, limit, variant='observed_permutation')
            except (ValueError, struct.error):
                aligned = (position + 2047) // 2048 * 2048
                handle.seek(position)
                if aligned >= limit or handle.read(aligned - position) != bytes(aligned - position):
                    raise ValueError('Unexpected original archive boundary')
                position = aligned
                entry = parse_entry(handle, position, limit, variant='observed_permutation')
            number += 1
            if 6471 <= number <= 6475:
                print(number, position, {key: entry[key] for key in ('flags', 'method', 'compressed',
                                                                  'uncompressed', 'header_size')})
                selected[number] = (position, entry)
            position = entry['next_pos']
        position, entry = selected[6473]
        handle.seek(position + entry['header_size'])
        encrypted = handle.read((entry['compressed'] + 15) // 16 * 16)
    result = {'pak': pak_path.name, 'entry': 6473, 'pak_offset': position,
              'encrypted': bool(entry['flags'] & 1), 'compression_method_index': entry['method'],
              'key_candidates_tried': 0, 'header_decoded': False}
    if entry['flags'] & 1 and not entry['method']:
        pe_path = base / 'DeltaForce/Binaries/Win64/DeltaForceClient-Win64-Shipping.exe'
        with pe_path.open('rb') as handle, mmap.mmap(handle.fileno(), 0, access=mmap.ACCESS_READ) as data:
            candidates = [(None, bytes(32))]
            candidates.extend((match.start(), bytes.fromhex(match.group().decode('ascii')))
                              for match in re.finditer(rb'(?<![0-9A-Fa-f])[0-9A-Fa-f]{64}(?![0-9A-Fa-f])', data))
            for offset, key in candidates:
                result['key_candidates_tried'] += 1
                if AES.new(key, AES.MODE_ECB).decrypt(encrypted[:16])[:4] != b'\xc1\x83\x2a\x9e':
                    continue
                raw = AES.new(key, AES.MODE_ECB).decrypt(encrypted)[:entry['uncompressed']]
                names = name_map(raw)
                result.update({'header_decoded': True, 'key_source_offset': offset,
                               'header_sha256': hashlib.sha256(raw).hexdigest(), 'names': names})
                destination = ROOT / 'work/evidence/reputation-candidate6473-header-20261019.uasset'
                destination.write_bytes(raw)
                break
    output = ROOT / 'work/evidence/reputation-candidate6474-header-binding-20261019.json'
    output.write_text(json.dumps(result, ensure_ascii=True, indent=2) + '\n', encoding='utf-8')
    print('report', output, result)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--show-lua')
    parser.add_argument('--functions', nargs='+', default=[])
    parser.add_argument('--native-reputation', action='store_true')
    parser.add_argument('--typed-reputation', action='store_true')
    parser.add_argument('--witnesses', action='store_true')
    parser.add_argument('--schema-candidates', action='store_true')
    parser.add_argument('--archive-candidates', action='store_true')
    parser.add_argument('--archive-resume', action='store_true')
    parser.add_argument('--numeric-curves', action='store_true')
    parser.add_argument('--small-numeric-schemas', action='store_true')
    parser.add_argument('--candidate-header', action='store_true')
    args = parser.parse_args()
    if args.candidate_header:
        candidate_header()
    elif args.small_numeric_schemas:
        schema_candidates(small_numeric=True)
    elif args.numeric_curves:
        numeric_curve_candidates()
    elif args.archive_resume:
        archive_candidates(resume=True)
    elif args.archive_candidates:
        archive_candidates()
    elif args.schema_candidates:
        schema_candidates()
    elif args.witnesses:
        witnesses()
    elif args.typed_reputation:
        typed_reputation()
    elif args.native_reputation:
        native_reputation()
    elif args.show_lua:
        show_lua(args.show_lua, args.functions)
    else:
        scan_lua()


if __name__ == '__main__':
    main()
