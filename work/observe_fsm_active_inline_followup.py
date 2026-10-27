"""Independent read-only follow-up; the running cohort and server stay unchanged."""
import argparse
import ctypes
import hashlib
import json
import mmap
from pathlib import Path
import struct

from fsm_character_readiness_scope import ROOT, CLIENT, SIGNATURE, source_record, read_root_activity
from fsm_readonly_scope import array_header
from observe_owned_fsm_metadata import observe as previous_observe
from observe_owned_gameplay_metadata import write_exclusive_report, owned_trial_identity
from observe_portable_map_runtime import request_elevation, validate_source
from offline_received_packet_xrefs import ImmutableImage
from skill_rpc_layout_readonly_scope_v2 import private_function

FOLDER = 'work/evidence/skill-flow-research-20261020-v1/'
GRAPH = FOLDER + 'authored-main-fsm-graph.json'
PINS = {
    GRAPH: '2e2b74ec1c122deebabff271984caba88316220f43cd21fbb03953c6e7691e85',
    FOLDER + 'native-local-fsm-active-collection-v1.json':
        '10429dc31562c1e322dd95025aa0e7be0816d467556679c02a00736d830427ba',
    FOLDER + 'native-local-fsm-sparse-data-getter-v1.json':
        '7e4cb8a7528d743b8712949583d75949bd775c0c16aeccdbf3379e769f5de8ca',
    FOLDER + 'native-local-fsm-node-callback-gates-v1.json':
        'cd81d56efccc6773e720862838043c95cfa7b23a7669c57814933bd25c816a52',
}


def extra_sources():
    documents = {}
    pins = dict(PINS)
    for relative, digest in PINS.items():
        raw = (ROOT / relative).read_bytes()
        if hashlib.sha256(raw).hexdigest() != digest:
            raise ValueError('Independent active-node source changed: ' + relative)
        documents[relative] = json.loads(raw)
    graph = documents[GRAPH]
    for row in graph['source_files']:
        relative = row['relative_path']
        if hashlib.sha256((ROOT / relative).read_bytes()).hexdigest() != row['sha256']:
            raise ValueError('The cooked graph asset changed')
        pins[relative] = row['sha256']
    instructions = {i['rva']: i for key, document in documents.items() if key != GRAPH
                    for function in document['functions'] for i in function['instructions']}
    for at, expected in (
            ('0xd968d0', '488b01'), ('0xd968d3', 'c3'),
            ('0xd9f984', 'ff15cee47f1c'), ('0xd9f991', '48c1e604'),
            ('0xd9f9b6', '488b0e')):
        if instructions[at]['bytes'] != expected:
            raise ValueError('The native sparse-data getter or element stride changed')
    pins['work/observe_fsm_active_inline_followup.py'] = hashlib.sha256(Path(__file__).read_bytes()).hexdigest()
    return documents, pins


def read_active_inline(read, instance, record):
    result = read_root_activity(read, instance, record)
    documents, _ = extra_sources()
    if result['referenced_instance_nonnull']:
        return dict(result, inline_active_scope='referenced_instance_not_followed')
    if result['active_set_free']:
        return dict(result, inline_active_scope='sparse_holes_not_supported')
    count = result['active_set_slots']
    if count > 32:
        raise ValueError('The independent active-node count exceeds its fixed read scope')
    header = read(instance + 0x480, 16)
    checked = array_header(header)
    if checked['count'] != count:
        raise ValueError('The active-node count changed between qualified reads')
    data, = struct.unpack('<Q', header[:8])
    entries = read(data, count * 16) if count else b''
    before = {f['name']: dict(f, declaring_class=d['class_name'])
              for d in source_record()['declarations'] for f in d['fields']}
    cooked = {n['name']: n for n in documents[GRAPH]['nodes']}
    rows, seen = [], set()
    for index in range(count):
        node, = struct.unpack_from('<Q', entries, index * 16)
        candidates = [dict(f, declaring_class=d['class_name'])
                      for d in record['declarations'] for f in d['fields']
                      if instance + f['storage_offset'] == node and f['name'] in cooked]
        if len(candidates) != 1 or node in seen:
            raise ValueError('An active pointer is outside the exact current inline declarations')
        field = candidates[0]
        source = before[field['name']]
        authored = cooked[field['name']]
        if (any(field.get(k) != source.get(k) for k in SIGNATURE) or
                field['field_vtable_rva'] != 0x15a86f40 or field['element_bytes'] < 0x138 or
                authored['meta'] not in (['SMState'], ['SMStateMachine'])):
            raise ValueError('The selected current inline state declaration differs')
        owner, = struct.unpack('<Q', read(node + 0xd8, 8))
        if owner != instance:
            raise ValueError('The actual inline state has a different owning instance')
        active = read(node + 0x132, 1)
        if active not in (b'\x00', b'\x01'):
            raise ValueError('The actual inline active boolean is not canonical')
        labels = [p['value'] for p in authored['properties'] if p['name'] == 'NodeName']
        if len(labels) != 1 or type(labels[0]) is not str:
            raise ValueError('One exact cooked state label is required')
        rows.append(dict(field_name=field['name'], storage_offset=field['storage_offset'],
            cooked_name=labels[0], local_active=active == b'\x01', owner_matches=True))
        seen.add(node)
    return dict(result, inline_active_scope='observed_no_hole_inline_states',
        inline_active_states=rows, node_instances_followed=False,
        gameplay_execution_inferred=False)


def observe(game_root, trial_report):
    _, pins = extra_sources()
    exe, _ = validate_source(game_root)
    with exe.open('rb') as stream, mmap.mmap(stream.fileno(), 0, access=mmap.ACCESS_READ) as data:
        if ImmutableImage(data).read(0x1d59de58, 8).hex() != 'd068d94001000000':
            raise ValueError('The immutable sparse-data getter dispatch changed')
    scoped = private_function(previous_observe, read_root_activity=read_active_inline)
    result = scoped(game_root, trial_report)
    if extra_sources()[1] != pins:
        raise ValueError('Independent sources changed before publication')
    result['independent_active_node_sources'] = pins
    result['frozen_server_and_cohort_sources_modified'] = False
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--game-root', type=Path, required=True)
    parser.add_argument('--trial-report', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--request-uac', action='store_true')
    args = parser.parse_args()
    output = args.output.resolve()
    if output.exists() or not output.is_relative_to((ROOT / 'work').resolve()):
        parser.error('Use an exclusive project work output')
    owned_trial_identity(json.loads(args.trial_report.read_bytes()), args.game_root)
    extra_sources()
    if args.request_uac and not ctypes.windll.shell32.IsUserAnAdmin():
        request_elevation(['-B', str(Path(__file__).resolve()), '--game-root', str(args.game_root.resolve()),
            '--trial-report', str(args.trial_report.resolve()), '--output', str(output)], output)
        result = json.loads(output.read_bytes())
    else:
        try:
            result = observe(args.game_root, args.trial_report)
        except Exception as error:
            result = dict(status='refused', reason=str(error), process_memory_written=False,
                native_methods_invoked=False, packets_sent=False)
        write_exclusive_report(output, result)
    print(json.dumps(dict(status=result['status'], reason=result.get('reason'), output=str(output))))


if __name__ == '__main__':
    main()
