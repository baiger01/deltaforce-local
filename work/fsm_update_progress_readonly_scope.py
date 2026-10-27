"""Two bounded non-atomic FSM update samples; no calls, writes or flag repairs."""
import hashlib
import json
import math
from pathlib import Path
import struct
import time

from fsm_character_readiness_scope import ROOT, CLIENT, SIGNATURE, source_record, CAPTURE, _sealed

SOURCE = 'work/evidence/skill-flow-research-20261020-v1/native-fsm-update-progress-observation-manifest-v1.json'
SOURCE_SHA256 = '2982d310ad43fc368ece44b99f1992015cf0d9c31b6672c75d69b1e7b4527ace'
TICK_SOURCE = 'work/evidence/skill-flow-research-20261020-v1/native-primary-tick-function-state-v1.json'
TICK_SHA256 = '162c5ab6508eaf88881b8e3035357ddd977ca8af6df667292a24350fe2eb0278'


def source_qualification():
    raw = (ROOT / SOURCE).read_bytes()
    if hashlib.sha256(raw).hexdigest() != SOURCE_SHA256:
        raise ValueError('The FSM update observation manifest changed')
    document = json.loads(raw)
    if (document['client_sha256'] != CLIENT or document['process_access'] is not False
            or document['native_methods_invoked'] is not False or len(document['fields']) != 16):
        raise ValueError('The bounded FSM update observation source differs')
    documents, pins = {}, {SOURCE: SOURCE_SHA256}
    for row in document['source_pins']:
        relative, digest = row['path'], row['sha256']
        path = (ROOT / relative).resolve(strict=True)
        if not path.is_relative_to(ROOT.resolve()):
            raise ValueError('An update observation source escaped the checkout')
        raw = path.read_bytes()
        if hashlib.sha256(raw).hexdigest() != digest:
            raise ValueError('The update observation source changed: ' + relative)
        documents[relative], pins[relative] = json.loads(raw), digest
    keys = set()
    for row in document['fields']:
        key = row['scope'], row['label']
        if (key in keys or row['scope'] not in ('instance', 'root', 'main_init', 'component')
                or (row['type'], row['bytes']) not in (('float32', 4), ('raw_bool', 1), ('raw_bytes', 104))):
            raise ValueError('The fixed FSM update field extent differs')
        keys.add(key)
        instructions = [i for f in documents[row['source_path']].get('functions', [])
                        for i in f['instructions'] if i['rva'] == row['consumer_rva']]
        if len(instructions) != 1 or instructions[0]['bytes'] != row['consumer_bytes']:
            raise ValueError('The actual native update field anchor differs')
    from observe_fsm_active_inline_followup import extra_sources
    pins.update(extra_sources()[1])
    raw = (ROOT / TICK_SOURCE).read_bytes()
    if hashlib.sha256(raw).hexdigest() != TICK_SHA256:
        raise ValueError('The native tick enabling source changed')
    instructions = {i['rva']: i for f in json.loads(raw)['functions'] for i in f['instructions']}
    if instructions['0x130364b9']['bytes'] != '4088710d':
        raise ValueError('The native tick enable write differs')
    pins[TICK_SOURCE] = TICK_SHA256
    pins['work/fsm_update_progress_readonly_scope.py'] = hashlib.sha256(Path(__file__).read_bytes()).hexdigest()
    return document, pins


def _field(record, name):
    matches = [dict(f, declaring_class=d['class_name'])
               for d in record['declarations'] for f in d['fields'] if f['name'] == name]
    if len(matches) != 1:
        raise ValueError('One exact current update field declaration is required: ' + name)
    return matches[0]


def _same_field(record, frozen, name):
    field, expected = _field(record, name), _field(frozen, name)
    if any(field.get(k) != expected.get(k) for k in SIGNATURE):
        raise ValueError('The exact update field declaration changed: ' + name)
    return field


def observe_progress(*, read, instance, instance_record, component, component_record,
                     invariant_read=None, clock=time.monotonic, wait=time.sleep):
    document, _ = source_qualification()
    frozen = source_record()
    root = _same_field(instance_record, frozen, 'RootStateMachine')
    from observe_fsm_active_inline_followup import extra_sources, GRAPH
    graph = extra_sources()[0][GRAPH]
    names = [n['name'] for n in graph['nodes'] if any(
        p['name'] == 'NodeName' and p['value'] == 'MainInit' for p in n['properties'])]
    if len(names) != 1:
        raise ValueError('One exact cooked MainInit declaration is required')
    main = _same_field(instance_record, frozen, names[0])
    frozen_component, = [o for o in _sealed(CAPTURE)['objects']
                         if o['class_path'] == component_record['class_path']]
    tick = _same_field(component_record, frozen_component, 'PrimaryComponentTick')
    active = _same_field(component_record, frozen_component, 'bIsActive')
    if (root['storage_offset'], root['element_bytes'], tick['storage_offset'],
            tick['element_bytes'], active['storage_offset'], active['element_bytes']) != (
            0x220, 0x358, 0x30, 104, 0xcb, 1):
        raise ValueError('The exact inline root or component tick declaration differs')
    bases = dict(instance=instance, component=component,
                 root=instance + root['storage_offset'], main_init=instance + main['storage_offset'])
    if any(type(value) is not int or not 0x10000 <= value < (1 << 47) - 0x10000
           for value in bases.values()):
        raise ValueError('A canonical current update scope address is required')
    if instance == component or not callable(read) or not callable(clock) or not callable(wait):
        raise ValueError('Distinct current instance/component and bounded read callbacks are required')
    fields = document['fields']
    for row in fields:
        limit = (root['element_bytes'] if row['scope'] == 'root' else
                 main['element_bytes'] if row['scope'] == 'main_init' else 0x1000)
        if type(row['offset']) is not int or not 0 <= row['offset'] <= limit - row['bytes']:
            raise ValueError('An update field escaped its exact inline declaration')
    invariant_read = invariant_read or read
    def check_inline_owners():
        for name in ('root', 'main_init'):
            raw = invariant_read(bases[name] + 0xd8, 8)
            if raw != struct.pack('<Q', instance):
                raise ValueError('A current inline update node belongs to another instance')
    check_inline_owners()
    samples = []
    for index in range(2):
        if index:
            wait(.5)
        sample = {key: {} for key in bases}
        sample['monotonic_time'] = clock()
        for row in fields:
            raw = read(bases[row['scope']] + row['offset'], row['bytes'])
            if type(raw) is not bytes or len(raw) != row['bytes']:
                raise ValueError('The bounded update field read is incomplete')
            value = dict(raw_hex=raw.hex(), storage_offset=row['offset'])
            if row['type'] == 'float32':
                number, = struct.unpack('<f', raw)
                if not math.isfinite(number):
                    raise ValueError('A native update timer is not finite')
                value['value'] = number
            elif row.get('bool_mask') == 0x20 and (row['scope'], row['offset']) == ('component', 0xcb):
                value.update(value=bool(raw[0] & 0x20), native_bool_mask=0x20)
            elif row['type'] == 'raw_bool':
                if raw not in (b'\x00', b'\x01'):
                    raise ValueError('A native update boolean is not canonical')
                value['value'] = raw == b'\x01'
            sample[row['scope']][row['label']] = value
        tick_raw = bytes.fromhex(sample['component']['PrimaryComponentTick']['raw_hex'])
        sample['component']['PrimaryComponentTick']['enable_byte_hex'] = tick_raw[13:14].hex()
        samples.append(sample)
    check_inline_owners()
    elapsed = samples[1]['monotonic_time'] - samples[0]['monotonic_time']
    if not math.isfinite(elapsed) or elapsed < 0:
        raise ValueError('The bounded observation clock is invalid')
    changed = [row['scope'] + '.' + row['label'] for row in fields
               if samples[0][row['scope']][row['label']]['raw_hex'] !=
                  samples[1][row['scope']][row['label']]['raw_hex']]
    return dict(samples=samples, elapsed_seconds=elapsed, changed_fields=changed,
        snapshot_atomic=False, mutable_fields_added_to_invariant_facts=False,
        inline_owner_fields_rechecked=True, primary_tick_internal_data_followed=False,
        native_methods_invoked=False, process_memory_written=False, packets_sent=False,
        gameplay_execution_inferred=False, outer_identity_and_binding_recheck_required=True)
