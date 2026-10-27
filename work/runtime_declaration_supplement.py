"""Exact same-build field variants from a completed, rechecked owned cohort."""
import argparse
import hashlib
import json
from pathlib import Path

ROOT=Path(__file__).resolve().parent.parent
CLIENT='4254fbe66585f260f1f9dbfc5e302887842552e7baed8939e023160a5e250be0'
SCHEMA_PATH='work/evidence/model-init-chain-20261018/native-runtime-map-vitals-declaration-supplement-v1.json'
SCHEMA_SHA256='8310a80010917a2de5ed8a1e7b0f7894743e085f5dabb030a6825144e52acf9d'
BASE='work/native-client-tests/1792328560808149500/'
SOURCES={BASE+'owned-map-marker-metadata.json':
    'ff8b2c90f7a07aa5a74351c7ada8c389a8c85c6a708fe0cf78c7e456dceed1c9',
    BASE+'owned-vitals-metadata.json':
    'f3bcb54f0ea117e894069294a39cf4732ce757e86c7b6f63eb6a7f22dded321f'}
SIGNATURE_KEYS=('declaring_class','name','storage_offset','element_bytes','array_dimension',
    'field_vtable_rva','property_flags','native_property_type','declared_native_class',
    'declared_native_class_path')


def signature(field):
    return {key:field.get(key) for key in SIGNATURE_KEYS}


def sealed_capture(relative):
    raw=(ROOT/relative).read_bytes()
    if hashlib.sha256(raw).hexdigest()!=SOURCES[relative]:
        raise ValueError('The recorded runtime declaration capture changed')
    report=json.loads(raw)
    if (report.get('client_sha256')!=CLIENT or report.get('status') not in ('observed','partial') or
            report.get('identities_and_fields_rechecked') is not True or
            report.get('process_memory_written') is not False or
            report.get('native_methods_invoked') is not False):
        raise ValueError('The recorded declaration lacks completed source/identity checks')
    return report


def derive():
    map_report=sealed_capture(BASE+'owned-map-marker-metadata.json')
    vitals_report=sealed_capture(BASE+'owned-vitals-metadata.json')
    specs=(('map_interact',map_report['root_metadata']['game_state'],'InteractSystemComponent',0x100000000a000d),
        ('map_array',next(r for r in map_report['objects'] if r['scope']=='MapInfoSystemComponent'),
            'HighValueBoxInfoArray',0x10000100000020),
        ('map_array',next(r for r in map_report['objects'] if r['scope']=='MapInfoSystemComponent'),
            'AZHighValueZoneInfoArray',0x20080100000020),
        ('map_array',next(r for r in map_report['objects'] if r['scope']=='MapInfoComp'),
            'MapQuestLocationDataArray',0x10000000000020),
        ('map_bool',next(r for r in map_report['objects'] if r['scope']=='MapInfoComp'),
            'bQuestInited',0x10000000000024),
        ('sprint_input_reference',next(r for r in vitals_report['objects']
            if r['scope']=='current_pawn.Blackboard'),'SprintComponent',0x1400000008001c))
    rows=[]
    for guard,record,name,static_flags in specs:
        fields=[dict(f,declaring_class=d['class_name']) for d in record['declarations']
                for f in d['fields'] if f['name']==name]
        if len(fields)!=1: raise ValueError('The exact runtime declaration is ambiguous: '+name)
        field=fields[0]
        hook=field['hooks']['0x90']
        if (hook['target_module_sha256']!=CLIENT or hook['identity_rechecked'] is not True or
                hook['inside_pinned_image'] is not True):
            raise ValueError('The exact runtime declaration hook differs: '+name)
        rows.append(dict(guard=guard,root_class_path=record['class_path'],signature=signature(field),
            static_source_flags=hex(static_flags),
            observed_flag_xor=hex(int(field['property_flags'],16)^static_flags),
            field_values_observed=False,wire_layout_inferred=False))
    return dict(kind='same_build_exact_runtime_declaration_supplement',version=1,client_sha256=CLIENT,
        sources=SOURCES,fields=rows,flag_masks_ignored=False,process_addresses_published=False,
        policy='Accept the entire recorded signature only under its exact guard and current root class.')


def schema_binding():
    raw=(ROOT/SCHEMA_PATH).read_bytes()
    schema=json.loads(raw)
    if (hashlib.sha256(raw).hexdigest()!=SCHEMA_SHA256 or schema.get('client_sha256')!=CLIENT or
            schema.get('kind')!='same_build_exact_runtime_declaration_supplement' or
            schema.get('sources')!=SOURCES):
        raise ValueError('The runtime declaration supplement changed')
    for relative in SOURCES: sealed_capture(relative)
    return schema


def exact_runtime_variant(guard,root_class_path,field):
    if not isinstance(root_class_path,str): return False
    return any(row['guard']==guard and row['root_class_path']==root_class_path and
        row['signature']==signature(field) for row in schema_binding()['fields'])


def source_pins():
    schema_binding()
    return {**SOURCES,SCHEMA_PATH:SCHEMA_SHA256,
        'work/runtime_declaration_supplement.py':hashlib.sha256(Path(__file__).read_bytes()).hexdigest()}


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output',required=True,type=Path)
    args=parser.parse_args()
    if args.output.exists() or not args.output.resolve().is_relative_to(ROOT/'work/evidence'):
        parser.error('Use a new evidence output')
    raw=(json.dumps(derive(),indent=2,sort_keys=True)+'\n').encode()
    with args.output.open('xb') as output: output.write(raw)
    print(json.dumps(dict(path=str(args.output),sha256=hashlib.sha256(raw).hexdigest())))
