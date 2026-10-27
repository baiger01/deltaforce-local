"""Existing weak-key layouts; serial-zero explicitly establishes no absence.

109929f0 builds index/serial, invoking10ea1680 only to allocate a missing serial.
The read-only path never performs that operation or substitutes a pointer key.
The frozen v1 implementations remain unchanged and are reused privately.
"""
import hashlib
import json
import struct
from types import FunctionType

import skill_rpc_layout_readonly_scope as previous

ROOT = previous.ROOT
TARGETS = {**previous.TARGETS, 46: 'ServerTriggerBehavior'}
KEY_SOURCE = 'work/evidence/skill-rpc-layout-v2-20261020/native-function-layout-key-construction-and-lookup-v1.json'
LAZY_SOURCE = 'work/evidence/model-init-chain-20261018/native-lazy-weak-serial-allocation-v1.json'
ENUM_SOURCE = 'work/evidence/skill-activation-authority-20261020-v1/native-skill-behavior-enum-immutable-declaration.json'
ENUM_PAIRS = 'work/evidence/skill-activation-authority-20261020-v1/native-skill-behavior-enum-name-value-pairs.json'
PINS = {
    KEY_SOURCE: '01370566a1d5772e01a3d7a6bf5592af792f29901be63a229dd3e2a4e0e7c6c5',
    LAZY_SOURCE: '46472c683408ece336601e03ec59e8532b9b92dae15c2143272baf02ed0aaa99',
    ENUM_SOURCE: '63e9791bb628847b86dfc86e28455d5af16440927202fc61b73df7a4933e6711',
    ENUM_PAIRS: 'ac5a46eea5b219573ff1db83d85d5883d0726b57c97167ca29c47ed15b08fd92',
}


def _sealed(relative):
    raw = (ROOT/relative).read_bytes()
    if hashlib.sha256(raw).hexdigest() != PINS[relative]:
        raise ValueError('The fixed native weak-key or skillbehavior source changed: '+relative)
    result = json.loads(raw)
    if result.get('client_sha256') != previous.SHIPPING_SHA256 or result.get('process_access') is not False:
        raise ValueError('A same-build offline native source is required')
    return result


def source_contract():
    contract = previous.source_contract()
    key, lazy, enum, table = (_sealed(path) for path in (KEY_SOURCE, LAZY_SOURCE, ENUM_SOURCE, ENUM_PAIRS))
    instructions = {i['rva']: (i['mnemonic'], i['operands']) for d in (key, lazy)
        for f in d['functions'] for i in f['instructions']}
    for rva, expected in {
        '0x109929fe': ('mov', 'edx, dword ptr [rdx + 0x24]'),
        '0x10992a01': ('mov', 'dword ptr [rcx], edx'),
        '0x10992a0a': ('call', '0x10ea1680'),
        '0x10992a0f': ('mov', 'dword ptr [rbx + 4], eax'),
        '0xd8cb2c': ('shr', 'r8, 0x20'),
        '0xd8cb39': ('xor', 'rbx, rdx'),
        '0xd8684b': ('cmp', 'dword ptr [rcx], eax'),
        '0xd86852': ('cmp', 'dword ptr [rcx + 4], eax'),
        '0x10ea16c6': ('mov', 'eax, dword ptr [rdi + 0x14]'),
        '0x10ea16d7': ('lock xadd', 'dword ptr [rsi + 0x140], ebx'),
        '0x10ea171e': ('lock cmpxchg', 'dword ptr [rdi + 0x14], ebx'),
    }.items():
        if instructions.get(rva) != expected:
            raise ValueError('The native index/serial construction or lookup proof changed')
    captured = previous._sealed(previous.CAPTURE)
    skill, = [o for o in captured['objects'] if o['class_path'] == previous.SKILL_CLASS]
    row, = [f for n in skill['existing_driver_class']['cache_nodes'] for f in n['fields']
        if f['rep_index'] == 46 and f['descriptor_name'] == TARGETS[46]]
    if row['descriptor_representation'] != 1 or row['incompatible'] is not False:
        raise ValueError('The actual field46 compatible Function binding changed')
    uht = previous._sealed(previous.UHT)
    declaration, = [f for c in uht['classes'] for f in c['net_function_declarations'] if f['name'] == TARGETS[46]]
    params = {p['name']: (p['native_gen_flags'], p['native_member_offset']) for p in declaration['parameters']}
    if (declaration['function_flags'] != '0x220cc0' or declaration['native_param_bytes'] != 8 or
            params.get('Skillid') != ('0x3', '0x4') or params.get('skillbehavior') != ('0x1e', '0x0')):
        raise ValueError('The source-qualified field46 native declaration changed')
    raw, = [bytes.fromhex(r['raw_hex']) for r in table['data'] if r['rva'] == '0x16774700']
    if len(raw) != 41*16:
        raise ValueError('The immutable native ESkillBehavior name/value table changed')
    pairs = tuple(struct.iter_unpack('<Qq', raw))
    normal, = [s for s in enum['strings'] if s['text'] == 'ESkillBehavior::NormalStart']
    image_base = pairs[0][0]-int(normal['rva'], 16)
    names = {int(s['rva'], 16): s['text'] for s in enum['strings']}
    records = tuple((names.get(pointer-image_base), value) for pointer, value in pairs)
    if (tuple(value for name, value in records) != tuple(range(41)) or
            any(type(name) is not str or not name.startswith('ESkillBehavior::') for name, value in records)):
        raise ValueError('The full native enum string/value identity closure changed')
    return dict(contract, targets=[*contract['targets'], {k: row[k] for k in previous.SIGNATURE}],
        flags=dict(contract['flags'], ServerTriggerBehavior=int(declaration['function_flags'], 16)),
        key_kind='weak_object_index_and_serial', behavior_enum=records)


def source_pins():
    source_contract()
    pins = dict(previous.source_pins(), **PINS)
    for relative in ('work/skill_rpc_layout_readonly_scope_v2.py', 'work/observe_owned_skill_rpc_layouts_v2.py'):
        pins[relative] = hashlib.sha256((ROOT/relative).read_bytes()).hexdigest()
    return pins


def private_function(function, **globals_override):
    scoped = FunctionType(function.__code__, dict(function.__globals__, **globals_override),
        function.__name__, function.__defaults__, function.__closure__)
    scoped.__kwdefaults__ = dict(function.__kwdefaults__ or {})
    return scoped


def export_existing_skill_rpc_layouts(session, module_base, driver_address, existing, *,
        object_identity, _final_recheck_sink=None):
    contract = source_contract()
    scoped = private_function(previous.export_existing_skill_rpc_layouts,
        source_contract=source_contract, TARGETS=dict(TARGETS))
    result = scoped(session, module_base, driver_address, existing, object_identity=object_identity,
        _final_recheck_sink=_final_recheck_sink)
    extra_checks = []
    for row in result:
        row.update(key_kind=contract['key_kind'], weak_serial_assignment_invoked=False,
            pointer_key_substituted=False, layout_absence_established=False)
        if row['status'] == 'missing_uninitialized_native_serial':
            at, before = row['descriptor_address'], row['identity_qualification']
            raw = session.stable(at+previous.exporter.RPC_FUNCTION_FLAGS_OFFSET, 4)
            if struct.unpack('<I', raw)[0] != contract['flags'][row['function_name']]:
                raise ValueError('The serial-zero UFunction actual flags changed')
            row.update(status='existing_function_without_initialized_weak_key',
                layout_status='not_queryable_uninitialized_weak_serial',
                flags_raw_u32=struct.unpack('<I', raw)[0],
                flags_source_offset=previous.exporter.RPC_FUNCTION_FLAGS_OFFSET,
                native_weak_key_construction_would_assign_serial=True)
            extra_checks.append((at, before, raw))
        elif row['layout_table_read'] and row['layout_status'] == 'missing':
            row['layout_absence_established'] = True

    def final_recheck():
        for at, before, raw in extra_checks:
            if (object_identity(at, 'Function') != before or
                    session.read(at+previous.exporter.RPC_FUNCTION_FLAGS_OFFSET, 4) != raw):
                raise ValueError('The serial-zero Function identity or flags changed before publication')

    final_recheck()
    if _final_recheck_sink is not None:
        _final_recheck_sink.append(final_recheck)
    return result
