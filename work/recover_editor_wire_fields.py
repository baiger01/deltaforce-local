"""Static register provenance for generated Lua protobuf codec metadata.

Does not execute chunks. Exports field metadata only. A field is accepted only
when independent encode and decode instruction sequences agree on its name,
number and helper category. Unknown sequences remain unresolved.
"""
from pathlib import Path
from collections import Counter
import json
import re
from lua53_reader import CLIENT_OPS, instruction

ROOT = Path(__file__).resolve().parent.parent
IDENT = re.compile(r'[A-Za-z_][A-Za-z_0-9]*\Z')

def exports(fn):
    regs, found = {}, {}
    def rk(v):
        return fn['constants'][v & 255] if v & 256 else regs.get(v)
    for word in fn['code']:
        i = instruction(word)
        op = CLIENT_OPS[i['op']]
        a, b, c, bx = (i[x] for x in ('a', 'b', 'c', 'bx'))
        if op == 'LOADK':
            regs[a] = fn['constants'][bx]
        elif op == 'CLOSURE':
            regs[a] = ('closure', bx)
        elif op == 'MOVE':
            regs[a] = regs.get(b)
        elif op == 'SETTABLE':
            key, value = rk(b), rk(c)
            if isinstance(value, tuple) and value[0] == 'closure' and isinstance(key, str):
                found[key] = fn['children'][value[1]]
        elif op in ('GETTABLE', 'GETTABUP', 'GETUPVAL', 'NEWTABLE', 'CALL'):
            regs.pop(a, None)
    return found

def fields(fn, direction):
    regs, records = {}, []
    current_field, last_array_field, active_read = None, None, None
    def rk(v):
        return ('constant', fn['constants'][v & 255]) if v & 256 else regs.get(v)
    def constant(v):
        return v[1] if isinstance(v, tuple) and v[0] == 'constant' else None
    for pc, word in enumerate(fn['code'], 1):
        i = instruction(word)
        op = CLIENT_OPS[i['op']]
        a, b, c, bx = (i[x] for x in ('a', 'b', 'c', 'bx'))
        if op == 'LOADK':
            regs[a] = ('constant', fn['constants'][bx])
        elif op == 'LOADBOOL':
            regs[a] = ('constant', bool(b))
        elif op == 'MOVE':
            regs[a] = regs.get(b)
        elif op == 'GETTABUP':
            regs[a] = ('path', constant(rk(c)))
        elif op == 'GETTABLE':
            key = constant(rk(c))
            owner = regs.get(b)
            if b == 0 and isinstance(key, str) and IDENT.fullmatch(key):
                current_field = key
                regs[a] = ('field', key)
            elif owner == ('path', 'pb') and isinstance(key, str):
                regs[a] = ('path', key)
                if direction == 'decode' and key.startswith('pb_') and key.endswith('Decode') and active_read is not None:
                    records[active_read]['nested_candidates'].add(key[3:-6])
                if direction == 'encode' and key.startswith('pb_') and key.endswith('Encode'):
                    candidates = [r for r in records if r.get('name') == current_field and r['helper'] == 'addsubmsg']
                    if candidates:
                        candidates[-1]['nested_candidates'].add(key[3:-6])
            else:
                regs.pop(a, None)
        elif op == 'SELF':
            helper = constant(rk(c))
            regs[a + 1] = regs.get(b)
            regs[a] = ('method', helper, current_field)
        elif op == 'SETTABLE':
            key, value = constant(rk(b)), rk(c)
            if direction == 'decode' and a == 1 and isinstance(key, str) and IDENT.fullmatch(key):
                if isinstance(value, tuple) and value[0] == 'read':
                    records[value[1]]['name'] = key
                elif isinstance(value, tuple) and value[0] == 'table':
                    last_array_field = key
        elif op == 'NEWTABLE':
            regs[a] = ('table', pc)
        elif op == 'CALL':
            target = regs.get(a)
            if isinstance(target, tuple) and target[0] == 'method':
                helper = target[1]
                prefix = 'get' if direction == 'decode' else 'add'
                number = constant(regs.get(a + 2))
                if isinstance(helper, str) and helper.startswith(prefix) and type(number) is int and 0 < number < (1 << 29):
                    record = {'name': target[2] if direction == 'encode' else None,
                              'number': number, 'helper': helper, 'instruction': pc,
                              'nested_candidates': set()}
                    if direction == 'decode' and helper.endswith('ary'):
                        record['name'] = last_array_field
                    records.append(record)
                    active_read = len(records) - 1
                    if direction == 'decode':
                        regs[a] = ('read', active_read)
                    else:
                        regs[a] = ('writer', active_read)
                    continue
            if isinstance(target, tuple) and target[0] == 'path' and isinstance(target[1], str):
                path = target[1]
                if direction == 'decode' and path.startswith('pb_') and path.endswith('Decode'):
                    read = regs.get(a + 1)
                    if isinstance(read, tuple) and read[0] == 'read':
                        records[read[1]]['nested_candidates'].add(path[3:-6])
                        regs[a] = read
                        continue
                if direction == 'encode' and path.startswith('pb_') and path.endswith('Encode'):
                    candidates = [r for r in records if r.get('name') == current_field and r['helper'] == 'addsubmsg']
                    if candidates:
                        candidates[-1]['nested_candidates'].add(path[3:-6])
            if c == 0:
                regs = {r: v for r, v in regs.items() if r < a}
            elif c > 1:
                for r in range(a, a + c - 1):
                    regs.pop(r, None)
        elif op in ('GETUPVAL', 'CLOSURE', 'VARARG'):
            regs.pop(a, None)
        elif op == 'LOADNIL':
            for r in range(a, a + b + 1):
                regs.pop(r, None)
    for record in records:
        record['nested_candidates'] = sorted(record['nested_candidates'])
    return records

def recover_module(row):
    fn = json.loads((ROOT / 'work/evidence/carved_lua' / (row['sha256'] + '.json')).read_text(encoding='utf-8'))
    functions = exports(fn)
    messages = {}
    for name, child in functions.items():
        match = re.fullmatch(r'pb_(\w+)(Encode|Decode)', name)
        if match:
            messages.setdefault(match[1], {})[match[2].lower()] = child
    recovered = []
    for name, pair in sorted(messages.items()):
        if set(pair) != {'encode', 'decode'}:
            continue
        enc, dec = fields(pair['encode'], 'encode'), fields(pair['decode'], 'decode')
        by_number = {}
        for value in enc:
            by_number.setdefault(value['number'], []).append(value)
        matched, unresolved = [], []
        for value in dec:
            candidates = by_number.get(value['number'], [])
            expected = 'add' + value['helper'][3:].removesuffix('ary')
            expected = 'addbuffer' if expected == 'addbytes' else expected
            accepted_helpers = {expected}
            if value['helper'].removesuffix('ary') == 'getstr':
                accepted_helpers.add('addbuffer')
            agree = [v for v in candidates if v['name'] == value['name'] and v['name'] is not None and v['helper'] in accepted_helpers]
            if len(agree) != 1:
                unresolved.append(value)
                continue
            e = agree[0]
            nested = sorted(set(e['nested_candidates']) & set(value['nested_candidates']))
            item = {'name': value['name'], 'number': value['number'],
                    'codec_category': 'buffer' if e['helper'] == 'addbuffer' else value['helper'][3:].removesuffix('ary'),
                    'repeated': value['helper'].endswith('ary'),
                    'encode_helper': e['helper'], 'decode_helper': value['helper'],
                    'encode_instruction': e['instruction'], 'decode_instruction': value['instruction'],
                    'nested_type': nested[0] if len(nested) == 1 else None}
            if item['codec_category'] == 'submsg' and item['nested_type'] is None:
                unresolved.append(value)
            else:
                matched.append(item)
        recovered.append({'name': name, 'source': row['source_name'], 'source_sha256': row['sha256'],
                          'encode_function_id': pair['encode']['id'], 'decode_function_id': pair['decode']['id'],
                          'fields': matched, 'unresolved_fields': unresolved,
                          'unpaired_encode_calls': [e for e in enc if not any(e['number'] == f['number'] and e['name'] == f['name'] for f in matched)],
                          'encode_field_calls': len(enc), 'decode_field_calls': len(dec),
                          'all_observed_field_calls_matched': not unresolved and len(matched) == len(enc) == len(dec)})
    return recovered

def main():
    report = json.loads((ROOT / 'outputs/df-local-server/protocol/pak_baseline_lua_probe.json').read_text(encoding='utf-8'))
    rows = [r for r in report['recovered_lua_metadata'] if str(r.get('source_name', '')).endswith('_editor_pb.lua')]
    recovered = [message for row in rows for message in recover_module(row)]
    result = {'scope': 'Static metadata from generated encode and decode routines; original Lua never executed',
              'original_client_interoperability_verified': False,
              'codec_wire_category_semantics_verified': False,
              'modules_examined': len(rows), 'messages': recovered,
              'limitations': ['Protocol category names are observed API helper names, not yet independently verified protobuf scalar encodings.',
                              'Matching fields do not establish account policy, request routing or an original-client connection.',
                              'Fields in unresolved_fields are excluded from usable bindings.']}
    (ROOT / 'outputs/df-local-server/protocol/generated_codec_fields.json').write_text(json.dumps(result, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')
    focus = [m for m in recovered if m['source'] in ('@cs_account_editor_pb.lua','@cs_deposit_editor_pb.lua','@cs_quest_editor_pb.lua')]
    print(json.dumps({'modules': len(rows), 'messages': len(recovered),
                      'fully_matched_messages': sum(m['all_observed_field_calls_matched'] for m in recovered),
                      'matched_fields': sum(len(m['fields']) for m in recovered),
                      'unresolved_fields': sum(len(m['unresolved_fields']) for m in recovered),
                      'focus': [{'source': source, 'messages': sum(m['source'] == source for m in focus),
                                 'fully_matched': sum(m['source'] == source and m['all_observed_field_calls_matched'] for m in focus)}
                                for source in sorted({m['source'] for m in focus})]}, indent=2))

if __name__ == '__main__':
    main()
