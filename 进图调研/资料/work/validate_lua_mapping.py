from pathlib import Path
import json,argparse
from lua53_reader import walk,instruction,CLIENT_OPS

args=argparse.ArgumentParser();args.add_argument('--baseline',action='store_true');args=args.parse_args()
workspace=Path(__file__).resolve().parent.parent
base=workspace/'work/evidence/lua'
inventory=json.loads((base/'inventory.json').read_text(encoding='utf-8'))
if args.baseline:
    base=workspace/'work/evidence/carved_lua'
    rows=json.loads((workspace/'outputs/df-local-server/protocol/pak_baseline_lua_probe.json').read_text(encoding='utf-8'))['recovered_lua_metadata']
    inventory=[{'module':r['source_name'],'sha256':r['sha256'],'parsed':True} for r in rows if r.get('source_name')]
checks=0;functions=0;errors=[]
for module in inventory:
    if not module['parsed']:continue
    filename=module['sha256'] if args.baseline else module['module']
    root=json.loads((base/(filename+'.json')).read_text(encoding='utf-8'))
    for fn in walk(root):
        functions+=1
        for pc,word in enumerate(fn['code'],1):
            d=instruction(word);op=CLIENT_OPS.get(d['op']);a,b,c,bx=(d[k] for k in ['a','b','c','bx']);error=[]
            if op=='LOADK' and bx>=len(fn['constants']):error.append('constant index')
            if op=='CLOSURE' and bx>=len(fn['children']):error.append('child index')
            if op in ('GETUPVAL','GETTABUP','SETUPVAL') and b>=len(fn['upvalues']):error.append('upvalue index')
            if op=='SETTABUP' and a>=len(fn['upvalues']):error.append('upvalue index')
            if op in ('JMP','FORLOOP','FORPREP','TFORLOOP') and not 1<=pc+1+d['sbx']<=len(fn['code'])+1:error.append('jump bounds')
            if op=='LOADKX' and (pc>=len(fn['code']) or CLIENT_OPS.get(fn['code'][pc]&63)!='EXTRAARG'):error.append('extended constant')
            if op in ('GETTABLE','GETTABUP','SELF'):
                if c&256 and (c&255)>=len(fn['constants']):error.append('RK constant')
            if op in ('SETTABLE','SETTABUP','ADD','SUB','MUL','MOD','POW','DIV','IDIV','BAND','BOR','BXOR','SHL','SHR','EQ','LT','LE'):
                for v in (b,c):
                    if v&256 and (v&255)>=len(fn['constants']):error.append('RK constant')
            checks+=1
            if error:errors.append({'module':module['module'],'function':fn['id'],'instruction':pc,'opcode':op,'errors':error})
result={'files':len(inventory),'functions':functions,'instruction_checks':checks,'invalid_instructions':len(errors),'errors':errors[:50],'verification':'Static operand and branch consistency only; no original scripts executed'}
destination=workspace/'outputs/df-local-server/protocol/baseline_lua_mapping_validation.json' if args.baseline else base/'mapping_validation.json'
destination.write_text(json.dumps(result,indent=2),encoding='utf-8')
print(json.dumps(result,indent=2))
