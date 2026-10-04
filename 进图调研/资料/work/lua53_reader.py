"""Read Lua 5.3 metadata and instructions without executing a chunk.

Format references: lua.org/source/5.3/lundump.c.html and lopcodes.h.html.
This is a local analysis reader, not a game loader or a protection patch.
"""
from pathlib import Path
import hashlib,json,re,struct
from local_game_paths import game_paths

OPS='MOVE LOADK LOADKX LOADBOOL LOADNIL GETUPVAL GETTABUP GETTABLE SETTABUP SETUPVAL SETTABLE NEWTABLE SELF ADD SUB MUL MOD POW DIV IDIV BAND BOR BXOR SHL SHR UNM BNOT NOT LEN CONCAT JMP EQ LT LE TEST TESTSET CALL TAILCALL RETURN FORLOOP FORPREP TFORCALL TFORLOOP SETLIST CLOSURE VARARG EXTRAARG'.split()
# This client's instruction IDs are permuted. The binary container is standard,
# but an opcode within 0..46 does not prove its meaning matches stock Lua.
# Mapping supported by import, constructor, assignment, request/callback and
# branch sequences across independent chunks. It must not be used to execute
# game chunks; it is an analysis overlay for this observed cache format.
CLIENT_NAMES=('MOVE SELF ADD SUB MUL MOD POW DIV IDIV BAND BOR BXOR SHL SHR UNM BNOT NOT LEN CONCAT JMP EQ LT LE TEST TESTSET CALL TAILCALL RETURN FORLOOP FORPREP TFORCALL TFORLOOP SETLIST CLOSURE LOADNIL LOADK LOADKX LOADBOOL VARARG GETUPVAL GETTABUP GETTABLE SETTABUP SETUPVAL SETTABLE NEWTABLE EXTRAARG').split()
CLIENT_OPS=dict(enumerate(CLIENT_NAMES))

class Reader:
    def __init__(self,data,*,allow_client_format1=False):
        self.data=data;self.at=0
        header=self.take(12)
        self.container_format=header[5]
        if header!=b'\x1bLua\x53\x00\x19\x93\x0d\x0a\x1a\x0a':
            if not allow_client_format1 or header!=b'\x1bLua\x53\x01\x19\x93\x0d\x0a\x1a\x0a':
                raise ValueError('Not a supported Lua 5.3 container')
        sizes=self.take(5)
        if sizes[0]!=4 or sizes[2:]!=bytes([4,8,8]) or sizes[1] not in (4,8):raise ValueError('Unsupported sizes')
        self.size_t=sizes[1]
        if self.number('<q')!=0x5678 or self.number('<d')!=370.5:raise ValueError('Endian/number check')
        self.upvalue_count=self.number('B')
    def take(self,count):
        if count<0 or count>len(self.data)-self.at:raise ValueError(f'Out of bounds at {self.at} length {count}')
        val=self.data[self.at:self.at+count];self.at+=count;return val
    def number(self,fmt):return struct.unpack(fmt,self.take(struct.calcsize(fmt)))[0]
    def count(self):
        value=self.number('<i')
        if not 0<=value<=1_000_000:raise ValueError(f'Invalid count {value} at {self.at}')
        return value
    def string(self):
        count=self.number('B')
        if count==255:count=self.number('<I' if self.size_t==4 else '<Q')
        if count==0:return None
        return self.take(count-1).decode('utf-8',errors='replace')
    def function(self,path='0',depth=0):
        if depth>60:raise ValueError('Function nesting')
        start=self.at
        source=self.string();first=self.number('<i');last=self.number('<i')
        params,vararg,stack=self.take(3)
        code_field=self.number('<I')
        code_marker=None
        if self.container_format==1 and code_field&0x80000000:
            marked=code_field&0x7fffffff
            if not 0<=marked<=1000000000:
                raise ValueError('Unsupported format 1 code marker')
            code_marker=marked
            code_field=self.number('<I')
        if code_field>1000000:raise ValueError('Invalid instruction count')
        code=[self.number('<I') for _ in range(code_field)]
        constants=[]
        for _ in range(self.count()):
            tag=self.number('B')
            if tag==0:val=None
            elif tag==1:val=bool(self.number('B'))
            elif tag==3:val=self.number('<d')
            elif tag==19:val=self.number('<q')
            elif tag in (4,20):val=self.string()
            else:raise ValueError(f'Unknown constant tag {tag} at {self.at}')
            constants.append(val)
        upvalues=[list(self.take(2)) for _ in range(self.count())]
        children=[self.function(path+'.'+str(i),depth+1) for i in range(self.count())]
        lines=[self.number('<i') for _ in range(self.count())]
        locals_=[{'name':self.string(),'start':self.number('<i'),'end':self.number('<i')} for _ in range(self.count())]
        upnames=[self.string() for _ in range(self.count())]
        return {'id':path,'offset':start,'source':source,'first_line':first,'last_line':last,'params':params,'vararg':vararg,'stack':stack,'code':code,'code_marker':code_marker,'code_encoding':'32-bit words with format 1 marker' if code_marker is not None else '32-bit words','constants':constants,'upvalues':upvalues,'upvalue_names':upnames,'locals':locals_,'children':children}

def walk(fn):
    yield fn
    for child in fn['children']:yield from walk(child)

def instruction(word):
    return {'op':word&63,'a':(word>>6)&255,'b':word>>23,'c':(word>>14)&511,'bx':word>>14,'sbx':(word>>14)-131071}

def listing(fn):
    rows=[];const=fn['constants']
    for pc,word in enumerate(fn['code'],1):
        d=instruction(word);o=d['op'];a=d['a'];b=d['b'];c=d['c'];bx=d['bx']
        name=CLIENT_OPS.get(o,'OP_'+str(o))
        args=f'R{a} {b} {c}'
        def rk(v):return 'K'+str(v&255)+'='+repr(const[v&255]) if v&256 and (v&255)<len(const) else 'R'+str(v)
        if name=='LOADK':args=f'R{a} K{bx}='+repr(const[bx] if bx<len(const) else '<invalid>')
        elif name=='GETTABUP':args=f'R{a} U{b} '+rk(c)
        elif name in ('GETTABLE','SELF'):args=f'R{a} R{b} '+rk(c)
        elif name in ('SETTABLE','SETTABUP'):args=f'{"U" if name=="SETTABUP" else "R"}{a} '+rk(b)+' '+rk(c)
        elif name=='CLOSURE':args=f'R{a} child[{bx}]'
        elif name in ('JMP','FORLOOP','FORPREP','TFORLOOP'):args=f'R{a} jump={pc+1+d["sbx"]}'
        rows.append(f'{pc:04} {name:10} {args}')
    return '\n'.join(rows)

if __name__=='__main__':
    base=game_paths()[0]/'DeltaForce/Saved/LuaSource'
    out=Path(__file__).resolve().parent/'evidence/lua';out.mkdir(exist_ok=True)
    records=[]
    for path in base.iterdir():
        if not path.is_file():continue
        try:module=''.join(chr(ord(x)^0xdf) for x in path.name)
        except ValueError:module='<unknown>'
        raw=path.read_bytes()
        record={'module':module,'size':len(raw),'sha256':hashlib.sha256(raw).hexdigest()}
        try:
            reader=Reader(raw);fn=reader.function()
            if reader.at!=len(raw):raise ValueError(f'Trailing {len(raw)-reader.at} bytes')
            functions=list(walk(fn))
            record.update({'parsed':True,'functions':len(functions),'opcode_ids_outside_lua53_range':sum(sum((w&63)>=len(OPS) for w in f['code']) for f in functions),'opcode_mapping':'client permutation; partially recovered','messages':sorted({c for f in functions for c in f['constants'] if isinstance(c,str) and re.fullmatch(r'(?:pb\.)?(?:CS|SC)[A-Z]\w*(?:Req|Res|Rsp|Ntf)',c)})})
            safe=re.sub(r'[^A-Za-z0-9_.-]','_',module)
            (out/(safe+'.json')).write_text(json.dumps(fn,ensure_ascii=False,indent=2),encoding='utf-8')
            if any(x in module for x in ['inventoryserver','questserver','loginmodule','wegame','itemmovecmd','itembase']):
                (out/(safe+'.dis.txt')).write_text('\n\n'.join('FUNCTION '+f['id']+' PARAMS '+str(f['params'])+'\nCONSTANTS '+repr(f['constants'])+'\n'+listing(f) for f in functions),encoding='utf-8')
        except Exception as e:record.update({'parsed':False,'error':str(e)})
        records.append(record)
    (out/'inventory.json').write_text(json.dumps(records,ensure_ascii=False,indent=2),encoding='utf-8')
    print(json.dumps({'files':len(records),'parsed':sum(r['parsed'] for r in records),'failures':[r for r in records if not r['parsed']],'network_modules':[r for r in records if r.get('messages')]},ensure_ascii=False,indent=2))
