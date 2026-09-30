"""Read-only extraction of plaintext protobuf metadata, not protected executable code."""
import argparse
import hashlib
import json
import mmap
from pathlib import Path
import re


def varint(data, position, limit):
    result=0
    for shift in range(0,70,7):
        if position>=limit:
            raise ValueError("Truncated varint")
        value=data[position]
        position+=1
        result|=(value&127)<<shift
        if value<128:
            return result,position
    raise ValueError("Oversized varint")


def descriptor_end(data,start):
    position=end=start
    limit=min(len(data),start+1024*1024)
    while position<limit:
        try:
            tag,next_position=varint(data,position,limit)
            field,wire=tag>>3,tag&7
            if field not in set(range(1,13))|{14}:
                break
            if field in {10,11,14} and wire==0:
                _,position=varint(data,next_position,limit)
            elif wire==2:
                length,position=varint(data,next_position,limit)
                if length>limit-position:
                    break
                position+=length
            else:
                break
            end=position
        except ValueError:
            break
    return end


def audit_field_names(binary,output):
    """Record qualified name literals; never infer tags or scalar types."""
    digest=hashlib.sha256()
    with binary.open('rb') as handle:
        for chunk in iter(lambda:handle.read(4*1024*1024),b''):
            digest.update(chunk)
    names={}
    with binary.open('rb') as handle,mmap.mmap(handle.fileno(),0,access=mmap.ACCESS_READ) as data:
        pattern=rb'pb\.([A-Za-z][A-Za-z0-9_]{1,127})\.([A-Za-z_][A-Za-z0-9_]{0,127})\x00'
        for match in re.finditer(pattern,data):
            message='pb.'+match[1].decode('ascii')
            field=match[2].decode('ascii')
            names.setdefault((message,field),match.start())
        for (message,field),offset in names.items():
            literal=(message+'.'+field).encode('ascii')+b'\0'
            assert data[offset:offset+len(literal)]==literal
    result={'source_sha256':digest.hexdigest(),
            'confidence':'Qualified name literals only; field numbers, scalar types and complete schemas remain unknown',
            'names':[{'message':message,'property':field,'offset':offset}
                     for (message,field),offset in sorted(names.items())]}
    output.mkdir(parents=True,exist_ok=True)
    (output/'field_name_catalog.json').write_text(json.dumps(result,ensure_ascii=False,indent=2)+'\n',encoding='utf-8')
    return {'sha256':digest.hexdigest(),'qualified_property_names':len(names),
            'message_types_with_property_names':len({name[0] for name in names}),
            'source_offset_checks':'passed','output':str(output.resolve())}


def audit(binary,output):
    from google.protobuf import descriptor_pb2
    digest=hashlib.sha256()
    with binary.open("rb") as handle:
        for chunk in iter(lambda:handle.read(4*1024*1024),b""):
            digest.update(chunk)
    names={}
    descriptors={}
    records=[]
    with binary.open("rb") as handle,mmap.mmap(handle.fileno(),0,access=mmap.ACCESS_READ) as data:
        position=0
        while True:
            position=data.find(b"pb.",position)
            if position<0:
                break
            match=re.match(rb"pb\.[A-Za-z][A-Za-z0-9_]{1,127}\x00",data[position:position+132])
            if match:
                names.setdefault(match[0][:-1].decode("ascii"),position)
            position+=3
        position=0
        while True:
            marker=data.find(b".proto",position)
            if marker<0:
                break
            position=marker+6
            for start in range(max(0,marker-160),marker):
                if data[start]!=10:
                    continue
                try:
                    length,name_start=varint(data,start+1,marker+6)
                except ValueError:
                    continue
                if length>160 or name_start+length!=marker+6:
                    continue
                name=data[name_start:marker+6]
                if not re.fullmatch(rb"[A-Za-z0-9_./-]+\.proto",name):
                    continue
                end=descriptor_end(data,start)
                descriptor=descriptor_pb2.FileDescriptorProto()
                try:
                    descriptor.ParseFromString(data[start:end])
                except Exception:
                    continue
                if descriptor.name!=name.decode() or not (descriptor.message_type or descriptor.enum_type):
                    continue
                if descriptor.name in descriptors:
                    continue
                descriptors[descriptor.name]=descriptor
                records.append({"file":descriptor.name,"package":descriptor.package,
                                "offset":start,"size":end-start,
                                "messages":[message.name for message in descriptor.message_type]})
    output.mkdir(parents=True,exist_ok=True)
    catalog={"source_sha256":digest.hexdigest(),"confidence":"Names and file offsets only; no message IDs or field layouts inferred",
             "message_names":[{"name":name,"offset":offset} for name,offset in sorted(names.items())]}
    (output/"message_catalog.json").write_text(json.dumps(catalog,ensure_ascii=False,indent=2),encoding="utf-8")
    (output/"descriptors.json").write_text(json.dumps(records,ensure_ascii=False,indent=2),encoding="utf-8")
    result=descriptor_pb2.FileDescriptorSet()
    for name,descriptor in sorted(descriptors.items()):
        result.file.add().CopyFrom(descriptor)
    (output/"descriptors.pb").write_bytes(result.SerializeToString())
    return {"sha256":digest.hexdigest(),"type_names":len(names),"descriptor_files":len(descriptors),"output":str(output.resolve())}


if __name__=="__main__":
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument("binary",type=Path)
    parser.add_argument("--output",type=Path,default=Path("work/client-audit"))
    parser.add_argument('--only-field-names',action='store_true',help='Extract qualified property names without guessing field numbers')
    arguments=parser.parse_args()
    action=audit_field_names if arguments.only_field_names else audit
    print(json.dumps(action(arguments.binary,arguments.output),indent=2))
