"""Inspect capture structure, without exporting packet values or account data.

Supports Ethernet, native 802.11 and IPv4 TCP in PCAP and PCAPNG. This is a protocol discovery
tool: finding a protobuf-shaped region does not establish a game wire schema.
"""
from pathlib import Path
from collections import defaultdict, Counter
import argparse, hashlib, json, re, struct, sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from dfserver.gcp_framing import decode_prefix

MAX_CAPTURE=128*1024*1024

def captured_packets(data):
    if len(data)<12:raise ValueError('Capture header is truncated')
    if data[:4]==b'\x0a\x0d\x0d\x0a':
        at=0;endian=None;interfaces=[]
        while at<len(data):
            if len(data)-at<12:raise ValueError('PCAPNG block header is truncated')
            if data[at:at+4]==b'\x0a\x0d\x0d\x0a':
                endian={b'\x4d\x3c\x2b\x1a':'<',b'\x1a\x2b\x3c\x4d':'>'}.get(data[at+8:at+12])
                if not endian:raise ValueError('Invalid PCAPNG byte order')
                interfaces=[]
            if endian is None:raise ValueError('PCAPNG section header is missing')
            block,length=struct.unpack_from(endian+'II',data,at)
            if length<12 or length%4 or length>len(data)-at:raise ValueError('Invalid or incomplete PCAPNG block')
            if struct.unpack_from(endian+'I',data,at+length-4)[0]!=length:raise ValueError('PCAPNG block lengths disagree')
            body=data[at+8:at+length-4]
            if block==1:
                if len(body)<8:raise ValueError('Truncated interface description')
                interfaces.append(struct.unpack_from(endian+'H',body)[0])
            elif block==6:
                if len(body)<20:raise ValueError('Truncated enhanced packet block')
                iface,high,low,caplen,original=struct.unpack_from(endian+'5I',body)
                if iface>=len(interfaces) or caplen>len(body)-20:raise ValueError('Invalid enhanced packet block')
                yield interfaces[iface],body[20:20+caplen],caplen<original
            at+=length
    else:
        endian={b'\xd4\xc3\xb2\xa1':'<',b'\xa1\xb2\xc3\xd4':'>',b'\x4d\x3c\xb2\xa1':'<',b'\xa1\xb2\x3c\x4d':'>'}.get(data[:4])
        if not endian or len(data)<24:raise ValueError('Unsupported capture format')
        link=struct.unpack_from(endian+'I',data,20)[0];at=24
        while at<len(data):
            if len(data)-at<16:raise ValueError('PCAP record header is truncated')
            _,_,caplen,original=struct.unpack_from(endian+'4I',data,at);at+=16
            if caplen>len(data)-at:raise ValueError('PCAP packet is truncated')
            yield link,data[at:at+caplen],caplen<original
            at+=caplen

def wifi_ipv4(frame):
    # Some Pktmon converters label native Wi-Fi buffers as Ethernet. Require
    # a valid data frame header AND an LLC/SNAP IPv4 signature before accepting
    # this fallback. Header layout follows Linux net/wireless/util.c.
    if len(frame)<24:return None
    fc=int.from_bytes(frame[:2],'little')
    if fc&3 or (fc>>2)&3!=2 or fc&0x40:return None
    size=24+(6 if fc&0x300==0x300 else 0)
    qos=bool(fc&0x80)
    if qos:
        if len(frame)<size+2 or frame[size]&0x80:return None  # A-MSDU needs separate subframe parsing.
        size+=2
        if fc&0x8000:size+=4
    if len(frame)<size+8 or frame[size:size+8]!=b'\xaa\xaa\x03\x00\x00\x00\x08\x00':return None
    return frame[size+8:]

def tcp_payload(link,frame):
    if link==1:
        if len(frame)<14:return None
        ether=struct.unpack_from('>H',frame,12)[0];at=14
        while ether in (0x8100,0x88a8):
            if len(frame)<at+4:return None
            ether=struct.unpack_from('>H',frame,at+2)[0];at+=4
        if ether==0x0800:ip=frame[at:]
        else:
            ip=wifi_ipv4(frame)
            if ip is None:return None
    elif link==105:
        ip=wifi_ipv4(frame)
        if ip is None:return None
    elif link in (101,228):ip=frame
    else:return None
    if len(ip)<20 or ip[0]>>4!=4 or ip[9]!=6:return None
    ihl=(ip[0]&15)*4;total=struct.unpack_from('>H',ip,2)[0]
    if ihl<20 or total<ihl+20 or len(ip)<total:return None
    if struct.unpack_from('>H',ip,6)[0]&0x3fff:return None  # Fragmented IP requires separate reconstruction.
    tcp=ip[ihl:total]
    if len(tcp)<20:return None
    size=(tcp[12]>>4)*4
    if size<20 or size>len(tcp):return None
    source,dest,seq=struct.unpack_from('>HHI',tcp)
    payload=tcp[size:]
    if not payload:return None
    return (ip[12:16],source,ip[16:20],dest),seq,payload

def reassemble(segments):
    if not segments:return [],0,0
    anchor=segments[0][0]
    ordered=sorted((((seq-anchor+2**31)%2**32-2**31,payload) for seq,payload in segments),key=lambda x:x[0])
    chunks=[];start=None;body=bytearray();duplicates=0;conflicts=0
    for seq,payload in ordered:
        if start is None:start=seq;body=bytearray(payload);continue
        end=start+len(body)
        if seq>end:
            chunks.append((start,bytes(body)));start=seq;body=bytearray(payload)
        elif seq==end:body.extend(payload)
        else:
            offset=seq-start;overlap=min(len(payload),end-seq)
            if bytes(body[offset:offset+overlap])!=payload[:overlap]:
                conflicts+=1
                # Conflicting bytes must not be combined into a schema candidate.
                chunks.append((start,bytes(body)));start=seq;body=bytearray(payload)
            elif overlap==len(payload):duplicates+=1
            else:body.extend(payload[overlap:])
    if start is not None:chunks.append((start,bytes(body)))
    return chunks,duplicates,conflicts

def varint(data,at):
    value=0
    for n in range(10):
        if at>=len(data):raise ValueError('Truncated varint')
        byte=data[at];at+=1
        if n==9 and byte>1:raise ValueError('Varint exceeds 64 bits')
        value|=(byte&127)<<(7*n)
        if not byte&128:return value,at
    raise ValueError('Varint too long')

def name_field(data,start,end):
    # Confirm an exact protobuf wire-2 tag/length immediately before a known
    # message name, rather than assigning any guessed envelope field number.
    for tag_at in range(max(0,start-8),start):
        try:
            tag,after=varint(data,tag_at);length,content=varint(data,after)
            number=tag>>3
            if tag&7==2 and 0<number<2**29 and content==start and content+length==end:
                return {'field_number':number,'wire_type':2,'value_length':length,'tag_offset':tag_at}
        except ValueError:continue
    return None

def wire_shape(data,start,limit=16):
    at=start;fields=[]
    for _ in range(limit):
        beginning=at
        try:
            tag,at=varint(data,at);number,wire=tag>>3,tag&7
            if not 0<number<2**29:break
            if wire==0:_,at=varint(data,at);size=at-beginning
            elif wire in (1,5):size=8 if wire==1 else 4;at+=size
            elif wire==2:size,at=varint(data,at);at+=size
            else:break
            if at>len(data):break
            fields.append({'field_number':number,'wire_type':wire,'encoded_value_length':size})
        except ValueError:break
    return fields

def inspect_bytes(data,names):
    messages=[]
    for match in re.finditer(rb'(?:pb\.)?[A-Z][A-Za-z0-9_]{1,126}',data):
        name=match[0].decode('ascii').removeprefix('pb.')
        if name not in names:continue
        field=name_field(data,match.start(),match.end())
        row={'message':name,'stream_offset':match.start(),'routing_field_candidate':field}
        if field:
            row['following_wire_shape_candidate']=wire_shape(data,match.end())
        messages.append(row)
        if len(messages)==2000:break
    tls=[]
    for m in re.finditer(rb'[\x14-\x17]\x03[\x00-\x04]',data):
        if m.start()+5>len(data):continue
        length=struct.unpack_from('>H',data,m.start()+3)[0]
        if 0<length<=18432 and m.start()+5+length<=len(data):
            tls.append({'offset':m.start(),'record_type':data[m.start()],'length':length})
            if len(tls)==100:break
    return {'known_message_names':messages,'tls_record_candidates':tls}

def inspect_gcp_region(data):
    if not data.startswith(b'\x33\x66'):
        return None
    at=0;frames=[]
    try:
        while at<len(data):
            parsed=decode_prefix(memoryview(data)[at:])
            if parsed is None:break
            frame,size=parsed
            frames.append(frame);at+=size
    except ValueError:
        return {'complete_frames':len(frames),'consumed_bytes':at,
                'unconsumed_bytes':len(data)-at,'invalid_frame_boundary':True}
    return {'complete_frames':len(frames),'consumed_bytes':at,
            'unconsumed_bytes':len(data)-at,'invalid_frame_boundary':False,
            'versions':dict(Counter(frame.version for frame in frames)),
            'command_counts':dict(Counter(f'0x{frame.command:04x}' for frame in frames)),
            'encryption_flag_counts':dict(Counter(frame.payload_encryption_flag for frame in frames)),
            'header_length_counts':dict(Counter(21+len(frame.extra_header) for frame in frames)),
            'nonempty_body_count':sum(bool(frame.body) for frame in frames),
            'nonempty_bodies_aligned_to_16_bytes':sum(bool(frame.body) and len(frame.body)%16==0 for frame in frames)}

def analyze(path,catalog):
    if path.stat().st_size>MAX_CAPTURE:raise ValueError('Capture exceeds the 128 MiB analysis limit')
    data=path.read_bytes();flows=defaultdict(list);packets=0;truncated=0
    for link,frame,was_truncated in captured_packets(data):
        packets+=1;truncated+=was_truncated
        found=tcp_payload(link,frame)
        if found:
            key,seq,payload=found;flows[key].append((seq,payload))
    names={r['name'].removeprefix('pb.') for r in catalog['message_names']}
    result={'capture_sha256':hashlib.sha256(data).hexdigest(),'packet_records':packets,
            'truncated_packet_records':truncated,'tcp_directions':[],
            'confidence':'Ethernet/native Wi-Fi packet structure and exact known-name matches only; game compatibility is unverified',
            'payload_values_exported':False}
    for key,segments in sorted(flows.items()):
        chunks,duplicates,conflicts=reassemble(segments)
        identity=key[0]+struct.pack('>H',key[1])+key[2]+struct.pack('>H',key[3])
        row={'direction_id':hashlib.sha256(identity).hexdigest()[:16],
             'source_port':key[1],'destination_port':key[3],'segments':len(segments),
             'duplicate_segments':duplicates,'conflicting_overlaps':conflicts,
             'contiguous_regions':[{'relative_sequence_offset':seq,'bytes':len(body),**inspect_bytes(body,names),
                                    'gcp_framing':inspect_gcp_region(body)} for seq,body in chunks]}
        result['tcp_directions'].append(row)
    return result

def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('capture',type=Path)
    parser.add_argument('--catalog',type=Path,default=Path(__file__).resolve().parents[1]/'protocol/message_catalog.json')
    parser.add_argument('--output',type=Path)
    args=parser.parse_args()
    try:
        result=analyze(args.capture,json.loads(args.catalog.read_text(encoding='utf-8')))
        output=args.output or args.capture.with_suffix('.analysis.json')
        output.write_text(json.dumps(result,ensure_ascii=False,indent=2),encoding='utf-8')
        print(json.dumps({'report':str(output),'packet_records':result['packet_records'],
                          'tcp_directions':len(result['tcp_directions']),
                          'known_message_name_matches':sum(len(c['known_message_names']) for f in result['tcp_directions'] for c in f['contiguous_regions'])},indent=2))
    except (OSError,ValueError,KeyError) as exc:parser.exit(1,str(exc)+'\n')

if __name__=='__main__':main()
