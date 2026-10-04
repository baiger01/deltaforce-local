"""Read only established handshake enum/length slots; never export key material."""
from pathlib import Path
from collections import defaultdict,Counter
import json,sys
ROOT=Path(__file__).resolve().parent.parent;PROJECT=ROOT/'outputs/df-local-server'
sys.path.insert(0,str(PROJECT/'tools'))
from analyze_capture import captured_packets,tcp_payload,reassemble
from dfserver.gcp_framing import decode_prefix
flows=defaultdict(list)
for link,packet,truncated in captured_packets(Path(sys.argv[1]).read_bytes()):
    parsed=tcp_payload(link,packet)
    if parsed and 65010 in (parsed[0][1],parsed[0][3]):
        key,seq,body=parsed;flows[key].append((seq,body))
rows=[]
for key,segments in flows.items():
    for seq,body in reassemble(segments)[0]:
        at=0
        while at<len(body):
            try:parsed=decode_prefix(body[at:])
            except ValueError:break
            if parsed is None:break
            frame,size=parsed;at+=size
            if frame.command==0x1001 and frame.extra_header:
                ext=frame.extra_header
                row={'command':'0x1001','key_mode':ext[0],'extension_bytes':len(ext),'body_bytes':len(frame.body)}
                if ext[0]==3 and len(ext)>=3:
                    length=int.from_bytes(ext[1:3],'big');after=3+length
                    row['dh_client_public_key_bytes']=length
                    row['opaque_dh_context_bytes']=64
                    if len(ext)>after+64:row['encryption_method']=ext[after+64]
                rows.append(row)
            if frame.command==0x1002 and frame.extra_header:
                ext=frame.extra_header;mode=ext[0]
                row={'command':'0x1002','key_mode':mode,'extension_bytes':len(ext),'body_bytes':len(frame.body)}
                if mode==3 and len(ext)>=3:
                    length=int.from_bytes(ext[1:3],'big');row['dh_server_public_key_bytes']=length
                    after=3+length
                    if len(ext)==after+9:
                        row.update({'compression_method':ext[after],
                                    'compression_threshold':int.from_bytes(ext[after+1:after+5],'big'),
                                    'compression_maximum':int.from_bytes(ext[after+5:after+9],'big')})
                rows.append(row)
print(json.dumps({'handshakes':rows,'key_material_exported':False},indent=2))
