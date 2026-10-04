from pathlib import Path
from collections import Counter
import json,struct,sys

ROOT=Path(__file__).resolve().parent.parent
sys.path.insert(0,str(ROOT/'outputs/df-local-server/tools'))
from analyze_capture import captured_packets,tcp_payload
counts=Counter(); links=Counter()
for link,frame,truncated in captured_packets(Path(sys.argv[1]).read_bytes()):
    links[link]+=1
    if link!=1:counts['non_ethernet']+=1;continue
    if len(frame)<14:counts['short_ethernet']+=1;continue
    ether=struct.unpack_from('>H',frame,12)[0];at=14
    while ether in (0x8100,0x88a8) and len(frame)>=at+4:
        ether=struct.unpack_from('>H',frame,at+2)[0];at+=4
    if ether!=0x0800:counts['not_ipv4']+=1;continue
    ip=frame[at:]
    if len(ip)<20:counts['short_ipv4']+=1;continue
    if ip[9]!=6:counts['not_tcp']+=1;continue
    ihl=(ip[0]&15)*4;total=struct.unpack_from('>H',ip,2)[0]
    if total<ihl+20:counts['invalid_ip_total']+=1;continue
    if len(ip)<total:counts['ip_total_exceeds_captured_bytes']+=1;continue
    if struct.unpack_from('>H',ip,6)[0]&0x3fff:counts['ipv4_fragment']+=1;continue
    tcp=ip[ihl:total]
    size=(tcp[12]>>4)*4
    if size<20 or size>len(tcp):counts['invalid_tcp_header']+=1;continue
    counts['tcp_payload_present' if len(tcp)>size else 'tcp_ack_or_control_only']+=1
print(json.dumps({'links':dict(links),'packet_classifications':dict(counts)},indent=2))
