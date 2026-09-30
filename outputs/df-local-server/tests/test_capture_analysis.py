from pathlib import Path
import importlib.util,json,struct,tempfile,unittest

source=Path(__file__).resolve().parents[1]/'tools/analyze_capture.py'
spec=importlib.util.spec_from_file_location('capture_analysis',source)
capture=importlib.util.module_from_spec(spec);spec.loader.exec_module(capture)

def frame(seq,payload):
    tcp=struct.pack('>HHII',45000,443,seq,0)+b'\x50\x18'+b'\x00'*6+payload
    ip=b'\x45\x00'+struct.pack('>H',20+len(tcp))+b'\x00'*5+b'\x06'+b'\x00'*2+b'\x0a\x00\x00\x01'+b'\xc0\x00\x02\x01'+tcp
    return b'\x00'*12+b'\x08\x00'+ip

def block(kind,body):
    body+=b'\0'*((-len(body))%4);length=12+len(body)
    return struct.pack('<II',kind,length)+body+struct.pack('<I',length)

class CaptureTests(unittest.TestCase):
    def test_catalog_names_without_cs_prefix_and_gcp_value_redaction(self):
        name=b'QuestAcceptReq'
        payload=b'\x0a'+bytes([len(name)])+name+b'\x10\x7b'
        found=capture.inspect_bytes(payload,{'QuestAcceptReq'})['known_message_names']
        self.assertEqual(found[0]['message'],'QuestAcceptReq')
        self.assertEqual(found[0]['routing_field_candidate']['field_number'],1)
        from dfserver.gcp_framing import Frame
        packet=Frame(11,13,0x4013,0,123456,b'\x00'*4,payload).encode()
        summary=capture.inspect_gcp_region(packet)
        self.assertEqual(summary['complete_frames'],1)
        self.assertEqual(summary['command_counts'],{'0x4013':1})
        self.assertNotIn('123456',json.dumps(summary))

    def test_pcapng_reassembly_and_value_redaction(self):
        name=b'CSQuestAcceptReq';body=b'\x0a'+bytes([len(name)])+name+b'\x10\x7b'
        packets=[frame(100+len(body)//2,body[len(body)//2:]),frame(100,body[:len(body)//2]),frame(100,body[:len(body)//2])]
        raw=block(0x0a0d0d0a,struct.pack('<IHHq',0x1a2b3c4d,1,0,-1))+block(1,struct.pack('<HHI',1,0,65535))
        for p in packets:raw+=block(6,struct.pack('<5I',0,0,0,len(p),len(p))+p)
        with tempfile.TemporaryDirectory() as d:
            path=Path(d)/'test.pcapng';path.write_bytes(raw)
            report=capture.analyze(path,{'message_names':[{'name':'pb.CSQuestAcceptReq'}]})
        direction=report['tcp_directions'][0]
        self.assertEqual(direction['duplicate_segments'],1)
        found=direction['contiguous_regions'][0]['known_message_names'][0]
        self.assertEqual(found['routing_field_candidate']['field_number'],1)
        self.assertEqual(found['following_wire_shape_candidate'][0]['field_number'],2)
        self.assertFalse(report['payload_values_exported'])
        self.assertNotIn('encoded_value',json.dumps(report).replace('encoded_value_length',''))

    def test_gap_is_not_joined(self):
        chunks,_,_=capture.reassemble([(10,b'CSQuest'),(30,b'AcceptReq')])
        self.assertEqual(len(chunks),2)
        self.assertFalse(any(capture.inspect_bytes(data,{'CSQuestAcceptReq'})['known_message_names'] for _,data in chunks))

    def test_conflicting_retransmission_is_flagged(self):
        _,_,conflicts=capture.reassemble([(10,b'abcdef'),(12,b'XY')])
        self.assertEqual(conflicts,1)

    def test_sequence_wrap(self):
        chunks,_,_=capture.reassemble([(2**32-2,b'ab'),(0,b'cd')])
        self.assertEqual([data for _,data in chunks],[b'abcd'])

    def test_truncated_and_invalid_block_rejected(self):
        raw=block(0x0a0d0d0a,struct.pack('<IHHq',0x1a2b3c4d,1,0,-1))
        with self.assertRaises(ValueError):list(capture.captured_packets(raw[:-1]))
        with self.assertRaises(ValueError):list(capture.captured_packets(raw[:-4]+b'\0'*4))

    def test_name_match_without_wire_tag_is_not_schema(self):
        found=capture.inspect_bytes(b'prefix CSQuestAcceptReq suffix',{'CSQuestAcceptReq'})['known_message_names'][0]
        self.assertIsNone(found['routing_field_candidate'])

    def test_oversized_varint_rejected(self):
        with self.assertRaises(ValueError):capture.varint(b'\xff'*10,0)

    def test_pktmon_wifi_buffer_labeled_ethernet_recovers_payload(self):
        ip=frame(100,b'own-fixture')[14:]
        wifi=b'\x08\x01'+b'\0'*22+b'\xaa\xaa\x03\0\0\0\x08\0'+ip
        self.assertEqual(capture.tcp_payload(1,wifi),capture.tcp_payload(1,frame(100,b'own-fixture')))

    def test_qos_four_address_ht_wifi_header(self):
        ip=frame(200,b'own-fixture')[14:]
        wifi=struct.pack('<H',0x8388)+b'\0'*34+b'\xaa\xaa\x03\0\0\0\x08\0'+ip
        self.assertEqual(capture.tcp_payload(105,wifi),capture.tcp_payload(1,frame(200,b'own-fixture')))

    def test_non_snap_and_truncated_wifi_are_rejected(self):
        ip=frame(300,b'own-fixture')[14:]
        wifi=b'\x08\x01'+b'\0'*22+b'\xaa\xaa\x03\0\0\0\x08\0'+ip
        self.assertIsNone(capture.tcp_payload(105,wifi[:30]))
        self.assertIsNone(capture.tcp_payload(105,wifi[:24]+b'\0'*8+ip))

if __name__=='__main__':unittest.main()
