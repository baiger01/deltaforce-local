from pathlib import Path
import struct,tempfile,unittest
from unittest.mock import patch

from tools.capture_gateway import verified_live_endpoints, verified_client_tcp_flows, ensure_pktmon_idle, command_output, captured_gateway_endpoints


class CaptureScopeTests(unittest.TestCase):
    root = Path('sample-game')
    executable = root/'DeltaForce/Binaries/Win64/DeltaForceClient-Win64-Shipping.exe'

    def _capture_seed(self, port, body):
        def block(kind,data):
            data+=b'\x00'*((-len(data))%4);size=12+len(data)
            return struct.pack('<II',kind,size)+data+struct.pack('<I',size)
        tcp=struct.pack('>HHII',45000,port,100,0)+b'\x50\x18'+b'\x00'*6+body
        ip=b'\x45\x00'+struct.pack('>H',20+len(tcp))+b'\x00'*5+b'\x06'+b'\x00'*2+b'\x0a\x00\x00\x01'+b'\xcb\x00\x71\x63'+tcp
        packet=b'\x00'*12+b'\x08\x00'+ip
        return block(0x0a0d0d0a,struct.pack('<IHHq',0x1a2b3c4d,1,0,-1))+block(1,struct.pack('<HHI',1,0,65535))+block(6,struct.pack('<5I',0,0,0,len(packet),len(packet))+packet)

    def test_login_seed_uses_observed_gcp_peer(self):
        from dfserver.gcp_framing import Frame
        body=Frame(11,13,0x4013,0,1,b'\x00'*4,b'sample').encode()
        with tempfile.TemporaryDirectory() as directory:
            (Path(directory)/'sample.pcapng').write_bytes(self._capture_seed(65010,body))
            self.assertEqual(captured_gateway_endpoints(directory),[('203.0.113.99',65010)])

    def test_login_seed_rejects_unrelated_peer_and_malformed_frame(self):
        from dfserver.gcp_framing import Frame
        body=Frame(11,13,0x4013,0,1,b'\x00'*4,b'sample').encode()
        for port,payload in [(443,body),(65010,b'\x33\x66'+b'\x00'*30)]:
            with tempfile.TemporaryDirectory() as directory:
                (Path(directory)/'sample.pcapng').write_bytes(self._capture_seed(port,payload))
                self.assertEqual(captured_gateway_endpoints(directory),[])

    def test_client_httpdns_peer_can_differ_from_os_dns(self):
        rows = [{'state':5,'pid':7,'remote_ip':'203.0.113.99','remote_port':65010}]
        with patch('tools.capture_gateway.tcp_connections',return_value=rows), \
             patch('tools.capture_gateway.process_path',return_value=self.executable):
            self.assertEqual(verified_live_endpoints(self.root,[('192.0.2.1',65010)]),
                             [('203.0.113.99',65010)])

    def test_other_program_on_same_gateway_port_is_excluded(self):
        rows = [{'state':5,'pid':8,'remote_ip':'192.0.2.1','remote_port':65010}]
        with patch('tools.capture_gateway.tcp_connections',return_value=rows), \
             patch('tools.capture_gateway.process_path',return_value=Path('other.exe')):
            self.assertEqual(verified_live_endpoints(self.root,[('192.0.2.1',65010)]),[])

    def test_unrelated_web_peer_and_loopback_are_excluded(self):
        rows = [{'state':5,'pid':7,'remote_ip':'203.0.113.99','remote_port':443},
                {'state':5,'pid':7,'remote_ip':'127.0.0.1','remote_port':65010}]
        with patch('tools.capture_gateway.tcp_connections',return_value=rows), \
             patch('tools.capture_gateway.process_path',return_value=self.executable):
            self.assertEqual(verified_live_endpoints(self.root,[('192.0.2.1',443),('192.0.2.2',65010)]),[])

    def test_idle_pktmon_status_in_english_and_chinese(self):
        for status in ('Packet Monitor is not running.', '数据包监视器未运行。', 'PktMon 已停止。'):
            ensure_pktmon_idle(status)

    def test_active_or_unrecognized_status_preserves_existing_capture(self):
        for status in ('Packet capture is running', '正在运行', '', 'Unknown status'):
            with self.assertRaises(RuntimeError):
                ensure_pktmon_idle(status)

    def test_chinese_status_is_read_in_utf8_and_local_encoding(self):
        text='数据包监视器没有运行。'
        for encoding in ('utf-8','utf-8-sig','gbk'):
            decoded=command_output(text.encode(encoding))
            self.assertEqual(decoded,text)
            ensure_pktmon_idle(decoded)

    def test_utf16_status_bom_is_read(self):
        text='数据包监视器没有运行。'
        self.assertEqual(command_output(text.encode('utf-16')),text)

    def test_shared_proxy_only_selects_this_game_flow(self):
        rows=[{'state':5,'pid':7,'local_ip':'127.0.0.1','local_port':42000,
               'remote_ip':'127.0.0.1','remote_port':7897},
              {'state':5,'pid':8,'local_ip':'127.0.0.1','local_port':42001,
               'remote_ip':'127.0.0.1','remote_port':7897}]
        paths={7:self.executable,8:Path('other.exe')}
        with patch('tools.capture_gateway.tcp_connections',return_value=rows), \
             patch('tools.capture_gateway.process_path',side_effect=paths.get):
            self.assertEqual(verified_client_tcp_flows(self.root),
                             [('127.0.0.1',42000,'127.0.0.1',7897)])


if __name__=='__main__':
    unittest.main()
