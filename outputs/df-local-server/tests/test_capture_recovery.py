from pathlib import Path
import json,tempfile,unittest
from unittest.mock import patch
from types import SimpleNamespace
from tools.capture_gateway import stale_capture_session,recover_stale_capture


class CaptureRecoveryTests(unittest.TestCase):
    def setUp(self):
        self.directory=tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.root=Path(self.directory.name)
        self.etl=self.root/'20260927-003830-82932.etl'
        self.etl.write_bytes(b'self-authored test fixture')
        self.status=f'日志文件: {self.etl}\n'
        self.filters='1 DFLocal_82932_0 TCP 203.0.113.99 65010\n2 DFLocal_82932_1 TCP 192.0.2.1 65010\n'

    def test_owned_interrupted_session_in_english_and_chinese(self):
        for status in (self.status,f'Log file: {self.etl}\n'):
            self.assertEqual(stale_capture_session(status,self.filters,self.root,lambda pid:False),
                             (self.etl.resolve(),['DFLocal_82932_0','DFLocal_82932_1'],82932))

    def test_live_owner_and_foreign_filters_are_preserved(self):
        for filters,alive in [(self.filters,True),(self.filters+'3 OtherCapture TCP\n',False),
                              ('1 DFLocal_42_0 TCP\n',False),('',False)]:
            with self.assertRaises(RuntimeError):
                stale_capture_session(self.status,filters,self.root,lambda pid:alive)

    def test_external_path_and_missing_file_are_preserved(self):
        with self.assertRaises(RuntimeError):
            stale_capture_session(self.status,self.filters,self.root/'other',lambda pid:False)
        self.etl.unlink()
        with self.assertRaises(RuntimeError):
            stale_capture_session(self.status,self.filters,self.root,lambda pid:False)

    def test_recovery_stops_owned_session_exports_and_removes_only_its_filters(self):
        calls=[];stopped=False
        def fake_run(args):
            nonlocal stopped
            calls.append(args)
            if args[1:]==['stop']:stopped=True
            stdout=('数据包监视器没有运行。' if stopped else self.status) if args[1]=='status' else self.filters
            return SimpleNamespace(stdout=stdout,returncode=0)
        with patch('tools.capture_gateway.run',side_effect=fake_run), \
             patch('tools.capture_gateway.stale_capture_session',side_effect=lambda *args:(self.etl.resolve(),['DFLocal_82932_0','DFLocal_82932_1'],82932)):
            result=recover_stale_capture('pktmon',self.status,self.root)
        self.assertTrue(result['capture_export_succeeded'])
        self.assertEqual([c for c in calls if c[1]=='stop'],[['pktmon','stop']])
        self.assertEqual([c[-1] for c in calls if c[1:3]==['filter','remove']],['DFLocal_82932_1','DFLocal_82932_0'])
        self.assertIn(['pktmon','etl2pcap',str(self.etl.resolve()),'--out',str(self.etl.resolve().with_suffix('.pcapng'))],calls)
        self.assertEqual(json.loads(self.etl.with_suffix('.json').read_text())['original_helper_pid'],82932)

    def test_changed_owner_does_not_stop_capture(self):
        with patch('tools.capture_gateway.run',return_value=SimpleNamespace(stdout='',returncode=0)) as run, \
             patch('tools.capture_gateway.stale_capture_session',side_effect=[(self.etl,['DFLocal_82932_0'],82932),RuntimeError('changed')]):
            with self.assertRaises(RuntimeError):recover_stale_capture('pktmon',self.status,self.root)
        self.assertFalse(any(call.args[0][1]=='stop' for call in run.call_args_list))

    def test_failed_stop_preserves_filters_and_original_file(self):
        def fake_run(args):
            if args[1]=='stop':raise RuntimeError('stop failed')
            return SimpleNamespace(stdout='',returncode=0)
        with patch('tools.capture_gateway.run',side_effect=fake_run) as run, \
             patch('tools.capture_gateway.stale_capture_session',return_value=(self.etl,['DFLocal_82932_0'],82932)):
            with self.assertRaises(RuntimeError):recover_stale_capture('pktmon',self.status,self.root)
        self.assertTrue(self.etl.is_file())
        self.assertFalse(any(call.args[0][1:3]==['filter','remove'] for call in run.call_args_list))


if __name__=='__main__':unittest.main()
