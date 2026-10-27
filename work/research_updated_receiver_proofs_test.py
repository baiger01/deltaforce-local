import struct
import unittest

from research_updated_rpc_receive import witness
from research_updated_network_config import selected_lines
from research_updated_header_context import table
from research_updated_metadata_roots import decoder


class ReceiverProofTests(unittest.TestCase):
    def test_exact_witness_rejects_missing_and_changed_instruction(self):
        row = dict(rva='0x10',instruction='ret')
        self.assertEqual(witness({16:row},16,'ret','terminal')['rva'],'0x10')
        with self.assertRaises(ValueError):
            witness({},16,'ret','terminal')
        with self.assertRaises(ValueError):
            witness({16:row},16,'jmp 0x20','terminal')

    def test_config_array_operators_order_and_section_are_preserved(self):
        raw = (b'[/Script/Engine.NetDriver]\n; +ChannelDefinitions=ignored\n'
            b'!ChannelDefinitions=CLEAR_ARRAY\n+ChannelDefinitions=(ChannelName=Actor,ClassName=GPActorChannel)\n')
        rows = selected_lines(raw)
        self.assertEqual([r['key'] for r in rows],['!ChannelDefinitions','+ChannelDefinitions'])
        self.assertEqual([r['line'] for r in rows],[3,4])
        self.assertTrue(all(r['section']=='/Script/Engine.NetDriver' for r in rows))

    def test_utf16_network_config_and_local_bound(self):
        raw = b'\xff\xfe'+'[X]\nGameEngine=/Script/GPGameplay.GPGameEngine'.encode('utf-16le')
        self.assertEqual(selected_lines(raw)[0]['key'],'GameEngine')
        with self.assertRaises(ValueError):
            selected_lines(b'x'*(8*1024*1024+1))

    def test_table_proof_rejects_changed_slot_and_source_assignment(self):
        class Fixture:
            base = 0x140000000

            def instructions(self,root):
                return list(decoder().disasm(bytes.fromhex('488d05f90f0000488903c3'),0x1000))

            @staticmethod
            def rip(ins):
                return ins.address+ins.size+ins.operands[1].mem.disp

            def read(self,rva,size):
                self.last_read = (rva,size)
                return struct.pack('<Q',self.base+0x3000)

        a = Fixture()
        result = table(a,0x1000,0x1000,0x1007,'mov qword ptr [rbx], rax',0x2000,{0x260:0x3000})
        self.assertEqual(result['methods'][0]['target_rva'],'0x3000')
        self.assertEqual(a.last_read,(0x2260,8))
        with self.assertRaises(ValueError):
            table(a,0x1000,0x1000,0x1007,'mov qword ptr [rbx], rax',0x2000,{0x260:0x3010})
        with self.assertRaises(ValueError):
            table(a,0x1000,0x1000,0x1007,'mov qword ptr [rdi], rax',0x2000,{0x260:0x3000})


if __name__ == '__main__':
    unittest.main()
