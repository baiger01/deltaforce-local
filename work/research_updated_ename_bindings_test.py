"""Pure FName constructor pipeline tests; no runtime NamePool fixture."""
import struct
import unittest

from research_updated_metadata_roots import decoder
from research_updated_ename_bindings import extract_ename_bindings


class ENameBindingTests(unittest.TestCase):
    def fixture(self):
        data=bytearray(512); data[128:134]=b'Actor\0'; data[160:166]=b'Other\0'
        raw=bytearray()
        def pointer(target):
            raw.extend(b'\x48\x8d\x05'+struct.pack('<i',target-len(raw)-7))
            raw.extend(bytes.fromhex('4889442430'))
        pointer(128); raw.extend(bytes.fromhex('c744243805000000c644243c00'))
        raw.extend(b'\xe8'+struct.pack('<i',0x10b77890-len(raw)-5))
        raw.extend(bytes.fromhex('8b08'))
        pointer(160)
        raw.extend(bytes.fromhex('898bd8410100c3'))
        return data,list(decoder().disasm(bytes(raw),0))

    def test_table_assignment_tracks_returned_name_not_the_next_prepared_argument(self):
        data,ins=self.fixture()
        result=extract_ename_bindings(ins,lambda at,n:bytes(data[at:at+n]),{0x66})
        self.assertEqual(result[0]['literal_name'],'Actor')
        self.assertEqual(result[0]['ename_index'],0x66)

    def test_wrong_argument_length_and_missing_required_store_fail_closed(self):
        data,ins=self.fixture(); data[128:134]=b'Act\0\0\0'
        with self.assertRaises(ValueError): extract_ename_bindings(ins,lambda at,n:bytes(data[at:at+n]),{0x66})
        with self.assertRaises(ValueError): extract_ename_bindings(ins,lambda at,n:bytes(data[at:at+n]),{0x3b})

    def test_constructor_return_path_cannot_skip_the_selected_assignment(self):
        data,ins=self.fixture()
        skip=list(decoder().disasm(bytes((0xeb,ins[-1].address)), -2))[0]
        with self.assertRaises(ValueError):
            extract_ename_bindings([skip]+ins,lambda at,n:bytes(data[at:at+n]),{0x66})


if __name__=='__main__':
    unittest.main()
