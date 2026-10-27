"""Synthetic constructor-assignment tracking, with no native execution."""
import unittest

from research_updated_metadata_roots import decoder
from research_updated_source_template_bindings import constructor_assignments


class ConstructorAssignmentTests(unittest.TestCase):
    def test_primary_and_secondary_assignments_preserve_this_alias(self):
        raw=bytes.fromhex('4889cf488d0500100000488907488d0500200000488987600a0000c3')
        rows=constructor_assignments(list(decoder().disasm(raw,0)))
        self.assertEqual([(r['object_offset'],r['source_rva']) for r in rows],[(0,0x100a),(0xa60,0x2014)])

    def test_call_clobbers_volatile_pointer_values(self):
        raw=bytes.fromhex('4889cf488d0500100000e800000000488907c3')
        self.assertEqual(constructor_assignments(list(decoder().disasm(raw,0))),[])

    def test_initializer_object_pointer_is_not_the_initializer_itself(self):
        raw=bytes.fromhex('488b194885db488d0500100000488903c3')
        ins=list(decoder().disasm(raw,0))
        self.assertEqual(constructor_assignments(ins),[])
        self.assertEqual(constructor_assignments(ins,from_initializer=True)[0]['object_offset'],0)


if __name__=='__main__':
    unittest.main()
