"""Pure current leaf-branch precedence tests, using synthetic class IDs."""
import unittest

from research_updated_minimum_leaf_bindings import minimal_opcode


class MinimumOpcodeTests(unittest.TestCase):
    def ids(self):
        names=('Struct','Bool','Float','Int','Byte','ObjectBase','SoftObject','WeakObject','Name','UInt32','UInt64','Str')
        return {name:1<<i for i,name in enumerate(names)}

    def test_native_bool_and_bitfield_use_distinct_branches(self):
        ids=self.ids()
        self.assertEqual(minimal_opcode(ids['Bool'],ids,True),21)
        self.assertEqual(minimal_opcode(ids['Bool'],ids,False),3)

    def test_signed_int64_uses_default_leaf_and_uint64_has_special_opcode(self):
        ids=self.ids()
        self.assertEqual(minimal_opcode(1<<40,ids,None),2)
        self.assertEqual(minimal_opcode(ids['UInt64'],ids,None),20)

    def test_object_subtypes_preserve_native_branch_precedence(self):
        ids=self.ids()
        self.assertEqual(minimal_opcode(ids['ObjectBase'],ids,None),8)
        self.assertEqual(minimal_opcode(ids['ObjectBase']|ids['SoftObject'],ids,None),22)
        self.assertEqual(minimal_opcode(ids['ObjectBase']|ids['WeakObject'],ids,None),23)

    def test_struct_and_unknown_boolean_masks_are_not_guessed(self):
        ids=self.ids()
        with self.assertRaises(ValueError): minimal_opcode(ids['Struct'],ids,None)
        with self.assertRaises(ValueError): minimal_opcode(ids['Bool'],ids,None)


if __name__=='__main__':
    unittest.main()
