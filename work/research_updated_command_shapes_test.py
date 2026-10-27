"""Pure recursive command-shape tests without game inputs."""
import unittest

from research_updated_command_shapes import command_shapes


def field(name,kind='FIntProperty',offset=0,**kwargs):
    return dict(name=name,kind=kind,offset=offset,array_dim=1,flags=0,children=[],**kwargs)


class CommandShapeTests(unittest.TestCase):
    def test_nested_array_child_handles_do_not_increment_outer_scope(self):
        inner=field('Inner',offset=0)
        array=field('Items','FArrayProperty',offset=16); array['children']=[inner]
        result=command_shapes([array,field('Next',offset=32)],{})
        self.assertEqual([(r['kind'],r['relative_handle'],r['scope']) for r in result['commands']],
            [('array',1,[]),('leaf',1,['Items']),('return',0,['Items']),('leaf',2,[])])
        self.assertEqual(result['outer_handle_maximum'],2)
        self.assertEqual(result['commands'][0]['end_command_exclusive'],3)

    def test_struct_super_fields_are_sorted_and_rep_skip_is_excluded(self):
        structs={'B':dict(name='Base',parent=None,net_serializer=False,fields=[field('Base',offset=4)]),
            'D':dict(name='Derived',parent='B',net_serializer=False,fields=[field('First',offset=0),field('Skip',offset=8)])}
        structs['D']['fields'][1]['flags']=0x80000000
        root=field('Root','FStructProperty',offset=100,struct='D')
        result=command_shapes([root,field('After',offset=120)],structs)
        self.assertEqual([(r['name'],r['relative_handle'],r['constructor_offset_sum']) for r in result['commands']],
            [('First',1,100),('Base',2,104),('After',3,120)])

    def test_native_net_serializer_struct_is_one_leaf(self):
        structs={'S':dict(name='Native',parent=None,net_serializer=True,fields=[field('Ignored')])}
        result=command_shapes([field('Packed','FStructProperty',struct='S')],structs)
        self.assertEqual([(r['name'],r['relative_handle']) for r in result['commands']],[('Packed',1)])

    def test_missing_struct_ops_type_and_static_array_extent_fail_closed(self):
        for structures in ({},{'S':dict(name='Unknown',parent=None,net_serializer=None,fields=[])}):
            with self.assertRaises(ValueError): command_shapes([field('Value','FStructProperty',struct='S')],structures)
        malformed=field('Array'); malformed['array_dim']=2
        with self.assertRaises(ValueError): command_shapes([malformed],{})

    def test_bad_array_arity_and_recursive_struct_cycle_fail_closed(self):
        with self.assertRaises(ValueError): command_shapes([field('Missing','FArrayProperty')],{})
        structs={'S':dict(name='Recursive',parent=None,net_serializer=False,
            fields=[field('Self','FStructProperty',struct='S')])}
        with self.assertRaises(ValueError): command_shapes([field('Root','FStructProperty',struct='S')],structs)


if __name__=='__main__':
    unittest.main()
