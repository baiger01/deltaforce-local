"""Pure source-cache ordering tests; no fixture is a game binding."""
import unittest

from research_updated_source_map_schema import source_cache


def node(path,parent=None,properties=(),functions=()):
    return dict(path=path,parent=parent,properties=list(properties),functions=list(functions))


def prop(name,offset,dimension=1):
    return dict(name=name,offset=offset,array_dim=dimension,net=True)


def function(name,super_present=False):
    return dict(name=name,flags=0x40,super_present=super_present)


class SourceCacheTests(unittest.TestCase):
    def test_static_arrays_expand_class_reps_but_not_cache_indices(self):
        nodes={'A':node('A',properties=[prop('Array',4,3),prop('After',8)],functions=[function('RPC')])}
        result=source_cache(nodes,'A')
        self.assertEqual(result['exclusive_cache_index_maximum'],3)
        self.assertEqual(result['class_reps_count'],4)
        self.assertEqual([(f['name'],f['cache_index'],f.get('property_rep_index')) for f in result['fields']],
            [('Array',0,0),('After',1,3),('RPC',2,None)])

    def test_parent_count_and_case_insensitive_function_sort_are_preserved(self):
        nodes={'A':node('A',properties=[prop('Base',0)]),
            'B':node('B','A',functions=[function('z'),function('Apple'),function('Inherited',True)])}
        result=source_cache(nodes,'B')
        self.assertEqual([(r['name'],r['cache_index']) for r in result['fields']],
            [('Base',0),('Apple',1),('z',2)])

    def test_comparator_ties_cycle_and_missing_parent_fail_closed(self):
        for nodes,root in (({'A':node('A',properties=[prop('X',0),prop('x',0)])},'A'),
                ({'A':node('A','A')},'A'),({'A':node('A','B')},'A')):
            with self.assertRaises(ValueError): source_cache(nodes,root)

    def test_negative_offsets_and_truncated_dimensions_fail_closed(self):
        for p in (prop('Negative',-1),prop('ZeroDim',0,0)):
            with self.assertRaises(ValueError): source_cache({'A':node('A',properties=[p])},'A')


if __name__=='__main__':
    unittest.main()
