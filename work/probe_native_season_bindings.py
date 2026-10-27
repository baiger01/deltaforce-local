"""Reuse the read-only native registration probe for original season structs."""

import ast
from pathlib import Path


SOURCE = Path(__file__).with_name('probe_native_keycard_bindings.py')
STRUCTS = ('RankingSeasonInfo', 'TournamentSeason', 'SeasonDataRow')


class SeasonScope(ast.NodeTransformer):
    def visit_Tuple(self, node):
        if all(isinstance(value, ast.Constant) for value in node.elts):
            if tuple(value.value for value in node.elts) == (
                    'KeyBoxRow', 'KeyBoxUnlockRow', 'DFMKeyInfoRow', 'KeyChainSpaceInfo'):
                return ast.copy_location(ast.Tuple(
                    elts=[ast.Constant(name) for name in STRUCTS], ctx=ast.Load()), node)
        return self.generic_visit(node)

    def visit_Constant(self, node):
        if node.value == 'work/evidence/native-keycard-reflection-probe.json':
            return ast.copy_location(ast.Constant(
                'work/evidence/native-season-reflection-probe.json'), node)
        return node


def main():
    tree = SeasonScope().visit(ast.parse(SOURCE.read_text(encoding='utf-8')))
    ast.fix_missing_locations(tree)
    namespace = {'__file__': str(SOURCE), '__name__': 'season_reflection_probe'}
    exec(compile(tree, str(SOURCE), 'exec'), namespace)
    namespace['main']()


if __name__ == '__main__':
    main()
