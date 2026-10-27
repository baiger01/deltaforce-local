"""Read original role-quality and trader registrations without running the game."""

import ast
import argparse

from probe_native_season_bindings import SOURCE, SeasonScope


STRUCTS = ('RoleQuality', 'RoleQualityScene', 'TraderInfo', 'RepLevelConfig',
           'RoleQualityConfig', 'QuestObjectiveRow')


class DepartmentScope(SeasonScope):
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
                'work/evidence/native-department-reflection-probe.json'), node)
        return node


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--objectives-only', action='store_true')
    args = parser.parse_args()
    global STRUCTS
    if args.objectives_only:
        STRUCTS = ('QuestObjectiveRow',)
    tree = DepartmentScope().visit(ast.parse(SOURCE.read_text(encoding='utf-8')))
    ast.fix_missing_locations(tree)
    namespace = {'__file__': str(SOURCE), '__name__': 'department_reflection_probe'}
    exec(compile(tree, str(SOURCE), 'exec'), namespace)
    namespace['main']()


if __name__ == '__main__':
    main()
