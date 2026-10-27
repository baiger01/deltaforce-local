"""Read source registrations for quest reward effect research only."""

import ast
from pathlib import Path


NAMES = ('ItemUseFunction', 'RoleQuality', 'RoleQualityScene', 'RoleQualityConfig',
         'RoleQualityCard', 'RoleQualityUsage', 'ItemUseActionLimit', 'ItemUseAnimation',
         'GameItem', 'GameItemRow', 'ItemBase', 'ItemDataRow')


class RewardScope(ast.NodeTransformer):
    def visit_Tuple(self, node):
        if all(isinstance(value, ast.Constant) for value in node.elts):
            if tuple(value.value for value in node.elts) == (
                    'KeyBoxRow', 'KeyBoxUnlockRow', 'DFMKeyInfoRow', 'KeyChainSpaceInfo'):
                return ast.copy_location(ast.Tuple(
                    elts=[ast.Constant(name) for name in NAMES], ctx=ast.Load()), node)
        return self.generic_visit(node)

    def visit_Constant(self, node):
        if node.value == 'work/evidence/native-keycard-reflection-probe.json':
            return ast.copy_location(ast.Constant(
                'work/evidence/research-quest-reward-effects-20261019.json'), node)
        return node


if __name__ == '__main__':
    source = Path(__file__).with_name('probe_native_keycard_bindings.py')
    tree = RewardScope().visit(ast.parse(source.read_text(encoding='utf-8')))
    ast.fix_missing_locations(tree)
    namespace = {'__file__': str(source), '__name__': 'quest_reward_effect_probe'}
    exec(compile(tree, str(source), 'exec'), namespace)
    namespace['main']()
