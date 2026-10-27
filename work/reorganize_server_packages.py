"""Mechanically organize server modules; default mode only previews changes."""
import argparse
import ast
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import zipfile

ROOT = Path(__file__).resolve().parent.parent
PACKAGE = ROOT / 'outputs/df-local-server/dfserver'
GROUPS = {
    'app': ('业务事务与共享编排', 'core'),
    'entry': ('服务入口、HTTP与区服发现', 'http_api entrance zone_discovery'),
    'account': ('账号、身份、设置与会话', 'accounts native_identity native_settings native_session_auxiliary local_chat'),
    'inventory': ('库存、容器、仓库、安全箱与卡包', 'container_layouts deposit_sort native_keycards native_keychains native_prop_bindings native_warehouse_extensions native_warehouse_growth native_warehouse_wire safe_boxes'),
    'weapons': ('枪械、配件、弹药、近战与插槽', 'weapon_ammo weapon_assembly weapon_components melee_weapons socket_guid'),
    'commerce': ('交易、商城礼包与曼德尔扫描', 'local_commerce premium_shop mandel'),
    'cosmetics': ('干员、枪械、账户外观与收藏', 'gun_skins hero_customization profile_cosmetics weapon_pendants native_collection'),
    'progression': ('任务、声望、设施、通行证与赛季', 'battle_pass native_action_progress native_department_queries native_departments native_quest_abandon native_quest_conditions native_quest_rewards native_quest_wallet native_quests native_safehouse native_safehouse_progress native_season'),
    'match': ('战局准入与局内服务编排', 'game_server_probe legacy_ds_match_admission native_match_unavailable'),
    'transport/gcp': ('大厅分帧、认证、握手与加密', 'gcp_control gcp_crypto gcp_data gcp_framing gcp_handshake'),
    'transport/native': ('原生战局连接、控制消息与可靠交付', 'legacy_ds_bit_archive legacy_ds_control_connection legacy_ds_control_fields legacy_ds_control_probe legacy_ds_decoded_bunch legacy_ds_handshake_probe legacy_ds_identity_field legacy_ds_login_fields legacy_ds_packet_ack_probe legacy_ds_wire_codec unreal_handshake_payload'),
    'replication': ('Actor、NetGUID、复制字段与序列化', 'legacy_ds_actor_bunch legacy_ds_actor_content legacy_ds_actor_fields legacy_ds_actor_manifest legacy_ds_actor_open legacy_ds_class_net_cache legacy_ds_game_spawn_flags legacy_ds_guid_exports legacy_ds_quantized_vector legacy_ds_scalar_serializers'),
    'gateway': ('大厅业务协议与原客户端请求分发', 'handshake_diagnostic business_envelope candidate_business candidate_schema protobuf_codec client_errors'),
    'diagnostics': ('连接与业务消息诊断', 'business_probe connection_probe'),
}
CLI = {'__main__', 'accounts', 'entrance', 'connection_probe', 'handshake_diagnostic'}
MAPPING = {name: 'dfserver.' + group.replace('/', '.') + '.' + name
           for group, (_, names) in GROUPS.items() for name in names.split()}
MAPPING['__main__'] = 'dfserver.entry.cli'


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def migrated_source(raw):
    source = raw.decode('utf-8')
    tree = ast.parse(source)
    lines = raw.splitlines(keepends=True)
    starts = [0]
    for line in lines:
        starts.append(starts[-1] + len(line))
    edits = []
    used_paths = set()
    for node in ast.walk(tree):
        replacement = None
        if isinstance(node, ast.ImportFrom) and (node.level == 1 or node.level == 0 and node.module == 'dfserver'):
            if node.module not in (None, 'dfserver'):
                if node.module not in MAPPING:
                    raise ValueError('Unclassified relative import: ' + node.module)
                replacement = 'from ' + MAPPING[node.module] + ' import ' + ', '.join(
                    alias.name + (' as ' + alias.asname if alias.asname else '') for alias in node.names)
            else:
                imports = []
                for alias in node.names:
                    parent = MAPPING[alias.name].rsplit('.', 1)[0] if alias.name in MAPPING else 'dfserver'
                    imports.append('from ' + parent + ' import ' + alias.name +
                                   (' as ' + alias.asname if alias.asname else ''))
                replacement = ('\n' + ' ' * node.col_offset).join(imports)
        elif isinstance(node, ast.Attribute):
            expression = ast.unparse(node)
            if expression == 'Path(__file__).resolve().parent.parent':
                replacement = 'SERVER_ROOT'
                used_paths.add('SERVER_ROOT')
            elif expression == 'Path(__file__).resolve().parent':
                replacement = 'PACKAGE_ROOT'
                used_paths.add('PACKAGE_ROOT')
        if replacement is not None:
            start = starts[node.lineno - 1] + node.col_offset
            end = starts[node.end_lineno - 1] + node.end_col_offset
            if not any(a <= start and end <= b for a, b, _ in edits):
                edits.append((start, end, replacement.encode('utf-8')))
    for start, end, replacement in sorted(edits, reverse=True):
        raw = raw[:start] + replacement + raw[end:]
    if used_paths:
        # Larger resource expressions subsume their inner parent expression.
        actual = {name for name in used_paths if name.encode() in raw}
        insertion = 0
        for index, node in enumerate(tree.body):
            if index == 0 and isinstance(node, ast.Expr) and isinstance(node.value, ast.Constant) and isinstance(node.value.value, str):
                insertion = starts[node.end_lineno]
            elif isinstance(node, ast.ImportFrom) and node.module == '__future__':
                insertion = starts[node.end_lineno]
            else:
                break
        statement = ('from dfserver._paths import ' + ', '.join(sorted(actual)) + '\n').encode()
        raw = raw[:insertion] + statement + raw[insertion:]
    compile(raw, '<migrated-server-module>', 'exec')
    return raw


def shim(name, canonical):
    description = '"""Compatibility entry point; edit ' + canonical + ' instead."""\n'
    if name in CLI:
        return (description + 'if __name__ == "__main__":\n'
                '    from ' + canonical + ' import main\n'
                '    raise SystemExit(main())\n'
                'else:\n'
                '    from dfserver._compat import alias_module\n'
                '    alias_module(__name__, "' + canonical + '")\n').encode()
    return (description + 'from dfserver._compat import alias_module\n'
            'alias_module(__name__, "' + canonical + '")\n').encode()


def prepare():
    actual = {path.stem for path in PACKAGE.glob('*.py')} - {'__init__', '_compat', '_paths'}
    if actual != MAPPING.keys():
        raise ValueError('Module inventory differs from reviewed mapping: ' + repr(actual ^ MAPPING.keys()))
    changes = []
    for name, canonical in MAPPING.items():
        old = PACKAGE / (name + '.py')
        new = PACKAGE.parent / (canonical.replace('.', '/') + '.py')
        if not new.resolve().is_relative_to(PACKAGE.resolve()) or new.exists() or old.is_symlink():
            raise ValueError('Target exists or escapes the intended package: ' + str(new))
        raw = old.read_bytes()
        changes.append((old, new, raw, migrated_source(raw), shim(name, canonical)))
    return changes


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--apply', action='store_true')
    args = parser.parse_args()
    changes = prepare()
    print(json.dumps({'modules': len(changes), 'groups': len(GROUPS), 'apply': args.apply}))
    if not args.apply:
        return
    backup = ROOT / 'work/evidence/server-layout-20261020-before.zip'
    if backup.exists():
        parser.error('Refusing to replace the original source backup')
    for old, _, raw, _, _ in changes:
        if old.read_bytes() != raw:
            raise ValueError('Source changed during preflight: ' + str(old))
    with zipfile.ZipFile(backup, 'x', compression=zipfile.ZIP_DEFLATED) as archive:
        for old, _, raw, _, _ in changes:
            archive.writestr(old.relative_to(ROOT).as_posix(), raw)
    records = {}
    for old, new, raw, migrated, wrapper in changes:
        new.parent.mkdir(parents=True, exist_ok=True)
        new.write_bytes(migrated)
        old.write_bytes(wrapper)
        records[old.stem] = {'canonical': MAPPING[old.stem], 'source': new.relative_to(PACKAGE.parent).as_posix(),
                             'before_sha256': sha(raw), 'after_sha256': sha(migrated)}
    for group, (purpose, names) in GROUPS.items():
        directory = PACKAGE / group
        (directory / '__init__.py').write_text('"""' + purpose + '."""\n', encoding='utf-8')
        entries = names.split() + (['cli'] if group == 'entry' else [])
        text = '# ' + purpose + '\n\n本目录是实际实现。根包同名文件是旧路径兼容入口。\n\n'
        for name in entries:
            content = ast.parse((directory / (name + '.py')).read_text(encoding='utf-8'))
            summary = (ast.get_docstring(content) or purpose).splitlines()[0]
            text += '- [' + name + '.py](' + name + '.py)：' + summary + '\n'
        text += '\n资源位置统一读取 `dfserver._paths`；修改后运行服务根目录的测试。总览见[结构说明](../../../../docs/architecture/SERVER_LAYOUT.md)。\n'
        # Nested transport packages have one additional directory level.
        if '/' in group:
            text = text.replace('../../../../docs', '../../../../../docs')
        (directory / 'README.md').write_text(text, encoding='utf-8')
    (PACKAGE / 'transport/__init__.py').write_text('"""Lobby and native match network transports."""\n', encoding='utf-8')
    (PACKAGE / 'transport/README.md').write_text('# 网络传输\n\n- [gcp](gcp/README.md)：大厅TCP分帧、握手、认证与加密。\n- [native](native/README.md)：原生战局控制连接、ACK和线格式。\n\n业务请求分发在 `gateway`，Actor复制在 `replication`。\n', encoding='utf-8')
    manifest = {'kind': 'server_domain_module_layout_v1', 'created_at_utc': datetime.now(timezone.utc).isoformat(),
                'groups': {group: purpose for group, (purpose, _) in GROUPS.items()}, 'modules': records,
                'resource_root_unchanged': True, 'account_database_accessed': False,
                'backup': backup.relative_to(ROOT).as_posix()}
    (PACKAGE / 'module_layout.json').write_text(json.dumps(manifest, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')
    print(json.dumps({'written_modules': len(records), 'backup': str(backup)}, ensure_ascii=True))


if __name__ == '__main__':
    main()
