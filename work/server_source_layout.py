"""Expand historical server source pins to include the canonical implementations."""
import json
from pathlib import Path, PurePosixPath

SERVER = 'outputs/df-local-server/'
PACKAGE = SERVER + 'dfserver/'


def expand_server_sources(root, relatives):
    root = Path(root).resolve()
    ordered = dict.fromkeys(relatives)
    manifest = root / PACKAGE / 'module_layout.json'
    if not manifest.is_file():
        if (root / PACKAGE / 'app').is_dir():
            raise ValueError('Organized server is missing its module layout manifest')
        return tuple(ordered)
    layout = json.loads(manifest.read_text(encoding='utf-8'))
    if layout.get('kind') != 'server_domain_module_layout_v1':
        raise ValueError('Unknown server module layout')
    selected = False
    for relative in tuple(ordered):
        if not relative.startswith(PACKAGE) or not relative.endswith('.py'):
            continue
        stem = relative[len(PACKAGE):-3]
        row = layout['modules'].get(stem)
        if row is None:
            continue
        source = row['source']
        expected = row['canonical'].replace('.', '/') + '.py'
        if (source != expected or '..' in PurePosixPath(source).parts or
                not source.startswith('dfserver/') or
                not (root / SERVER / source).resolve().is_relative_to((root / PACKAGE).resolve())):
            raise ValueError('Canonical server source escapes its package or mapping')
        ordered[SERVER + source] = None
        for parent in PurePosixPath(source).parents:
            if parent == PurePosixPath('.'):
                break
            ordered[SERVER + str(parent) + '/__init__.py'] = None
        selected = True
    if selected:
        for relative in (PACKAGE + '_compat.py', PACKAGE + '_paths.py',
                         PACKAGE + 'module_layout.json', 'work/server_source_layout.py'):
            ordered[relative] = None
    return tuple(ordered)
