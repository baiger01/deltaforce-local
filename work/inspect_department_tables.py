"""Run the original typed export scanner with the department-only schema scope."""

import ast
from pathlib import Path
import struct
import sys

from explore_tagged_export import read_row
from extract_native_safehouse_catalog import field_value


SOURCE = Path(__file__).with_name('inspect_season_tables.py')
TABLES = {
    'qualities': (0, 0, 'RoleQuality', 489440096, 413382416, 14),
    'traders': (0, 0, 'TraderInfo', 489455184, 413329280, 54),
}


def rows(raw, columns):
    root = 29 if struct.unpack_from('<i', raw, 37)[0] == 0 else 55
    none, instance, prefix, count = struct.unpack_from('<iiii', raw, root)
    if instance or prefix or not 1 <= count <= 20000:
        raise ValueError('Not a bounded department table')
    offset, layout, signature, result = root + 16, {}, None, []
    for index in range(count):
        start = offset
        tags, offset, layout = read_row(raw, offset + 8, none, known_types=layout)
        layout = dict(layout)
        inherited_count = 1 if columns[0]['member_offset'] == 16 else 0
        if len(tags) != len(columns) + inherited_count:
            raise ValueError('Complete native column count differs')
        current = [(tag['field'], tag['kind'], tag['metadata_bytes']) for tag in tags]
        if signature is not None and current != signature:
            raise ValueError('Native column order differs')
        signature = current
        types, native_types = {}, {}
        row = {'source_row': index, 'serialized_offset': start}
        for tag, column in zip(tags, columns):
            kind = 'int32' if column['kind'] == 'int' else column['kind']
            # Array tags share one serialized ArrayProperty regardless of element type.
            kind = 'array' if kind.startswith('TArray<') else kind
            if types.setdefault(tag['kind'], kind) != kind or native_types.setdefault(kind, tag['kind']) != tag['kind']:
                raise ValueError('Serialized and reflected property kinds differ')
            row[column['name']] = field_value(raw, tag, column['kind'])
        if inherited_count:
            inherited = tags[-1]
            if inherited['size'] != 8 or inherited['metadata_bytes'] or inherited['kind'] in types:
                raise ValueError('Inherited row key differs')
            row['row_key_fname_hex'] = raw[inherited['value_start']:inherited['end']].hex()
        result.append(row)
    if raw[offset:] != b'\xc1\x83\x2a\x9e':
        raise ValueError('Native table trailer differs')
    return result, {column['name']: tag['field'] for tag, column in zip(tags, columns)}


class DepartmentReport(ast.NodeTransformer):
    def visit_Constant(self, node):
        if node.value == 'work/evidence/season-table-candidates-20261006.json':
            return ast.copy_location(ast.Constant(
                'work/evidence/department-table-candidates-20261019.json'), node)
        return node


def main():
    if len(sys.argv) != 1:
        raise ValueError('Department candidate discovery never writes a production catalog')
    tree = DepartmentReport().visit(ast.parse(SOURCE.read_text(encoding='utf-8')))
    ast.fix_missing_locations(tree)
    namespace = {'__file__': str(SOURCE), '__name__': 'department_export_scanner'}
    exec(compile(tree, str(SOURCE), 'exec'), namespace)
    namespace['TABLES'] = TABLES
    namespace['rows'] = rows
    namespace['main']()


if __name__ == '__main__':
    main()
