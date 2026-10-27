"""Bounded metadata reader for the preserved UE package summary variant.

This reads decoded .uasset headers only. Imports identify references; candidate
own paths additionally require a matching root export name.
"""

import struct


def package(data):
    if len(data) < 45 or data[:4] != b'\xc1\x83\x2a\x9e':
        return None
    custom = struct.unpack_from('<i', data, 20)[0]
    summary = 41 + custom * 20
    if not 0 <= custom <= 1024 or summary + 32 > len(data):
        return None
    count, offset = struct.unpack_from('<ii', data, summary)
    if not 0 < count < 100000 or not summary < offset < len(data):
        return None
    names = []
    for _ in range(count):
        if offset + 4 > len(data):
            raise ValueError('Truncated package name map')
        length = struct.unpack_from('<i', data, offset)[0]
        offset += 4
        if not length or abs(length) > 100000:
            raise ValueError('Invalid package name length')
        width = 2 if length < 0 else 1
        size = abs(length) * width
        if offset + size + 4 > len(data) or data[offset + size - width:offset + size] != bytes(width):
            raise ValueError('Invalid package name bounds or termination')
        names.append(data[offset:offset + size - width].decode('utf-16-le' if length < 0 else 'utf-8'))
        offset += size + 4
    exports_count, exports_offset, imports_count, imports_offset = struct.unpack_from('<iiii', data, summary + 16)
    for table_count, table_offset, stride in [(exports_count, exports_offset, 104), (imports_count, imports_offset, 28)]:
        if not 0 <= table_count < 100000 or not 0 <= table_offset <= len(data) or table_offset + table_count * stride > len(data):
            raise ValueError('Invalid package import/export map bounds')

    def fname(at):
        index, number = struct.unpack_from('<ii', data, at)
        if not 0 <= index < len(names) or number < 0:
            raise ValueError('Invalid package FName index')
        return names[index] if number == 0 else f'{names[index]}_{number - 1}'

    imports = []
    for index in range(imports_count):
        at = imports_offset + index * 28
        imports.append({'class_package': fname(at), 'class': fname(at + 8),
                        'outer': struct.unpack_from('<i', data, at + 16)[0], 'object': fname(at + 20)})
    exports = []
    for index in range(exports_count):
        at = exports_offset + index * 104
        class_index, _, _, outer = struct.unpack_from('<iiii', data, at)
        if class_index < 0 and -class_index > len(imports):
            raise ValueError('Invalid export class import index')
        exports.append({'object': fname(at + 16), 'outer': outer,
                        'class': imports[-class_index - 1]['object'] if class_index < 0 else None,
                        'class_index': class_index})
    imported_packages = {row['object'] for row in imports if row['class'] == 'Package' and row['outer'] == 0}
    root_names = {row['object'] for row in exports if row['outer'] == 0}
    root_names.update(value[:-2] for value in list(root_names) if value.endswith('_C'))
    own_paths = [name for name in names if name.startswith('/Game/') and name not in imported_packages
                 and '.' not in name and name.rsplit('/', 1)[-1] in root_names]
    return {'own_paths': own_paths, 'exports': exports, 'imports': imports,
            'name_count': count, 'names': names}
