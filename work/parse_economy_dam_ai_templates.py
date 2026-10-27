"""Inspect hashed installed AI world exports, without activating any template."""
import argparse
from collections import Counter
import hashlib
import json
from pathlib import Path
import struct

from extract_operator_avatar_catalog import fname, tags
from parse_economy_installed_tables import tag_value
from recover_dam_gameplay_catalog import Package
from recover_economy_pak_access import fstring, installed_name_map


ROOT = Path(__file__).resolve().parent.parent


class InstalledWorld(Package):
    def __init__(self, header_record, payload_record):
        self.header = self.checked_record(header_record)
        self.payload = self.checked_record(payload_record)
        self.names = installed_name_map(self.header)
        versions = struct.unpack_from('<i', self.header, 20)[0]
        field = 41 + versions * 20
        ec, eo, ic, io = struct.unpack_from('<4i', self.header, field + 16)
        depends = struct.unpack_from('<i', self.header, field + 32)[0]
        if not (0 < ec <= 5000 and 0 < ic <= 5000 and depends-eo == ec*104 and eo-io == ic*28):
            raise ValueError('Unobserved export/import boundaries')
        self.imports = [fname(self.header, io+i*28+20, self.names) for i in range(ic)]
        self.import_rows = [dict(name=self.imports[i], outer_index=struct.unpack_from('<i', self.header, io+i*28+16)[0],
                                class_name=fname(self.header, io+i*28+8, self.names)) for i in range(ic)]
        self.exports = []
        previous_end = len(self.header)
        for i in range(ec):
            at = eo+i*104
            cls, _, _, outer = struct.unpack_from('<4i', self.header, at)
            size, offset = struct.unpack_from('<qq', self.header, at+28)
            if not 0 <= size <= 8*1024*1024 or offset != previous_end:
                raise ValueError('Nonsequential export extent')
            previous_end = offset+size
            flags = struct.unpack_from('<3i', self.header, at+44)
            if not all(flag in (0, 1) for flag in flags):
                raise ValueError('Export filtering flags changed')
            self.exports.append(dict(index=i+1, name=fname(self.header, at+16, self.names),
                class_index=cls, outer_index=outer, size=size, offset=offset-len(self.header),
                filter_flags=dict(zip(('forced_export', 'not_for_client', 'not_for_server'), map(bool, flags)))))
        if previous_end-len(self.header)+4 != len(self.payload) or self.payload[-4:] != b'\xc1\x83\x2a\x9e':
            raise ValueError('Companion extent/terminator mismatch')
        self.property_cache = {}
        for row in self.exports:
            self.properties(row['index'])
        self.source = dict(indexed_path=header_record['path'], uasset_sha256=header_record['decoded_sha256'],
            uexp_sha256=payload_record['decoded_sha256'], export_count=ec,
            payload_association='same exact validated indexed stem and complete export extent')

    @staticmethod
    def checked_record(record):
        path = ROOT/record['output']
        data = path.read_bytes()
        if len(data) != record['bytes'] or hashlib.sha256(data).hexdigest() != record['decoded_sha256']:
            raise ValueError('Extracted payload differs from validated manifest')
        return data

    def full_object(self, index, depth=0):
        if depth > 16:
            raise ValueError('Import outer chain exceeds bound')
        if index >= 0:
            return self.object(index)
        row = self.import_rows[-index-1]
        prefix = self.full_object(row['outer_index'], depth+1) if row['outer_index'] else None
        return (prefix+'.' if prefix else '')+row['name']

    def decoded(self, tag):
        if tag['kind'] in ('SoftObjectProperty', 'SoftClassProperty'):
            name = fname(self.payload, tag['value_start'], self.names)
            subpath, end = fstring(self.payload, tag['value_start']+8)
            if end != tag['end']:
                raise ValueError('Soft reference exceeds its property')
            return name+((':'+subpath) if subpath else '')
        if tag['kind'] == 'StructProperty' and tag['meta'] == ['EncVector'] and tag['size'] == 12:
            return dict(serialized_type='EncVector', serialized_float32=list(struct.unpack_from('<3f', self.payload, tag['value_start'])),
                        runtime_world_coordinates_verified=False)
        try:
            value = tag_value(self.payload, tag, self.names)
            if isinstance(value, dict) and 'serialized_hex' in value:
                raise ValueError('Unsupported typed value')
            return value
        except (ValueError, struct.error, UnicodeError) as error:
            raw = self.payload[tag['value_start']:tag['end']]
            return dict(unparsed_kind=tag['kind'], meta=tag['meta'], bytes=len(raw),
                        payload_sha256=hashlib.sha256(raw).hexdigest(), reason=str(error))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--storage', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--include-blueprints', action='store_true')
    args = parser.parse_args()
    if args.output.exists() or not args.output.resolve().is_relative_to(ROOT/'work/evidence'):
        parser.error('Use a fresh evidence output')
    source_raw = args.storage.read_bytes()
    storage = json.loads(source_raw)
    if not storage['all_primary_indices_sha1_valid'] or not storage['all_secondary_indices_sha1_valid']:
        raise ValueError('Storage coverage is not validated')
    result = dict(kind='static_installed_dam_ai_template_exports', process_access=False, client_launched=False,
                  source_storage_sha256=hashlib.sha256(source_raw).hexdigest(), packages=[], failures=[],
                  template_activation_claimed=False, ai_runtime_or_replication_implemented=False)
    for pak in storage['paks']:
        assets = {row['path']: row for row in pak['extracted_assets']}
        for path, row in assets.items():
            suffix = '.uasset' if path.endswith('.uasset') and args.include_blueprints else '.umap'
            if not path.endswith(suffix):
                continue
            try:
                pkg = InstalledWorld(row, assets[path[:-len(suffix)]+'.uexp'])
                exports = []
                for export in pkg.exports:
                    cls = pkg.object(export['class_index'])
                    properties = pkg.properties(export['index'])
                    if cls.startswith('BP_') or cls in ('DramaAISpawnComponent', 'AIZoneBox', 'GuardPoint'):
                        exports.append(dict(export=export['index'], actor=export['name'],
                            class_name=cls, class_import=pkg.full_object(export['class_index']),
                            outer=pkg.object(export['outer_index']), filter_flags=export['filter_flags'],
                            payload_offset=export['offset'], payload_bytes=export['size'],
                            transform=pkg.root_transform(export['index']),
                            properties={name: dict(value=pkg.decoded(tag), serialized_kind=tag['kind'],
                                payload_offset=tag['value_start'], payload_bytes=tag['size'])
                                for name, tag in properties.items()}))
                result['packages'].append(dict(source=pkg.source, classes=dict(Counter(e['class_name'] for e in exports)), exports=exports))
            except (ValueError, struct.error, KeyError) as error:
                result['failures'].append(dict(path=path, reason=str(error)))
    result['counts'] = dict(packages=len(result['packages']), failures=len(result['failures']),
                            selected_exports=sum(len(p['exports']) for p in result['packages']))
    encoded = (json.dumps(result, indent=2, ensure_ascii=False)+'\n').encode('utf8')
    with args.output.open('xb') as stream:
        stream.write(encoded)
    print(json.dumps(dict(output=str(args.output), sha256=hashlib.sha256(encoded).hexdigest(), counts=result['counts'], failures=result['failures'])))


if __name__ == '__main__':
    main()
