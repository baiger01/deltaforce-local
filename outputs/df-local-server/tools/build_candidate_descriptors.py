"""Compile metadata only, without loading or executing the original client."""
from pathlib import Path
import argparse
import hashlib
import json
import sys

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from dfserver.candidate_schema import compile_candidate_descriptors


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('metadata', type=Path)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--report', type=Path, required=True)
    parser.add_argument('--class-metadata', type=Path)
    args = parser.parse_args()
    raw = args.metadata.read_bytes()
    if len(raw) > 64 * 1024 * 1024:
        raise ValueError('Metadata input exceeds its size limit')
    classes = class_raw = None
    if args.class_metadata is not None:
        class_raw = args.class_metadata.read_bytes()
        if len(class_raw) > 64 * 1024 * 1024:
            raise ValueError('Class metadata input exceeds its size limit')
        classes = json.loads(class_raw.decode('utf-8'))
    descriptor, report = compile_candidate_descriptors(json.loads(raw.decode('utf-8')), class_metadata=classes)
    report.update({'metadata_sha256': hashlib.sha256(raw).hexdigest(),
                   'descriptor_sha256': hashlib.sha256(descriptor).hexdigest()})
    if class_raw is not None:
        report['class_metadata_sha256'] = hashlib.sha256(class_raw).hexdigest()
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.report.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_bytes(descriptor)
    args.report.write_text(json.dumps(report, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')
    print(json.dumps({'messages_compiled': report['messages_compiled'],
                      'fields_compiled': report['fields_compiled'],
                      'excluded_messages': len(report['excluded_messages']),
                      'descriptor_pool_validation': report['descriptor_pool_validation'],
                      'original_client_compatibility_verified': False}, indent=2))


if __name__ == '__main__':
    main()
