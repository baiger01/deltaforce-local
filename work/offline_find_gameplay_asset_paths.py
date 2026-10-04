"""Bounded symbol/path inspection of already extracted resource bytes only."""
import hashlib
import json
from pathlib import Path

BASE = Path(__file__).resolve().parent.parent
PLAN = BASE / 'work/evidence/gameplay-class-asset-source-plan.json'
OUT = BASE / 'work/evidence/gameplay-class-asset-byte-search.json'


def literal(data, at, encoding):
    step = 1 if encoding == 'ascii' else 2
    start = end = at
    def char(pos):
        if pos < 0 or pos + step > len(data):
            return None
        raw = data[pos:pos + step]
        value = raw[0] if step == 1 else int.from_bytes(raw, 'little')
        return value if 32 <= value <= 126 else None
    for _ in range(512):
        if char(start - step) is None:
            break
        start -= step
    for _ in range(1024):
        if char(end) is None:
            break
        end += step
    raw = data[start:end]
    return dict(literal_offset=start, literal_bytes=len(raw),
                literal=raw.decode(encoding), literal_sha256=hashlib.sha256(raw).hexdigest(),
                complete_printable_run=(char(start - step) is None and char(end) is None))


def main():
    raw_plan = PLAN.read_bytes()
    plan = json.loads(raw_plan)
    if len(plan['sources']) > plan['max_files']:
        raise ValueError('Source-plan file count exceeds bound')
    root = (BASE / 'work/evidence').resolve()
    total = 0
    rows = []
    counts = {target: 0 for target in plan['targets']}
    for name in plan['sources']:
        path = (BASE / name).resolve()
        if not path.is_relative_to(root) or path.suffix not in ('.uasset', '.uexp'):
            raise ValueError('Source is outside extracted resource subset')
        size = path.stat().st_size
        if size > plan['max_per_file_bytes'] or total + size > plan['max_total_bytes']:
            raise ValueError('Resource-byte bound exceeded; no unreported skip')
        data = path.read_bytes()
        if len(data) != size:
            raise ValueError('Source size changed')
        total += size
        row = dict(relative_path=name, bytes=size, sha256=hashlib.sha256(data).hexdigest(),
                   matches=[])
        for target in plan['targets']:
            for enc in ('ascii', 'utf-16le'):
                needle = target.encode(enc)
                start = 0
                while True:
                    at = data.find(needle, start)
                    if at < 0:
                        break
                    if len(row['matches']) >= 128:
                        raise ValueError('Per-resource match bound exceeded')
                    hit = dict(target=target, encoding=enc, target_offset=at)
                    hit.update(literal(data, at, enc))
                    row['matches'].append(hit)
                    counts[target] += 1
                    start = at + len(needle)
        rows.append(row)
    output = dict(kind='bounded_existing_extracted_gameplay_class_path_byte_search',
                  source_plan='work/evidence/gameplay-class-asset-source-plan.json',
                  source_plan_sha256=hashlib.sha256(raw_plan).hexdigest(),
                  read_files=len(rows), read_bytes=total, target_occurrences=counts,
                  records=rows, process_read=False, new_extraction=False,
                  game_launch=False, server_changed=False,
                  qualification='Exact ASCII/UTF16 resource literals only; nearby names do not prove typed class/CDO outer assignments. No installed PAK payload scan or decryption.')
    OUT.write_text(json.dumps(output, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')
    print(json.dumps({k: output[k] for k in ('read_files', 'read_bytes', 'target_occurrences')},
                     ensure_ascii=False))
    print('evidence_sha256=' + hashlib.sha256(OUT.read_bytes()).hexdigest())


if __name__ == '__main__':
    main()
