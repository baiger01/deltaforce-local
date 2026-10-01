"""Local packing policy for the installed client's warehouse sort protocol."""

from functools import lru_cache
import json
from pathlib import Path

from .core import fail


@lru_cache(maxsize=1)
def warehouse_size():
    catalog = json.loads((Path(__file__).resolve().parent.parent /
                          'protocol/deposit_slot_catalog.json').read_text(encoding='utf-8'))
    row = catalog['rows'][str(catalog['main_container_slot_id'])]
    return int(row['grid_length']), int(row['grid_width'])


def pack_items(items, config):
    """Use deterministic first-fit packing; this is not a recovered server algorithm."""
    width, height = warehouse_size()

    def dimensions(item):
        x, y = item['length'], item['width']
        return (y, x) if item.get('rotated') else (x, y)

    def order(item):
        x, y = dimensions(item)
        size = (-x * y, -max(x, y), -y, -x)
        # Group identical templates for the local category-oriented mode.
        group = (item['template_id'],)
        return (*group, *size, item['gid']) if config.get('sort_style') == 1 else (
            *size, *group, item['gid'])

    occupied, packed = set(), []
    for item in sorted(items, key=order):
        size_x, size_y = dimensions(item)
        found = None
        for y in range(height):
            for x in range(width):
                for span_x, span_y, rotated in ((size_x, size_y, False), (size_y, size_x, True)):
                    if x + span_x > width or y + span_y > height:
                        continue
                    cells = {(cx, cy) for cx in range(x, x + span_x)
                             for cy in range(y, y + span_y)}
                    if not cells & occupied:
                        found = {**item, 'x': x, 'y': y, 'length': span_x,
                                 'width': span_y, 'rotated': rotated}
                        occupied.update(cells)
                        break
                if found is not None:
                    break
            if found is not None:
                break
        if found is None:
            fail('WAREHOUSE_FULL', 'No complete arrangement fits the selected warehouse page')
        packed.append(found)
    return packed
