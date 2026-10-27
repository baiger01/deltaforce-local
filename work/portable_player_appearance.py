"""Resolve catalog-backed values for an explicit local appearance policy.

The caller supplies the operator and equipped suit captured at match admission.
This local diagnostic policy shows that suit to both teams; it does not claim
to reproduce the original server's team visibility or fashion priority rules.
Nothing is sent here and catalog matching does not prove native application.
"""


def avatar_ids_for_selection(hero_id, fashion_id, hero_catalog, avatar_catalog):
    if any(type(value) is not int or not 0 < value < 1 << 63 for value in (hero_id, fashion_id)):
        raise ValueError('The current selected operator and equipped suit are required')
    suits = [r for r in hero_catalog['fashions'] if r['id'] == fashion_id and r['hero_id'] == hero_id]
    if len(suits) != 1:
        raise ValueError('Equipped suit does not uniquely belong to the selected native operator')
    rows = avatar_catalog['rows']
    avatar_id = fashion_id
    avatar = rows.get(str(avatar_id))
    if not avatar or avatar.get('id') != str(avatar_id) or avatar.get('character_tag') != 'ECharacterTag::Hero':
        raise ValueError('Equipped suit has no existing native human avatar row')
    for view in ('FPP', 'TPP'):
        if not any(type(p.get('mesh_path')) is str and p['mesh_path'].startswith('/Game/')
                   for p in avatar.get('views', {}).get(view, {}).get('core_parts', [])):
            raise ValueError('Selected native avatar lacks a configured ' + view + ' mesh')
    return hero_id, avatar_id, avatar_id
