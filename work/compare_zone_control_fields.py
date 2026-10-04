"""Compare public zone control values without exporting endpoints or secrets."""
from pathlib import Path
import json
import sys

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0,str(ROOT/'outputs/df-local-server'))
from dfserver.zone_discovery import ZoneDiscovery

public = json.loads((ROOT/'work/evidence/public_official_game_zones_response.json').read_text(encoding='utf-8'))
own = ZoneDiscovery().reply({'game_id':'2001918','from_src':'launcher'})['zone_info']
fields = ('game_id','zone_id','zone_id_str','parent_zone_id','bind_branch','is_visable','is_joinable',
          'is_flat_structure','zone_sequence','zone_state','activted_time_bj_in_unix','leaf_node','data_from_source')
result = []
for zone in own:
    matched = next(item for item in public['zone_info'] if item['zone_id'] == zone['zone_id'])
    differences = {key:{'public':matched.get(key),'local':zone.get(key)} for key in fields if matched.get(key) != zone.get(key)}
    result.append({'zone_id':zone['zone_id'],'control_value_differences':differences,
                   'public_extra_metadata_key_names':sorted(item.get('key','') for item in matched.get('extra_meta_data',[])),
                   'local_extra_metadata_key_names':sorted(item.get('key','') for item in zone.get('extra_meta_data',[]))})
(ROOT/'work/evidence/zone_control_field_comparison.json').write_text(json.dumps(result,indent=2)+'\n',encoding='utf-8')
print(json.dumps(result,indent=2))
