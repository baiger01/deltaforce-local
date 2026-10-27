"""Inspect published, unauthenticated official-wiki metadata without game access."""

from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import re
from urllib.parse import urlencode
from urllib.request import Request, urlopen


ROOT = Path(__file__).resolve().parent.parent
OUT = ROOT / 'work/evidence/official-public-curve-20261019'
WIKI = 'https://www.playdeltaforce.com/act/officialwiki/'
MAIN = WIKI + 'assets/main-Dby1Scop.js'
ACTIVITY = 'https://sg-apps.vasdgame.com/amside/page/4005360_Qa9W4x'
ENDPOINT = 'https://sg-apps.vasdgame.com/ide/'


def fetch(url, data=None):
    request = Request(url, data=data,
        headers={'User-Agent': 'Mozilla/5.0', 'Content-Type': 'application/x-www-form-urlencoded'})
    with urlopen(request, timeout=25) as response:
        raw = response.read(20 * 1024 * 1024)
        return raw, {'url': url, 'status': response.status,
            'sha256': hashlib.sha256(raw).hexdigest(), 'bytes': len(raw),
            'content_type': response.headers.get('Content-Type')}


def search(value, path=''):
    hits = []
    if isinstance(value, dict):
        for key, child in value.items():
            current = path + '.' + key
            if re.search(r'reputation|prestige|repLevel|rep_score|qualityValue|quality_value|声望|聲望', key, re.I):
                hits.append({'path': current, 'value': child})
            hits.extend(search(child, current))
    elif isinstance(value, list):
        for index, child in enumerate(value):
            hits.extend(search(child, f'{path}[{index}]'))
    elif isinstance(value, str) and re.search(r'reputation|prestige|声望|聲望', value, re.I):
        hits.append({'path': path, 'value': value})
    return hits


def main():
    OUT.mkdir(parents=True, exist_ok=True)
    sources = []
    for name, url in [('wiki.html', WIKI), ('main.js', MAIN), ('public-activity.json', ACTIVITY)]:
        raw, source = fetch(url)
        (OUT / name).write_bytes(raw)
        sources.append({**source, 'saved': name})
    bundle = (OUT / 'main.js').read_text(encoding='utf-8')
    activity = json.loads((OUT / 'public-activity.json').read_text(encoding='utf-8'))
    flow_id = activity['tokens']['nkxYQl']
    flow = activity['flows'][flow_id]
    if flow['isLogin'] != '0' or '无需登录' not in flow['sName']:
        raise ValueError('Official endpoint is not explicitly public')
    if 'projectd_oversea/config.list' not in bundle or 'projectd_oversea/place.list' not in bundle:
        raise ValueError('Public read methods are not in the published wiki bundle')
    methods = [('config', 'projectd_oversea/config.list', {'configType': 'all'})]
    for place in ('control', 'training', 'shoot', 'storage', 'workbench', 'pharmacy', 'armory', 'tech'):
        if f'="{place}"' not in bundle:
            raise ValueError('Place identifier is not in published wiki bundle: ' + place)
        methods.append(('place-' + place, 'projectd_oversea/place.list', {'type': 'place', 'place': place}))
    responses = []
    for name, method, param in methods:
        payload = {'iChartId': flow_id, 'sIdeToken': 'nkxYQl', 'instanceid': 4005360,
                   'method': method, 'param': json.dumps(param, separators=(',', ':'))}
        raw, source = fetch(ENDPOINT, urlencode(payload).encode('ascii'))
        parsed = json.loads(raw)
        if parsed.get('iRet') != 0 or parsed['jData']['data']['code'] != 0:
            raise ValueError('Public wiki read request failed: ' + name)
        data = parsed['jData']['data']['data']
        (OUT / (name + '.json')).write_text(json.dumps(data, ensure_ascii=True, indent=2) + '\n',
                                           encoding='utf-8')
        record = {**source, 'request': payload, 'saved': name + '.json',
                  'root_keys': list(data), 'reputation_matches': search(data)}
        responses.append(record)
        print(name, 'keys', list(data), 'reputation_matches', len(record['reputation_matches']), flush=True)
    report = {'retrieved_utc': datetime.now(timezone.utc).isoformat(),
        'scope': 'Published first-party international official wiki; no login, cookies, account identifiers or private endpoints used.',
        'public_endpoint_witness': {'activity_url': ACTIVITY, 'flow': flow},
        'sources': sources, 'responses': responses,
        'department_curve_recovered': False,
        'interpretation': 'Facility upgrade requirements may refer to reputation but do not prove reputation-level score thresholds.'}
    target = OUT / 'report.json'
    target.write_text(json.dumps(report, ensure_ascii=True, indent=2) + '\n', encoding='utf-8')
    print('report', target, flush=True)


if __name__ == '__main__':
    main()
