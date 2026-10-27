"""Plan or perform bounded HEAD checks for source-explicit bundle CDN paths.

Planning is the default. --execute performs HEAD only, without redirects,
authentication, response-body reads, or downloads. Both configuration branches
remain candidates until the native selection and URL composition are proven.
"""

import argparse
from collections import Counter
import copy
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
import hashlib
import http.client
import json
from pathlib import Path
import re
from urllib.parse import urlsplit


ROOT = Path(__file__).resolve().parents[1]
EVIDENCE = ROOT / 'work/evidence'
EXPECTED_PE = '4254fbe66585f260f1f9dbfc5e302887842552e7baed8939e023160a5e250be0'
EXPECTED_SETTINGS_SHA256 = '8cd7e771c3c093efefc57e4cd6fd91135028ae0c41c5fddf3caa8b008dfcea29'
EXPECTED_COMPOSITION_SHA256 = 'eeb969f598c2ef8dc4dbf5cb83dde1422c09edac80f7da4a6299859e7d055ac0'
DEFAULT_FIELD = 'AppSettingRow.MapleInfo.DefaultCDNUrl'
PC_FIELD = 'AppSettingRow.MapleInfo.CDNUrl_PC'
ROOT_FIELD = 'AppSettingRow.CDNRoot'
FIELD_OFFSETS = {DEFAULT_FIELD: 0x588, PC_FIELD: 0x598, ROOT_FIELD: 0x5d8}
ALLOWED_HOSTS = frozenset(('cdn.df.qq.com', 'repo.df.qq.com'))
RESOURCE_RE = re.compile(r'Resource/(?:[A-Za-z0-9_-]+/)*C=[0-9A-Fa-f]+(?:\.(?:[Jj][Pp][Gg]|[Pp][Nn][Gg]))?')
PREFIX_RE = re.compile(r'[A-Za-z0-9_.-]+(?:/[A-Za-z0-9_.-]+)*')
ROLE_RE = re.compile(r'[A-Za-z][A-Za-z0-9_]{0,63}')
SHA_RE = re.compile(r'[0-9a-f]{64}')
RESULT_STATUSES = frozenset(('head_response', 'head_timeout', 'head_request_failed'))
AVAILABILITY = frozenset(('reachable_by_head', 'redirect_not_followed', 'access_denied',
                          'head_unsupported', 'not_found_by_head', 'http_other', 'unknown'))
COMPOSITION_SPANS = (
    ('composition_helpers', 'URL_StringProcess', 0x109f6860, 1024,
     '71c9a784372a7c571722f8f2aa8830ad78391dbe49fb856c57865cc2679229af'),
    ('composition_helpers', 'URL_StringConstruct', 0xd5f420, 512,
     'c7afa7f69a5073b3088aaa8a04833541b98b6a913bbf1411ccdd923d88707e8f'),
    ('composition_helpers', 'URL_StringAppend', 0x109f31b0, 1024,
     '037ae88f5036511a10afefe4b65252afc776ea0d81d2eb18c5b3968a712bccff'),
    ('implementations', 'AppRow_GetCDNUrl', 0xdbcd20, 640,
     '5ac071c5c9b6d191c271094e8214449efa074888c8dfe29995c2d69ca3716cf3'),
    ('implementations', 'IconManager_GetCDNUrl', 0x11e5c70, 1024,
     '18a451c000a4b44489af14c43e95783f6122bdc5a51698d4318a6f89bff872ad'),
)
SCALAR_CONTRACT = {
    'app_override_enabled': (498292320, 0), 'app_url_override': (498292340, 0),
    'maple_url_override': (498292338, 0), 'default_url_override': (498292348, 0),
    'pc_url_selector': (492428864, 1), 'app_row_override': (498292345, 0),
    'app_row_fallback_override': (498292346, 0), 'manager_override_enabled': (498367072, 0),
    'manager_url_override': (498367126, 0), 'manager_input_override': (498367127, 0),
}


def _fail(reason):
    raise ValueError(reason)


def _sha(value):
    return isinstance(value, str) and bool(SHA_RE.fullmatch(value))


def _prefix(value):
    return (isinstance(value, str) and len(value) < 512 and bool(PREFIX_RE.fullmatch(value))
            and all(part not in ('.', '..') for part in value.split('/')))


def _base(value):
    if not isinstance(value, str) or value not in {'https://' + host for host in ALLOWED_HOSTS}:
        _fail('unsupported_or_nonpublic_cdn_base')
    return value


def _relative_resource(value, root):
    if not isinstance(value, str) or len(value) > 2048:
        return None
    if RESOURCE_RE.fullmatch(value):
        return value
    prefix = root + '/'
    if value.startswith(prefix) and RESOURCE_RE.fullmatch(value[len(prefix):]):
        return value[len(prefix):]
    return None


def validate_settings(settings, actual_sha256, expected_sha256):
    if not _sha(actual_sha256) or not _sha(expected_sha256) or actual_sha256 != expected_sha256:
        _fail('settings_report_sha256_mismatch')
    schema_contract = {
        'status': 'verified_source_types', 'source_pe_sha256': EXPECTED_PE,
        'setting_cache_type': 'TWeakObjectPtr<UAppSetting>', 'storage_rva': 0x1c9fe7b0,
        'setting_type': 'FAppSettingRow', 'setting_member_offset': 0x38, 'uappsetting_size': 0x7c8,
    }
    if (not isinstance(settings, dict) or settings.get('status') != 'captured_configuration_fields'
            or settings.get('reason') is not None
            or settings.get('weak_reference_and_headers_rechecked') is not True):
        _fail('settings_report_not_ready_and_rechecked')
    schema = settings.get('source_schema')
    if not isinstance(schema, dict) or any(schema.get(key) != value for key, value in schema_contract.items()):
        _fail('settings_source_type_or_pe_contract_mismatch')
    fields = settings.get('fields')
    if not isinstance(fields, list) or len(fields) != 3:
        _fail('settings_three_source_fields_required')
    values = {}
    for field in fields:
        if not isinstance(field, dict):
            _fail('invalid_settings_field')
        name = field.get('field')
        if (name not in FIELD_OFFSETS or name in values
                or field.get('object_member_offset') != FIELD_OFFSETS[name]
                or field.get('public_value_output_verified') is not True
                or field.get('status') != 'observed_public_configuration_value'):
            _fail('settings_field_source_or_value_not_verified')
        value = field.get('value')
        if name == ROOT_FIELD:
            if not _prefix(value):
                _fail('unsupported_or_nonpublic_cdn_root')
            values[name] = value
        else:
            values[name] = _base(value)
        if (type(field.get('utf16_count_including_nul')) is not int
                or field['utf16_count_including_nul'] != len(values[name]) + 1):
            _fail('settings_public_value_and_FString_length_mismatch')
    return values


def build_plan(manifest, settings, *, manifest_sha256, settings_sha256,
               expected_settings_sha256=EXPECTED_SETTINGS_SHA256):
    values = validate_settings(settings, settings_sha256, expected_settings_sha256)
    if (not _sha(manifest_sha256) or not isinstance(manifest, dict)
            or manifest.get('schema_version') != 1 or not isinstance(manifest.get('entries'), list)):
        _fail('unsupported_resource_manifest')
    rows, observations, by_url = [], [], {}
    for entry in manifest['entries']:
        if not isinstance(entry, dict) or entry.get('table') not in ('recommendations', 'gifts'):
            _fail('unsupported_resource_source_table')
        row = {'table': entry['table'], 'resources': []}
        for key in ('row', 'row_offset', 'tab_id', 'goods_id'):
            if key in entry:
                value = entry[key]
                if type(value) is not int or not 0 <= value < 2 ** 63:
                    _fail('invalid_resource_row_identifier')
                row[key] = value
        if 'row' not in row or 'row_offset' not in row or not isinstance(entry.get('resources'), list):
            _fail('missing_resource_row_or_fields')
        for resource in entry['resources']:
            if not isinstance(resource, dict):
                _fail('invalid_resource_field')
            role, index = resource.get('role'), resource.get('source_field_index')
            if not isinstance(role, str) or not ROLE_RE.fullmatch(role) or type(index) is not int or not 0 <= index < 65536:
                _fail('invalid_resource_source_role_or_field')
            item = {'role': role, 'source_field_index': index, 'observation_ids': []}
            value = resource.get('value')
            relative = _relative_resource(value, values[ROOT_FIELD])
            if resource.get('source_status') == 'empty_in_source' and value == '':
                item['status'] = 'empty_in_source'
            elif resource.get('source_status') != 'nonempty_verified':
                item['status'] = 'source_value_not_verified'
            elif resource.get('kind') != 'cdn_relative_reference' or relative is None:
                item['status'] = 'not_full_source_cdn_reference'
            else:
                item.update(status='candidate_urls_ready', source_relative_path=value)
                for field in (DEFAULT_FIELD, PC_FIELD):
                    url = values[field] + '/' + values[ROOT_FIELD] + '/' + relative
                    if url not in by_url:
                        by_url[url] = len(observations)
                        observations.append({'id': by_url[url], 'url': url,
                                             'candidate_base_fields': [], 'status': 'not_requested'})
                    observation = observations[by_url[url]]
                    if field not in observation['candidate_base_fields']:
                        observation['candidate_base_fields'].append(field)
                    if observation['id'] not in item['observation_ids']:
                        item['observation_ids'].append(observation['id'])
            row['resources'].append(item)
        rows.append(row)
    return {
        'schema_version': 1, 'mode': 'plan', 'request_method': 'HEAD',
        'source_manifest_sha256': manifest_sha256, 'source_settings_report_sha256': settings_sha256,
        'source_pe_sha256': EXPECTED_PE,
        'configuration_fields': values,
        'native_selected_branch_verified': False, 'native_url_composition_verified': False,
        'native_current_getcdnurl_result_verified': False,
        'native_image_setter_input_preprocessing_verified': False,
        'native_effective_request_url_verified': False,
        'native_resource_binding_and_rendering_verified': False,
        'interpretation': 'HEAD proves HTTP status only. Native composition and selection markers concern reviewed source snapshots; no native GetCDNUrl call, cache identity, body contents, local asset ownership, or rendering is verified. Redirects and access denial remain unresolved.',
        'rows': rows, 'observations': observations, 'request_count': 0,
    }


def apply_composition(plan, settings, report, *, actual_sha256,
                      expected_sha256=EXPECTED_COMPOSITION_SHA256):
    """Apply the independently reviewed fixed-code and stable-scalar witness."""
    if not _sha(actual_sha256) or not _sha(expected_sha256) or actual_sha256 != expected_sha256:
        _fail('composition_report_sha256_mismatch')
    if (not isinstance(report, dict) or report.get('native_pe_sha256') != EXPECTED_PE
            or report.get('composition_scalars_stable') is not True
            or type(settings.get('pid')) is not int or settings['pid'] <= 0
            or report.get('pid') != settings['pid']
            or report.get('module_base') != settings.get('module_base')):
        _fail('composition_source_or_snapshot_identity_mismatch')
    for group, name, rva, size, sha in COMPOSITION_SPANS:
        span = report.get(group, {}).get(name, {})
        if (span.get('rva'), span.get('size'), span.get('sha256')) != (rva, size, sha):
            _fail('composition_code_source_contract_mismatch')
    scalars = report.get('composition_scalars')
    if not isinstance(scalars, dict) or set(scalars) != set(SCALAR_CONTRACT):
        _fail('composition_selector_or_override_contract_mismatch')
    for name, (rva, value) in SCALAR_CONTRACT.items():
        scalar = scalars[name]
        if (not isinstance(scalar, dict) or scalar.get('rva') != rva or scalar.get('size') != 1
                or scalar.get('stable') is not True or scalar.get('rip_relative_target_verified') is not True
                or scalar.get('value') != value or scalar.get('value_recheck') != value):
            _fail('composition_selector_or_override_contract_mismatch')
    root = plan['configuration_fields'][ROOT_FIELD]
    for row in plan['rows']:
        for item in row['resources']:
            if item['status'] == 'candidate_urls_ready':
                path = item['source_relative_path']
                stripped = re.sub(re.escape(root + '/'), '', path, flags=re.IGNORECASE)
                if stripped != _relative_resource(path, root):
                    _fail('source_path_not_covered_by_verified_composition')
    result = copy.deepcopy(plan)
    result.update(source_composition_report_sha256=actual_sha256,
                  native_url_composition_verified=True, native_selected_branch_verified=True,
                  source_selected_base_field=PC_FIELD,
                  selection_scope='Source evaluated from the same-PID ready settings and stable fixed module selectors; no native GetCDNUrl call or persistent-state claim',
                  composition_source_spans=[{'name': name, 'rva': rva, 'size': size, 'sha256': sha}
                                            for _, name, rva, size, sha in COMPOSITION_SPANS])
    for observation in result['observations']:
        observation['branch_status'] = ('source_selected_in_snapshot' if PC_FIELD in observation['candidate_base_fields']
                                        else 'alternate_observed_base')
    return result


def _bounds(workers, timeout):
    if type(workers) is not int or not 1 <= workers <= 4 or type(timeout) not in (int, float) or not 0 < timeout <= 10:
        _fail('workers_must_be_1_to_4_and_socket_timeout_0_to_10_seconds')


def _request_url(url):
    if not isinstance(url, str) or len(url) > 3072 or any(ord(c) < 33 or ord(c) > 126 for c in url):
        _fail('nonpublic_request_url')
    try:
        parsed = urlsplit(url)
        if (parsed.scheme != 'https' or parsed.hostname not in ALLOWED_HOSTS or parsed.port is not None
                or parsed.username is not None or parsed.password is not None
                or '?' in url or '#' in url or '\\' in url):
            _fail('unsupported_request_authority_or_delimiters')
    except ValueError:
        _fail('unsupported_request_authority_or_delimiters')
    prefix, marker, resource = parsed.path[1:].partition('/Resource/')
    if not marker or not _prefix(prefix) or not RESOURCE_RE.fullmatch('Resource/' + resource):
        _fail('request_path_is_not_an_explicit_resource_candidate')
    return parsed.hostname, parsed.path


def head_url(url, timeout, *, connection_factory=None):
    """Read only the HEAD status; ignore all headers and never read a body."""
    _bounds(1, timeout)
    host, path = _request_url(url)
    connection, response = None, None
    try:
        connection = (connection_factory or http.client.HTTPSConnection)(host, timeout=timeout)
        connection.request('HEAD', path, headers={'Connection': 'close'})
        response = connection.getresponse()
        status = response.status
        if type(status) is not int or not 100 <= status <= 599:
            return {'status': 'head_request_failed', 'availability': 'unknown'}
        availability = ('reachable_by_head' if 200 <= status < 300 else
                        'redirect_not_followed' if 300 <= status < 400 else
                        'access_denied' if status in (401, 403) else
                        'head_unsupported' if status == 405 else
                        'not_found_by_head' if status in (404, 410) else 'http_other')
        return {'status': 'head_response', 'http_status': status, 'availability': availability}
    except TimeoutError:
        return {'status': 'head_timeout', 'availability': 'unknown'}
    except (OSError, http.client.HTTPException, ValueError):
        return {'status': 'head_request_failed', 'availability': 'unknown'}
    finally:
        for item in (response, connection):
            if item is not None:
                try:
                    item.close()
                except OSError:
                    pass


def run_audit(plan, *, execute=False, workers=4, timeout=10, requester=None, progress=None):
    _bounds(workers, timeout)
    if execute and plan.get('native_url_composition_verified') is not True:
        _fail('execute_requires_verified_source_url_composition')
    result = copy.deepcopy(plan)
    result['started_at_utc'] = datetime.now(timezone.utc).isoformat()
    result.update(mode='head' if execute else 'plan', workers=workers,
                  socket_timeout_seconds=timeout, redirects_followed=False,
                  response_body_read=False, authentication_sent=False)
    if not execute:
        result['finished_at_utc'] = datetime.now(timezone.utc).isoformat()
        return result
    request = requester or head_url

    def observe(observation):
        try:
            response = request(observation['url'], timeout)
            if not isinstance(response, dict):
                response = {}
        except Exception:
            response = {}
        status, availability = response.get('status'), response.get('availability')
        safe = {'status': status if status in RESULT_STATUSES else 'head_request_failed',
                'availability': availability if availability in AVAILABILITY else 'unknown'}
        code = response.get('http_status')
        if safe['status'] == 'head_response' and type(code) is int and 100 <= code <= 599:
            safe['http_status'] = code
        elif safe['status'] == 'head_response':
            safe.update(status='head_request_failed', availability='unknown')
        return safe

    with ThreadPoolExecutor(max_workers=workers) as executor:
        outcomes = executor.map(observe, result['observations'])
        for completed, (observation, outcome) in enumerate(zip(result['observations'], outcomes), 1):
            observation.update(outcome)
            if progress and (completed % 50 == 0 or completed == len(result['observations'])):
                progress(completed, len(result['observations']))
    result['request_count'] = len(result['observations'])
    result['finished_at_utc'] = datetime.now(timezone.utc).isoformat()
    return result


def status_groups(report):
    branches = {}
    for field in (DEFAULT_FIELD, PC_FIELD):
        observations = [o for o in report['observations'] if field in o['candidate_base_fields']]
        branches[field] = {'unique_url_observations': len(observations),
                           'http_status_counts': dict(Counter(str(o.get('http_status', o['status'])) for o in observations)),
                           'availability_counts': dict(Counter(o.get('availability', 'not_requested') for o in observations))}
    roles, path_classes, cohorts, paths = {}, {}, Counter(), set()
    occurrences = 0
    for row in report['rows']:
        codes = []
        for resource in row['resources']:
            if resource['status'] != 'candidate_urls_ready':
                continue
            occurrences += 1
            path = resource['source_relative_path']
            paths.add(path)
            observation = next(report['observations'][index] for index in resource['observation_ids']
                               if PC_FIELD in report['observations'][index]['candidate_base_fields'])
            code = str(observation.get('http_status', observation['status']))
            roles.setdefault(resource['role'], Counter())[code] += 1
            directory, _, basename = path.rpartition('/')
            extension = ('.' + basename.rpartition('.')[2]) if '.' in basename else '<no_literal_extension>'
            path_classes.setdefault((directory, extension), Counter())[code] += 1
            codes.append(code)
        cohort = ('no_full_source_cdn_reference' if not codes else 'all_http_200' if set(codes) == {'200'} else
                  'all_http_404' if set(codes) == {'404'} else 'mixed_or_other_head_status')
        cohorts[cohort] += 1
    return {'total_source_rows': len(report['rows']), 'source_reference_occurrences': occurrences,
            'distinct_source_paths': len(paths), 'branch_observations': branches,
            'pc_branch_reference_status_counts_by_role': {key: dict(value) for key, value in roles.items()},
            'pc_branch_reference_status_counts_by_path_class': [
                {'source_directory': directory, 'literal_extension': extension, 'status_counts': dict(counts)}
                for (directory, extension), counts in path_classes.items()],
            'pc_branch_source_row_head_cohorts': dict(cohorts)}


def public_summary(report, *, include_source_paths=False):
    """Export source correlations and statuses, without URLs or runtime metadata."""
    public = {key: report[key] for key in (
        'schema_version', 'mode', 'request_method', 'source_manifest_sha256',
        'source_settings_report_sha256', 'source_pe_sha256', 'native_selected_branch_verified',
        'native_url_composition_verified', 'native_current_getcdnurl_result_verified',
        'native_resource_binding_and_rendering_verified',
        'request_count',
    )}
    if 'source_composition_report_sha256' in report:
        public['source_composition_report_sha256'] = report['source_composition_report_sha256']
    public.update(native_image_setter_input_preprocessing_verified=False,
                  native_effective_request_url_verified=False,
                  url_scope='raw_source_path_composed_with_observed_configuration',
                  interpretation='HEAD statuses describe the source-composed URLs checked here. Native image setter preprocessing before GetCDNUrl is unverified, so source HEAD404 is not a verified native final URL404. No response body, texture decoding, cache identity, or rendering was checked.')
    for key in ('started_at_utc', 'finished_at_utc', 'audit_script_sha256', 'source_selected_base_field', 'selection_scope'):
        if key in report:
            public[key] = report[key]
    public['summary'] = status_groups(report)
    public['rows'] = []
    for row in report['rows']:
        safe_row = {key: row[key] for key in ('table', 'row', 'row_offset', 'tab_id', 'goods_id') if key in row}
        safe_row['resources'] = []
        for resource in row['resources']:
            item = {key: resource[key] for key in ('role', 'source_field_index', 'status')}
            if include_source_paths and resource['status'] == 'candidate_urls_ready':
                path = resource['source_relative_path']
                if _relative_resource(path, report['configuration_fields'][ROOT_FIELD]) is None:
                    _fail('public_source_path_not_verified')
                item['source_relative_path'] = path
            item['candidate_observations'] = [
                {key: report['observations'][index][key] for key in
                 ('candidate_base_fields', 'branch_status', 'status', 'http_status', 'availability')
                 if key in report['observations'][index]}
                for index in resource['observation_ids']
            ]
            for safe in item['candidate_observations']:
                safe['url_scope'] = 'raw_source_path_composed_with_observed_configuration'
            if include_source_paths:
                for safe, index in zip(item['candidate_observations'], resource['observation_ids']):
                    url = report['observations'][index]['url']
                    _request_url(url)
                    safe['url'] = url
            safe_row['resources'].append(item)
        public['rows'].append(safe_row)
    return public


def _load(path, max_bytes):
    with Path(path).open('rb') as handle:
        data = handle.read(max_bytes + 1)
    if len(data) > max_bytes:
        _fail('input_file_exceeds_size_bound')
    try:
        parsed = json.loads(data)
    except (ValueError, UnicodeError):
        _fail('input_is_not_valid_json')
    return parsed, hashlib.sha256(data).hexdigest()


def _command(args):
    def source_path(path):
        path = path.resolve()
        return path.relative_to(ROOT).as_posix() if path.is_relative_to(ROOT) else '<external-input-path-redacted>'
    command = ['python', 'work/check_bundle_cdn_resources.py',
               '--resources', source_path(args.resources), '--settings', source_path(args.settings),
               '--settings-sha256', args.settings_sha256, '--workers', str(args.workers),
               '--timeout', str(args.timeout), '--output', source_path(args.output)]
    if args.execute:
        command.append('--execute')
    if args.composition:
        command.extend(('--composition', source_path(args.composition),
                        '--composition-sha256', args.composition_sha256))
    if args.public_output:
        command.extend(('--public-output', source_path(args.public_output)))
    return command


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--resources', type=Path, default=ROOT / 'outputs/df-local-server/protocol/premium_shop_resources.json')
    parser.add_argument('--settings', type=Path, required=True)
    parser.add_argument('--settings-sha256', default=EXPECTED_SETTINGS_SHA256,
                        help='Expected digest from an independently verified ready settings report')
    parser.add_argument('--composition', type=Path, help='Reviewed fixed-code and selector snapshot; required for --execute')
    parser.add_argument('--composition-sha256', default=EXPECTED_COMPOSITION_SHA256)
    parser.add_argument('--execute', action='store_true', help='Perform HEAD requests; otherwise only prepare the plan')
    parser.add_argument('--workers', type=int, default=4)
    parser.add_argument('--timeout', type=float, default=10, help='Socket timeout in seconds, maximum 10')
    parser.add_argument('--output', type=Path, default=EVIDENCE / 'bundle-cdn-availability-private.json')
    parser.add_argument('--public-output', type=Path, help='Optional separate source/status-only summary')
    args = parser.parse_args()
    try:
        _bounds(args.workers, args.timeout)
        output = args.output.resolve()
        if not output.is_relative_to(EVIDENCE.resolve()):
            _fail('private_output_must_be_under_work_evidence')
        public_output = args.public_output.resolve() if args.public_output else None
        if public_output and not public_output.is_relative_to(EVIDENCE.resolve()):
            _fail('public_summary_output_must_be_under_work_evidence')
        if public_output == output:
            _fail('public_and_private_outputs_must_differ')
        inputs = (args.resources.resolve(), args.settings.resolve(),
                  args.composition.resolve() if args.composition else None)
        if output in inputs or (public_output is not None and public_output in inputs):
            _fail('audit_output_must_not_overwrite_input_evidence')
        manifest, manifest_sha = _load(args.resources, 8 * 1024 * 1024)
        settings, settings_sha = _load(args.settings, 1024 * 1024)
        plan = build_plan(manifest, settings, manifest_sha256=manifest_sha,
                          settings_sha256=settings_sha, expected_settings_sha256=args.settings_sha256)
        if args.composition:
            composition, composition_sha = _load(args.composition, 4 * 1024 * 1024)
            plan = apply_composition(plan, settings, composition, actual_sha256=composition_sha,
                                     expected_sha256=args.composition_sha256)
        report = run_audit(plan, execute=args.execute, workers=args.workers, timeout=args.timeout,
                           progress=lambda completed, total: print(json.dumps({'head_completed': completed,
                                                                              'head_total': total}), flush=True))
        report['command'] = _command(args)
        report['audit_script_sha256'] = hashlib.sha256(Path(__file__).read_bytes()).hexdigest()
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(json.dumps(report, indent=2) + '\n', encoding='utf-8')
        if args.public_output:
            args.public_output.parent.mkdir(parents=True, exist_ok=True)
            args.public_output.write_text(json.dumps(public_summary(report, include_source_paths=True), indent=2) + '\n', encoding='utf-8')
    except OSError:
        parser.error('input_or_output_file_not_accessible')
    except ValueError as exc:
        parser.error(str(exc))
    print(json.dumps({'mode': report['mode'], 'rows': len(report['rows']),
                      'unique_candidate_urls': len(report['observations']), 'requests': report['request_count']}))


if __name__ == '__main__':
    main()
