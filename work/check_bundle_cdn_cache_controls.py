"""Compare 1-3 exact source HTTP200 URLs with existing image cache hashes.

Default mode verifies and prepares the controls. --execute reads bounded original
GET bodies only into a streaming digest, never saves bodies, follows redirects,
sends authentication, writes caches, or claims native filename/render proof.
"""

import argparse
from datetime import datetime, timezone
import hashlib
import http.client
import json
from pathlib import Path
import re
import time

import check_bundle_cdn_resources as source


MAX_BYTES = 8 * 1024 * 1024
HEAD_SHA256 = 'a0f8e479beebc331a6929b1bff42c2c17172a3479a0b21d8c1f882c531d86aad'
CACHE_SHA256 = 'bf2d5039fd8c40a7697cd29e9337984fb653bf7dc37aaac619bdae44ec4a8ca3'


def _bounds(timeout, max_bytes):
    if type(timeout) not in (int, float) or not 0 < timeout <= 2 or type(max_bytes) is not int or not 0 < max_bytes <= MAX_BYTES:
        raise ValueError('control_requires_timeout_at_most_2_seconds_and_body_at_most_8_MiB')


def public_redirect_location(location, request_url):
    if location is None:
        return {'location_status': 'not_present'}
    try:
        _, requested_path = source._request_url(request_url)
        host, path = source._request_url(location)
        if path != requested_path:
            raise ValueError('redirect_is_not_the_same_original_source_path')
    except ValueError:
        return {'location_status': 'redacted_or_unsupported'}
    return {'location_status': 'public_same_source_path', 'location': 'https://' + host + path}


def _phase_budget(connection, response, deadline):
    remaining = deadline - time.monotonic()
    if remaining <= 0:
        raise TimeoutError('control_deadline_exceeded')
    connection.timeout = remaining
    sockets = (getattr(connection, 'sock', None),
               getattr(getattr(getattr(response, 'fp', None), 'raw', None), '_sock', None))
    for sock in sockets:
        if sock is not None:
            sock.settimeout(remaining)
    return remaining


def get_body_hash(url, *, timeout=2, max_bytes=MAX_BYTES, connection_factory=None):
    _bounds(timeout, max_bytes)
    host, path = source._request_url(url)
    if Path(path).suffix.lower() not in ('.jpg', '.png'):
        raise ValueError('control_GET_requires_literal_source_image_extension')
    connection, response, count = None, None, 0
    deadline = time.monotonic() + timeout
    try:
        connection = (connection_factory or http.client.HTTPSConnection)(host, timeout=timeout)
        _phase_budget(connection, None, deadline)
        if callable(getattr(connection, 'connect', None)):
            connection.connect()
        _phase_budget(connection, None, deadline)
        connection.request('GET', path, headers={'Connection': 'close', 'Accept-Encoding': 'identity'})
        _phase_budget(connection, None, deadline)
        response = connection.getresponse()
        _phase_budget(connection, response, deadline)
        if type(response.status) is not int or not 100 <= response.status <= 599:
            return {'status': 'get_failed', 'bytes': 0}
        if response.status != 200:
            result = {'status': 'get_non_200_body_not_read', 'http_status': response.status, 'bytes': 0}
            if 300 <= response.status < 400:
                getter = getattr(response, 'getheader', None)
                result.update(public_redirect_location(getter('Location'), url) if callable(getter)
                              else {'location_status': 'not_observed'})
            return result
        digest = hashlib.sha256()
        while True:
            _phase_budget(connection, response, deadline)
            reader = getattr(response, 'read1', response.read)
            data = reader(min(65536, max_bytes + 1 - count))
            count += len(data)
            if time.monotonic() >= deadline:
                return {'status': 'get_deadline_exceeded', 'http_status': 200, 'bytes': count}
            if not data:
                return {'status': 'get_body_hashed', 'http_status': 200, 'bytes': count,
                        'sha256': digest.hexdigest()}
            if count > max_bytes:
                return {'status': 'get_body_exceeds_bound', 'http_status': 200, 'bytes': count}
            digest.update(data)
    except TimeoutError:
        return {'status': 'get_timeout', 'bytes': count}
    except (OSError, ValueError, http.client.HTTPException):
        return {'status': 'get_failed', 'bytes': count}
    finally:
        for item in (response, connection):
            if item is not None:
                try:
                    item.close()
                except OSError:
                    pass


def cache_hash(path, expected_size):
    if type(expected_size) is not int or not 0 < expected_size <= MAX_BYTES:
        raise ValueError('cache_control_file_exceeds_size_bound')
    digest, count = hashlib.sha256(), 0
    with path.open('rb') as handle:
        if path.stat().st_size != expected_size:
            raise ValueError('cache_control_file_size_changed')
        while True:
            chunk = handle.read(min(65536, MAX_BYTES + 1 - count))
            if not chunk:
                break
            count += len(chunk)
            if count > MAX_BYTES:
                raise ValueError('cache_control_file_exceeds_size_bound')
            digest.update(chunk)
    if count != expected_size:
        raise ValueError('cache_control_file_size_changed')
    return digest.hexdigest()


def prepare_controls(manifest, head, cache, *, manifest_sha256, head_sha256, cache_sha256,
                     expected_head_sha256, expected_cache_sha256, shadow_root, selections,
                     base_field=source.PC_FIELD):
    if (not source._sha(head_sha256) or not source._sha(cache_sha256)
            or head_sha256 != expected_head_sha256 or cache_sha256 != expected_cache_sha256):
        raise ValueError('control_input_report_sha256_mismatch')
    if (head.get('source_manifest_sha256') != manifest_sha256 or head.get('source_pe_sha256') != source.EXPECTED_PE
            or head.get('native_url_composition_verified') is not True or head.get('mode') != 'head'):
        raise ValueError('control_source_HEAD_report_not_verified')
    if not 1 <= len(selections) <= 3 or len(set(selections)) != len(selections):
        raise ValueError('control_requires_1_to_3_distinct_exact_source_fields')
    if base_field not in (source.DEFAULT_FIELD, source.PC_FIELD):
        raise ValueError('control_requires_one_observed_source_base_field')
    root = head.get('configuration_fields', {}).get(source.ROOT_FIELD)
    if not source._prefix(root):
        raise ValueError('control_source_root_not_verified')
    controls = []
    for table, row, field in selections:
        entries = [entry for entry in manifest.get('entries', []) if entry.get('table') == table and entry.get('row') == row]
        if len(entries) != 1:
            raise ValueError('control_source_row_not_unique')
        entries = [resource for resource in entries[0]['resources'] if resource.get('source_field_index') == field]
        if len(entries) != 1:
            raise ValueError('control_source_field_not_unique')
        resource = entries[0]
        value = resource.get('value')
        if (resource.get('source_status') != 'nonempty_verified' or resource.get('kind') != 'cdn_relative_reference'
                or source._relative_resource(value, root) is None or Path(value).suffix.lower() not in ('.jpg', '.png')):
            raise ValueError('control_requires_original_source_path_with_literal_extension')
        rows = [entry for entry in head['rows'] if entry['table'] == table and entry['row'] == row]
        items = [item for entry in rows for item in entry['resources'] if item['source_field_index'] == field]
        if len(items) != 1 or items[0].get('source_relative_path') != value or items[0].get('role') != resource['role']:
            raise ValueError('control_source_and_HEAD_correlation_mismatch')
        observations = [head['observations'][index] for index in items[0]['observation_ids']
                        if base_field in head['observations'][index]['candidate_base_fields']]
        if len(observations) != 1 or observations[0].get('http_status') != 200 or observations[0].get('status') != 'head_response':
            raise ValueError('control_requires_observed_source_HEAD200')
        observation = observations[0]
        source._request_url(observation['url'])
        base = source._base(head.get('configuration_fields', {}).get(base_field))
        if observation['url'] != base + '/' + root + '/' + source._relative_resource(value, root):
            raise ValueError('control_HEAD_URL_does_not_match_exact_source_composition')
        refs = [ref for ref in cache.get('references', []) if ref.get('table') == table and ref.get('row') == row
                and ref.get('field_index') == field and ref.get('value') == value]
        if (len(refs) != 1 or refs[0].get('source_serialized_string_and_relative_path_verified') is not True
                or refs[0].get('cache_presence_status') != 'observed_existing'):
            raise ValueError('control_cache_source_correlation_not_verified')
        ref = refs[0]
        basename = ref.get('cache_basename')
        if not isinstance(basename, str) or not re.fullmatch(r'C=-?[0-9]{1,10}', basename):
            raise ValueError('control_cache_basename_not_supported')
        directory = (Path(shadow_root) / 'DeltaForce/Saved/Cdn' / root / value.rpartition('/')[0]).resolve()
        metadata = [item for item in ref.get('existing_cache_metadata', [])
                    if Path(item.get('path', '')).resolve().parent == directory
                    and Path(item.get('path', '')).name == basename
                    and item.get('path') in ref.get('physical_cache_existing', [])]
        if len(metadata) != 1 or not source._sha(metadata[0].get('sha256')):
            raise ValueError('control_requires_one_existing_cache_file_in_explicit_shadow_tree')
        metadata = metadata[0]
        if metadata.get('format') not in ('JPEG', 'PNG', 'native_serialized_image_with_png_signature'):
            raise ValueError('control_requires_observed_image_cache_format')
        path = Path(metadata['path']).resolve()
        actual = cache_hash(path, metadata['size'])
        if actual != metadata['sha256']:
            raise ValueError('control_existing_cache_sha256_changed')
        controls.append({'table': table, 'row': row, 'source_field_index': field, 'role': resource['role'],
                         'source_relative_path': value, 'url': observation['url'], 'cache_basename': basename,
                         'observed_base_field': base_field, 'branch_status': observation.get('branch_status', 'source_branch_candidate'),
                         'cache_expected_size': metadata['size'], 'cache_expected_sha256': actual,
                         'cache_observed_format': metadata.get('format', 'unclassified'),
                         '_cache_path': path})
    return controls


def run_controls(controls, *, execute=False, getter=None):
    rows = []
    for control in controls:
        row = {key: value for key, value in control.items() if key != '_cache_path'}
        row.update(status='prepared_not_requested', payload_equals_observed_cache=False)
        if execute:
            if cache_hash(control['_cache_path'], control['cache_expected_size']) != control['cache_expected_sha256']:
                raise ValueError('control_cache_changed_before_GET')
            observed = (getter or get_body_hash)(control['url'])
            response = {key: observed[key] for key in ('status', 'http_status', 'bytes', 'sha256') if key in observed}
            if type(response.get('http_status')) is int and 300 <= response['http_status'] < 400:
                if 'location' in observed:
                    response.update(public_redirect_location(observed['location'], control['url']))
                else:
                    status = observed.get('location_status', 'not_observed')
                    response['location_status'] = status if status in ('not_present', 'not_observed', 'redacted_or_unsupported') else 'redacted_or_unsupported'
            row['GET'] = response
            after = cache_hash(control['_cache_path'], control['cache_expected_size'])
            row['cache_sha256_after'] = after
            row['status'] = ('cache_changed_during_control' if after != control['cache_expected_sha256'] else response['status'])
            row['payload_equals_observed_cache'] = (response.get('status') == 'get_body_hashed'
                                                    and response.get('sha256') == after == control['cache_expected_sha256']
                                                    and response.get('bytes') == control['cache_expected_size'])
        rows.append(row)
    return {'controls': rows, 'request_count': len(rows) if execute else 0,
            'response_body_persisted': False, 'cache_files_written': False, 'redirects_followed': False,
            'authentication_sent': False, 'cache_filename_algorithm_native_verified': False,
            'native_image_setter_input_preprocessing_verified': False,
            'native_effective_request_url_verified': False, 'native_rendering_verified': False,
            'scope': 'Only exact original URLs already HEAD200 and exact existing cache files selected here; matching hashes do not prove the native cache naming algorithm or transformed final URL'}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--resources', type=Path, default=source.ROOT / 'outputs/df-local-server/protocol/premium_shop_resources.json')
    parser.add_argument('--head-report', type=Path, required=True)
    parser.add_argument('--head-sha256', default=HEAD_SHA256)
    parser.add_argument('--cache-report', type=Path, required=True)
    parser.add_argument('--cache-sha256', default=CACHE_SHA256)
    parser.add_argument('--shadow-root', type=Path, required=True)
    parser.add_argument('--control', action='append', required=True, help='Exact table:row:source_field_index, maximum three')
    parser.add_argument('--branch', choices=('pc', 'default'), default='pc')
    parser.add_argument('--execute', action='store_true')
    args = parser.parse_args()
    try:
        selections = []
        for text in args.control:
            parts = text.split(':')
            if len(parts) != 3 or parts[0] not in ('recommendations', 'gifts') or not all(re.fullmatch('[0-9]+', p) for p in parts[1:]):
                raise ValueError('invalid_exact_source_control_selector')
            selections.append((parts[0], int(parts[1]), int(parts[2])))
        manifest, manifest_sha = source._load(args.resources, 8 * 1024 * 1024)
        head, head_sha = source._load(args.head_report, 8 * 1024 * 1024)
        cache, cache_sha = source._load(args.cache_report, 8 * 1024 * 1024)
        controls = prepare_controls(manifest, head, cache, manifest_sha256=manifest_sha, head_sha256=head_sha,
                                    cache_sha256=cache_sha, expected_head_sha256=args.head_sha256,
                                    expected_cache_sha256=args.cache_sha256, shadow_root=args.shadow_root,
                                    selections=selections, base_field=source.PC_FIELD if args.branch == 'pc' else source.DEFAULT_FIELD)
        started = datetime.now(timezone.utc).isoformat()
        result = run_controls(controls, execute=args.execute)
        result.update(source_manifest_sha256=manifest_sha, source_HEAD_report_sha256=head_sha,
                      source_cache_report_sha256=cache_sha, source_pe_sha256=source.EXPECTED_PE,
                      started_at_utc=started, finished_at_utc=datetime.now(timezone.utc).isoformat(),
                      control_script_sha256=hashlib.sha256(Path(__file__).read_bytes()).hexdigest())
    except OSError:
        parser.error('control_input_or_exact_cache_file_not_accessible')
    except ValueError as exc:
        parser.error(str(exc))
    print(json.dumps(result, indent=2))


if __name__ == '__main__':
    main()
