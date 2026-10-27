"""Synthetic tests: no network, process, game, or cache access."""

import hashlib
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

try:
    import check_bundle_cdn_resources as audit
except ModuleNotFoundError:
    audit = None


class AuditModuleTests(unittest.TestCase):
    def test_audit_module_exists(self):
        self.assertIsNotNone(audit, 'The availability audit has not been implemented')


class CDNAvailabilityTests(unittest.TestCase):
    def setUp(self):
        if audit is None:
            self.skipTest('Availability audit module is not yet implemented')

    def settings(self):
        return {
            'status': 'captured_configuration_fields',
            'reason': None,
            'source_schema': {
                'status': 'verified_source_types', 'source_pe_sha256': audit.EXPECTED_PE,
                'setting_cache_type': 'TWeakObjectPtr<UAppSetting>', 'storage_rva': 0x1c9fe7b0,
                'setting_type': 'FAppSettingRow', 'setting_member_offset': 0x38,
                'uappsetting_size': 0x7c8,
            },
            'weak_reference_and_headers_rechecked': True,
            'fields': [
                {'field': name, 'object_member_offset': offset,
                 'public_value_output_verified': True,
                 'utf16_count_including_nul': len(value) + 1,
                 'status': 'observed_public_configuration_value', 'value': value}
                for name, offset, value in (
                    (audit.DEFAULT_FIELD, 0x588, 'https://cdn.df.qq.com'),
                    (audit.PC_FIELD, 0x598, 'https://repo.df.qq.com'),
                    (audit.ROOT_FIELD, 0x5d8, 'G/CN'),
                )
            ],
            'pid': 12345, 'module_base': 0x140000000, 'unrelated_private': 'do-not-copy',
        }

    def composition(self):
        report = {'native_pe_sha256': audit.EXPECTED_PE, 'pid': 12345,
                  'module_base': 0x140000000, 'composition_scalars_stable': True,
                  'composition_scalars': {name: {'size': 1, 'rva': rva, 'value': value,
                                                'value_recheck': value, 'stable': True,
                                                'rip_relative_target_verified': True}
                                         for name, (rva, value) in audit.SCALAR_CONTRACT.items()}}
        for group, name, rva, size, sha in audit.COMPOSITION_SPANS:
            report.setdefault(group, {})[name] = {'rva': rva, 'size': size, 'sha256': sha}
        return report

    def ready_plan(self, manifest=None):
        plan = self.plan(manifest)
        composition = self.composition()
        sha = hashlib.sha256(json.dumps(composition).encode()).hexdigest()
        return audit.apply_composition(plan, self.settings(), composition, actual_sha256=sha,
                                       expected_sha256=sha)

    def manifest(self, count=2):
        return {
            'schema_version': 1,
            'entries': [
                {'table': 'recommendations' if row < 158 else 'gifts', 'row': row,
                 'row_offset': row * 100, 'tab_id': 10101000 + row,
                 'resources': [
                     {'role': 'cdn_small', 'source_field_index': 274,
                      'value': 'Resource/Store/C=AB12', 'source_status': 'nonempty_verified',
                      'kind': 'cdn_relative_reference'},
                     {'role': 'field_304_unclassified', 'source_field_index': 304,
                      'value': 'Resource/Store/C=AB12', 'source_status': 'nonempty_verified',
                      'kind': 'cdn_relative_reference'},
                     {'role': 'local_big', 'source_field_index': 271,
                      'value': "Texture2D'/Game/Public.Asset'", 'source_status': 'nonempty_verified',
                      'kind': 'local_ue_reference'},
                     {'role': 'cdn_logo_cn', 'source_field_index': 276,
                      'value': '', 'source_status': 'empty_in_source'},
                     {'role': 'unclassified_reward', 'source_field_index': 1823,
                      'value': 'C=AB12.jpg', 'source_status': 'nonempty_verified'},
                 ]}
                for row in range(count)
            ],
        }

    def plan(self, manifest=None, settings=None):
        settings = settings or self.settings()
        sha = hashlib.sha256(json.dumps(settings).encode()).hexdigest()
        return audit.build_plan(manifest or self.manifest(), settings,
                                manifest_sha256='a' * 64, settings_sha256=sha,
                                expected_settings_sha256=sha)

    def test_preserves_all_rows_and_source_roles_while_reusing_urls(self):
        plan = self.plan(self.manifest(219))
        self.assertEqual(len(plan['rows']), 219)
        self.assertEqual(len(plan['observations']), 2)
        self.assertEqual(plan['observations'][0]['url'], 'https://cdn.df.qq.com/G/CN/Resource/Store/C=AB12')
        self.assertEqual(plan['observations'][1]['url'], 'https://repo.df.qq.com/G/CN/Resource/Store/C=AB12')
        self.assertEqual(plan['rows'][218]['table'], 'gifts')
        self.assertEqual(plan['rows'][0]['resources'][1]['role'], 'field_304_unclassified')
        self.assertEqual(plan['rows'][0]['resources'][1]['source_field_index'], 304)
        self.assertEqual(plan['rows'][0]['resources'][0]['observation_ids'], [0, 1])
        self.assertFalse(plan['native_selected_branch_verified'])
        self.assertFalse(plan['native_url_composition_verified'])
        self.assertNotIn('do-not-copy', json.dumps(plan))
        self.assertNotIn('12345', json.dumps(plan))

    def test_local_empty_and_bare_reward_filenames_never_receive_urls(self):
        resources = self.plan()['rows'][0]['resources']
        for item in resources[2:]:
            self.assertEqual(item['observation_ids'], [])
            self.assertNotIn('value', item)
        self.assertEqual(resources[4]['status'], 'not_full_source_cdn_reference')

    def test_unverified_or_changed_settings_are_rejected(self):
        for mutate in (
            lambda s: s.update(status='skipped'),
            lambda s: s.update(weak_reference_and_headers_rechecked=False),
            lambda s: s['source_schema'].update(source_pe_sha256='0' * 64),
            lambda s: s['fields'][0].update(public_value_output_verified=False),
            lambda s: s['fields'][0].update(object_member_offset=0),
        ):
            settings = self.settings()
            mutate(settings)
            with self.assertRaises(ValueError):
                self.plan(settings=settings)
        with self.assertRaises(ValueError):
            audit.build_plan(self.manifest(), self.settings(), manifest_sha256='a' * 64,
                             settings_sha256='b' * 64, expected_settings_sha256='c' * 64)

    def test_unsafe_setting_values_are_rejected_without_echoing_values(self):
        for value in ('https://user:secret@cdn.df.qq.com', 'https://cdn.df.qq.com?token=secret',
                      'https://cdn.df.qq.com#secret', 'https://cdn.df.qq.com/?',
                      'https://@cdn.df.qq.com', 'https://evil.example',
                      'https://cdn.df.qq.com/extra', 'https://cdn.df.qq.com:secret',
                      'https://cdn.df.qq.com/\u4e2d', 'http://cdn.df.qq.com'):
            settings = self.settings()
            settings['fields'][0]['value'] = value
            with self.assertRaises(ValueError) as raised:
                self.plan(settings=settings)
            self.assertNotIn('secret', str(raised.exception))
        for value in ('../private', '/G/CN', 'G/CN?token=secret', 'G/CN/\u4e2d'):
            settings = self.settings()
            settings['fields'][2]['value'] = value
            with self.assertRaises(ValueError):
                self.plan(settings=settings)

    def test_manifest_path_injection_is_not_constructed_or_persisted(self):
        for value in ('Resource/Store/C=AB?token=secret', 'Resource/../C=AB',
                      'Resource/Store/C=AB#secret', 'Resource/Store/C=\u4e2d',
                      'https://evil.example/Resource/Store/C=AB'):
            manifest = self.manifest(1)
            manifest['entries'][0]['resources'][0]['value'] = value
            result = self.plan(manifest)
            self.assertEqual(result['rows'][0]['resources'][0]['observation_ids'], [])
            self.assertNotIn('secret', json.dumps(result))
            self.assertNotIn('evil.example', json.dumps(result))

    def test_unverified_resource_value_is_not_requested(self):
        manifest = self.manifest(1)
        manifest['entries'][0]['resources'][0]['source_status'] = 'unknown'
        self.assertEqual(self.plan(manifest)['rows'][0]['resources'][0]['observation_ids'], [])

    def test_source_root_prefixed_path_is_preserved_without_double_prefix(self):
        manifest = self.manifest(1)
        manifest['entries'][0]['resources'][0]['value'] = 'G/CN/Resource/Store/C=AB12'
        plan = self.plan(manifest)
        self.assertEqual(len(plan['observations']), 2)
        self.assertEqual(plan['rows'][0]['resources'][0]['observation_ids'], [0, 1])
        self.assertNotIn('/G/CN/G/CN/', plan['observations'][0]['url'])

    def test_direct_resource_png_path_does_not_acquire_an_invented_store_directory(self):
        manifest = self.manifest(1)
        manifest['entries'][0]['resources'][0]['value'] = 'Resource/C=AB12.PNG'
        plan = self.plan(manifest)
        self.assertEqual(len(plan['observations']), 4)
        self.assertEqual(plan['observations'][0]['url'], 'https://cdn.df.qq.com/G/CN/Resource/C=AB12.PNG')

    def test_composition_snapshot_proves_selected_pc_branch_only_in_observed_state(self):
        plan = self.ready_plan()
        self.assertTrue(plan['native_url_composition_verified'])
        self.assertTrue(plan['native_selected_branch_verified'])
        self.assertFalse(plan['native_current_getcdnurl_result_verified'])
        self.assertEqual(plan['observations'][0]['branch_status'], 'alternate_observed_base')
        self.assertEqual(plan['observations'][1]['branch_status'], 'source_selected_in_snapshot')

    def test_changed_composition_hash_scalar_or_pid_is_rejected(self):
        for change in (
            lambda r: r.update(pid=98765),
            lambda r: r.update(native_pe_sha256='0' * 64),
            lambda r: r['composition_scalars']['pc_url_selector'].update(value=0),
            lambda r: r['composition_scalars']['app_url_override'].update(value=1),
            lambda r: r['composition_helpers']['URL_StringAppend'].update(sha256='0' * 64),
        ):
            report = self.composition()
            change(report)
            sha = hashlib.sha256(json.dumps(report).encode()).hexdigest()
            with self.assertRaises(ValueError):
                audit.apply_composition(self.plan(), self.settings(), report,
                                        actual_sha256=sha, expected_sha256=sha)
        with self.assertRaises(ValueError):
            audit.apply_composition(self.plan(), self.settings(), self.composition(),
                                    actual_sha256='a' * 64, expected_sha256='b' * 64)

    def test_native_root_stripping_would_change_an_interior_prefix_is_rejected(self):
        manifest = self.manifest(1)
        manifest['entries'][0]['resources'][0]['value'] = 'Resource/G/CN/Store/C=AB12'
        with self.assertRaises(ValueError):
            self.ready_plan(manifest)

    def test_execute_requires_composition_proof_before_any_request(self):
        def forbidden(*args):
            self.fail('Unverified composition reached requester')
        with self.assertRaises(ValueError):
            audit.run_audit(self.plan(), execute=True, requester=forbidden)

    def test_plan_mode_never_calls_requester(self):
        def forbidden(*args):
            self.fail('Plan mode attempted a request')
        result = audit.run_audit(self.plan(), requester=forbidden)
        self.assertEqual(result['request_count'], 0)
        self.assertTrue(all(o['status'] == 'not_requested' for o in result['observations']))

    def test_duplicate_references_only_request_unique_urls_and_preserve_head_404_scope(self):
        calls = []
        def head(url, timeout):
            calls.append((url, timeout))
            return {'status': 'head_response', 'http_status': 404,
                    'availability': 'not_found_by_head', 'raw_private': 'do-not-copy'}
        result = audit.run_audit(self.ready_plan(self.manifest(219)), execute=True, requester=head)
        self.assertEqual(len(calls), 2)
        self.assertEqual(result['request_count'], 2)
        self.assertEqual(result['observations'][0]['http_status'], 404)
        self.assertFalse(result['native_resource_binding_and_rendering_verified'])
        self.assertNotIn('do-not-copy', json.dumps(result))

    def test_invalid_worker_or_timeout_limits_rejected_before_request(self):
        def forbidden(*args):
            self.fail('Invalid bounds reached requester')
        for workers, timeout in ((0, 10), (5, 10), (4, 0), (4, 11)):
            with self.assertRaises(ValueError):
                audit.run_audit(self.plan(), execute=True, workers=workers, timeout=timeout,
                                requester=forbidden)

    def test_head_never_reads_body_follows_redirects_or_copies_headers(self):
        class Response:
            status = 302
            def read(self, *args):
                raise AssertionError('Body read attempted')
            def getheader(self, *args):
                raise AssertionError('Response header copied')
            def close(self):
                self.closed = True
        class Connection:
            def __init__(self, host, *, timeout):
                self.host, self.timeout = host, timeout
                self.response = Response()
            def request(self, method, path, *, headers):
                self.method, self.path, self.headers = method, path, headers
            def getresponse(self):
                return self.response
            def close(self):
                self.closed = True
        connections = []
        def factory(*args, **kwargs):
            connection = Connection(*args, **kwargs)
            connections.append(connection)
            return connection
        result = audit.head_url('https://cdn.df.qq.com/G/CN/Resource/Store/C=AB12', 10,
                                connection_factory=factory)
        self.assertEqual(len(connections), 1)
        self.assertEqual(connections[0].method, 'HEAD')
        self.assertEqual(connections[0].path, '/G/CN/Resource/Store/C=AB12')
        self.assertEqual(connections[0].headers, {'Connection': 'close'})
        self.assertTrue(connections[0].closed)
        self.assertTrue(connections[0].response.closed)
        self.assertEqual(result['availability'], 'redirect_not_followed')

    def test_timeout_exception_does_not_persist_private_exception_text(self):
        def failed(*args, **kwargs):
            raise TimeoutError('secret account data')
        result = audit.head_url('https://cdn.df.qq.com/G/CN/Resource/Store/C=AB12', 10,
                                connection_factory=failed)
        self.assertEqual(result['status'], 'head_timeout')
        self.assertNotIn('secret', json.dumps(result))

    def test_head_403_and_405_are_access_and_unsupported_not_absence(self):
        class Response:
            def __init__(self, status):
                self.status = status
            def close(self):
                pass
        class Connection:
            def __init__(self, status):
                self.status = status
            def request(self, *args, **kwargs):
                pass
            def getresponse(self):
                return Response(self.status)
            def close(self):
                pass
        for status, expected in ((403, 'access_denied'), (405, 'head_unsupported')):
            result = audit.head_url('https://cdn.df.qq.com/G/CN/Resource/Store/C=AB12', 10,
                                    connection_factory=lambda *a, **k: Connection(status))
            self.assertEqual(result['availability'], expected)

    def test_head_rejects_arbitrary_hosts_and_query_before_connecting(self):
        def forbidden(*args, **kwargs):
            self.fail('Unsafe URL reached connection')
        for value in ('https://evil.example/G/CN/Resource/Store/C=AB12',
                      'https://cdn.df.qq.com/G/CN/Resource/Store/C=AB12?secret',
                      'https://user:secret@cdn.df.qq.com/G/CN/Resource/Store/C=AB12'):
            with self.assertRaises(ValueError):
                audit.head_url(value, 10, connection_factory=forbidden)

    def test_public_summary_has_no_urls_settings_or_process_data(self):
        public = audit.public_summary(self.plan())
        encoded = json.dumps(public)
        self.assertNotIn('https://', encoded)
        self.assertNotIn('pid', encoded)
        self.assertEqual(len(public['rows']), 2)
        self.assertEqual(public['rows'][0]['resources'][0]['source_field_index'], 274)

    def test_public_source_paths_and_urls_are_validated_and_labels_remain_source_scoped(self):
        public = audit.public_summary(self.ready_plan(), include_source_paths=True)
        resource = public['rows'][0]['resources'][0]
        self.assertEqual(resource['source_relative_path'], 'Resource/Store/C=AB12')
        self.assertEqual(resource['candidate_observations'][1]['branch_status'], 'source_selected_in_snapshot')
        self.assertEqual(resource['candidate_observations'][1]['url'], 'https://repo.df.qq.com/G/CN/Resource/Store/C=AB12')
        self.assertFalse(public['native_image_setter_input_preprocessing_verified'])
        self.assertFalse(public['native_effective_request_url_verified'])
        self.assertEqual(resource['candidate_observations'][1]['url_scope'], 'raw_source_path_composed_with_observed_configuration')
        self.assertEqual(public['summary']['source_reference_occurrences'], 4)
        bad = self.ready_plan()
        bad['observations'][0]['url'] = 'https://user:secret@evil.example/private'
        with self.assertRaises(ValueError):
            audit.public_summary(bad, include_source_paths=True)

    def test_cli_defaults_to_plan_and_records_safe_command_time_and_digests(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            resources = root / 'resources.json'
            settings = root / 'settings.json'
            resources.write_text(json.dumps(self.manifest()), encoding='utf-8')
            data = json.dumps(self.settings()).encode()
            settings.write_bytes(data)
            output = root / 'evidence/audit-private.json'
            args = ['check_bundle_cdn_resources.py', '--resources', str(resources),
                    '--settings', str(settings), '--settings-sha256', hashlib.sha256(data).hexdigest(),
                    '--output', str(output)]
            with patch.object(audit, 'ROOT', root), patch.object(audit, 'EVIDENCE', root / 'evidence'), \
                    patch('sys.argv', args), patch('builtins.print'), \
                    patch.object(audit, 'head_url', side_effect=AssertionError('Network attempted')):
                audit.main()
            result = json.loads(output.read_text(encoding='utf-8'))
            self.assertEqual(result['mode'], 'plan')
            self.assertEqual(result['request_count'], 0)
            self.assertIn('--settings', result['command'])
            self.assertIn('settings.json', result['command'])
            self.assertTrue(result['started_at_utc'].endswith('+00:00'))
            self.assertTrue(result['finished_at_utc'].endswith('+00:00'))
            self.assertEqual(result['source_settings_report_sha256'], hashlib.sha256(data).hexdigest())


if __name__ == '__main__':
    unittest.main()
