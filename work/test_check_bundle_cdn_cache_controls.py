"""Bounded GET/cache hash controls with synthetic bodies, never network."""

import hashlib
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

try:
    import check_bundle_cdn_cache_controls as control
except ModuleNotFoundError:
    control = None


class ControlModuleTests(unittest.TestCase):
    def test_control_module_exists(self):
        self.assertIsNotNone(control, 'The bounded body hash control is not implemented')


class BodyHashTests(unittest.TestCase):
    def setUp(self):
        if control is None:
            self.skipTest('Control module is not yet implemented')
    def factory(self, body, status=200, location=None):
        class Response:
            def __init__(self):
                self.status, self.at, self.reads, self.headers_read = status, 0, [], []
            def getheader(self, name):
                self.headers_read.append(name)
                return location
            def read(self, size):
                self.reads.append(size)
                value = body[self.at:self.at + size]
                self.at += len(value)
                return value
            def close(self):
                self.closed = True
        class Connection:
            def __init__(self):
                self.response = Response()
            def request(self, method, path, *, headers):
                self.method, self.path, self.headers = method, path, headers
            def getresponse(self):
                return self.response
            def close(self):
                self.closed = True
        connection = Connection()
        return connection, lambda *args, **kwargs: connection

    def test_get_hashes_original_bytes_without_body_output_and_closes(self):
        body = b'\xff\xd8synthetic-public-jpeg'
        connection, factory = self.factory(body)
        result = control.get_body_hash('https://repo.df.qq.com/G/CN/Resource/Store/C=AB12.jpg',
                                       connection_factory=factory)
        self.assertEqual(connection.method, 'GET')
        self.assertEqual(connection.headers, {'Connection': 'close', 'Accept-Encoding': 'identity'})
        self.assertEqual(result['sha256'], hashlib.sha256(body).hexdigest())
        self.assertEqual(result['bytes'], len(body))
        self.assertNotIn('body', result)
        self.assertTrue(connection.closed)
        self.assertTrue(connection.response.closed)

    def test_redirect_never_reads_a_body_or_follows(self):
        connection, factory = self.factory(b'private redirect response', 302)
        result = control.get_body_hash('https://repo.df.qq.com/G/CN/Resource/Store/C=AB12.jpg',
                                       connection_factory=factory)
        self.assertEqual(result['status'], 'get_non_200_body_not_read')
        self.assertEqual(connection.response.reads, [])
        self.assertNotIn('sha256', result)
        self.assertEqual(result['location_status'], 'not_present')
        self.assertEqual(connection.response.headers_read, ['Location'])

    def test_redirect_exposes_only_an_official_exact_original_source_path(self):
        target = 'https://cdn.df.qq.com/G/CN/Resource/Store/C=AB12.jpg'
        connection, factory = self.factory(b'not read', 302, target)
        result = control.get_body_hash('https://repo.df.qq.com/G/CN/Resource/Store/C=AB12.jpg',
                                       connection_factory=factory)
        self.assertEqual(result['location'], target)
        self.assertEqual(result['location_status'], 'public_same_source_path')
        self.assertEqual(connection.response.reads, [])
        self.assertEqual(connection.method, 'GET')

    def test_redirect_private_or_unrelated_location_values_are_redacted(self):
        prefix = 'https://cdn.df.qq.com/G/CN/Resource/Store/C=AB12.jpg'
        targets = (prefix + '?secret', prefix + '?', prefix + '#',
                   'https://user:secret@cdn.df.qq.com/G/CN/Resource/Store/C=AB12.jpg',
                   prefix.replace('cdn.df.qq.com', 'evil.example'),
                   prefix.replace('cdn.df.qq.com', 'cdn.df.qq.com:notaport'),
                   prefix.replace('AB12', 'CD34'), prefix + '\u79d8',
                   '/G/CN/Resource/Store/C=AB12.jpg', ' private secret')
        for target in targets:
            with self.subTest(target=target):
                connection, factory = self.factory(b'not read', 302, target)
                result = control.get_body_hash('https://repo.df.qq.com/G/CN/Resource/Store/C=AB12.jpg',
                                               connection_factory=factory)
                self.assertEqual(result['location_status'], 'redacted_or_unsupported')
                self.assertNotIn('location', result)
                self.assertNotIn(target, str(result))
                self.assertEqual(connection.response.reads, [])

    def test_size_bound_stops_without_a_complete_or_partial_hash(self):
        connection, factory = self.factory(b'A' * 17)
        result = control.get_body_hash('https://repo.df.qq.com/G/CN/Resource/Store/C=AB12.jpg',
                                       max_bytes=16, connection_factory=factory)
        self.assertEqual(result['status'], 'get_body_exceeds_bound')
        self.assertNotIn('sha256', result)
        self.assertLessEqual(sum(connection.response.reads), 17)

    def test_timeout_or_unsafe_url_never_outputs_private_exception_text(self):
        def failed(*args, **kwargs):
            raise TimeoutError('secret private account data')
        result = control.get_body_hash('https://repo.df.qq.com/G/CN/Resource/Store/C=AB12.jpg',
                                       connection_factory=failed)
        self.assertEqual(result['status'], 'get_timeout')
        self.assertNotIn('secret', str(result))
        with self.assertRaises(ValueError):
            control.get_body_hash('https://user:secret@evil.example/private', connection_factory=failed)

    def test_limits_cannot_exceed_authorized_control_bounds(self):
        for timeout, maximum in ((3, 100), (2, 8 * 1024 * 1024 + 1), (0, 100)):
            with self.assertRaises(ValueError):
                control.get_body_hash('https://repo.df.qq.com/G/CN/Resource/Store/C=AB12.jpg',
                                       timeout=timeout, max_bytes=maximum)

    def test_read_finishing_after_deadline_never_reports_a_successful_hash(self):
        for body in (b'late bytes', b''):
            with self.subTest(body=body):
                clock = [0.0]
                connection, factory = self.factory(body)
                original = connection.response.read
                def late_read(size):
                    clock[0] = 2.1
                    return original(size)
                connection.response.read = late_read
                with patch.object(control.time, 'monotonic', side_effect=lambda: clock[0]):
                    result = control.get_body_hash('https://repo.df.qq.com/G/CN/Resource/Store/C=AB12.jpg',
                                                   connection_factory=factory)
                self.assertEqual(result['status'], 'get_deadline_exceeded')
                self.assertNotIn('sha256', result)

    def test_remaining_budget_is_applied_before_connection_header_and_body_phases(self):
        clock, budgets = [0.0], []
        connection, factory = self.factory(b'')
        class Socket:
            def settimeout(self, timeout):
                budgets.append(timeout)
        connection.sock = Socket()
        connection.connect = lambda: clock.__setitem__(0, 0.4)
        original_request, original_response = connection.request, connection.getresponse
        def request(*args, **kwargs):
            self.assertLessEqual(budgets[-1], 1.6)
            clock[0] += 0.3
            return original_request(*args, **kwargs)
        def response():
            self.assertLessEqual(budgets[-1], 1.3 + 1e-10)
            clock[0] += 0.2
            return original_response()
        connection.request, connection.getresponse = request, response
        with patch.object(control.time, 'monotonic', side_effect=lambda: clock[0]):
            result = control.get_body_hash('https://repo.df.qq.com/G/CN/Resource/Store/C=AB12.jpg',
                                           connection_factory=factory)
        self.assertEqual(result['status'], 'get_body_hashed')
        self.assertTrue(budgets)
        self.assertTrue(all(0 < budget <= 2 for budget in budgets))
        self.assertEqual(budgets, sorted(budgets, reverse=True))


class SourceControlTests(unittest.TestCase):
    def setUp(self):
        if control is None:
            self.skipTest('Control module is not yet implemented')
        self.folder = tempfile.TemporaryDirectory()
        self.addCleanup(self.folder.cleanup)
        self.shadow = Path(self.folder.name)
        self.body = b'\xff\xd8synthetic-public-jpeg'
        self.file = self.shadow / 'DeltaForce/Saved/Cdn/G/CN/Resource/Store/C=7'
        self.file.parent.mkdir(parents=True)
        self.file.write_bytes(self.body)
        self.manifest = {'entries': [{'table': 'recommendations', 'row': 127, 'resources': [
            {'source_field_index': 272, 'role': 'cdn_big', 'value': 'Resource/Store/C=AB12.jpg',
             'kind': 'cdn_relative_reference', 'source_status': 'nonempty_verified'}]}]}
        self.head = {'source_manifest_sha256': 'a' * 64, 'source_pe_sha256': control.source.EXPECTED_PE,
                     'native_url_composition_verified': True, 'mode': 'head',
                     'configuration_fields': {control.source.ROOT_FIELD: 'G/CN',
                                              control.source.PC_FIELD: 'https://repo.df.qq.com'},
                     'rows': [{'table': 'recommendations', 'row': 127, 'resources': [
                         {'source_field_index': 272, 'role': 'cdn_big',
                          'source_relative_path': 'Resource/Store/C=AB12.jpg', 'observation_ids': [0]}]}],
                     'observations': [{'candidate_base_fields': [control.source.PC_FIELD],
                                       'status': 'head_response', 'http_status': 200,
                                       'url': 'https://repo.df.qq.com/G/CN/Resource/Store/C=AB12.jpg'}]}
        self.cache = {'references': [{'table': 'recommendations', 'row': 127, 'field_index': 272,
                                     'value': 'Resource/Store/C=AB12.jpg', 'cache_basename': 'C=7',
                                     'source_serialized_string_and_relative_path_verified': True,
                                     'cache_presence_status': 'observed_existing',
                                     'physical_cache_existing': [str(self.file)],
                                     'existing_cache_metadata': [{'path': str(self.file), 'size': len(self.body),
                                                                  'sha256': hashlib.sha256(self.body).hexdigest(),
                                                                  'format': 'JPEG'}]}]}

    def prepare(self, **changes):
        args = {'manifest_sha256': 'a' * 64, 'head_sha256': 'b' * 64, 'cache_sha256': 'c' * 64,
                'expected_head_sha256': 'b' * 64, 'expected_cache_sha256': 'c' * 64,
                'shadow_root': self.shadow, 'selections': [('recommendations', 127, 272)]}
        args.update(changes)
        return control.prepare_controls(self.manifest, self.head, self.cache, **args)

    def test_exact_source_and_existing_cache_hash_control_records_only_metadata(self):
        controls = self.prepare()
        expected = hashlib.sha256(self.body).hexdigest()
        result = control.run_controls(controls, execute=True, getter=lambda url: {
            'status': 'get_body_hashed', 'bytes': len(self.body), 'sha256': expected, 'http_status': 200})
        self.assertTrue(result['controls'][0]['payload_equals_observed_cache'])
        self.assertFalse(result['cache_filename_algorithm_native_verified'])
        self.assertNotIn(str(self.shadow), str(result))
        self.assertNotIn('_cache_path', str(result))

    def test_HEAD404_or_changed_input_report_hash_is_rejected(self):
        with self.assertRaises(ValueError):
            self.prepare(head_sha256='0' * 64)
        self.head['observations'][0]['http_status'] = 404
        with self.assertRaises(ValueError):
            self.prepare()

    def test_HEAD_URL_cannot_silently_target_another_source_resource(self):
        self.head['observations'][0]['url'] = 'https://repo.df.qq.com/G/CN/Resource/Store/C=CD34.jpg'
        with self.assertRaises(ValueError):
            self.prepare()

    def test_exact_cache_file_outside_shadow_source_directory_is_rejected(self):
        outside = self.shadow / 'outside/C=7'
        metadata = self.cache['references'][0]
        metadata['physical_cache_existing'] = [str(outside)]
        metadata['existing_cache_metadata'][0]['path'] = str(outside)
        with self.assertRaises(ValueError):
            self.prepare()

    def test_changed_existing_cache_hash_is_rejected_before_GET(self):
        controls = self.prepare()
        self.file.write_bytes(b'X' * len(self.body))
        def forbidden(url):
            self.fail('Changed cache reached GET')
        with self.assertRaises(ValueError):
            control.run_controls(controls, execute=True, getter=forbidden)

    def test_plan_only_never_calls_GET(self):
        def forbidden(url):
            self.fail('Prepare mode reached GET')
        result = control.run_controls(self.prepare(), getter=forbidden)
        self.assertEqual(result['request_count'], 0)

    def test_redirect_summary_revalidates_location_and_marks_old_unobserved_headers(self):
        controls = self.prepare()
        for observed, expected in (({'status': 'get_non_200_body_not_read', 'http_status': 302, 'bytes': 0},
                                    'not_observed'),
                                   ({'status': 'get_non_200_body_not_read', 'http_status': 302, 'bytes': 0,
                                     'location': 'https://evil.example/private?secret'},
                                    'redacted_or_unsupported')):
            with self.subTest(expected=expected):
                result = control.run_controls(controls, execute=True, getter=lambda url: observed)
                self.assertEqual(result['controls'][0]['GET']['location_status'], expected)
                self.assertNotIn('evil.example', str(result))


if __name__ == '__main__':
    unittest.main()
