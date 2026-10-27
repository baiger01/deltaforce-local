"""Synthetic cache repair contracts. No network or game files are used."""

import hashlib
import io
import os
from pathlib import Path
import tempfile
import struct
from types import SimpleNamespace
import unittest
from unittest.mock import patch

import repair_bundle_cdn_cache as repair


BIG = 'Resource/Store/C=D0DC1B1DF312F19778F4F51297BA33B6AF1B628952C25B8CA38731FA485F82ADC8788BE674874CB14D6ECBED39E12C53.jpg'
LOGO = 'Resource/Store/C=43A66C67DE172EEBDF95AF80F78A420A50B1E9304F9FE9C128B047AE0372CDF4D2D764793D5A0BFCDEA4694855810B8D.png'


def image_bytes(format='PNG'):
    from PIL import Image
    stream = io.BytesIO()
    Image.new('RGB', (2, 3), (11, 32, 54)).save(stream, format=format)
    return stream.getvalue()


class FileTests(unittest.TestCase):
    def setUp(self):
        self.folder = tempfile.TemporaryDirectory()
        self.addCleanup(self.folder.cleanup)
        self.root = Path(self.folder.name)
        self.installed, self.shadow = self.root / 'installed', self.root / 'shadow'
        self.installed.mkdir()
        self.shadow.mkdir()

    def test_explicit_separate_existing_roots_are_required(self):
        repair.safe_roots(self.installed, self.shadow)
        for source, shadow in ((self.installed, self.installed),
                               (self.installed, self.installed / 'sub'),
                               (self.root / 'missing', self.shadow)):
            with self.assertRaises(ValueError):
                repair.safe_roots(source, shadow)

    def test_atomic_publication_creates_only_a_new_complete_cache(self):
        payload = image_bytes()
        path = self.shadow / 'DeltaForce/Saved/Cdn/G/CN/Resource/Store/C=7'
        result = repair.publish_new_cache(self.shadow, path, payload)
        self.assertEqual(result['status'], 'created')
        self.assertEqual(path.read_bytes(), payload)
        self.assertEqual(result['sha256'], hashlib.sha256(payload).hexdigest())
        self.assertEqual(list(path.parent.glob('.bundle-repair-*')), [])

    def test_existing_cache_is_never_overwritten(self):
        path = self.shadow / 'DeltaForce/Saved/Cdn/G/CN/Resource/Store/C=7'
        path.parent.mkdir(parents=True)
        path.write_bytes(b'existing-native-cache')
        result = repair.publish_new_cache(self.shadow, path, image_bytes())
        self.assertEqual(result['status'], 'existing_preserved')
        self.assertEqual(path.read_bytes(), b'existing-native-cache')

    def test_symlink_parent_or_existing_target_is_never_written(self):
        source = self.installed / 'untouched'
        source.mkdir()
        link = self.shadow / 'DeltaForce'
        try:
            link.symlink_to(source, target_is_directory=True)
        except OSError:
            self.skipTest('The test host cannot create symlinks')
        with self.assertRaises(ValueError):
            repair.publish_new_cache(self.shadow, link / 'Saved/Cdn/G/CN/Resource/C=7', image_bytes())
        self.assertEqual(list(source.iterdir()), [])

    def test_target_broken_symlink_is_preserved(self):
        path = self.shadow / 'DeltaForce/Saved/Cdn/G/CN/Resource/C=7'
        path.parent.mkdir(parents=True)
        try:
            path.symlink_to(self.root / 'not-created')
        except OSError:
            self.skipTest('The test host cannot create symlinks')
        with self.assertRaises(ValueError):
            repair.publish_new_cache(self.shadow, path, image_bytes())
        self.assertTrue(path.is_symlink())
        self.assertFalse((self.root / 'not-created').exists())

    def test_Windows_reparse_attribute_is_blocked_without_symlink_privileges(self):
        self.assertTrue(repair._reparse(SimpleNamespace(st_mode=0o040755, st_file_attributes=0x400)))
        self.assertFalse(repair._reparse(SimpleNamespace(st_mode=0o040755, st_file_attributes=0)))


class SourceTests(FileTests):
    def source_plan(self):
        rows = [{'table': 'recommendations', 'row': i, 'row_offset': i * 100,
                 'resources': []} for i in range(219)]
        for row in (0, 1):
            rows[row]['resources'].append({'source_field_index': 272, 'role': 'cdn_big',
                                           'status': 'candidate_urls_ready', 'source_relative_path': BIG})
        rows[2]['resources'].append({'source_field_index': 304, 'role': 'field_304_unclassified',
                                    'status': 'candidate_urls_ready', 'source_relative_path': 'Resource/C=AB12.PNG'})
        rows[3]['resources'].append({'source_field_index': 1823, 'role': 'bare_reward',
                                    'status': 'not_full_source_cdn_reference'})
        rows[4]['resources'].append({'source_field_index': 274, 'role': 'cdn_small',
                                    'status': 'empty_in_source'})
        return {'rows': rows, 'source_manifest_sha256': repair.MANIFEST_SHA256,
                'native_url_composition_verified': True, 'source_pe_sha256': repair.source.EXPECTED_PE,
                'configuration_fields': {repair.source.ROOT_FIELD: 'G/CN',
                                         repair.source.DEFAULT_FIELD: 'https://cdn.df.qq.com',
                                         repair.source.PC_FIELD: 'https://repo.df.qq.com'}}

    def plan(self):
        return repair.plan_targets(self.source_plan(), self.installed, self.shadow,
                                   crc_verified=True, expected_counts=(219, 2))

    def test_original_source_rows_dedup_and_unknown_role_are_retained(self):
        plan = self.plan()
        self.assertEqual(len(plan['rows']), 219)
        self.assertEqual(len(plan['targets']), 2)
        self.assertEqual(plan['rows'][0]['resources'][0]['target_id'], plan['rows'][1]['resources'][0]['target_id'])
        self.assertFalse(plan['targets'][1]['eligible'])
        self.assertEqual(plan['rows'][2]['resources'][0]['status'], 'unknown_source_consumer_excluded')
        self.assertNotIn('target_id', plan['rows'][3]['resources'][0])
        self.assertEqual(plan['rows'][4]['resources'][0]['status'], 'empty_in_source')
        self.assertIsNone(plan['targets'][0]['url'])

    def test_plan_mode_never_calls_network_or_creates_directories(self):
        def forbidden(*args, **kwargs):
            self.fail('Plan mode attempted network')
        result = repair.run_repair(self.plan(), execute=False, downloader=forbidden)
        self.assertEqual(result['request_count'], 0)
        self.assertEqual(list(self.shadow.iterdir()), [])

    def test_missing_native_formula_blocks_before_any_network_or_write(self):
        def forbidden(*args, **kwargs):
            self.fail('Unverified formula attempted network')
        with self.assertRaises(ValueError):
            repair.run_repair(self.plan(), execute=True, downloader=forbidden)
        self.assertEqual(list(self.shadow.iterdir()), [])

    def test_crc_must_be_verified_before_cache_targets_are_planned(self):
        with self.assertRaises(ValueError):
            repair.plan_targets(self.source_plan(), self.installed, self.shadow, crc_verified=False)

    def test_distinct_original_paths_with_colliding_cache_targets_are_rejected(self):
        plan = self.source_plan()
        plan['rows'][2]['resources'][0]['source_relative_path'] = 'Resource/Store/C=AB12.PNG'
        with patch.object(repair, 'cache_basename', return_value='C=7'):
            with self.assertRaises(ValueError):
                repair.plan_targets(plan, self.installed, self.shadow, crc_verified=True, expected_counts=(219, 2))

    def test_existing_cache_created_during_GET_is_preserved_and_body_not_exported(self):
        plan = self.plan()
        plan['native_request_formula_verified'] = True
        target = plan['targets'][0]
        target['url'] = 'https://cdn.df.qq.com/G/CN/' + target['source_relative_path']
        def download(url):
            target['_cache_path'].parent.mkdir(parents=True)
            target['_cache_path'].write_bytes(b'client-created-cache')
            return {'status': 'body_received', 'http_status': 200, 'bytes': 80, '_body': image_bytes()}
        result = repair.run_repair(plan, execute=True, downloader=download)
        self.assertEqual(result['targets'][0]['status'], 'existing_preserved')
        self.assertEqual(target['_cache_path'].read_bytes(), b'client-created-cache')
        self.assertEqual(len(result['rows']), 219)
        self.assertNotIn("'_body':", str(result))
        self.assertEqual(result['created_count'], 0)


class BytesTests(unittest.TestCase):
    def test_original_complete_basename_crc_includes_literal_extension(self):
        self.assertEqual(repair.cache_basename(BIG), 'C=951152861')
        self.assertEqual(repair.cache_basename(LOGO), 'C=-1469832761')
        self.assertEqual(repair.cache_basename('Resource/Store/' + BIG.rsplit('/', 1)[-1].upper()), 'C=951152861')
        self.assertNotEqual(repair.cache_basename(BIG.rsplit('.', 1)[0]), 'C=951152861')

    def test_complete_standard_png_and_jpeg_are_validated(self):
        for format in ('PNG', 'JPEG'):
            result = repair.validate_image(image_bytes(format))
            self.assertEqual(result['format'], format)
            self.assertEqual((result['width'], result['height']), (2, 3))

    def test_html_corrupted_or_unproven_native_wrapper_is_rejected(self):
        png = image_bytes()
        for body in (b'<html>access denied</html>', png[:24], b'unproven-native-header' + png,
                     png + b'extra-data'):
            with self.assertRaises(ValueError):
                repair.validate_image(body)

    def test_native_report_digest_mismatch_fails_closed(self):
        with self.assertRaises(ValueError):
            repair.verify_crc({}, '0' * 64)

    def test_native_wrapper_requires_proof_and_decompresses_original_bytes_only(self):
        body = bytes.fromhex('89504e470d0a1a0a') + struct.pack('<8I', 3, 8, 8, 64, 7, 0, 1, 4) + b'original-compressed-bytes'
        calls = []
        def decode(payload, expected):
            calls.append((payload, expected))
            return b'X' * expected
        with self.assertRaises(ValueError):
            repair.validate_image(body, native_decoder=decode)
        self.assertEqual(calls, [])
        result = repair.validate_image(body, native_decoder=decode, native_payload_verified=True)
        self.assertEqual(calls, [(body[40:], 64)])
        self.assertEqual(result['sha256'], hashlib.sha256(body).hexdigest())
        self.assertFalse(result['header_field_semantics_native_verified'])
        self.assertFalse(result['native_texture_decoding_or_rendering_verified'])

    def test_native_header_bounds_are_checked_before_codec(self):
        def forbidden(*args):
            self.fail('Out-of-bound native header reached codec')
        for width, height, expected in ((8193, 8, 64), (8, 8, repair.MAX_BYTES + 1), (8, 8, 32)):
            body = bytes.fromhex('89504e470d0a1a0a') + struct.pack('<8I', 3, width, height, expected, 7, 0, 1, 4) + b'compressed'
            with self.assertRaises(ValueError):
                repair.validate_image(body, native_decoder=forbidden, native_payload_verified=True)

    def test_native_wrong_decompressed_length_never_validates(self):
        body = bytes.fromhex('89504e470d0a1a0a') + struct.pack('<8I', 3, 8, 8, 64, 7, 0, 1, 4) + b'compressed'
        with self.assertRaises(ValueError):
            repair.validate_image(body, native_decoder=lambda *args: b'X' * 63, native_payload_verified=True)

    def test_payload_control_digest_is_mandatory(self):
        with self.assertRaises(ValueError):
            repair.verify_native_payload_control({}, '0' * 64)

    def test_known_source_PNG_trailer_requires_exact_body_pin_and_dimensions(self):
        image = image_bytes()
        body = image + b'opaque-original-trailer'
        original = 'Resource/Store/C=AB12.PNG'
        approved = {'size': len(body), 'sha256': hashlib.sha256(body).hexdigest(),
                    'width': 2, 'height': 3, 'png_stream_bytes': len(image)}
        with patch.dict(repair.OBSERVED_STANDARD_PNG, {original: approved}):
            result = repair.validate_image(body, original_source=original)
            self.assertEqual(result['original_png_trailing_bytes_preserved'], len(body) - len(image))
            with self.assertRaises(ValueError):
                repair.validate_image(body[:-1] + b'X', original_source=original)
            with self.assertRaises(ValueError):
                repair.validate_image(body)
            approved['width'] = 3
            with self.assertRaises(ValueError):
                repair.validate_image(body, original_source=original)

    def test_only_observed_large_source_has_a_larger_input_bound(self):
        self.assertEqual(repair.body_limit_for_source('Resource/Store/C=AB12.PNG'), repair.MAX_BYTES)
        large = [path for path, row in repair.OBSERVED_STANDARD_PNG.items() if row['size'] > repair.MAX_BYTES]
        self.assertEqual(len(large), 1)
        self.assertEqual(repair.body_limit_for_source(large[0]), 11077506)

    def test_CLI_default_payload_control_is_public_and_explicit_override_remains(self):
        parser = repair.build_parser()
        base = ['--game-root', 'source', '--shadow-root', 'shadow']
        default = parser.parse_args(base)
        self.assertEqual(default.native_payload_proof,
                         repair.source.ROOT / 'outputs/df-local-server/protocol/premium_shop_native_cache_control.json')
        explicit = parser.parse_args(base + ['--native-payload-proof', 'explicit.json'])
        self.assertEqual(explicit.native_payload_proof, Path('explicit.json'))

    def test_public_native_contract_is_pinned_and_exact_processed_URL_is_applied(self):
        contract, digest = repair.source._load(repair.source.ROOT / 'outputs/df-local-server/protocol/premium_shop_native_resource_contract.json', 8192)
        config = repair.validate_native_contract(contract, digest)
        plan = {'targets': [{'source_relative_path': 'Resource/Store/C=AB12'},
                            {'source_relative_path': 'Resource/C=AB12.PNG'}]}
        repair.apply_native_contract(plan, contract, digest, branch='default')
        self.assertEqual(plan['targets'][0]['url'], 'https://cdn.df.qq.com/G/CN/Resource/Store/7/C=AB12')
        self.assertEqual(plan['targets'][1]['url'], 'https://cdn.df.qq.com/G/CN/Resource/C=AB12.PNG')
        self.assertEqual(plan['targets'][0]['branch_status'], 'alternate_observed_base')
        self.assertEqual(config['selected_base_role'], 'pc')
        with self.assertRaises(ValueError):
            repair.validate_native_contract(contract, '0' * 64)


class DownloadTests(unittest.TestCase):
    def factory(self, body, status=200, location=None):
        class Response:
            def __init__(self):
                self.status, self.at, self.reads = status, 0, []
            def getheader(self, name):
                return location
            def read(self, size):
                self.reads.append(size)
                data = body[self.at:self.at + size]
                self.at += len(data)
                return data
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

    def test_byte_bound_unknown_status_and_no_auth(self):
        connection, factory = self.factory(b'A' * 17)
        result = repair.download_original('https://cdn.df.qq.com/G/CN/Resource/Store/C=AB12.jpg',
                                          max_bytes=16, connection_factory=factory)
        self.assertEqual(result['status'], 'body_exceeds_bound')
        self.assertNotIn('_body', result)
        self.assertEqual(connection.headers, {'Connection': 'close', 'Accept-Encoding': 'identity'})
        self.assertTrue(connection.closed)

    def test_redirect_with_query_or_unrelated_host_is_never_followed(self):
        for location in ('https://evil.example/secret',
                         'https://cdn.df.qq.com/G/CN/Resource/Store/C=AB12.jpg?secret'):
            connection, factory = self.factory(b'not read', 302, location)
            result = repair.download_original('https://repo.df.qq.com/G/CN/Resource/Store/C=AB12.jpg',
                                              connection_factory=factory)
            self.assertEqual(result['status'], 'redirect_rejected')
            self.assertEqual(connection.response.reads, [])
            self.assertNotIn('location', result)

    def test_non200_is_observed_without_reading_body(self):
        connection, factory = self.factory(b'not read', 403)
        result = repair.download_original('https://cdn.df.qq.com/G/CN/Resource/Store/C=AB12.jpg',
                                          connection_factory=factory)
        self.assertEqual(result['http_status'], 403)
        self.assertEqual(connection.response.reads, [])
        self.assertNotIn('_body', result)

    def test_unsafe_request_is_rejected_before_connection(self):
        def forbidden(*args, **kwargs):
            self.fail('Unsafe request attempted connection')
        with self.assertRaises(ValueError):
            repair.download_original('https://user:secret@evil.example/private', connection_factory=forbidden)

    def test_generic_URL_cannot_use_a_larger_source_specific_byte_bound(self):
        def forbidden(*args, **kwargs):
            self.fail('Unapproved larger bound reached connection')
        with self.assertRaises(ValueError):
            repair.download_original('https://cdn.df.qq.com/G/CN/Resource/Store/C=AB12.PNG',
                                     max_bytes=repair.MAX_BYTES + 1, connection_factory=forbidden)


if __name__ == '__main__':
    unittest.main()
