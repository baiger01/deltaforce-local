from concurrent.futures import ThreadPoolExecutor
from dataclasses import FrozenInstanceError
import json
import unittest
from unittest.mock import patch

from dfserver.legacy_ds_match_admission import (
    LocalMatchAdmissions, MatchAdmissionCapacityReached, MatchAdmissionDenied,
    MAX_LOGIN_OPTIONS, MAX_LOGIN_URL_CHARS,
)


class Clock:
    def __init__(self, now=10):
        self.now = now

    def __call__(self):
        return self.now


def login_url(ticket, **overrides):
    fields = {'Cookie': ticket.cookie, 'PlayerId': ticket.player_id,
              'DSRoomId': ticket.room_id, 'MapId': ticket.map_id}
    fields.update(overrides)
    return '127.0.0.1:65034?' + '?'.join(f'{key}={value}' for key, value in fields.items())


class LocalMatchAdmissionsTests(unittest.TestCase):
    def setUp(self):
        self.clock = Clock()
        self.admissions = LocalMatchAdmissions(ttl=5, max_tickets=2, clock=self.clock)
        self.ticket = self.admissions.issue(123, 456, 2201, 142201103, 10001)

    def test_ticket_is_immutable_and_redacts_repr(self):
        self.assertEqual(len(self.ticket.cookie), 32)
        self.assertRegex(self.ticket.cookie, r'^[0-9a-f]{32}$')
        self.assertEqual((self.ticket.player_id, self.ticket.room_id, self.ticket.map_id,
                          self.ticket.match_mode_id, self.ticket.selected_hero_id),
                         (123, 456, 2201, 142201103, 10001))
        self.assertEqual((self.ticket.issued_at, self.ticket.expires_at), (10, 15))
        with self.assertRaises(FrozenInstanceError):
            self.ticket.map_id = 9
        self.assertNotIn(self.ticket.cookie, repr(self.ticket))
        self.assertNotIn(self.ticket.cookie, repr(self.admissions))

    def test_retransmission_returns_same_ticket_without_extending_expiry(self):
        url = login_url(self.ticket)
        self.assertIs(self.admissions.authorize_login_url(url), self.ticket)
        self.clock.now = 14.9
        self.assertIs(self.admissions.authorize_login_url(url), self.ticket)
        self.assertEqual(self.ticket.expires_at, 15)
        self.clock.now = 15
        with self.assertRaises(MatchAdmissionDenied):
            self.admissions.authorize_login_url(url)
        self.assertEqual(self.admissions.summary()['expired_ticket_count'], 1)

    def test_cookie_and_each_identity_binding_are_required(self):
        for key, value in [('Cookie', '0' * 32), ('PlayerId', 124),
                           ('DSRoomId', 457), ('MapId', 2202)]:
            with self.subTest(key=key), self.assertRaises(MatchAdmissionDenied):
                self.admissions.authorize_login_url(login_url(self.ticket, **{key: value}))
        self.assertEqual(self.admissions.summary()['active_ticket_count'], 1)

    def test_extra_options_are_accepted_without_platform_authentication(self):
        url = (login_url(self.ticket) + '?ModularWeapon=1,2,3?Response0=anything'
               '?UID=not-the-player?Platform=QQ?SpectatorOnly')
        self.assertIs(self.admissions.authorize_login_url(url), self.ticket)
        platform_only = '?Response0=0?UID=123?PlayerId=123?DSRoomId=456?MapId=2201'
        with self.assertRaises(MatchAdmissionDenied):
            self.admissions.authorize_login_url(platform_only)
        self.assertEqual(self.admissions.summary()['issued_ticket_count'], 1)

    def test_keys_are_case_insensitive_but_cookie_is_opaque(self):
        url = (f'?cookie={self.ticket.cookie}?PLAYERID=123'
               '?dsroomid=456?mApId=2201')
        self.assertIs(self.admissions.authorize_login_url(url), self.ticket)
        with patch('dfserver.legacy_ds_match_admission.secrets.token_hex',
                   return_value='abcdef0123456789abcdef0123456789'):
            ticket = self.admissions.issue(1, 2, 3, 4)
        with self.assertRaises(MatchAdmissionDenied):
            self.admissions.authorize_login_url(login_url(ticket, Cookie=ticket.cookie.upper()))

    def test_duplicate_key_rejected_even_if_same_value_or_different_case(self):
        for option in [f'Cookie={self.ticket.cookie}', f'cookie={self.ticket.cookie}',
                       'PLAYERID=123', 'DSRoomId=456', 'MapId=2201']:
            with self.subTest(option=option.split('=')[0]), self.assertRaises(MatchAdmissionDenied):
                self.admissions.authorize_login_url(login_url(self.ticket) + '?' + option)

    def test_missing_and_valueless_keys_are_rejected(self):
        options = login_url(self.ticket).split('?')
        for index in range(1, 5):
            for variant in [options[:index] + options[index + 1:],
                            options[:index] + [options[index].split('=')[0]] + options[index + 1:]]:
                with self.subTest(index=index), self.assertRaises(MatchAdmissionDenied):
                    self.admissions.authorize_login_url('?'.join(variant))

    def test_ascii_decimal_only_without_percent_or_http_query_decoding(self):
        for key in ('PlayerId', 'DSRoomId', 'MapId'):
            for value in ('', '-1', '+123', ' 123', '123 ', '1.0', '0x7b',
                          '1e2', '１２３', '١٢٣', '%31%32%33', '123&UID=123'):
                with self.subTest(key=key, kind=value[:5]), self.assertRaises(MatchAdmissionDenied):
                    self.admissions.authorize_login_url(login_url(self.ticket, **{key: value}))
        url = login_url(self.ticket).replace('?', '&', 3).replace('&', '?', 1)
        with self.assertRaises(MatchAdmissionDenied):
            self.admissions.authorize_login_url(url)
        self.assertIs(self.admissions.authorize_login_url(
            login_url(self.ticket, PlayerId='000123', DSRoomId='000456', MapId='002201')),
            self.ticket)

    def test_unsigned_boundaries_and_optional_hero(self):
        ticket = self.admissions.issue((1 << 64) - 1, (1 << 64) - 1,
                                       (1 << 32) - 1, (1 << 32) - 1)
        self.assertIsNone(ticket.selected_hero_id)
        self.assertIs(self.admissions.authorize_login_url(login_url(ticket)), ticket)
        for key, value in [('PlayerId', 1 << 64), ('DSRoomId', 1 << 64), ('MapId', 1 << 32)]:
            with self.subTest(key=key), self.assertRaises(MatchAdmissionDenied):
                self.admissions.authorize_login_url(login_url(ticket, **{key: value}))
        huge_decimal = '9' * 3000
        with self.assertRaises(MatchAdmissionDenied):
            self.admissions.authorize_login_url(login_url(self.ticket, PlayerId=huge_decimal))

    def test_selected_hero_uses_actual_uint64_id(self):
        admissions = LocalMatchAdmissions(clock=self.clock)
        ticket = admissions.issue(123, 456, 2201, 142201103, 88000000025)
        self.assertEqual(ticket.selected_hero_id, 88000000025)
        self.assertIs(admissions.authorize_login_url(login_url(ticket)), ticket)
        maximum = admissions.issue(123, 456, 2201, 142201103, (1 << 64) - 1)
        self.assertEqual(maximum.selected_hero_id, (1 << 64) - 1)
        for value in (True, False, 1 << 64):
            with self.subTest(kind=type(value).__name__), self.assertRaises(ValueError):
                admissions.issue(123, 456, 2201, 142201103, value)

    def test_issue_fields_reject_non_int_negative_or_out_of_range(self):
        good = [1, 2, 3, 4, 5]
        for index, bits in enumerate((64, 64, 32, 32, 64)):
            for value in (True, False, 1.0, '1', None, -1, 1 << bits):
                if index == 4 and value is None:
                    continue
                fields = good.copy()
                fields[index] = value
                with self.subTest(index=index, kind=type(value).__name__), self.assertRaises(ValueError):
                    self.admissions.issue(*fields)
        self.assertEqual(self.admissions.summary()['issued_ticket_count'], 1)

    def test_limits_expire_and_reclaim_capacity_without_destroying_valid_tickets(self):
        second = self.admissions.issue(2, 3, 4, 5)
        with self.assertRaises(MatchAdmissionCapacityReached):
            self.admissions.issue(3, 4, 5, 6)
        self.assertIs(self.admissions.authorize_login_url(login_url(second)), second)
        self.clock.now = 15
        third = self.admissions.issue(3, 4, 5, 6)
        self.assertEqual(third.issued_at, 15)
        self.assertEqual(self.admissions.summary()['expired_ticket_count'], 2)
        self.assertEqual(self.admissions.summary()['active_ticket_count'], 1)
        with self.assertRaises(MatchAdmissionDenied):
            self.admissions.authorize_login_url(login_url(self.ticket))

    def test_denied_attempts_do_not_refresh_expiry_or_consume_ticket(self):
        self.clock.now = 14
        for _ in range(5):
            with self.assertRaises(MatchAdmissionDenied):
                self.admissions.authorize_login_url(login_url(self.ticket, MapId=9))
        self.assertIs(self.admissions.authorize_login_url(login_url(self.ticket)), self.ticket)
        self.clock.now = 15
        with self.assertRaises(MatchAdmissionDenied):
            self.admissions.authorize_login_url(login_url(self.ticket))

    def test_url_resource_limits_and_control_characters_fail_closed(self):
        url = login_url(self.ticket)
        bad = [None, b'not-a-string', '', url + '?', url + '??Other=1',
               url + '?Other=' + 'x' * MAX_LOGIN_URL_CHARS,
               url + '?Other=1' * MAX_LOGIN_OPTIONS, url + '?Other=\0',
               url + '?Other=\n', url + '?Other=\x7f']
        for value in bad:
            with self.subTest(kind=type(value).__name__), self.assertRaises(MatchAdmissionDenied):
                self.admissions.authorize_login_url(value)

    def test_summary_and_rejection_diagnostics_do_not_expose_cookie_or_url(self):
        url = login_url(self.ticket)
        self.admissions.authorize_login_url(url)
        bad = login_url(self.ticket, MapId=9)
        with self.assertRaises(MatchAdmissionDenied) as caught:
            self.admissions.authorize_login_url(bad)
        self.assertNotIn(self.ticket.cookie, repr(caught.exception))
        self.assertNotIn(bad, str(caught.exception))
        summary = self.admissions.summary()
        self.assertTrue(all(type(value) is int for value in summary.values()))
        self.assertNotIn(self.ticket.cookie, json.dumps(summary))
        self.assertEqual(summary['authorized_login_count'], 1)
        self.assertEqual(summary['denied_login_count'], 1)

    def test_constructor_and_clock_fail_closed(self):
        for params in [{'ttl': True}, {'ttl': 0}, {'ttl': float('nan')},
                       {'ttl': float('inf')}, {'max_tickets': True}, {'max_tickets': 0},
                       {'max_tickets': 4097}, {'clock': None}]:
            with self.subTest(params=list(params)), self.assertRaises(ValueError):
                LocalMatchAdmissions(**params)
        self.clock.now = 9
        with self.assertRaises(ValueError):
            self.admissions.authorize_login_url(login_url(self.ticket))
        self.clock.now = float('nan')
        with self.assertRaises(ValueError):
            self.admissions.issue(1, 2, 3, 4)
        self.clock.now = 10
        self.assertIs(self.admissions.authorize_login_url(login_url(self.ticket)), self.ticket)

    def test_generator_collision_is_bounded_and_never_overwrites_ticket(self):
        with patch('dfserver.legacy_ds_match_admission.secrets.token_hex',
                   return_value=self.ticket.cookie) as generate:
            with self.assertRaises(RuntimeError):
                self.admissions.issue(1, 2, 3, 4)
            self.assertEqual(generate.call_count, 8)
            generate.assert_called_with(16)
        self.assertIs(self.admissions.authorize_login_url(login_url(self.ticket)), self.ticket)
        self.assertEqual(self.admissions.summary()['active_ticket_count'], 1)

    def test_concurrent_issue_keeps_capacity_bound(self):
        admissions = LocalMatchAdmissions(ttl=5, max_tickets=3, clock=Clock())

        def issue(index):
            try:
                return admissions.issue(index, 2, 3, 4)
            except MatchAdmissionCapacityReached:
                return None

        with ThreadPoolExecutor(max_workers=8) as pool:
            tickets = [ticket for ticket in pool.map(issue, range(16)) if ticket is not None]
        self.assertEqual(len(tickets), 3)
        self.assertEqual(len({ticket.cookie for ticket in tickets}), 3)
        self.assertEqual(admissions.summary()['capacity_rejection_count'], 13)


if __name__ == '__main__':
    unittest.main()
