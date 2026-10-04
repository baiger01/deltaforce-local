"""Bounded local match tickets, independent of platform or packet authentication.

Login URLs use Unreal's '?' separated FURL options, not HTTP query parsing.
Only an issued Cookie plus its bound PlayerId, DSRoomId and MapId authorizes
this local admission. Other options remain the caller's data and confer no
identity or permission. This module performs no network or gameplay work.
"""
from dataclasses import dataclass
import math
import re
import secrets
import threading
import time


MAX_LOGIN_URL_CHARS = 4096
MAX_LOGIN_OPTIONS = 64
_COOKIE = re.compile(r'[0-9a-f]{32}', re.ASCII)
_DECIMAL = re.compile(r'[0-9]+', re.ASCII)
_REQUIRED = frozenset(('cookie', 'playerid', 'dsroomid', 'mapid'))


class MatchAdmissionDenied(ValueError):
    """The submitted URL does not authorize a stored local match ticket."""


class MatchAdmissionCapacityReached(ValueError):
    """All bounded local match ticket slots are occupied."""


def _unsigned(value, bits):
    if type(value) is not int or not 0 <= value < 1 << bits:
        raise ValueError('Invalid unsigned local match field')
    return value


def _decimal(value, bits):
    if not _DECIMAL.fullmatch(value):
        raise ValueError('Invalid decimal local match option')
    # Permit decimal leading zeroes without constructing arbitrarily large ints.
    significant = value.lstrip('0') or '0'
    if len(significant) > (20 if bits == 64 else 10):
        raise ValueError('Local match option exceeds its unsigned range')
    return _unsigned(int(significant, 10), bits)


def _login_options(url):
    if (type(url) is not str or not 1 <= len(url) <= MAX_LOGIN_URL_CHARS or
            any(ord(char) < 32 or ord(char) == 127 for char in url)):
        raise ValueError('Invalid bounded local login URL')
    segments = url.split('?')
    if not 1 <= len(segments) - 1 <= MAX_LOGIN_OPTIONS:
        raise ValueError('Invalid local login option count')
    options = {}
    for option in segments[1:]:
        if not option:
            raise ValueError('Empty local login option')
        key, separator, value = option.partition('=')
        key = key.casefold()
        if key not in _REQUIRED:
            continue  # Includes UID, Response0 and ModularWeapon; never identities.
        if not separator or key in options:
            raise ValueError('Missing or duplicate local login option')
        options[key] = value
    if set(options) != _REQUIRED or not _COOKIE.fullmatch(options['cookie']):
        raise ValueError('Missing local login authorization')
    return (options['cookie'], _decimal(options['playerid'], 64),
            _decimal(options['dsroomid'], 64), _decimal(options['mapid'], 32))


@dataclass(frozen=True, slots=True, repr=False)
class LocalMatchTicket:
    player_id: int
    room_id: int
    map_id: int
    match_mode_id: int
    selected_hero_id: int | None
    cookie: str
    issued_at: float
    expires_at: float

    def __repr__(self):
        return 'LocalMatchTicket(<redacted>)'


class LocalMatchAdmissions:
    """Issue immutable tickets with a fixed lifetime and a bounded slot count.

    A successful retransmission returns the same ticket and does not refresh
    its expiry. Binding the ticket to a transport peer is the caller's job.
    """

    def __init__(self, *, ttl=120, max_tickets=256, clock=time.monotonic):
        if (type(ttl) not in (int, float) or not math.isfinite(ttl) or ttl <= 0 or
                type(max_tickets) is not int or not 1 <= max_tickets <= 4096 or
                not callable(clock)):
            raise ValueError('Invalid local match admission limits')
        self._ttl = float(ttl)
        self._max_tickets = max_tickets
        self._clock = clock
        self._last_now = None
        self._tickets = {}
        self._lock = threading.Lock()
        self._issued = self._authorized = self._denied = 0
        self._expired = self._capacity_rejections = 0

    def _now(self):
        value = self._clock()
        if (type(value) not in (int, float) or not math.isfinite(value) or
                (self._last_now is not None and value < self._last_now)):
            raise ValueError('Invalid monotonic local match clock')
        now = float(value)
        self._last_now = now
        return now

    def _expire(self, now):
        expired = [cookie for cookie, ticket in self._tickets.items()
                   if now >= ticket.expires_at]
        for cookie in expired:
            del self._tickets[cookie]
        self._expired += len(expired)

    def issue(self, player_id, room_id, map_id, match_mode_id, selected_hero_id=None):
        _unsigned(player_id, 64)
        _unsigned(room_id, 64)
        _unsigned(map_id, 32)
        _unsigned(match_mode_id, 32)
        if selected_hero_id is not None:
            _unsigned(selected_hero_id, 64)
        with self._lock:
            now = self._now()
            self._expire(now)
            if len(self._tickets) >= self._max_tickets:
                self._capacity_rejections += 1
                raise MatchAdmissionCapacityReached('Local match ticket capacity reached')
            expires_at = now + self._ttl
            if not math.isfinite(expires_at) or expires_at <= now:
                raise ValueError('Invalid local match expiry')
            for _ in range(8):
                cookie = secrets.token_hex(16)
                if type(cookie) is not str or not _COOKIE.fullmatch(cookie):
                    raise RuntimeError('Invalid local match ticket generator')
                if cookie not in self._tickets:
                    break
            else:
                raise RuntimeError('Unable to issue a unique local match ticket')
            ticket = LocalMatchTicket(player_id, room_id, map_id, match_mode_id,
                                      selected_hero_id, cookie, now, expires_at)
            self._tickets[cookie] = ticket
            self._issued += 1
            return ticket

    def is_active(self, ticket):
        """Check an issued server-side ticket by identity without refreshing it."""
        if type(ticket) is not LocalMatchTicket:
            return False
        with self._lock:
            self._expire(self._now())
            return self._tickets.get(ticket.cookie) is ticket

    def authorize_login_url(self, url):
        with self._lock:
            now = self._now()
            self._expire(now)
            try:
                cookie, player_id, room_id, map_id = _login_options(url)
                ticket = self._tickets.get(cookie)
                if (ticket is None or ticket.player_id != player_id or
                        ticket.room_id != room_id or ticket.map_id != map_id):
                    raise ValueError('Local match binding mismatch')
            except ValueError:
                self._denied += 1
                # Never echo a URL, Cookie, identity, or parser input in diagnostics.
                raise MatchAdmissionDenied('Local match authorization rejected') from None
            self._authorized += 1
            return ticket

    def summary(self):
        with self._lock:
            self._expire(self._now())
            return {'active_ticket_count': len(self._tickets),
                    'issued_ticket_count': self._issued,
                    'authorized_login_count': self._authorized,
                    'denied_login_count': self._denied,
                    'expired_ticket_count': self._expired,
                    'capacity_rejection_count': self._capacity_rejections}
