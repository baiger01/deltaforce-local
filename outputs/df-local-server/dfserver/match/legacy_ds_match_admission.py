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
    selected_fashion_id: int | None = None
    room_seed: int | None = None
    loadout_snapshot: bytes | None = None

    def __repr__(self):
        return 'LocalMatchTicket(<redacted>)'


class LocalMatchAdmissions:
    """Issue immutable tickets with a fixed lifetime and a bounded slot count.

    A successful retransmission returns the same ticket and does not refresh
    its expiry. Binding the ticket to a transport peer is the caller's job.
    """

    def __init__(self, *, ttl=120, joined_session_ttl=3600, max_tickets=256, clock=time.monotonic):
        if (type(ttl) not in (int, float) or not math.isfinite(ttl) or ttl <= 0 or
                type(joined_session_ttl) not in (int, float) or not math.isfinite(joined_session_ttl) or
                not 1 <= joined_session_ttl <= 86400 or
                type(max_tickets) is not int or not 1 <= max_tickets <= 4096 or
                not callable(clock)):
            raise ValueError('Invalid local match admission limits')
        self._ttl = float(ttl)
        self._joined_session_ttl = float(joined_session_ttl)
        self._max_tickets = max_tickets
        self._clock = clock
        self._last_now = None
        self._tickets = {}
        self._joined_until = {}
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
                   if now >= self._joined_until.get(cookie, ticket.expires_at)]
        for cookie in expired:
            del self._tickets[cookie]
            self._joined_until.pop(cookie, None)
        self._expired += len(expired)

    def issue(self, player_id, room_id, map_id, match_mode_id, selected_hero_id=None,
              selected_fashion_id=None, *, room_capacity=None, room_seed=None, loadout_snapshot=None):
        _unsigned(player_id, 64)
        _unsigned(room_id, 64)
        _unsigned(map_id, 32)
        _unsigned(match_mode_id, 32)
        if room_seed is not None:
            _unsigned(room_seed, 63)
        if loadout_snapshot is not None and (
                type(loadout_snapshot) is not bytes or not 0 < len(loadout_snapshot) <= 1024*1024):
            raise ValueError('An immutable bounded carried equipment snapshot is required')
        if room_capacity is not None and (type(room_capacity) is not int or not 1 <= room_capacity <= 4096):
            raise ValueError('A bounded explicit local room capacity is required')
        if selected_hero_id is not None:
            _unsigned(selected_hero_id, 64)
        if selected_fashion_id is not None:
            _unsigned(selected_fashion_id, 64)
            if not selected_fashion_id or not selected_hero_id:
                raise ValueError('An equipped suit requires its selected operator')
        with self._lock:
            now = self._now()
            self._expire(now)
            if room_capacity is not None and sum(
                    (t.room_id, t.map_id, t.match_mode_id) == (room_id, map_id, match_mode_id)
                    for t in self._tickets.values()) >= room_capacity:
                self._capacity_rejections += 1
                raise MatchAdmissionCapacityReached('Qualified local room capacity reached')
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
                                      selected_hero_id, cookie, now, expires_at, selected_fashion_id, room_seed,
                                      loadout_snapshot)
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

    def begin_joined_session(self, ticket):
        """Commit an authenticated Join to a bounded independent session lease.

        The controller calls this only after its complete Hello/Login/Welcome/
        Netspeed/Join chain and peer binding are valid. Repeated Join is
        idempotent; it does not extend either admission or session deadlines.
        An expired admission cannot initiate a session or authorize a new Login.
        """
        if type(ticket) is not LocalMatchTicket:
            raise MatchAdmissionDenied('A current admitted local ticket is required')
        with self._lock:
            now = self._now();self._expire(now)
            if self._tickets.get(ticket.cookie) is not ticket:
                raise MatchAdmissionDenied('Local admission is no longer current')
            if ticket.cookie in self._joined_until:
                return
            if now >= ticket.expires_at:
                raise MatchAdmissionDenied('Local admission expired before Join')
            deadline = now + self._joined_session_ttl
            if not math.isfinite(deadline) or deadline <= now:
                raise ValueError('Invalid bounded local session deadline')
            self._joined_until[ticket.cookie] = deadline

    def end_joined_session(self, ticket):
        """End only this exact Join lease; retain an unexpired admission."""
        if type(ticket) is not LocalMatchTicket:
            return
        with self._lock:
            if self._tickets.get(ticket.cookie) is ticket:
                self._joined_until.pop(ticket.cookie, None)
            self._expire(self._now())

    def revoke(self, ticket):
        """Explicitly cancel this exact allocation and release its room slot."""
        if type(ticket) is not LocalMatchTicket:
            return False
        with self._lock:
            self._expire(self._now())
            if self._tickets.get(ticket.cookie) is not ticket:
                return False
            self._joined_until.pop(ticket.cookie, None)
            del self._tickets[ticket.cookie]
            return True

    def has_joined_session(self, ticket):
        """Read the exact owner's committed Join lease without extending it."""
        if type(ticket) is not LocalMatchTicket:
            return False
        with self._lock:
            self._expire(self._now())
            return self._tickets.get(ticket.cookie) is ticket and ticket.cookie in self._joined_until

    def active_room_tickets(self, ticket):
        """Return a bounded owner-side roster for one exact room/map/mode."""
        if type(ticket) is not LocalMatchTicket:
            return ()
        with self._lock:
            self._expire(self._now())
            if self._tickets.get(ticket.cookie) is not ticket:
                return ()
            return tuple(t for t in self._tickets.values()
                         if (t.room_id, t.map_id, t.match_mode_id) ==
                            (ticket.room_id, ticket.map_id, ticket.match_mode_id))

    def active_player_solo_tickets(self, player_id):
        """Include issued tickets whose Actor projection is still in progress."""
        _unsigned(player_id, 64)
        if not player_id:
            raise ValueError('An actual local player is required')
        with self._lock:
            self._expire(self._now())
            return tuple(ticket for ticket in self._tickets.values()
                         if ticket.player_id == player_id and ticket.room_id == player_id)

    def authorize_login_url(self, url):
        with self._lock:
            now = self._now()
            self._expire(now)
            try:
                cookie, player_id, room_id, map_id = _login_options(url)
                ticket = self._tickets.get(cookie)
                if (ticket is None or ticket.player_id != player_id or
                        ticket.room_id != room_id or ticket.map_id != map_id or
                        now >= ticket.expires_at):
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
                    'joined_session_count': len(self._joined_until),
                    'issued_ticket_count': self._issued,
                    'authorized_login_count': self._authorized,
                    'denied_login_count': self._denied,
                    'expired_ticket_count': self._expired,
                    'capacity_rejection_count': self._capacity_rejections}
