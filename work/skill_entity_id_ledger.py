"""Allocate local signed int32 skill instance IDs without reusing a reservation."""
from contextlib import closing
from pathlib import Path
import re
import sqlite3

_DIGEST = re.compile(r'[0-9a-f]{64}')
_LIMIT = 0x7fffffff


class SkillEntityIdLedger:
    def __init__(self, path):
        self.path = Path(path).resolve()

    def reserve(self, admission_digest, plan_digest, count):
        if (any(type(value) is not str or not _DIGEST.fullmatch(value)
                for value in (admission_digest, plan_digest))
                or type(count) is not int or not 1 <= count <= 65535):
            raise ValueError('A hashed admission, frozen plan and bounded entity count are required')
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with closing(sqlite3.connect(self.path, timeout=10, isolation_level=None)) as connection:
            connection.execute('BEGIN IMMEDIATE')
            try:
                version = connection.execute('PRAGMA user_version').fetchone()[0]
                tables = {row[0] for row in connection.execute(
                    "SELECT name FROM sqlite_master WHERE type='table'")}
                if version == 0 and not tables:
                    connection.execute('CREATE TABLE skill_entity_counter ('
                        'singleton INTEGER PRIMARY KEY CHECK(singleton=1), '
                        'next_id INTEGER NOT NULL CHECK(next_id BETWEEN 1 AND 2147483648))')
                    connection.execute('INSERT INTO skill_entity_counter VALUES (1,1)')
                    connection.execute('CREATE TABLE skill_entity_reservations ('
                        'admission_digest TEXT PRIMARY KEY, plan_digest TEXT NOT NULL, '
                        'first_id INTEGER NOT NULL CHECK(first_id>0), '
                        'entity_count INTEGER NOT NULL CHECK(entity_count BETWEEN 1 AND 65535), '
                        'CHECK(first_id+entity_count<=2147483648))')
                    connection.execute('PRAGMA user_version=1')
                elif version != 1 or tables != {'skill_entity_counter', 'skill_entity_reservations'}:
                    raise ValueError('The persistent skill ID ledger schema is incompatible')
                counters = connection.execute('SELECT singleton,next_id FROM skill_entity_counter').fetchall()
                high = connection.execute('SELECT max(first_id+entity_count) '
                    'FROM skill_entity_reservations').fetchone()[0]
                if (len(counters) != 1 or counters[0][0] != 1
                        or type(counters[0][1]) is not int or not 1 <= counters[0][1] <= _LIMIT+1
                        or high is not None and counters[0][1] < high):
                    raise ValueError('The persistent skill entity counter is inconsistent')
                prior = connection.execute('SELECT plan_digest,first_id,entity_count '
                    'FROM skill_entity_reservations WHERE admission_digest=?',
                    (admission_digest,)).fetchone()
                if prior is not None:
                    if prior[0] != plan_digest or prior[2] != count:
                        raise ValueError('This admission already has a different frozen skill plan')
                    first = prior[1]
                else:
                    first = counters[0][1]
                    if first+count > _LIMIT+1:
                        raise ValueError('The signed int32 skill entity ID range is exhausted')
                    connection.execute('INSERT INTO skill_entity_reservations VALUES (?,?,?,?)',
                        (admission_digest, plan_digest, first, count))
                    connection.execute('UPDATE skill_entity_counter SET next_id=? WHERE singleton=1',
                        (first+count,))
                connection.commit()
                return first
            except BaseException:
                connection.rollback()
                raise
