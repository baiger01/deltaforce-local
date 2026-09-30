"""Check the staged source snapshot without printing any matched secret values."""

import json
from pathlib import PurePosixPath
import re
import subprocess


ALLOWED_BINARY = {
    'outputs/df-local-server/protocol/candidate_business.pb',
    'outputs/df-local-server/protocol/recovered_telemetry.pb',
}
FORBIDDEN_PARTS = {
    '.venv', '__pycache__', 'data', 'evidence', 'native-test-account',
    'native-client-tests', 'native-provider-tests', 'elevated-native-trials',
    'sdk-local-provider-stage',
}
FORBIDDEN_SUFFIXES = {
    '.dll', '.exe', '.bin', '.pak', '.uasset', '.uexp', '.ubulk', '.db',
    '.sqlite3', '.sqlite', '.log', '.jsonl', '.dfcode', '.etl', '.pcap',
    '.pcapng', '.zip', '.7z', '.pem', '.key', '.pyc',
}
SECRET_PATTERNS = (
    ('GitHub credential', re.compile(rb'(?:gh[pousr]_[A-Za-z0-9]{30,}|github_pat_[A-Za-z0-9_]{60,})')),
    ('private key', re.compile(rb'-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----')),
    ('AWS access key', re.compile(rb'(?:AKIA|ASIA)[A-Z0-9]{16}')),
)


def git(*args):
    return subprocess.check_output(['git', *args])


def main():
    paths = [value.decode('utf-8') for value in git('ls-files', '-z').split(b'\0') if value]
    problems, total = [], 0
    for name in paths:
        path = PurePosixPath(name)
        if (FORBIDDEN_PARTS.intersection(path.parts)
                or path.suffix.lower() in FORBIDDEN_SUFFIXES
                or path.name == '.env' or path.name.startswith('.env.')
                or path.name.startswith('client-observation')
                or path.name == 'validation.json'):
            problems.append((name, 'local artifact is tracked'))
            continue
        data = git('show', ':' + name)
        total += len(data)
        if len(data) > 95 * 1024 * 1024:
            problems.append((name, 'file exceeds source snapshot size limit'))
        if name in ALLOWED_BINARY:
            continue
        if b'\0' in data:
            problems.append((name, 'unexpected binary content'))
            continue
        try:
            data.decode('utf-8')
            if path.suffix == '.json':
                json.loads(data)
        except (UnicodeError, ValueError):
            problems.append((name, 'invalid UTF-8 text or JSON'))
        for label, pattern in SECRET_PATTERNS:
            match = pattern.search(data)
            if match:
                line = data.count(b'\n', 0, match.start()) + 1
                problems.append((f'{name}:{line}', label))
    print(f'Indexed files: {len(paths)}; content bytes: {total}')
    for name, reason in problems:
        print(f'{name}: {reason}')
    print('Upload audit: ' + ('FAIL' if problems else 'PASS'))
    return 1 if problems else 0


if __name__ == '__main__':
    raise SystemExit(main())
