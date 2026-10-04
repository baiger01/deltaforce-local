"""Diagnostic-only native protobuf lifetime probe using the installed catalog.

Uses a temporary account database. This does not grant real account data, run
the client, or change codec behavior in the local service.
"""

import argparse
import faulthandler
import gc
import json
from pathlib import Path
import sys
import tempfile
import time
import weakref


PROJECT = Path(__file__).resolve().parent.parent / 'outputs/df-local-server'
sys.path.insert(0, str(PROJECT))


def indexed_validator(message):
    from dfserver.candidate_schema import EMPTY_ONLY_TYPES

    pending = [message]
    while pending:
        current = pending.pop()
        if current.DESCRIPTOR.name in EMPTY_ONLY_TYPES:
            if current.ByteSize():
                raise ValueError('Unrecovered empty-only message content')
            continue
        for field, value in current.ListFields():
            if field.type != field.TYPE_MESSAGE:
                continue
            if field.label == field.LABEL_REPEATED:
                if field.message_type.name in EMPTY_ONLY_TYPES and len(value):
                    raise ValueError('Unrecovered empty-only nested message occurrence')
                for index in range(len(value)):
                    pending.append(value[index])
            else:
                if field.message_type.name in EMPTY_ONLY_TYPES:
                    raise ValueError('Unrecovered empty-only nested message occurrence')
                pending.append(value)


def reachable_classes(codec, name):
    classes, seen, pending = [], set(), [name]
    while pending:
        current = pending.pop()
        if current in seen:
            continue
        seen.add(current)
        cls = codec._class(current)
        classes.append(cls)
        pending.extend(field.message_type.full_name for field in cls.DESCRIPTOR.fields
                       if field.message_type is not None)
    return classes


def emit(**fields):
    print(json.dumps(fields), flush=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--iterations', type=int, default=128)
    parser.add_argument('--collect-every', type=int, default=1)
    parser.add_argument('--retain-classes', action='store_true')
    parser.add_argument('--validator', choices=('original', 'indexed'), default='original')
    args = parser.parse_args()
    if not 1 <= args.iterations <= 4096 or not 0 <= args.collect_every <= 4096:
        parser.error('iterations and collection interval must remain bounded')
    faulthandler.enable()
    faulthandler.dump_traceback_later(115, exit=True)

    from google.protobuf import json_format
    import google.protobuf
    from google.protobuf.internal import api_implementation
    from dfserver.core import Backend
    from dfserver import premium_shop
    from dfserver.handshake_diagnostic import _candidate_codec

    codec = _candidate_codec().codec
    name = 'pb.CSHeroUnlockNtf'
    with tempfile.TemporaryDirectory() as folder:
        backend = Backend(Path(folder) / 'save.sqlite3', PROJECT / 'definitions.json')
        token = backend.register('protobuf-lifetime-diagnostic', 'local-password-123')['session']
        fields = {'heros': premium_shop.hero_records(backend, token)}
    assert len(fields['heros']) == 17
    retained = reachable_classes(codec, name) if args.retain_classes else []
    message_class = codec._class(name)
    fixture = message_class()
    json_format.ParseDict(fields, fixture, ignore_unknown_fields=False)
    payload = fixture.SerializeToString(deterministic=True)
    del fixture, message_class
    gc.collect()

    module = api_implementation._c_module
    emit(event='runtime', executable=sys.executable, protobuf=google.protobuf.__version__,
         implementation=api_implementation.Type(),
         extension=getattr(module, '__file__', None), validator=args.validator,
         retained_classes=len(retained), payload_bytes=len(payload), heroes=len(fields['heros']))
    validator = codec.validate_empty_only if args.validator == 'original' else indexed_validator
    collected_classes = 0
    started = time.monotonic()
    for index in range(args.iterations):
        message_class = codec._class(name)
        class_ref = weakref.ref(message_class)
        message = message_class()
        message.ParseFromString(payload)
        validator(message)
        assert message.SerializeToString(deterministic=True) == payload
        del message, message_class
        if args.collect_every and (index + 1) % args.collect_every == 0:
            gc.collect()
            collected_classes += class_ref() is None
        if index == 0 or (index + 1) % 8 == 0:
            emit(event='progress', iterations=index + 1, collected_classes=collected_classes,
                 elapsed_seconds=round(time.monotonic() - started, 3))
    faulthandler.cancel_dump_traceback_later()
    emit(event='complete', iterations=args.iterations, collected_classes=collected_classes,
         elapsed_seconds=round(time.monotonic() - started, 3))


if __name__ == '__main__':
    main()
