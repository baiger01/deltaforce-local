"""Candidate CSPkg envelope from paired generated-codec field metadata.

Uses standard protobuf scalar encodings for the observed i32/u32/u64/str helper
categories. These encodings and the placement inside GCP 0x4013 still require
original-client verification. This adapter does not activate the game gateway.
"""
from dataclasses import dataclass, field
from functools import lru_cache

MAX_ENVELOPE_BYTES = 2 * 1024 * 1024


@lru_cache(maxsize=1)
def _message_type():
    from google.protobuf import descriptor_pb2, descriptor_pool, message_factory
    file = descriptor_pb2.FileDescriptorProto(name='local_candidate_cs_pkg.proto', package='pb', syntax='proto2')
    head = file.message_type.add(name='CSPkgHead')
    for name, number, category in (
        ('plat_id', 2, 5), ('client_sequence_id', 3, 5), ('mod_route_id', 4, 4),
        ('dst_zone_id', 5, 13), ('result', 6, 5), ('name', 7, 9),
        ('service', 8, 9), ('language', 9, 9),
    ):
        head.field.add(name=name, number=number, type=category, label=1)
    package = file.message_type.add(name='CSPkg')
    package.field.add(name='head', number=1, type=11, type_name='.pb.CSPkgHead', label=1)
    package.field.add(name='body', number=2, type=12, label=1)
    pool = descriptor_pool.DescriptorPool()
    pool.Add(file)
    return message_factory.GetMessageClass(pool.FindMessageTypeByName('pb.CSPkg'))


@dataclass(frozen=True)
class BusinessEnvelope:
    """Explicit fields only; header unknowns are rejected rather than discarded."""
    body: bytes = field(repr=False)
    header: dict = field(default_factory=dict, repr=False)

    def encode(self):
        if not isinstance(self.body, bytes) or len(self.body) > MAX_ENVELOPE_BYTES:
            raise ValueError('Invalid bounded business payload')
        if not isinstance(self.header, dict):
            raise ValueError('Expected explicit envelope header fields')
        message = _message_type()()
        for name, value in self.header.items():
            descriptor = message.head.DESCRIPTOR.fields_by_name.get(name)
            if descriptor is None:
                raise ValueError('Unimplemented business header field')
            if descriptor.type == 9:
                if not isinstance(value, str):
                    raise ValueError('Expected header text')
            elif type(value) is not int:
                raise ValueError('Expected exact header integer')
            try:
                setattr(message.head, name, value)
            except (TypeError, ValueError, OverflowError) as exc:
                raise ValueError('Invalid header value') from exc
        if self.header:
            message.head.SetInParent()
        message.body = self.body
        encoded = message.SerializeToString(deterministic=True)
        if len(encoded) > MAX_ENVELOPE_BYTES:
            raise ValueError('Envelope exceeds its size limit')
        return encoded


def parse_business_envelope(plaintext):
    from google.protobuf.message import DecodeError
    if not isinstance(plaintext, bytes) or len(plaintext) > MAX_ENVELOPE_BYTES:
        raise ValueError('Expected bounded immutable envelope bytes')
    message = _message_type()()
    try:
        message.ParseFromString(plaintext)
    except DecodeError as exc:
        raise ValueError('Malformed candidate protobuf envelope') from exc
    known_only = _message_type()()
    known_only.CopyFrom(message)
    known_only.DiscardUnknownFields()
    if message.SerializeToString(deterministic=True) != known_only.SerializeToString(deterministic=True):
        raise ValueError('Unimplemented envelope fields')
    header = {}
    for descriptor, value in message.head.ListFields():
        # Some protobuf proto2 runtimes expose invalid UTF-8 strings as bytes.
        if descriptor.type == 9 and not isinstance(value, str):
            raise ValueError('Malformed envelope header text')
        header[descriptor.name] = value
    return BusinessEnvelope(bytes(message.body), header)
