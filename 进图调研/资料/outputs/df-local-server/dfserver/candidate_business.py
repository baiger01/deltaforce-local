"""Explicit candidate business messages; no game listener or account policy.

Services are read from independently recovered class declarations. Placement
inside GCP and scalar wire semantics still require original-client verification.
"""
from dataclasses import dataclass, field
import json
from pathlib import Path
import re

from .business_envelope import BusinessEnvelope, MAX_ENVELOPE_BYTES, parse_business_envelope
from .candidate_schema import CandidateProtobufCodec
from .core import DomainError

IDENTIFIER = re.compile(r'[A-Za-z_][A-Za-z_0-9]*\Z')


@dataclass(frozen=True)
class CandidateMessage:
    name: str
    service: str
    sequence: int
    fields: dict = field(repr=False)


class CandidateBusinessCodec:
    def __init__(self, descriptor_path, class_metadata_path):
        self.codec = CandidateProtobufCodec(descriptor_path)
        raw = Path(class_metadata_path).read_bytes()
        if len(raw) > 64 * 1024 * 1024:
            raise ValueError('Class metadata exceeds its size limit')
        metadata = json.loads(raw.decode('utf-8'))
        messages = metadata.get('messages')
        if not isinstance(messages, list) or len(messages) > 10000:
            raise ValueError('Invalid bounded class declaration metadata')
        self.services = {}
        seen = set()
        available = set(self.codec.names)
        for message in messages:
            name, service = message.get('name'), message.get('service')
            if not isinstance(name, str) or not IDENTIFIER.fullmatch(name) or name in seen:
                raise ValueError('Invalid or duplicate class declaration name')
            seen.add(name)
            if service is None:
                continue
            if not isinstance(service, str) or not IDENTIFIER.fullmatch(service):
                raise ValueError('Invalid declared service')
            if 'pb.' + name in available:
                self.services[name] = service

    def _service(self, name):
        if not isinstance(name, str) or name not in self.services:
            raise DomainError('UNAVAILABLE_CANDIDATE_MESSAGE', 'No complete candidate schema and service declaration')
        return self.services[name]

    @staticmethod
    def _sequence(sequence):
        if type(sequence) is not int or not -(1 << 31) <= sequence < 1 << 31:
            raise DomainError('INVALID_CANDIDATE_SEQUENCE', 'Expected an explicit int32 request sequence')
        return sequence

    def encode(self, name, fields, *, sequence):
        service = self._service(name)
        self._sequence(sequence)
        body = self.codec.encode('pb.' + name, fields)
        return BusinessEnvelope(body, {'client_sequence_id': sequence, 'name': name, 'service': service}).encode()

    def decode(self, plaintext):
        try:
            envelope = parse_business_envelope(plaintext)
        except ValueError as exc:
            raise DomainError('INVALID_CANDIDATE_ENVELOPE', 'Malformed or unsupported candidate envelope') from exc
        name = envelope.header.get('name')
        service = self._service(name)
        if envelope.header.get('service') != service:
            raise DomainError('CANDIDATE_SERVICE_MISMATCH', 'Envelope service conflicts with the class declaration')
        sequence = self._sequence(envelope.header.get('client_sequence_id'))
        if len(envelope.body) > MAX_ENVELOPE_BYTES:
            raise DomainError('INVALID_CANDIDATE_BODY', 'Candidate body exceeds its size limit')
        message = self.codec._class('pb.' + name)()
        try:
            message.ParseFromString(envelope.body)
            known = type(message)()
            known.CopyFrom(message)
            known.DiscardUnknownFields()
            if message.SerializeToString(deterministic=True) != known.SerializeToString(deterministic=True):
                raise ValueError('Unimplemented payload fields')
            from google.protobuf import json_format
            fields = json_format.MessageToDict(message, preserving_proto_field_name=True)
        except Exception as exc:
            raise DomainError('INVALID_CANDIDATE_BODY', 'Malformed payload or fields outside the candidate schema') from exc
        return CandidateMessage(name, service, sequence, fields)

    def response(self, request, fields):
        """Construct only the declared Req/Res pair; caller supplies every result."""
        if not isinstance(request, CandidateMessage) or not request.name.endswith('Req'):
            raise DomainError('UNAVAILABLE_CANDIDATE_RESPONSE', 'Expected a decoded candidate request')
        service = self._service(request.name)
        name = request.name[:-3] + 'Res'
        if request.service != service or self._service(name) != service:
            raise DomainError('CANDIDATE_SERVICE_MISMATCH', 'Request and response service declarations differ')
        return self.encode(name, fields, sequence=request.sequence)

    def status(self):
        result = self.codec.status()
        result.update({'declared_service_message_count': len(self.services),
                       'request_response_sequence_policy': 'candidate: echo explicit client_sequence_id',
                       'original_client_request_correlation_verified': False,
                       'account_authorization_implemented': False})
        return result
