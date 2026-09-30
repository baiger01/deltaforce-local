"""Decode only recovered descriptor-backed messages. Unknown schemas fail explicitly."""
from pathlib import Path

from .core import DomainError


class ProtobufCodec:
    def __init__(self, descriptor_path):
        self.pool = None
        self.names = []
        try:
            from google.protobuf import descriptor_pb2, descriptor_pool
        except ImportError:
            self.problem = "Optional protobuf runtime is unavailable"
            return
        descriptor_path = Path(descriptor_path)
        if not descriptor_path.is_file():
            self.problem = "Recovered descriptor set is unavailable"
            return
        descriptor_set = descriptor_pb2.FileDescriptorSet()
        descriptor_set.ParseFromString(descriptor_path.read_bytes())
        pool = descriptor_pool.DescriptorPool()
        pending = list(descriptor_set.file)
        while pending:
            previous = len(pending)
            for descriptor in pending[:]:
                try:
                    pool.AddSerializedFile(descriptor.SerializeToString())
                except Exception:
                    continue
                pending.remove(descriptor)
                def collect(messages, prefix):
                    for message in messages:
                        self.names.append(prefix+message.name)
                        collect(message.nested_type,prefix+message.name+".")
                collect(descriptor.message_type, descriptor.package+"." if descriptor.package else "")
            if len(pending) == previous:
                raise DomainError("INVALID_DESCRIPTOR_SET", "Descriptors have missing dependencies or invalid definitions")
        self.pool = pool
        self.names.sort()
        self.problem = None

    def _class(self, name):
        if self.pool is None:
            raise DomainError("PROTOBUF_UNAVAILABLE", self.problem)
        from google.protobuf import message_factory
        try:
            descriptor = self.pool.FindMessageTypeByName(name)
        except KeyError:
            raise DomainError("UNKNOWN_MESSAGE_SCHEMA", "A type name was observed but its field schema has not been recovered")
        if hasattr(message_factory,"GetMessageClass"):
            return message_factory.GetMessageClass(descriptor)
        return message_factory.MessageFactory(self.pool).GetPrototype(descriptor)

    def decode(self, name, payload):
        message = self._class(name)()
        from google.protobuf import json_format
        try:
            message.ParseFromString(payload)
            if not message.IsInitialized():
                raise ValueError("Required fields are missing")
        except Exception as error:
            raise DomainError("INVALID_PROTOBUF", "Payload cannot be decoded with the recovered schema") from error
        return json_format.MessageToDict(message,preserving_proto_field_name=True)

    def encode(self, name, fields):
        message = self._class(name)()
        from google.protobuf import json_format
        try:
            json_format.ParseDict(fields,message,ignore_unknown_fields=False)
            return message.SerializeToString()
        except Exception as error:
            raise DomainError("INVALID_PROTOBUF_FIELDS", "Response fields do not match the recovered descriptor") from error

    def status(self):
        return {"descriptor_backed_types":len(self.names),"problem":self.problem,
                "business_gateway_ready":False,
                "schema_selection":"default recovered descriptor set; candidate business schema requires explicit opt-in",
                "missing":["validated business schemas and bindings","client-configured DH modulus and account flow","original client integration verification"]}
