"""Compile paired codec metadata into explicitly candidate protobuf schemas.

Field numbers and references come from static client metadata. Scalar helper
categories are interpreted as standard protobuf types, and absent scalar
defaults use proto2 defaults. Neither assumption establishes game compatibility.
"""
import re

from .protobuf_codec import ProtobufCodec
from .core import DomainError

IDENTIFIER = re.compile(r'[A-Za-z_][A-Za-z_0-9]*\Z')
SCALAR_TYPES = {'double': 1, 'float': 2, 'i64': 3, 'u64': 4, 'i32': 5,
                'bool': 8, 'str': 9, 'buffer': 12, 'u32': 13}
STORAGE_TYPES = {'i32': {'Int8', 'Int16', 'Int32'}, 'u32': {'Int8', 'Int16', 'Int32'},
                 'i64': {'Integer'}, 'u64': {'Integer'}, 'float': {'Float'},
                 'double': {'Number'}, 'bool': {'Boolean'}, 'str': {'String'},
                 'buffer': {'String'}}
EMPTY_ONLY_TYPE = 'BattlePassPackInfo_BoughtPacksEntry'
EMPTY_ONLY_TYPES = frozenset({EMPTY_ONLY_TYPE, 'RollingNotice'})


def _empty_rolling_notice(message):
    """Allow only this installed asymmetric codec's empty parent references."""
    if message.get('name') != 'RollingNotice':
        return False
    fields = message.get('fields')
    if not isinstance(fields, list):
        return False
    signature = [(field.get('name'), field.get('number'), field.get('codec_category'),
                  field.get('repeated'), field.get('nested_type')) for field in fields]
    unpaired = message.get('unpaired_encode_calls')
    return (message.get('name') == 'RollingNotice' and message.get('source') == '@cs_chat_editor_pb.lua'
        and message.get('source_sha256') == '6cd943f0f562dce18d037198ba9c1ecdd3f61a032e5c85ae5b9f75e2e56296d3'
        and message.get('encode_function_id') == '0.81' and message.get('decode_function_id') == '0.80'
        and message.get('encode_field_calls') == 5 and message.get('decode_field_calls') == 4
        and message.get('unresolved_fields') == []
        and signature == [('begin_timestamp', 1, 'u64', False, None),
                          ('end_timestamp', 2, 'u64', False, None),
                          ('content', 3, 'str', False, None), ('is_multiline', 4, 'bool', False, None)]
        and all(field.get('encode_helper') == 'add' + field['codec_category']
                and field.get('decode_helper') == 'get' + field['codec_category']
                for field in message['fields'])
        and isinstance(unpaired, list) and len(unpaired) == 1
        and unpaired[0].get('name') == 'game_mode' and unpaired[0].get('number') == 5
        and unpaired[0].get('helper') == 'addu32' and unpaired[0].get('nested_candidates') == [])


def validate_class_metadata(recovery, class_metadata):
    """Cross-check Lua storage declarations; do not infer protobuf signedness."""
    if not isinstance(class_metadata, dict) or not isinstance(class_metadata.get('messages'), list):
        raise ValueError('Expected class declaration metadata')
    if len(class_metadata['messages']) > 10000:
        raise ValueError('Class declaration count exceeds its bound')
    declarations = {}
    for message in class_metadata['messages']:
        name, fields = message.get('name'), message.get('dynamic_fields')
        if (not isinstance(name, str) or not IDENTIFIER.fullmatch(name) or name in declarations
                or not isinstance(fields, list) or len(fields) > 10000):
            raise ValueError('Invalid class declaration')
        by_name = {}
        for field in fields:
            field_name, storage = field.get('name'), field.get('declared_type')
            if (not isinstance(field_name, str) or not IDENTIFIER.fullmatch(field_name)
                    or field_name in by_name or not isinstance(storage, str)):
                raise ValueError('Invalid class field declaration')
            by_name[field_name] = storage
        declarations[name] = by_name
    count = 0
    for message in recovery['messages']:
        fields = declarations.get(message['name'], {})
        for field in message.get('fields', []):
            category = field['codec_category']
            expected = {'Table'} if field['repeated'] or category == 'submsg' else STORAGE_TYPES.get(category, set())
            if fields.get(field['name']) not in expected:
                raise ValueError('Class declaration does not corroborate an observed codec field')
            count += 1
    return {'observed_codec_fields_corroborated': count,
            'class_declaration_count': len(declarations),
            'wire_signedness_or_encoding_verified': False,
            'dynamic_userdata_defaults_or_presence_verified': False}


def compile_candidate_descriptors(recovery, *, class_metadata=None):
    """Compile observed fields, preserving precisely restricted empty-only types."""
    from google.protobuf import descriptor_pb2, descriptor_pool
    if not isinstance(recovery, dict) or not isinstance(recovery.get('messages'), list):
        raise ValueError('Expected generated codec field metadata')
    if len(recovery['messages']) > 10000:
        raise ValueError('Candidate message count exceeds its bound')
    messages, excluded, dependencies = {}, {}, {}
    for message in recovery['messages']:
        name = message.get('name')
        if not isinstance(name, str) or not IDENTIFIER.fullmatch(name) or name in messages or name in excluded:
            raise ValueError('Invalid or duplicate candidate message name')
        if message.get('all_observed_field_calls_matched') is not True and not _empty_rolling_notice(message):
            excluded[name] = 'Generated encode/decode field calls did not all match'
            continue
        fields = message.get('fields')
        if not isinstance(fields, list) or len(fields) > 10000:
            raise ValueError('Invalid candidate field list')
        field_names, field_numbers, required = set(), set(), set()
        for field in fields:
            field_name, number = field.get('name'), field.get('number')
            category, nested = field.get('codec_category'), field.get('nested_type')
            if (not isinstance(field_name, str) or not IDENTIFIER.fullmatch(field_name)
                    or field_name in field_names or type(number) is not int
                    or not 0 < number < 1 << 29 or 19000 <= number <= 19999
                    or number in field_numbers or type(field.get('repeated')) is not bool):
                raise ValueError('Invalid or duplicate candidate field definition')
            if category == 'submsg':
                if not isinstance(nested, str) or not IDENTIFIER.fullmatch(nested):
                    excluded[name] = 'Unresolved nested message reference'
                    break
                required.add(nested)
            elif category not in SCALAR_TYPES:
                excluded[name] = 'Unimplemented scalar helper category'
                break
            elif nested is not None:
                raise ValueError('Scalar field cannot reference a nested message')
            field_names.add(field_name)
            field_numbers.add(number)
        if name not in excluded:
            messages[name], dependencies[name] = message, required

    # The installed cs_battlepass_editor_pb.lua 0.10/0.11 observes this
    # repeated field-7 submessage but does not define its entry's fields.
    # Preserve the reference without inventing key/value types. The candidate
    # codec below rejects every populated occurrence of this opaque entry.
    opaque = []
    pack = messages.get('BattlePassPackInfo', {})
    if EMPTY_ONLY_TYPE not in messages and EMPTY_ONLY_TYPE not in excluded and any(
            f['name'] == 'bought_packs' and f['number'] == 7
            and f['codec_category'] == 'submsg' and f['repeated']
            and f['nested_type'] == EMPTY_ONLY_TYPE for f in pack.get('fields', [])):
        messages[EMPTY_ONLY_TYPE] = {'fields': []}
        dependencies[EMPTY_ONLY_TYPE] = set()
        opaque.append(EMPTY_ONLY_TYPE)

    # Iterate to a fixed point. This also removes parents of partially recovered
    # dependencies, while retaining cycles whose members are all fully known.
    while True:
        removed = [name for name in messages if dependencies[name] - messages.keys()]
        if not removed:
            break
        for name in removed:
            missing = sorted(dependencies[name] - messages.keys())
            excluded[name] = 'Unavailable nested type(s): ' + ', '.join(missing)
            del messages[name]

    descriptor_set = descriptor_pb2.FileDescriptorSet()
    file = descriptor_set.file.add(name='local_candidate_business.proto', package='pb', syntax='proto2')
    for name, original in sorted(messages.items()):
        message = file.message_type.add(name=name)
        for field in sorted(original['fields'], key=lambda value: value['number']):
            category = field['codec_category']
            value = message.field.add(name=field['name'], number=field['number'],
                                      label=3 if field['repeated'] else 1,
                                      type=11 if category == 'submsg' else SCALAR_TYPES[category])
            if category == 'submsg':
                value.type_name = '.pb.' + field['nested_type']
            # Per-field add calls emit individual scalar values. Protobuf also
            # accepts packed inputs for repeated numeric fields when decoding.
            if field['repeated'] and category not in ('submsg', 'str', 'buffer'):
                value.options.packed = False
    pool = descriptor_pool.DescriptorPool()
    pool.AddSerializedFile(file.SerializeToString(deterministic=True))
    report = {'descriptor_kind': 'independently compiled candidate schema',
              'original_client_wire_compatibility_verified': False,
              'scalar_category_encodings_verified_against_original_client': False,
              'explicit_defaults_or_required_presence_recovered': False,
              'messages_compiled': len(messages),
              'fields_compiled': sum(len(m['fields']) for m in messages.values()),
              'excluded_messages': excluded,
              'opaque_empty_only_types': opaque,
              'empty_only_types': sorted(EMPTY_ONLY_TYPES.intersection(messages)),
              'asymmetric_empty_only_sources': {'RollingNotice':
                  'cs_chat_editor_pb.lua 0.80/0.81; game_mode field 5 is encode-only'},
              'opaque_reference_source': 'cs_battlepass_editor_pb.lua 0.10/0.11; field 7 bought_packs',
              'descriptor_pool_validation': 'passed',
              'assumptions': ['Observed i32/u32/i64/u64/float/double helpers use standard protobuf scalar encodings.',
                              'Fields use optional or repeated labels and standard proto2 defaults.',
                              'This descriptor does not authorize accounts or activate a game gateway.']}
    if class_metadata is not None:
        report['class_declaration_crosscheck'] = validate_class_metadata(recovery, class_metadata)
    return descriptor_set.SerializeToString(deterministic=True), report


class CandidateProtobufCodec(ProtobufCodec):
    """Explicit opt-in codec; separate from the default recovered descriptor set."""
    @staticmethod
    def validate_empty_only(message):
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
                children = value if field.label == field.LABEL_REPEATED else [value]
                if field.message_type.name in EMPTY_ONLY_TYPES and children:
                    raise ValueError('Unrecovered empty-only nested message occurrence')
                pending.extend(children)

    def encode(self, name, fields):
        from google.protobuf import json_format
        message = self._class(name)()
        try:
            json_format.ParseDict(fields, message, ignore_unknown_fields=False)
            self.validate_empty_only(message)
            return message.SerializeToString()
        except Exception as exc:
            raise DomainError('INVALID_PROTOBUF_FIELDS',
                'Response fields do not match the recovered candidate descriptor') from exc

    def decode(self, name, payload):
        from google.protobuf import json_format
        message = self._class(name)()
        try:
            message.ParseFromString(payload)
            if not message.IsInitialized():
                raise ValueError('Required fields are missing')
            self.validate_empty_only(message)
        except Exception as exc:
            raise DomainError('INVALID_PROTOBUF',
                'Payload cannot be decoded with the recovered candidate schema') from exc
        return json_format.MessageToDict(message, preserving_proto_field_name=True)

    def status(self):
        result = super().status()
        result.update({'schema_kind': 'candidate_from_generated_codec_metadata',
                       'schema_selection': 'explicit candidate business descriptor set',
                       'original_client_wire_compatibility_verified': False,
                       'business_gateway_ready': False,
                       'missing': ['original-client scalar/presence verification',
                                   'transport compression and business envelope placement verification',
                                   'local account flow, client connection configuration and DH modulus']})
        return result
