"""Preserve the original inventory consumer's cached extension counters.

InventoryServer_Network.ProcessPbDataChange (0.40) applies nonnegative counters
and preserves negatives. Protocol defaults are zero, so an unrelated change
must explicitly use -1. Keep this local lobby policy outside the generic codec.
"""

from dfserver.gateway.candidate_business import CandidateBusinessCodec


COUNTERS = ('cur_extension_num', 'max_extension_num', 'upperlimit_extension_num')


def _preserve(descriptor, fields):
    if not isinstance(fields, dict):
        return fields
    result = dict(fields)
    if descriptor.full_name == 'pb.DataChange':
        for name in COUNTERS:
            result.setdefault(name, -1)
    for name, value in fields.items():
        field = descriptor.fields_by_name.get(name)
        if field is not None and field.message_type is not None:
            result[name] = ([_preserve(field.message_type, item) for item in value]
                            if field.label == field.LABEL_REPEATED and isinstance(value, list)
                            else _preserve(field.message_type, value))
    return result


class WarehouseBusinessCodec(CandidateBusinessCodec):
    def encode(self, name, fields, *, sequence):
        self._service(name)
        if name.endswith(('Res', 'Ntf')):
            descriptor = self.codec.pool.FindMessageTypeByName('pb.' + name)
            fields = _preserve(descriptor, fields)
        return super().encode(name, fields, sequence=sequence)
