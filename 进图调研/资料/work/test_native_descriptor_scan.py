"""Check descriptor boundaries and false-positive rejection before using findings."""
import importlib.util
import unittest
from pathlib import Path
from google.protobuf import descriptor_pb2

ROOT = Path(__file__).resolve().parent.parent
SPEC = importlib.util.spec_from_file_location("analyze_client", ROOT / "outputs/client-analysis/analyze_client.py")
SCAN = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(SCAN)


def descriptor(name="sample.proto", number=1):
    fd = descriptor_pb2.FileDescriptorProto(name=name, package="example", syntax="proto2")
    message = fd.message_type.add(name="Sample")
    message.field.add(name="count", number=number, label=1, type=13)
    return fd


class ScanTests(unittest.TestCase):
    def test_adjacent_descriptors_do_not_merge(self):
        a, b = descriptor("a.proto"), descriptor("b.proto")
        data = a.SerializeToString() + b.SerializeToString() + b"\0"
        found = list(SCAN.scan_descriptors(data))
        self.assertEqual([f[3].name for f in found], ["a.proto", "b.proto"])
        self.assertEqual(found[0][1], len(a.SerializeToString()))
        self.assertEqual(found[0][2], "repeated_singular_field")

    def test_missing_required_field_metadata_rejected(self):
        fd = descriptor()
        fd.message_type[0].field[0].ClearField("type")
        self.assertEqual(list(SCAN.scan_descriptors(fd.SerializeToString())), [])

    def test_reserved_field_number_rejected(self):
        self.assertEqual(list(SCAN.scan_descriptors(descriptor(number=19000).SerializeToString())), [])

    def test_broken_oneof_reference_rejected(self):
        fd = descriptor()
        fd.message_type[0].field[0].oneof_index = 4
        self.assertEqual(list(SCAN.scan_descriptors(fd.SerializeToString())), [])

    def test_truncated_nested_message_rejected(self):
        data = descriptor().SerializeToString()
        end, _ = SCAN.descriptor_extent(data[:-10], 0)
        self.assertLess(end, len(data))
        self.assertEqual(list(SCAN.scan_descriptors(data[:-10])), [])

    def test_proto_filename_in_log_is_not_descriptor(self):
        self.assertEqual(list(SCAN.scan_descriptors(b"INFO loading sample.proto failed\0")), [])

    def test_uint64_overflow_rejected(self):
        with self.assertRaises(ValueError):
            SCAN.read_varint(b"\x80" * 9 + b"\x02", 0, 10)

    def test_dependency_order_is_resolved(self):
        dependency = descriptor("dependency.proto")
        fd = descriptor("dependent.proto")
        fd.message_type[0].name = "Other"
        fd.dependency.append("dependency.proto")
        field = fd.message_type[0].field[0]
        field.type = 11
        field.type_name = ".example.Sample"
        blobs = {"a": fd.SerializeToString(), "b": dependency.SerializeToString()}
        modules = [{"descriptor_candidates": [{"sha256": "a"}, {"sha256": "b"}]}]
        SCAN.link_candidates(modules, blobs)
        self.assertTrue(all(d["descriptor_pool_linked"] for d in modules[0]["descriptor_candidates"]))

    def test_unresolved_reference_is_not_linked(self):
        fd = descriptor()
        fd.dependency.append("missing.proto")
        modules = [{"descriptor_candidates": [{"sha256": "a"}]}]
        SCAN.link_candidates(modules, {"a": fd.SerializeToString()})
        self.assertFalse(modules[0]["descriptor_candidates"][0]["descriptor_pool_linked"])


if __name__ == "__main__":
    unittest.main()
