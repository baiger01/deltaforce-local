"""Fixed method-name metadata only; immutable PE, no process or launch APIs."""
import hashlib
import json
import mmap
import struct
from pathlib import Path

from offline_received_packet_xrefs import CLIENT, ROOT, SOURCE_SHA, ImmutableImage

METHODS = ("OnActorChannelOpen", "OnRep_Pawn", "ClientRestart_Implementation",
           "AcknowledgePossession", "ReceivedPlayer", "ReceiveNetGUIDBunch")


def text_at(image, address):
    if not image.image_base < address < image.image_base + 0x30000000:
        return None
    try:
        raw = image.read(address - image.image_base, 1024)
        if len(raw) > 2 and raw[1] == 0:
            end = next(i for i in range(0, len(raw), 2) if raw[i:i+2] == b"\0\0")
            return raw[:end].decode("utf-16le")
        return raw.split(b"\0", 1)[0].decode("ascii")
    except (ValueError, UnicodeDecodeError):
        return None


def file_rva(image, offset):
    for base, raw_size, raw_offset, _ in image.sections:
        if raw_offset <= offset < raw_offset + raw_size:
            return base + offset - raw_offset
    raise ValueError("Name outside file-backed section")


def main():
    with CLIENT.open("rb") as stream:
        if hashlib.file_digest(stream, "sha256").hexdigest() != SOURCE_SHA:
            raise ValueError("Immutable executable SHA differs")
        with mmap.mmap(stream.fileno(), 0, access=mmap.ACCESS_READ) as mapped:
            image = ImmutableImage(mapped)
            results = []
            for name in METHODS:
                matches = []
                for encoding in ("ascii", "utf-16le"):
                    needle = (name + "\0").encode(encoding)
                    offset = -1
                    while True:
                        offset = mapped.find(needle, offset + 1)
                        if offset < 0:
                            break
                        rva = file_rva(image, offset)
                        pointer = struct.pack("<Q", image.image_base + rva)
                        ref = -1
                        while True:
                            ref = mapped.find(pointer, ref + 1)
                            if ref < 0:
                                break
                            if ref % 8:
                                continue
                            words = struct.unpack_from("<6Q", mapped, ref)
                            if not 0 < words[5] <= 8:
                                continue
                            return_type = text_at(image, words[3])
                            if return_type is None:
                                continue
                            try:
                                args = struct.unpack("<" + "Q" * words[5],
                                    image.read(words[4] - image.image_base, words[5] * 8))
                            except ValueError:
                                continue
                            arg_types = [text_at(image, value) for value in args]
                            if any(value is None for value in arg_types):
                                continue
                            matches.append({"encoding": encoding, "name_rva": hex(rva),
                                "record_rva": hex(file_rva(image, ref)),
                                "words": [hex(value) for value in words],
                                "implementation_rva": hex(words[1] - image.image_base),
                                "invoker_rva": hex(words[2] - image.image_base),
                                "return_type": return_type, "argument_types": arg_types})
                results.append({"method": name, "typed_records": matches})
    result = {"client_sha256": SOURCE_SHA, "policy": {"immutable_file_only": True,
        "process_accessed": False, "game_launched": False}, "methods": results}
    path = ROOT / "work/evidence/native-post-join-typed-method-anchors.json"
    path.write_text(json.dumps(result, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({"path": path.relative_to(ROOT).as_posix(),
        "sha256": hashlib.sha256(path.read_bytes()).hexdigest(), "methods": results}))


if __name__ == "__main__":
    main()
