"""Verify fixed-version event fields using our objects and vendor readers.

This checks memory layout, not ticket issuance or a real client callback.
The fixture contains an empty ticket and an opaque non-success result.
"""
from pathlib import Path
import argparse
import bisect
import ctypes
import hashlib
import json
import os
import struct
import capstone
import pefile

HERE = Path(__file__).resolve().parent
SDK_SHA = "9d39a0f5af96d56f465060a582e21faf5c11d5cfdd4e221891d81c58cd7f1723"

class NativeString(ctypes.Structure):
    _fields_ = [("vtable",ctypes.c_void_p), ("data",ctypes.c_void_p),
                ("count",ctypes.c_uint64), ("capacity",ctypes.c_uint64)]

class EventBase(ctypes.Structure):
    _fields_ = [("vtable",ctypes.c_void_p), ("rail_id",ctypes.c_uint64),
                ("game_id",ctypes.c_uint64), ("user_data",NativeString),
                ("result",ctypes.c_uint32), ("padding",ctypes.c_uint32)]

class Response(ctypes.Structure):
    _fields_ = [("base",EventBase), ("ticket",NativeString),
                ("expires",ctypes.c_uint32), ("padding",ctypes.c_uint32)]

def main(sdk):
    raw = sdk.read_bytes()
    assert hashlib.sha256(raw).hexdigest() == SDK_SHA
    pe = pefile.PE(data=raw,fast_load=True)
    pe.parse_data_directories(directories=[0])
    exports = {e.name.decode("ascii"):e.address for e in pe.DIRECTORY_ENTRY_EXPORT.symbols if e.name}
    addresses = sorted(set(exports.values()))
    decoder = capstone.Cs(capstone.CS_ARCH_X86,capstone.CS_MODE_64)
    checks = {
        "CSharp_EventBase_rail_id_get":("lea","rax, [rcx + 8]",8),
        "CSharp_EventBase_game_id_get":("lea","rax, [rcx + 0x10]",16),
        "CSharp_EventBase_user_data_get":("mov","rax, qword ptr [rcx + 0x20]",32),
        "CSharp_EventBase_result_get":("mov","eax, dword ptr [rcx + 0x38]",56),
        "CSharp_EventBase_get_event_id":("jmp","qword ptr [rax + 8]",1),
        "CSharp_AcquireSessionTicketResponse_session_ticket_get":("lea","rax, [rcx + 0x40]",64),
        "CSharp_AcquireSessionTicketResponse_ticket_expire_time_get":("mov","eax, dword ptr [rcx + 0x60]",96),
        "CSharp_RailSessionTicket_ticket_get":("mov","rax, qword ptr [rcx + 8]",8),
        "CSharp_RailEventkRailEventSessionTicketGetSessionTicket_kInternalRailEventEventId_get":("mov","eax, 0x32c9",13001),
        "CSharp_RailEventkRailEventDlcCheckAllDlcsStateReadyResult_kInternalRailEventEventId_get":("mov","eax, 0x426e",17006),
        "CSharp_new_RailCheckAllDlcsStateReadyResult__SWIG_0":("mov","ecx, 0x40",64),
        "CSharp_new_RailEventkRailEventDlcCheckAllDlcsStateReadyResult__SWIG_0":("mov","ecx, 0x40",64),
        "CSharp_RailEventkRailExpansionPackQueryExpansionPackListResult_kInternalRailEventEventId_get":("mov","eax, 0x7d01",32001),
        "CSharp_new_RailQueryExpansionPackListResult__SWIG_0":("mov","ecx, 0x40",64),
        "CSharp_new_RailEventkRailExpansionPackQueryExpansionPackListResult__SWIG_0":("mov","ecx, 0x40",64),
        "CSharp_RailEventkRailThirdPartyAccountLoginResult_kInternalRailEventEventId_get":("mov","eax, 0x7531",30001),
        "CSharp_RailThirdPartyAccountLoginResult_account_info_get":("lea","rax, [rcx + 0x40]",64),
        "CSharp_new_RailThirdPartyAccountLoginResult__SWIG_0":("mov","ecx, 0x198",408),
    }
    proven = {}
    for name,(mnemonic,operands,value) in checks.items():
        start = exports[name]
        end = addresses[bisect.bisect_right(addresses,start)]
        instructions = list(decoder.disasm(pe.get_data(start,min(end-start,4096)),start))
        hits = [ins.address for ins in instructions if (ins.mnemonic,ins.op_str) == (mnemonic,operands)]
        assert len(hits) == 1,name
        proven[name] = {"export_rva":start,"evidence_rva":hits[0],"value":value}
    assert ctypes.sizeof(EventBase) == 64 and ctypes.sizeof(Response) == 104
    assert EventBase.rail_id.offset == 8 and EventBase.game_id.offset == 16
    assert EventBase.user_data.offset == 24 and EventBase.result.offset == 56
    assert Response.ticket.offset == 64 and Response.expires.offset == 96
    # Pin the native listener ABI independently of our callback fixture.
    # The CSharp bridge listener's first vtable entry is OnRailEvent;
    # it receives (this, event_id, event_data) in RCX, EDX, R8.
    listener_slot_zero = struct.unpack("<Q", pe.get_data(0xd09c68, 8))[0] - pe.OPTIONAL_HEADER.ImageBase
    assert listener_slot_zero == 0x248170
    bridge = {i.address:(i.mnemonic,i.op_str) for i in
              decoder.disasm(pe.get_data(0x248170, 0x90), 0x248170)}
    assert bridge[0x24818c] == ("mov", "r14, r8")
    assert bridge[0x24818f] == ("mov", "ebp, edx")
    assert bridge[0x2481f9] == ("mov", "rdx, r14")
    assert bridge[0x2481fc] == ("mov", "ecx, ebp")
    assert bridge[0x2481fe] == ("call", "rax")
    callbacks = []
    event_id_type = ctypes.WINFUNCTYPE(ctypes.c_uint32,ctypes.c_void_p)
    @event_id_type
    def event_id(self):
        callbacks.append(self)
        return 13001
    vtable = (ctypes.c_void_p * 2)(None,ctypes.cast(event_id,ctypes.c_void_p).value)
    context = ctypes.create_string_buffer(b"own-fixture-only")
    empty_ticket = ctypes.create_string_buffer(b"")
    event = Response()
    event.base.vtable = ctypes.addressof(vtable)
    event.base.rail_id = 0x1234567890123
    event.base.game_id = 2001918
    event.base.user_data = NativeString(None,ctypes.addressof(context),len(context),0)
    event.base.result = 0x7fffffff
    event.ticket = NativeString(None,ctypes.addressof(empty_ticket),1,0)
    event.expires = 123456789
    with os.add_dll_directory(str(sdk.resolve().parent)):
        vendor = ctypes.WinDLL(str(sdk.resolve()))
        pointer_names = ("CSharp_EventBase_rail_id_get","CSharp_EventBase_game_id_get",
                         "CSharp_AcquireSessionTicketResponse_session_ticket_get")
        for name in pointer_names:
            getattr(vendor,name).argtypes = [ctypes.c_void_p]
            getattr(vendor,name).restype = ctypes.c_void_p
        for name in ("CSharp_EventBase_result_get","CSharp_EventBase_get_event_id",
                     "CSharp_AcquireSessionTicketResponse_ticket_expire_time_get"):
            getattr(vendor,name).argtypes = [ctypes.c_void_p]
            getattr(vendor,name).restype = ctypes.c_uint32
        for name in ("CSharp_EventBase_user_data_get","CSharp_RailSessionTicket_ticket_get"):
            getattr(vendor,name).argtypes = [ctypes.c_void_p]
            getattr(vendor,name).restype = ctypes.c_char_p
        pointer = ctypes.addressof(event)
        assert vendor.CSharp_EventBase_rail_id_get(pointer) == pointer + 8
        assert vendor.CSharp_EventBase_game_id_get(pointer) == pointer + 16
        assert vendor.CSharp_EventBase_user_data_get(pointer) == b"own-fixture-only"
        assert vendor.CSharp_EventBase_result_get(pointer) == 0x7fffffff
        assert vendor.CSharp_EventBase_get_event_id(pointer) == 13001
        assert callbacks == [pointer]
        ticket = vendor.CSharp_AcquireSessionTicketResponse_session_ticket_get(pointer)
        assert ticket == pointer + 64
        assert vendor.CSharp_RailSessionTicket_ticket_get(ticket) == b""
        assert vendor.CSharp_AcquireSessionTicketResponse_ticket_expire_time_get(pointer) == 123456789
    report = {"sdk_metadata_sha256":SDK_SHA,"getter_evidence":proven,
              "native_string_bytes":32,"event_base_bytes":64,"response_bytes":104,
              "event_id_virtual_slot":1,"session_ticket_response_event_id":13001,
              "local_catalog_ready_event_id":17006,"local_catalog_ready_event_bytes":64,
              "local_expansion_list_event_id":32001,"local_expansion_list_event_bytes":64,
              "local_account_login_event_id":30001,"local_account_login_event_bytes":408,
              "native_listener_callback_slot":0,
              "native_listener_abi":"void(this RCX, uint32 event_id EDX, borrowed event_data R8)",
              "native_listener_bridge_method_rva":listener_slot_zero,
              "own_fixture_read_by_vendor_getters":True,
              "virtual_event_id_callback_verified":True,
              "valid_session_ticket_issued":False,"sdk_initialized":False,
              "original_client_callback_delivery_verified":False,"game_files_modified":False}
    (HERE / "event-abi-validation.json").write_text(json.dumps(report,indent=2)+"\n",encoding="utf-8")
    print(json.dumps({key:report[key] for key in ("own_fixture_read_by_vendor_getters",
          "virtual_event_id_callback_verified","original_client_callback_delivery_verified")},indent=2))

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--sdk",type=Path,required=True)
    main(parser.parse_args().sdk)
