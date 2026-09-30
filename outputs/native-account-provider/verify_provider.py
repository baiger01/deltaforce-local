"""Integrate our real local account backend, native DLL and vendor ABI readers.

Positive identity comes only from a freshly registered local test account.
No original game or official account is used by this verification.
"""
from pathlib import Path
import argparse
import ctypes
import hashlib
import json
import os
import re
import secrets
import struct
import subprocess
import sys
import threading
import time

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent.parent
PREFIX = "DF_LOCAL_PROVIDER:"
SDK_SHA = "9d39a0f5af96d56f465060a582e21faf5c11d5cfdd4e221891d81c58cd7f1723"


def verify_local_catalog_events(own, vendor, helper, expected, event_id=17006,
                                method_name="CSharp_IRailDlcHelper_AsyncCheckAllDlcsStateReady", slot_index=1,
                                expected_token=None):
    """Exercise copied contexts, listener ABI, reentrancy and queue bounds."""
    for name in ("RailRegisterEvent", "RailUnregisterEvent"):
        getattr(own, name).argtypes = [ctypes.c_uint32, ctypes.c_void_p]
        getattr(own, name).restype = None
    request = getattr(vendor, method_name)
    request.argtypes = [ctypes.c_void_p, ctypes.c_char_p]
    request.restype = ctypes.c_uint32
    for name in ("CSharp_EventBase_rail_id_get", "CSharp_EventBase_game_id_get"):
        getattr(vendor, name).argtypes = [ctypes.c_void_p]
        getattr(vendor, name).restype = ctypes.c_void_p
    for name in ("CSharp_EventBase_result_get", "CSharp_EventBase_get_event_id"):
        getattr(vendor, name).argtypes = [ctypes.c_void_p]
        getattr(vendor, name).restype = ctypes.c_uint32
    vendor.CSharp_EventBase_user_data_get.argtypes = [ctypes.c_void_p]
    vendor.CSharp_EventBase_user_data_get.restype = ctypes.c_char_p
    callback_type = ctypes.WINFUNCTYPE(None, ctypes.c_void_p, ctypes.c_uint32, ctypes.c_void_p)
    class Listener(ctypes.Structure):
        _fields_ = [("vtable", ctypes.POINTER(ctypes.c_void_p))]
    seen, errors, other_seen = [], [], []
    @callback_type
    def secondary(this, event_id, event):
        other_seen.append(event_id)
    other_table = (ctypes.c_void_p * 1)(ctypes.cast(secondary, ctypes.c_void_p).value)
    other = Listener(other_table)
    @callback_type
    def primary(this, event_id, event):
        try:
            assert this == ctypes.addressof(first) and event_id == requested_id
            assert vendor.CSharp_EventBase_get_event_id(event) == requested_id
            assert vendor.CSharp_EventBase_result_get(event) == 0
            assert vendor.CSharp_RailID_get_id(vendor.CSharp_EventBase_rail_id_get(event)) == expected["native_id"]
            assert vendor.CSharp_RailGameID_get_id(vendor.CSharp_EventBase_game_id_get(event)) == 2001918
            if requested_id == 30001:
                info = vendor.CSharp_RailThirdPartyAccountLoginResult_account_info_get(event)
                assert info == event + 64
                assert vendor.CSharp_RailThirdPartyAccountInfo_error_code_get(info) == 0
                assert vendor.CSharp_RailThirdPartyAccountInfo_open_id_get(info) == str(expected["native_id"]).encode()
                assert vendor.CSharp_RailThirdPartyAccountInfo_user_name_get(info) == expected["username"].encode("utf-8")
                assert vendor.CSharp_RailThirdPartyAccountInfo_token_get(info) == expected_token
                assert vendor.CSharp_RailThirdPartyAccountInfo_token_expire_time_get(info) == expected["expires"]
                assert vendor.CSharp_RailThirdPartyAccountInfo_channel_get(info) == b"QQ"
                assert vendor.CSharp_RailThirdPartyAccountInfo_channel_id_get(info) == 10000
                assert vendor.CSharp_RailThirdPartyAccountInfo_real_name_auth_get(info) == 0
            context = vendor.CSharp_EventBase_user_data_get(event)
            seen.append(context)
            if context == b"own-catalog-first":
                own.RailUnregisterEvent(requested_id, ctypes.byref(other))
                assert request(helper, b"own-catalog-next") == 0
                own.RailFireEvents()  # Nested pumping must not recurse.
        except BaseException as error:
            errors.append(repr(error))
    first_table = (ctypes.c_void_p * 1)(ctypes.cast(primary, ctypes.c_void_p).value)
    first = Listener(first_table)
    requested_id = event_id
    own.RailRegisterEvent(event_id, ctypes.byref(first))
    own.RailRegisterEvent(event_id, ctypes.byref(first))
    own.RailRegisterEvent(event_id, ctypes.byref(other))
    own.RailRegisterEvent(event_id + 1, ctypes.byref(other))
    assert request(helper, b"own-catalog-first") == 0
    assert not seen and not other_seen
    own.RailFireEvents()
    assert not errors and seen == [b"own-catalog-first"] and not other_seen, errors
    own.RailFireEvents()
    assert not errors and seen == [b"own-catalog-first", b"own-catalog-next"] and not other_seen, errors
    own.RailUnregisterEvent(event_id, ctypes.byref(first))
    assert request(helper, b"unregistered") == 0
    own.RailFireEvents()
    assert len(seen) == 2 and not other_seen
    for _ in range(32):
        assert request(helper, b"bounded-queue") == 0
    assert request(helper, b"overflow") != 0
    own.RailFireEvents()
    class NativeString(ctypes.Structure):
        _fields_ = [("vtable", ctypes.c_void_p), ("data", ctypes.c_void_p),
                    ("count", ctypes.c_uint64), ("capacity", ctypes.c_uint64)]
    table = ctypes.cast(helper, ctypes.POINTER(ctypes.POINTER(ctypes.c_void_p))).contents
    direct_async = ctypes.WINFUNCTYPE(ctypes.c_uint32, ctypes.c_void_p, ctypes.POINTER(NativeString))(table[slot_index])
    buffer = ctypes.create_string_buffer(b"a\x00b")
    for context in (NativeString(None, None, 1, 1),
                    NativeString(None, ctypes.addressof(buffer), 0, 4),
                    NativeString(None, ctypes.addressof(buffer), 4, 2),
                    NativeString(None, ctypes.addressof(buffer), 4, 4),
                    NativeString(None, ctypes.addressof(buffer), 4098, 4098)):
        assert direct_async(helper, ctypes.byref(context)) != 0
    own.RailRegisterEvent(event_id, ctypes.byref(first))
    # Keep callbacks and objects alive until the stale event is discarded.
    return seen, errors, (first, other, first_table, other_table, primary, secondary)


def bind(module):
    module.RailNeedRestartAppForCheckingEnvironment.argtypes = [ctypes.c_uint64, ctypes.c_int, ctypes.POINTER(ctypes.c_char_p)]
    module.RailNeedRestartAppForCheckingEnvironment.restype = ctypes.c_bool
    for name in ("RailInitialize", "DFLocalRefresh"):
        getattr(module, name).argtypes = []
        getattr(module, name).restype = ctypes.c_bool
    for name in ("RailFinalize", "RailFireEvents"):
        getattr(module, name).argtypes = []
        getattr(module, name).restype = None
    module.RailFactory.argtypes = []
    module.RailFactory.restype = ctypes.c_void_p
    return module


def verify_local_zone_addresses(vendor, helper):
    from verify_event_abi import NativeString
    class Array(ctypes.Structure):
        _fields_ = [("vtable", ctypes.c_void_p), ("data", ctypes.c_void_p),
                    ("count", ctypes.c_uint64), ("capacity", ctypes.c_uint64)]
    zone_id = ctypes.c_uint64(1)
    result = ctypes.c_uint32(0xffffffff)
    vendor.CSharp_IRailZoneServerHelper_OpenZoneServer.argtypes = [ctypes.c_void_p, ctypes.c_void_p, ctypes.POINTER(ctypes.c_uint32)]
    vendor.CSharp_IRailZoneServerHelper_OpenZoneServer.restype = ctypes.c_void_p
    array_getters = {
        "CSharp_IRailZoneServer_GetZoneNameLanguages": b"zh-CN",
        "CSharp_IRailZoneServer_GetZoneDescriptionLanguages": b"zh-CN",
        "CSharp_IRailZoneServer_GetGameServerAddresses": b"127.0.0.1:65010",
    }
    for name in array_getters:
        getattr(vendor, name).argtypes = [ctypes.c_void_p, ctypes.c_void_p]
        getattr(vendor, name).restype = ctypes.c_uint32
    vendor.CSharp_IRailZoneServer_GetZoneID.argtypes = [ctypes.c_void_p]
    vendor.CSharp_IRailZoneServer_GetZoneID.restype = ctypes.c_void_p
    vendor.CSharp_IRailComponent_GetComponentVersion.argtypes = [ctypes.c_void_p]
    vendor.CSharp_IRailComponent_GetComponentVersion.restype = ctypes.c_uint64
    vendor.CSharp_IRailComponent_Release.argtypes = [ctypes.c_void_p]
    vendor.CSharp_IRailComponent_Release.restype = None
    vendor.CSharp_delete_IRailZoneServer.argtypes = [ctypes.c_void_p]
    vendor.CSharp_delete_IRailZoneServer.restype = None
    vendor.CSharp_new_RailArrayRailString__SWIG_0.argtypes = []
    vendor.CSharp_new_RailArrayRailString__SWIG_0.restype = ctypes.c_void_p
    vendor.CSharp_RailArrayRailString_size.argtypes = [ctypes.c_void_p]
    vendor.CSharp_RailArrayRailString_size.restype = ctypes.c_uint32
    vendor.CSharp_RailArrayRailString_Item.argtypes = [ctypes.c_void_p, ctypes.c_uint32]
    vendor.CSharp_RailArrayRailString_Item.restype = ctypes.c_void_p
    vendor.CSharp_delete_RailArrayRailString.argtypes = [ctypes.c_void_p]
    vendor.CSharp_delete_RailArrayRailString.restype = None
    zone = vendor.CSharp_IRailZoneServerHelper_OpenZoneServer(helper, ctypes.byref(zone_id), ctypes.byref(result))
    assert zone and result.value == 0
    array = vendor.CSharp_new_RailArrayRailString__SWIG_0()
    original_vptr = Array.from_address(array).vtable
    try:
        assert vendor.CSharp_IRailComponent_GetComponentVersion(zone) == 1
        copied = vendor.CSharp_IRailZoneServer_GetZoneID(zone)
        try:
            assert vendor.CSharp_RailZoneID_get_id(copied) == 1
        finally:
            vendor.CSharp_delete_RailZoneID(copied)
        for _ in range(2):
            for name, expected_string in array_getters.items():
                assert getattr(vendor, name)(zone, array) == 0
                assert Array.from_address(array).vtable == original_vptr
                assert vendor.CSharp_RailArrayRailString_size(array) == 1
                element = vendor.CSharp_RailArrayRailString_Item(array, 0)
                assert vendor.CSharp_RailSessionTicket_ticket_get(element) == expected_string
                assert NativeString.from_address(element).count == len(expected_string) + 1
    finally:
        vendor.CSharp_delete_RailArrayRailString(array)
        vendor.CSharp_IRailComponent_Release(zone)
    zone = vendor.CSharp_IRailZoneServerHelper_OpenZoneServer(helper, ctypes.byref(zone_id), ctypes.byref(result))
    assert zone and result.value == 0
    vendor.CSharp_delete_IRailZoneServer(zone)
    zone_id.value = 999
    assert not vendor.CSharp_IRailZoneServerHelper_OpenZoneServer(helper, ctypes.byref(zone_id), ctypes.byref(result))
    assert result.value != 0


def verify_local_account_info(vendor, helper, expected, token):
    abi = json.loads((HERE / "local-account-info-abi.json").read_text(encoding="utf-8"))
    STRINGS = {row["field"]: row["field_offset"] for row in abi["fields"]
               if row["field_type"] == "NativeString32"}
    from verify_event_abi import NativeString
    vendor.CSharp_IRailThirdPartyAccountLoginHelper_GetAccountInfo.argtypes = [ctypes.c_void_p, ctypes.c_void_p]
    vendor.CSharp_IRailThirdPartyAccountLoginHelper_GetAccountInfo.restype = ctypes.c_uint32
    vendor.CSharp_new_RailThirdPartyAccountInfo__SWIG_0.argtypes = []
    vendor.CSharp_new_RailThirdPartyAccountInfo__SWIG_0.restype = ctypes.c_void_p
    vendor.CSharp_delete_RailThirdPartyAccountInfo.argtypes = [ctypes.c_void_p]
    vendor.CSharp_delete_RailThirdPartyAccountInfo.restype = None
    for field in (*STRINGS, "error_code", "token_expire_time", "channel_id", "real_name_auth"):
        getter = getattr(vendor, "CSharp_RailThirdPartyAccountInfo_" + field + "_get")
        getter.argtypes = [ctypes.c_void_p]
        getter.restype = ctypes.c_char_p if field in STRINGS else ctypes.c_uint32
    info = vendor.CSharp_new_RailThirdPartyAccountInfo__SWIG_0()
    vptrs = {field:NativeString.from_address(info + offset).vtable for field, offset in STRINGS.items()}
    assert all(vptrs.values())
    wanted = {"error_msg":b"", "open_id":str(expected["native_id"]).encode(), "token":token,
              "channel":b"QQ", "pf":b"df-local", "user_name":expected["username"].encode("utf-8"),
              "pf_key":b"", "picture_url":b"", "ext_str":b"", "register_channel_id":b"10000"}
    try:
        for _ in range(2):
            assert vendor.CSharp_IRailThirdPartyAccountLoginHelper_GetAccountInfo(helper, info) == 0
            for field, value in wanted.items():
                assert getattr(vendor, "CSharp_RailThirdPartyAccountInfo_" + field + "_get")(info) == value
                native = NativeString.from_address(info + STRINGS[field])
                assert native.vtable == vptrs[field] and native.count == len(value) + 1
            assert vendor.CSharp_RailThirdPartyAccountInfo_error_code_get(info) == 0
            assert vendor.CSharp_RailThirdPartyAccountInfo_token_expire_time_get(info) > time.time()
            assert vendor.CSharp_RailThirdPartyAccountInfo_channel_id_get(info) == 10000
            assert vendor.CSharp_RailThirdPartyAccountInfo_real_name_auth_get(info) == 0
    except BaseException:
        vendor.CSharp_delete_RailThirdPartyAccountInfo(info)
        raise
    return info


def host(args):
    with os.add_dll_directory(str(args.stage.resolve())), os.add_dll_directory(str(args.sdk.resolve().parent)):
        own = bind(ctypes.WinDLL(str(args.stage.resolve() / "rail_api64.dll")))
        if args.unsupported:
            own.CSharp_RailInitialize.argtypes = []
            own.CSharp_RailInitialize.restype = ctypes.c_bool
            own.CSharp_RailInitialize()
            raise AssertionError("Unsupported export returned")
        if args.invalid_bootstrap:
            assert own.RailNeedRestartAppForCheckingEnvironment(2001918, 0, None) is True
            assert own.RailInitialize() is False
            assert not own.RailFactory()
            own.RailFinalize()
            print(PREFIX + json.dumps({"invalid_session_does_not_initialize":True}), flush=True)
            return
        expected = json.loads(args.expected.read_text(encoding="utf-8"))
        with args.sdk.open("rb") as stream:
            assert hashlib.file_digest(stream, "sha256").hexdigest() == SDK_SHA
        vendor = ctypes.WinDLL(str(args.sdk.resolve()))
        for name in ("CSharp_IRailFactory_RailPlayer", "CSharp_IRailFactory_RailGame", "CSharp_IRailFactory_RailDlcHelper", "CSharp_IRailFactory_RailSystemHelper", "CSharp_IRailFactory_RailExpansionPack", "CSharp_IRailFactory_RailZoneServerHelper", "CSharp_IRailFactory_RailThirdPartyAccountLoginHelper", "CSharp_IRailZoneServerHelper_GetRootZoneID", "CSharp_IRailZoneServerHelper_GetPlayerSelectedZoneID", "CSharp_IRailPlayer_GetRailID", "CSharp_IRailGame_GetGameID"):
            getattr(vendor, name).argtypes = [ctypes.c_void_p]
            getattr(vendor, name).restype = ctypes.c_void_p
        vendor.CSharp_IRailPlayer_AlreadyLoggedIn.argtypes = [ctypes.c_void_p]
        vendor.CSharp_IRailPlayer_AlreadyLoggedIn.restype = ctypes.c_bool
        vendor.CSharp_IRailPlayer_GetPlayerAccountType.argtypes = [ctypes.c_void_p]
        vendor.CSharp_IRailPlayer_GetPlayerAccountType.restype = ctypes.c_uint32
        vendor.CSharp_IRailDlcHelper_GetDlcCount.argtypes = [ctypes.c_void_p]
        vendor.CSharp_IRailDlcHelper_GetDlcCount.restype = ctypes.c_uint32
        vendor.CSharp_IRailDlcHelper_IsDlcInstalled__SWIG_1.argtypes = [ctypes.c_void_p, ctypes.c_void_p]
        vendor.CSharp_IRailDlcHelper_IsDlcInstalled__SWIG_1.restype = ctypes.c_bool
        vendor.CSharp_IRailExpansionPack_GetExpansionPackCount.argtypes = [ctypes.c_void_p]
        vendor.CSharp_IRailExpansionPack_GetExpansionPackCount.restype = ctypes.c_uint32
        vendor.CSharp_RailID_get_id.argtypes = [ctypes.c_void_p]
        vendor.CSharp_RailID_get_id.restype = ctypes.c_uint64
        vendor.CSharp_RailGameID_get_id.argtypes = [ctypes.c_void_p]
        vendor.CSharp_RailGameID_get_id.restype = ctypes.c_uint64
        vendor.CSharp_RailZoneID_get_id.argtypes = [ctypes.c_void_p]
        vendor.CSharp_RailZoneID_get_id.restype = ctypes.c_uint64
        for name in ("CSharp_delete_RailID", "CSharp_delete_RailGameID", "CSharp_delete_RailSessionTicket", "CSharp_delete_RailZoneID"):
            getattr(vendor, name).argtypes = [ctypes.c_void_p]
            getattr(vendor, name).restype = None
        vendor.CSharp_new_RailSessionTicket.argtypes = []
        vendor.CSharp_new_RailSessionTicket.restype = ctypes.c_void_p
        vendor.CSharp_IRailPlayer_GetPlayerName.argtypes = [ctypes.c_void_p, ctypes.c_void_p]
        vendor.CSharp_IRailPlayer_GetPlayerName.restype = ctypes.c_uint32
        vendor.CSharp_RailSessionTicket_ticket_get.argtypes = [ctypes.c_void_p]
        vendor.CSharp_RailSessionTicket_ticket_get.restype = ctypes.c_char_p

        assert own.RailNeedRestartAppForCheckingEnvironment(2001918, 0, None) is False
        assert own.RailInitialize() is True
        factory = own.RailFactory()
        assert factory
        player = vendor.CSharp_IRailFactory_RailPlayer(factory)
        game = vendor.CSharp_IRailFactory_RailGame(factory)
        dlc = vendor.CSharp_IRailFactory_RailDlcHelper(factory)
        system = vendor.CSharp_IRailFactory_RailSystemHelper(factory)
        assert system
        expansion = vendor.CSharp_IRailFactory_RailExpansionPack(factory)
        assert expansion and vendor.CSharp_IRailExpansionPack_GetExpansionPackCount(expansion) == 0
        zone_helper = vendor.CSharp_IRailFactory_RailZoneServerHelper(factory)
        assert zone_helper
        for name in ("CSharp_IRailZoneServerHelper_GetRootZoneID", "CSharp_IRailZoneServerHelper_GetPlayerSelectedZoneID"):
            zone_id = getattr(vendor, name)(zone_helper)
            try:
                assert vendor.CSharp_RailZoneID_get_id(zone_id) == 1
            finally:
                vendor.CSharp_delete_RailZoneID(zone_id)
        assert dlc and vendor.CSharp_IRailDlcHelper_GetDlcCount(dlc) == 0
        local_dlc_id = ctypes.c_uint64(1)
        assert vendor.CSharp_IRailDlcHelper_IsDlcInstalled__SWIG_1(
            dlc, ctypes.byref(local_dlc_id)) is False
        assert vendor.CSharp_IRailPlayer_AlreadyLoggedIn(player) is True
        assert vendor.CSharp_IRailPlayer_GetPlayerAccountType(player) == 1
        copied = vendor.CSharp_IRailPlayer_GetRailID(player)
        try:
            assert vendor.CSharp_RailID_get_id(copied) == expected["native_id"]
        finally:
            vendor.CSharp_delete_RailID(copied)
        game_id = vendor.CSharp_IRailGame_GetGameID(game)
        try:
            assert vendor.CSharp_RailGameID_get_id(game_id) == 2001918
        finally:
            vendor.CSharp_delete_RailGameID(game_id)
        name_buffer = vendor.CSharp_new_RailSessionTicket()
        try:
            assert vendor.CSharp_IRailPlayer_GetPlayerName(player, name_buffer) == 0
            assert vendor.CSharp_RailSessionTicket_ticket_get(name_buffer).decode("utf-8") == expected["username"]
        finally:
            vendor.CSharp_delete_RailSessionTicket(name_buffer)
        vendor.CSharp_IRailSystemHelper_GetDistributeID.argtypes = [ctypes.c_void_p, ctypes.c_void_p]
        vendor.CSharp_IRailSystemHelper_GetDistributeID.restype = ctypes.c_uint32
        channel_buffer = vendor.CSharp_new_RailSessionTicket()
        try:
            assert vendor.CSharp_IRailSystemHelper_GetDistributeID(system, channel_buffer) == 0
            assert vendor.CSharp_RailSessionTicket_ticket_get(channel_buffer) == b"df-local"
        finally:
            vendor.CSharp_delete_RailSessionTicket(channel_buffer)
        event_seen, event_errors, event_keepalive = verify_local_catalog_events(own, vendor, dlc, expected)
        expansion_seen, expansion_errors, expansion_keepalive = verify_local_catalog_events(own, vendor, expansion,
            expected, 32001, "CSharp_IRailExpansionPack_AsyncQueryExpansionPackList", 0)
        verify_local_zone_addresses(vendor, zone_helper)
        account_helper = vendor.CSharp_IRailFactory_RailThirdPartyAccountLoginHelper(factory)
        assert account_helper
        local_token = (args.stage / "df_local_identity_bootstrap.bin").read_bytes()[12:]
        account_info = verify_local_account_info(vendor, account_helper, expected, local_token)
        vendor.CSharp_RailThirdPartyAccountLoginResult_account_info_get.argtypes = [ctypes.c_void_p]
        vendor.CSharp_RailThirdPartyAccountLoginResult_account_info_get.restype = ctypes.c_void_p
        login_seen, login_errors, login_keepalive = verify_local_catalog_events(own, vendor, account_helper,
            expected, 30001, "CSharp_IRailThirdPartyAccountLoginHelper_AsyncAutoLogin", 0, local_token)
        vendor.CSharp_IRailThirdPartyAccountLoginHelper_GetChannelID.argtypes = [ctypes.c_void_p, ctypes.c_void_p]
        vendor.CSharp_IRailThirdPartyAccountLoginHelper_GetChannelID.restype = ctypes.c_uint32
        channel = vendor.CSharp_new_RailSessionTicket()
        try:
            assert vendor.CSharp_IRailThirdPartyAccountLoginHelper_GetChannelID(account_helper, channel) == 0
            assert vendor.CSharp_RailSessionTicket_ticket_get(channel) == b"QQ"
        finally:
            vendor.CSharp_delete_RailSessionTicket(channel)
        assert vendor.CSharp_IRailDlcHelper_AsyncCheckAllDlcsStateReady(dlc, b"revoked-before-pump") == 0
        assert vendor.CSharp_IRailExpansionPack_AsyncQueryExpansionPackList(expansion, b"revoked-before-pump") == 0
        assert vendor.CSharp_IRailThirdPartyAccountLoginHelper_AsyncAutoLogin(account_helper, b"revoked-before-pump") == 0
        print(PREFIX + json.dumps({"phase":"authorized"}), flush=True)
        assert sys.stdin.readline().strip() == ("identity-changed" if args.identity_change else "revoked")
        assert own.DFLocalRefresh() is False
        try:
            assert vendor.CSharp_IRailThirdPartyAccountLoginHelper_GetAccountInfo(account_helper, account_info) != 0
            assert vendor.CSharp_RailThirdPartyAccountInfo_error_code_get(account_info) != 0
            assert vendor.CSharp_RailThirdPartyAccountInfo_token_get(account_info) == b""
            assert vendor.CSharp_RailThirdPartyAccountInfo_open_id_get(account_info) == b""
            assert vendor.CSharp_RailThirdPartyAccountInfo_user_name_get(account_info) == b""
            assert vendor.CSharp_RailThirdPartyAccountInfo_token_expire_time_get(account_info) == 0
        finally:
            vendor.CSharp_delete_RailThirdPartyAccountInfo(account_info)
        own.RailFireEvents()
        assert len(event_seen) == 2 and not event_errors
        assert len(expansion_seen) == 2 and not expansion_errors
        assert len(login_seen) == 2 and not login_errors
        assert vendor.CSharp_IRailDlcHelper_AsyncCheckAllDlcsStateReady(dlc, b"unauthorized") != 0
        assert vendor.CSharp_IRailExpansionPack_AsyncQueryExpansionPackList(expansion, b"unauthorized") != 0
        assert vendor.CSharp_IRailThirdPartyAccountLoginHelper_AsyncAutoLogin(account_helper, b"unauthorized") != 0
        assert vendor.CSharp_IRailPlayer_AlreadyLoggedIn(player) is False
        assert vendor.CSharp_IRailPlayer_GetPlayerAccountType(player) == 0
        selected_id = vendor.CSharp_IRailZoneServerHelper_GetPlayerSelectedZoneID(zone_helper)
        try:
            assert vendor.CSharp_RailZoneID_get_id(selected_id) == 0
        finally:
            vendor.CSharp_delete_RailZoneID(selected_id)
        copied = vendor.CSharp_IRailPlayer_GetRailID(player)
        try:
            assert vendor.CSharp_RailID_get_id(copied) == 0
        finally:
            vendor.CSharp_delete_RailID(copied)
        own.RailFinalize()
        assert not own.RailFactory()
        print(PREFIX + json.dumps({"phase":"complete", "local_account_consumed_by_native_provider":True,
            "native_id_and_utf8_name_verified_by_vendor_wrappers":True,
            "native_string_allocator_and_vendor_deallocator_verified":True,
            "native_account_type_legacy_qq_selector_read_by_vendor_wrapper":True,
            "local_authenticated_account_type":1,
            "legacy_client_channel_label":"QQ",
            "legacy_client_derived_channel_value":2,
            "official_qq_identity_or_ticket_supplied":False,
            "local_optional_catalog_empty_count_verified":True,
            "local_dlc_installation_absent_verified":True, "vendor_dlc_ownership_asserted":False,
            "local_expansion_catalog_empty_count_verified":True,
            "local_expansion_list_callback_verified_by_vendor_readers":True,
            "local_zone_ids_verified_by_vendor_wrappers":True,
            "local_zone_address_array_read_and_freed_by_vendor_sdk":True,
            "local_zone_language_arrays_read_and_freed_by_vendor_sdk":True,
            "local_account_info_fields_read_and_freed_by_vendor_sdk":True,
            "local_account_info_revocation_clears_returned_credentials":True,
            "local_account_login_callback_verified_by_vendor_readers":True,
            "local_account_login_callback_reentrancy_and_revocation_verified":True,
            "vendor_third_party_account_asserted":False,
            "local_zone_release_and_virtual_delete_verified":True,
            "unknown_local_zone_rejected":True,
            "local_distribution_id_verified_by_vendor_wrappers":True,
            "local_catalog_callback_verified_by_vendor_readers":True,
            "local_catalog_events_deferred_until_pump":True,
            "local_catalog_callback_context_copy_verified":True,
            "event_listener_dedup_unregister_and_reentrancy_verified":True,
            "event_queue_capacity_and_revocation_verified":True,
            "invalid_native_event_context_rejected":True,
            "revoked_session_clears_player_identity":not args.identity_change,
            "unexpected_identity_change_clears_state":args.identity_change, "worker_shutdown_verified":True,
            "vendor_sdk_initialized":False, "original_game_tested":False,
            "native_event_delivery_complete":False, "original_lobby_compatible":False}), flush=True)


def main(args):
    if args.host:
        host(args)
        return
    stage = args.stage.resolve()
    assert stage.name == "sdk-local-provider-stage"
    sys.path.insert(0, str(ROOT / "outputs/df-local-server"))
    from dfserver.core import Backend
    from dfserver.http_api import create_server
    from dfserver.protobuf_codec import ProtobufCodec
    test_root = ROOT / "work/native-provider-tests" / str(time.time_ns())
    test_root.mkdir(parents=True)
    definitions = ROOT / "outputs/df-local-server/definitions.json"
    class IdentityFixtureBackend(Backend):
        change_identity_for_test = False
        def native_identity(self, token):
            answer = super().native_identity(token)
            if self.change_identity_for_test:
                # Deliberately inconsistent authenticated response from our
                # isolated fixture; production account IDs never change.
                number = answer["native_id"]
                answer["native_id"] = number + 1 if number < (1 << 63) - 1 else number - 1
            return answer
    backend = IdentityFixtureBackend(test_root / "save.sqlite3", definitions)
    password = secrets.token_urlsafe(24)
    registered = backend.register("原生本地玩家", password)
    expected = backend.native_identity(registered["session"])
    expected_file = test_root / "expected.json"
    expected_file.write_text(json.dumps(expected, ensure_ascii=False), encoding="utf-8")
    server = create_server(backend, ProtobufCodec(ROOT / "outputs/df-local-server/protocol/recovered_telemetry.pb"), port=0)
    thread = threading.Thread(target=server.serve_forever, kwargs={"poll_interval":.01}, daemon=True)
    thread.start()
    bootstrap = stage / "df_local_identity_bootstrap.bin"
    assert not bootstrap.exists()
    log = test_root / "events.jsonl"
    env = os.environ.copy()
    env["DF_SDK_OBSERVER_LOG"] = str(log)
    command = [sys.executable, str(Path(__file__).resolve()), "--host", "--stage", str(stage), "--sdk", str(args.sdk.resolve())]
    child = None
    try:
        token = registered["session"].encode("ascii")
        bootstrap.write_bytes(struct.pack("<4sHHHH", b"DFLC", 1, server.server_port, len(token), 0) + token)
        child = subprocess.Popen(command + ["--expected", str(expected_file)], env=env, stdin=subprocess.PIPE,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, encoding="utf-8", errors="replace",
            creationflags=subprocess.CREATE_NO_WINDOW)
        ready = child.stdout.readline()
        if not ready.startswith(PREFIX):
            _, stderr = child.communicate(timeout=5)
            raise AssertionError({"ready": ready, "exit": child.returncode, "stderr": (stderr or "")[-3000:]})
        assert json.loads(ready[len(PREFIX):])["phase"] == "authorized"
        backend.logout(registered["session"])
        stdout, stderr = child.communicate("revoked\n", timeout=30)
        assert child.returncode == 0, {"exit":child.returncode,"stderr":stderr[-1500:]}
        result_lines = [json.loads(line[len(PREFIX):]) for line in stdout.splitlines() if line.startswith(PREFIX)]
        assert len(result_lines) == 1 and result_lines[0]["phase"] == "complete"
        result = result_lines[0]
        second = backend.login("原生本地玩家", password)
        # A new local session has its own expiry; retain the stable account ID.
        second_expected = backend.native_identity(second["session"])
        assert second_expected["native_id"] == expected["native_id"]
        expected_file.write_text(json.dumps(second_expected, ensure_ascii=False), encoding="utf-8")
        second_token = second["session"].encode("ascii")
        bootstrap.write_bytes(struct.pack("<4sHHHH", b"DFLC", 1, server.server_port, len(second_token), 0) + second_token)
        child = subprocess.Popen(command + ["--expected", str(expected_file), "--identity-change"], env=env,
            stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            text=True, encoding="utf-8", creationflags=subprocess.CREATE_NO_WINDOW)
        ready = child.stdout.readline()
        assert ready.startswith(PREFIX) and json.loads(ready[len(PREFIX):])["phase"] == "authorized"
        backend.change_identity_for_test = True
        stdout, stderr = child.communicate("identity-changed\n", timeout=30)
        assert child.returncode == 0, {"exit":child.returncode,"stderr":stderr[-1500:]}
        changed = [json.loads(line[len(PREFIX):]) for line in stdout.splitlines() if line.startswith(PREFIX)]
        assert len(changed) == 1 and changed[0]["unexpected_identity_change_clears_state"]
        backend.change_identity_for_test = False
        backend.logout(second["session"])
        result["unexpected_identity_change_clears_state"] = True
        invalid = b"invalid-session"
        bootstrap.write_bytes(struct.pack("<4sHHHH", b"DFLC", 1, server.server_port, len(invalid), 0) + invalid)
        done = subprocess.run(command + ["--invalid-bootstrap"], env=env, capture_output=True, text=True, timeout=30,
            creationflags=subprocess.CREATE_NO_WINDOW)
        assert done.returncode == 0 and PREFIX in done.stdout
        unsupported = subprocess.run(command + ["--unsupported"], env=env, capture_output=True, text=True, timeout=30,
            creationflags=subprocess.CREATE_NO_WINDOW)
        assert unsupported.returncode == 120 and PREFIX not in unsupported.stdout
        events = [json.loads(line) for line in log.read_text(encoding="utf-8").splitlines()]
        assert any(e["event"] == "local_dlc_installation_absent" and e["result"] is False for e in events)
        assert any(e["event"] == "unsupported_export_CSharp_RailInitialize" for e in events)
        assert all(session not in log.read_text(encoding="utf-8") for session in (registered["session"], second["session"]))
        locations = [e for e in events if e["event"].startswith("sdk_trace_")]
        assert locations and all(re.fullmatch(
            r"sdk_trace_(account_type_caller|login_callback|login_listener_vtable)_(unresolved|(shipping|base)_rva_[0-9]{1,10})",
            e["event"]) for e in locations)
        # Python fixture callbacks and SDK wrapper callers belong to neither
        # allowlisted client module, so their addresses must not be recorded.
        assert all(e["event"].endswith("_unresolved") and e["result"] is False for e in locations)
        assert not list(test_root.glob("*.dfcode"))
        result.update({"invalid_session_does_not_initialize":True, "unsupported_export_stops_with_named_diagnostic":True,
            "callback_location_logging_omits_non_client_addresses":True,
            "logs_contain_no_session_token":True, "game_directory_modified":False,
            "provider_sha256":hashlib.sha256((stage / "rail_api64.dll").read_bytes()).hexdigest(),
            "provider_source_sha256":hashlib.sha256((HERE / "provider.c").read_bytes()).hexdigest()})
        (HERE / "validation.json").write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
        print(json.dumps(result, indent=2))
    finally:
        if child and child.poll() is None:
            child.terminate()
            child.wait(timeout=5)
        bootstrap.unlink(missing_ok=True)
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--stage", type=Path, required=True)
    parser.add_argument("--sdk", type=Path, required=True)
    parser.add_argument("--host", action="store_true")
    parser.add_argument("--expected", type=Path)
    parser.add_argument("--unsupported", action="store_true")
    parser.add_argument("--invalid-bootstrap", action="store_true")
    parser.add_argument("--identity-change", action="store_true")
    main(parser.parse_args())
