"""Read named local-runtime image code from the existing shadow through UAC.

No client launch, function invocation, injection, memory write, heap traversal,
or game-file change. A symbol or code sample is not proof of map playability.
"""

import argparse
import ctypes as C
from ctypes import wintypes as W
from datetime import datetime, timezone
import hashlib
import json
import mmap
import os
from pathlib import Path
import struct
import subprocess
import sys
import time

import capstone
import pefile
import psutil

from capture_official_ds import SOURCE_SHA, digest, save, verified_pids
from read_named_ds_transport_code import (
    Module, Memory, kernel, direct_implementation_span, bounded_image_function_span,
)


ROOT = Path(__file__).resolve().parent.parent
OUTPUT = ROOT / 'work/evidence/local-runtime-code'
CLIENT_PATH = Path('DeltaForce/Binaries/Win64/DeltaForceClient-Win64-Shipping.exe')

# Six-qword registrations verified in the immutable, version-pinned Shipping PE.
# The first five fields are image pointers; the last is an argument descriptor.
REGISTRATIONS = {
    'StartLocalDS.static': ('StartLocalDS', 0x15c23dd0,
                          (0x15c241c0, 0x2f408f0, 0x11eea10, 0x14edf3dc, 0x1cb9c620, 3)),
    'StartLocalDS.instance': ('StartLocalDS', 0x16078f50,
                            (0x15c241c0, 0x5bf4a40, 0x1b61310, 0x14ee4878, 0x1cbdf6e0, 0x100000001)),
    'StartLaunchLocalDS': ('StartLaunchLocalDS', 0x18ba2470,
                         (0x18ba2f98, 0xd45eef0, 0xd4622c0, 0x14edf3dc, 0x1d2ca6a0, 0x100000009)),
    'SpawnDefaultCharacter': ('SpawnDefaultCharacter', 0x182ae500,
                            (0x182bf5f0, 0xc91dcb0, 0xdfe430, 0x14ee4878, 0x1d138e40, 1)),
    'CreateGameModeForURL': ('CreateGameModeForURL', 0x16167b20,
                           (0x16184af0, 0x5b9f8b0, 0x5bdb5d0, 0x16184c78, 0x1cbf2a28, 2)),
    'JoinLocalDS': ('JoinLocalDS', 0x15c23e00,
                   (0x15c241d0, 0x2f40960, 0x11eea10, 0x14edf3dc, 0x1cb9c638, 3)),
    'OnExecStartLocalDS': ('OnExecStartLocalDS', 0x15c24010,
                         (0x15c24298, 0x2f40a80, 0x1166000, 0x14edf3dc, 0x1cb9c6c8, 3)),
    'OnExecJoinLocalDS': ('OnExecJoinLocalDS', 0x15c24040,
                        (0x15c242b0, 0x2f40a90, 0x11eea10, 0x14edf3dc, 0x1cb9c6e0, 3)),
    'InitOfflineController': ('InitOfflineController', 0x182bb3c0,
        (0x182fc580, 0xc93d520, 0xca2ae20, 0x14edf3dc, 0x1d13a988, 7)),
    'InitOfflineCharacter': ('InitOfflineCharacter', 0x182bb3f0,
        (0x182fc888, 0x5b8dd60, 0xdffa30, 0x14edf3dc, 0x1d13a9f0, 2)),
    'SpawnPlayerController': ('SpawnPlayerController', 0x182bb120,
        (0x182f5268, 0x19d9530, 0x5c7cac0, 0x14ee3740, 0x1d13a458, 3)),
    'FindPlayerStart.base_registration': ('FindPlayerStart', 0x1b2d6050,
        (0x182f33d0, 0x1293c560, 0xca0ff00, 0x14ede058, 0x1d77ce98, 3)),
    'SpawnDefaultPawnFor.base_registration': ('SpawnDefaultPawnFor', 0x1b2d6170,
        (0x1b2e7c30, 0x131173b0, 0x5cdc030, 0x15a082a8, 0x1d77d038, 3)),
    'SpawnDefaultPawnAtTransform.base_registration': ('SpawnDefaultPawnAtTransform', 0x1b2d61a0,
        (0x1b2e7c90, 0x13117430, 0x5cdc030, 0x15a082a8, 0x1d77d0b8, 3)),
    'GetDefaultPawnClassForController.base_registration': ('GetDefaultPawnClassForController', 0x1b2d5990,
        (0x1672f6c8, 0x13114300, 0x233a110, 0x14ee3238, 0x1d77c490, 2)),
    'ADFMGameMode.InitGame': ('InitGame', 0x182baca0,
        (0x161f0b48, 0x1168a00, 0x11eef50, 0x14edf3dc, 0x1d139c88, 4)),
    'ADFMGameMode.InitGameState': ('InitGameState', 0x182bacd0,
        (0x161f0da0, 0x1168a30, 0xdfc740, 0x14edf3dc, 0x1d139d08, 1)),
    'ADFMGameMode.Login': ('Login', 0x182babe0,
        (0x15b476f0, 0x5b99200, 0x5c8a2a0, 0x14ee3740, 0x1d139a30, 7)),
    'ADFMGameMode.PostLogin': ('PostLogin', 0x182bac10,
        (0x161ebc10, 0x5b91e30, 0xdfea50, 0x14edf3dc, 0x1d139b00, 2)),
    'ADFMGameMode.InitNewPlayer': ('InitNewPlayer', 0x182bad60,
        (0x161cbf68, 0x5cbe270, 0x5bb1d00, 0x14edf408, 0x1d139de0, 5)),
    'ADFMGameMode.HandleStartingNewPlayer': ('HandleStartingNewPlayer_Implementation', 0x182bb0c0,
        (0x182f4cc8, 0x11688d0, 0xdfea50, 0x14edf3dc, 0x1d13a398, 2)),
}
NAME_CODE_PAIRS = {
    'GetProjectFilePath.1': ('GetProjectFilePath', 0x15a0f6e8, 0x15a0df18, 0x23ebfa0),
    'GetProjectFilePath.2': ('GetProjectFilePath', 0x15a148d0, 0x15a0df18, 0x23f5670),
    'FindPlayerStart.function_metadata_getter': ('FindPlayerStart', 0x1b50d7d8, 0x182f33d0, 0x132ef410),
    'SpawnDefaultPawnFor.native_exec': ('SpawnDefaultPawnFor', 0x1b50f580, 0x1b2e7c30, 0x132fa740),
    'SpawnDefaultPawnAtTransform.native_exec': ('SpawnDefaultPawnAtTransform', 0x1b50f570, 0x1b2e7c90, 0x132fa620),
    'GetDefaultPawnClassForController.native_exec': ('GetDefaultPawnClassForController', 0x1b50f470, 0x1672f6c8, 0x132f5ad0),
}
CLASS_INITIALIZERS = {
    'UGPNetConnection.initializer': ('UGPNetConnection', 0x1ccd2bd8, 0x1622da80,
                                   0x15e75f18, 0x2990, 0x5bf5c30),
    'UGPGameplayStatics.initializer': ('UGPGameplayStatics', 0x1ccd1678, 0x160739d8,
                                      0x16074568, 0x28, 0x5b75ec0),
    'UGPGameInstance.initializer': ('UGPGameInstance', 0x1ccd1300, 0x16164448,
                                  0x15c24140, 0x3d8, 0x5bbe100),
    'UDFMGameInstance.initializer': ('UDFMGameInstance', 0x1cb9c798, 0x15c23c38,
                                   0x15c22178, 0x3e0, 0x2f40850),
    'ADFMGameMode.initializer': ('ADFMGameMode', 0x1d165fa0, 0x182b46f8,
                                0x17929260, 0x860, 0xca48e10),
}
# The named class initializer selects helper slot 5, whose complete 15-byte
# leaf references this descriptor. Method counts and rows are source-pinned.
CLASS_METHOD_TABLES = {
    'UGPGameplayStatics': (0x1607a888,
        (0x160784f0, 0x16078f20, 0x16079ed8, 0x1607a500, 0x2000100150001),
        'StartLocalDS.instance', 1, 0x5de3730, bytes.fromhex('488b0a488d154e712910e921c8ea0a')),
    'UGPGameInstance': (0x16169948,
        (0x161675b8, 0x16167940, 0x161681e0, 0x16168750, 0x1000c001c0002),
        'CreateGameModeForURL', 10, 0x5de36c0, bytes.fromhex('488b0a488d157e623810e991c8ea0a')),
    'UDFMGameInstance': (0x15c24100,
        (0x15c23c40, 0x15c23c50, 0x15c240d0, 0x15c240e8, 0x1000100180001),
        'StartLocalDS.static', 8, 0x2f40b60, bytes.fromhex('488b0a488d159635ce12e9f1f3d40d')),
    'ADFMGameMode': (0x182bd218,
        (0x182b9f98, 0x182baa00, 0x182bbe80, 0x182bc8c0, 0x1001d004b0001),
        'InitOfflineController', 52, 0xcbc1070, bytes.fromhex('488b0a488d159ec16f0be9e1ee0c04')),
}
CALL_WITNESSES = {
    'UGPNetConnection.class_target': ('UGPNetConnection.type_helper.1', 0x5db23f0,
        'cc27c45dc81460218fae0dcaa956d77a5b34388a2b9400b7143044cce3223aa7',
        0x5db23f6, 0x6042030),
    'GetProjectFilePath.target': ('GetProjectFilePath.2', 0x23f5670,
        '872930959d5dd7f0b05e0e89d145571a9bc7ec44541029b76376eae20c40b3ba',
        0x23f5691, 0x23e39d0),
    'StartLocalDS.static.target': ('StartLocalDS.static.callback', 0x2f408f0,
                                 'e176d81e1e548e157cef469f61ac9d60f19b865c0863d96a78b06eaa7627421d',
                                 0x2f40933, 0x2f3e560),
    'StartLocalDS.instance.target': ('StartLocalDS.instance.callback', 0x5bf4a40,
                                   'bf053e7ea7c586fd4fe362cd2d03bdf2770520ad1c481b3c8a2d32252880c907',
                                   0x5bf4a5d, 0x4d92b70),
    'StartLocalDS.static.launch_target': ('StartLocalDS.static.target', 0x2f3e560,
                                        'e21769c6a8beba8ab7492c445b1424f4ef11c2719a1ed6d80a98a8d44392de71',
                                        0x2f3eafc, 0x2f415d0),
    'StartLaunchLocalDS.world_target': ('StartLaunchLocalDS.callback', 0xd421e80,
                                      '6f75c949a16bd74dd2e9b083d9d8e546700dff51036280ce19a574337fa8cdd8',
                                      0xd42205a, 0xd41d1f0),
    'StartLaunchLocalDS.reset_target': ('StartLaunchLocalDS.callback', 0xd421e80,
                                      '6f75c949a16bd74dd2e9b083d9d8e546700dff51036280ce19a574337fa8cdd8',
                                      0xd422030, 0xd420de0),
    'SpawnDefaultCharacter.create_target': ('SpawnDefaultCharacter.callback', 0x9d812d0,
                                          '915403e6dfb198db57bd4838e7a4ae4967e86937fb2d08add444275ace591e52',
                                          0x9d81485, 0x12a99d90),
    'SpawnDefaultCharacter.bind_target': ('SpawnDefaultCharacter.callback', 0x9d812d0,
                                        '915403e6dfb198db57bd4838e7a4ae4967e86937fb2d08add444275ace591e52',
                                        0x9d814d8, 0x1285f1f0),
    'StartLaunchLocalDS.quest_target': ('StartLaunchLocalDS.world_target', 0xd41d1f0,
                                      '0514a9155f9a5dcfb3231b5febd7d255e2bc129e029436e06886d8a7fa5debec',
                                      0xd41d28f, 0x114a0c0),
    'UGPGameInstance.class_target': ('UGPGameInstance.type_helper.1', 0x5dafb60,
        'b285925ae0c2d34abf0ee1390286044f8fcccdb65573d3271cc3d5004c5f0307',
        0x5dafb66, 0x5ff6b30),
    'UDFMGameInstance.class_target': ('UDFMGameInstance.type_helper.1', 0x2f40ab0,
        '492846e95f4c541e4d86d62274da5156c8d2c91f8f3f8a0e6c372a7a118abc63',
        0x2f40ab6, 0x2f41020),
    'JoinLocalDS.target': ('JoinLocalDS.callback', 0x2f40960,
        'd75f42a98cf9b83dc8857a11e5b5fd78bb9735602802a60b04dd9b1a4f720480',
        0x2f409a3, 0x2f3cbb0),
    'ADFMGameMode.class_target': ('ADFMGameMode.type_helper.1', 0xcb3b100,
        'e75e5dc814252f0415f6f01adb1d5008e8d20e9cace7fcb5c585a2d04522caac',
        0xcb3b106, 0xce96eb0),
}
RIP_CODE_WITNESSES = {
    'UGPNetConnection.constructor_code_reference': ('UGPNetConnection.class_target', 0x6042030,
        '408ee3bd138ac98c8143a44b1bf9396d33676f4bc058bf91d011865a5c15a000',
        0x6042095, 0x6040fb0),
    'UDFMGameInstance.native_registration_callback_reference': ('UDFMGameInstance.class_target', 0x2f41020,
        '04501e89109b3dd083ab233c9bb898a598160e242ca6a679d4857ada4b27f5f0',
        0x2f41047, 0x2f417a0, b'\x4c\x8d\x0d'),
    'UGPGameInstance.class_code_reference': ('UGPGameInstance.class_target', 0x5ff6b30,
        'e85484d892d8f21bcceec14787d3f5f53eaab4fd46a65daee95ae27687b32c9d',
        0x5ff6b95, 0x5ff5580),
    'UDFMGameInstance.class_code_reference': ('UDFMGameInstance.class_target', 0x2f41020,
        '04501e89109b3dd083ab233c9bb898a598160e242ca6a679d4857ada4b27f5f0',
        0x2f41085, 0x2f41410),
    'ADFMGameMode.class_code_reference': ('ADFMGameMode.class_target', 0xce96eb0,
        '4a45892ba175d3e1185593d966861726cead9fff098d2845044b427a217b0a80',
        0xce96f15, 0xce98170),
}
LEAF_JUMP_WITNESSES = {
    'UDFMGameInstance.native_registration_dispatch': ('UDFMGameInstance.native_registration_callback_reference', 0x2f417a0,
        '4a5f7dbc7cfb2f2fb0c5a3a7879fae0f41a06c58e85ab6263e57e2e022ee4cb8',
        0x2f417bd, 0x10d060b0),
    'UGPGameInstance.constructor_target': ('UGPGameInstance.class_code_reference.prefix', 0x5ff5580,
        '6fbbbda987df855a4bc881fd2e0fb6bf3e7f2df38592d5e8fa8f2bfb7d33c02f',
        0x5ff558e, 0x49996f0),
    'UDFMGameInstance.constructor_target': ('UDFMGameInstance.class_code_reference.prefix', 0x2f41410,
        'f1b2c049a29408927848e8d02e5d85aedffdeeb591f00c79507481057ea22595',
        0x2f4141e, 0x2f3c0c0),
    'ADFMGameMode.constructor_target': ('ADFMGameMode.class_code_reference.prefix', 0xce98170,
        '211574c0c74141885c2a3c71b9fce009efc4fb43b7286fa7609e3d9771b1b4bf',
        0xce9817e, 0xb883200),
}
CONSTRUCTOR_BRANCH_WITNESSES = {
    'UGPNetConnection.constructor_target': ('UGPNetConnection.constructor_code_reference.prefix', 0x6040fb0,
        'd56fe357bb53c42d5fb95c3907522b5b9c77059254c43b5d60adbad032e0c741',
        0x6040fb6, 0x49999f0),
}
VTABLE_CODE_WITNESSES = {
    'UGPGameInstance.GameMode_factory': ('UGPGameInstance.constructor_target', 0x49996f0,
        '35fe1620d310be65c784d322fe4d792cd391d78d6f2f41bf97a1a1852822b3ca',
        0x4999763, 0x15c21998, 0x328, 0x49a88b0),
    'UDFMGameInstance.GameMode_factory': ('UDFMGameInstance.constructor_target', 0x2f3c0c0,
        'ba5318a83f5539df2842cadf76206e0fb5f74973b5fa12e8d065690604dc17b0',
        0x2f3c0ce, 0x15c21d88, 0x328, 0x49a88b0),
    'UDFMGameInstance.event_dispatch': ('UDFMGameInstance.constructor_target', 0x2f3c0c0,
        'ba5318a83f5539df2842cadf76206e0fb5f74973b5fa12e8d065690604dc17b0',
        0x2f3c0ce, 0x15c21d88, 0x220, 0x10eb4480),
    'ADFMGameMode.offline_controller': ('ADFMGameMode.constructor_target', 0xb883200,
        '7ba22701dc5a63288eb3a15df41952682fd42f10d70ba8b85129b6b5ab3597d9',
        0xb88322a, 0x17b21e20, 0xb68, 0xb8bb400),
    'ADFMGameMode.offline_character': ('ADFMGameMode.constructor_target', 0xb883200,
        '7ba22701dc5a63288eb3a15df41952682fd42f10d70ba8b85129b6b5ab3597d9',
        0xb88322a, 0x17b21e20, 0xb70, 0xb8ba840),
    'ADFMGameMode.spawn_controller': ('ADFMGameMode.constructor_target', 0xb883200,
        '7ba22701dc5a63288eb3a15df41952682fd42f10d70ba8b85129b6b5ab3597d9',
        0xb88322a, 0x17b21e20, 0x7e0, 0xb8edee0),
    'ADFMGameMode.default_spawn_controller': ('ADFMGameMode.constructor_target', 0xb883200,
        '7ba22701dc5a63288eb3a15df41952682fd42f10d70ba8b85129b6b5ab3597d9',
        0xb88322a, 0x17b21e20, 0x7d8, 0x1294dd70),
    'ADFMGameMode.spectator_spawn_controller': ('ADFMGameMode.constructor_target', 0xb883200,
        '7ba22701dc5a63288eb3a15df41952682fd42f10d70ba8b85129b6b5ab3597d9',
        0xb88322a, 0x17b21e20, 0x7e8, 0x1294e040),
    'ADFMGameMode.controller_spawn_implementation': ('ADFMGameMode.constructor_target', 0xb883200,
        '7ba22701dc5a63288eb3a15df41952682fd42f10d70ba8b85129b6b5ab3597d9',
        0xb88322a, 0x17b21e20, 0x878, 0x1294def0),
    'ADFMGameMode.virtual_slot_7f0': ('ADFMGameMode.constructor_target', 0xb883200,
        '7ba22701dc5a63288eb3a15df41952682fd42f10d70ba8b85129b6b5ab3597d9',
        0xb88322a, 0x17b21e20, 0x7f0, 0x12921ea0),
    'ADFMGameMode.restart_at_player_start': ('ADFMGameMode.constructor_target', 0xb883200,
        '7ba22701dc5a63288eb3a15df41952682fd42f10d70ba8b85129b6b5ab3597d9',
        0xb88322a, 0x17b21e20, 0x800, 0x4d84950),
    'ADFMGameMode.virtual_slot_820': ('ADFMGameMode.constructor_target', 0xb883200,
        '7ba22701dc5a63288eb3a15df41952682fd42f10d70ba8b85129b6b5ab3597d9',
        0xb88322a, 0x17b21e20, 0x820, 0x1293c090),
    'ADFMGameMode.default_pawn_implementation': ('ADFMGameMode.constructor_target', 0xb883200,
        '7ba22701dc5a63288eb3a15df41952682fd42f10d70ba8b85129b6b5ab3597d9',
        0xb88322a, 0x17b21e20, 0x6c0, 0x1294c0a0),
    'ADFMGameMode.pawn_at_transform_implementation': ('ADFMGameMode.constructor_target', 0xb883200,
        '7ba22701dc5a63288eb3a15df41952682fd42f10d70ba8b85129b6b5ab3597d9',
        0xb88322a, 0x17b21e20, 0x6b8, 0xb8edb70),
    'ADFMGameMode.default_pawn_class_implementation': ('ADFMGameMode.constructor_target', 0xb883200,
        '7ba22701dc5a63288eb3a15df41952682fd42f10d70ba8b85129b6b5ab3597d9',
        0xb88322a, 0x17b21e20, 0x700, 0x1292ed90),
    'ADFMGameMode.init_game_implementation': ('ADFMGameMode.constructor_target', 0xb883200,
        '7ba22701dc5a63288eb3a15df41952682fd42f10d70ba8b85129b6b5ab3597d9',
        0xb88322a, 0x17b21e20, 0x708, 0xb8b4e70),
    'ADFMGameMode.init_game_state_implementation': ('ADFMGameMode.constructor_target', 0xb883200,
        '7ba22701dc5a63288eb3a15df41952682fd42f10d70ba8b85129b6b5ab3597d9',
        0xb88322a, 0x17b21e20, 0x710, 0xb8b51e0),
    'ADFMGameMode.login_implementation': ('ADFMGameMode.constructor_target', 0xb883200,
        '7ba22701dc5a63288eb3a15df41952682fd42f10d70ba8b85129b6b5ab3597d9',
        0xb88322a, 0x17b21e20, 0x7c0, 0xb8bfab0),
    'ADFMGameMode.post_login_implementation': ('ADFMGameMode.constructor_target', 0xb883200,
        '7ba22701dc5a63288eb3a15df41952682fd42f10d70ba8b85129b6b5ab3597d9',
        0xb88322a, 0x17b21e20, 0x7c8, 0xb8d1ed0),
    'ADFMGameMode.starting_player_implementation': ('ADFMGameMode.constructor_target', 0xb883200,
        '7ba22701dc5a63288eb3a15df41952682fd42f10d70ba8b85129b6b5ab3597d9',
        0xb88322a, 0x17b21e20, 0x6f0, 0xb8b24b0),
    'ADFMGameMode.new_player_implementation': ('ADFMGameMode.constructor_target', 0xb883200,
        '7ba22701dc5a63288eb3a15df41952682fd42f10d70ba8b85129b6b5ab3597d9',
        0xb88322a, 0x17b21e20, 0x840, 0xb8b6630),
    'ADFMGameMode.virtual_slot_aa0': ('ADFMGameMode.constructor_target', 0xb883200,
        '7ba22701dc5a63288eb3a15df41952682fd42f10d70ba8b85129b6b5ab3597d9',
        0xb88322a, 0x17b21e20, 0xaa0, 0x4d09d10),
}
FACTORY_CALL_WITNESSES = {
    'UGPGameInstance.GameMode_base_factory': ('UGPGameInstance.GameMode_factory', 0x49a88b0,
        '345046fedc2c285097c7a234b491b96261adcb67a4f4064dbb42b07049c661ca',
        0x49a8e0f, 0x12924890),
    'UGPGameInstance.world_getter': ('UGPGameInstance.GameMode_factory', 0x49a88b0,
        '345046fedc2c285097c7a234b491b96261adcb67a4f4064dbb42b07049c661ca',
        0x49a8c16, 0x12932820),
}
OFFLINE_CALL_WITNESSES = {
    'ADFMGameMode.game_logic_base_class_target': ('ADFMGameMode.virtual_slot_aa0', 0x4d09d10,
        'ae825ca9cec15597a53b8ca41b4576668443c196022fb8375f480a98fe497953',
        0x4d09f07, 0x2faa160),
    'ADFMGameMode.game_logic_object_create_target': ('ADFMGameMode.virtual_slot_aa0', 0x4d09d10,
        'ae825ca9cec15597a53b8ca41b4576668443c196022fb8375f480a98fe497953',
        0x4d09fa5, 0x10ebd0a0),
    'ADFMGameMode.ds_logic_getter_target': ('ADFMGameMode.init_game_implementation', 0xb8b4e70,
        '4051d4ecb5a3d2df2e65b140cbf5d0299a8dc8f5602168f708726575264eeca5',
        0xb8b4f6f, 0xb8aa810),
    'ADFMGameMode.parent_init_game_target': ('ADFMGameMode.init_game_implementation', 0xb8b4e70,
        '4051d4ecb5a3d2df2e65b140cbf5d0299a8dc8f5602168f708726575264eeca5',
        0xb8b4efd, 0x4d0a020),
    'ADFMGameMode.parent_init_game_state_target': ('ADFMGameMode.init_game_state_implementation', 0xb8b51e0,
        'ef3656f0e84c7e66056b8bc626c71372c9872b9d64ace586bfcfd90c4f095bfd',
        0xb8b523c, 0x4d0a370),
    'ADFMGameMode.player_info_lookup_target': ('ADFMGameMode.new_player_implementation', 0xb8b6630,
        'd161c0dccdefbbf4c97e380afd9af587dede6c381f6b1ede0f5443f2f01438c0',
        0xb8b6a46, 0xb745670),
    'ADFMGameMode.base_starting_player_target': ('ADFMGameMode.starting_player_implementation', 0xb8b24b0,
        '37e68950857e3ac26bdb21dffad332921e1543cc16820858c630e6a70aa85cd0',
        0xb8b270b, 0x12936c30),
    'ADFMGameMode.parent_constructor': ('ADFMGameMode.constructor_target', 0xb883200,
        '7ba22701dc5a63288eb3a15df41952682fd42f10d70ba8b85129b6b5ab3597d9',
        0xb883212, 0x4cef3c0),
    'ADFMGameMode.base_constructor': ('ADFMGameMode.parent_constructor', 0x4cef3c0,
        'dfab404b03f665cf1f6b3d23d59c3185b40eda995dc493cb1a3720d7295590b8',
        0x4cef3cd, 0x4a25dc0),
    'ADFMGameMode.engine_constructor': ('ADFMGameMode.base_constructor', 0x4a25dc0,
        '10e759bba770467a452d007d1f70fce8325955e8b21c7eb6fd04ab6b2567cf2c',
        0x4a25dcd, 0x1291aa20),
    'ADFMGameMode.engine_reference_3a8': ('ADFMGameMode.engine_constructor', 0x1291aa20,
        '04e79b0c5cda310046d7c6e6c71d0bb1f8c1ea852e077429e43b322bfc6cb549',
        0x1291ab03, 0x132da770),
    'ADFMGameMode.base_reference_390': ('ADFMGameMode.parent_constructor', 0x4cef3c0,
        'dfab404b03f665cf1f6b3d23d59c3185b40eda995dc493cb1a3720d7295590b8',
        0x4cef4aa, 0x6051480),
    'ADFMGameMode.base_reference_3a0': ('ADFMGameMode.parent_constructor', 0x4cef3c0,
        'dfab404b03f665cf1f6b3d23d59c3185b40eda995dc493cb1a3720d7295590b8',
        0x4cef486, 0x313f550),
    'ADFMGameMode.base_reference_398': ('ADFMGameMode.parent_constructor', 0x4cef3c0,
        'dfab404b03f665cf1f6b3d23d59c3185b40eda995dc493cb1a3720d7295590b8',
        0x4cef49e, 0x6057580),
    'ADFMGameMode.base_reference_388': ('ADFMGameMode.parent_constructor', 0x4cef3c0,
        'dfab404b03f665cf1f6b3d23d59c3185b40eda995dc493cb1a3720d7295590b8',
        0x4cef492, 0x5fff470),
    'ADFMGameMode.pawn_transform_event': ('ADFMGameMode.default_pawn_implementation', 0x1294c0a0,
        '019d73958f92832016ea10e784c49bd01ab270d9884f8651fc0696c7bb30d920',
        0x1294cb37, 0x132f0ff0),
    'ADFMGameMode.parent_pawn_at_transform': ('ADFMGameMode.pawn_at_transform_implementation', 0xb8edb70,
        '1a2af538a3ad6dfe3cab4fb79b00a6677ed65428f741ecff34553f6a9695b662',
        0xb8edebc, 0x4d92080),
    'ADFMGameMode.pawn_class_event': ('ADFMGameMode.parent_pawn_at_transform', 0x4d92080,
        '37b2a6a428f4f11717dc7671f31c823abbb13a4aaf5bd9608777ad6026ad3882',
        0x4d92151, 0x132f0540),
    'ADFMGameMode.pawn_class_type_reference': ('ADFMGameMode.default_pawn_class_implementation', 0x1292ed90,
        '5ab7782d5f2cb38174ec663afc0ef516b42e406ad4b2f4fbc3cd99c96b77e91f',
        0x1292eda3, 0x133a2260),
    'ADFMGameMode.constructor_reference_388': ('ADFMGameMode.constructor_target', 0xb883200,
        '7ba22701dc5a63288eb3a15df41952682fd42f10d70ba8b85129b6b5ab3597d9',
        0xb88344a, 0xceaaf40),
    'ADFMGameMode.constructor_reference_5e8': ('ADFMGameMode.constructor_target', 0xb883200,
        '7ba22701dc5a63288eb3a15df41952682fd42f10d70ba8b85129b6b5ab3597d9',
        0xb88343e, 0xce68e60),
    'ADFMGameMode.constructor_reference_720': ('ADFMGameMode.constructor_target', 0xb883200,
        '7ba22701dc5a63288eb3a15df41952682fd42f10d70ba8b85129b6b5ab3597d9',
        0xb883456, 0xd004b30),
    'ADFMGameMode.constructor_reference_730': ('ADFMGameMode.constructor_target', 0xb883200,
        '7ba22701dc5a63288eb3a15df41952682fd42f10d70ba8b85129b6b5ab3597d9',
        0xb883336, 0xcef3050),
    'ADFMGameMode.offline_controller_class': ('ADFMGameMode.offline_controller', 0xb8bb400,
        '734b92fbbabe4f172d7becfeaddc0a82cc56a039cc36be72c7f1b30a0434196e',
        0xb8bb9c9, 0xced42c0),
    'ADFMGameMode.offline_controller_create': ('ADFMGameMode.offline_controller', 0xb8bb400,
        '734b92fbbabe4f172d7becfeaddc0a82cc56a039cc36be72c7f1b30a0434196e',
        0xb8bb9f4, 0x12a9b890),
    'ADFMGameMode.offline_start_locator': ('ADFMGameMode.offline_character', 0xb8ba840,
        'ea7946e41e75399f9149bf85537dab98f89972b00fc263cb1aeef82eadaf05ae',
        0xb8bac3d, 0x132f0460),
    'ADFMGameMode.offline_pawn_create': ('ADFMGameMode.offline_character', 0xb8ba840,
        'ea7946e41e75399f9149bf85537dab98f89972b00fc263cb1aeef82eadaf05ae',
        0xb8bac60, 0x132f1080),
    'ADFMGameMode.offline_possess': ('ADFMGameMode.offline_character', 0xb8ba840,
        'ea7946e41e75399f9149bf85537dab98f89972b00fc263cb1aeef82eadaf05ae',
        0xb8bac82, 0x1285f1f0),
    'ADFMGameMode.base_spawn_controller': ('ADFMGameMode.spawn_controller', 0xb8edee0,
        '1572dc993bb5646216e6ae4b37dc7ff489ff956b02d70ce48a12f98062c33625',
        0xb8ee482, 0x1294dd90),
    'ADFMGameMode.controller_post_init': ('ADFMGameMode.spawn_controller', 0xb8edee0,
        '1572dc993bb5646216e6ae4b37dc7ff489ff956b02d70ce48a12f98062c33625',
        0xb8ee490, 0xb8bbdf0),
}
OFFLINE_RIP_CODE_WITNESSES = {
    'DFMDSLogic.constructor_code_reference': ('ADFMGameMode.constructor_reference_5e8', 0xce68e60,
        '4905e156da18551827de48ccf11f58ecf28e11a357227fd6b9e7b120d3fa50df',
        0xce68ec5, 0xce69640),
    'DFMOfflinePlayerController.class_code_reference': ('ADFMGameMode.offline_controller_class', 0xced42c0,
        '7bc59a8c884f2dd54da3cb82829d12f9c00f90e2288652a35f0932fa77f536f8',
        0xced4325, 0xced43e0),
    'DFMOfflinePlayerController.registration_callback_reference': ('ADFMGameMode.offline_controller_class', 0xced42c0,
        '7bc59a8c884f2dd54da3cb82829d12f9c00f90e2288652a35f0932fa77f536f8',
        0xced42e7, 0xd5f350, b'\x4c\x8d\x0d'),
    'DFMOfflinePlayerController.parent_class_candidate': ('ADFMGameMode.offline_controller_class', 0xced42c0,
        '7bc59a8c884f2dd54da3cb82829d12f9c00f90e2288652a35f0932fa77f536f8',
        0xced4304, 0x1043440),
}
OFFLINE_LEAF_JUMP_WITNESSES = {
    'DFMDSLogic.constructor_target': ('DFMDSLogic.constructor_code_reference.prefix', 0xce69640,
        '2cb7be9df102e8241b66ccb82fdf12806c878ec9f5d5954be722651412a5ef91',
        0xce6964e, 0xb71cc60),
}
DS_LOGIC_CALL_WITNESSES = {
    'DFMDSLogic.message_name_reference_6eb3df0': ('DFMDSLogic.constructor_target', 0xb71cc60,
        'f28ea571bee0c369e37fa7b697d742184ed811813f4756cd11ddb87464fd2edb',
        0xb71d0b8, 0x6eb3df0),
    'DFMDSLogic.message_name_reference_6eb3bd0': ('DFMDSLogic.constructor_target', 0xb71cc60,
        'f28ea571bee0c369e37fa7b697d742184ed811813f4756cd11ddb87464fd2edb',
        0xb71d10b, 0x6eb3bd0),
    'DFMDSLogic.message_name_reference_6eb3c40': ('DFMDSLogic.constructor_target', 0xb71cc60,
        'f28ea571bee0c369e37fa7b697d742184ed811813f4756cd11ddb87464fd2edb',
        0xb71d15d, 0x6eb3c40),
}
DS_LOGIC_RIP_CODE_WITNESSES = {
    'DFMDSLogic.callback_reference_b767300': ('DFMDSLogic.constructor_target', 0xb71cc60,
        'f28ea571bee0c369e37fa7b697d742184ed811813f4756cd11ddb87464fd2edb',
        0xb71d0cb, 0xb767300, b'\x4c\x8d\x0d'),
    'DFMDSLogic.callback_reference_b7658f0': ('DFMDSLogic.constructor_target', 0xb71cc60,
        'f28ea571bee0c369e37fa7b697d742184ed811813f4756cd11ddb87464fd2edb',
        0xb71d11e, 0xb7658f0, b'\x4c\x8d\x0d'),
    'DFMDSLogic.callback_reference_b76b240': ('DFMDSLogic.constructor_target', 0xb71cc60,
        'f28ea571bee0c369e37fa7b697d742184ed811813f4756cd11ddb87464fd2edb',
        0xb71d170, 0xb76b240, b'\x4c\x8d\x0d'),
}
LATE_VTABLE_CODE_WITNESSES = {
    'UGPNetConnection.client_player_slot': ('UGPNetConnection.constructor_target', 0x49999f0,
        '46a25c47d59dbae79041408b746d87d13226deb4d34d4b822158e728fd56a09f',
        0x4999a1b, 0x15e73e20, 0x2c0, 0x49b7010),
    'DFMOfflinePlayerController.actor_open_hook': ('DFMOfflinePlayerController.class_code_reference', 0xced43e0,
        '7cf53d91081e83614121a52da7b5a5fa714019fb5548fa8772373b56befc7fbd',
        0xced43f9, 0x187200a0, 0x3d8, 0x12d4ddb0),
}
LATE_CALL_WITNESSES = {
    'UGPNetConnection.seamless_interface_constructor': ('UGPNetConnection.constructor_target', 0x49999f0,
        '46a25c47d59dbae79041408b746d87d13226deb4d34d4b822158e728fd56a09f',
        0x4999a14, 0x4999470),
    'UGPNetConnection.client_player_gate': ('UGPNetConnection.client_player_slot', 0x49b7010,
        'dca9f002163f7ff18996c00a51aed9a6128029825f6dd0bd108e19ef6a90de85',
        0x49b70ee, 0x49a3460),
    'UGPNetConnection.base_client_player': ('UGPNetConnection.client_player_slot', 0x49b7010,
        'dca9f002163f7ff18996c00a51aed9a6128029825f6dd0bd108e19ef6a90de85',
        0x49b7135, 0x12b91a80),
}
EVENT_NAME_CELL_WITNESSES = {
    'ADFMGameMode.player_start_event_name': ('ADFMGameMode.offline_start_locator', 0x132f0460,
        'b2386864fe832b24a5b9bf39dc71e4279e02d95ecaa5dec812cc5794f9e6c043',
        0x132f04f4, 0x1e522dd8),
    'ADFMGameMode.default_pawn_event_name': ('ADFMGameMode.offline_pawn_create', 0x132f1080,
        '6d17fe844d91f4a2903bf972e54372f7ee792e04474f9f44c3f3741e3df6734a',
        0x132f1095, 0x1e522e48),
}
TYPE_HELPER_WITNESSES = {
    'UGPNetConnection.type_helper.1': ('UGPNetConnection.initializer', 0x5bf5c30,
        '3778fe2b1fc2888ca1634ed0852abd0e1b5b4b54ce48cb0ec58afa96035aa2f1',
        0x5bf5c4f, 0x165701f0, 1, 0x5db23f0),
    'UGPGameplayStatics.type_helper.1': ('UGPGameplayStatics.initializer', 0x5b75ec0,
        'd949ce70abcd0408ad8050d86b9f5235c4b4485d6fe7c5a13f4a07cff7c38d61',
        0x5b75edf, 0x165723e0, 1, 0x5db0030),
    'UGPGameplayStatics.type_helper.5': ('UGPGameplayStatics.initializer', 0x5b75ec0,
        'd949ce70abcd0408ad8050d86b9f5235c4b4485d6fe7c5a13f4a07cff7c38d61',
        0x5b75edf, 0x165723e0, 5, 0x5de3730),
    'UGPGameInstance.type_helper.1': ('UGPGameInstance.initializer', 0x5bbe100,
        'ade5462893a0cc0da2892e4726a3d13cbeaa22df2b37ab28fa85cbce68abfe58',
        0x5bbe11f, 0x165700d0, 1, 0x5dafb60),
    'UGPGameInstance.type_helper.5': ('UGPGameInstance.initializer', 0x5bbe100,
        'ade5462893a0cc0da2892e4726a3d13cbeaa22df2b37ab28fa85cbce68abfe58',
        0x5bbe11f, 0x165700d0, 5, 0x5de36c0),
    'UDFMGameInstance.type_helper.1': ('UDFMGameInstance.initializer', 0x2f40850,
        '83f3a0cf5a0c1f937293d2c46400e3aae81892a6f262b192c5cf2fad11827a0b',
        0x2f4086f, 0x15c24318, 1, 0x2f40ab0),
    'UDFMGameInstance.type_helper.5': ('UDFMGameInstance.initializer', 0x2f40850,
        '83f3a0cf5a0c1f937293d2c46400e3aae81892a6f262b192c5cf2fad11827a0b',
        0x2f4086f, 0x15c24318, 5, 0x2f40b60),
    'ADFMGameMode.type_helper.1': ('ADFMGameMode.initializer', 0xca48e10,
        'd944621439ea337596f8cc2e480a683d5cf81c09c0ae70e2912b3a7e52d4baa0',
        0xca48e2f, 0x184a3728, 1, 0xcb3b100),
    'ADFMGameMode.type_helper.5': ('ADFMGameMode.initializer', 0xca48e10,
        'd944621439ea337596f8cc2e480a683d5cf81c09c0ae70e2912b3a7e52d4baa0',
        0xca48e2f, 0x184a3728, 5, 0xcbc1070),
}


def validate_call_witness(body, source_rva, pin, call_rva, target_rva):
    if hashlib.sha256(body).hexdigest() != pin:
        raise ValueError('Named call witness hash mismatch')
    offset = call_rva - source_rva
    if not 0 <= offset <= len(body) - 5 or body[offset] != 0xe8:
        raise ValueError('Named call witness is not a bounded direct E8')
    if call_rva + 5 + struct.unpack_from('<i', body, offset + 1)[0] != target_rva:
        raise ValueError('Named call witness target mismatch')


def validate_leaf_jump_witness(prefix, source_rva, pin, jump_rva, target_rva):
    if hashlib.sha256(prefix).hexdigest() != pin:
        raise ValueError('Leaf jump witness hash mismatch')
    offset = jump_rva - source_rva
    if not 0 <= offset <= len(prefix) - 5 or prefix[offset] != 0xe9:
        raise ValueError('Leaf jump witness is not the fixed direct E9')
    if jump_rva + 5 + struct.unpack_from('<i', prefix, offset + 1)[0] != target_rva:
        raise ValueError('Leaf jump witness target mismatch')


def validate_image_load_witness(body, source_rva, pin, instruction_rva, cell_rva):
    if hashlib.sha256(body).hexdigest() != pin:
        raise ValueError('Image data witness hash mismatch')
    offset = instruction_rva - source_rva
    if not 0 <= offset <= len(body) - 7 or body[offset:offset + 3] != b'\x48\x8b\x15':
        raise ValueError('Image data witness is not the fixed RIP-relative MOV')
    if instruction_rva + 7 + struct.unpack_from('<i', body, offset + 3)[0] != cell_rva:
        raise ValueError('Image data witness target mismatch')


def validate_rip_witness(body, source_rva, pin, lea_rva, target_rva, *, opcode=b'\x48\x8d\x0d'):
    if hashlib.sha256(body).hexdigest() != pin:
        raise ValueError('Type helper witness hash mismatch')
    offset = lea_rva - source_rva
    if (opcode not in (b'\x48\x8d\x0d', b'\x48\x8d\x05', b'\x4c\x8d\x0d') or
            not 0 <= offset <= len(body) - 7 or body[offset:offset + 3] != opcode):
        raise ValueError('Type helper witness is not the fixed RIP-relative LEA')
    if lea_rva + 7 + struct.unpack_from('<i', body, offset + 3)[0] != target_rva:
        raise ValueError('Type helper witness target mismatch')


def code_targets():
    targets = {}
    for label, (_name, _rva, row) in REGISTRATIONS.items():
        targets[label + '.callback'] = row[1], 32
        targets[label + '.binding'] = row[2], 32
    targets.update({label: (row[3], 32) for label, row in NAME_CODE_PAIRS.items()})
    targets.update({label: (row[5], 32) for label, row in CLASS_INITIALIZERS.items()})
    return targets


def code_witnesses():
    # Later reads may depend on a body produced by an earlier group.
    groups = (TYPE_HELPER_WITNESSES, CALL_WITNESSES, RIP_CODE_WITNESSES,
              LEAF_JUMP_WITNESSES, CONSTRUCTOR_BRANCH_WITNESSES,
              VTABLE_CODE_WITNESSES, FACTORY_CALL_WITNESSES,
              OFFLINE_CALL_WITNESSES, OFFLINE_RIP_CODE_WITNESSES,
              OFFLINE_LEAF_JUMP_WITNESSES, DS_LOGIC_CALL_WITNESSES,
              DS_LOGIC_RIP_CODE_WITNESSES, LATE_VTABLE_CODE_WITNESSES,
              LATE_CALL_WITNESSES)
    return [(label, witness) for group in groups for label, witness in group.items()]


def validate_constructor_branch_witness(prefix, source_rva, pin, branch_rva, target_rva):
    if hashlib.sha256(prefix).hexdigest() != pin:
        raise ValueError('Constructor branch witness hash mismatch')
    if (len(prefix) < 13 or branch_rva != source_rva + 6 or
            prefix[:8] != b'\x48\x8b\x09\x48\x85\xc9\x0f\x85' or prefix[12] != 0xc3):
        raise ValueError('Witness is not the fixed null-checked constructor leaf')
    if branch_rva + 6 + struct.unpack_from('<i', prefix, 8)[0] != target_rva:
        raise ValueError('Constructor branch witness target mismatch')


def capture_metadata(read, base, module_size):
    spans = {(rva, 48) for _name, rva, _row in REGISTRATIONS.values()}
    spans.update((row[0], len(name) + 1) for name, _rva, row in REGISTRATIONS.values())
    if (base <= 0 or module_size <= 0 or base + module_size >= 1 << 64 or
            any(rva < 0 or rva + length > module_size for rva, length in spans)):
        raise ValueError('Named registrations exceed module bounds')

    def fixed_read(rva, length):
        if (rva, length) not in spans:
            raise ValueError('Read is not a fixed named registration')
        value = read(base + rva, length)
        if not isinstance(value, bytes) or len(value) != length:
            raise ValueError('Native read length differs from the fixed registration')
        return value

    evidence = {}
    for label, (name, rva, row) in REGISTRATIONS.items():
        live = struct.unpack('<6Q', fixed_read(rva, 48))
        expected = tuple(base + value for value in row[:5]) + (row[5],)
        if live != expected:
            raise ValueError('Loaded named registration differs from source')
        if fixed_read(row[0], len(name) + 1) != name.encode('ascii') + b'\0':
            raise ValueError('Loaded registration name differs from source')
        evidence[label] = {'registration_rva': hex(rva), 'all_fields_verified': True}
    return evidence


def capture_class_metadata(read, base, module_size):
    spans = set()
    for name, descriptor, cell, name_rva, _size, _code in CLASS_INITIALIZERS.values():
        spans.update(((descriptor, 24), (cell, 8), (name_rva, len(name) + 1)))
    if (base <= 0 or module_size <= 0 or base + module_size >= 1 << 64 or
            any(rva < 0 or rva + length > module_size for rva, length in spans)):
        raise ValueError('Named class descriptors exceed module bounds')

    def fixed_read(rva, length):
        if (rva, length) not in spans:
            raise ValueError('Read is not a fixed named class descriptor')
        value = read(base + rva, length)
        if not isinstance(value, bytes) or len(value) != length:
            raise ValueError('Native class read length differs from the fixed descriptor')
        return value

    evidence = {}
    for label, (name, descriptor, cell, name_rva, size, code) in CLASS_INITIALIZERS.items():
        if fixed_read(descriptor, 24) != struct.pack('<3Q', base + cell, base + name_rva, size):
            raise ValueError('Loaded class descriptor differs from source')
        if fixed_read(cell, 8) != struct.pack('<Q', base + code):
            raise ValueError('Loaded class initializer differs from source')
        if fixed_read(name_rva, len(name) + 1) != name.encode('ascii') + b'\0':
            raise ValueError('Loaded class name differs from source')
        evidence[label] = {'descriptor_rva': hex(descriptor), 'initializer_cell_rva': hex(cell),
                           'initializer_rva': hex(code), 'all_fields_verified': True}
    return evidence


def capture_class_method_metadata(read, base, module_size, *, verify_helper_code=True):
    spans = set()
    for descriptor, row, method_label, index, code, prefix in CLASS_METHOD_TABLES.values():
        method_rva = REGISTRATIONS[method_label][1]
        count = (row[4] >> 16) & 0xffff
        if index >= count or row[1] + index * 48 != method_rva:
            raise ValueError('Named method is outside the fixed class method array')
        spans.update(((descriptor, 40), (code, len(prefix)), (method_rva, 48)))
    if (base <= 0 or module_size <= 0 or base + module_size >= 1 << 64 or
            any(rva < 0 or rva + length > module_size for rva, length in spans)):
        raise ValueError('Class method records exceed module bounds')

    def fixed_read(rva, length):
        if (rva, length) not in spans:
            raise ValueError('Read is not a fixed class method record')
        value = read(base + rva, length)
        if not isinstance(value, bytes) or len(value) != length:
            raise ValueError('Class method read length differs from the fixed record')
        return value

    evidence = {}
    for owner, (descriptor, row, label, index, code, prefix) in CLASS_METHOD_TABLES.items():
        if fixed_read(descriptor, 40) != struct.pack(
                '<5Q', *(tuple(base + value for value in row[:4]) + (row[4],))):
            raise ValueError('Loaded class method descriptor differs from source')
        if verify_helper_code and fixed_read(code, len(prefix)) != prefix:
            raise ValueError('Loaded class method helper differs from source')
        _name, method_rva, method = REGISTRATIONS[label]
        if fixed_read(method_rva, 48) != struct.pack(
                '<6Q', *(tuple(base + value for value in method[:5]) + (method[5],))):
            raise ValueError('Loaded class method registration differs from source')
        evidence[owner] = {'descriptor_rva': hex(descriptor), 'helper_rva': hex(code),
                           'method_array_rva': hex(row[1]), 'method_index': index,
                           'method_count': (row[4] >> 16) & 0xffff,
                           'method_registration_rva': hex(method_rva),
                           'descriptor_fields_verified': True,
                           'helper_code_verified': verify_helper_code}
    return evidence


def validate_source(source_game, game_root):
    executable = (game_root / CLIENT_PATH).resolve()
    source = (source_game / CLIENT_PATH).resolve()
    if executable == source:
        raise ValueError('Diagnostic must target the independent shadow')
    if digest(source) != SOURCE_SHA or digest(executable) != SOURCE_SHA:
        raise ValueError('Installed source or shadow version hash mismatch')
    with source.open('rb') as stream, mmap.mmap(stream.fileno(), 0, access=mmap.ACCESS_READ) as raw:
        pe = pefile.PE(data=raw, fast_load=True)
        base = pe.OPTIONAL_HEADER.ImageBase
        for name, rva, row in REGISTRATIONS.values():
            expected = tuple(base + value for value in row[:5]) + (row[5],)
            if struct.unpack_from('<6Q', raw, pe.get_offset_from_rva(rva)) != expected:
                raise ValueError('Immutable registration differs from the fixed witness')
            offset = pe.get_offset_from_rva(row[0])
            if raw[offset:offset + len(name) + 1] != name.encode('ascii') + b'\0':
                raise ValueError('Immutable registration name mismatch')
        for name, rva, name_rva, code_rva in NAME_CODE_PAIRS.values():
            if struct.unpack_from('<QQ', raw, pe.get_offset_from_rva(rva)) != (base + name_rva, base + code_rva):
                raise ValueError('Immutable name/code pair mismatch')
            offset = pe.get_offset_from_rva(name_rva)
            if raw[offset:offset + len(name) + 1] != name.encode('ascii') + b'\0':
                raise ValueError('Immutable pair name mismatch')
        capture_class_metadata(lambda address, length: bytes(raw[
            pe.get_offset_from_rva(address - base):pe.get_offset_from_rva(address - base) + length]),
            base, pe.OPTIONAL_HEADER.SizeOfImage)
        # Shipping code is unpacked at startup; the disk check covers immutable
        # descriptor fields. Full helper linkage is checked against live code.
        capture_class_method_metadata(lambda address, length: bytes(raw[
            pe.get_offset_from_rva(address - base):pe.get_offset_from_rva(address - base) + length]),
            base, pe.OPTIONAL_HEADER.SizeOfImage, verify_helper_code=False)
        for _parent, _rva, _pin, _lea, table, slot, code in TYPE_HELPER_WITNESSES.values():
            if struct.unpack_from('<Q', raw, pe.get_offset_from_rva(table + slot * 8))[0] != base + code:
                raise ValueError('Immutable type helper pointer differs from source')
        for _parent, _rva, _pin, _lea, table, offset, code in (
                *VTABLE_CODE_WITNESSES.values(), *LATE_VTABLE_CODE_WITNESSES.values()):
            if struct.unpack_from('<Q', raw, pe.get_offset_from_rva(table + offset))[0] != base + code:
                raise ValueError('Immutable class vtable pointer differs from source')
        for rva, length in code_targets().values():
            if not any(section.Characteristics & 0x20000000 and
                       section.VirtualAddress <= rva < rva + length <=
                       section.VirtualAddress + section.Misc_VirtualSize for section in pe.sections):
                raise ValueError('Named code prefix is outside executable image bounds')
    return executable


def collect(source_game, game_root, folder, expected_pid, expected_start):
    executable = validate_source(source_game, game_root)
    report = {'kind': 'bounded_local_runtime_code_evidence', 'client_sha256': SOURCE_SHA,
              'observed_at_utc': datetime.now(timezone.utc).isoformat(),
              'game_files_modified': False, 'process_memory_written': False,
              'client_functions_invoked': False, 'heap_read': False,
              'maximum_code_bytes': (len(code_targets()) + len(code_witnesses())) * (32 + 8192),
              'maximum_event_name_cell_bytes': len(EVENT_NAME_CELL_WITNESSES) * 8,
              'functions': [], 'map_playability_not_inferred': True}
    pids = verified_pids(executable)
    if pids != [expected_pid] or psutil.Process(expected_pid).create_time() != expected_start:
        report['status'] = 'shadow_process_identity_changed'
        return report
    api = kernel()
    handle = api.OpenProcess(0x1010, False, expected_pid)
    if not handle:
        report.update(status='read_not_permitted', windows_error=C.get_last_error())
        return report
    snapshot = api.CreateToolhelp32Snapshot(0x18, expected_pid)
    try:
        base, size = None, None
        if snapshot and snapshot != C.c_void_p(-1).value:
            item = Module()
            item.dwSize = C.sizeof(item)
            ok = api.Module32FirstW(snapshot, C.byref(item))
            while ok:
                if os.path.normcase(str(Path(item.szExePath).resolve())) == os.path.normcase(str(executable)):
                    base, size = item.modBaseAddr, item.modBaseSize
                    break
                ok = api.Module32NextW(snapshot, C.byref(item))
        if base is None:
            report['status'] = 'shadow_module_unavailable'
            return report

        def read(address, length, *, code=False):
            if psutil.Process(expected_pid).create_time() != expected_start:
                raise ValueError('Shadow process identity changed during capture')
            memory = Memory()
            valid = (base <= address < address + length <= base + size and
                     api.VirtualQueryEx(handle, address, C.byref(memory), C.sizeof(memory)) == C.sizeof(memory) and
                     memory.State == 0x1000 and memory.Type == 0x1000000 and
                     memory.AllocationBase == base and not memory.Protect & 0x100 and
                     memory.Protect & 0xff in ((0x10, 0x20, 0x40, 0x80) if code else (2, 4, 8, 0x20, 0x40, 0x80)) and
                     address + length <= memory.BaseAddress + memory.RegionSize)
            if not valid:
                raise ValueError('Read is outside the verified image page')
            buffer, copied = (C.c_ubyte * length)(), C.c_size_t()
            if not api.ReadProcessMemory(handle, address, buffer, length, C.byref(copied)) or copied.value != length:
                raise OSError(C.get_last_error(), 'Fixed image read failed')
            return bytes(buffer)

        report['registrations'] = capture_metadata(read, base, size)
        report['class_initializers'] = capture_class_metadata(read, base, size)
        for name, rva, name_rva, code_rva in NAME_CODE_PAIRS.values():
            if read(base + rva, 16) != struct.pack('<QQ', base + name_rva, base + code_rva):
                raise ValueError('Loaded name/code pair differs from source')
            if read(base + name_rva, len(name) + 1) != name.encode('ascii') + b'\0':
                raise ValueError('Loaded name/code pair name differs from source')
        decoder = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
        bodies = {}
        for label, (rva, length) in code_targets().items():
            prefix = read(base + rva, length, code=True)
            entry = {'name': label, 'prefix_rva': hex(rva), 'prefix_sha256': hashlib.sha256(prefix).hexdigest()}
            samples = [(label + '.prefix', rva, prefix)]
            try:
                if prefix[0] == 0xe9:
                    target, span, fragments = direct_implementation_span(executable, rva, prefix)
                    origin = 'named_prefix_direct_jump'
                else:
                    target, span, fragments = bounded_image_function_span(executable, rva)
                    origin = 'named_registration_entry'
                body = read(base + target, span, code=True)
                bodies[label] = body
                entry['direct_implementation'] = {'rva': hex(target), 'bytes': span,
                                                  'origin': origin,
                                                  'unwind_fragments': [[hex(a), hex(b)] for a, b in fragments],
                                                  'sha256': hashlib.sha256(body).hexdigest()}
                samples.append((label + '.implementation', target, body))
            except ValueError as error:
                entry['direct_implementation_not_followed'] = str(error)
            for sample_label, sample_rva, value in samples:
                instructions = list(decoder.disasm(value, sample_rva))
                (folder / (sample_label + '.dfcode')).write_bytes(
                    struct.pack('<4Q', 0x0000000145444344, sample_rva, len(value), base) + value)
                (folder / (sample_label + '.asm.txt')).write_text('\n'.join(
                    f'{ins.address:#x}: {ins.mnemonic} {ins.op_str}' for ins in instructions) + '\n', encoding='utf-8')
                entry[sample_label.rsplit('.', 1)[1] + '_first_instructions'] = [
                    f'{ins.mnemonic} {ins.op_str}' for ins in instructions[:8]]
            report['functions'].append(entry)
        for label, witness in code_witnesses():
            if (label in CALL_WITNESSES or label in FACTORY_CALL_WITNESSES or
                    label in OFFLINE_CALL_WITNESSES or label in DS_LOGIC_CALL_WITNESSES or
                    label in LATE_CALL_WITNESSES):
                parent, parent_rva, pin, call_rva, target_rva = witness
                validate_call_witness(bodies[parent], parent_rva, pin, call_rva, target_rva)
                origin = {'call_source': {'name': parent, 'rva': hex(call_rva), 'code_sha256': pin}}
            elif label in TYPE_HELPER_WITNESSES:
                parent, parent_rva, pin, lea_rva, table_rva, slot, target_rva = witness
                validate_rip_witness(bodies[parent], parent_rva, pin, lea_rva, table_rva)
                pointer_rva = table_rva + slot * 8
                if read(base + pointer_rva, 8) != struct.pack('<Q', base + target_rva):
                    raise ValueError('Loaded type helper pointer differs from source')
                origin = {'type_helper_source': {'name': parent, 'lea_rva': hex(lea_rva),
                          'pointer_rva': hex(pointer_rva), 'code_sha256': pin}}
            elif (label in RIP_CODE_WITNESSES or label in OFFLINE_RIP_CODE_WITNESSES or
                  label in DS_LOGIC_RIP_CODE_WITNESSES):
                parent, parent_rva, pin, lea_rva, target_rva, *encoding = witness
                validate_rip_witness(bodies[parent], parent_rva, pin, lea_rva, target_rva,
                                     opcode=encoding[0] if encoding else b'\x48\x8d\x05')
                origin = {'code_reference_source': {'name': parent, 'lea_rva': hex(lea_rva),
                          'code_sha256': pin}}
            elif label in LEAF_JUMP_WITNESSES or label in OFFLINE_LEAF_JUMP_WITNESSES:
                parent, parent_rva, pin, jump_rva, target_rva = witness
                validate_leaf_jump_witness(bodies[parent], parent_rva, pin, jump_rva, target_rva)
                origin = {'leaf_jump_source': {'name': parent, 'jump_rva': hex(jump_rva),
                          'code_sha256': pin}}
            elif label in CONSTRUCTOR_BRANCH_WITNESSES:
                parent, parent_rva, pin, branch_rva, target_rva = witness
                validate_constructor_branch_witness(bodies[parent], parent_rva, pin, branch_rva, target_rva)
                origin = {'constructor_branch_source': {'name': parent, 'branch_rva': hex(branch_rva),
                          'code_sha256': pin}}
            else:
                parent, parent_rva, pin, lea_rva, table_rva, offset, target_rva = witness
                validate_rip_witness(bodies[parent], parent_rva, pin, lea_rva, table_rva,
                                     opcode=b'\x48\x8d\x05')
                pointer_rva = table_rva + offset
                if read(base + pointer_rva, 8) != struct.pack('<Q', base + target_rva):
                    raise ValueError('Loaded class vtable pointer differs from source')
                origin = {'class_vtable_source': {'name': parent, 'lea_rva': hex(lea_rva),
                          'pointer_rva': hex(pointer_rva), 'slot_offset': hex(offset), 'code_sha256': pin}}
            prefix = read(base + target_rva, 32, code=True)
            bodies[label + '.prefix'] = prefix
            entry = {'name': label, 'prefix_rva': hex(target_rva), **origin,
                     'prefix_sha256': hashlib.sha256(prefix).hexdigest()}
            (folder / (label + '.prefix.dfcode')).write_bytes(
                struct.pack('<4Q', 0x0000000145444344, target_rva, len(prefix), base) + prefix)
            (folder / (label + '.prefix.asm.txt')).write_text('\n'.join(
                f'{ins.address:#x}: {ins.mnemonic} {ins.op_str}'
                for ins in decoder.disasm(prefix, target_rva)) + '\n', encoding='utf-8')
            try:
                if prefix[0] == 0xe9:
                    target, span, fragments = direct_implementation_span(executable, target_rva, prefix)
                else:
                    target, span, fragments = bounded_image_function_span(executable, target_rva)
            except ValueError as error:
                entry['direct_implementation_not_followed'] = str(error)
                report['functions'].append(entry)
                continue
            body = read(base + target, span, code=True)
            bodies[label] = body
            instructions = list(decoder.disasm(body, target))
            entry['direct_implementation'] = {'rva': hex(target), 'bytes': span,
                                               'sha256': hashlib.sha256(body).hexdigest(),
                                               'unwind_fragments': [[hex(a), hex(b)] for a, b in fragments]}
            (folder / (label + '.implementation.dfcode')).write_bytes(
                struct.pack('<4Q', 0x0000000145444344, target, len(body), base) + body)
            (folder / (label + '.implementation.asm.txt')).write_text('\n'.join(
                f'{ins.address:#x}: {ins.mnemonic} {ins.op_str}' for ins in instructions) + '\n', encoding='utf-8')
            report['functions'].append(entry)
        report['event_name_cells'] = {}
        for label, (parent, parent_rva, pin, instruction_rva, cell_rva) in EVENT_NAME_CELL_WITNESSES.items():
            validate_image_load_witness(bodies[parent], parent_rva, pin, instruction_rva, cell_rva)
            value = read(base + cell_rva, 8)
            pointer, = struct.unpack('<Q', value)
            report['event_name_cells'][label] = {
                'parent': parent, 'parent_code_sha256': pin, 'instruction_rva': hex(instruction_rva),
                'cell_rva': hex(cell_rva), 'raw_hex': value.hex(),
                'in_image_pointer_rva': hex(pointer - base) if base <= pointer < base + size else None,
                'pointed_memory_read': False,
            }
        report['class_methods'] = capture_class_method_metadata(read, base, size)
        report['status'] = 'bounded_read_complete'
        return report
    finally:
        if snapshot and snapshot != C.c_void_p(-1).value:
            api.CloseHandle(snapshot)
        api.CloseHandle(handle)


def dependency_hashes():
    return {name: digest(Path(__file__).with_name(name)) for name in
            ('probe_local_runtime_code.py', 'read_named_ds_transport_code.py', 'capture_official_ds.py')}


def elevate(source_game, game_root):
    executable = validate_source(source_game, game_root)
    pids = verified_pids(executable)
    if len(pids) != 1:
        raise ValueError('Expected exactly one running shadow client')
    folder = OUTPUT / str(time.time_ns())
    folder.mkdir(parents=True)
    save(folder / 'request.json', {'source_game': str(source_game.resolve()),
                                 'game_root': str(game_root.resolve()),
                                 'helper_sha256': dependency_hashes(), 'pid': pids[0],
                                 'process_start': psutil.Process(pids[0]).create_time()})

    class ShellInfo(C.Structure):
        _fields_ = [('cbSize', W.DWORD), ('fMask', W.ULONG), ('hwnd', W.HWND),
                    ('lpVerb', W.LPCWSTR), ('lpFile', W.LPCWSTR), ('lpParameters', W.LPCWSTR),
                    ('lpDirectory', W.LPCWSTR), ('nShow', C.c_int), ('hInstApp', W.HINSTANCE),
                    ('lpIDList', C.c_void_p), ('lpClass', W.LPCWSTR), ('hkeyClass', W.HKEY),
                    ('dwHotKey', W.DWORD), ('hIcon', W.HANDLE), ('hProcess', W.HANDLE)]

    info = ShellInfo()
    info.cbSize, info.fMask, info.lpVerb, info.lpFile = C.sizeof(info), 0x140, 'runas', sys.executable
    info.lpParameters = subprocess.list2cmdline([str(Path(__file__).resolve()), '--worker', str(folder)])
    info.lpDirectory, info.nShow = str(ROOT), 0
    shell = C.WinDLL('shell32', use_last_error=True).ShellExecuteExW
    shell.argtypes, shell.restype = [C.POINTER(ShellInfo)], W.BOOL
    print('Requesting normal Windows authorization for fixed local-runtime image reads', flush=True)
    if not shell(C.byref(info)):
        save(folder / 'result.json', {'status': 'authorization_failed', 'windows_error': C.get_last_error()})
        return 1
    api = kernel()
    try:
        print(json.dumps({'helper_pid': api.GetProcessId(info.hProcess),
                          'result_relative_to_project_root': (folder / 'result.json').relative_to(ROOT).as_posix()}), flush=True)
        while api.WaitForSingleObject(info.hProcess, 1000) == 258:
            pass
    finally:
        if info.hProcess:
            api.CloseHandle(info.hProcess)
    report = json.loads((folder / 'result.json').read_text(encoding='utf-8'))
    print(json.dumps(report, indent=2), flush=True)
    return 0 if report['status'] == 'bounded_read_complete' else 1


def main():
    sys.stdout.reconfigure(encoding='utf-8', errors='backslashreplace')
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source-game', type=Path)
    parser.add_argument('--game-root', type=Path)
    parser.add_argument('--validate-only', action='store_true')
    parser.add_argument('--worker', type=Path)
    args = parser.parse_args()
    if args.worker:
        folder = args.worker.resolve()
        if folder.parent != OUTPUT.resolve():
            parser.error('Worker request must be inside the local-runtime evidence directory')
        request = json.loads((folder / 'request.json').read_text(encoding='utf-8'))
        if request['helper_sha256'] != dependency_hashes():
            parser.error('Diagnostic dependencies changed after request preparation')
        try:
            report = collect(Path(request['source_game']), Path(request['game_root']), folder,
                             request['pid'], request['process_start'])
        except Exception as error:
            report = {'status': 'bounded_read_failed', 'error_type': type(error).__name__,
                      'error': str(error), 'game_files_modified': False,
                      'process_memory_written': False, 'client_functions_invoked': False}
        save(folder / 'result.json', report)
        return 0 if report['status'] == 'bounded_read_complete' else 1
    if args.source_game is None or args.game_root is None:
        parser.error('Provide installed source and independent shadow roots')
    if args.validate_only:
        validate_source(args.source_game, args.game_root)
        print(json.dumps({'client_sha256': SOURCE_SHA, 'registrations': len(REGISTRATIONS),
                          'code_prefixes': len(code_targets()), 'source_witnesses_verified': True}))
        return 0
    return elevate(args.source_game, args.game_root)


if __name__ == '__main__':
    raise SystemExit(main())
