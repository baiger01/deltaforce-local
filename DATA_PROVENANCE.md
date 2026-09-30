# 数据从哪里来

GitHub 协作仓库仅包含源码、静态 JSON 目录、重建描述符和来源元数据；不包含下文提到的原始表提取物、编译 DLL、测试账号或日志。迁移包与 GitHub 仓库的内容范围不同，克隆后无需先找回旧缓存即可使用已有目录继续开发。

以下路径均相对于 `game/` 游戏根目录；项目路径相对于 `deltaforce-local/`。运行时脚本通过 `work/local_game_paths.py` 定位 `../game`，也支持 `DF_LOCAL_SOURCE_GAME` 覆盖。版本目录 `1.101.37117.36` 和 PAK 文件名是**当前已验证游戏版本的资源标识**，并非这台电脑的安装路径；不同版本不能沿用这些表和偏移。

| 项目内数据 | 游戏内来源 | 处理逻辑 |
| --- | --- | --- |
| `outputs/df-local-server/protocol/game_item_catalog.json` | `DeltaForce/Saved/Dolphin/1.101.37117.36/Paks/1.101.37117.36.10_WindowsNoEditor_37127_P.pak`，资源表 `/Game/R13N/Common/Base/DataTables/GameItem` | 从已验证的明文 PAK 条目获得 `.uasset/.uexp`，`work/extract_game_item_catalog.py` 读取 Unreal 属性，按物品 ID 生成类型、稀有度、堆叠上限、长宽、重量和基础价格。目录头记录源表名、PAK 名与两个提取物的 SHA-256。 |
| `outputs/df-local-server/protocol/deposit_slot_catalog.json` | `DeltaForce/Saved/Dolphin/1.101.37117.36/Paks/1.101.37117.36.524_WindowsNoEditor_37641_P.pak`，资源表 `/Game/R13N/Common/Base/DataTables/PropSlotConfig` | `work/extract_prop_slot_config.py` 只读扫描并取出两个表文件，`work/extract_prop_slot_catalog.py` 按 PageId 提取格子长宽及容量。源提取物位于 `work/evidence/prop_slot_config/`。 |
| `outputs/df-local-server/protocol/operator_asset_catalog.json` | 同一个 `.524_...pak`，资源表 `/Game/R13N/Common/PC/DataTables/CharacterAvatarData` | `work/extract_operator_avatar_catalog.py` 从已提取的 `.uasset/.uexp` 解析外观行及 UI/TPP/FPP 网格路径。源提取物位于 `work/evidence/character_avatar_tables/`。这只说明模型资源存在，**不等于**该干员已解锁或时装归属已确认。 |
| `outputs/df-local-server/protocol/armor_durability_catalog.json` | 当前版本明文 PAK 条目中的 `/Game/DataTables/Armor/BodyArmorFunction`；原始 PAK 的具体文件名未保留 | `work/extract_armor_durability_catalog.py` 从 `work/evidence/armor_tables/` 的提取物读取护甲最大耐久。若需重新定位，先在相对游戏目录 `DeltaForce/Content/Paks/` 与 `DeltaForce/Saved/Dolphin/1.101.37117.36/Paks/` 的明文表条目中按完整资源表名检索，再核对提取物哈希；不能凭文件名猜测。背包、胸挂容量与耐久是不同属性。 |
| `outputs/df-local-server/protocol/business_contracts.json`、`generated_codec_fields.json`、`generated_class_metadata.json`、`candidate_business.pb` | 客户端 `DeltaForce/Saved/LuaSource/` 缓存与当前版本明文 PAK 内 Lua 容器；原生程序也提供部分类型名 | `work/lua53_reader.py` 只读解析 Lua 5.3 容器；恢复的字段、类声明和候选 Protobuf 定义保存在项目内。它们是重建业务消息的候选证据，不能单凭静态字段表宣称原客户端接口全部可用。 |
| `work/sdk-local-provider-stage/rail_api64.dll` | **本项目自建** DLL，接口形状来自同版本原版 `DeltaForce/Binaries/ThirdParty/WeGame/Win64/rail_api64.dll` | `outputs/native-account-provider/provider.c` 与 `build_provider.py` 生成；`build-record.json` 记录原版 SDK、源码和成品的 SHA-256。包内无原版游戏 DLL。运行测试前会校验原版哈希并在结束后恢复。 |
| `container_layout_catalog.json` | 基础包 `pakchunk2-WindowsClient.pak` 中背包与胸挂表明文条目 | `work/extract_container_layout_catalog.py` 恢复每个配置的实际分区，目录记录条目与哈希；不能用容量反推格子排列。 |
| `weapon_preset_catalog.json`、`weapon_component_catalog.json` | 同版本明文武器配置与基础包 `pakchunk2-WindowsClient.pak` 的组件节点条目 4567 | `work/extract_weapon_preset_catalog.py`、`extract_weapon_components_catalog.py` 恢复预设、receiver 和组件树，目录保留实际来源与偏移。 |
| `weapon_ammo_catalog.json` | 基础包 `pakchunk2-WindowsClient.pak` 条目 4489/4555；热更新 PartsData/PartsFunction；基础包 Lua `cs_deposit_pb.lua` | `work/extract_weapon_ammo_catalog.py` 恢复弹药类别、已有弹匣容量与装卸弹枚举，交叉核对客户端 Lua 规则；未恢复的弹匣或武器关系保持未知。目录记录源哈希、行偏移与函数。 |
| `client_error_catalog.json` | 基础包 `pakchunk1-WindowsClient.pak` 的 `errcode_pb.lua` 条目 6809 | `work/extract_client_error_catalog.py` 只读恢复实际错误名与值；不以统一猜测结果码代替库存业务错误。 |

`work/evidence/` 在迁移包中仅保留上述小范围表提取物，以便不重新扫描整套游戏就能复核目录。大型原始 PAK、原始 Lua 缓存、历史抓包及日志不在包内。同版本游戏在新电脑上按相对目录可重新读取；重新提取前请先核对游戏版本与目录头内的源文件哈希。`work/evidence/character_avatar_tables/` 中 GameItem 的 `.uexp` 约 35 MiB，已压缩进迁移包，毋须额外复制游戏素材。

交易购买、货币扣减、装备落位和弹药展示不仅依赖资源表，还依赖客户端请求及服务端状态链。物品表中的价格、模型和长宽不是完整商城售卖规则；地图资源存在也不是解锁条件。缺失规则应从客户端同版本配置和交互协议继续恢复，不能把目录行当成可购买或可用的证明。

口袋位置由已提取 `common_pb.lua` 根函数指令 426-428 确认：`Pocket=199997`；指令 399-401 的 `CarryOutPropsPos=1999` 是另一个位置。该 Lua 提取物 SHA-256 为 `81e071e35f33f0e5704d5098ac2a182c794bbe5b1e5a7e24f415a0473b40350b`。`QuickOperationLogic.lua` 根函数指令 51-61 将 Pocket 纳入身体容器快照，实际请求中有五个 1x1 口袋分区；购买与重开页面均按这个真实位置持久化。

心跳 `tick_count` 是客户端时钟的 Unix 秒，不是进程运行毫秒。2026-09-30 从当前安装 `DeltaForce/Content/Paks/pak-0-0-pakchunk1-WindowsClient.pak` 只读提取：

| 条目 | 客户端函数与依据 | 提取物 SHA-256 |
| --- | --- | --- |
| 7032，`ClockManager.lua` | `0.9` 直接记录服务时间；`0.11` 加上本地秒差，供商品时间判断使用 | `780f5d721f03c8965496a36fec011647d4bd9d45184dd9a2cc839a8f11b83a1e` |
| 7333，`TimeUtil.lua` | `0.1` 的 `GetCurrentTime` 调用 `os.time()` | `953acb6204def71e92ca497c9d74df65f60abd95fcaa17f34b3be18ae5a83260` |
| 7131，`ProtoManager.lua` | `0.82` 的 `UECall_UpdateServerTime` 将响应 `tick_count` 直接传给 `ClockManager.UpdateServerTime` | `83773304fcbaaceb2b335d4ba92fd14b95de31c490ae08e66df55ec67ef91c82` |

已提取 `AuctionServer.lua` 函数 `0.45` 将 `auction_vaild_time_begin/end` 与 `ClockManager.GetLocalTimestamp()` 比较（SHA-256：`ad10c29ff0fa53ca89ebebf9f0ba447cae2e47195b8921b24731cd01e4a82a6c`）。错误的心跳时间会在商品详情拉取后将其判成未开放；首次目录尚无此时间窗口，因而首次有选项、再次进入丢失。使用 `work/scan_weapon_tables.py --baseline --pak-name pak-0-0-pakchunk1-WindowsClient.pak --lua-pattern 'ClockManager|TimeUtil|ProtoManager' --asset-pattern 'a^'` 可重新取得时钟来源，用 `work/summarize_weapon_lua.py` 静态查看函数，不执行客户端 Lua。

单条防具报价的档位同样来自客户端逻辑：`AuctionServer.lua` 函数 `0.17`（指令 40-57）仅在头盔或护甲恰有三个报价档位时读取 1/2/3，否则读取档位 0。`GoodsItemStruct.lua` 函数 `0.13`（指令 8-15）把 `GetSaleInfo()` 是否有报价作为交易购买解锁条件；当前安装基础包 `pak-0-0-pakchunk1-WindowsClient.pak` 条目 1778 的该提取物 SHA-256 为 `34ae5cbc845b364949e34633630642150aced86398d1b6263b8b453a616f7ffa`。本地仅提供一个满耐久报价，类型目录及商品详情必须一致使用档位 0；此档位是报价索引，不能当成物品实际耐久。2026-09-30 原客户端请求并成功购买护甲 `11050006001` 到位置 105、头盔 `11010005011` 到位置 101，SQLite 重读确认两者持久化，用户确认四类装备均可购买。
