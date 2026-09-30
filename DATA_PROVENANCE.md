# 数据从哪里来

近战目录的 18 组真实对应中，本地只提供原客户端收藏日志确认解锁的 15 组；`28101250021/22/23` 是尚未恢复拥有规则的系列中间档。旧记录 `18100000001` 已由用户截图确认显示为喷枪，迁移到实际基础刀具 `18100000002` 与外观 `28101200002`。收藏使用 `weapon_skin_props`，装备物品使用 `weapon.skin_id`，选择持久化到本地账号。`InventoryServer_Network.lua` 的 Move 分支会访问两端实际格子，刀具切换按其 Add/Del 分支下发，不把内部未装备位置 0 当成客户端格子。2026-09-30 原客户端实际装备 receiver `18100000014` 成功，用户确认名称、模型及切换正常。提取脚本与目录记录相关 Lua 哈希和静态函数依据；这属于本地测试账号的提供策略，不代表官方账号归属。

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
| `melee_weapon_catalog.json` | 当前安装 `DeltaForce/Content/Paks/pak-0-0-pakchunk2-WindowsClient.pak` 明文导出条目 7276 | `work/extract_melee_catalog.py` 读取 18 行中序列化字段索引 40/41 的外观 ID 与武器 ID。源文件 SHA-256 为 `e6ab2c414dc8b972b0f20b647a8deedcb39c82912d968209f057db469defb845`。15 组对应由原客户端 `MeleeWeaponSkinDataTable` 日志交叉确认；加密名称表未恢复，不能冒称已解出原属性名。每行保留偏移、GameItem 名称键与尺寸。 |
| `gun_skin_catalog.json` | 当前安装基础包 `pak-0-0-pakchunk2-WindowsClient.pak` 明文导出条目 7292 | `work/extract_cosmetic_catalogs.py` 从 1781 行恢复可与 GameItem 核对的 1776 条外观；序列化字段 1820/1792/1794/1812 分别关联外观、武器、预设和收藏开放标志。源 SHA-256 为 `03929c8c36ef4bd21de0e6262809095a863f3e65d6e44e8eefcf6ac57a59cce7`。本地提供 1514 条开放普通皮肤，曼德尔实例单独保存。 |
| `mandel_box_catalog.json` | 同一基础包条目 6764/6766/6768/7152/7134，以及已有 GameItem 导出 | `work/extract_cosmetic_catalogs.py` 保留 464 行箱体、558 行分组、3962 行奖励、11 项商城关联、5 项经验卡赠送配置及 34 种砖的 ConnectedPool。每行保留原始索引与偏移，各源 SHA-256 在目录头内；名称沿用客户端 GameItem 名称键。 |
| `premium_shop_catalog.json` | 当前安装基础包 `pak-0-0-pakchunk2-WindowsClient.pak` 条目 7142/7156/7152/6774/6394/7154 | `work/extract_premium_shop_catalog.py` 恢复推荐配方、礼包价格、干员奖池、奖励与外观归属、主页签。所有记录保留行号、序列化偏移；完整来源和限制见下节。 |

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

## 枪械皮肤与曼德尔协议

普通外观归属是本地测试账号的提供策略。外观 ID、武器 ID 和预设关联来自客户端目录；`ItemHelperTool.lua` 函数 `0.40/0.60` 的 ID 分类规则用于区分普通与曼德尔外观。没有把未恢复的挂饰、花纹、磨损或材质 ID 写入账号。曼德尔奖励实例使用客户端 `CollectionServer.lua` 函数 `0.11.3/0.206` 明确支持的 `appearance.id=0` 默认查表分支；该值是客户端哨兵，不是假造 AppearanceID。

`MandelDrawOnly.lua` 函数 `0.5` 通过 `GetCollectionPropById(GetKeyID())` 读取密钥，因此 `32320000001` 必须作为收藏道具下发。该提取物 SHA-256 为 `f02cd1f699e83b7884bdf0a40f5b494600ceff39d26e055354dd641a86b01118`。`CollectionServer.lua` SHA-256 为 `30fd97e50c22998e987b1fdcf8ee7a0e4edfe1ae51b93dc1d6e11ff5e7bf37f2`。商城条目 7134 的字段 19/11/21/9/20 对应赠品、货币、价格、商品、赠送数量；实际购买商品是 `32210000004` 武器次级经验卡，每个 60 三角币，附送一个量子密钥。密钥请求的 `price` 是该次经验卡购买总价，砖请求的 `price` 是单价，二者由原客户端实际请求交叉确认。旧密钥货币记录在同一个 SQLite 事务中迁移为收藏数量并删除旧记录，重复启动不会再次赠送。

`StoreServer.lua` 函数 `0.119.0` 成功回调直接执行后续扫描；`MandelDrawOnly.lua` 函数 `0.36` 会再次检查收藏数量。因此本地购买先发送 `CSCollectionPropChangeNtf`，随后发送购买响应，保留请求业务序号并递增外层包序号。

十连奖励展示的约束来自 `RewardServer.lua` 函数 `0.17.0`：所有 `Add/Modify` 且 `prop.num>0` 的行都会进入奖励列表，不检查扣除的负 `delta`。该提取物 SHA-256 为 `12c62cdedc2d117e444b63c37e7e538f907d52b9976d7acb66c658c2c59d1dec`。2026-09-30 22:23 崩溃堆栈经过 `RewardSceneViewTen.lua:513/674`，向十件展示场景传入了十件奖励及两个剩余消耗栈。现在剩余砖和密钥仅通过收藏通知同步，扫描响应只提供实际奖励；回归用例通过真实加密包和重连处理入口检查该约束。

上述十连展示 Lua 来自基础包 `pak-0-0-pakchunk1-WindowsClient.pak` 条目 5556，SHA-256 为 `bf1e6845d4e398234ce5469c19734dc5fcb167800c8e00453316b72acc7cb258`。函数 `0.19` 对奖励列表逐项调用 `SetCurveLinearColorByItemQuality`，与崩溃堆栈一致；函数 `0.22` 进入抽奖子场景后执行该调用。

扫描规则分为客户端配置与本地执行策略：分组启用、权重、核心标志及 `TimeAssured=75` 来自分组条目字段 562/577/567/582；奖励 ID、数量和启用标志来自奖励条目字段 3982/3977/3967。本地使用配置分组权重，在组内均匀抽样，并按配置次数与本地连续未出核心的计数执行保证规则。组内动态概率、官方计数语义及增量调整规则未恢复，因此这套执行策略和显示的 `real_prob` 仅表示本地服务行为，不能宣称为官方概率。原始 `ProbShowed` 保留并单独下发。砖的 20000 曼德尔币报价也是本地诊断策略。奖池、名称、ID 和模型关联均采用已恢复的客户端配置。

## 原版商城与干员研究

2026-10-01 从本机安装只读提取，原始缓存是否存在不作为前置条件。当前基础包内已包含安魂、狂怒、飞虎、猛火强攻、游园惊梦及群星补给所引用的配置和资源路径。名称和宣传图仍由原客户端自己的配置读取，本地响应不编写替代名称或素材路径。与官方在线服务一致的活动轮换清单未恢复，不能把本地展示目录宣称为官方当前售卖清单。

| 基础包条目 | 提取内容 | SHA-256 |
| --- | --- | --- |
| 7142，`StoreHotRecommendation` | 158 条推荐配置及真实礼包配方、分项原价和包内价格 | `bcf064ebee25d046e21712375adf8e68f80b71bedd9c5c65f1fcb6a6d771a1fc` |
| 7156，`StoreMallGiftConfig` | 61 条特供配置、礼包内容、价格、日期、限购及原始支付商品标识 | `1b7640b1121e61e9fef64a8f986f5620588fb1e9a70822f8feae9898056b68d7` |
| 7152，`StoreLottery` | 19 条商城抽奖关联，其中 8 条为干员研究，11 条为曼德尔 | `9afbcc8eb3b98d08ee45b4ef0cea12464decb9f82b1faeb64337a2a25d757e62` |
| 6774，`LotteryProbDistribution` | 64 条干员奖池奖励，保留原始成本字段 69 与权重字段 72 | `c18ea9aaff395fc15dead24004e52d7fc9339c617667cd240e4f2b079d7b2563` |
| 6394，外观关联导出 | 54 条外观 ID 与干员 ID 对应，字段索引 112/113；加密名称表未恢复 | `efacdce4b68c07df77ed86589b4a79159e22a643bfdb188c8e0dae3d98eb2d74` |
| 7154，`StoreMainTab` | 原生四页签 `HotRecommendation/StaffLottery/MandelLottery/WeaponSkinSales`，以及两个有条件的活动页签 | `bc952ca89fb4548e9ae7976e0c14c486303ac5978e91a6278a842fa8e5fab467` |

安魂对应 `20300008`，其奖励 `num_id=57` 的外观物品为 `30000060010`；条目 6394 将该外观关联至 `88000000029`。不能把安魂外观换成另一个奖池的 `30000060008`。飞虎礼包 `10104007` 中外观 `30000050013` 对应 `88000000025`，四个语音物品分别为 `38050050066/67/68/69`，不能把连字符配方当成一个新物品 ID。

协议消费者来自基础包 Lua。`StoreServer.lua`（SHA-256 `71987b0e506b13d19e57e813f64e09552482df76a17fe94302d91149f7d44d0e`）函数 `0.4/0.126` 等待配置、购买记录、主题时间和活动配置，并按真实 tab/goods ID 查客户端表；`0.145` 允许整包购买省略 `item_ids`。2026-10-01 02:19 的原客户端请求确认：全部付费皮肤已拥有时，整包请求可省略价格，以零价领取未拥有赠品；单买外观 `30000050029` 报价为原价 2210。服务按归属和原始配方核价，不接受客户端任意零价。

`StaffLotteryMainUI.lua`（SHA-256 `38f9665d38e53c4ac1af22494e9020045911edc834b45eee2aa9334f2c02f4a2`）函数 `0.10/0.27` 从已获奖励数量计算下一轮，并将不足的研究密钥购买放在 `buy_prop` 中。02:18 实机初始查询省略 `lottery_id`，需要返回全部研究奖池。`HeroServer.lua`（SHA-256 `6e56ce2b082124aceae30488055b866a29954869e8c4c8626efb24a49fc660be`）函数 `0.116` 通过 `CSHeroUnlockNtf` 更新外观归属；购买响应之前必须同步完整干员外观列表，装备另外保存并检查物品所属干员。

本地研究抽样使用字段 72 的权重，从剩余奖励中抽取；成本依次读取字段 69。获得核心外观时发放本池全部剩余配置奖励，历史与消耗在同一事务中保存。此抽样与离线开放时间属于明确的本地诊断规则，未恢复官方动态概率或活动排期。加密字段名仍未知，不宣称已完整还原原始概率表。

特供按已恢复的配置日期和限购执行。购买记录按 goods ID 合并，周限购只返回当周数量。尚未恢复武器外观装备映射、空间物品发货或支付方式的条目保留在提取目录供研究，不向客户端提供可购买报价。原版现金礼包在本地测试中校验原始商品标识后直接发放配置内容，响应禁止继续调用外部支付 SDK；不提交真实订单，不代表官方支付流程已恢复。

推荐页的 16 条奖池宣传项配方为空，但不是空商品。条目 7142 的字段 282 保存实际跳转目标字符串，例如安魂 `10210005 -> 20300008`。基础包 `pak-0-0-pakchunk1-WindowsClient.pak` 条目 1856 的数据类 `StoreRecommendItem.lua`（SHA-256 `3560dec1dce0c13e81bea6e4c036840f88bdc0341bfcf7c33312dad949793cc7`）函数 `0.2` 从服务响应读取 `jump_to`；`RecommendHomepage.lua` 函数 `0.27` 的 `banner_type=2` 分支转交该目标到商城页签事件。服务提供已恢复奖池的原始宣传项和目标，购买接口仍只接受实际商品配方。未恢复活动跳转的 `banner_type=3` 条目保持关闭。
