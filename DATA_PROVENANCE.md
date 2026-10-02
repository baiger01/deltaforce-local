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
| `safe_box_layout_catalog.json` | 当前安装基础包 `pak-0-0-pakchunk2-WindowsClient.pak` 条目 7056，PAK 偏移 50318377，以及已有命名 `PropSlotConfig` 导出 | `work/extract_safe_box_layout_catalog.py` 校验源哈希、38 行与尾标记，直接读取 UInt64 模板 ID、原始两尺寸和容量，逐 ID 与 GameItem 核对；保存原始字段索引和行偏移，非方形横纵方向未恢复。 |
| `weapon_preset_catalog.json`、`weapon_component_catalog.json` | 同版本明文武器配置与基础包 `pakchunk2-WindowsClient.pak` 的组件节点条目 4567 | `work/extract_weapon_preset_catalog.py`、`extract_weapon_components_catalog.py` 恢复预设、receiver 和组件树，目录保留实际来源与偏移。 |
| `weapon_ammo_catalog.json` | 基础包 `pakchunk2-WindowsClient.pak` 条目 4489/4555；热更新 PartsData/PartsFunction；基础包 Lua `cs_deposit_pb.lua` | `work/extract_weapon_ammo_catalog.py` 恢复弹药类别、已有弹匣容量与装卸弹枚举，交叉核对客户端 Lua 规则；未恢复的弹匣或武器关系保持未知。目录记录源哈希、行偏移与函数。 |
| `client_error_catalog.json` | 基础包 `pakchunk1-WindowsClient.pak` 的 `errcode_pb.lua` 条目 6809 | `work/extract_client_error_catalog.py` 只读恢复实际错误名与值；不以统一猜测结果码代替库存业务错误。 |
| `melee_weapon_catalog.json` | 当前安装 `DeltaForce/Content/Paks/pak-0-0-pakchunk2-WindowsClient.pak` 明文导出条目 7276 | `work/extract_melee_catalog.py` 读取 18 行中序列化字段索引 40/41 的外观 ID 与武器 ID。源文件 SHA-256 为 `e6ab2c414dc8b972b0f20b647a8deedcb39c82912d968209f057db469defb845`。15 组对应由原客户端 `MeleeWeaponSkinDataTable` 日志交叉确认；加密名称表未恢复，不能冒称已解出原属性名。每行保留偏移、GameItem 名称键与尺寸。 |
| `gun_skin_catalog.json` | 当前安装基础包 `pak-0-0-pakchunk2-WindowsClient.pak` 明文导出条目 7292 | `work/extract_cosmetic_catalogs.py` 从 1781 行恢复可与 GameItem 核对的 1776 条外观；序列化字段 1820/1792/1794/1812 分别关联外观、武器、预设和收藏开放标志。源 SHA-256 为 `03929c8c36ef4bd21de0e6262809095a863f3e65d6e44e8eefcf6ac57a59cce7`。本地提供 1514 条开放普通皮肤，曼德尔实例单独保存。 |
| `mandel_box_catalog.json` | 同一基础包条目 6764/6766/6768/7152/7134，以及已有 GameItem 导出 | `work/extract_cosmetic_catalogs.py` 保留 464 行箱体、558 行分组、3962 行奖励、11 项商城关联、5 项经验卡赠送配置及 34 种砖的 ConnectedPool。每行保留原始索引与偏移，各源 SHA-256 在目录头内；名称沿用客户端 GameItem 名称键。 |
| `premium_shop_catalog.json` | 当前安装基础包 `pak-0-0-pakchunk2-WindowsClient.pak` 条目 7142/7156/7152/6774/6394/7154 | `work/extract_premium_shop_catalog.py` 恢复推荐配方、礼包价格、干员奖池、奖励与外观归属、主页签。所有记录保留行号、序列化偏移；完整来源和限制见下节。 |
| `profile_cosmetics_catalog.json` | 当前安装基础包 `pak-0-0-pakchunk2-WindowsClient.pak` 条目 7110，`SocialAvatarDataTable` | `work/extract_profile_cosmetics_catalog.py` 恢复 2098 条社交外观 ID 与类别，字段索引 5213/5215；SHA-256 为 `50fe5c89e0ae53540ebf1a3df8cfca572b2c7558513516601f321fb12a7e8cbe`。原始行、偏移和解析数量完整校验；资源与开放时间仍由原客户端读取。 |
| `hero_customization_catalog.json` | 同一基础包条目 6614/6620/6624/6630/6632/6634/6636/6648/6660/6662；HeroData 条目 6628及礼包、研究配置 | `work/extract_hero_customization_catalog.py` 恢复 54 条服装、2049 条附件及默认标记。目录记录各表 SHA-256、行偏移、原始字段索引、独立奖励锚点和名称索引恢复方式；名称表仍加密，关联证据的不同强度见下节。 |
| `battle_pass_catalog.json` | 当前安装基础包条目 6358/6360/6362/6364/6368/6370/6372；原版 Shipping EXE 的结构注册、属性指针和成员偏移 | `work/verify_battle_pass_reflection_bindings.py` 先校验原 EXE SHA-256，再逐个 PE 节进行 raw/VA 映射；独立恢复 C++ 原属性名，并与原始 PAK 全部派生字段的序列、类型、长度和 FName 索引双向对应。502 行、131 个派生字段均通过后，`work/extract_battle_pass_catalog.py` 从原字段名生成价格、礼包和奖励；旧的顺序推断仅保留为已替代的来源记录。 |
| `weapon_pendant_catalog.json` | 同一基础包条目 6886 的挂饰表与已提取的 PartsData、GameItem 表 | `work/extract_weapon_pendant_catalog.py` 恢复 283 条真实 ID；本地普通挂饰提供策略要求两个可见布尔字段同时为真，80 条符合。原名称表仍加密，单个布尔字段名称未单独宣称恢复；神秘实例不凭空生成。 |

## 门卡基础表

`native_keycard_catalog.json` 的门卡来自当前基础包条目 6730 `KeyInfo`，334 条原行的地图与耐久字段通过原 EXE 的 `DFMKeyInfoRow` C++ 反射核验。`KeyFeature.lua` 使用表中 `Durability` 及物品 `health/health_max` 显示剩余次数；本地保存的零耐久不会被默认满耐久覆盖。条目 6726 `KeyBox` 的 109 行分区与条目 6728 `KeyBoxUnlock` 的 9 行解锁配置保留原字段和来源，物品位置 116、内容位置 116001 及分类限制由客户端配置确认。

`KeyBox.ItemID` 是序列化 FName，不能把包内索引当作数字物品 ID。现已从匹配哈希的原版 Shipping 进程只读解析配置：验证配置管理器、`GetDataTable` 接口、实际 RowMap 访问函数、分配位与 `KeyBoxRow` 字段偏移，再使用原生 FName 解码函数对应名称。`Key/KeyBox` 是原 Lua 消费的命名空间；它与 `KeyBox` 的 109 行逐项一致。`work/bind_native_keybox_catalog.py` 用 Index、MapID、初始槽数、四级槽数、BoxLength 八个标量的完整唯一指纹绑定 21 个 FName 组，保存源哈希与捕获哈希，不上传运行时指针或原始捕获。

104 行能对应现有 GameItem 的 20 个模板并用于布局；其余 5 行真实引用 `11120000011`，该模板不在当前 GameItem 目录，只作为证据保留。另有 6 个 GameItem 卡包模板没有匹配布局，继续拒绝，不按序号猜配。默认 `11120000001` 的 MapID 为 `[19,22,39,81,88,89]`，每区四格，总计 24；格子 ID 使用原 MapID，不能改成顺序编号。零到期权限与地图分区开放属于明确的本地测试策略，不代表官方账号归属。`KeyBoxUnlock` 名称绑定和扩槽写操作未恢复，当前只接受源表的初始可用格子。

## 安全屋与任务来源

`native_safehouse_catalog.json` 从当前安装基础包条目 7068 `SafeHouseFormula`、7072 `SafeHouseUpgrade` 恢复 492/73 行；`native_quest_catalog.json` 从条目 6930 `Quest`、6934 `QuestLine`、6940 `QuestRewards` 恢复 2365/13/5585 行。两个提取器按原版 Shipping EXE 的 C++ 结构注册逐列核验名称、类型、字段偏移与序列化索引；目录保留每张表的哈希、原行及偏移。消费者 Lua 直接从基础 PAK 读取并核验条目和哈希，克隆后重新提取不依赖旧 `work/evidence` 缓存。

生产只使用源 `MaterialList`、确定 `ProductList` 与原始时长。该中文安装的日期按 UTC+8 解释，避免服务器主机时区改变开放窗口；保存设备生产线，事务扣除实际持有材料，到期一次性领取实际产物。458 条受支持配方已在临时数据库验证生产、领取与库存通知编码。蓝图、首领解锁、随机产物及尚未关联物理 receiver 的预制枪械配方仍拒绝，不能先扣材料再让领取永久失败。

任务状态和 Mission 类型来自实际 `common_pb.lua` 枚举；普通任务接受按源任务线、等级、前置领奖与冷却保存真实目标，`QuestServer` 成功回调依赖 `CSQuestDataChangeNtf`，因此通知在接受响应之前发送。当前只实现普通 Mission 接受与查询；特殊任务类型、战局目标完成和任务领奖不由此响应伪造。

## 配件装配与通行证核验

2026-10-01 的原生测试中，四次 `CSMallSellReq` 返回 14026；每批都包含已装 30 发弹药的 MP5。旧服务拒绝任何装弹枪械，导致全部货物回滚。原版 `ShopServer.lua` 的 `CalcSalePriceForWholeItem`（函数 `0.131.0`，偏移 104516）递归计算组件与枪内弹药；`CheckIfHasPrice`（`0.115`，偏移 89229）与 `GetShopDynamicGuidePrice`（`0.121`，偏移 95753）令 `IsModelOnly` 组件价格为零。已核对默认组件树中的 159 个不同模板均为模型组件。修正后的出售事务只使用数据库保存的实例树计算上限，并删除实际组件和弹药；客户端请求不能添加虚构弹药提高回收价。具体回收单价仍采用本地目录价格，不宣称还原官方动态市场报价。

`work/probe_gunsmith_native.py` 只读校验磁盘 PE，并用查询和读取权限查看 shadow 进程中已加载的原始函数；不写入游戏代码。插槽类型、深度、ID 和父节点函数分别来自 RVA `0x507efd0`、`0x507f160`、`0x507f1e0`、`0x507f060`，完整读取段哈希记录在 `dfserver/socket_guid.py`。实际购买 GUID `281474976710710` 对应根槽 54，`72339069014645763` 对应路径 `(3,28)`；不能将后者误当成 `(3,0)`。实现保留原生 32 位移位与 63 位父节点掩码语义，自动装配仅使用已核实的 0～3 层路径。原 Lua 单件购买分支只发购买请求，没有后续装配请求，因此服务端必须原子完成购买和装配。拍卖变更原因采用原枚举 `AuctionBuy=18`。

通行证当前目录选用安装内最新季 `202604`，不能据此声称其为线上当前活动。原 EXE SHA-256 为 `4254fbe66585f260f1f9dbfc5e302887842552e7baed8939e023160a5e250be0`；11 个节均同名 `.std`，须逐节按地址范围映射，不能按节名合并或把后部节误判为 overlay。礼包 11 的原字段为等级 20、价格 640，Lua `MakeGiftRewardList` 根据当前会员类型计算新增等级奖励，购买请求不含 `buy_type`，因此不会顺带开启会员。扣费、奖励和领取记录在同一事务，提交后才通知客户端；60 级奖励 `13460040086` 经挂饰目录核对后进入收藏。日期使用持久化的本地诊断窗口，经验卡与当前季线索的未恢复关联仍拒绝写入。

`work/evidence/` 在迁移包中仅保留上述小范围表提取物，以便不重新扫描整套游戏就能复核目录。大型原始 PAK、原始 Lua 缓存、历史抓包及日志不在包内。同版本游戏在新电脑上按相对目录可重新读取；重新提取前请先核对游戏版本与目录头内的源文件哈希。`work/evidence/character_avatar_tables/` 中 GameItem 的 `.uexp` 约 35 MiB，已压缩进迁移包，毋须额外复制游戏素材。

交易购买、货币扣减、装备落位和弹药展示不仅依赖资源表，还依赖客户端请求及服务端状态链。物品表中的价格、模型和长宽不是完整商城售卖规则；地图资源存在也不是解锁条件。缺失规则应从客户端同版本配置和交互协议继续恢复，不能把目录行当成可购买或可用的证明。

2026-10-01 用户截图明确要求保留“感知强化剂”所在行及此前常规药品，移除其后特殊药剂与饮品。`QuickOperationLogic.lua` 函数 `0.1`（偏移 4916，SHA-256 `6c6f9c474a1d54b12e280bfc14b5b34cd463401340da8ba74cb3fe199b2db8fe`）按服务端售卖名单及开放状态把 `ItemHealth` 行加入购买页。因此仅有 `GameItem.InitialGuidePrice` 不能作为上架依据。新的 `medicine_sale_policy.json` 是按用户要求制定的本地可售范围，不是提取出的官方上架标志；`ItemHealth` 完整行及特殊药剂、饮品逐项中文映射尚未恢复，不将未知名称猜配到 ID。

原客户端 `DFMGlobalConst.lua` 条目 1882 的主类指令 1124～1126 定义 `Medicine=14`，子类指令 1206～1222 定义治疗、手术、止血、持续治疗、维修和注射剂类别；SHA-256 `4887a7f2b5265a5277c5c2553f4ff56ec08f1219a632220e3b2efa367baddcc4`。本地开放现有物品表中子类 2～6 的 22 件治疗、维修用品，注射剂仅开放已核对中文名称的 `14070000001/03/04/05/06/08/09`，共 29 件。ID 主类、子类取法来自 `ItemHelperTool.lua` 函数 `0.38/0.39`，不是 `ItemHealth.MedicineType` 的页面四分类；函数、偏移和哈希均保存在策略文件中。

八种注射剂的中文名由基础包 `pak-0-0-pakchunk2-WindowsClient.pak` 条目 7068 双重核对：492 行导出中的原字段索引 497 是中文 FString，515 是物品 UInt64，516 的输出字符串含相同 `ID:1;`；每种还有一行重复产物记录。源 SHA-256 为 `b26f25dd754180c442e141e64fc19c2cdaa487347686c0bdb8779f7fffbcfa33`，所有行号与偏移保存到策略文件。`14070000006` 是保留的“体能激活针”，`14070000007` 是用户要求下架的“体能强化剂”；不得混淆。`work/verify_medicine_sale_policy.py --payload <条目7068导出文件>` 实际验证了 16 行中文、ID、产物字符串及源哈希。购买目录、报价和成交共用受限名单，回收计价仍按原物品目录及实际归属验证；不删除已有物品。

## 安全箱与仓库整理

条目 7056 的 SHA-256 为 `67e8779e53eba3eaaad941d177ad9baf4e49e06a83d3384438132d5ad9154480`，UInt64 字段索引 51 直接给出模板 ID，Int 字段 48/49 是两尺寸，62 为容量；38 行容量均等于两尺寸乘积。表名 `SafeBoxFunc` 由 1109 物品集合及客户端布局消费者支持，但加密名称表未恢复，不将数字字段冒称原属性名。`11090000002` 行偏移 269 为 2×2，`11090000004` 行偏移 665 为 3×3。本地测试账号提供这两个已验证真实模板的永久权限，`expire_timestamp=0`；这是本地账号策略，不是官方免费归属。其余非方形尺寸保留为原始 A/B，不猜测坐标方向。

命名 `PropSlotConfig` 导出 SHA-256 为 `1e1cfe1bd65be0b8a3bfb1eb5511e748e3adf8e17feffbb645b63bb6c499c830`：装备槽 109 行偏移 4052，内容槽 109001 行偏移 30431，后者 `bIsContainerByItem=true`、静态 0×0。内容限制采用此行的真实 `IgnorePropTypes` 前缀/具体 ID，并保留 GameItem 的安全箱标志检查；未恢复的 `UncarryableItem` 白名单、价值等规则不能宣称已完整实现。多个安全箱权限共用装备位 109 和内容位 109001，不是多个仓库页。

`ItemOperaTool.lua` SHA-256 `40de2bf2c60e09661ab4ac24e1bb0768719fbdc09bf71b12dc1645f0395a4892`，`DoPlacePermissionItem` 函数 `0.29`、偏移 26759，只发送 `prop_id/target_pos`。权限通过已认证账号查找，不能按缺失 gid 拒绝，也不能把权限箱当普通商品移出。`InventoryServer_Network.lua` SHA-256 `d7f83db2ae2cf4902b440131c15648c7b7d4b8b8f5e459231b9eb6ec17dcb0dc`，函数 `0.13`、偏移 15938 读取权限，`0.40`、偏移 35142 先处理位置变更，`0.50`、偏移 53269 优先按 `src_prop_id` 生成客户端布局。切换响应下发内容位 109001 的 Modify=3、真实模板及旧装备删除/新装备加入，随后刷新内容位置。`EquipmentFeature.lua` SHA-256 `f9be61db7cfc5a4bb3cc00e88bf3f51ea2c01dbfbbf6753d27d1e76dc0cb0600`，函数 `0.38/0.39/0.40`、偏移 16081/16335/16495，证明零到期值可永久使用，负值才标记免费，正值必须未过期。

原版整理设置请求是 `CSDepositSetCommonConfigReq`。`InventoryServer_SortLogic.lua` SHA-256 `b179130620dd63e41128c69218ad334535aa40e40990d6855933beeb6370bcd9`，`0.1`、偏移 1199 发送 `CSDepositSortMultiplePosReq`，回调 `0.1.0`、偏移 1619 消费 `changes` 后提示成功；`0.2`、偏移 3255 发送设置和 `extension_pos_order`。旧实现返回成功但空变更；现主仓库页 2 按命名模板的 9×40 格执行确定性落位并持久化，保存实例与旋转，失败整笔回滚。`sort_style=0/1` 与八个分类枚举来自 `common_pb.lua` 根函数，SHA-256 `81e071e35f33f0e5704d5098ac2a182c794bbe5b1e5a7e24f415a0473b40350b`；分类顺序已保存，但原 `DepositSortClass.ItemTypeID` 的字段关联尚未验证，当前分类模式仅按同模板分组，不声称复现官方分类及服务端整理算法。

`WarehouseWithTab_HD.lua` SHA-256 `6442714ffa908c79db4807438021da7be437559d71940b228e56517b0a212cac`：`_OnExtArrangeBtnClick` 函数 `0.61`、偏移 46636，单仓库且无钓鱼仓库时直接整理，多仓库进入选择；`_StartExtArrange` 函数 `0.62`、偏移 48113 绑定确认/取消/全选；`_OnConfirmExtArrangeBtnClicked` 函数 `0.67`、偏移 57653 将选择映射为真实仓库页 ID 再提交。仓库扩容 ID 算法来自 `InventoryServer_DepositLogic.lua`（SHA-256 `594f6ef7896cae11051fd67d365160af4afb699b51c0febb794e7c9dc588bb84`）函数 `0.17/0.18/0.20/0.21`、偏移 10182/10329/10632/11243；模板槽 1001 不能当成已拥有扩容页。扩容配置和分类表候选尚缺命名字段的独立对应，不生成假扩容页，不宣称多仓库分类整理已恢复。

2026-10-01 11:29 的原客户端试验捕获了 34 次 `CSDepositEquipPropReq`。请求序号 1821 的 `spec_loc` 指定胸挂分区 5、`start_x=1`，省略默认的 `start_y=0`；1843 反向省略 `start_x=0`。序号 1903 同时指定 `target_prop_gid`，属于交换，不能只移动源物品。旧实现遇到省略的坐标改为自动落位，并忽略容器内交换目标，随后四次 `CSDepositAssemblySyncBodyContainerReq` 在胸挂分区 5 出现两件物品同占 `(0,0)`，数据库副本重放确认拒绝原因为 `POSITION_OCCUPIED`。现在保留明确位置的零坐标及旋转，交换两件实际拥有的实例，无法容纳时整笔回滚；不接受重叠快照，不删除物品来绕过错误。

上述字段来源为 `EquipPropCommand` 的 `target_prop_gid` 字段 6、`spec_loc` 字段 10，以及 `PropLocation` 的 `start_x/start_y` 字段 2/3、`rotate` 字段 7。来源 Lua 的 SHA-256 分别为 `9e0e59f87781ec6184a52b3cf09e661084945b1330ecc0bc8c4e671c1a364d01`（`cs_deposit_editor_pb.lua`）与 `5fe89634d480907ba0f4657ef699151e147594750ddba37247a50d718ac8b753`（`ds_common_editor_pb.lua`）。`InventoryServer_Network.lua` 函数 `0.43/0.44`（序列化偏移 44387/45587）分别按响应移除源位置、设置目标位置；SHA-256 为 `d7f83db2ae2cf4902b440131c15648c7b7d4b8b8f5e459231b9eb6ec17dcb0dc`。位置冲突改用已提取错误目录中的 `DepositSpaceHasOccupied`，不再笼统归为 `DepositInternalError`。

`ItemLocationDefine.lua` 函数 `0.5` 的指令 10～11 将协议 `loc.rotate` 直接赋给 `bRotated`；`ItemBase.lua` 函数 `0.76` 的 `IsRotated` 读取此位置状态。仓库中非方形物品旋转后，除存档尺寸外，移动与库存重取响应也必须返回保存的旋转标记。独立审查在临时数据库复现旧响应固定为 `False` 的问题；修正后加密接口用例验证 3×1 医疗物品旋转、重新拉取和后续移入胸挂的方向一致。

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

2026-10-01 客户端日志出现 `ShopLotteryDataTable` 找不到 `MandelItemId=16110000001`、随后 `MandelDrawOnly` 读取空奖池。该物品存在于基础物品目录，但没有原版 `StoreLottery` 的商城关联，不能因 ID 前缀相同而上架。现在购买列表只接受 `16110000014`、`16110000017` 至 `16110000026`，共 11 个实际商城关联；每项同时核验 `MandelItemId`、箱体及奖励分组。已有旧物品保留原 ID，不假造旧 ID 到新奖池的映射。

普通外观归属是本地测试账号的提供策略。外观 ID、武器 ID 和预设关联来自客户端目录；`ItemHelperTool.lua` 函数 `0.40/0.60` 的 ID 分类规则用于区分普通与曼德尔外观。没有把未恢复的挂饰、花纹、磨损或材质 ID 写入账号。曼德尔奖励实例使用客户端 `CollectionServer.lua` 函数 `0.11.3/0.206` 明确支持的 `appearance.id=0` 默认查表分支；该值是客户端哨兵，不是假造 AppearanceID。

`MandelDrawOnly.lua` 函数 `0.5` 通过 `GetCollectionPropById(GetKeyID())` 读取密钥，因此 `32320000001` 必须作为收藏道具下发。该提取物 SHA-256 为 `f02cd1f699e83b7884bdf0a40f5b494600ceff39d26e055354dd641a86b01118`。`CollectionServer.lua` SHA-256 为 `30fd97e50c22998e987b1fdcf8ee7a0e4edfe1ae51b93dc1d6e11ff5e7bf37f2`。商城条目 7134 的字段 19/11/21/9/20 对应赠品、货币、价格、商品、赠送数量；实际购买商品是 `32210000004` 武器次级经验卡，每个 60 三角币，附送一个量子密钥。密钥请求的 `price` 是该次经验卡购买总价，砖请求的 `price` 是单价，二者由原客户端实际请求交叉确认。旧密钥货币记录在同一个 SQLite 事务中迁移为收藏数量并删除旧记录，重复启动不会再次赠送。

`StoreServer.lua` 函数 `0.119.0` 成功回调直接执行后续扫描；`MandelDrawOnly.lua` 函数 `0.36` 会再次检查收藏数量。因此本地购买先发送 `CSCollectionPropChangeNtf`，随后发送购买响应，保留请求业务序号并递增外层包序号。

`CollectionServer.lua` 的 Add 分支按物品 ID/gid 替换当前栈，不把 `prop.num` 当增量累加。重复购买必须下发交易后的总量，`delta` 单独表示本次购买数；重连加密接口用例验证两次各买 10 个密钥后，通知与数据库均为 20。

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

安魂对应 `20300008`，原表全局行 ID（字段 73）为 `57` 的奖励包含外观物品 `30000060010`；条目 6394 将该外观关联至 `88000000029`。协议 `num_id` 使用字段 81 的池内 `SortIndex=1`，不是全局行 ID。`StoreServer.lua` 函数 `0.83` 按 `LotteryId/SortIndex` 查表，`StaffLotteryMainUI.lua` 函数 `0.13` 按奖励表长度判断已领完；返回稀疏的全局 ID 会使 Lua 长度为 0，误显示已获得全部奖励。八个池均返回原表池内序号 1～8；旧存档全局 ID 在读取时映射，不再次发奖或扣费。不能把安魂外观换成另一个奖池的 `30000060008`。飞虎礼包 `10104007` 中外观 `30000050013` 对应 `88000000025`，四个语音物品分别为 `38050050066/67/68/69`，不能把连字符配方当成一个新物品 ID。

推荐图的本地路径不可用时，原客户端会使用 `HotRecommendationPropDesc` 的四个 CDN 字段（协议编号 20～23）：`IamgeSourceSmall_CDN`、`IamgeSourceBig_CDN`、`ImageSourceLogo_CDN_CN`、`ImageSourceLogo_CDN_EN`。对应源表序列化索引为 274/272/276/277，保留原始 `Resource/Store/` 地址和扩展名，不编造图片路径。`StoreRecommendBanner.lua` 函数 `0.10` 与 `RecommendHomepage.lua` 函数 `0.30` 调用 `LuaSubsystem:CheckPathValid` 检查本地图后再选择 CDN。条目 `10102077` 没有任何本地或 CDN 地址，故不作为可见推荐，但保留原始目录和历史购买记录。其余条目有资源引用并不证明本机素材已成功加载，仍须原客户端验证。

曼德尔页签的奖池也必须带开放时间：`StoreLotteryItem.lua` 函数 `0.2` 保存 `begin_time/end_time`，`StoreServer.lua` 函数 `0.101` 筛掉未开放的池，主页面在列表为空时隐藏页签。11 个曼德尔池使用与干员研究相同的本地诊断开放窗口；这是本地开放策略，不代表官方活动轮换。

协议消费者来自基础包 Lua。`StoreServer.lua`（SHA-256 `71987b0e506b13d19e57e813f64e09552482df76a17fe94302d91149f7d44d0e`）函数 `0.4/0.126` 等待配置、购买记录、主题时间和活动配置，并按真实 tab/goods ID 查客户端表；`0.145` 允许整包购买省略 `item_ids`。2026-10-01 02:19 的原客户端请求确认：全部付费皮肤已拥有时，整包请求可省略价格，以零价领取未拥有赠品；单买外观 `30000050029` 报价为原价 2210。服务按归属和原始配方核价，不接受客户端任意零价。

`StaffLotteryMainUI.lua`（SHA-256 `38f9665d38e53c4ac1af22494e9020045911edc834b45eee2aa9334f2c02f4a2`）函数 `0.10/0.27` 从已获奖励数量计算下一轮，并将不足的研究密钥购买放在 `buy_prop` 中。02:18 实机初始查询省略 `lottery_id`，需要返回全部研究奖池。`HeroServer.lua`（SHA-256 `6e56ce2b082124aceae30488055b866a29954869e8c4c8626efb24a49fc660be`）函数 `0.116` 通过 `CSHeroUnlockNtf` 更新外观归属；购买响应之前必须同步完整干员外观列表，装备另外保存并检查物品所属干员。

本地研究抽样使用字段 72 的权重，从剩余奖励中抽取；成本依次读取字段 69。获得核心外观时发放本池全部剩余配置奖励，历史与消耗在同一事务中保存。此抽样与离线开放时间属于明确的本地诊断规则，未恢复官方动态概率或活动排期。加密字段名仍未知，不宣称已完整还原原始概率表。

特供按已恢复的配置日期和限购执行。购买记录按 goods ID 合并，周限购只返回当周数量。尚未恢复武器外观装备映射、空间物品发货或支付方式的条目保留在提取目录供研究，不向客户端提供可购买报价。原版现金礼包在本地测试中校验原始商品标识后直接发放配置内容，响应禁止继续调用外部支付 SDK；不提交真实订单，不代表官方支付流程已恢复。

推荐页的 16 条奖池宣传项配方为空，但不是空商品。条目 7142 的字段 282 保存实际跳转目标字符串，例如安魂 `10210005 -> 20300008`。基础包 `pak-0-0-pakchunk1-WindowsClient.pak` 条目 1856 的数据类 `StoreRecommendItem.lua`（SHA-256 `3560dec1dce0c13e81bea6e4c036840f88bdc0341bfcf7c33312dad949793cc7`）函数 `0.2` 从服务响应读取 `jump_to`；`RecommendHomepage.lua` 函数 `0.27` 的 `banner_type=2` 分支转交该目标到商城页签事件。服务提供已恢复奖池的原始宣传项和目标，购买接口仍只接受实际商品配方。未恢复活动跳转的 `banner_type=3` 条目保持关闭。

账户社交外观使用 `CSCollectionUnlockAvatarsReq` 查询实际收藏归属，`CSAccountUpdateAvatarReq`、`CSPlayerUpdateMilitaryTagReq`、`CSPlayerUpdateTitleReq`、`CSPlayerUpdateHonorMarkReq` 更新装备。登录与重连通过 `pic_url/military_tag/title/honor_mark` 恢复，头像按原 `AccountServer` 用法返回 ID 的字符串。`RoleInfoServer.lua` 函数 `0.19` 在收藏通知含社交物品时重新查询归属，`0.20.0` 遍历原表构建已获得和锁定列表；不用把全目录赠送给账号。`SocialChangeTitle.lua` 函数 `0.19` 明确以 ID 0 卸下称号或徽记，SHA-256 为 `a49b991f716d0fc5c61d2b3860901aee4490b985fbf19bfa6c3f385fe4eee760`。未知 ID、错误类别或其它账号拥有的物品不能装备。

## 干员自定义

`HeroServer.lua` 函数 `0.18.0` 从 `CSHero.fashion_list/accessories` 建立列表；客户端不会补齐服务省略的服装或附件。`HeroWatchMainPanel.lua` 函数 `0.2` 将本地手表配置与服务器附件列表求交集，原先没有 `accessories` 就会显示空页。现在提供适用于每个干员的完整锁定和已拥有列表，仅实际收藏或原生默认标记解锁；获取服装、手表、名片、语音等后先通知对应干员，再执行购买回调。

详情筛选不等于名单筛选。`HeroServer.lua`（SHA-256 `6e56ce2b082124aceae30488055b866a29954869e8c4c8626efb24a49fc660be`）函数 `0.19` 分批发送 `hero_id_list/filter_by_id`；回调 `0.19.0`（偏移 27911）仍以响应 `hero_ids` 替换完整名单，再由 `0.17`（偏移 21702）删除名单外的干员、服装与附件缓存。`0.100`（偏移 85369）在服装缓存被删除时返回套装 ID 0。服务现仅筛选 `heros` 详情，所有加载响应保留完整 17 个 `hero_ids` 和账号选择字段；加密响应回归覆盖全量加载后的单人及空详情刷新，按原消费者规则验证名单、所选干员与服装缓存仍保留。

2026-10-01 11:12:55 原客户端 `CSHeroEquipFashionReq` 序号 823 为干员 `88000000029` 装备 `30000060010`，`new_fashions` 只带 `id`，省略默认值为 0 的 `slot`；旧校验将省略字段视为 -1，返回原错误码 `117302`。`HeroFashion` 来自 `ds_common_editor_pb.lua`（SHA-256 `5fe89634d480907ba0f4657ef699151e147594750ddba37247a50d718ac8b753`），字段 1 是 `slot:uint32`。现按已核实的 `FashionSuit=0` 处理省略值；真实请求编码回归验证抽奖外观可装备并重读保存，非零槽位及未拥有服装仍被拒绝。

原版使用按钮的“正在使用”表示已装备：`HeroConfig.lua`（SHA-256 `3fb52f24168638c364fffb8d2840e60ef441c814b2310841324f73d53c5a3be1`）常量 196～198 将 `Using/Lua_Hero_Text_Using` 对应到此文字。`HeroAppearancePanel.lua`（SHA-256 `51f629c7c3ba80c5ac1aee6814c4b7231d7b5f69f21e131514f14fa63e47f450`）函数 `0.27`、偏移 26458 依据 `item:SetOperated()` 选择“正在使用”并禁用按钮，未装备时显示“使用”；成功回调 `0.27.0.0`、偏移 27867 刷新按钮和当前外观。2026-10-01 11:30～11:31 原客户端三次分别装备 `30000020004/30000040007/30000060010` 并同步处决，响应均成功；用户截图基础套装已装备的绿色圆点与禁用按钮一致。原版已装备状态与当前服务响应一致。

套装位置 `FashionSuit=0` 来自基础包 pakchunk1 条目 6801 的 `ds_common_pb.lua`，SHA-256 为 `6f1bec3a236dbd47c28d932a2702bc8cc386ecb6119312d71d57a62d6e8b8f6b`。`DFMGlobalConst.lua` 条目 1882 提供实际附件类型，SHA-256 为 `4887a7f2b5265a5277c5c2553f4ff56ec08f1219a632220e3b2efa367baddcc4`。`HeroHelperTool.lua` 函数 `0.89/0.90` 判断默认附件与通用归属；`HeroServer.lua` 函数 `0.68` 的喷漆、展示动作、手势和语音共享槽位规则用于保存装备。处决与服装的限制来自原表字段 50及八个研究池中的皮肤/处决对应，由 `HeroHelperTool.lua` 函数 `0.139` 交叉核对。

加密 Hero 名称表没有解密。目录逐关联标记 `independent_bundle_anchor` 或 `numeric_fname_order_reconstruction`：前者有原礼包或研究奖励及干员对应的独立见证；后者由本安装 44 份明文名称表一致的数字名称字典序、HeroData 的 23 个实际干员 ID 锚点及连续索引范围恢复。两类证据不能混称完整原始名称表。每个见证均记录条目、行、偏移与实际 ID；主物品 ID 必须与已有 GameItem 名称键相符且在所有有效匹配中唯一。

默认服装用 17 套已核对 UI 模型家族的对应，避免同名换色行被错当默认解锁。未恢复命名来源的击杀语音类型 10、战局技能装备类型 11及 `CSHero.sol_expert_data` 技能关联没有编造。完整干员目录约 358 KiB，原服务 64 KiB 默认策略会阻止出站编码；仅目录与解锁通知提高到 1 MiB，接收限制保持原值。端到端用例验证真实加密响应、研究奖励到外观与手表装备，以及数据库重开后的恢复。

`CSHeroGrowLineRewardViewReq` 被原通用查询处理器的动词过滤拒绝，导致每次加载干员后发出的预览查询没有响应。`HeroServer.lua` 函数 `0.22/0.22.0` 将响应的 `hero_id/rewards` 保存为成长界面的预览缓存，不更新收藏或装备。当前本地未配置成长奖励，因此仅为 17 个已支持干员返回明确的空预览，未知干员使用原错误码；查询不改进度、不发奖。基础包条目 6644 的 153 行 HeroLevel 数据中，两组数组全部为空，字段 171 的目标 ID 不是 GameItem 奖励 ID。非空成长奖励来源仍未恢复，不能宣称成长奖励系统已实现。
