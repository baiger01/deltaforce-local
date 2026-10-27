# 地图难度、模式与准入生产链

2026-10-21，北京时间。只读原安装、既有代码缓存和当前地图服务端源码；没有启动游戏、读取进程、发包或访问账号数据库。本轮找到六图的实际模式组合、原始枚举、独立难度字段及准入消费者，也确认默认发布目录没有接齐这些数据。这里没有发布新的地图或难度。

**后续更新：** [独立难度语义补查](GAMEPLAY_MAP_DIFFICULTY_MAPPING_20261021.md)已从RecruitConfig、ArmedForceConfig和实际board消费者闭合 `1=常规、2=机密、3=绝密` 及其与sub10/11/12的关系。下文关于“独立difficulty与本地化对应尚未恢复”保留原采样背景，以该补查为准；当前官方board的动态开放和准入值仍未取得。

复核工具：[research_map_difficulty_20261021.py](../work/research_map_difficulty_20261021.py)；[JSON 证据](../work/evidence/gameplay-map-difficulty-research-20261021.json)。原 EXE SHA256 `4254fbe66585f260f1f9dbfc5e302887842552e7baed8939e023160a5e250be0`，代码缓存 manifest `dfd5c279d7db45842cee2bbc485ac8bf3cab03e4249ef5fe36bc9e8d6cd14754`。

## 1. 原版难度相关数值有两个域

[原始枚举定义](GAMEPLAY_MAP_ENUM_RESEARCH_20261021.md)从原 PAK 的 `@ds_common_pb.lua` 恢复实际赋值：

- `MatchSubMode.SOLPMC=10`。
- `MatchSubMode.HighYieldSOLPMC=11`。
- `MatchSubMode.ExtremeHighYieldSOLPMC=12`。

GameModeServer 的 `CheckIsSOLLowValue/CheckIsSOLMiddleValue/CheckIsSOLHighValue` 分别引用上述成员；夜战、洪水等还有独立成员。不是根据模式 ID 的十进制位数猜难度。

**`MapBoardInfoDesc.difficulty` 是另外的业务字段，不能填成10/11/12。** 原安装 `cs_solo_editor_pb.lua` 的 decoder0.40/encoder0.41 给出字段16、u32；source SHA256 `cfbba56c8e69f8f3e5a168817371da44d6fba16bb97a7e0fff118acd557fc63a`。GameModeServer0.107（1583–1636）按当前 match_mode_id 从服务器 board 条目返回 difficulty；0.143（2446–2465）按 `point_id -> sub_mode -> match_mode_type` 保存整条条目，再按独立 difficulty 建入口索引。

本轮恢复了普通/高收益/极高收益的原始模式枚举，尚未恢复独立 difficulty 字段的官方发布值、全部本地化标签及其映射。不能把玩家提到的“普通、机密、绝密”的显示顺序推导成另一套枚举，或仅改标签就宣布难度接通。

## 2. 六图实际模式组合

重新校验原安装257个PAK、1174183条目录记录及全部主/次索引；完整解析 MapConfig640行、MatchModeDataConfig424行、WorldEntranceConfig18行、SubWorld81行，再按实际 MapID/LevelName/SubWorldName 连接。六个地图族有82条模式记录，其中32条满足 `GameMode1 / GameRule4 / MatchSubMode10、11、12`。它们包含单人、训练、Long3和区域变体，不能全部发布为正式难度。

下列是主要 Level1/2/3 的三人配置，枚举名称按上一节。时长是 MapConfig 秒数；倍率是门卡**耐久**消费的地图配置，不能扩成所有数量消耗均乘倍数：

- **长弓溪谷 / Forrest**：`141901103 -> Map1901 / Forrest_Level1 / sub10 / 2100秒 / 倍率1`；`141902113 -> 1902 / Forrest_Level2 / sub11 / 2100秒 / 倍率2`。本集合没有其 sub12 对应行。
- **零号大坝 / Dam_Iris**：`142201103 -> 2201 / Dam_Iris_Level1 / sub10 / 1800秒 / 倍率1`；`142202113 -> 2202 / Dam_Iris_Level2 / sub11 / 1500秒 / 倍率2`。不能把两个档位均设置1800秒。
- **航天基地 / SpaceCenter**：`143901113 -> 3901 / SpaceCenter_Level1 / sub11 / 1800秒 / 倍率2`；`143902123 -> 3902 / SpaceCenter_Level2 / sub12 / 1800秒 / 倍率4`。该主要组合不含 sub10。
- **巴克什 / Brakkesh**：`148101103 -> 8101 / Brakkesh_Level1 / sub10 / 1800秒 / 倍率1`；`148102113 -> 8102 / Brakkesh_Level2 / sub11 / 1800秒 / 倍率2`；`148103123 -> 8103 / Brakkesh_Level3 / sub12 / 1800秒 / 倍率4`。
- **潮汐监狱 / Tide**：`148801103 -> 8801 / Tide_Level1 / sub10 / 1800秒 / 倍率1`；`148802113 -> 8802 / Tide_Level2 / sub11 / 1800秒 / 倍率2`；`148803123 -> 8803 / Tide_Level3 / sub12 / 1800秒 / 倍率4`。
- **AZ-5**：`148901103 -> 8901 / AZ-5_Level1 / sub10 / 1800秒 / 倍率1`；`148902113 -> 8902 / AZ-5_Level2 / sub11 / 1800秒 / 倍率2`。本集合没有其 sub12 对应行。

每条的 mode/map 原始行偏移和全部实际字段在 JSON `family_mode_matrix`；SubWorld 的规则类、子系统引用与世界路径保留在表记录。Tide、AZ-5 有专属规则/子系统，不能一律套用大坝实现。以上证明该安装基线中有这些静态合同，不证明每条当前开放、资源均完整、服务器已发布或实际已进图。

## 3. 选择难度还依赖准入条目

原版 `GameModeServer.lua` SHA256 `c4ced93f1059d9cb8f91874a1d0084090d4263a95d443dcd7d9101548088e381` 已重新解析到EOF；本轮保留18个明确消费者：

- 0.140/0.141 发起 `CSPrepareMapBoardReq`；成功回调将 `board_info_array` 交给分类消费者。
- 0.142 分开保存普通、night、flood等条目；0.143 按 point、sub_mode、match_mode_type 索引，不能用同一个模式覆盖全部难度。
- 0.106（1572–1579）要求对应条目的 lock_reason 为 MapOpen，且 seasonLevel 达到 need_level。
- 0.119/0.120 从具体 match_mode_id 或 map_id 找对应条目的 need_level；Boss 分支另取 boss 限制。
- 0.121 从实际 board 条目取 hafcoin_admission_tickets；字段缺省时有原客户端回退，但不构成“官方门票为0”的来源。
- 0.131/0.132 读取 equip_limit_lv，挑战模式另向 LobbySOLChallengeServer 取装备要求，不能把不同 GameRule 合并。

除 difficulty16 外，原版 MapBoardInfoDesc 还包括 need_level20、equip_price21、is_open22、is_show23、match_mode_type33、hafcoin_admission_tickets35、equip_limit_lv36、equip_level_limit38、carry_in_limit41、装备/物品禁用列表和时段字段。字段号、类型和 encode/decode PC 同时保存在证据的 schema 记录及原始0.40/0.41指令中。结构存在不代表已恢复每个官方准入值。

WorldEntrance、MapID与point_id的命名空间保持独立。原表入口13指向Map76/TestAIMap_Mobile，不能为补巴克什入口而借用13；发布point与各难度的关系须来自原响应或明确本地发布策略。既有大坝point1的来源不能推广给其它图。

## 4. 当前实现为什么没有接齐

本轮快照直接读取地图 checkout 的默认 `protocol/local_map_board_candidates.json` 和 `dfserver/handshake_diagnostic.py`，字节hash及函数起止行在 JSON `current_publication`。

默认目录仅两条 operation：均 `point_id1 / Map2201 / match_mode142201103 / sub10 / min_level1`，match_mode_type分别1与3。这是同一地图模式的两个类型，不是两个难度，更没有完整六图档位。环境变量可以替换目录，本轮没有读取运行进程环境，因此不将默认文件直接当成所有实机响应。

当前 `_candidate_local_prepare_map_response` 发送 mode、need_level、is_open、is_show、lock_reason、match_mode_type，另取已配置TOD；**没有显式发送difficulty**，也没有补齐装备价值、门票、各类装备/携带限制及官方开放条件。season level 与目录min_level的比较只覆盖一个局部条件。protobuf的缺省值不能替代正确的难度和准入条目。

即使把列表显示补全，入局仍必须冻结所选 `point/map/match_mode/sub_mode/difficulty/team/GameRule` 与限制、时段、消耗策略，绑定对应SubWorld/规则/时长/门卡倍率/任务/出生/物资/AI/撤离，再将同一合同用于终局与重连。当前只验证了默认目录与响应构建，没有将本轮静态表直接安装到生产流程，也不宣称所有准入校验完全不存在。

## 5. 精确剩余依赖与复核

可以据此继续实施的来源已经明确：六图真实mode/map行、submode定义、客户端条目分类与准入消费者。仍缺独立difficulty官方发布值、未观察入口的point映射、实际生效overlay和各模式动态开放/门票/装备门槛，以及每个世界的可执行资源和同局权威流程。现有静态表不能补造这些值。

```text
.venv/Scripts/python.exe -X utf8 -B work/research_map_difficulty_20261021.py --verify --compact
```

完整提取和第二次重放均exit0；重放比较原表、Lua消费者、当前默认目录、当前响应源及生成schema。结果为82条地图族模式、32条10/11/12基线记录、默认发布2条、difficulty未显式发送。此为来源复核，没有进行地图难度实机验收。
