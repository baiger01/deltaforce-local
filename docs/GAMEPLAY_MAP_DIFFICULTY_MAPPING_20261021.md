# 地图独立难度值与显示语义补查

2026-10-21，北京时间。本轮继续读取原安装PAK，不启动游戏、不读取进程、不发包、不访问账号，也不修改协作者生产源码。本报告补齐上一轮未恢复的独立难度语义；当前官方服务器实际发布的开放条件仍未取得。

## 1. 已恢复真实赋值

原 `RecruitConfig.lua` 的顶层函数0，PC691至744连续赋值，明确给出：

- `TargetId2Text[1] = 常规行动`，`[2] = 机密行动`，`[3] = 绝密行动`。文本通过真实NSLOCTEXT namespace/key登记，本轮静态记录参数，没有执行调用。
- `TargetId2SubMode[1] = MatchSubMode.SOLPMC`，`[2] = HighYieldSOLPMC`，`[3] = ExtremeHighYieldSOLPMC`。
- 原 `ds_common_pb.lua` PC139至141的实际成员值分别为10、11、12。因此独立难度/目标值与普通SOL子模式的配置关系是 `1 -> 10`、`2 -> 11`、`3 -> 12`，不是两个字段共用枚举。

第二处独立定义在原 `ArmedForceConfig.lua`：PC2591至2592创建Loc，PC5355至5396构造ModeDifficulty，PC5954挂回配置。键值为 `-1=无`、`0=默认`、`1=常规`、`2=机密`、`3=绝密`。后两个特殊文字不构成服务器应当发布这些难度的证明。

两份原chunk均来自 `pak-0-0-pakchunk1-WindowsClient.pak`：RecruitConfig entry25903104，SHA256 `fb416d821d3db47055abf3ea2464cbd12cf454891beb9a5cb73cb0e6bd27a29c`；ArmedForceConfig entry11460608，SHA256 `099b45b57a4d1571e5b7888085130a0b3d4beee43a68c16cebe753c235f2bd58`。子模式定义和完整指令另见[枚举报告](GAMEPLAY_MAP_ENUM_RESEARCH_20261021.md)。

## 2. 与实际board字段的连接

只看到本地化表不足以确认用途。本轮同时核对以下消费者：

1. `GameModeServer.lua` 函数0.143 PC40至56从实际board条目读取 `difficulty`，按 `point_id -> difficulty` 保存整条条目；0.105返回该入口的难度键集合。
2. `RecruitLogic.lua` 函数0.72，源码行831至844，形参明确为targetId、selectedMapIDs。它从GameModeServer.GetEntranceDifficulty取得真实键，比较 `targetId == difficulty`，并检查同一入口/难度的解锁条件。不是把另一个AI难度值拿来贴文字。
3. `RecruitLogic.lua` 函数0.89 PC200至218遍历所选difficulty，调用IsTargetAvailable，再用 `TargetId2SubMode[difficulty]` 组装match_sub_mode；PC223至248以入口、该子模式和type3查询实际board条目并读取match_mode_id。这里闭合了难度目标、子模式与服务器候选的消费关系。
4. `GameModeServer.lua` 0.107仍按所选match_mode_id返回实际条目的difficulty。不能仅根据地图名或客户端静态模式ID自行决定服务器开放列表。

RecruitLogic原chunk SHA256 `1e6b53ce9a568d2b7174c9fcac13bb105c66cf87e0834266a727197b0968204f`。五个完整chunk的原entry与SHA256、三处定义片段、六个消费者函数、局部变量名和完整指令均保存在[映射证据](../work/evidence/gameplay-map-difficulty-mapping-20261021.json)。

## 3. 对六图与当前代码的影响

结合[上一轮真实map/mode关联](GAMEPLAY_MAP_DIFFICULTY_RESEARCH_20261021.md)，该安装的主要三人SOL静态组合可明确表达为：长弓溪谷和大坝有常规/机密；航天有机密/绝密；巴克什和潮汐监狱有常规/机密/绝密；AZ-5有常规/机密。此处是原配置与显示语义的连接，不是当前所有档位开放或地图已可玩的声明。

当前默认目录仍只有大坝sub10，响应仍未显式填独立difficulty；本轮没有修改该实现。现在可以按来源修正“拿10/11/12填difficulty”的错误做法，但每个发布条目的point、模式、档位、等级/装备/门票/携带限制、时段仍须一并来源限定。

`WorldEntranceConfig.Difficulty` 不能代替逐条board的difficulty：原表本身包含大坝入口1的静态值1、长弓入口2的值2、航天入口12的值3；它们无法代表各图全部档位。当前有效overlay、缺少的实际入口及动态准入值继续保留为具体依赖。AI、Raid和挑战难度也不能复用本报告的普通SOL映射。

## 4. 检索与复核

本轮先对既有原PAK索引中的5701个有source_name的chunk逐项验证entry SHA1和chunk SHA256，共77,281,628字节；按内容匹配difficulty及机密/绝密，定位48个来源模块。结果保存于[扫描证据](../work/evidence/gameplay-map-difficulty-consumer-scan-20261021.json)，它是这份有界baseline索引的覆盖，不是所有当前挂载资源的覆盖证明。

[只读映射脚本](../work/research_map_difficulty_mapping_20261021.py)重新读取五个原entry，完整解析proto至EOF，只解释无分支赋值片段，并将NSLOCTEXT表示为符号参数；不运行游戏Lua。已执行：

```bash
python -B work/research_map_difficulty_mapping_20261021.py --verify work/evidence/gameplay-map-difficulty-mapping-20261021.json
python -B work/research_map_difficulty_consumers_20261021.py --verify work/evidence/gameplay-map-difficulty-consumer-scan-20261021.json
```

两条均exit0；前者验证五个来源和 `1->10/2->11/3->12`，后者重放5701个chunk并再次定位48个来源。原[消费者完整列表](../work/evidence/gameplay-map-difficulty-consumers-20261021.json)和[选择链列表](../work/evidence/gameplay-map-difficulty-selection-20261021.json)独立保留。旧报告所说“尚未恢复显示对应”仅代表其采样时点，应由本报告更新；旧证据不覆盖。
