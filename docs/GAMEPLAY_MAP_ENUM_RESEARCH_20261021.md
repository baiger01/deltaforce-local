# MatchSubMode 的实际数值定义

研究截至 2026-10-21 01:17:19 北京时间。本轮只读本仓库缓存及原安装 `DF_LOCAL_SOURCE_GAME`，写入本仓库的新研究文件；未启动游戏、执行游戏 Lua、读取进程、打开数据库、修改原安装或协作者文件。使用已安装的压缩 codec 解压原 PAK entry，未调用游戏 SDK 或 gameplay。

## 已恢复定义

定义在原安装 baseline `pak-0-0-pakchunk1-WindowsClient.pak` 的 **`@ds_common_pb.lua`**，entry offset `32942080`、Lua offset `0`、chunk length `274454`，SHA256 `6f1bec3a236dbd47c28d932a2702bc8cc386ecb6119312d71d57a62d6e8b8f6b`。这是实际赋值源，文件名没有 Enum/Define，因此按文件名筛选会漏掉它。

顶层 function0 的原始指令，经现存 client opcode reader 解码：

```text
0137 NEWTABLE   R1 0 30
0138 SETTABLE   R1 K146='InvalidSubMode' K9=0
0139 SETTABLE   R1 K147='SOLPMC' K94=10
0140 SETTABLE   R1 K148='HighYieldSOLPMC' K96=11
0141 SETTABLE   R1 K149='ExtremeHighYieldSOLPMC' K98=12
0142 SETTABLE   R1 K150='SOLNight' K100=13
0143 SETTABLE   R1 K151='HighYieldSOLNight' K102=14
0144 SETTABLE   R1 K152='ExtremeHighYieldSOLNight' K104=15
0145 SETTABLE   R1 K153='VeryHighYieldSOLNight' K106=16
...
0194 SETTABUP   U0 K145='MatchSubMode' R1
```

U0 的实际 upvalue name 是 `_ENV`。PC137..194 是 NEWTABLE/SETTABLE/SETTABUP 的连续定义段，没有调用或分支；完整56项与原始 word 在 [证据 JSON](../work/evidence/gameplay-map-enum-research-20261021.json) 的 `enum_exports`。因此可确定：`MatchSubMode.SOLPMC=10`、`HighYieldSOLPMC=11`、`ExtremeHighYieldSOLPMC=12`。这也闭合了 GameModeServer 消费者所引用的名字与原始 MatchModeDataConfig 的数值域，未依靠10/11/12的排列猜映射。

这些是 Lua 全局 enum 的成员值。`DFMGlobalConst.lua` 的协议字段序号 `MatchSubMode=3` 是另一个契约；不能拿字段序号3代替这里的 enum 值。

## UI 难度边界

同一个 `ds_common_pb.lua` 顶层共30263条指令。本轮检查了其字面 global `SETTABUP` 定义，没有找到名字包含 `Difficulty`/`Difficult` 的全局表定义。该结论限定这个 chunk 和这种定义形式，不宣称所有脚本、反射注册或动态生成路径均不存在 UI 难度 enum。

`MapBoardInfoDesc.difficulty` 的独立 `u32` 字段16仍没有实际源值。本文不把 MatchSubMode 的10/11/12当成该字段的取值，也没有从 UI 低/中/高的展示顺序推导另一个 enum。地图表、入口及 GameModeServer 消费者的后续 join 由主研究继续记录。

后续已在其它原chunk找到真实定义和消费者，见[独立难度语义补查](GAMEPLAY_MAP_DIFFICULTY_MAPPING_20261021.md)：普通SOL中1/2/3对应常规/机密/绝密，并由RecruitConfig显式连接sub10/11/12。这更新了前段对语义值的未知项，不推翻“ds_common_pb这一chunk没有该全局定义”的有界结论，也不是当前官方board响应的采样。

## 查找与重放

首先按实际 chunk 内容检查本仓库1331份已提取 Lua，目标字符串只命中消费者。随后从现存 `outputs/df-local-server/protocol/pak_baseline_lua_probe.json` 的真实 entry offset 直接重读原 PAK，对5701个有 source_name 的 chunk 共77281628字节逐一核对 SHA256，内容定位到 `ds_common_pb.lua`。这不是重新按 Enum/Define 文件名做候选扫描；没有把该次有限索引说成整个安装的 Lua 覆盖证明。

[helper](../work/research_map_enum_20261021.py) 的重放只读这一条已定位的原 entry，检查原 entry SHA1、chunk SHA256、完整 proto 解析、`_ENV` 绑定、定义段位置和字面赋值，并保存原 index/helper/reader/codec 来源哈希。codec SHA256 `fc923f9bbbf185ca6e853de0e3ebbc81c839323e6e161cd0f75058c60a2b05a6`。

```bash
python -B work/research_map_enum_20261021.py --verify work/evidence/gameplay-map-enum-research-20261021.json
```

本轮已执行重放，输出 `replay_matches=true`，三个成员值为10/11/12，`difficulty_global_export_count=0`。helper 仅在显式 `--output` 时允许写入本仓库新的 `work/evidence` 文件；`--verify` 不写文件。原 PAK 的 footer/entry/hash、58条定义指令、56项成员、5个依赖 pin 见证据 JSON。
