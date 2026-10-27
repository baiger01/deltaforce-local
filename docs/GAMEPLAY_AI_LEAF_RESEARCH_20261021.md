# SOL 巡逻任务的 Blueprint 实现补查

这次将 [上一轮 AI 研究](GAMEPLAY_AI_AUTHORITY_RESEARCH_20261020.md) 的一个实际叶节点闭合到函数脚本：`GetGroupPatrolPoint_C`。已经恢复事件入口、条件分支、外部调用参数、黑板读写方向和完成结果；还把主要外部调用对应到原生 UHT、exec 与方法体。尚未完整恢复原生选点、坐标调整或导航算法，也没有执行该任务或接入本地 AI。

只读取原安装与既存代码缓存。没有访问 shadow、游戏进程或数据库，没有启动游戏、发送游戏网络流量或改动协作者文件。查阅了公开 CUE4Parse 源码以核对序列化语法；重放工具本身不联网。新增文件仅为本报告、[提取工具](../work/research_ai_leaf_20261021.py) 和 [JSON 证据](../work/evidence/gameplay-ai-leaf-research-20261021.json)。

## 来源与重放

- 原客户端 PE：`DF_LOCAL_SOURCE_GAME/DeltaForce/Binaries/Win64/DeltaForceClient-Win64-Shipping.exe`，SHA256 `4254fbe66585f260f1f9dbfc5e302887842552e7baed8939e023160a5e250be0`。
- 只读代码缓存：`deltaforce-map-appearance/work/native-code-cache/1792259162856698600`，manifest SHA256 `dfd5c279d7db45842cee2bbc485ac8bf3cab03e4249ef5fe36bc9e8d6cd14754`。所有原生地址均为 RVA。
- 安装包：`DeltaForce/Content/Paks/pak-0-1-pakchunk73-WindowsClient.pak`。主索引、path hash 索引、完整目录索引及两个载荷的 compressed SHA1 均验证通过。
- 精确包路径：`../../../DeltaForce/Content/BluePrints/Characters/AI_SOL_V2/Drama_SOL/Patrol/Common/GetGroupPatrolPoint`。`.uasset` 的 encoded offset 为 `5664`，物理 offset `10997760`，4282 字节，SHA256 `77506f4b901a3fda3c4ab97d37aaa14e9cbb435a69892423324202c33ed9aa69`；`.uexp` 分别为 `5688`、`10999817`、4833 字节、`6bc324b4c54af74576be30b2d0495a7913b7e982544b7387f6bcd706e8889180`。
- 仅调用安装内纯解压 codec `oo2core_8_win64.dll`，SHA256 `fc923f9bbbf185ca6e853de0e3ebbc81c839323e6e161cd0f75058c60a2b05a6`。选定载荷各限 64 KiB，内容留在内存，未保存密钥或解压资源副本。

在 `deltaforce-local` 中重放：

```bash
PYTHONDONTWRITEBYTECODE=1 .venv/Scripts/python.exe -X utf8 work/research_ai_leaf_20261021.py
```

资源有 32 个 import、4 个连续 export：`ExecuteUbergraph_GetGroupPatrolPoint`、`ReceiveExecuteAI`、`GetGroupPatrolPoint_C` 和 CDO。两个 UFunction 的完整脚本分别是磁盘 1156 / 82 字节、加载后的代码长度 784 / 54 字节，SHA256 分别为 `02951535a6f75b166d2abc51403146aaf635ec152de2690d5f184753cdce638d` 和 `95ce824762ab3e7c8980fe584e84a6c90ddf2029b5acab1afa9826d3f9396f85`。

工具解析 18 / 2 / 10 个顶层 FField 声明，完整消费函数脚本和 UFunction 尾部，校验所有直接跳转均落在语句边界。62 个脚本字段引用全部对应到本包实际声明。FieldPath 的磁盘变长表示与运行时指针长度分开记账，没有把物理偏移误当跳转地址。语法参照 [UStruct](https://github.com/FabianFG/CUE4Parse/blob/master/CUE4Parse/UE4/Objects/UObject/UStruct.cs)、[FFieldPath](https://github.com/FabianFG/CUE4Parse/blob/master/CUE4Parse/UE4/Objects/UObject/FFieldPath.cs) 和 [Kismet reader](https://github.com/FabianFG/CUE4Parse/blob/master/CUE4Parse/UE4/Assets/Readers/FKismetArchive.cs)，实际名称、参数与控制流均来自本构建载荷。JSON 保存每个 AST 表达式的 UEXP 物理偏移及逻辑代码范围。

## 实际任务逻辑

下述代码偏移均属于主 ubergraph；括号内是 UEXP 物理偏移。原始拼写 `AssmblePos` 与 `FucosPoint` 保留。

1. `ReceiveExecuteAI` 在 UEXP `2289` / `2323` 将 `OwnerController`、`ControlledPawn` 写入 persistent frame；`2357` 调用主图，EntryPoint 为 `10`。函数 flags 为 `0x08080800`，主图为 `0x00008001`，两者均无 `FUNC_Net`。
2. 代码 `10`（`1005`）以 `PatrolJob` selector 调用 `GetBlackboardValueAsObject(Self, PatrolJob)`；`40`（`1047`）调用 `IsValid`，`69`（`1088`）无效时跳到 `568`。有效后再读同一 selector，在 `113`（`1152`）动态转换为 `/Script/DFMGameplay.AIGroupPatrolJob`，`178`（`1245`）转换失败也到 `568`。`568`（`1819`）明确调用 `FinishExecute(false)`。
3. `192`（`1267`）测试实例变量 `AssmblePos`。为 true 的分支在 `206`（`1289`）调用该 job 的虚函数 `GetAssemblePosition(OwnerController)`，`269`（`1388`）将结果写到 `TempTargetLocation` selector，然后到公共段 `298`。该分支没有调用 `GetNextPointConfig`，没有在本次入口给公共段使用的 Dir、Staytime、Pose 临时变量重新赋值，不能推定它们一定为零或适合当前任务。
4. `AssmblePos` 为 false 时跳到 `584`（`1831`）。原生调用参数按脚本顺序为 `GetNextPointConfig(OwnerController, out Destination, out Adjusted, out KP, out Staytime, out Pose, out Dir)`。返回 bool 被赋给 `CallFunc_GetNextPointConfig_ReturnValue`，但后续没有读取该变量或以它作条件。
5. 普通分支随后在 `689` / `718` / `747`（`2012` / `2053` / `2094`）分别将 Destination、Adjusted、KP 写入 `TempTargetLocation`、`AdjustedLocation`、`KPCenter` selector，`776` 跳回公共段 `298`。
6. 公共段 `298` / `327`（`1429` / `1470`）写 Dir 与 Staytime；`356`（`1511`）调用 `GetMemberOrder(OwnerController)`；`415`（`1606`）乘以真实 float32 常量 `0.6000000238418579`，`457`（`1668`）写 `RandomStartTime`。`486` / `523`（`1709` / `1766`）将 Pose byte 转成 int 后写 `Pose` selector。`552`（`1807`）调用 `FinishExecute(true)`。

因此原任务确实有对象检查、选点调用、结果写回和成功/失败路径。`FinishExecute(true)` 在解码控制流中不依赖原生 `GetNextPointConfig` 的 bool；这不是原生选点成功、黑板写入成功、NPC 已移动或任务实际运行的证明。

## 默认对象与巡逻树绑定

CDO export 4 的 UEXP extent 是 `3036..4829`。8 个 `BlackboardKeySelector` 全部完整解析：`AllowedTypes=[]`、`SelectedKeyName=None`、`SelectedKeyType=0`、`SelectedKeyID=255`、`bNoneIsAllowedValue=false`。这些是 CDO 序列化值，不能据此把未配置任务视为可直接运行。

上一轮已核实树 export `143 / GetGroupPatrolAssemblePoint_C_1` 的真实类正是本包；本次按该证据文件 SHA256 绑定其 selector。普通分支实际写入 `Destination → Temp_TargetLocation`、`Adjusted → G_WanderCenter`、`KP → G_DestinationPos`；公共段写入 `Dir → Temp_DirectionVector`、`Staytime → T_TimeRemain`、`Pose → MovePose`、`GetMemberOrder × 0.6 → Alert_CoverTime`，对象读取键为 `AIJob`。这闭合了上一轮只知道键名、不知道读写方向的缺口。

生成类确实声明了 bool `AssmblePos`；该字段既没有出现在 CDO 的属性 tag 中，也没有出现在所选树节点 `143` 的属性 tag 中。本次没有恢复这个省略字段的有效构造默认值或当前实例值，所以不凭节点旧名称中的 `Assemble` 选择分支。未对外部黑板类型、当前值和 persistent frame 内容作猜测。

## 原生调用边界

`GetNextPointConfig` 的 UHT `FFunctionParams` 在 `0x1d17c730`，outer getter `0xcd4afc0` 经 class record `0x184f0ed0` 对应 StaticClass `0xcd4bf40`，其真实类名为 `AIGroupPatrolJob`。flags `0x04c20401` 无 `FUNC_Net`，原生参数帧 72 字节。参数布局为 `AIController+0`、Destination `+8`、Adjusted `+20`、KP `+32`、Staytime `+44`、Pose `+48`、Dir `+52`、ReturnValue `+64`；bool 返回位置由 setter `0xe34e90` 的实际写入确认。反射表中第 9 项 `UnderlyingType` 是枚举底层声明，不额外算成调用参数。72 字节不是网络载荷。

UFunction 构造记录 `0x184f0a58` 绑定 getter `0xcd4c000`；原生注册记录 `0x184f65e0` 绑定 exec `0xcd51f80`。exec 在 `0xcd521bd` 实际调用方法 `0x9eb13d0`，`0xcd521c6` 写回 bool。方法的完整 unwind extent 为 `0x9eb13d0..0x9eb3612`，8770 字节均可从已校验缓存读取，SHA256 `d9ff0cd16e333a3b5e849faaa0b7a5839cf9afe227928dcdca1f8f45e78044c4`。不是源字节缺失；本次只限定恢复了前段。

普通原生分支的前段确认：空 AIController 或 `self+0x58` 数量为零返回 false；遍历 `self+0x68` 处 stride `0x78` 的成员记录，以记录 `+8` 匹配控制器，未找到也返回 false。随后依据 `self+0xcc` 将记录 `+0x20` 从 `self+0xc8` 覆盖或递增，向 `0x9eb4190` 传入该值和下一值以求索引。选定点记录 stride `0x50`，在 `0x9eb1812..0x9eb1817` 将点 `+0x44` 写给 Staytime，在 `0x9eb188b..0x9eb188f` 将点 `+0x48` 写给 Pose。这里只记录已验证偏移关系，未把这些结构偏移命名成永久服务器配置。

方法入口还存在可选 instrumentation 路径；没有采样其运行时开关。索引 helper `0x9eb4190`、点配置实例、后续坐标/导航调整、组编队与所有返回路径尚未完整恢复；`GetAssemblePosition` 和 `GetMemberOrder` 的内部算法也未闭合。继续研究已有明确入口，不需要重新从 AI 启动函数开始。

## 验证与剩余缺口

完整重放已成功退出 0：两载荷 hash、PAK 三类索引校验、4 个 export 连续 extent 与尾 magic、两脚本精确长度、62 个字段引用、全部直接跳转、CDO 全 extent、UHT 名称/参数与 14 个原生指令锚均通过。工具与所有直接引用解析器的 SHA256、PE 数据范围和代码范围 pin 在 JSON 中。完成的是静态来源验证，没有用合成测试或 `FinishExecute(true)` 代替原客户端运行证明。

缺口从“任务算法未知”收敛为：该叶节点的脚本控制流与黑板数据方向已恢复，原生选点后段、有效默认值和当前实例输入仍待查。`BTDecorator_JobIsFinish`、两个巡逻 service、外部 Blackboard、AdvancedMoveTo、导航/碰撞、感知/开火/伤害/死亡/掉落、服务器时钟与复制，以及同一 NPC 的实际运行验收，仍是各自独立的未完成项。本次没有新增本地权威 AI 运行代码。
