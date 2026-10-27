# F 动作绑定、输入队列与面板分发的静态闭合

日期：2026-10-21。旧版 F 报告第 32 行将 `0x32e4000` 描述为对 HUD 委托的调用，这一描述有误。`AGPPlayerController::OnInputInteract1 0x4e11180` 的准确顺序是：`0x4e111e7 -> GetBaseHUD 0x517bd10` 仅检查返回值非空；`0x4e111f1 mov rcx,rbx` 仍传入 controller；`0x4e111f4 -> 0x32e4000` 按 `GPGameplayDelegates` 类取得委托对象；`0x4e11206 lea rcx,[rax+0x648]`，最后 `0x4e1120d -> 0xd96400` 才广播整数 1。因此不得把 `GetBaseHUD` 的返回对象作为 `+0x648` 的 owner，也不得把 `0x32e4000` 命名为广播函数。本报告保留旧证据，新增独立可重放勘误。

本次进一步恢复了另一条有直接绑定依据的输入管理器路径：源配置 `Interact=F`，`UGPInputManager::SetupInputComponent` 将 `Interact` 的两种输入事件绑定到实际按下/释放函数；动作经过队列、动作分发表和 `UDFHDInputManager` 的条件处理，广播面板已注册的 `DFMGameplayDelegates +0x1fa8/+0x1fb8`，再进入 `DoInteract1KeyPressed/Released`。这闭合了输入管理器到面板的静态分发片段。旧的 AGP controller `+0x648` 与这条路径的转发关系仍未证明，两者不能拼接成同一条链。

## 范围与复核

仅静态读取本地同版本代码缓存、原 EXE 的不可变记录及既有研究文件。未读取进程、启动游戏、打开数据库、发包或访问网络；未写 peer、原安装、shadow 或生产代码。原 `Interact=F` 的 PAK 行与源哈希沿用 [前次 F 研究](GAMEPLAY_F_INTERACTION_RESEARCH_20261021.md)及其 `f-interaction-input-ini-20261021.json`，本次不重复提取。

- 原 EXE SHA256：`4254fbe66585f260f1f9dbfc5e302887842552e7baed8939e023160a5e250be0`。
- 缓存：peer `work/native-code-cache/1792259162856698600`；manifest SHA256：`dfd5c279d7db45842cee2bbc485ac8bf3cab03e4249ef5fe36bc9e8d6cd14754`。既有缓存不是本次实时原生执行证明。
- 采集及验证器：[research_f_dispatch_20261021.py](../work/research_f_dispatch_20261021.py)。复用的前次采集器也保留源码哈希。
- 证据：[gameplay-f-dispatch-research-20261021.json](../work/evidence/gameplay-f-dispatch-research-20261021.json)。每项保留原始指令字节、范围哈希、pdata/unwind 身份、完整线性解码前缀及限定标记；原 EXE 记录与缓存中的二级分发表分别保存。

```bash
PYTHONDONTWRITEBYTECODE=1 /c/Users/BaiGe/.conda/envs/python12_conda3/python -B work/research_f_dispatch_20261021.py --verify
```

结果为 `PASS`：65 个不同原生范围、146 份 unwind 记录、6 个不可变 EXE 记录/节、2 份缓存数据记录；验证 22 条直接 call/jmp、34 条指令、6 个不可变指针及 2 条动作路由。两个探索范围未完整线性解码：`0x4d48710` 的范围尾部包含分发表；`0x5bc7ec0` 是未采用的元数据候选，不能据其名字指针命名实际输入处理器。关键 switch、虚调用和 exec 范围均另有完整有界解码。所有范围仍保留 `complete_native_function_claimed=False`。

## 1. Interact 的真实注册

`UGPInputManager::SetupInputComponent` 的准确原生范围为 `0x4d88580`，34548 字节，SHA256 `add2703138c9104ed71d14e4ab006abc69357e25b0e01d69cd196fdb798f2147`。query 为 `physical-input-manager-binding`。

按下绑定在同一个连续范围中：

```text
0x4d8d0ba lea rax,[rip-0x6e4b1]   ; 0x4d1ec10
0x4d8d0ce lea rdx,...              ; Interact
0x4d8d0f7 mov r9d,0x8f             ; action
0x4d8d102 xor r8d,r8d              ; input event = 0
0x4d8d110 call 0x4cea1f0
```

释放绑定：`0x4d8d115` 持有 `0x4d1ecc0`，`0x4d8d129` 同样取 `Interact`，`0x4d8d152` 传 action `0x90`，`0x4d8d15d` 传 input event 1，`0x4d8d16e` 调同一绑定辅助 `0x4cea1f0`。辅助范围也已保留；不能把别的类、同名元数据候选或相同 hotpatch ID 代入这两处实际成员函数地址。

`OnInputInteractPress 0x4d1ec10` 在 `0x4d1ec66` 传 `edx=0x8f`，`0x4d1ec71` 调 self 虚槽 `+0x438`；`OnInputInteractRelease 0x4d1ecc0` 在 `0x4d1ed16/21` 对应传 `0x90` 并调同槽。它们的反射 exec `0x601c390/0x601c3b0` 也分别尾跳到这两个实际函数。

## 2. 队列、接收者类与动作分发表

原生类注册 `0xcdd5090` 的名字为 `/Script/DFMGameplay.DFHDInputManager`。其构造 callback `0xcdd6130` 在 `0xcdd613e` 尾跳 `0xb6a8f40`；构造体 `0xb6a8f58/5f` 把 `0x17afc318` 写入对象首虚表。这里具有构造写入和类注册依据，不再只是邻近不可变指针候选。

该表 `+0x438 = 0x17afc750` 指向 `0xb6cec60`。后者在 `0xb6cee32` 尾跳 `UGPInputManager 0x4d13e20`。`r8b=0` 时，`0x4d13ea3/ec9` 取 `+0x4b8/+0x4b0` 的计数/数组，`0x4d13f0a` 把动作作为 16 位值写入队列；另一分支使用 `+0x4c0/+0x4c8`。这里不是在物理按键回调内立即完成全部交互。

`UGPInputManager::UpdateInputManager 0x4d9a920` 在 `0x4d9ab49` 取同一 `+0x4b0` 队列，经过其输入启用/状态条件，`0x4d9c249` 调 `ProcessInputAction 0x4d48710`。该处理器在 `0x4d49fb5` 使用 action-1，通过 `0x4d4c120` 的 byte map 与 `0x4d4bdfc` 的 RVA 表分发。缓存表原字节及哈希已保存：

```text
action 0x8f: byte_map[0x8e] = 70 -> rva_table[70] = 0x4d4b2a9
action 0x90: byte_map[0x8f] = 70 -> rva_table[70] = 0x4d4b2a9
0x4d4b2b3 call [self_vtable+0x6d8]
0x17afc318+0x6d8 = 0x17afc9f0 -> 0xb6e68a0
```

query：`hd-input-class-identity`、`hd-input-native-constructor`、`hd-input-vtable-qualified`、`input-action-switch`、`queue-to-interact-dispatch`、`input-action-table`。未把任意同偏移虚槽视为同一类型。

## 3. 面板广播、注册与 exec

`0xb6e68a0` 为实际输入接收体，6613 字节，SHA256 `71e6b6170b2204d73fb9994db6e88cbf6f1dfae34d6bffd8c8c28c95ad0fd9a3`。它比较 `0x8f/0x90`，按运行模式和 `GHS_RealOpenLoot`、`GHS_InteractPanel` 等状态分支。以数值模式 `0xa` 的已限定分支为例，RealOpenLoot 为真会退出，InteractPanel 为假也退出；按下到 `0xb6e7891 -> owner+0x1fa8`，释放到 `0xb6e824a -> owner+0x1fb8`，最终 `0xb6e8255/5c` 把整数 1 交给 `0xd96400`。模式 `0xe` 另有对象有效性及状态检查，不能省略或直接套入模式 `0xa`。

这里 owner 由 `0x73fee20` 获取。它调用类 getter `0xcea30b0`，后者的注册名字明确为 `DFMGameplayDelegates`。`0x5ffafd0` 则注册 `GPGameplayDelegates`；两个 getter、两个字段偏移不能混称为 HUD。

面板初始化 `0x87ae820` 保存了明确方法地址：`0x87ae91c` 持 `OnInteractKeyPressed 0x87c4ef0`，`0x87ae9d2` 持 `OnInteractKeyReleased 0x87c5260`，并分别在 `0x87ae9bf/9cd`、`0x87aea77/a85` 向同类 owner 的 `+0x1fa8/+0x1fb8` 注册 self。注册辅助 `0xe6e8e0` 实际存入弱对象与 FName；广播 `0xd96400` 在 `0xd96553` 经 `ProcessEvent +0x220` 调解析出的函数，不能把它说成直接调用局部保存的 C++ 方法指针。

不可变注册对 `0x175e74d0` 的原记录为 `OnInteractKeyPressed -> exec 0x9359990`，`0x175e74e0` 为 `OnInteractKeyReleased -> exec 0x9359a10`。exec 中 `0x93599f9 -> 0x87c4ef0` 和 `0x9359a79 -> 0x87c5260` 均是直接 call。面板索引为 1 时，前者 `0x87c512b -> DoInteract1KeyPressed 0x8789110`；后者 `0x87c5485 -> DoInteract1KeyReleased 0x8789f80`。

据此可复核的片段为：

```text
Interact 绑定 -> OnInputInteractPress/Release -> action 0x8f/0x90
  -> self+0x438 -> 输入队列 -> UpdateInputManager
  -> ProcessInputAction 二级表 -> self+0x6d8 -> 0xb6e68a0
  -> 运行模式及 HUD 状态检查 -> DFMGameplayDelegates+0x1fa8/+0x1fb8
  -> 已注册面板 self + FName -> ProcessEvent -> 对应 exec
  -> OnInteractKeyPressed/Released(index=1) -> DoInteract1KeyPressed/Released
```

该链证明源定义的绑定与有条件分发，不证明某次实机中实际构造的是这一管理器、当前面板已注册、运行模式/目标/权限有效或所有条件通过。

## 4. 搜索调度的进一步收窄

全缓存扫描 `StartLootSearchProcess 0xc1f6750` 的直接 call 候选后，按完整 pdata 范围确认了三个调用点：

- `0xb483bfd` 位于 `ADFMCharacter::SetIsLooting_Implementation 0xb481ee0`。进入其相应拾取状态分支且当前 loot source 的接口/对象有效时，取得 `ItemSearchSubSystem 0xc1ba120`，传 character 与真实 loot source 接口再启动搜索。退出状态有 `0xb48395f -> StopLootSearchProcess 0xc1f9b20`。
- `0xc1d64df` 位于 `MarkItemSearchDone 0xc1d6110` 的后续搜索分支，是已有搜索状态传播路径，不能作为第一次开箱的开始证明。
- `0xc1dba20` 位于 `OnLootObjGainItem 0xc1db360`，该体有明确 `restart searching box` 日志，是已有 loot source 增加物品后的重启路径。

开箱 Finish `0xc1c9040` 的成功权威分支在 `0xc1c936e` 可直接到 `UInventoryManager::TryOpenBox 0xbfd05e0`；这个范围恢复了箱子内容准备与后续通知片段，但尚未闭合它到角色 `SetIsLooting_Implementation` 的首次状态设置。Finish 的反射事件、虚调用或 PC226 收据均不能充当这条缺失边。

## 仍需闭合

当前尚缺：实际生产对象生命周期/模式与本输入管理器及面板注册的关系；旧 AGP `GPGameplayDelegates+0x648` 的实际消费者；面板缓存 `+0x518` 的真实 receiver 类型及 `+0x490` 到 SOL 执行器的连接；Box Finish 到首次角色拾取状态/搜索启动；Blueprint 条件、中断绑定和最终复制提交。原版逐项 timer 片段继续沿用前次证据，不能据本次输入链宣称完整 F 游戏逻辑可执行。

运行时状态继续沿用最新限定：有 manifests 时可安装 `RegisteredBoxReceiptRuntime`，同时 `mutation_ready=False`；真实服务端位置和锁许可仍有依赖。没有把状态改写成一律未安装。
