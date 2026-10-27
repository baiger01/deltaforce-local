# F 面板接收者与组件版请求调研

此前将 `GetBaseHUD` 返回对象视作委托 owner、将 `0x32e4000` 视作广播的描述有误：`OnInputInteract1 0x4e11180` 的 `0x4e111e7` 调用 `GetBaseHUD 0x517bd10` 仅作非空 gate；`0x4e111f1` 仍将 controller 放入 rcx，`0x4e111f4` 调用 `0x32e4000` 得到类限定的 `GPGameplayDelegates`，真正广播是 `0x4e11206` 取 `+0x648`、`0x4e1120d` 调用 `0xd96400`。该纠正在前份 dispatch 报告固定。本次另确认：`[panel+0x518]` 缓存目标侧 `UDFInteractableComponentBase`，角色侧 `USOLInteractorComponent` 是后续查找的另一个接收者，不能将两者或相同虚槽偏移等同。

本次只新增 receiver helper、JSON 和本报告，未改前三份 F 文件、生产代码、peer 或原安装。没有访问进程、启动游戏、打开 DB、发网络包或读取 shared shadow。复用了不可变 EXE、既有同版本代码缓存和磁盘上的历史元数据；不宣称实机功能完成。

## 1. 来源与复核

- EXE SHA256：`4254fbe66585f260f1f9dbfc5e302887842552e7baed8939e023160a5e250be0`。
- 既有代码缓存 manifest：`dfd5c279d7db45842cee2bbc485ac8bf3cab03e4249ef5fe36bc9e8d6cd14754`，路径为 peer 的 `work/native-code-cache/1792259162856698600`。该采样不是原子快照。
- Helper：`work/research_f_receiver_20261021.py`；证据：`work/evidence/gameplay-f-receiver-research-20261021.json`。查找候选仍保留 `instruction_boundary_verified=false`；正文使用经完整范围或明确小范围解码核验的 callsite。
- 历史 SOL owner 元数据：peer `work/native-client-tests/1792548525430131600/world-interaction-rpc-metadata.json`，SHA256 `1259aa9a1470fda7950627853ee6911c84a7d95f2f9e8868c245e3e9731456e1`。其原观察时间为 `2026-10-21T02:23:23.772313+00:00`；本次仅重新读取已保存文件，`snapshot_atomic=false`。其中历史地址不作为本次活动对象地址复用。

## 2. 缓存的实际写入与类型

`UDFHDInteractorPanel` 更新体 `0x87e33d0` 将入参 rdx 保存为 r13、self 保存为 rsi。它的调试参数描述函数 `0x92d36d0` 在 `0x92d3763` 明确引用 `FPotentialInteractorInfo`；调用点 `0x87e3429` 将原入参放入 r8，`0x87e343f` 调用该描述函数。该名字与下面独立静态反射布局一致，不单靠名字归类。

反射记录闭合如下：

1. `PotentialInteractorInfo` 构建参数 `0x1d22d750` 给出 size `0x40`，property array 为 `0x18814d90`。`0x18814ca0` 是 `InteractableProxy` 属性记录，offset `0x18`，类型 getter `0xcf958c0`。
2. Getter `0xcf958c0` 在 `0xcf958d0` 指向 `0x1d22d7a0`：结构名 `InteractableProxy`，size `0x10`，property array `0x18814ee8`。
3. 其中 `0x18814e88` 是 `InteractableComponent` 属性，offset `8`，类型 getter `0xcdde1a0`。其跳转链 `0xcdde1a0 -> 0x80698e0 -> 0xcdde8f0` 的最终 class getter 名为 `/Script/DFMGameplay.DFInteractableComponentBase`。

对应原生数据流：

```text
ShowPanel 0x87ede80 的单项分支
  0x87ee00a  从 panel+0x318 列表取当前项
  0x87ee017  rdx = 列表项
  0x87ee01d  call 0x87e33d0

更新体 0x87e33d0
  0x87e361f  xmm0 = [PotentialInteractorInfo+0x18]，共16字节
  0x87e3623  [panel+0x520] = xmm0
  0x87e362a  先检查 proxy 第一项 [panel+0x520]
  第一项为空或未通过有效性检查时进入 0x87e7178
  0x87e7178  r14 = [panel+0x528] = proxy.InteractableComponent
  通过 UObject 有效性检查
  0x87e71d0  [panel+0x530] = 2
  0x87e71da  [panel+0x518] = r14
```

因此 `+0x518` 的静态类型限定是 `UDFInteractableComponentBase` 或其子类。另一分支缓存 `proxy` 第一项到 `panel+0x510`，并把模式设为 1；不能把这两条接收者路径合并。此次未恢复 `panel+0x318` 列表所有生产者及某个生产实例的具体子类。

核心更新体范围 `0x87e33d0`，17489 字节，SHA256 `a73870894e0e6449c0f938717554e977157eb576fb50efd7b84ed21bf131d899`。对应 query：`typed-update-and-struct-params`、`proxy-reflection-property-arrays`、`proxy-receiver-class`、`receiver-final-critical-spans`。

## 3. 目标组件的 +0x490

短按 `0x878a400` 在 `0x878b069` 取 rcx=`panel+0x518`，`0x878b070` 取 r8=`panel+0x540`，`0x878b077` 取 rdx=`panel+0x538`，于 `0x878b081` 调用目标组件虚槽 `+0x490`。按前述布局，后两者分别来自交互 tag 与操作角色。

`DFInteractableComponentBase` 的 class getter 给出的构造 callback `0xcdde6a0` 转到 `0xbace020`；构造器在 `0xbace03d/044` 将虚表 `0x16cdf000` 写入 self。独立不可变槽记录确认：`0x16cdf490 -> 0xbb92d70`，`0x16cdf4a0 -> 0xbba44c0`。这是基类实现；具体子类可 override。

`0xbb92d70` 的正常分支先取 `[self+0x1f8]` 并做有效性检查：有效时 `0xbb92e82 -> 0xcde3b00`，将操作角色、tag、`self+0xe8` 和 self 组成参数；`0xcde3b40` 经该对象的 `ProcessEvent +0x220` 转发。静态 FName 初始化 `0x7753d0` 将 `OnLocalExecute` 写入 `0x1e0d7160`，包装函数 `0xcde3b1a` 正好读取同一 FName。这里的具体事件接收者/Blueprint override 仍未限定。

`self+0x1f8` 无效时，`0xbb92e95` 调用 self 虚槽 `+0x4a0`。该基类函数 `0xbba44c0` 的内嵌日志明确命名 `UDFInteractableComponentBase::OnLocalExecute`。不要将 `0xbbb2bf0` 的 `OnServerExecuteReturn` 日志套到该槽；它在这张表的 `+0x4b0`。

上述基类 `+0x490` 与 SOL 表 `0x1a67fe40` 的 `+0x490=0xffce530` 是不同槽实例。真实 Actor 版 `ExecuteInteractByTag 0xbb4e140` 在 SOL 表 `+0x450`，仍不能由面板的同偏移虚调用直接推出。

## 4. Fallback 到角色组件

在基类 `OnLocalExecute 0xbba44c0` 中，通过角色及 UObject 有效性检查后：

1. `0xbba484d -> 0x60a4da0` 获取 `/Script/GPGameplay.InteractorComponentBase` class；`0xbba4855 -> 0x12704230`，随后在操作角色 `+0x320` 的组件集合中查找兼容组件并检查有效性。
2. `0xbba4984` 准备请求上下文，`0xbba498e` 取 tag，`0xbba4995` 以 rdx 传目标 interactable self，`0xbba499d` 以 rcx 传找到的角色组件，`0xbba49ca` 调用其虚槽 `+0x458`。
3. **若该角色组件使用已核对的 SOL 虚表**，`0x1a680298` 确认 `+0x458 -> 0xbb4f500`。该函数内嵌名字是 `UDFMInteractorComponentBase::ExecuteInteractableCompByTag`。
4. 它在 `0xbb50237 -> ClientCheckCurrentInteracting 0xbb0e4a0`，false 会拒绝；通过后于 `0xbb50359` 调用虚槽 `+0x8d0`。SOL 槽 `0x1a680710 -> 0xceba830`。
5. `0xceba830` 建立 component/tag/context 参数，于 `0xceba886` 经 `ProcessEvent +0x220`。FName 初始化 `0x7ab700` 与包装函数 `0xceba85c` 均指向 `0x1e0ea608`，其名为 `ServerExecuteInteractableCompByTag`。

这是条件明确的组件版转发路径；没有证明任意当前面板一定走基类 fallback，也没有把查找到的每个角色组件都当成 SOL 实例。此路线与 Actor 版 `ExecuteInteractByTag` 分别保留。

## 5. 真正的 RPC 字段身份

已保存元数据的 owner scope 是 `InteractorComponent`，class path `/Script/SOL.SOLInteractorComponent`。实际 ClassNetCache 条目为 **field 70 `ServerExecuteInteractableCompByTag`**，checksum `2299019140`，descriptor representation `1`，exclusive index maximum `168`。同一 owner 的 field 71 是 `ServerExecuteInteractByTag`，field 72 是 `ServerInteractAction`。不得将组件版字段认作 71/72。

原 EXE 的 `0x1d1ea140` UHT 函数构建参数重读 SHA256 为 `3e9bfeb5d5bea7786200473b0a5e26722bd07618254e5627278bd9da738f632f`，flags `0x220cc0`、原生参数结构大小 `72`、属性数 `3`。实际参数方向由原生包装函数和属性记录共同限定：`InInteractableComp +0`（`0x18700580`，类型 getter 指向上述 `DFInteractableComponentBase`），`InTag +8`（`0x18700548`），`InInteractingContext +0x10`（`0x187004e8`，getter `0x60a7e30`）。这是原生属性布局，不能按 72 字节 memcpy 为网络载荷，也不能把目标组件引用改成 Actor 引用。

同一个历史 RPC 明细只导出了 71/72，且其 FunctionRepLayout 状态为 missing；**field 70 的 FunctionRepLayout 没有导出**。现有证据能限定 field 70 身份和参数声明，不能单凭这些记录宣称组件版 wire codec/当前活动引用已完成。

只读核对 peer `work/portable_world_interact_request.py`：schema 的 94-96 行仅核对 71/72；144 行返回 `execute_index=71, action_index=72`；`decode_field` 第 166 行明确拒绝不在 `(71, 72)` 的字段。peer `work/portable_world_loot_dispatch.py:141` 的 `interact_field` 正调用这个 decoder。因此这一个 decoder/调用路径明确不支持 field 70，组件版请求不能由现有 Actor 版解码测试覆盖。此源码结论不扩展为所有运行路径均缺失。两份原文件完整 hash 与对应源码行已封入 `saved_consumer_sources`，验证只读文件内容，不导入或执行它们。

## 6. 剩余边界

- 具体生产面板的生命周期、模式、目标组件子类及 `+0x490/+0x4a0` override；`self+0x1f8` 的具体 `OnLocalExecute` 事件实现；角色侧实际组件实例及其字段 70 网络属性序列化。
- `GPGameplayDelegates+0x648` 与 `DFMGameplayDelegates+0x1fa8` 未新增连接；前份 dispatch 证明的输入管理器分支仍带模式 gate。
- Box finish 到客户端开页、可能的第二次请求、角色首次进入 looting 和搜索启动仍需逐边恢复。没有因缺直接 call 否认这些流程，也没有把 PC226 收据当成拾取状态设置。
- 当前 manifest receipt 可为 installed true，但 mutation_ready 仍缺真实位置和锁许可；此静态类型连接不改变该边界。

## 7. 验证

在 local checkout 执行：

```bash
PYTHONDONTWRITEBYTECODE=1 /c/Users/BaiGe/.conda/envs/python12_conda3/python -B work/research_f_receiver_20261021.py --verify
```

结果 `PASS`：57 个原生范围、103 个 unwind 记录、24 个不可变记录/区段；15 条直接分支、28 条指令、15 条指针、9 个反射布局值、10 个 RIP 目标、1 份历史 RPC 元数据源及 2 份 consumer 源码。3 个探索用小范围的线性解码未覆盖整个请求范围，JSON 保留该限定；正文断言均逐条核对缓存字节与边界。

证据 SHA256：`8395186412a478d3cdde92be09b7dd1ed3e7ec4172e4b05a93617bd0b7dba5d4`。此 PASS 表示磁盘证据和断言可复核，不表示原版完整 F 交互已在本地执行。
