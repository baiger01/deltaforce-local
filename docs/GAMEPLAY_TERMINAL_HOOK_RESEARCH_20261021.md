# SOL terminal hook source narrowing, 2026-10-21

本轮只收窄 SOL 终局 `+0x440` 的剩余桥接来源。已将此前泛称的 hotpatch 缺口收窄为 **DFMGameplay 模块 167 的两个指定 MetaRuntime stub，以及这些 stub 到 Lua 函数别名的实际绑定**。已恢复绑定基础设施，未恢复一个有效的 SOL 终局 producer，未进行原生终局、账号写入或客户端验收。

## 范围与来源

- 自有输出：本报告、`work/research_terminal_hook_20261021.py`、`work/evidence/gameplay-terminal-hook-research-20261021.json`。
- 只读原安装：`DF_LOCAL_SOURCE_GAME`。只读 peer：`historical map checkout`。
- EXE：`DeltaForce/Binaries/Win64/DeltaForceClient-Win64-Shipping.exe`，514156152 字节，SHA256 `4254fbe66585f260f1f9dbfc5e302887842552e7baed8939e023160a5e250be0`。
- 既有 code cache：peer `work/native-code-cache/1792259162856698600`，manifest SHA256 `dfd5c279d7db45842cee2bbc485ac8bf3cab03e4249ef5fe36bc9e8d6cd14754`。
- `CodeCache -> validate_plan` 本轮重新校验原 EXE 整体、PE header、代码节及已知 sender anchors；读取的 cache block 逐块校验 SHA256。未刷新 cache，未访问进程。
- JSON SHA256：`b3e5cc01f7deefb2837caecba4852cbd9b56d78836828def45398db0a69fa7f2`。
- helper SHA256：`8735d12dd9a30b1ad785dec08bb4ea7e79f48dafbb2401bbf424b82340604596`。完整 helper/前序报告/解析器来源 pin 保存在 JSON `source_pins`。
- 工具记录的 UTC 为 `2026-10-20T16:15:06.730646+00:00`，即北京时间 2026-10-21 00:15。文件日期采用北京时间。

没有修改 shadow、原安装、peer、生产源码、已有报告、数据库或外部服务；未启动游戏、访问进程、执行 Lua、发包。

## 1. 真正的 stub 标识已闭合

延续前序已验证的 SOL getter/constructor/class 身份，本轮重新读取真实 primary vtable `0x1a8f6428 + 0x440`，其值仍是 `0xb845590`。263 字节连续 unwind chain 的 SHA256 是 `f0603a9b500759544b802432c6ef3fc10e398a6a43cc1da86a37a3d84f9f5240`。

该函数在 `0xb845604/0xb845672` 分别设置 StubId `0x65af/0x6569`，两次均调用 `0xcc5dd00`；该 helper 在 `0xcc5de05` 将原 StubId 传入 edx，在 `0xcc5de08` 固定 ecx=`0xa7`，随后 `0xcc5de0d -> 0x10c8e260`。因此标识是 `(ModuleId=167, StubId=26031/25961)`，不能当成两个全局唯一数字。全代码的同一 ID 常量还有其它函数命中，单个数字不能指认消费者。

`0x72dd20` 的静态登记提供独立来源闭环：

- `0x72dd33`：ModuleId=`0xa7`；`0x72dd39`：模块名 `DFMGameplay`。
- `0x72dd44/4b`：stub flag table base=`0x1e0b1720`。
- `0x72dd56`：stub count=`0xd64c`；`0x72dd4f/5e`：lazy initializer=`0xcbd18d0`。
- `0xcbd18d0` 的日志来源明确是 `DeltaForceClient/Inc/DFMGameplay/MetaCode/DFMGameplay.stub.init.cpp`；在 `0xcbd191f/1925` 交付 count=`0xd64c` 和名称表 `0x1d036860`，末尾跳 `0x10c8e5d0`。

名称表的原始 16 字节记录逐项验证 ID、指针及指向的完整 NUL 结尾 ASCII：

- `0x1d09c340`：`0x65af`，字符串 `0x1819e9e0`，`UDFMSettlementComponent::OnPlayerMatchOver_BS`；记录 SHA256 `1ddeb6180112b252c0e3bab45ea049aff9be896c403d954b3a86d5b55e5447e3`。
- `0x1d09bee0`：`0x6569`，字符串 `0x18190678`，`UDFMSettlementComponent::OnPlayerMatchOver_ES`；记录 SHA256 `4e294c3663ba793a11379cc997da4929c0fec61b7aa76fed3e978e57e48aa81a`。

地址关系也吻合实际 gate：`0x1e0b1720 + 0x65af = 0x1e0b7ccf`，`+0x6569 = 0x1e0b7c89`。这是 native body 中实际读取的两个 flag。此关系不意味着当前运行中的 flag 已启用。

## 2. native stub 到 Lua 的基础设施已恢复

`0x10c8e260` 的不可变字符串直接命名 `MTModuleManager::HandleStubCall`。它经 `0x10c8c070` 取 manager，在 `0x10c8e34f` 先要求 manager+`0x128` callback 非空，再检查模块初始化与范围，索引 manager+`0x118` 的 module，再按 StubId 索引 module+`0x18` 的 stub context。`0x10c8e393` 要求 context 非空，设置当前 context/frame，在 `0x10c8e3c8` 调 manager+`0x128`。

该 callback 的来源可闭合：

1. `UMetaDorianManager::Init 0x1092e1e0` 在 `0x1092e27a` 调 manager Initialize，随后在 `0x1092e27f` 调 `0x109c93e0`。
2. `0x109c93e0` 在 `0x109c93f6` 取地址 `0x109c95d0`，末尾跳 leaf setter `0x2f6a3b0`。
3. setter 的准确 8 字节是 `mov [rcx+0x128],rdx; ret`；未把其后的 padding/邻函数算入函数。
4. `0x109c95d0` 具有来源 `MetaHotfix/MetaGlue/MTStubCallHandler.cpp` 和名字 `MTStubCallHandler::OnStubCall`。它在 `0x109c999a/99aa` 读取 Lua VM，在 `0x109c99d4` 取 stub+8 的别名索引，经 `0x10c8d0c0` 还原名字，再于 `0x109c9a15` 查找 Lua global，`0x109c9a25` 校验 Lua function 类型，后续构造 frame 参数并调用 Lua。

这不是无条件执行路径：无 VM、缺少函数或线程不符都有明确拒绝/日志分支；不能把基础设施存在当成有效 producer。handler 的日志明确提示绑定不存在的 Lua function 或拼写错误，并在无 VM 分支回写 stub flag 为 3。

绑定 writer 也有明确边界。`MTModuleManager::AddDorianFunction 0x10c89210` 接收 ModuleId、StubId、FuncAliasName、Flag，要求 manager 初始化和模块范围，取得 stub context，在 `0x10c892d4` 将别名登记到 context+8，`0x10c892e2` 写具体 stub flag。`0x10931710` 是传数字 ID 与可变 Flag 的包装；另有按 ModuleName/StubName 的重载。当前尚无证据显示它以 `(167,26031/25961)` 绑定了哪个实际别名。

## 3. 原安装中的 MetaDorian 脚本只提供有界排除

本轮重新遍历原安装 257 个 PAK 的 1174183 条目录记录，主索引、次级索引和选中的压缩 payload 校验均成功。只解压 MetaDorianEntry/Driver 与同目录 44 个 Impl，共 46 个 Lua；所有 Reader 均解析到准确 EOF，未执行。

`pak-0-0-pakchunk1-WindowsClient.pak` 的 Entry 物理偏移 36922013，2396 字节，decoded SHA256 `82165ea39e67cd3d1733686955820e66b68e7187e297cfaa4b3eaa92a9f2974c`。其 `0` 号函数先对五条版本路径逐条 `isexist -> require -> return`，全未选中才 fallback 到 `MetaDorian.MetaDorianDriver`：

- `${MetaDorianRevisionManual}`。
- `Ma4Release_7689207`。
- `Ma4Release_37117`。
- `Ma4Release_20260829_6`。
- `Ma4Release_2026-08-29`。

上述五个 Impl 完整模块路径均不在此次原安装 PAK 索引中。原安装 loose 文件名中也没有 `Dorian|HotPatch|MetaHotfix` 命中。此文件名扫描**不等于**已还原所有编码缓存文件名、挂载优先级、远端内容或当前运行中的 loader 选择，因此不能宣布运行时一定 fallback。

Driver 物理偏移 36921344，1032 字节，SHA256 `2c89ecc75888c1220049ff6b6e5526734adbcc67f993e53b7419cc49ae8802f7`。其两个函数只定义 flag 常量和打印 stub/RTTI 数量；常量明确给出 Disable=0、Enable=1、Replace=2、PreProc=3。native BS flag==2 直接返回的分支与 Replace 名义一致，仍不证明某个当前 flag 的值。

46 个选定 Lua 的全部递归函数常量中，没有本轮 pattern `OnPlayerMatchOver|SettlementComponent|65af|6569`，也没有数值 25961/26031；38 个含 AddDorianFunction 的函数保留了 call 附近的 listing。JSON 对每个 payload 留有 PAK 名、索引位置、物理偏移、长度、SHA256 和解析状态。此处是指定目录集合的可复核结果，不把“没有关键词”提升成整个客户端/DS 没有终局逻辑。

## 4. 剩余依赖与停点

现在缺口可精确描述为：**同一构建真实挂载的 MetaDorian 实现，将 DFMGameplay 的 OnPlayerMatchOver_BS/ES 绑定到哪个 Lua alias，该 alias 是否实际完成 SOL 终局生产；或者实际 DS 构建是否在这个槽提供原生主体。** 本轮恢复的 hook 框架说明 Lua 补充具有真实路径，但没有证明此 terminal stub 已安装有效绑定。

`0xb845590` 内没有 ProcessEvent 或 Blueprint dispatch，实际 `+0x440` 调用落在上文 gate/MetaRuntime 路径。这个观察只约束已验证的 native 槽；不能据此排除其它 Blueprint、Lua/delegate 订阅者或不同 DS 构建的独立 producer，也未读取所有 Blueprint 资产。

前序已排除 `0xfe09ef0` 是 PropHunt 的完整 producer，不能借它填补 SOL 缺口。已恢复的 SOLPlayer `+0x470 -> ServerSendSettlementData -> settlementsvr/SSSettlement` 发送链仍需真实 terminal producer 将状态与数据交汇；账号 carry_out 投影与提交边界继续保持未知。

本轮在找到上述指定 module/stub/Lua binding 依赖后停止，不扩大到其它 gameplay 分支；没有把本地独立终局状态机或 ACK 当作原生终局证据。

## 复核

在 `repository root` 执行：

```text
python -B work/research_terminal_hook_20261021.py --verify
```

本轮运行 exit 0，返回 `status=verified` 以及上述 JSON SHA256。该命令重新读取原 EXE/cache、PAK 索引和 46 个 Lua，比较除观测时间外的完整结构；没有落地解密 archive、密钥、原始 EXE 或完整 Lua payload。它验证的是静态证据可重算，不能证明 DS/客户端运行结果。
