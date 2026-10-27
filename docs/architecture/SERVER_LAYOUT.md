# 自建服务端目录与维护说明

本次整理保持 `outputs/df-local-server` 为可运行服务根，协议目录、配置、静态网页与存档位置固定。Python实现按领域迁入 `dfserver` 子包；旧 `dfserver.xxx` 路径保留同一模块对象的兼容入口，继续支持现有脚本、私有函数patch和命令行。修改功能应编辑子目录中的实现，不在兼容文件里增加业务。

## 目录职责

```text
outputs/df-local-server/
  dfserver/
    app/                  Backend、事务、共享业务编排
    entry/                HTTP、网页入口、区服发现、服务CLI
    account/              本地账号、原生身份、设置、会话辅助、聊天
    inventory/            容器、仓库、安全箱、卡包、绑定与库存通知
    weapons/              枪械组件、装配、弹药、近战与插槽GUID
    commerce/             买卖、商城礼包、曼德尔扫描
    cosmetics/            枪皮、挂饰、干员与账户外观、收藏
    progression/          任务、声望、行动等级、设施、通行证、赛季
    match/                战局准入、局内服务探针、未开放匹配响应
    transport/gcp/        大厅TCP分帧、握手、加密与认证
    transport/native/     原生战局连接、控制消息、ACK与线格式
    replication/          Actor、NetGUID、字段、标量和复制元数据
    gateway/              原客户端大厅请求分发、业务封包与描述符
    diagnostics/          首帧、业务消息等受限诊断
    web/                  现有网页静态资源
    _paths.py             唯一固定资源根
    _compat.py            旧模块路径兼容，不能放业务
    module_layout.json    旧模块 -> 实现位置与模块职责索引
  config/                 本地运营配置；任务一键完成默认关闭
  protocol/               客户端派生目录、描述符和来源记录
  tests/                  服务离线与socket回归
  data/                   本地运行存档；不入Git
work/                     提取、迁移、原客户端试验与调研工具
docs/                     运行说明、研究、结构与协作记录
outputs/native-account-provider/  独立本地身份提供者源码与构建工具
```

各领域目录附有自己的README，列出实际模块及职责。`protocol`、`tests`、`work`现有文件位置保留，避免破坏原始证据引用、提取器和独立试验路径；运行代码已经实际分类，不是复制一套展示目录。

## 请求怎么走

网页/开发接口：`entry.http_api -> app.core.Backend -> 对应领域模块 -> 当前SQLite事务 -> 响应`。

原客户端大厅：`transport.gcp -> gateway.handshake_diagnostic -> account / inventory / weapons / commerce / cosmetics / progression -> Backend事务 -> 原协议响应与通知`。

战局：`match.game_server_probe -> match.legacy_ds_match_admission -> transport.native.legacy_ds_control_connection -> replication`。2026-10-22起，大厅与战局统一以 `repository root` 的当前实现为准；旧地图工作区已退役，完整历史保存在 `historical-map-archive`，不能将其运行代码自动覆盖到本目录。已有玩法调查及历史勘误见[总报告](../GAMEPLAY_INTEGRATION_RESEARCH_20261020.md)。

`app/core.py`和`gateway/handshake_diagnostic.py`暂保留既有编排职责与函数内延迟导入；本轮不同时重写事务、消息顺序或拆分它们的方法，便于核对整理前后的行为。

## 兼容与约束

- `python -m dfserver`、`.accounts`、`.entrance`、`.connection_probe`、`.handshake_diagnostic`继续可用；新目录中的对应入口也可以使用。
- 旧名和新名指向同一模块对象，不用`import *`复制全局变量；旧测试patch仍影响真实实现。
- 新实现内部用明确的领域绝对导入，保留lazy import所在位置；资源从`_paths`读取，不再依赖代码文件的目录深度。
- 原生试验的新源码封存应同时包含兼容入口、实际实现、路径/兼容辅助及映射清单；历史试验文件与哈希不改写。
- 本次只调整实现位置与导入/资源定位；存档、客户端ID、原生枚举、协议和已实现业务规则保持原值。

## 执行与验证清单

- [x] 记录整理前离线测试与源码备份。
- [x] 将80个实现模块和根CLI按映射迁入领域子包，生成各目录说明。
- [x] 旧/新模块对象一致；五个CLI、默认资源、网页和配置路径验证。
- [x] 更新新采样的源码封存，验证修改真实实现能被检测。
- [x] 完整离线服务测试、直接相关工具测试及README/运行说明核对。

机械迁移工具：[reorganize_server_packages.py](../../work/reorganize_server_packages.py)。运行前先预览；应用会校验输入与目标路径并将原源码存入本地备份。它不是账号迁移工具，也不会访问游戏或数据库。

## 本次验证

整理前1369项服务测试通过（173.162秒）；整理后1373项通过（170.471秒），新增4项覆盖全部81个旧/新模块身份、私有/全局patch、固定资源和5个CLI。独立复核将迁移前后AST的导入/路径变更归一化后，未发现其它逻辑差异；三种不同导入顺序均通过，没有数据库连接。

源码封存与直接相关工具54项通过（0.303秒）。新增封存包含真实实现、所经包的`__init__.py`、兼容/路径辅助和映射；修改canonical实现而不改shim会改变封存结果。旧的`InitialActorBootstrapTrialTests`还依赖本工作区缺失的`1791073668497579200/replication-metadata-after-actor-open/result.json`，其包含实源夹具的测试本轮无法完成，未造替代证据或记为通过。普通元数据、CLI、源码封存和服务测试已分别验证。

迁移前81份源码的本地ZIP备份SHA256为`d9922af92f5f2f9057345ccbfd2a3b843f5f82bbbf475d8f42785eda63470efa`，274117字节；81个canonical文件与迁移manifest中的after哈希逐项一致。详细记录见[验证记录](../../work/evidence/server-layout-validation-20261020.json)。没有通过本次目录整理宣称原客户端玩法已可用。
