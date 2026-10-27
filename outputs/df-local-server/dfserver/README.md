# 服务端源码入口

这里是实际Python服务包。进入对应目录修改实现；本层旧名`.py`只保持历史导入/命令行兼容。同一模块仅有一份业务实现，旧路径与新路径指向同一对象。

- [app](app/README.md)：共享业务Backend、账号事务和操作编排。
- [entry](entry/README.md)：HTTP服务、网页启动、区服发现、主CLI。
- [account](account/README.md)：本地账号、原生身份、设置、会话与聊天。
- [inventory](inventory/README.md)：仓库、容器、卡包、安全箱、扩容及物品绑定。
- [weapons](weapons/README.md)：枪械组件、配件装配、弹药、近战和插槽。
- [commerce](commerce/README.md)：拍卖买卖、商城礼包、曼德尔购买和扫描。
- [cosmetics](cosmetics/README.md)：干员套装、枪皮、挂饰、名片等外观及收藏。
- [progression](progression/README.md)：任务、声望、行动经验、设施、通行证与赛季。
- [match](match/README.md)：战局准入、本地DS服务与匹配状态。
- [transport](transport/README.md)：大厅GCP与原生战局网络，分两个子目录。
- [replication](replication/README.md)：Actor、NetGUID、复制字段与序列化。
- [gateway](gateway/README.md)：原客户端大厅协议、业务封包、消息分发和错误码。
- [diagnostics](diagnostics/README.md)：首帧与业务消息诊断。
- [web](web/)：浏览器入口静态资源，由HTTP白名单提供。

`_paths.py`固定资源位置；`_compat.py`只做同对象模块别名。精确旧名与新位置、迁移前后哈希见[module_layout.json](module_layout.json)。详细请求流程、维护规则和验证结果见[结构说明](../../../docs/architecture/SERVER_LAYOUT.md)。

协议与目录在服务根`protocol/`，本地配置在`config/`，离线测试在`tests/`，提取和原客户端研究工具在项目根`work/`。SQLite账号文件不是源码目录的一部分，本次整理不移动它们。
