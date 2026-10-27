# 战局准入与局内服务编排

本目录是实际实现。根包同名文件是旧路径兼容入口。

本分支当前覆盖回环DS连接诊断、有限票据准入与初始Actor投递，尚未实现完整可玩战局。

- [game_server_probe.py](game_server_probe.py)：编排有界的回环DS连接、收发记录和初始Actor投递诊断。
- [legacy_ds_match_admission.py](legacy_ds_match_admission.py)：管理有限期本地战局票据及准入状态。
- [native_match_unavailable.py](native_match_unavailable.py)：在本地匹配服务不可用时返回原客户端对应错误响应。

资源位置统一读取 `dfserver._paths`；修改后运行服务根目录的测试。总览见[结构说明](../../../../docs/architecture/SERVER_LAYOUT.md)。
