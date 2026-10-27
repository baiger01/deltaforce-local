# 连接与业务消息诊断

本目录是实际实现。根包同名文件是旧路径兼容入口。

- [business_probe.py](business_probe.py)：提取已解密业务消息的结构摘要，并避免输出凭据内容。
- [connection_probe.py](connection_probe.py)：仅记录回环连接的首帧结构，用于连接诊断。

资源位置统一读取 `dfserver._paths`；修改后运行服务根目录的测试。总览见[结构说明](../../../../docs/architecture/SERVER_LAYOUT.md)。
