# 大厅分帧、认证、握手与加密

本目录是实际实现。根包同名文件是旧路径兼容入口。

- [gcp_control.py](gcp_control.py)：定义传输认证请求与响应的正文格式。
- [gcp_crypto.py](gcp_crypto.py)：实现已观测的GCP模式3传输加解密。
- [gcp_data.py](gcp_data.py)：处理GCP版本11数据头、压缩合并消息及接收解码。
- [gcp_framing.py](gcp_framing.py)：按已恢复布局处理0x3366 GCloud分帧。
- [gcp_handshake.py](gcp_handshake.py)：编解码DH握手头和版本11的ACK正文。

资源位置统一读取 `dfserver._paths`；修改后运行服务根目录的测试。总览见[结构说明](../../../../../docs/architecture/SERVER_LAYOUT.md)。
