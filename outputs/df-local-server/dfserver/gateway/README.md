# 大厅业务协议与原客户端请求分发

本目录是实际实现。根包同名文件是旧路径兼容入口。

- [handshake_diagnostic.py](handshake_diagnostic.py)：在回环诊断会话中处理GCP握手、认证及已接入的大厅业务分发。
- [business_envelope.py](business_envelope.py)：按恢复字段封装和解析候选CSPkg业务包头。
- [candidate_business.py](candidate_business.py)：为已恢复的候选业务消息提供编解码与响应构造。
- [candidate_schema.py](candidate_schema.py)：将配对恢复的字段和类元数据编译成候选Protobuf描述符。
- [protobuf_codec.py](protobuf_codec.py)：按已恢复描述符编解码消息，并对未知消息定义明确报错。
- [client_errors.py](client_errors.py)：加载真实客户端错误码目录并提供业务错误码查询。

资源位置统一读取 `dfserver._paths`；修改后运行服务根目录的测试。总览见[结构说明](../../../../docs/architecture/SERVER_LAYOUT.md)。
