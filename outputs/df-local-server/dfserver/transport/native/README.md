# 原生战局连接、控制消息与可靠交付

本目录是实际实现。根包同名文件是旧路径兼容入口。

- [legacy_ds_bit_archive.py](legacy_ds_bit_archive.py)：提供有边界检查的低位优先位流读写基础工具。
- [legacy_ds_control_connection.py](legacy_ds_control_connection.py)：处理有界原生控制连接准入及显式初始Actor投递。
- [legacy_ds_control_fields.py](legacy_ds_control_fields.py)：编解码已对齐的原生控制消息字段。
- [legacy_ds_control_probe.py](legacy_ds_control_probe.py)：使用已恢复线格式执行可选的本地Hello与Challenge诊断交换。
- [legacy_ds_decoded_bunch.py](legacy_ds_decoded_bunch.py)：维护普通接收路径上已解码bunch的数据接收状态。
- [legacy_ds_handshake_probe.py](legacy_ds_handshake_probe.py)：执行受限的回环DS明文握手诊断。
- [legacy_ds_identity_field.py](legacy_ds_identity_field.py)：处理当前版本原生身份装载器对应的字段格式。
- [legacy_ds_login_fields.py](legacy_ds_login_fields.py)：处理已核实的PendingNetGame发送端Login5字段格式。
- [legacy_ds_packet_ack_probe.py](legacy_ds_packet_ack_probe.py)：对已观测的握手后包头执行有界ACK诊断。
- [legacy_ds_wire_codec.py](legacy_ds_wire_codec.py)：编解码当前版本原生包通知头与bunch线格式。
- [unreal_handshake_payload.py](unreal_handshake_payload.py)：编解码已核实的普通及扩展重启握手正文。

资源位置统一读取 `dfserver._paths`；修改后运行服务根目录的测试。总览见[结构说明](../../../../../docs/architecture/SERVER_LAYOUT.md)。
