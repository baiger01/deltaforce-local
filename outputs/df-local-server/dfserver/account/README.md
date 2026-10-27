# 账号、身份、设置与会话

本目录是实际实现。根包同名文件是旧路径兼容入口。

- [accounts.py](accounts.py)：提供本地账号注册、登录和改密的命令行入口，密码通过隐藏输入读取。
- [native_identity.py](native_identity.py)：编码供本项目原生组件读取的版本化本地身份响应。
- [native_settings.py](native_settings.py)：按已恢复的设置协议保存和查询账号设置原始数据。
- [native_session_auxiliary.py](native_session_auxiliary.py)：处理已核实的会话辅助查询及经认证的单向通知回执。
- [local_chat.py](local_chat.py)：为离线账号的聊天查询返回空历史及对应协议响应。

资源位置统一读取 `dfserver._paths`；修改后运行服务根目录的测试。总览见[结构说明](../../../../docs/architecture/SERVER_LAYOUT.md)。
