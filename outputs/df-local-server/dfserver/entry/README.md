# 服务入口、HTTP与区服发现

本目录是实际实现。根包同名文件是旧路径兼容入口。

- [http_api.py](http_api.py)：提供本地账号和业务的HTTP接口，并按白名单提供前端静态资源。
- [entrance.py](entrance.py)：检查本地服务状态，按需启动后端并打开独立前端。
- [zone_discovery.py](zone_discovery.py)：按已恢复的GetZone字段格式生成本地区服发现响应。
- [cli.py](cli.py)：解析服务启动参数并组装后端、协议编解码器和HTTP服务。

资源位置统一读取 `dfserver._paths`；修改后运行服务根目录的测试。总览见[结构说明](../../../../docs/architecture/SERVER_LAYOUT.md)。
