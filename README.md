# deltaforce-local

Delta Force 本地服务与原客户端诊断接入项目。当前开发目标是修复原客户端大厅、仓库、装备购买、出售、弹药和模型状态的对应关系。

本仓库包含源码、测试、只读提取工具、运行所需的 JSON 目录和重建的 Protobuf 描述符。游戏本体、原始资源、账号数据库、会话、日志和编译后的 DLL 均留在本地。克隆仓库后需要自己准备同版本游戏和本地测试账号。

**不得伪造客户端物品 ID、枚举、配置或关联信息。** 永久映射必须有客户端来源、行/函数/偏移和可用的源哈希，具体规范见 [AGENTS.md](AGENTS.md) 与 [DATA_PROVENANCE.md](DATA_PROVENANCE.md)。

## 目录

| 路径 | 内容 |
| --- | --- |
| `outputs/df-local-server/dfserver/` | Python 服务、持久化库存、协议适配、网页入口 |
| `outputs/df-local-server/protocol/` | 静态目录、Lua 字段元数据、候选消息定义 |
| `outputs/df-local-server/tests/` | 账号、事务、库存与协议检查 |
| `outputs/native-account-provider/` | 本项目身份提供者 C 源码、构建工具、ABI 元数据 |
| `work/*.py` | 只读提取、shadow 创建、限时启动、恢复与日志工具 |
| `docs/COLLABORATION.md` | 当前交接记录、待修问题、分工与验证要求 |

## 服务与测试

建议使用独立的 Python 3.12 环境；涉及 `hashlib.file_digest` 的工具至少需要 Python 3.11。以下命令在项目根目录的 PowerShell 执行：

```powershell
python -m venv .venv
.\.venv\Scripts\python.exe -m pip install -r outputs/df-local-server/requirements-optional.txt
$env:PYTHONPATH = (Resolve-Path outputs/df-local-server).Path
.\.venv\Scripts\python.exe -m dfserver.entrance --no-browser
```

网页入口为 `http://127.0.0.1:8877/`，默认网页数据库是 `outputs/df-local-server/data/local.sqlite3`。网页入口与原游戏客户端的诊断启动是两个流程。

在另一终端从项目根目录执行测试：

```powershell
.\.venv\Scripts\python.exe -m unittest discover -s outputs/df-local-server/tests -t outputs/df-local-server -v
```

`definitions.json` 中 `local_*` 数据用于独立服务测试。不得把这些开发数据当成原客户端的真实配置或物品 ID。

## 原客户端准备

下文的 `python` 需使用上述安装依赖的解释器，例如 `.\.venv\Scripts\python.exe`。指定自有安装位置时，可先设置：

```powershell
$env:DF_LOCAL_SOURCE_GAME = "F:/WeGameApps/rail_apps/DeltaForce(2001918)"
$env:DF_LOCAL_SHADOW_GAME = "F:/deltaforce-local-shadow"
```

1. 准备同版本游戏，默认位于 `../game`。安装在别处时设置 `DF_LOCAL_SOURCE_GAME`；用 `DF_LOCAL_SHADOW_GAME` 指定独立测试目录。源游戏与 shadow 必须不同，硬链接创建要求同一磁盘卷。
2. 运行 `python work/create_local_client_shadow.py`。脚本只读源安装，对 shadow 中的 SDK 和可变文件使用独立副本。
3. 构建本项目提供者，需要自行准备 Zig 编译器和同版本原版 SDK：

```powershell
python outputs/native-account-provider/build_provider.py --sdk "$env:DF_LOCAL_SOURCE_GAME/DeltaForce/Binaries/ThirdParty/WeGame/Win64/rail_api64.dll" --compiler "C:/path/to/zig.exe" --stage work/sdk-local-provider-stage
python outputs/native-account-provider/verify_provider.py --sdk "$env:DF_LOCAL_SOURCE_GAME/DeltaForce/Binaries/ThirdParty/WeGame/Win64/rail_api64.dll" --stage work/sdk-local-provider-stage
```

这一步生成本机 `build-record.json` 和 `validation.json`，不复用其他电脑的验证结果。源 SDK SHA-256 必须为 `9d39a0f5af96d56f465060a582e21faf5c11d5cfdd4e221891d81c58cd7f1723`。

4. 创建自己的原客户端测试账号：从项目根目录设置上述 `PYTHONPATH`，用 `python -m dfserver --port 8878 --database work/native-test-account/save.sqlite3` 启动临时服务。然后在另一终端同样设置 `PYTHONPATH`，执行 `python -m dfserver.accounts register YOUR_LOCAL_USERNAME --port 8878`。密码通过隐藏输入提供。完成后停止这个临时服务。原客户端测试与网页入口使用各自的端口和数据库。

## 6 分钟诊断启动

关闭游戏和 WeGame 后，在项目根目录运行下列命令；Windows UAC 由用户确认：

```powershell
python work/run_native_elevated_trial.py --entry shipping --game-root "$env:DF_LOCAL_SHADOW_GAME" --wire-identity-probe --wire-auth-response-probe --wire-auth-identity-probe --wire-ready-probe --wire-ready-identity-probe --wire-business-login-probe --wire-business-bootstrap-probe --observation-seconds 360 --precreate-game-nick
```

若使用默认目录，`--game-root ../shadow` 即可。多账号库需额外传入 `--native-username`。诊断服务只监听 `127.0.0.1:65010`；测试结束必须核对 `original_sdk_restored` 为 `true`。Shipping 程序版本哈希为 `4254fbe66585f260f1f9dbfc5e302887842552e7baed8939e023160a5e250be0`。

启动前在另一终端挂日志，输出路径和源游戏路径按实际目录填写：

```powershell
python work/watch_client_log.py --source "$env:DF_LOCAL_SHADOW_GAME/DeltaForce/Saved/Logs/DeltaForce.log" --output work/evidence/native-trial-live.log --duration-seconds 420
```

诊断握手和有限的业务实现仍处于开发阶段，只用于本机测试。自动测试通过不代表所有原客户端界面与业务已经可用。

## 协作

从 `main` 创建独立分支，通过 Pull Request 汇总修改。每项客户端映射同时提交来源说明、针对性测试和脱敏的实机结论；原始日志与存档保留本地。提交前运行 `python work/audit_git_upload.py` 检查 Git 索引，详见 [协作记录](docs/COLLABORATION.md)。历史服务 README 保留早期调查内容，最新交接以本页和协作记录为准。
