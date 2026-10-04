# 运行说明

以下 PowerShell 命令从项目根目录执行。推荐独立 Python 3.12 环境；使用 `hashlib.file_digest` 的工具至少需要 Python 3.11。

## 服务与测试

```powershell
python -m venv .venv
.\.venv\Scripts\python.exe -m pip install -r outputs/df-local-server/requirements-optional.txt
$env:PYTHONPATH = (Resolve-Path outputs/df-local-server).Path
.\.venv\Scripts\python.exe -m dfserver.entrance --no-browser
```

网页入口为 `http://127.0.0.1:8877/`，默认网页数据库是 `outputs/df-local-server/data/local.sqlite3`。

在另一终端执行测试：

```powershell
.\.venv\Scripts\python.exe -m unittest discover -s outputs/df-local-server/tests -t outputs/df-local-server -v
```

下文的 `python` 需使用已安装依赖的解释器，例如 `.\.venv\Scripts\python.exe`。`definitions.json` 中 `local_*` 数据是独立服务的测试数据。

## 原客户端准备

1. 准备同版本游戏，默认位于 `../game`。安装在别处时设置下列路径；源游戏与 shadow 必须不同，硬链接创建要求同一磁盘卷。

```powershell
$env:DF_LOCAL_SOURCE_GAME = "F:/WeGameApps/rail_apps/DeltaForce(2001918)"
$env:DF_LOCAL_SHADOW_GAME = "F:/deltaforce-local-shadow"
python work/create_local_client_shadow.py
```

2. 使用自行准备的 Zig 编译器及同版本 SDK，构建并验证本项目提供者：

```powershell
python outputs/native-account-provider/build_provider.py --sdk "$env:DF_LOCAL_SOURCE_GAME/DeltaForce/Binaries/ThirdParty/WeGame/Win64/rail_api64.dll" --compiler "C:/path/to/zig.exe" --stage work/sdk-local-provider-stage
python outputs/native-account-provider/verify_provider.py --sdk "$env:DF_LOCAL_SOURCE_GAME/DeltaForce/Binaries/ThirdParty/WeGame/Win64/rail_api64.dll" --stage work/sdk-local-provider-stage
```

本机生成 `build-record.json` 和 `validation.json`。源 SDK SHA-256 必须为 `9d39a0f5af96d56f465060a582e21faf5c11d5cfdd4e221891d81c58cd7f1723`；Shipping 程序 SHA-256 必须为 `4254fbe66585f260f1f9dbfc5e302887842552e7baed8939e023160a5e250be0`。

3. 设置上述 `PYTHONPATH`，用 `python -m dfserver --port 8878 --database work/native-test-account/save.sqlite3` 启动临时服务。在另一终端同样设置 `PYTHONPATH`，执行 `python -m dfserver.accounts register YOUR_LOCAL_USERNAME --port 8878`，通过隐藏输入设置自己的密码。完成后停止临时服务。原客户端测试与网页入口使用各自的数据库。

如需给该本地测试账号提供默认门禁卡包，先在服务停止时预览，再执行提供：

```powershell
python work/provision_native_test_keychain.py --template-id 11120000001
python work/provision_native_test_keychain.py --template-id 11120000001 --apply
```

工具要求库内恰好一个账号，应用前自动备份存档并核验实际原生库存响应。该模板及六区共 24 格来自客户端原表；提供权限是本地测试策略。已经装备其它卡包时，工具拒绝覆盖，应通过客户端切换。普通新账号不会自动获得卡包。

## 12 分钟原客户端测试

关闭游戏和 WeGame 后，在项目根目录启动日志监听：

```powershell
python work/watch_client_log.py --source "$env:DF_LOCAL_SHADOW_GAME/DeltaForce/Saved/Logs/DeltaForce.log" --output work/evidence/native-trial-live.log --duration-seconds 780
```

在另一终端设置相同路径，执行以下命令，Windows UAC 由用户确认：

```powershell
python work/run_native_elevated_trial.py --entry shipping --game-root "$env:DF_LOCAL_SHADOW_GAME" --wire-identity-probe --wire-auth-response-probe --wire-auth-identity-probe --wire-ready-probe --wire-ready-identity-probe --wire-business-login-probe --wire-business-bootstrap-probe --observation-seconds 720 --precreate-game-nick
```

默认测试时长为 720 秒，届时自动关闭测试客户端；日志监听多保留 60 秒。默认目录可使用 `--game-root ../shadow`；多账号库需额外传入 `--native-username`。诊断服务只监听 `127.0.0.1:65010`，结束后必须核对 `original_sdk_restored` 为 `true`。

游戏本体、原始资源、账号数据库、会话、日志及编译 DLL 保留本地。重新提取所需原始条目需按 [数据来源](../DATA_PROVENANCE.md) 定位；已有静态目录可以直接用于开发。
