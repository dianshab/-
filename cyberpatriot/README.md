# CyberPatriot Windows 11 Fixed v3 (archived, unverified)

> **状态：历史版本 / 未验证可正常运行。** 用户此前报告运行 PowerShell 或 CMD 启动器后窗口仍会立即关闭，且没有确认获得 CyberPatriot 评分。此存档是为保存源码，不代表问题已修复。

## 文件

- `CyberPatriot_Win11_Fixed_v3.ps1`：入口 PowerShell 脚本（默认 Apply）。
- `CyberPatriot_Win11_Fixed_v3_Core.ps1`：实际检查与配置逻辑。
- `01_Apply_KEEP_OPEN.cmd`：尝试以 Apply 模式启动，**可能修改系统策略**。
- `02_Check_ONLY_KEEP_OPEN.cmd`：Audit 模式启动，仅检查。
- `README_启动说明.txt`：原版使用说明。

这些文件必须放在同一个文件夹内；单独下载入口 .ps1 无法调用 Core。

## 安全建议

1. 先阅读当轮 README 与 Forensics Questions，确认关键服务和不可更改的配置。
2. 先使用 `02_Check_ONLY_KEEP_OPEN.cmd` 检查，不要在真实机器或未备份的比赛镜像上直接执行 Apply。
3. 即使命令执行成功，也不能证明比赛计分成功。应检查 Scoring Report 和实际策略值。
4. 本脚本不应替代按 README 核对账户、管理员、共享、远程桌面及必要服务。
5. 若启动器闪退，先在已经打开的命令提示符窗口中运行，并保留错误信息进行诊断。

此文件夹保留原始 v3 代码及启动器，不对原有系统安全设置提出新的无条件修改建议。
