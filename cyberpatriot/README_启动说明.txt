CyberPatriot Windows 11 Fixed v3 - 使用说明

最简单且最稳妥的运行方法：
1. 完整解压 ZIP（不要直接在压缩包内运行）。
2. 双击 01_Apply_KEEP_OPEN.cmd，允许管理员权限 (UAC)。
3. 如出现两个窗口，请查看新打开的管理员 PowerShell 窗口。
4. 等到显示 RUN SUMMARY，再检查 Verified / Error / Review 项目。
5. 查看 Scoring Report 的变化，不能仅凭脚本输出判断得分。
6. 当看到 Press ENTER 后，截图或复制错误信息，再按 Enter。

如果想用右键 > Run with PowerShell：
请右键 CyberPatriot_Win11_Fixed_v3.ps1，不能用 _Core.ps1 或旧的 v2 脚本。
该入口会尝试请求管理员权限，并在结束或出现启动错误时等待 Enter。
如果 PowerShell 连脚本入口都无法解析/执行（例如组策略禁止脚本），
改用 01_Apply_KEEP_OPEN.cmd；它始终有 pause。

检查但不修复：02_Check_ONLY_KEEP_OPEN.cmd

注意：此包保留 v2 固定加固逻辑，主要修复“闪退/看不到报错”。
仍不自动删除账户、共享、软件、桌面文件，也不保证评分。
写入操作前的备份、报告在 C:\ProgramData\CyberPatriotFixed\ 中。

如果仍然没有得分，请提供：
- PowerShell/命令行窗口中 ERROR 或 PRECHECK FAILED 的原文截图
- 最新的 run.log、summary.csv（以及 launcher_v3_*.txt）
- 本轮 Scoring Report 截图/文字

适用：Windows 11 Pro / Education / Enterprise，独立本地机器。
如果没有管理员权限或执行策略受组织强制限制，不尝试绕过组织策略。