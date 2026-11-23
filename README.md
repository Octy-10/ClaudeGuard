# Claude Guard — 现代透明的 Claude 防封环境一键配置与守护工具

专为复用 **本机 Clash Verge (`verge-mihomo`)** 打造：不替换你的 VPN，仅专注**一键配置与实时监控 Claude 防封环境**。采用 **WebView2 原生暗夜桌面控制台 (`pywebview`) + 并发 Python 后端 + Win32 原生系统托盘**，无开放本地端口、无闭源常驻 `SYSTEM` 服务、无硬件指纹上报。

---

## 核心能力（与 Clash Verge 完美互补）

| 模块 | 实现原理 | 可逆还原 |
|---|---|---|
| **断网锁 Kill Switch** | Windows Defender 防火墙按**物理网卡**阻断 Anthropic IPv4/IPv6 段与本地 Claude 客户端直连；TUN 正常时无感通行，TUN 崩溃时秒断防裸连 | 一键关闭 / Rescue |
| **物理网卡锁 DNS** | `Set-DnsClientServerAddress` 将物理网卡锁定为 `1.1.1.1 / 8.8.8.8`，防多宿解析回落本地运营商 DNS（自动备份原 DHCP / 静态 DNS） | 一键精确还原 |
| **禁用物理网卡 IPv6** | `Disable-NetAdapterBinding -ComponentID ms_tcpip6` 防止双栈直连暴露 | 自动备份并还原 |
| **防 WebRTC 泄漏** | 写入 Chrome / Edge / Firefox 组策略限制 WebRTC，并记录修改前的值 | 按备份还原策略 |
| **系统时区同步** | `tzutil /s` 一键对齐出口 IP 所在时区，自动备份原时区 | 一键恢复原时区 |
| **安全关闭 Claude 桌面端** | 按 `Anthropic, PBC` 数字签名精确匹配并结束 Claude 进程，切环境无残留连接 | 按需手动触发 |
| **Clash Verge 覆写脚本** | 内置 [clash-verge-override.js](clash-verge-override.js) 添加仅限回环的测试入口。Claude 和其他应用按订阅规则分流 | 可移除全局扩展脚本 |
| **9 项自检与托盘哨兵** | 核对有效的防火墙规则和 Mihomo 回环体检入口，通过该入口做 HTTPS 探测。可监控测试出口 IP 漂移 | 最小化到托盘常驻 |

---

## 快速开始

### 1. 依赖（首次运行）
安装桌面窗口和 Clash 配置审计所需依赖。
```powershell
python -m pip install -r requirements.txt
```

### 2. 验证运行环境与并发自检
在 `E:\Code\Claude防护` 运行：
```powershell
python verify.py
```

### 3. 启动现代化可视化控制台
双击 [start_guard.bat](start_guard.bat)（弹出标准 UAC 提权确认，打开桌面控制台）：
1. 点击总览的 **「配置出口检测」**，复制完整脚本，替换 **Clash Verge → 订阅 → 全局扩展脚本** 的旧内容，再应用订阅。
2. 在 Clash 使用规则模式，开启 TUN、自动路由、严格路由和 DNS，关闭 Clash 顶层和 DNS 的 IPv6。在 **Guard-Probe** 组选择一个内联代理节点。首次加载和无可用节点时使用 `REJECT`。
3. 返回 Guard 自检或运行 IP 体检。探测通过 Mihomo 的 `127.0.0.1:17897`，VM 继续使用原来的局域网 mixed-port。测试结果覆盖 Guard-Probe 所选节点。
4. 在总览点击 **「一键配置」** 应用防护。如需监控测试节点的出口变化，点击 **「开始监控」**。点击窗口关闭按钮 `×` 可最小化到托盘。

---

## 紧急恢复与彻底卸载

- 在标题栏 **「···」** 菜单选择 **「紧急恢复」**，或双击 [rescue.bat](rescue.bat)。程序按备份恢复已记录的系统改动，失败的项保留备份并写入日志。
- 旧版 WebRTC 备份只记录是否修改过。遇到该提示时，请手动核对原组策略。完成恢复后再卸载，并保留尚未恢复项目的备份。
