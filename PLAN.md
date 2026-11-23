# Claude Guard — 轻量透明防泄漏托盘工具

基于现有 **Clash Verge (`verge-mihomo`)** 构建的本地防泄漏、严格模式 Kill Switch 与启动前自检工具。

## 模块规划

1. **Clash Verge 防泄漏覆写规则 (`clash-verge-override.js`)**
   - 按订阅原有规则分流。增加独立的 Guard-Probe 回环体检入口及 REJECT 兜底。
   - 关闭 Clash 顶层和 DNS 的 IPv6，提供 Windows TUN / DNS 预设。

2. **严格模式 Kill Switch (`guard/firewall.py`)**
   - 通过 Windows 防火墙规则阻止 Claude 进程及 Anthropic IP 段绕过 TUN 走物理网卡直连
   - 支持一键开启、暂停、紧急恢复（Rescue，清理全部规则与系统改动）

3. **系统防泄漏加固 (`guard/hardening.py`)**
   - Chrome / Edge / Firefox WebRTC 防非代理 UDP 泄漏策略
   - 物理网卡 IPv6 开关与恢复
   - 系统时区与出口节点时区比对、一键对齐与还原

4. **防泄漏深度自检 (`guard/doctor.py`)**
   - 检查 Clash Verge / `verge-mihomo` 与 TUN 网卡 (`Mihomo`) 运行状态
   - 检查出口 IP（校验是否与绑定的固定节点一致、是否落入高风控地区）
   - 检查 IPv6 泄漏、DNS 泄漏、WebRTC 策略、时区偏差、冲突代理及残留 `cc-hahaeasy` 项

5. **桌面托盘 GUI (`app.py`)**
   - 系统托盘常驻图标（绿=正常保护 / 黄=存在警告 / 红=防护中断或 IP 变更）
   - 一键开启/关闭保护、运行自检、查看实时状态面板、打开 Rescue 恢复
