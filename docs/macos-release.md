# macOS 安装包构建与验证

正式版支持 macOS 15 及更新版本，分别提供 Apple Silicon（`arm64`）和 Intel（`x86_64`）安装包。安装器把应用放到 `/Applications/ClaudeGuard.app`，把独立的设置组件放到 `/Library/PrivilegedHelperTools`。网络扩展和登录项由 macOS 管理。

## 防护范围

- Native Network Extension 识别 Claude Desktop 主程序及其签名标识下的子进程，限制它们的外部套接字。Guard 以 `127.0.0.1:17898` 启动官方 Claude Desktop。该入口由 Clash 的 **Guard-Claude** 组处理，组内只有独立远端节点与 `REJECT`。
- **Guard-Probe** 使用 `127.0.0.1:17897`，用于出口巡检和 IP 体检。两个入口均核对运行 YAML、监听地址和 Mihomo 进程，诊断结果按各自的节点理解。
- DNS、IPv6 修改针对当前网络位置中已启用的 Wi-Fi 或以太网服务。备份按 macOS 网络服务 ID 存在 `/var/db/io.github.octy-10.claudeguard/backup.plist`。重复应用保留原始值，恢复时核对当前值，其他来源的修改会触发冲突并保留备份。
- Chrome 和 Edge 描述文件限制非代理 WebRTC UDP，Firefox 描述文件禁用 `RTCPeerConnection`。系统设置负责安装和移除，重启相应浏览器后可在浏览器策略页核验。浏览器已有受管策略时，先由设备管理员核对策略冲突。
- 物理接口出站还使用 Windows 版共享的已知 Anthropic IPv4 和 IPv6 地址段。该地址规则同样作用于浏览器和 CLI 流量。Claude Code CLI、浏览器和其他应用目前以地址段规则为限，完整的应用身份限制覆盖 Claude Desktop。

## 证书、描述文件和公证

在 Apple Developer 为以下两个明确的标识符配置 **Network Extensions → Content Filter Provider**，生成适用于 Developer ID 分发的 provisioning profile。宿主应用还使用 System Extension 安装权限。

| 用途 | Bundle ID |
| --- | --- |
| 主应用 | `io.github.octy-10.claudeguard` |
| 过滤系统扩展 | `io.github.octy-10.claudeguard.filter` |

在 GitHub 仓库创建 `macos-release` 环境。Profile、证书和公证密钥通过环境密钥配置。

| 环境变量 | 值 |
| --- | --- |
| `MACOS_TEAM_ID` | 10 位 Apple Developer Team ID |
| `MACOS_APPLICATION_IDENTITY` | Developer ID Application 签名身份全名 |
| `MACOS_INSTALLER_IDENTITY` | Developer ID Installer 签名身份全名 |

| 环境密钥 | 值 |
| --- | --- |
| `MACOS_APPLICATION_P12`、`MACOS_INSTALLER_P12` | 带私钥的两个 P12 文件的 Base64 |
| `MACOS_APPLICATION_P12_PASSWORD`、`MACOS_INSTALLER_P12_PASSWORD` | 对应 P12 的密码 |
| `MACOS_APP_PROFILE_B64`、`MACOS_FILTER_PROFILE_B64` | 主应用和网络扩展的 provisioning profile 文件的 Base64 |
| `MACOS_NOTARY_KEY_B64` | Apple 公证 API `.p8` 私钥文件的 Base64 |
| `MACOS_NOTARY_KEY_ID`、`MACOS_NOTARY_ISSUER_ID` | 公证 API Key ID 和 Issuer ID |

在 GitHub Actions 运行 **macOS signed release**，输入与 `guard/__init__.py` 一致、且指向 `main` 历史的版本标签。工作流编译 Swift 组件和两种 `.app`，校验 provisioning profile，签名构建 `.pkg`，提交 Apple 公证并贴附票据。默认生成可下载的构建产物。启用 `publish` 后，工作流将两个包和 `latest-macos.json` 上传至对应的 GitHub Release。已有同名资产时，GitHub 会提示冲突。

## 验收场景

用签名安装包在 Apple Silicon 和 Intel Mac 验证。普通 CI 的临时签名构建用于检查编译与启动，系统扩展实际启用需要 Developer ID 构建和本机批准。

| 场景 | 通过条件 |
| --- | --- |
| 从浏览器下载安装包 | Gatekeeper 接受安装包、安装到「应用程序」，应用启动并能进入诊断页 |
| 网络扩展批准和拒绝 | 批准后报告扩展状态，拒绝时界面给出处理入口，未启用时受保护启动不可用 |
| 正常连接与异常切换 | Claude Desktop 由 Guard-Claude 启动后可连接。退出 Clash、拔网线后接回、切换 Wi-Fi、睡眠唤醒时，核对客户端套接字与物理接口抓包，确认无直连回落。浏览器和 CLI 通过物理接口访问已知受保护地址应被阻止，其他目标按原网络策略处理 |
| 重复启用和恢复 | 分别使用 DHCP、固定 DNS 与自定义 IPv6。重复应用后恢复到原值，外部改动时保留备份并报告冲突 |
| 登录、WebRTC 和更新 | 登录批准后可在菜单栏找到 Guard，浏览器策略可核对与移除，按照 CPU 架构获取正确的已签名安装包 |

更新时先退出 Guard 和 Claude Desktop。安装后打开 Guard，重新开启断网锁以更新已注册的系统扩展。GUI 无法打开时，可在用户终端运行 `/Applications/ClaudeGuard.app/Contents/MacOS/ClaudeGuard --doctor`，也可将参数换为 `--rescue` 执行恢复。恢复时系统设置操作仍通过 macOS 授权对话框处理。

[Apple Network Extension 部署说明](https://developer.apple.com/documentation/technotes/tn3134-network-extension-provider-deployment) · [Apple Developer ID 公证说明](https://developer.apple.com/documentation/security/notarizing-macos-software-before-distribution/)
