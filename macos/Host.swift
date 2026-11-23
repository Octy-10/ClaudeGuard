import AppKit
import Foundation
import NetworkExtension
import Security
import ServiceManagement
import SystemExtensions

private let appID = "io.github.octy-10.claudeguard"
private let extensionID = appID + ".filter"
private let loginAgent = appID + ".login.plist"
private let claudeID = "com.anthropic.claudefordesktop"

private struct HostError: LocalizedError {
    let errorDescription: String?
    init(_ message: String) { errorDescription = message }
}

private final class Completion<Value> {
    private let condition = NSCondition()
    private var result: Result<Value, Error>?

    func finish(_ result: Result<Value, Error>) {
        condition.lock()
        if self.result == nil { self.result = result }
        condition.broadcast()
        condition.unlock()
    }

    func wait(seconds: TimeInterval = 30) throws -> Value {
        let deadline = Date().addingTimeInterval(seconds)
        condition.lock()
        defer { condition.unlock() }
        while result == nil && Date() < deadline {
            if Thread.isMainThread {
                condition.unlock()
                RunLoop.current.run(until: Date().addingTimeInterval(0.025))
                condition.lock()
            } else {
                _ = condition.wait(until: deadline)
            }
        }
        guard let result else { throw HostError("系统操作仍在等待批准或已超时，请重新检查状态。") }
        return try result.get()
    }
}

private final class ExtensionRequest: NSObject, OSSystemExtensionRequestDelegate {
    static var pending: ExtensionRequest?
    let completion = Completion<Void>()
    let enabling: Bool

    init(enabling: Bool) { self.enabling = enabling }

    func requestNeedsUserApproval(_ request: OSSystemExtensionRequest) {
        completion.finish(.failure(HostError("请在系统设置的「登录项与扩展 → 网络扩展」批准 Claude Guard，然后重新操作。")))
    }

    func request(_ request: OSSystemExtensionRequest, didFinishWithResult result: OSSystemExtensionRequest.Result) {
        let success = result == .completed
        completion.finish(success ? .success(()) : .failure(HostError("系统扩展变更需要重新启动 Mac。")))
        Self.pending = nil
    }

    func request(_ request: OSSystemExtensionRequest, didFailWithError error: Error) {
        completion.finish(.failure(error))
        Self.pending = nil
    }

    func request(_ request: OSSystemExtensionRequest, actionForReplacingExtension existing: OSSystemExtensionProperties,
                 withExtension replacement: OSSystemExtensionProperties) -> OSSystemExtensionRequest.ReplacementAction {
        replacement.bundleVersion.compare(existing.bundleVersion, options: .numeric) == .orderedAscending ? .cancel : .replace
    }

    static func run(enabling: Bool) throws {
        let delegate = ExtensionRequest(enabling: enabling)
        DispatchQueue.main.async {
            if let pending = Self.pending, pending.enabling == enabling {
                delegate.completion.finish(.failure(HostError("系统正在处理网络扩展，请先检查系统设置。")))
                return
            }
            guard Self.pending == nil else {
                delegate.completion.finish(.failure(HostError("请先完成或取消系统中待批准的网络扩展操作。")))
                return
            }
            Self.pending = delegate
            let request = enabling
                ? OSSystemExtensionRequest.activationRequest(forExtensionWithIdentifier: extensionID, queue: .main)
                : OSSystemExtensionRequest.deactivationRequest(forExtensionWithIdentifier: extensionID, queue: .main)
            request.delegate = delegate
            OSSystemExtensionManager.shared.submitRequest(request)
        }
        try delegate.completion.wait()
    }
}

private func awaitPreference(_ action: (@escaping (Error?) -> Void) -> Void) throws {
    let completion = Completion<Void>()
    action { error in
        if let error { completion.finish(.failure(error)) }
        else { completion.finish(.success(())) }
    }
    try completion.wait()
}

private let filterLock = NSLock()

private func configured(_ manager: NEFilterManager) -> Bool {
    guard let provider = manager.providerConfiguration else { return false }
    return manager.isEnabled && provider.filterSockets && provider.filterPackets
        && provider.filterDataProviderBundleIdentifier == extensionID && provider.filterPacketProviderBundleIdentifier == extensionID
}

private func filterCommand(_ verb: String) throws -> [String: Any] {
    filterLock.lock()
    defer { filterLock.unlock() }
    let manager = NEFilterManager.shared()
    try awaitPreference { manager.loadFromPreferences(completionHandler: $0) }
    let configuredID = manager.providerConfiguration?.filterDataProviderBundleIdentifier
    if verb == "filter-status" {
        return ["configured": configured(manager)]
    }
    if verb == "filter-enable" && manager.providerConfiguration != nil && configuredID != extensionID {
        throw HostError("当前存在其他来源的网络过滤配置。请在系统设置中检查现有配置。")
    }
    if verb == "filter-enable" {
        guard NSRunningApplication.runningApplications(withBundleIdentifier: claudeID).isEmpty else {
            throw HostError("请先退出 Claude Desktop，启用断网锁后再通过 Guard 启动。")
        }
        try ExtensionRequest.run(enabling: true)
        if configured(manager) { return ["configured": true] }
        let configuration = NEFilterProviderConfiguration()
        configuration.filterDataProviderBundleIdentifier = extensionID
        configuration.filterPacketProviderBundleIdentifier = extensionID
        configuration.serverAddress = "127.0.0.1"
        configuration.filterSockets = true
        configuration.filterPackets = true
        configuration.filterBrowsers = false
        manager.providerConfiguration = configuration
        manager.localizedDescription = "Claude Guard"
        manager.isEnabled = true
        try awaitPreference { manager.saveToPreferences(completionHandler: $0) }
        try awaitPreference { manager.loadFromPreferences(completionHandler: $0) }
        guard configured(manager) else {
            throw HostError("系统尚未保存 Claude Guard 过滤配置。")
        }
        return ["configured": true]
    }
    if configuredID == extensionID {
        try awaitPreference { manager.removeFromPreferences(completionHandler: $0) }
        try awaitPreference { manager.loadFromPreferences(completionHandler: $0) }
        guard manager.providerConfiguration?.filterDataProviderBundleIdentifier != extensionID else {
            throw HostError("系统仍保留 Claude Guard 过滤配置。")
        }
    }
    if verb == "filter-uninstall" { try ExtensionRequest.run(enabling: false) }
    return ["configured": false]
}

private func loginCommand(_ verb: String) throws -> [String: Any] {
    let service = SMAppService.agent(plistName: loginAgent)
    if verb == "login-enable" && service.status != .enabled { try service.register() }
    if verb == "login-disable" && [.enabled, .requiresApproval].contains(service.status) { try service.unregister() }
    return ["enabled": service.status == .enabled, "approval": service.status == .requiresApproval]
}

private func claudeCommand(_ verb: String) throws -> [String: Any] {
    let running = NSRunningApplication.runningApplications(withBundleIdentifier: claudeID)
    if verb == "claude-quit" {
        guard running.allSatisfy({ $0.terminate() }) else { throw HostError("Claude 拒绝退出，请在客户端中手动退出。") }
        return ["count": running.count]
    }
    guard running.isEmpty else { throw HostError("请先完整退出当前 Claude 客户端，再通过 Guard 启动。") }
    guard let app = NSWorkspace.shared.urlForApplication(withBundleIdentifier: claudeID) else {
        throw HostError("未找到 Claude Desktop。")
    }
    var code: SecStaticCode?
    var requirement: SecRequirement?
    let identifier = "identifier \"\(claudeID)\" and anchor apple generic and certificate leaf[subject.OU] = \"Q6L2SF6YDW\""
    guard SecStaticCodeCreateWithPath(app as CFURL, [], &code) == errSecSuccess, let code,
          SecRequirementCreateWithString(identifier as CFString, [], &requirement) == errSecSuccess, let requirement,
          SecStaticCodeCheckValidity(code, [], requirement) == errSecSuccess else { throw HostError("无法核实 Claude Desktop 的签名。") }
    let completion = Completion<Void>()
    DispatchQueue.main.async {
        let configuration = NSWorkspace.OpenConfiguration()
        configuration.arguments = ["--proxy-server=http://127.0.0.1:17898", "--proxy-bypass-list=localhost;127.0.0.1;[::1]", "--disable-quic"]
        NSWorkspace.shared.openApplication(at: app, configuration: configuration) { _, error in
            if let error { completion.finish(.failure(error)) }
            else { completion.finish(.success(())) }
        }
    }
    try completion.wait()
    return [:]
}

private func browserPolicies() -> [String: Any] {
    let browsers = ["Chrome": "com.google.Chrome", "Edge": "com.microsoft.edgemac", "Firefox": "org.mozilla.firefox"]
    var result = [String: Any]()
    for (name, domain) in browsers where NSWorkspace.shared.urlForApplication(withBundleIdentifier: domain) != nil {
        let key = name == "Chrome" ? "WebRtcIPHandling" : name == "Edge" ? "WebRtcLocalhostIpHandling" : "Preferences"
        let value = CFPreferencesCopyAppValue(key as CFString, domain as CFString)
        let forced = CFPreferencesAppValueIsForced(key as CFString, domain as CFString)
        if name == "Firefox" {
            let preferences = value as? [String: [String: Any]]
            let peerConnection = preferences?["media.peerconnection.enabled"]
            result[name] = forced && peerConnection?["Value"] as? Bool == false && peerConnection?["Status"] as? String == "locked"
        } else {
            result[name] = forced && value as? String == "disable_non_proxied_udp"
        }
    }
    return result
}

@_cdecl("claude_guard_host_command")
public func guardHostCommand(_ command: UnsafePointer<CChar>) -> UnsafeMutablePointer<CChar>? {
    var response: [String: Any]
    let verb = String(cString: command)
    do {
        switch verb {
        case "filter-status", "filter-enable", "filter-disable", "filter-uninstall": response = try filterCommand(verb)
        case "login-status", "login-enable", "login-disable": response = try loginCommand(verb)
        case "claude-quit", "claude-launch": response = try claudeCommand(verb)
        case "webrtc-status": response = ["browsers": browserPolicies()]
        default: throw HostError("不支持的系统操作。")
        }
        response["ok"] = true
    } catch {
        response = ["ok": false, "message": error.localizedDescription]
    }
    guard let data = try? JSONSerialization.data(withJSONObject: response) else { return nil }
    return strdup(String(decoding: data, as: UTF8.self))
}

@_cdecl("claude_guard_host_free")
public func guardHostFree(_ pointer: UnsafeMutablePointer<CChar>?) { free(pointer) }
