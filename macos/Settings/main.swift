import Darwin
import Foundation
import SystemConfiguration

private let statePath = "/var/db/io.github.octy-10.claudeguard"
private let journalURL = URL(fileURLWithPath: statePath).appendingPathComponent("backup.plist")
private let dnsServers = ["1.1.1.1", "8.8.8.8"]

private struct SettingsError: LocalizedError {
    let errorDescription: String?
    init(_ description: String) { self.errorDescription = description }
}

private struct Snapshot: Codable, Equatable {
    let configuration: Data?
    let enabled: Bool

    init(_ value: SCNetworkProtocol) throws {
        enabled = SCNetworkProtocolGetEnabled(value)
        if let current = SCNetworkProtocolGetConfiguration(value) {
            configuration = try PropertyListSerialization.data(fromPropertyList: current, format: .binary, options: 0)
        } else {
            configuration = nil
        }
    }

    func fields() throws -> NSDictionary? {
        guard let configuration else { return nil }
        guard let fields = try PropertyListSerialization.propertyList(from: configuration, options: [], format: nil) as? NSDictionary else {
            throw SettingsError("备份中的网络配置无效。")
        }
        return fields
    }

    func matches(_ other: Snapshot) throws -> Bool {
        if enabled != other.enabled { return false }
        return try fields()?.isEqual(other.fields()) ?? (other.configuration == nil)
    }

    func restore(_ value: SCNetworkProtocol) throws {
        let content = try fields() as? [String: Any]
        guard SCNetworkProtocolSetConfiguration(value, content as CFDictionary?), SCNetworkProtocolSetEnabled(value, enabled) else {
            throw SettingsError("无法恢复原网络协议配置。")
        }
    }
}

private struct Change: Codable {
    let before: Snapshot
    let applied: Snapshot
}

private struct TimeChange: Codable {
    let before: String
    let applied: String
}

private struct Journal: Codable {
    var dns: [String: Change] = [:]
    var ipv6: [String: Change] = [:]
    var timezone: TimeChange?
}

private enum Setting: String {
    case dns, ipv6

    var protocolName: CFString { self == .dns ? kSCNetworkProtocolTypeDNS : kSCNetworkProtocolTypeIPv6 }
    var record: WritableKeyPath<Journal, [String: Change]> { self == .dns ? \.dns : \.ipv6 }

    func isProtected(_ value: SCNetworkProtocol) -> Bool {
        if self == .ipv6 { return !SCNetworkProtocolGetEnabled(value) }
        let config = SCNetworkProtocolGetConfiguration(value) as? [String: Any]
        return SCNetworkProtocolGetEnabled(value) && config?[kSCPropNetDNSServerAddresses as String] as? [String] == dnsServers
    }

    func apply(_ value: SCNetworkProtocol) throws {
        if self == .ipv6 {
            guard SCNetworkProtocolSetEnabled(value, false) else { throw SettingsError("无法关闭网络服务的 IPv6。") }
        } else {
            var config = SCNetworkProtocolGetConfiguration(value) as? [String: Any] ?? [:]
            config[kSCPropNetDNSServerAddresses as String] = dnsServers
            guard SCNetworkProtocolSetConfiguration(value, config as CFDictionary), SCNetworkProtocolSetEnabled(value, true) else {
                throw SettingsError("无法保存网络服务的 DNS。")
            }
        }
    }
}

private func preferences() throws -> SCPreferences {
    guard let result = SCPreferencesCreate(nil, "Claude Guard" as CFString, nil) else { throw SettingsError("无法访问 macOS 网络配置。") }
    return result
}

private func physicalServices(_ preferences: SCPreferences) throws -> [SCNetworkService] {
    guard let location = SCNetworkSetCopyCurrent(preferences), let services = SCNetworkSetCopyServices(location) as? [SCNetworkService] else {
        throw SettingsError("无法读取当前网络位置。")
    }
    return services.filter { service in
        guard SCNetworkServiceGetEnabled(service), let interface = SCNetworkServiceGetInterface(service),
              let name = SCNetworkInterfaceGetBSDName(interface) as String?, let type = SCNetworkInterfaceGetInterfaceType(interface) else { return false }
        return name.range(of: "^en[0-9]+$", options: .regularExpression) != nil
            && [kSCNetworkInterfaceTypeEthernet as String, kSCNetworkInterfaceTypeIEEE80211 as String].contains(type as String)
    }
}

private func withJournal<T>(_ action: (inout Journal) throws -> T) throws -> T {
    guard geteuid() == 0 else { throw SettingsError("此操作需要管理员授权。") }
    if mkdir(statePath, 0o700) != 0 && errno != EEXIST { throw SettingsError("无法创建系统备份目录。") }
    var metadata = stat()
    guard lstat(statePath, &metadata) == 0, (metadata.st_mode & S_IFMT) == S_IFDIR,
          metadata.st_uid == 0, (metadata.st_mode & 0o077) == 0 else { throw SettingsError("系统备份目录权限异常。") }
    let lock = open(statePath + "/operations.lock", O_CREAT | O_RDWR | O_NOFOLLOW, 0o600)
    guard lock >= 0 else { throw SettingsError("无法打开系统设置锁。") }
    defer { close(lock) }
    guard flock(lock, LOCK_EX | LOCK_NB) == 0 else { throw SettingsError("另一项系统设置正在变更。") }
    var journal = Journal()
    if lstat(journalURL.path, &metadata) == 0 {
        guard (metadata.st_mode & S_IFMT) == S_IFREG, metadata.st_uid == 0, (metadata.st_mode & 0o077) == 0 else {
            throw SettingsError("系统备份文件权限异常。")
        }
        journal = try PropertyListDecoder().decode(Journal.self, from: Data(contentsOf: journalURL))
    } else if errno != ENOENT { throw SettingsError("无法读取系统备份文件。") }
    return try action(&journal)
}

private func save(_ journal: Journal) throws {
    try PropertyListEncoder().encode(journal).write(to: journalURL, options: .atomic)
}

private func changeNetwork(_ setting: Setting, enable: Bool, journal: inout Journal) throws -> String {
    let prefs = try preferences()
    guard SCPreferencesLock(prefs, false) else { throw SettingsError("macOS 网络配置正在使用中，请稍候重试。") }
    defer { SCPreferencesUnlock(prefs) }
    let services: [SCNetworkService]
    if enable { services = try physicalServices(prefs) }
    else { services = SCNetworkServiceCopyAll(prefs) as? [SCNetworkService] ?? [] }
    let targets = Dictionary(uniqueKeysWithValues: services.compactMap { service -> (String, SCNetworkProtocol)? in
        guard let id = SCNetworkServiceGetServiceID(service),
              let protocolSettings = SCNetworkServiceCopyProtocol(service, setting.protocolName) else { return nil }
        return (id as String, protocolSettings)
    })
    var records = journal[keyPath: setting.record]
    var problems = 0
    if enable {
        guard !services.isEmpty, targets.count == services.count else { throw SettingsError("当前网络位置缺少可管理的 Wi-Fi 或以太网服务。") }
        for (id, protocolSettings) in targets {
            let current = try Snapshot(protocolSettings)
            if let saved = records[id] {
                let matchesBefore = try current.matches(saved.before)
                let matchesApplied = try current.matches(saved.applied)
                guard matchesBefore || matchesApplied else { throw SettingsError("发现其他程序修改过网络服务，请先核对现有配置。") }
            }
            if setting.isProtected(protocolSettings) { continue }
            try setting.apply(protocolSettings)
            records[id] = Change(before: records[id]?.before ?? current, applied: try Snapshot(protocolSettings))
        }
        journal[keyPath: setting.record] = records
        try save(journal)
    } else {
        guard !records.isEmpty else { return "没有需要恢复的设置。" }
        for (id, saved) in records {
            guard let protocolSettings = targets[id] else { problems += 1; continue }
            let current = try Snapshot(protocolSettings)
            if try !current.matches(saved.before) {
                guard try current.matches(saved.applied) else { problems += 1; continue }
                try saved.before.restore(protocolSettings)
            }
            records.removeValue(forKey: id)
        }
    }
    guard SCPreferencesCommitChanges(prefs), SCPreferencesApplyChanges(prefs) else {
        throw SettingsError("macOS 未完全应用配置，恢复记录已保留。")
    }
    if !enable {
        journal[keyPath: setting.record] = records
        try save(journal)
    }
    if problems > 0 { throw SettingsError("有 \(problems) 个网络服务已被删除或由其他来源修改，相关恢复记录已保留。") }
    return enable ? "已应用到当前网络位置的 \(targets.count) 个服务。" : "原设置已恢复。"
}

private func validateTimeZone(_ identifier: String) throws {
    guard identifier.range(of: "^[A-Za-z0-9_+/-]{1,100}$", options: .regularExpression) != nil,
          TimeZone(identifier: identifier) != nil else { throw SettingsError("无效的 IANA 时区。") }
}

private func setTimeZone(_ identifier: String) throws {
    try validateTimeZone(identifier)
    let process = Process()
    process.executableURL = URL(fileURLWithPath: "/usr/sbin/systemsetup")
    process.arguments = ["-settimezone", identifier]
    process.standardOutput = FileHandle.nullDevice
    process.standardError = FileHandle.nullDevice
    try process.run()
    process.waitUntilExit()
    guard process.terminationStatus == 0, try currentTimeZone() == identifier else { throw SettingsError("未验证到目标时区；请检查系统的自动时区设置。") }
}

private func currentTimeZone() throws -> String {
    let target = try FileManager.default.destinationOfSymbolicLink(atPath: "/etc/localtime")
    guard let range = target.range(of: "/zoneinfo/") else { throw SettingsError("无法识别当前系统时区。") }
    return String(target[range.upperBound...])
}

private func changeTimeZone(_ target: String?, journal: inout Journal) throws -> String {
    let current = try currentTimeZone()
    if let target {
        try validateTimeZone(target)
        if current == target { return "当前时区已是 \(target)。" }
        if let previous = journal.timezone, current != previous.applied && current != previous.before {
            throw SettingsError("系统时区已由其他来源修改，原恢复记录已保留。")
        }
        let previous = journal.timezone
        journal.timezone = TimeChange(before: previous?.before ?? current, applied: target)
        try save(journal)
        do { try setTimeZone(target) }
        catch {
            if (try? currentTimeZone()) == current {
                journal.timezone = previous
                try save(journal)
            }
            throw error
        }
        return "时区已设置为 \(target)。"
    }
    guard let change = journal.timezone else { return "没有需要恢复的时区。" }
    if current != change.before {
        guard current == change.applied else { throw SettingsError("系统时区已由其他来源修改，原恢复记录已保留。") }
        try setTimeZone(change.before)
    }
    journal.timezone = nil
    try save(journal)
    return "原时区已恢复。"
}

private func networkStatus() throws -> [String: Any] {
    let prefs = try preferences()
    let services = try physicalServices(prefs)
    func verified(_ setting: Setting) -> Bool {
        !services.isEmpty && services.allSatisfy { service in
            guard let value = SCNetworkServiceCopyProtocol(service, setting.protocolName) else { return false }
            return setting.isProtected(value)
        }
    }
    return ["services": services.compactMap { SCNetworkServiceGetName($0) as String? }, "dns": verified(.dns), "ipv6": verified(.ipv6)]
}

umask(0o077)
let arguments = Array(CommandLine.arguments.dropFirst())
var result: [String: Any]
do {
    switch arguments.first ?? "" {
    case "status" where arguments.count == 1:
        result = try networkStatus()
    case "dns-on", "dns-off", "ipv6-on", "ipv6-off":
        guard arguments.count == 1, let verb = arguments.first, let setting = Setting(rawValue: String(verb.split(separator: "-")[0])) else {
            throw SettingsError("无效的网络设置参数。")
        }
        let message = try withJournal { try changeNetwork(setting, enable: verb.hasSuffix("-on"), journal: &$0) }
        result = ["message": message]
    case "network-on" where arguments.count == 1:
        result = try withJournal { journal in
            _ = try changeNetwork(.dns, enable: true, journal: &journal)
            _ = try changeNetwork(.ipv6, enable: true, journal: &journal)
            return ["message": "已应用 DNS 和 IPv6 防护。"]
        }
    case "timezone-set" where arguments.count == 2:
        result = ["message": try withJournal { try changeTimeZone(arguments[1], journal: &$0) }]
    case "timezone-restore" where arguments.count == 1:
        result = ["message": try withJournal { try changeTimeZone(nil, journal: &$0) }]
    case "rescue" where arguments.count == 1:
        result = try withJournal { journal in
            var failures: [String] = []
            for setting in [Setting.dns, .ipv6] {
                do { _ = try changeNetwork(setting, enable: false, journal: &journal) }
                catch { failures.append(error.localizedDescription) }
            }
            do { _ = try changeTimeZone(nil, journal: &journal) }
            catch { failures.append(error.localizedDescription) }
            if !failures.isEmpty { throw SettingsError(failures.joined(separator: "；")) }
            return ["message": "DNS、IPv6 和时区恢复已完成。"]
        }
    default:
        throw SettingsError("未知的系统设置操作。")
    }
    result["ok"] = true
} catch {
    result = ["ok": false, "message": error.localizedDescription]
}
let data = try JSONSerialization.data(withJSONObject: result)
print(String(decoding: data, as: UTF8.self))
