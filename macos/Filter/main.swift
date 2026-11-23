import Foundation
import Network
import NetworkExtension
import Security

private let claudeID = "com.anthropic.claudefordesktop"
private let claudeTeam = "Q6L2SF6YDW"

private func isClaudeIdentifier(_ value: String?) -> Bool {
    guard let value else { return false }
    let identifier = value.hasPrefix(claudeTeam + ".") ? String(value.dropFirst(claudeTeam.count + 1)) : value
    return identifier == claudeID || identifier.hasPrefix(claudeID + ".")
}

private func isClaudeProcess(_ token: Data?) -> Bool {
    guard let token else { return false }
    var code: SecCode?
    let attributes = [kSecGuestAttributeAudit as String: token] as CFDictionary
    guard SecCodeCopyGuestWithAttributes(nil, attributes, [], &code) == errSecSuccess, let code else { return false }
    var staticCode: SecStaticCode?
    guard SecCodeCopyStaticCode(code, [], &staticCode) == errSecSuccess, let staticCode else { return false }
    var info: CFDictionary?
    let flags = SecCSFlags(rawValue: UInt32(kSecCSSigningInformation))
    guard SecCodeCopySigningInformation(staticCode, flags, &info) == errSecSuccess,
          let fields = info as? [String: Any],
          fields[kSecCodeInfoTeamIdentifier as String] as? String == claudeTeam else { return false }
    return isClaudeIdentifier(fields[kSecCodeInfoIdentifier as String] as? String)
}

@objc(GuardFilterDataProvider)
final class GuardFilterDataProvider: NEFilterDataProvider {
    override func startFilter(completionHandler: @escaping @Sendable (Error?) -> Void) {
        // The default action sends every eligible socket flow to handleNewFlow.
        apply(nil, completionHandler: completionHandler)
    }

    override func stopFilter(with reason: NEProviderStopReason, completionHandler: @escaping @Sendable () -> Void) {
        completionHandler()
    }

    override func handleNewFlow(_ flow: NEFilterFlow) -> NEFilterNewFlowVerdict {
        let appToken = flow.sourceAppAuditToken
        let processToken = flow.sourceProcessAuditToken
        let isClaude = isClaudeProcess(appToken)
            || (processToken != appToken && isClaudeProcess(processToken))
        guard isClaude else { return .allow() }
        guard let socket = flow as? NEFilterSocketFlow,
              let endpoint = socket.remoteEndpoint as? NWHostEndpoint else { return .drop() }
        // Keep local OAuth and MCP callbacks available. Hostnames are never resolved here.
        return ["127.0.0.1", "::1", "::ffff:127.0.0.1"].contains(endpoint.hostname) ? .allow() : .drop()
    }
}

@objc(GuardPacketProvider)
final class GuardPacketProvider: NEFilterPacketProvider {
    override func startFilter(completionHandler: @escaping @Sendable (Error?) -> Void) {
        packetHandler = { _, interface, direction, data, count in
            guard direction == .outbound else { return .allow }
            let name = String(cString: nw_interface_get_name(interface))
            let packet = UnsafeRawBufferPointer(start: data, count: count)
            return shouldBlockDirectPacket(packet, interface: name) ? .drop : .allow
        }
        completionHandler(nil)
    }

    override func stopFilter(with reason: NEProviderStopReason, completionHandler: @escaping @Sendable () -> Void) {
        packetHandler = nil
        completionHandler()
    }
}

NEProvider.startSystemExtensionMode()
dispatchMain()
