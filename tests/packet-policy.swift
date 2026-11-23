@main
struct PacketPolicyTest {
    static func main() {
        var ipv4 = [UInt8](repeating: 0, count: 20)
        ipv4[0] = 0x45
        ipv4.replaceSubrange(16..<20, with: [160, 79, 104, 1])
        precondition(ipv4.withUnsafeBytes { shouldBlockDirectPacket($0, interface: "en0") })
        precondition(!ipv4.withUnsafeBytes { shouldBlockDirectPacket($0, interface: "utun12") })
        precondition(!ipv4.withUnsafeBytes { shouldBlockDirectPacket($0, interface: "lo0") })
        ipv4.replaceSubrange(16..<20, with: [160, 79, 112, 1])
        precondition(!ipv4.withUnsafeBytes { shouldBlockDirectPacket($0, interface: "en0") })

        var ipv6 = [UInt8](repeating: 0, count: 40)
        ipv6[0] = 0x60
        ipv6.replaceSubrange(24..<30, with: [0x26, 0x07, 0x6b, 0xc0, 0, 0])
        precondition(ipv6.withUnsafeBytes { shouldBlockDirectPacket($0, interface: "en5") })
        ipv6[29] = 1
        precondition(!ipv6.withUnsafeBytes { shouldBlockDirectPacket($0, interface: "en5") })
        precondition(![UInt8(0x60)].withUnsafeBytes { shouldBlockDirectPacket($0, interface: "en0") })
    }
}
