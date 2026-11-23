struct AddressPrefix {
    let bytes: [UInt8]
    let bits: Int

    func contains(_ packet: UnsafeRawBufferPointer, at offset: Int) -> Bool {
        let fullBytes = bits / 8
        let remaining = bits % 8
        if fullBytes > 0 {
            for index in 0..<fullBytes where packet[offset + index] != bytes[index] { return false }
        }
        if remaining == 0 { return true }
        let mask = UInt8.max << (8 - remaining)
        return (packet[offset + fullBytes] & mask) == (bytes[fullBytes] & mask)
    }
}

// Packet Filter Provider receives raw IP packets. Always bound-check before examining an address.
func shouldBlockDirectPacket(_ packet: UnsafeRawBufferPointer, interface: String) -> Bool {
    if interface == "lo0" || (interface.hasPrefix("utun") && UInt32(interface.dropFirst(4)) != nil) { return false }
    guard let first = packet.first else { return false }
    switch first >> 4 {
    case 4 where packet.count >= 20: return protectedIPv4.contains { $0.contains(packet, at: 16) }
    case 6 where packet.count >= 40: return protectedIPv6.contains { $0.contains(packet, at: 24) }
    default: return false
    }
}
