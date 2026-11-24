use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use super::models::DiscoveryDevice;

const HEADER_LEN: usize = 4;
const TLV_HEADER_LEN: usize = 4;

// MNDP TLV types from Wireshark's packet-mndp.c and observed RouterOS packets.
const TLV_MAC_ADDRESS: u16 = 1;
const TLV_IDENTITY: u16 = 5;
const TLV_VERSION: u16 = 7;
const TLV_PLATFORM: u16 = 8;
const TLV_UPTIME: u16 = 10;
const TLV_BOARD: u16 = 12;
const TLV_IPV6_ADDRESS: u16 = 15;
const TLV_INTERFACE_NAME: u16 = 16;
const TLV_IPV4_ADDRESS: u16 = 17;

fn read_string(value: &[u8]) -> Option<String> {
    let value = &value[..value
        .iter()
        .position(|byte| *byte == 0)
        .unwrap_or(value.len())];
    let text = std::str::from_utf8(value).ok()?.trim();

    if text.is_empty() || text.chars().any(char::is_control) {
        None
    } else {
        Some(text.to_owned())
    }
}

fn format_mac(value: &[u8]) -> Option<String> {
    if value.len() != 6 {
        return None;
    }

    Some(
        value
            .iter()
            .map(|byte| format!("{byte:02X}"))
            .collect::<Vec<_>>()
            .join(":"),
    )
}

/// Reads a single TLV. Returns its type, value and the offset after the value.
///
/// Type and length are big-endian u16 values; length excludes the 4-byte header.
fn read_tlv(data: &[u8], offset: usize) -> Option<(u16, &[u8], usize)> {
    let header = data.get(offset..offset.checked_add(TLV_HEADER_LEN)?)?;
    let kind = u16::from_be_bytes([header[0], header[1]]);
    let length = usize::from(u16::from_be_bytes([header[2], header[3]]));

    let value_start = offset.checked_add(TLV_HEADER_LEN)?;
    let value_end = value_start.checked_add(length)?;
    let value = data.get(value_start..value_end)?;

    Some((kind, value, value_end))
}

/// Parses an MNDP announcement received from `source_ip`.
///
/// An MNDP packet starts with a 4-byte header (2 unknown bytes followed by a
/// big-endian sequence number) and continues with big-endian TLV records.
/// Real MikroTik advertisements always begin with the mandatory 6-byte MAC
/// TLV, which is used here to validate the packet shape before reading the
/// remaining attributes.
pub fn parse_mndp(data: &[u8], source_ip: IpAddr) -> Option<DiscoveryDevice> {
    if data.len() < HEADER_LEN + TLV_HEADER_LEN {
        return None;
    }

    let (first_type, first_value, mut position) = read_tlv(data, HEADER_LEN)?;

    if first_type != TLV_MAC_ADDRESS || first_value.len() != 6 {
        return None;
    }

    let mut device = DiscoveryDevice {
        mac_address: format_mac(first_value),
        identity: None,
        version: None,
        platform: None,
        board: None,
        uptime: None,
        interface_name: None,
        ipv4_address: None,
        ipv6_address: None,
        source_ip: source_ip.to_string(),
    };

    while position < data.len() {
        if data.len() - position < TLV_HEADER_LEN {
            // Truncated TLV header: malformed packet.
            return None;
        }

        let (kind, value, next) = read_tlv(data, position)?;

        match kind {
            TLV_IDENTITY => device.identity = read_string(value),
            TLV_VERSION => device.version = read_string(value),
            TLV_PLATFORM => device.platform = read_string(value),
            TLV_BOARD => device.board = read_string(value),
            TLV_INTERFACE_NAME => device.interface_name = read_string(value),

            // RouterOS encodes uptime as a 32-bit little-endian seconds counter.
            TLV_UPTIME if value.len() == 4 => {
                let bytes: [u8; 4] = value.try_into().ok()?;
                device.uptime = Some(u32::from_le_bytes(bytes));
            }

            TLV_IPV6_ADDRESS if value.len() == 16 => {
                let bytes: [u8; 16] = value.try_into().ok()?;
                device.ipv6_address = Some(Ipv6Addr::from(bytes).to_string());
            }

            TLV_IPV4_ADDRESS if value.len() == 4 => {
                device.ipv4_address =
                    Some(Ipv4Addr::new(value[0], value[1], value[2], value[3]).to_string());
            }

            // Unknown or malformed optional attributes are ignored.
            _ => {}
        }

        position = next;
    }

    // MAC is mandatory in MNDP, so a device without it is not usable.
    device.mac_address.as_ref()?;

    Some(device)
}

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr};

    use super::parse_mndp;

    // Captured RouterOS 6.47.10 advertisement (gist: mertcangokgoz/MNDP decode sample).
    const SAMPLE_PACKET: &[u8] = b"\x63\x2f\x01\x00\
\x00\x01\x00\x06\xb8\x69\xf4\xbe\x3c\x29\
\x00\x05\x00\x15GNS_SAIX_TERACO_CCR01\
\x00\x07\x00\x136.47.10 (long-term)\
\x00\x08\x00\x08MikroTik\
\x00\x0a\x00\x04M%G\x00\
\x00\x0b\x00\x093GNX-A7SG\
\x00\x0c\x00\x0fCCR1016-12S-1S+\
\x00\x0e\x00\x01\x00\
\x00\x10\x00\x04sfp5\
\x00\x11\x00\x04\xc4\xdf\x1f\x2a";

    #[test]
    fn parses_real_routeros_packet() {
        let source = IpAddr::V4(Ipv4Addr::new(192, 168, 88, 1));
        let device = parse_mndp(SAMPLE_PACKET, source).expect("valid packet");

        assert_eq!(device.mac_address.as_deref(), Some("B8:69:F4:BE:3C:29"));
        assert_eq!(device.identity.as_deref(), Some("GNS_SAIX_TERACO_CCR01"));
        assert_eq!(device.version.as_deref(), Some("6.47.10 (long-term)"));
        assert_eq!(device.platform.as_deref(), Some("MikroTik"));
        assert_eq!(device.board.as_deref(), Some("CCR1016-12S-1S+"));
        assert_eq!(device.uptime, Some(4_662_605));
        assert_eq!(device.interface_name.as_deref(), Some("sfp5"));
        assert_eq!(device.ipv4_address.as_deref(), Some("196.223.31.42"));
        assert_eq!(device.source_ip, "192.168.88.1");
    }

    #[test]
    fn rejects_packets_without_mandatory_mac_tlv() {
        let packet = b"\x63\x2f\x01\x00\x00\x05\x00\x01A";
        assert!(parse_mndp(packet, IpAddr::V4(Ipv4Addr::LOCALHOST)).is_none());
    }

    #[test]
    fn rejects_truncated_and_short_packets() {
        assert!(parse_mndp(&[0; 7], IpAddr::V4(Ipv4Addr::LOCALHOST)).is_none());
        assert!(
            parse_mndp(
                &SAMPLE_PACKET[..SAMPLE_PACKET.len() - 1],
                IpAddr::V4(Ipv4Addr::LOCALHOST),
            )
            .is_none()
        );
    }

    #[test]
    fn ignores_unknown_tlvs() {
        let mut packet = SAMPLE_PACKET.to_vec();
        let ipv4_offset = packet.len() - 8;
        packet.splice(
            ipv4_offset..ipv4_offset,
            [0x00, 0x02, 0x00, 0x02, 0xAA, 0xBB],
        );

        let device = parse_mndp(&packet, IpAddr::V4(Ipv4Addr::LOCALHOST)).expect("valid packet");
        assert_eq!(device.ipv4_address.as_deref(), Some("196.223.31.42"));
    }
}
