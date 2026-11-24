use serde::Serialize;

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DiscoveryDevice {
    pub mac_address: Option<String>,
    pub identity: Option<String>,
    pub version: Option<String>,
    pub platform: Option<String>,
    pub board: Option<String>,
    pub uptime: Option<u32>,
    pub interface_name: Option<String>,
    pub ipv4_address: Option<String>,
    pub ipv6_address: Option<String>,
    pub source_ip: String,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DiscoveryEvent {
    pub device: DiscoveryDevice,
    pub event_type: String,
}
