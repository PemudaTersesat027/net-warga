use serde::Serialize;

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RouterIdentity {
    pub identity: String,
    pub version: String,
    pub board_name: String,
    pub uptime: String,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RouterConnectionStatus {
    pub connected: bool,
    pub host: String,
    pub identity: Option<String>,
}
