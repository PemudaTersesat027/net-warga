
use std::time::Duration;

use crate::routeros::winbox::WinboxTransport;

#[tauri::command]
pub async fn test_winbox_connection(
    host: String,
    port: Option<u16>,
) -> Result<String, String> {
    let result = WinboxTransport::probe(
        &host,
        port,
        Duration::from_secs(5),
    )
    .await
    .map_err(|error| error.to_string())?;

    Ok(format!(
        "Connected to {}:{} in {} ms",
        result.host,
        result.port,
        result.latency_ms
    ))
}
