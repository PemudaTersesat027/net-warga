
use std::io;
use std::time::{Duration, Instant};

use tokio::net::TcpStream;
use tokio::time::timeout;

const DEFAULT_WINBOX_PORT: u16 = 8291;

#[derive(Debug, Clone)]
pub struct WinboxProbeResult {
    pub host: String,
    pub port: u16,
    pub latency_ms: u128,
}

pub struct WinboxTransport;

impl WinboxTransport {
    /// Checks whether the Winbox TCP service is reachable.
    ///
    /// This does not perform authentication or send RouterOS commands.
    pub async fn probe(
        host: &str,
        port: Option<u16>,
        timeout_duration: Duration,
    ) -> io::Result<WinboxProbeResult> {
        let port = port.unwrap_or(DEFAULT_WINBOX_PORT);

        let started_at = Instant::now();

        let connection = timeout(
            timeout_duration,
            TcpStream::connect((host, port)),
        )
        .await
        .map_err(|_| {
            io::Error::new(
                io::ErrorKind::TimedOut,
                "Winbox connection timed out",
            )
        })?;

        let stream = connection?;

        let latency_ms = started_at.elapsed().as_millis();

        // Close the probe connection immediately.
        drop(stream);

        Ok(WinboxProbeResult {
            host: host.to_string(),
            port,
            latency_ms,
        })
    }
}
