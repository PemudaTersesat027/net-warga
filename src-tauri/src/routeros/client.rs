use std::time::Duration;
use tokio::net::TcpStream;
use tokio::time::timeout;

use crate::core::error::{AppError, AppResult};

pub struct RouterClient {
    stream: TcpStream,
}

impl RouterClient {
    pub async fn connect(host: &str, port: u16) -> AppResult<Self> {
        let address = format!("{host}:{port}");

        let stream = timeout(Duration::from_secs(5), TcpStream::connect(&address))
            .await
            .map_err(|_| AppError::Router("Connection timeout".into()))??;

        stream.set_nodelay(true)?;

        Ok(Self { stream })
    }

    pub fn is_connected(&self) -> bool {
        self.stream.peer_addr().is_ok()
    }
}
