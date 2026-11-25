use std::io;
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::timeout;

use super::encoder::{EncodeError, TlvRecord, encode_m2_message};
use super::framing::{
    ChunkedFrame, FrameEncodeError, FrameError, MAX_FRAME_SIZE, TAG_CONTINUATION, TAG_ENCRYPTED,
    TAG_PLAINTEXT, decode_chunked_frame, encode_chunked_frame,
};

const DEFAULT_WINBOX_PORT: u16 = 8291;
const DEFAULT_TIMEOUT: Duration = Duration::from_secs(10);

#[derive(Debug)]
pub enum WinboxSessionError {
    Io(io::Error),
    Timeout,
    Frame(FrameError),
    FrameEncode(FrameEncodeError),
    MessageEncode(EncodeError),
    InvalidFrame,
    MalformedFrame(&'static str),
    TruncatedFrame(&'static str),
}

impl std::fmt::Display for WinboxSessionError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Io(error) => write!(f, "Winbox I/O error: {error}"),
            Self::Timeout => write!(f, "Winbox operation timed out"),
            Self::Frame(error) => write!(f, "Winbox frame error: {error}"),
            Self::FrameEncode(error) => {
                write!(f, "Winbox frame encoding error: {error}")
            }
            Self::MessageEncode(error) => {
                write!(f, "Winbox message encoding error: {error}")
            }
            Self::InvalidFrame => write!(f, "Malformed or incomplete Winbox frame"),
            Self::MalformedFrame(reason) => {
                write!(f, "Malformed Winbox frame: {reason}")
            }
            Self::TruncatedFrame(part) => {
                write!(f, "Truncated Winbox frame while reading {part}")
            }
        }
    }
}

impl std::error::Error for WinboxSessionError {}

impl From<io::Error> for WinboxSessionError {
    fn from(error: io::Error) -> Self {
        Self::Io(error)
    }
}

impl From<FrameError> for WinboxSessionError {
    fn from(error: FrameError) -> Self {
        Self::Frame(error)
    }
}

impl From<FrameEncodeError> for WinboxSessionError {
    fn from(error: FrameEncodeError) -> Self {
        Self::FrameEncode(error)
    }
}

impl From<EncodeError> for WinboxSessionError {
    fn from(error: EncodeError) -> Self {
        Self::MessageEncode(error)
    }
}

/// Koneksi TCP persisten ke layanan Winbox.
///
/// Session ini belum melakukan autentikasi EC-SRP5 atau enkripsi AES.
pub struct WinboxSession {
    stream: TcpStream,
    host: String,
    port: u16,
    timeout: Duration,
}

impl WinboxSession {
    /// Membuka koneksi TCP persisten.
    pub async fn connect(
        host: &str,
        port: Option<u16>,
        timeout_duration: Option<Duration>,
    ) -> Result<Self, WinboxSessionError> {
        let port = port.unwrap_or(DEFAULT_WINBOX_PORT);
        let timeout_duration = timeout_duration.unwrap_or(DEFAULT_TIMEOUT);

        let connection = timeout(timeout_duration, TcpStream::connect((host, port)))
            .await
            .map_err(|_| WinboxSessionError::Timeout)??;

        Ok(Self {
            stream: connection,
            host: host.to_string(),
            port,
            timeout: timeout_duration,
        })
    }

    pub fn host(&self) -> &str {
        &self.host
    }

    pub fn port(&self) -> u16 {
        self.port
    }

    /// Mengirim payload yang sudah disiapkan.
    ///
    /// first_tag hanya menentukan jenis frame. Fungsi ini tidak
    /// melakukan enkripsi meskipun TAG_ENCRYPTED digunakan.
    pub async fn send_payload(
        &mut self,
        payload: &[u8],
        first_tag: u8,
    ) -> Result<(), WinboxSessionError> {
        let frame = encode_chunked_frame(payload, first_tag)?;

        timeout(self.timeout, self.stream.write_all(&frame))
            .await
            .map_err(|_| WinboxSessionError::Timeout)??;

        Ok(())
    }

    /// Mengirim pesan M2 sebagai frame plaintext.
    ///
    /// Ini hanya fasilitas encoding dan transport, bukan perintah
    /// RouterOS yang dijamin valid untuk dikirim sebelum handshake.
    pub async fn send_m2(&mut self, tlvs: &[TlvRecord]) -> Result<(), WinboxSessionError> {
        let message = encode_m2_message(tlvs)?;
        self.send_payload(&message, TAG_PLAINTEXT).await
    }

    /// Membaca satu frame lengkap dari TCP stream.
    ///
    /// The timeout applies to the entire frame, not to each individual read.
    /// The frame-size cap is an application safety limit, not a protocol limit.
    pub async fn receive_frame(&mut self) -> Result<ChunkedFrame, WinboxSessionError> {
        timeout(self.timeout, async {
            let mut frame_bytes = Vec::new();
            let mut first_chunk = true;

            loop {
                let mut header = [0u8; 2];

                match self.stream.read_exact(&mut header).await {
                    Ok(_) => {}
                    Err(error) if error.kind() == io::ErrorKind::UnexpectedEof => {
                        return Err(WinboxSessionError::TruncatedFrame("chunk header"));
                    }
                    Err(error) => return Err(WinboxSessionError::Io(error)),
                }

                let chunk_length = header[0] as usize;
                let chunk_tag = header[1];
                let next_frame_length = frame_bytes
                    .len()
                    .checked_add(header.len())
                    .and_then(|length| length.checked_add(chunk_length))
                    .unwrap_or(usize::MAX);

                if next_frame_length > MAX_FRAME_SIZE {
                    return Err(WinboxSessionError::Frame(FrameError::FrameTooLarge));
                }

                if first_chunk {
                    if chunk_tag != TAG_PLAINTEXT && chunk_tag != TAG_ENCRYPTED {
                        return Err(WinboxSessionError::MalformedFrame(
                            "unsupported first chunk tag",
                        ));
                    }
                    first_chunk = false;
                } else if chunk_tag != TAG_CONTINUATION {
                    return Err(WinboxSessionError::MalformedFrame(
                        "invalid continuation chunk tag",
                    ));
                }

                frame_bytes.extend_from_slice(&header);
                let mut chunk_payload = vec![0u8; chunk_length];

                if chunk_length > 0 {
                    match self.stream.read_exact(&mut chunk_payload).await {
                        Ok(_) => {}
                        Err(error) if error.kind() == io::ErrorKind::UnexpectedEof => {
                            return Err(WinboxSessionError::TruncatedFrame("chunk payload"));
                        }
                        Err(error) => return Err(WinboxSessionError::Io(error)),
                    }

                    frame_bytes.extend_from_slice(&chunk_payload);
                }

                // 255 means another chunk follows (existing assumed wire layout).
                if chunk_length < u8::MAX as usize {
                    break;
                }
            }

            let (frame, consumed) = decode_chunked_frame(&frame_bytes)?;

            if consumed != frame_bytes.len() {
                return Err(WinboxSessionError::InvalidFrame);
            }

            Ok(frame)
        })
        .await
        .map_err(|_| WinboxSessionError::Timeout)?
    }

    pub async fn close(mut self) -> Result<(), WinboxSessionError> {
        self.stream.shutdown().await?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;

    use crate::routeros::winbox::framing::decode_chunked_frame;

    #[tokio::test]
    async fn session_sends_and_receives_frame() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();

        let address = listener.local_addr().unwrap();
        let response_payload = b"router-response".to_vec();
        let server_response_payload = response_payload.clone();

        let server = tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.unwrap();

            // Payload 300 bytes:
            // chunk 1 = 255 + 2-byte header
            // chunk 2 = 45 + 2-byte header
            let mut received = vec![0u8; 304];

            socket.read_exact(&mut received).await.unwrap();

            let (frame, consumed) = decode_chunked_frame(&received).unwrap();

            assert_eq!(consumed, received.len());
            assert_eq!(frame.tag, TAG_PLAINTEXT);
            assert_eq!(frame.payload, vec![0xAA; 300]);

            let response = encode_chunked_frame(&server_response_payload, TAG_PLAINTEXT).unwrap();

            socket.write_all(&response).await.unwrap();
        });

        let mut session = WinboxSession::connect(
            "127.0.0.1",
            Some(address.port()),
            Some(Duration::from_secs(3)),
        )
        .await
        .unwrap();

        let payload = vec![0xAA; 300];

        session.send_payload(&payload, TAG_PLAINTEXT).await.unwrap();

        let response = session.receive_frame().await.unwrap();

        assert_eq!(response.tag, TAG_PLAINTEXT);
        assert_eq!(response.payload, response_payload);

        server.await.unwrap();
        session.close().await.unwrap();
    }

    #[tokio::test]
    async fn session_sends_m2_message() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();

        let address = listener.local_addr().unwrap();

        let server = tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.unwrap();

            // M2 body:
            // M2 + one TLV (4-byte header + 1-byte value)
            // Envelope = 2-byte length + 7-byte body
            // Frame = 2-byte header + 9-byte payload
            let mut received = vec![0u8; 11];

            socket.read_exact(&mut received).await.unwrap();

            let (frame, consumed) = decode_chunked_frame(&received).unwrap();

            assert_eq!(consumed, received.len());
            assert_eq!(frame.tag, TAG_PLAINTEXT);

            let message =
                crate::routeros::winbox::message::parse_m2_message(&frame.payload).unwrap();

            assert_eq!(message.body, b"M2\x01\x00\xFF\x09\x42");
        });

        let mut session = WinboxSession::connect(
            "127.0.0.1",
            Some(address.port()),
            Some(Duration::from_secs(3)),
        )
        .await
        .unwrap();

        let tlvs = vec![TlvRecord::new(0x01, 0x00, 0xFF, 0x09, vec![0x42])];

        session.send_m2(&tlvs).await.unwrap();

        server.await.unwrap();
        session.close().await.unwrap();
    }

    #[tokio::test]
    async fn receive_frame_times_out_for_the_whole_frame() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();

        let server = tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.unwrap();
            let mut first_chunk = vec![u8::MAX, TAG_PLAINTEXT];
            first_chunk.extend_from_slice(&[0xAA; u8::MAX as usize]);
            socket.write_all(&first_chunk).await.unwrap();

            tokio::time::sleep(Duration::from_millis(120)).await;
            let mut second_chunk = vec![u8::MAX, TAG_CONTINUATION];
            second_chunk.extend_from_slice(&[0xBB; u8::MAX as usize]);
            let _ = socket.write_all(&second_chunk).await;

            tokio::time::sleep(Duration::from_millis(120)).await;
            let _ = socket.write_all(&[0, TAG_CONTINUATION]).await;
        });

        let mut session = WinboxSession::connect(
            "127.0.0.1",
            Some(address.port()),
            Some(Duration::from_millis(200)),
        )
        .await
        .unwrap();

        assert!(matches!(
            session.receive_frame().await,
            Err(WinboxSessionError::Timeout)
        ));

        server.await.unwrap();
    }

    #[tokio::test]
    async fn receive_frame_reports_malformed_first_tag() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();

        let server = tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.unwrap();
            socket.write_all(&[0, 0x77]).await.unwrap();
        });

        let mut session = WinboxSession::connect(
            "127.0.0.1",
            Some(address.port()),
            Some(Duration::from_secs(1)),
        )
        .await
        .unwrap();

        assert!(matches!(
            session.receive_frame().await,
            Err(WinboxSessionError::MalformedFrame(
                "unsupported first chunk tag"
            ))
        ));

        server.await.unwrap();
    }

    #[tokio::test]
    async fn receive_frame_reports_truncated_payload() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();

        let server = tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.unwrap();
            socket.write_all(&[3, TAG_PLAINTEXT, 0xAA]).await.unwrap();
            socket.shutdown().await.unwrap();
        });

        let mut session = WinboxSession::connect(
            "127.0.0.1",
            Some(address.port()),
            Some(Duration::from_secs(1)),
        )
        .await
        .unwrap();

        assert!(matches!(
            session.receive_frame().await,
            Err(WinboxSessionError::TruncatedFrame("chunk payload"))
        ));

        server.await.unwrap();
    }

    #[tokio::test]
    async fn receive_frame_rejects_frame_over_application_size_limit() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();

        let server = tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.unwrap();
            let mut frame_bytes = Vec::with_capacity(MAX_FRAME_SIZE + 257);
            let mut first_chunk = true;

            while frame_bytes.len() <= MAX_FRAME_SIZE {
                frame_bytes.push(u8::MAX);
                frame_bytes.push(if first_chunk {
                    TAG_PLAINTEXT
                } else {
                    TAG_CONTINUATION
                });
                frame_bytes.extend_from_slice(&[0xAA; u8::MAX as usize]);
                first_chunk = false;
            }

            let _ = socket.write_all(&frame_bytes).await;
        });

        let mut session = WinboxSession::connect(
            "127.0.0.1",
            Some(address.port()),
            Some(Duration::from_secs(3)),
        )
        .await
        .unwrap();

        assert!(matches!(
            session.receive_frame().await,
            Err(WinboxSessionError::Frame(FrameError::FrameTooLarge))
        ));

        server.await.unwrap();
    }
}
