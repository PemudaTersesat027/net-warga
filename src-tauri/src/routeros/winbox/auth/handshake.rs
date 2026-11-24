
use std::fmt;

pub const AUTH_TAG: u8 = 0x06;
pub const PUBLIC_KEY_LENGTH: usize = 32;
pub const SALT_LENGTH: usize = 16;
pub const CONFIRMATION_LENGTH: usize = 32;
pub const MAX_AUTH_PAYLOAD: usize = u8::MAX as usize;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthPacket {
    pub payload: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServerParameters {
    pub public_key: [u8; PUBLIC_KEY_LENGTH],
    pub parity: u8,
    pub salt: [u8; SALT_LENGTH],
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AuthError {
    EmptyUsername,
    UsernameContainsNull,
    UsernameTooLong,
    PayloadTooLarge(usize),
    InvalidPacketLength,
    InvalidAuthTag(u8),
    InvalidServerParametersLength(usize),
    InvalidParity(u8),
    InvalidConfirmationLength(usize),
}

impl fmt::Display for AuthError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::EmptyUsername => write!(f, "Username cannot be empty"),
            Self::UsernameContainsNull => {
                write!(f, "Username cannot contain a null byte")
            }
            Self::UsernameTooLong => {
                write!(f, "Username is too long for an auth packet")
            }
            Self::PayloadTooLarge(length) => {
                write!(f, "Authentication payload too large: {length}")
            }
            Self::InvalidPacketLength => {
                write!(f, "Invalid authentication packet length")
            }
            Self::InvalidAuthTag(tag) => {
                write!(f, "Invalid authentication tag: 0x{tag:02X}")
            }
            Self::InvalidServerParametersLength(length) => {
                write!(
                    f,
                    "Invalid server parameter length: {length}, expected 49"
                )
            }
            Self::InvalidParity(parity) => {
                write!(f, "Invalid public key parity: {parity}")
            }
            Self::InvalidConfirmationLength(length) => {
                write!(
                    f,
                    "Invalid confirmation length: {length}, expected 32"
                )
            }
        }
    }
}

impl std::error::Error for AuthError {}

/// Encodes an EC-SRP5 authentication packet.
///
/// Wire format:
/// [payload_length: u8][0x06][payload...]
pub fn encode_auth_packet(
    payload: &[u8],
) -> Result<Vec<u8>, AuthError> {
    if payload.len() > MAX_AUTH_PAYLOAD {
        return Err(AuthError::PayloadTooLarge(payload.len()));
    }

    let mut output = Vec::with_capacity(payload.len() + 2);

    output.push(payload.len() as u8);
    output.push(AUTH_TAG);
    output.extend_from_slice(payload);

    Ok(output)
}

/// Decodes one EC-SRP5 authentication packet.
///
/// Returns the decoded packet and the number of consumed bytes.
/// Additional bytes remain available to the caller.
pub fn decode_auth_packet(
    input: &[u8],
) -> Result<(AuthPacket, usize), AuthError> {
    if input.len() < 2 {
        return Err(AuthError::InvalidPacketLength);
    }

    let payload_length = input[0] as usize;
    let tag = input[1];

    if tag != AUTH_TAG {
        return Err(AuthError::InvalidAuthTag(tag));
    }

    let total_length = payload_length + 2;

    if input.len() < total_length {
        return Err(AuthError::InvalidPacketLength);
    }

    Ok((
        AuthPacket {
            payload: input[2..total_length].to_vec(),
        },
        total_length,
    ))
}

/// Builds the first client authentication payload.
///
/// Payload:
/// [username + null][public_key: 32][parity: 1]
pub fn build_client_init(
    username: &str,
    public_key: &[u8; PUBLIC_KEY_LENGTH],
    parity: u8,
) -> Result<Vec<u8>, AuthError> {
    if username.is_empty() {
        return Err(AuthError::EmptyUsername);
    }

    if username.as_bytes().contains(&0) {
        return Err(AuthError::UsernameContainsNull);
    }

    if parity > 1 {
        return Err(AuthError::InvalidParity(parity));
    }

    // Username + null terminator + public key + parity
    let max_username_length =
        MAX_AUTH_PAYLOAD - 1 - PUBLIC_KEY_LENGTH - 1;

    if username.len() > max_username_length {
        return Err(AuthError::UsernameTooLong);
    }

    let mut payload = Vec::with_capacity(
        username.len() + 1 + PUBLIC_KEY_LENGTH + 1,
    );

    payload.extend_from_slice(username.as_bytes());
    payload.push(0x00);
    payload.extend_from_slice(public_key);
    payload.push(parity);

    Ok(payload)
}

/// Parses the server's EC-SRP5 response.
///
/// Payload:
/// [server_public_key: 32][parity: 1][salt: 16]
pub fn parse_server_parameters(
    payload: &[u8],
) -> Result<ServerParameters, AuthError> {
    let expected_length = PUBLIC_KEY_LENGTH + 1 + SALT_LENGTH;

    if payload.len() != expected_length {
        return Err(
            AuthError::InvalidServerParametersLength(payload.len())
        );
    }

    let mut public_key = [0u8; PUBLIC_KEY_LENGTH];
    public_key.copy_from_slice(&payload[..PUBLIC_KEY_LENGTH]);

    let parity = payload[PUBLIC_KEY_LENGTH];

    if parity > 1 {
        return Err(AuthError::InvalidParity(parity));
    }

    let mut salt = [0u8; SALT_LENGTH];
    salt.copy_from_slice(
        &payload[PUBLIC_KEY_LENGTH + 1..],
    );

    Ok(ServerParameters {
        public_key,
        parity,
        salt,
    })
}

/// Validates the length of an EC-SRP5 confirmation proof.
pub fn parse_confirmation(
    payload: &[u8],
) -> Result<[u8; CONFIRMATION_LENGTH], AuthError> {
    if payload.len() != CONFIRMATION_LENGTH {
        return Err(
            AuthError::InvalidConfirmationLength(payload.len())
        );
    }

    let mut confirmation = [0u8; CONFIRMATION_LENGTH];
    confirmation.copy_from_slice(payload);

    Ok(confirmation)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encodes_auth_packet() {
        let payload = b"hello";

        let encoded = encode_auth_packet(payload).unwrap();

        assert_eq!(
            encoded,
            vec![0x05, 0x06, b'h', b'e', b'l', b'l', b'o']
        );
    }

    #[test]
    fn decodes_auth_packet() {
        let input = vec![0x03, 0x06, 0xAA, 0xBB, 0xCC];

        let (packet, consumed) =
            decode_auth_packet(&input).unwrap();

        assert_eq!(packet.payload, vec![0xAA, 0xBB, 0xCC]);
        assert_eq!(consumed, 5);
    }

    #[test]
    fn leaves_next_packet_unconsumed() {
        let input = vec![
            0x01, 0x06, 0xAA,
            0x01, 0x06, 0xBB,
        ];

        let (packet, consumed) =
            decode_auth_packet(&input).unwrap();

        assert_eq!(packet.payload, vec![0xAA]);
        assert_eq!(consumed, 3);
    }

    #[test]
    fn rejects_invalid_auth_tag() {
        let input = vec![0x01, 0x01, 0xAA];

        assert_eq!(
            decode_auth_packet(&input),
            Err(AuthError::InvalidAuthTag(0x01))
        );
    }

    #[test]
    fn rejects_truncated_packet() {
        let input = vec![0x03, 0x06, 0xAA];

        assert_eq!(
            decode_auth_packet(&input),
            Err(AuthError::InvalidPacketLength)
        );
    }

    #[test]
    fn builds_client_init_payload() {
        let public_key = [0xAA; PUBLIC_KEY_LENGTH];

        let payload =
            build_client_init("admin", &public_key, 1).unwrap();

        assert_eq!(&payload[..6], b"admin\0");
        assert_eq!(&payload[6..38], &public_key);
        assert_eq!(payload[38], 1);
        assert_eq!(payload.len(), 39);
    }

    #[test]
    fn rejects_empty_username() {
        let result = build_client_init(
            "",
            &[0xAA; PUBLIC_KEY_LENGTH],
            0,
        );

        assert_eq!(result, Err(AuthError::EmptyUsername));
    }

    #[test]
    fn rejects_null_in_username() {
        let result = build_client_init(
            "admin\0test",
            &[0xAA; PUBLIC_KEY_LENGTH],
            0,
        );

        assert_eq!(result, Err(AuthError::UsernameContainsNull));
    }

    #[test]
    fn rejects_invalid_client_parity() {
        let result = build_client_init(
            "admin",
            &[0xAA; PUBLIC_KEY_LENGTH],
            2,
        );

        assert_eq!(result, Err(AuthError::InvalidParity(2)));
    }

    #[test]
    fn parses_server_parameters() {
        let mut payload = vec![0xBB; 32];
        payload.push(1);
        payload.extend_from_slice(&[0xCC; 16]);

        let parameters =
            parse_server_parameters(&payload).unwrap();

        assert_eq!(parameters.public_key, [0xBB; 32]);
        assert_eq!(parameters.parity, 1);
        assert_eq!(parameters.salt, [0xCC; 16]);
    }

    #[test]
    fn rejects_invalid_server_parameter_length() {
        let payload = vec![0xAA; 48];

        assert_eq!(
            parse_server_parameters(&payload),
            Err(AuthError::InvalidServerParametersLength(48))
        );
    }

    #[test]
    fn parses_confirmation() {
        let payload = [0xDD; CONFIRMATION_LENGTH];

        let confirmation =
            parse_confirmation(&payload).unwrap();

        assert_eq!(confirmation, payload);
    }

    #[test]
    fn rejects_invalid_confirmation_length() {
        let payload = [0xDD; 31];

        assert_eq!(
            parse_confirmation(&payload),
            Err(AuthError::InvalidConfirmationLength(31))
        );
    }
}
