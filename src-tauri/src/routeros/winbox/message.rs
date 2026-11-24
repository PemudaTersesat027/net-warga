
use std::fmt;

/// Penanda awal pesan Winbox M2.
pub const M2_MAGIC: &[u8; 2] = b"M2";

/// Representasi pesan M2 yang sudah divalidasi.
#[derive(Debug, PartialEq, Eq)]
pub struct M2Message<'a> {
    pub body: &'a [u8],
    pub tlv_data: &'a [u8],
}

/// Header TLV Winbox.
///
/// Format header:
/// [key_low][key_high][namespace][data_type]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TlvHeader {
    pub key_low: u8,
    pub key_high: u8,
    pub namespace: u8,
    pub data_type: u8,
}

impl TlvHeader {
    /// Menggabungkan namespace, key_high, dan key_low.
    pub fn full_key(&self) -> u32 {
        ((self.namespace as u32) << 16)
            | ((self.key_high as u32) << 8)
            | self.key_low as u32
    }
}

/// Header TLV beserta data mentah setelah header.
///
/// Kita belum menginterpretasikan data_type karena pemetaan
/// tipe dan panjang nilainya masih perlu diverifikasi.
#[derive(Debug, PartialEq, Eq)]
pub struct Tlv<'a> {
    pub header: TlvHeader,
    pub raw_value: &'a [u8],
}

#[derive(Debug, PartialEq, Eq)]
pub enum MessageError {
    EmptyInput,
    TruncatedLength,
    InvalidLength {
        declared: usize,
        actual: usize,
    },
    InvalidMagic,
    TruncatedTlvHeader,
}

impl fmt::Display for MessageError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::EmptyInput => write!(f, "M2 message is empty"),
            Self::TruncatedLength => {
                write!(f, "M2 message length prefix is truncated")
            }
            Self::InvalidLength { declared, actual } => {
                write!(
                    f,
                    "M2 message length mismatch: declared {declared}, actual {actual}"
                )
            }
            Self::InvalidMagic => write!(f, "Invalid M2 magic header"),
            Self::TruncatedTlvHeader => {
                write!(f, "TLV header is incomplete")
            }
        }
    }
}

impl std::error::Error for MessageError {}

/// Membaca envelope pesan M2.
///
/// Format:
/// [body_length: u16 big-endian][M2][TLV data...]
pub fn parse_m2_message(input: &[u8]) -> Result<M2Message<'_>, MessageError> {
    if input.is_empty() {
        return Err(MessageError::EmptyInput);
    }

    if input.len() < 2 {
        return Err(MessageError::TruncatedLength);
    }

    let declared_length = u16::from_be_bytes([input[0], input[1]]) as usize;
    let body = &input[2..];

    if declared_length != body.len() {
        return Err(MessageError::InvalidLength {
            declared: declared_length,
            actual: body.len(),
        });
    }

    if body.len() < 2 || &body[..2] != M2_MAGIC {
        return Err(MessageError::InvalidMagic);
    }

    Ok(M2Message {
        body,
        tlv_data: &body[2..],
    })
}

/// Membaca satu header TLV.
///
/// Fungsi ini tidak mengasumsikan panjang atau format nilai TLV.
/// Seluruh byte setelah empat byte header dikembalikan sebagai raw_value.
pub fn parse_tlv(input: &[u8]) -> Result<Tlv<'_>, MessageError> {
    if input.len() < 4 {
        return Err(MessageError::TruncatedTlvHeader);
    }

    let header = TlvHeader {
        key_low: input[0],
        key_high: input[1],
        namespace: input[2],
        data_type: input[3],
    };

    Ok(Tlv {
        header,
        raw_value: &input[4..],
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_valid_m2_message() {
        let input = [
            0x00, 0x06, // body length = 6
            b'M', b'2',
            0x01, 0x02, 0xFF, 0x09,
        ];

        let message = parse_m2_message(&input).unwrap();

        assert_eq!(message.body, &input[2..]);
        assert_eq!(message.tlv_data, &[0x01, 0x02, 0xFF, 0x09]);
    }

    #[test]
    fn rejects_empty_message() {
        assert_eq!(
            parse_m2_message(&[]),
            Err(MessageError::EmptyInput)
        );
    }

    #[test]
    fn rejects_truncated_length_prefix() {
        assert_eq!(
            parse_m2_message(&[0x00]),
            Err(MessageError::TruncatedLength)
        );
    }

    #[test]
    fn rejects_length_mismatch() {
        let input = [0x00, 0x05, b'M', b'2'];

        assert_eq!(
            parse_m2_message(&input),
            Err(MessageError::InvalidLength {
                declared: 5,
                actual: 2,
            })
        );
    }

    #[test]
    fn rejects_invalid_magic() {
        let input = [0x00, 0x02, b'X', b'Y'];

        assert_eq!(
            parse_m2_message(&input),
            Err(MessageError::InvalidMagic)
        );
    }

    #[test]
    fn parses_tlv_header() {
        let input = [
            0x01, // key_low
            0x00, // key_high
            0xFF, // namespace
            0x09, // data_type
            0x42, // raw value
        ];

        let tlv = parse_tlv(&input).unwrap();

        assert_eq!(tlv.header.key_low, 0x01);
        assert_eq!(tlv.header.key_high, 0x00);
        assert_eq!(tlv.header.namespace, 0xFF);
        assert_eq!(tlv.header.data_type, 0x09);
        assert_eq!(tlv.header.full_key(), 0xFF0001);
        assert_eq!(tlv.raw_value, &[0x42]);
    }

    #[test]
    fn preserves_unknown_data_type() {
        let input = [0x10, 0x20, 0x00, 0xFE, 0xAA];

        let tlv = parse_tlv(&input).unwrap();

        assert_eq!(tlv.header.data_type, 0xFE);
        assert_eq!(tlv.raw_value, &[0xAA]);
    }

    #[test]
    fn rejects_truncated_tlv_header() {
        assert_eq!(
            parse_tlv(&[0x01, 0x02, 0xFF]),
            Err(MessageError::TruncatedTlvHeader)
        );
    }
}
