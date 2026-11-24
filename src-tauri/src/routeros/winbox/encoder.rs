
use std::fmt;

use super::message::M2_MAGIC;

/// Satu TLV yang akan dimasukkan ke pesan M2.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TlvRecord {
    pub key_low: u8,
    pub key_high: u8,
    pub namespace: u8,
    pub data_type: u8,
    pub value: Vec<u8>,
}

impl TlvRecord {
    pub fn new(
        key_low: u8,
        key_high: u8,
        namespace: u8,
        data_type: u8,
        value: impl Into<Vec<u8>>,
    ) -> Self {
        Self {
            key_low,
            key_high,
            namespace,
            data_type,
            value: value.into(),
        }
    }

    pub fn full_key(&self) -> u32 {
        ((self.namespace as u32) << 16)
            | ((self.key_high as u32) << 8)
            | self.key_low as u32
    }
}

#[derive(Debug, PartialEq, Eq)]
pub enum EncodeError {
    BodyTooLarge { actual: usize, maximum: usize },
    TlvTooLarge { actual: usize },
}

impl fmt::Display for EncodeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::BodyTooLarge { actual, maximum } => {
                write!(
                    f,
                    "M2 body is too large: {actual} bytes (maximum {maximum})"
                )
            }
            Self::TlvTooLarge { actual } => {
                write!(f, "TLV value is too large: {actual} bytes")
            }
        }
    }
}

impl std::error::Error for EncodeError {}

/// Mengubah satu TLV menjadi byte buffer.
///
/// Format header TLV:
/// [key_low][key_high][namespace][data_type][raw_value...]
pub fn encode_tlv(tlv: &TlvRecord) -> Result<Vec<u8>, EncodeError> {
    let mut output = Vec::with_capacity(4 + tlv.value.len());

    output.push(tlv.key_low);
    output.push(tlv.key_high);
    output.push(tlv.namespace);
    output.push(tlv.data_type);
    output.extend_from_slice(&tlv.value);

    Ok(output)
}

/// Menyusun pesan M2 lengkap.
///
/// Format:
/// [body_length: u16 big-endian][M2][TLV data...]
///
/// Panjang yang dihitung adalah panjang body, termasuk magic M2,
/// tetapi tidak termasuk dua byte length prefix.
pub fn encode_m2_message(tlvs: &[TlvRecord]) -> Result<Vec<u8>, EncodeError> {
    let mut body = Vec::new();
    body.extend_from_slice(M2_MAGIC);

    for tlv in tlvs {
        let encoded_tlv = encode_tlv(tlv)?;
        body.extend_from_slice(&encoded_tlv);
    }

    let body_length = body.len();

    if body_length > u16::MAX as usize {
        return Err(EncodeError::BodyTooLarge {
            actual: body_length,
            maximum: u16::MAX as usize,
        });
    }

    let mut output = Vec::with_capacity(2 + body_length);
    output.extend_from_slice(&(body_length as u16).to_be_bytes());
    output.extend_from_slice(&body);

    Ok(output)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::routeros::winbox::message::parse_m2_message;

    #[test]
    fn encodes_empty_m2_message() {
        let encoded = encode_m2_message(&[]).unwrap();

        assert_eq!(encoded, vec![0x00, 0x02, b'M', b'2']);
    }

    #[test]
    fn encodes_single_tlv() {
        let tlv = TlvRecord::new(
            0x01,
            0x00,
            0xFF,
            0x09,
            vec![0x42],
        );

        let encoded = encode_m2_message(&[tlv]).unwrap();

        assert_eq!(
            encoded,
            vec![
                0x00, 0x07,
                b'M', b'2',
                0x01, 0x00, 0xFF, 0x09, 0x42,
            ]
        );
    }

    #[test]
    fn encodes_multiple_tlvs() {
        let tlvs = vec![
            TlvRecord::new(0x01, 0x00, 0xFF, 0x09, vec![0x42]),
            TlvRecord::new(0x02, 0x00, 0xFF, 0x09, vec![0x43]),
        ];

        let encoded = encode_m2_message(&tlvs).unwrap();

        assert_eq!(&encoded[0..2], &[0x00, 0x0C]);
        assert_eq!(&encoded[2..4], b"M2");
        assert_eq!(&encoded[4..], &[
            0x01, 0x00, 0xFF, 0x09, 0x42,
            0x02, 0x00, 0xFF, 0x09, 0x43,
        ]);
    }

    #[test]
    fn calculates_big_endian_length() {
        let value = vec![0xAA; 256];
        let tlv = TlvRecord::new(0x01, 0x00, 0xFF, 0x30, value);

        let encoded = encode_m2_message(&[tlv]).unwrap();

        // Body = M2 (2) + TLV header (4) + value (256) = 262
        assert_eq!(&encoded[0..2], &262u16.to_be_bytes());
    }

    #[test]
    fn preserves_unknown_data_type() {
        let tlv = TlvRecord::new(
            0x10,
            0x20,
            0x00,
            0xFE,
            vec![0xAA, 0xBB],
        );

        let encoded = encode_m2_message(&[tlv]).unwrap();

        assert_eq!(encoded[7], 0xFE);
        assert_eq!(&encoded[8..], &[0xAA, 0xBB]);
    }

    #[test]
    fn rejects_body_larger_than_u16() {
        let tlv = TlvRecord::new(
            0x01,
            0x00,
            0xFF,
            0x30,
            vec![0xAA; u16::MAX as usize],
        );

        let result = encode_m2_message(&[tlv]);

        assert!(matches!(
            result,
            Err(EncodeError::BodyTooLarge { .. })
        ));
    }

    #[test]
    fn round_trip_with_m2_parser() {
        let tlvs = vec![
            TlvRecord::new(0x01, 0x00, 0xFF, 0x09, vec![0x42]),
            TlvRecord::new(0x02, 0x00, 0x00, 0x21, b"router".to_vec()),
        ];

        let encoded = encode_m2_message(&tlvs).unwrap();
        let parsed = parse_m2_message(&encoded).unwrap();

        assert_eq!(&parsed.body[..2], b"M2");
        assert_eq!(
            parsed.tlv_data,
            &[
                0x01, 0x00, 0xFF, 0x09, 0x42,
                0x02, 0x00, 0x00, 0x21,
                b'r', b'o', b'u', b't', b'e', b'r',
            ]
        );
    }

    #[test]
    fn calculates_full_key() {
        let tlv = TlvRecord::new(0x01, 0x00, 0xFF, 0x09, vec![]);

        assert_eq!(tlv.full_key(), 0xFF0001);
    }
}
