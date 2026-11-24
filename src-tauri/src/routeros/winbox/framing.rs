use std::fmt;

pub const TAG_PLAINTEXT: u8 = 0x01;
pub const TAG_ENCRYPTED: u8 = 0x06;
pub const TAG_CONTINUATION: u8 = 0xFF;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChunkedFrame {
    pub tag: u8,
    pub payload: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FrameError {
    EmptyInput,
    InvalidFirstTag(u8),
    MissingChunkHeader {
        offset: usize,
    },
    InvalidContinuationTag {
        offset: usize,
        found: u8,
    },
    TruncatedChunk {
        offset: usize,
        declared_len: usize,
        available: usize,
    },
    FrameTooLarge,
}

impl fmt::Display for FrameError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::EmptyInput => write!(f, "input does not contain a Winbox chunk"),
            Self::InvalidFirstTag(tag) => {
                write!(f, "unsupported first chunk tag: 0x{tag:02X}")
            }
            Self::MissingChunkHeader { offset } => {
                write!(f, "missing chunk header at byte offset {offset}")
            }
            Self::InvalidContinuationTag { offset, found } => write!(
                f,
                "invalid continuation tag 0x{found:02X} at byte offset {offset}"
            ),
            Self::TruncatedChunk {
                offset,
                declared_len,
                available,
            } => write!(
                f,
                "truncated chunk at byte offset {offset}: declared {declared_len} bytes, only {available} available"
            ),
            Self::FrameTooLarge => write!(f, "decoded frame exceeds the supported size"),
        }
    }
}

impl std::error::Error for FrameError {}

/// Reassembles one chunked frame.
///
/// Assumed wire layout:
/// - first chunk: `[length: u8][tag: u8][payload...]`
/// - continuation chunk: `[length: u8][0xFF][payload...]`
/// - a chunk length of 255 means another chunk follows
/// - a chunk length below 255 terminates the frame
///
/// This is a framing experiment based on reverse-engineered references.
/// It does not decrypt payloads, parse M2 messages, or authenticate.
pub fn decode_chunked_frame(input: &[u8]) -> Result<(ChunkedFrame, usize), FrameError> {
    if input.is_empty() {
        return Err(FrameError::EmptyInput);
    }

    if input.len() < 2 {
        return Err(FrameError::MissingChunkHeader { offset: 0 });
    }

    let first_tag = input[1];
    if first_tag != TAG_PLAINTEXT && first_tag != TAG_ENCRYPTED {
        return Err(FrameError::InvalidFirstTag(first_tag));
    }

    let mut payload = Vec::new();
    let mut offset = 0usize;
    let mut first_chunk = true;

    loop {
        if input.len().saturating_sub(offset) < 2 {
            return Err(FrameError::MissingChunkHeader { offset });
        }

        let chunk_len = input[offset] as usize;
        let chunk_tag = input[offset + 1];

        if first_chunk {
            if chunk_tag != first_tag {
                return Err(FrameError::InvalidFirstTag(chunk_tag));
            }
            first_chunk = false;
        } else if chunk_tag != TAG_CONTINUATION {
            return Err(FrameError::InvalidContinuationTag {
                offset,
                found: chunk_tag,
            });
        }

        let data_start = offset + 2;
        let data_end = data_start
            .checked_add(chunk_len)
            .ok_or(FrameError::FrameTooLarge)?;

        if data_end > input.len() {
            return Err(FrameError::TruncatedChunk {
                offset,
                declared_len: chunk_len,
                available: input.len().saturating_sub(data_start),
            });
        }

        payload
            .try_reserve(chunk_len)
            .map_err(|_| FrameError::FrameTooLarge)?;
        payload.extend_from_slice(&input[data_start..data_end]);

        offset = data_end;

        if chunk_len < u8::MAX as usize {
            break;
        }
    }

    Ok((
        ChunkedFrame {
            tag: first_tag,
            payload,
        },
        offset,
    ))
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FrameEncodeError {
    InvalidFirstTag(u8),
}

impl std::fmt::Display for FrameEncodeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidFirstTag(tag) => {
                write!(f, "Invalid first chunk tag: 0x{tag:02X}")
            }
        }
    }
}

impl std::error::Error for FrameEncodeError {}

/// Membungkus payload menjadi chunked Winbox frame.
///
/// `first_tag` harus TAG_PLAINTEXT atau TAG_ENCRYPTED.
///
/// Setiap chunk memiliki format:
/// [length: u8][tag: u8][payload]
///
/// Panjang 255 menandakan bahwa chunk berikutnya masih menjadi
/// bagian dari frame yang sama. Karena itu, payload yang panjangnya
/// kelipatan 255 memerlukan terminator kosong.
pub fn encode_chunked_frame(payload: &[u8], first_tag: u8) -> Result<Vec<u8>, FrameEncodeError> {
    if first_tag != TAG_PLAINTEXT && first_tag != TAG_ENCRYPTED {
        return Err(FrameEncodeError::InvalidFirstTag(first_tag));
    }

    let chunk_count = if payload.is_empty() {
        1
    } else {
        payload.len().div_ceil(255)
    };

    let needs_empty_terminator = !payload.is_empty() && payload.len().is_multiple_of(255);

    let total_chunks = chunk_count + usize::from(needs_empty_terminator);
    let mut output = Vec::with_capacity(payload.len() + total_chunks * 2);

    if payload.is_empty() {
        output.push(0);
        output.push(first_tag);
        return Ok(output);
    }

    for (index, chunk) in payload.chunks(255).enumerate() {
        let tag = if index == 0 {
            first_tag
        } else {
            TAG_CONTINUATION
        };

        output.push(chunk.len() as u8);
        output.push(tag);
        output.extend_from_slice(chunk);
    }

    if needs_empty_terminator {
        output.push(0);
        output.push(TAG_CONTINUATION);
    }

    Ok(output)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decodes_single_plaintext_chunk() {
        let input = [0x03, TAG_PLAINTEXT, b'M', b'2', 0x00];

        let (frame, consumed) = decode_chunked_frame(&input).unwrap();

        assert_eq!(frame.tag, TAG_PLAINTEXT);
        assert_eq!(frame.payload, b"M2\x00");
        assert_eq!(consumed, input.len());
    }

    #[test]
    fn decodes_multiple_chunks() {
        let mut input = vec![0xFF, TAG_ENCRYPTED];
        input.extend_from_slice(&vec![0xA5; 255]);
        input.extend_from_slice(&[0x02, TAG_CONTINUATION, 0x11, 0x22]);

        let (frame, consumed) = decode_chunked_frame(&input).unwrap();

        assert_eq!(frame.tag, TAG_ENCRYPTED);
        assert_eq!(frame.payload.len(), 257);
        assert_eq!(&frame.payload[..255], &[0xA5; 255]);
        assert_eq!(&frame.payload[255..], &[0x11, 0x22]);
        assert_eq!(consumed, input.len());
    }

    #[test]
    fn leaves_next_frame_unconsumed() {
        let mut input = vec![0x02, TAG_PLAINTEXT, b'M', b'2'];
        input.extend_from_slice(&[0x01, TAG_PLAINTEXT, b'X']);

        let (frame, consumed) = decode_chunked_frame(&input).unwrap();

        assert_eq!(frame.payload, b"M2");
        assert_eq!(consumed, 4);
        assert_eq!(&input[consumed..], &[0x01, TAG_PLAINTEXT, b'X']);
    }

    #[test]
    fn rejects_unknown_first_tag() {
        let input = [0x01, 0x77, b'X'];

        assert_eq!(
            decode_chunked_frame(&input),
            Err(FrameError::InvalidFirstTag(0x77))
        );
    }

    #[test]
    fn rejects_invalid_continuation_tag() {
        let mut input = vec![0xFF, TAG_PLAINTEXT];
        input.extend_from_slice(&vec![0xAA; 255]);
        input.extend_from_slice(&[0x01, 0x22, 0xBB]);

        assert_eq!(
            decode_chunked_frame(&input),
            Err(FrameError::InvalidContinuationTag {
                offset: 257,
                found: 0x22
            })
        );
    }

    #[test]
    fn rejects_truncated_chunk() {
        let input = [0x05, TAG_PLAINTEXT, 0x01, 0x02];

        assert_eq!(
            decode_chunked_frame(&input),
            Err(FrameError::TruncatedChunk {
                offset: 0,
                declared_len: 5,
                available: 2
            })
        );
    }

    #[test]
    fn rejects_empty_input() {
        assert_eq!(decode_chunked_frame(&[]), Err(FrameError::EmptyInput));
    }

    #[test]
    fn encodes_empty_payload() {
        let encoded = encode_chunked_frame(&[], TAG_PLAINTEXT).unwrap();

        assert_eq!(encoded, vec![0x00, TAG_PLAINTEXT]);
    }

    #[test]
    fn encodes_single_chunk() {
        let payload = vec![0xAA, 0xBB, 0xCC];

        let encoded = encode_chunked_frame(&payload, TAG_PLAINTEXT).unwrap();

        assert_eq!(encoded, vec![0x03, TAG_PLAINTEXT, 0xAA, 0xBB, 0xCC]);
    }

    #[test]
    fn encodes_encrypted_first_chunk() {
        let payload = vec![0x11, 0x22];

        let encoded = encode_chunked_frame(&payload, TAG_ENCRYPTED).unwrap();

        assert_eq!(encoded, vec![0x02, TAG_ENCRYPTED, 0x11, 0x22]);
    }

    #[test]
    fn encodes_multiple_chunks() {
        let payload = vec![0xAA; 256];

        let encoded = encode_chunked_frame(&payload, TAG_PLAINTEXT).unwrap();

        assert_eq!(encoded[0], 255);
        assert_eq!(encoded[1], TAG_PLAINTEXT);

        let second_chunk_offset = 2 + 255;

        assert_eq!(encoded[second_chunk_offset], 1);
        assert_eq!(encoded[second_chunk_offset + 1], TAG_CONTINUATION);
        assert_eq!(encoded[second_chunk_offset + 2], 0xAA);
    }

    #[test]
    fn terminates_exact_255_byte_payload() {
        let payload = vec![0xAA; 255];

        let encoded = encode_chunked_frame(&payload, TAG_PLAINTEXT).unwrap();

        assert_eq!(encoded.len(), 259);
        assert_eq!(encoded[0], 255);
        assert_eq!(encoded[1], TAG_PLAINTEXT);
        assert_eq!(encoded[257], 0);
        assert_eq!(encoded[258], TAG_CONTINUATION);
    }

    #[test]
    #[test]
    fn terminates_exact_multiple_of_255() {
        let payload = vec![0xBB; 510];

        let encoded = encode_chunked_frame(&payload, TAG_ENCRYPTED).unwrap();

        assert_eq!(encoded.len(), 516);
        assert_eq!(encoded[0], 255);
        assert_eq!(encoded[1], TAG_ENCRYPTED);

        let second_chunk_offset = 257;

        assert_eq!(encoded[second_chunk_offset], 255);
        assert_eq!(encoded[second_chunk_offset + 1], TAG_CONTINUATION);

        // Empty terminator
        assert_eq!(encoded[514], 0);
        assert_eq!(encoded[515], TAG_CONTINUATION);
    }

    #[test]
    fn rejects_invalid_first_tag() {
        let result = encode_chunked_frame(&[0xAA], 0x99);

        assert_eq!(result, Err(FrameEncodeError::InvalidFirstTag(0x99)));
    }

    #[test]
    fn encoded_frame_can_be_decoded() {
        let payload = vec![0x42; 300];

        let encoded = encode_chunked_frame(&payload, TAG_ENCRYPTED).unwrap();

        let (decoded, consumed) = decode_chunked_frame(&encoded).unwrap();

        assert_eq!(decoded.tag, TAG_ENCRYPTED);
        assert_eq!(decoded.payload, payload);
        assert_eq!(consumed, encoded.len());
    }
}
