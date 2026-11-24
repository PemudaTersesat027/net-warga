
use num_bigint::BigUint;
use num_traits::Zero;
use std::fmt;

pub const FIELD_BYTES: usize = 32;
pub const GENERATOR_MONTGOMERY_X: u8 = 9;
pub const GENERATOR_PARITY: u8 = 0;
pub const COFACTOR: u8 = 8;

const FIELD_PRIME_HEX: &str =
    "7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffed";

const MONTGOMERY_A_DIV_3_HEX: &str =
    "2aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaad2451";

const WEIERSTRASS_A_HEX: &str =
    "2aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa984914a144";

const WEIERSTRASS_B_HEX: &str =
    "7b425ed097b425ed097b425ed097b425ed097b4260b5e9c7710c864";

const GROUP_ORDER_HEX: &str =
    "1000000000000000000000000000000014def9dea2f79cd65812631a5cf5d3ed";

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CurveError {
    InvalidCoordinate,
    InvalidParity(u8),
    InvalidCoordinateLength(usize),
}

impl fmt::Display for CurveError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidCoordinate => {
                write!(f, "Coordinate is outside the field")
            }
            Self::InvalidParity(value) => {
                write!(f, "Invalid point parity: {value}")
            }
            Self::InvalidCoordinateLength(length) => {
                write!(
                    f,
                    "Invalid coordinate length: {length}, expected 32"
                )
            }
        }
    }
}

impl std::error::Error for CurveError {}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MontgomeryPublicKey {
    pub x: [u8; FIELD_BYTES],
    pub parity: u8,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WeierstrassPublicCoordinate {
    pub x: [u8; FIELD_BYTES],
    pub parity: u8,
}

fn parse_hex(value: &str) -> BigUint {
    BigUint::parse_bytes(value.as_bytes(), 16)
        .expect("valid curve constant")
}

pub fn field_prime() -> BigUint {
    parse_hex(FIELD_PRIME_HEX)
}

pub fn group_order() -> BigUint {
    parse_hex(GROUP_ORDER_HEX)
}

pub fn weierstrass_a() -> BigUint {
    parse_hex(WEIERSTRASS_A_HEX)
}

pub fn weierstrass_b() -> BigUint {
    parse_hex(WEIERSTRASS_B_HEX)
}

fn montgomery_a_div_3() -> BigUint {
    parse_hex(MONTGOMERY_A_DIV_3_HEX)
}

fn bytes_to_field_value(
    bytes: &[u8; FIELD_BYTES],
) -> Result<BigUint, CurveError> {
    let value = BigUint::from_bytes_be(bytes);

    if value >= field_prime() {
        return Err(CurveError::InvalidCoordinate);
    }

    Ok(value)
}

fn field_value_to_bytes(value: &BigUint) -> [u8; FIELD_BYTES] {
    let bytes = value.to_bytes_be();

    let mut output = [0u8; FIELD_BYTES];
    let start = FIELD_BYTES - bytes.len();

    output[start..].copy_from_slice(&bytes);
    output
}

impl MontgomeryPublicKey {
    pub fn new(
        x: [u8; FIELD_BYTES],
        parity: u8,
    ) -> Result<Self, CurveError> {
        if parity > 1 {
            return Err(CurveError::InvalidParity(parity));
        }

        bytes_to_field_value(&x)?;

        Ok(Self { x, parity })
    }

    /// Parses the wire representation:
    /// [x: 32 bytes big-endian][parity: 1 byte]
    pub fn from_wire(input: &[u8]) -> Result<Self, CurveError> {
        if input.len() != FIELD_BYTES + 1 {
            return Err(CurveError::InvalidCoordinateLength(input.len()));
        }

        let mut x = [0u8; FIELD_BYTES];
        x.copy_from_slice(&input[..FIELD_BYTES]);

        Self::new(x, input[FIELD_BYTES])
    }

    pub fn to_wire(&self) -> Vec<u8> {
        let mut output = Vec::with_capacity(FIELD_BYTES + 1);

        output.extend_from_slice(&self.x);
        output.push(self.parity);

        output
    }

    /// Converts Montgomery X to Weierstrass X.
    ///
    /// xW = xM + A/3 (mod p)
    pub fn to_weierstrass(
        &self,
    ) -> Result<WeierstrassPublicCoordinate, CurveError> {
        let x_m = bytes_to_field_value(&self.x)?;
        let p = field_prime();

        let x_w = (x_m + montgomery_a_div_3()) % &p;

        Ok(WeierstrassPublicCoordinate {
            x: field_value_to_bytes(&x_w),
            parity: self.parity,
        })
    }
}

impl WeierstrassPublicCoordinate {
    /// Converts Weierstrass X back to Montgomery X.
    ///
    /// xM = xW - A/3 (mod p)
    pub fn to_montgomery(
        &self,
    ) -> Result<MontgomeryPublicKey, CurveError> {
        if self.parity > 1 {
            return Err(CurveError::InvalidParity(self.parity));
        }

        let x_w = bytes_to_field_value(&self.x)?;
        let p = field_prime();

        let offset = montgomery_a_div_3();

        let x_m = if x_w >= offset {
            x_w - offset
        } else {
            x_w + &p - offset
        };

        Ok(MontgomeryPublicKey {
            x: field_value_to_bytes(&x_m),
            parity: self.parity,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn generator_key() -> MontgomeryPublicKey {
        let mut x = [0u8; FIELD_BYTES];
        x[FIELD_BYTES - 1] = GENERATOR_MONTGOMERY_X;

        MontgomeryPublicKey::new(x, GENERATOR_PARITY).unwrap()
    }

    #[test]
    fn validates_curve_field_prime() {
        assert_eq!(
            field_prime(),
            (BigUint::from(1u8) << 255usize) - BigUint::from(19u8)
        );
    }

    #[test]
    fn validates_group_order() {
        let expected =
            (BigUint::from(1u8) << 252usize)
            + parse_hex(
                "14def9dea2f79cd65812631a5cf5d3ed"
            );

        assert_eq!(group_order(), expected);
    }

    #[test]
    fn validates_weierstrass_parameters() {
        assert!(!weierstrass_a().is_zero());
        assert!(!weierstrass_b().is_zero());
    }

    #[test]
    fn parses_generator_public_key() {
        let key = generator_key();

        assert_eq!(key.x[31], 9);
        assert_eq!(key.parity, 0);
    }

    #[test]
    fn converts_generator_to_weierstrass() {
        let key = generator_key();

        let converted = key.to_weierstrass().unwrap();

        let expected = parse_hex(
            "2aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaad245a"
        );

        assert_eq!(
            BigUint::from_bytes_be(&converted.x),
            expected
        );

        assert_eq!(converted.parity, 0);
    }

    #[test]
    fn converts_weierstrass_back_to_montgomery() {
        let original = generator_key();

        let weierstrass = original.to_weierstrass().unwrap();
        let restored = weierstrass.to_montgomery().unwrap();

        assert_eq!(restored, original);
    }

    #[test]
    fn preserves_public_key_wire_format() {
        let original = generator_key();

        let wire = original.to_wire();
        let restored = MontgomeryPublicKey::from_wire(&wire).unwrap();

        assert_eq!(restored, original);
        assert_eq!(wire.len(), 33);
    }

    #[test]
    fn rejects_coordinate_outside_field() {
        let invalid = field_prime();
        let bytes = field_value_to_bytes(&invalid);

        assert_eq!(
            MontgomeryPublicKey::new(bytes, 0),
            Err(CurveError::InvalidCoordinate)
        );
    }

    #[test]
    fn rejects_invalid_parity() {
        let mut x = [0u8; FIELD_BYTES];
        x[31] = 9;

        assert_eq!(
            MontgomeryPublicKey::new(x, 2),
            Err(CurveError::InvalidParity(2))
        );
    }

    #[test]
    fn rejects_invalid_wire_length() {
        assert_eq!(
            MontgomeryPublicKey::from_wire(&[0u8; 32]),
            Err(CurveError::InvalidCoordinateLength(32))
        );
    }
}
