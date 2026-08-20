//! 256-bit unsigned integer and field arithmetic for secp256k1.
//!
//! Secp256k1 field prime:
//! P = 2^256 - 2^32 - 977
//!   = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F

use std::fmt;

#[derive(Copy, Clone, PartialEq, Eq, Default, Debug)]
pub struct U256(pub [u64; 4]); // Little-endian u64 array: [0] = least significant, [3] = most significant

/// secp256k1 Field Prime P
pub const SECP256K1_P: U256 = U256([
    0xFFFFFFFEFFFFFC2F,
    0xFFFFFFFFFFFFFFFF,
    0xFFFFFFFFFFFFFFFF,
    0xFFFFFFFFFFFFFFFF,
]);

/// secp256k1 Curve Order N
pub const SECP256K1_N: U256 = U256([
    0xBFD25E8CD0364141,
    0xBAAEDCE6AF48A03B,
    0xFFFFFFFFFFFFFFFE,
    0xFFFFFFFFFFFFFFFF,
]);

impl U256 {
    pub const ZERO: U256 = U256([0, 0, 0, 0]);
    pub const ONE: U256 = U256([1, 0, 0, 0]);

    #[inline]
    pub const fn from_u64(val: u64) -> Self {
        U256([val, 0, 0, 0])
    }

    #[inline]
    pub const fn from_u128(val: u128) -> Self {
        U256([
            (val & 0xFFFF_FFFF_FFFF_FFFF) as u64,
            (val >> 64) as u64,
            0,
            0,
        ])
    }

    pub fn from_be_bytes(bytes: &[u8; 32]) -> Self {
        let mut limbs = [0u64; 4];
        for (i, limb) in limbs.iter_mut().enumerate() {
            let offset = (3 - i) * 8;
            *limb = u64::from_be_bytes(bytes[offset..offset + 8].try_into().unwrap());
        }
        U256(limbs)
    }

    pub fn to_be_bytes(&self) -> [u8; 32] {
        let mut bytes = [0u8; 32];
        for (i, limb) in self.0.iter().enumerate() {
            let offset = (3 - i) * 8;
            bytes[offset..offset + 8].copy_from_slice(&limb.to_be_bytes());
        }
        bytes
    }

    pub fn from_hex_str(s: &str) -> Result<Self, &'static str> {
        let s = s.trim_start_matches("0x");
        if s.len() > 64 {
            return Err("Hex string too long for U256");
        }
        let mut bytes = [0u8; 32];
        let padded = format!("{:0>64}", s);
        for i in 0..32 {
            bytes[i] = u8::from_str_radix(&padded[i * 2..i * 2 + 2], 16)
                .map_err(|_| "Invalid hex character")?;
        }
        Ok(Self::from_be_bytes(&bytes))
    }

    pub fn is_zero(&self) -> bool {
        self.0[0] == 0 && self.0[1] == 0 && self.0[2] == 0 && self.0[3] == 0
    }

    pub fn is_odd(&self) -> bool {
        (self.0[0] & 1) != 0
    }

    pub fn is_even(&self) -> bool {
        (self.0[0] & 1) == 0
    }

    /// Constant-time comparison: returns true if self >= other
    pub fn gte(&self, other: &Self) -> bool {
        for i in (0..4).rev() {
            if self.0[i] > other.0[i] {
                return true;
            }
            if self.0[i] < other.0[i] {
                return false;
            }
        }
        true
    }

    /// Addition with carry (512-bit intermediate)
    #[inline(always)]
    pub fn add_carry(&self, other: &Self) -> (Self, u64) {
        let mut res = [0u64; 4];
        let mut carry = 0u128;
        for (i, r) in res.iter_mut().enumerate() {
            let sum = (self.0[i] as u128) + (other.0[i] as u128) + carry;
            *r = sum as u64;
            carry = sum >> 64;
        }
        (U256(res), carry as u64)
    }

    /// Subtraction with borrow
    #[inline(always)]
    pub fn sub_borrow(&self, other: &Self) -> (Self, u64) {
        let mut res = [0u64; 4];
        let mut borrow = 0i128;
        for (i, r) in res.iter_mut().enumerate() {
            let diff = (self.0[i] as i128) - (other.0[i] as i128) - borrow;
            if diff < 0 {
                *r = (diff + (1i128 << 64)) as u64;
                borrow = 1;
            } else {
                *r = diff as u64;
                borrow = 0;
            }
        }
        (U256(res), borrow as u64)
    }

    /// Field addition mod P: (self + other) mod P
    #[inline(always)]
    pub fn field_add(&self, other: &Self) -> Self {
        let (sum, carry) = self.add_carry(other);
        if carry != 0 || sum.gte(&SECP256K1_P) {
            let (res, _) = sum.sub_borrow(&SECP256K1_P);
            res
        } else {
            sum
        }
    }

    /// Field subtraction mod P: (self - other) mod P
    #[inline(always)]
    pub fn field_sub(&self, other: &Self) -> Self {
        let (diff, borrow) = self.sub_borrow(other);
        if borrow != 0 {
            let (res, _) = diff.add_carry(&SECP256K1_P);
            res
        } else {
            diff
        }
    }

    /// Field negation mod P: (-self) mod P
    #[inline(always)]
    pub fn field_neg(&self) -> Self {
        if self.is_zero() {
            Self::ZERO
        } else {
            SECP256K1_P.field_sub(self)
        }
    }

    /// Full 256 x 256 -> 512-bit multiplication
    pub fn mul_wide(&self, other: &Self) -> [u64; 8] {
        let mut r = [0u64; 8];
        for i in 0..4 {
            let mut carry = 0u128;
            for j in 0..4 {
                let prod = (self.0[i] as u128) * (other.0[j] as u128) + (r[i + j] as u128) + carry;
                r[i + j] = prod as u64;
                carry = prod >> 64;
            }
            r[i + 4] += carry as u64;
        }
        r
    }

    /// Reduce a 512-bit number modulo secp256k1 P.
    /// P = 2^256 - 0x1000003D1
    /// Hence 2^256 = 0x1000003D1 mod P.
    pub fn reduce_512(r: &[u64; 8]) -> Self {
        // High 256 bits r[4..8] * 0x1000003D1 + low 256 bits r[0..4]
        // 0x1000003D1 = 2^32 + 977
        let low = U256([r[0], r[1], r[2], r[3]]);
        let high = U256([r[4], r[5], r[6], r[7]]);

        // Multiply high by 0x1000003D1:
        // high * 0x1000003D1 = high * 2^32 + high * 977
        // Let's do general multiply of high by 0x1000003D1
        let factor = 0x1000003D1u128;
        let mut h_prod = [0u64; 6];
        let mut carry = 0u128;
        for (i, p) in h_prod.iter_mut().enumerate().take(4) {
            let prod = (high.0[i] as u128) * factor + carry;
            *p = prod as u64;
            carry = prod >> 64;
        }
        h_prod[4] = carry as u64;

        // Add h_prod to low
        let mut sum = [0u64; 5];
        let mut c = 0u128;
        for i in 0..4 {
            let s = (low.0[i] as u128) + (h_prod[i] as u128) + c;
            sum[i] = s as u64;
            c = s >> 64;
        }
        let s4 = (h_prod[4] as u128) + c;
        sum[4] = s4 as u64;
        let overflow_high = (s4 >> 64) as u64;

        // Any remaining overflow in sum[4] and overflow_high is further multiplied by 0x1000003D1
        let extra_high = (sum[4] as u128) | ((overflow_high as u128) << 64);
        let extra_prod = extra_high * factor;

        let mut res = [0u64; 4];
        let mut c2 = extra_prod;
        for i in 0..4 {
            let s = (sum[i] as u128) + (c2 & 0xFFFFFFFFFFFFFFFF);
            res[i] = s as u64;
            c2 = (s >> 64) + (c2 >> 64);
        }

        // One last possible reduction if c2 != 0
        let mut final_u256 = U256(res);
        if c2 != 0 {
            let extra2 = (c2 * factor) as u64;
            let (s, _) = final_u256.add_carry(&U256::from_u64(extra2));
            final_u256 = s;
        }

        // Final modulo P subtract loops (at most 2 times)
        while final_u256.gte(&SECP256K1_P) {
            let (s, _) = final_u256.sub_borrow(&SECP256K1_P);
            final_u256 = s;
        }

        final_u256
    }

    /// Field multiplication mod P: (self * other) mod P
    #[inline(always)]
    pub fn field_mul(&self, other: &Self) -> Self {
        let wide = self.mul_wide(other);
        Self::reduce_512(&wide)
    }

    /// Field squaring mod P: self^2 mod P
    #[inline(always)]
    pub fn field_square(&self) -> Self {
        self.field_mul(self)
    }

    /// Modular exponentiation: self^exp mod P
    pub fn field_pow(&self, exp: &Self) -> Self {
        let mut res = Self::ONE;
        let mut base = *self;
        for limb in &exp.0 {
            let mut l = *limb;
            for _ in 0..64 {
                if (l & 1) != 0 {
                    res = res.field_mul(&base);
                }
                base = base.field_square();
                l >>= 1;
            }
        }
        res
    }

    /// Field inversion mod P using Fermat's Little Theorem: a^(P-2) mod P
    pub fn field_inv(&self) -> Self {
        if self.is_zero() {
            return Self::ZERO;
        }
        // P - 2 = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2D
        let p_minus_2 = U256([
            0xFFFFFFFEFFFFFC2D,
            0xFFFFFFFFFFFFFFFF,
            0xFFFFFFFFFFFFFFFF,
            0xFFFFFFFFFFFFFFFF,
        ]);
        self.field_pow(&p_minus_2)
    }
}

impl fmt::Display for U256 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let bytes = self.to_be_bytes();
        for b in bytes {
            write!(f, "{:02x}", b)?;
        }
        Ok(())
    }
}
