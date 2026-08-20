//! Secp256k1 elliptic curve arithmetic.
//!
//! Curve equation: y^2 = x^3 + 7 over F_P
//! Base generator point G = (Gx, Gy)

use crate::crypto::u256::U256;

/// Affine representation of a point on secp256k1
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub struct AffinePoint {
    pub x: U256,
    pub y: U256,
    pub infinity: bool,
}

/// Jacobian representation (X : Y : Z) where affine x = X/Z^2, y = Y/Z^3
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub struct JacobianPoint {
    pub x: U256,
    pub y: U256,
    pub z: U256,
    pub infinity: bool,
}

/// Generator Point G (x-coordinate)
pub const GEN_X: U256 = U256([
    0x59F2815B16F81798,
    0x029BFCDB2DCE28D9,
    0x55A06295CE870B07,
    0x79BE667EF9DCBBAC,
]);

/// Generator Point G (y-coordinate)
pub const GEN_Y: U256 = U256([
    0x9C47D08FFB10D4B8,
    0xFD17B448A6855419,
    0x5DA4FBFC0E1108A8,
    0x483ADA7726A3C465,
]);

pub const G: AffinePoint = AffinePoint {
    x: GEN_X,
    y: GEN_Y,
    infinity: false,
};

impl AffinePoint {
    pub const INFINITY: AffinePoint = AffinePoint {
        x: U256::ZERO,
        y: U256::ZERO,
        infinity: true,
    };

    pub fn to_jacobian(&self) -> JacobianPoint {
        if self.infinity {
            JacobianPoint::INFINITY
        } else {
            JacobianPoint {
                x: self.x,
                y: self.y,
                z: U256::ONE,
                infinity: false,
            }
        }
    }

    /// Compress to 33-byte standard Bitcoin SEC format
    pub fn to_compressed(&self) -> [u8; 33] {
        let mut out = [0u8; 33];
        if self.infinity {
            return out;
        }
        out[0] = if self.y.is_odd() { 0x03 } else { 0x02 };
        out[1..33].copy_from_slice(&self.x.to_be_bytes());
        out
    }

    /// Check if point is valid on the secp256k1 curve y^2 = x^3 + 7 mod P
    pub fn is_valid(&self) -> bool {
        if self.infinity {
            return true;
        }
        let lhs = self.y.field_square();
        let rhs = self
            .x
            .field_square()
            .field_mul(&self.x)
            .field_add(&U256::from_u64(7));
        lhs == rhs
    }
}

impl JacobianPoint {
    pub const INFINITY: JacobianPoint = JacobianPoint {
        x: U256::ONE,
        y: U256::ONE,
        z: U256::ZERO,
        infinity: true,
    };

    /// Convert Jacobian point to Affine point using a single field inversion
    pub fn to_affine(&self) -> AffinePoint {
        if self.infinity || self.z.is_zero() {
            return AffinePoint::INFINITY;
        }
        let z_inv = self.z.field_inv();
        let z_inv2 = z_inv.field_square();
        let z_inv3 = z_inv2.field_mul(&z_inv);

        let x = self.x.field_mul(&z_inv2);
        let y = self.y.field_mul(&z_inv3);

        AffinePoint {
            x,
            y,
            infinity: false,
        }
    }

    /// Point doubling: 2 * self
    pub fn double(&self) -> JacobianPoint {
        if self.infinity || self.y.is_zero() {
            return JacobianPoint::INFINITY;
        }

        // S = 4 * X * Y^2
        let ysq = self.y.field_square();
        let s = self.x.field_mul(&ysq);
        let s = s.field_add(&s);
        let s = s.field_add(&s);

        // M = 3 * X^2
        let xsq = self.x.field_square();
        let m = xsq.field_add(&xsq).field_add(&xsq);

        // X' = M^2 - 2*S
        let msq = m.field_square();
        let s2 = s.field_add(&s);
        let x_out = msq.field_sub(&s2);

        // Y' = M * (S - X') - 8 * Y^4
        let ysq_sq = ysq.field_square();
        let ysq_sq2 = ysq_sq.field_add(&ysq_sq);
        let ysq_sq4 = ysq_sq2.field_add(&ysq_sq2);
        let y8 = ysq_sq4.field_add(&ysq_sq4);

        let y_out = m.field_mul(&s.field_sub(&x_out)).field_sub(&y8);

        // Z' = 2 * Y * Z
        let z_out = self.y.field_mul(&self.z);
        let z_out = z_out.field_add(&z_out);

        JacobianPoint {
            x: x_out,
            y: y_out,
            z: z_out,
            infinity: false,
        }
    }

    /// Mixed addition: self (Jacobian) + other (Affine where Z=1)
    pub fn add_affine(&self, other: &AffinePoint) -> JacobianPoint {
        if self.infinity {
            return other.to_jacobian();
        }
        if other.infinity {
            return *self;
        }

        // U1 = X1, S1 = Y1
        // U2 = X2 * Z1^2
        // S2 = Y2 * Z1^3
        let z1_sq = self.z.field_square();
        let z1_cub = z1_sq.field_mul(&self.z);

        let u2 = other.x.field_mul(&z1_sq);
        let s2 = other.y.field_mul(&z1_cub);

        if self.x == u2 {
            if self.y == s2 {
                return self.double();
            } else {
                return JacobianPoint::INFINITY;
            }
        }

        // H = U2 - X1
        let h = u2.field_sub(&self.x);
        // R = S2 - Y1
        let r = s2.field_sub(&self.y);

        let h_sq = h.field_square();
        let h_cub = h_sq.field_mul(&h);

        // X3 = R^2 - H^3 - 2 * X1 * H^2
        let r_sq = r.field_square();
        let x1_h_sq = self.x.field_mul(&h_sq);
        let two_x1_h_sq = x1_h_sq.field_add(&x1_h_sq);
        let x3 = r_sq.field_sub(&h_cub).field_sub(&two_x1_h_sq);

        // Y3 = R * (X1 * H^2 - X3) - Y1 * H^3
        let y3 = r
            .field_mul(&x1_h_sq.field_sub(&x3))
            .field_sub(&self.y.field_mul(&h_cub));

        // Z3 = Z1 * H
        let z3 = self.z.field_mul(&h);

        JacobianPoint {
            x: x3,
            y: y3,
            z: z3,
            infinity: false,
        }
    }

    /// General Jacobian + Jacobian addition
    pub fn add_jacobian(&self, other: &JacobianPoint) -> JacobianPoint {
        if self.infinity {
            return *other;
        }
        if other.infinity {
            return *self;
        }

        let z1_sq = self.z.field_square();
        let z2_sq = other.z.field_square();

        let u1 = self.x.field_mul(&z2_sq);
        let u2 = other.x.field_mul(&z1_sq);

        let s1 = self.y.field_mul(&z2_sq.field_mul(&other.z));
        let s2 = other.y.field_mul(&z1_sq.field_mul(&self.z));

        if u1 == u2 {
            if s1 == s2 {
                return self.double();
            } else {
                return JacobianPoint::INFINITY;
            }
        }

        let h = u2.field_sub(&u1);
        let r = s2.field_sub(&s1);

        let h_sq = h.field_square();
        let h_cub = h_sq.field_mul(&h);

        let u1_h_sq = u1.field_mul(&h_sq);
        let two_u1_h_sq = u1_h_sq.field_add(&u1_h_sq);

        let x3 = r.field_square().field_sub(&h_cub).field_sub(&two_u1_h_sq);
        let y3 = r
            .field_mul(&u1_h_sq.field_sub(&x3))
            .field_sub(&s1.field_mul(&h_cub));
        let z3 = self.z.field_mul(&other.z).field_mul(&h);

        JacobianPoint {
            x: x3,
            y: y3,
            z: z3,
            infinity: false,
        }
    }
}

/// Scalar multiplication: k * G
pub fn scalar_mul_g(k: &U256) -> AffinePoint {
    let mut res = JacobianPoint::INFINITY;
    let mut current = G.to_jacobian();

    for limb in &k.0 {
        let mut l = *limb;
        for _ in 0..64 {
            if (l & 1) != 0 {
                res = res.add_jacobian(&current);
            }
            current = current.double();
            l >>= 1;
        }
    }

    res.to_affine()
}

/// Scalar multiplication for any affine point: k * P
pub fn scalar_mul(p: &AffinePoint, k: &U256) -> AffinePoint {
    let mut res = JacobianPoint::INFINITY;
    let mut current = p.to_jacobian();

    for limb in &k.0 {
        let mut l = *limb;
        for _ in 0..64 {
            if (l & 1) != 0 {
                res = res.add_jacobian(&current);
            }
            current = current.double();
            l >>= 1;
        }
    }

    res.to_affine()
}
