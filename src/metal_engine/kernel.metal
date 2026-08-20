#include <metal_stdlib>
using namespace metal;

// ==============================================================================
// 256-bit Integer & secp256k1 Field Arithmetic (8 x uint32 limbs, Little Endian)
// secp256k1 Prime P = 2^256 - 2^32 - 977
// ==============================================================================

struct U256 {
    uint32_t d[8];
};

constant uint32_t P_LIMBS[8] = {
    0xFFFFFC2F, 0xFFFFFFFE, 0xFFFFFFFF, 0xFFFFFFFF,
    0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF
};

constant uint32_t G_X_LIMBS[8] = {
    0x16F81798, 0x59F2815B, 0x2DCE28D9, 0x029BFCDB,
    0xCE870B07, 0x55A06295, 0xF9DCBBAC, 0x79BE667E
};

constant uint32_t G_Y_LIMBS[8] = {
    0xFB10D4B8, 0x9C47D08F, 0xA6855419, 0xFD17B448,
    0x0E1108A8, 0x5DA4FBFC, 0x26A3C465, 0x483ADA77
};

inline bool u256_is_zero(thread const U256& a) {
    for (int i = 0; i < 8; ++i) {
        if (a.d[i] != 0) return false;
    }
    return true;
}

inline bool u256_gte_p(thread const U256& a) {
    for (int i = 7; i >= 0; --i) {
        if (a.d[i] > P_LIMBS[i]) return true;
        if (a.d[i] < P_LIMBS[i]) return false;
    }
    return true;
}

inline U256 u256_add(thread const U256& a, thread const U256& b) {
    U256 r;
    uint64_t carry = 0;
    for (int i = 0; i < 8; ++i) {
        uint64_t sum = (uint64_t)a.d[i] + (uint64_t)b.d[i] + carry;
        r.d[i] = (uint32_t)sum;
        carry = sum >> 32;
    }
    if (carry || u256_gte_p(r)) {
        uint64_t borrow = 0;
        for (int i = 0; i < 8; ++i) {
            int64_t diff = (int64_t)r.d[i] - (int64_t)P_LIMBS[i] - borrow;
            if (diff < 0) {
                r.d[i] = (uint32_t)(diff + 0x100000000ULL);
                borrow = 1;
            } else {
                r.d[i] = (uint32_t)diff;
                borrow = 0;
            }
        }
    }
    return r;
}

inline U256 u256_sub(thread const U256& a, thread const U256& b) {
    U256 r;
    uint64_t borrow = 0;
    for (int i = 0; i < 8; ++i) {
        int64_t diff = (int64_t)a.d[i] - (int64_t)b.d[i] - borrow;
        if (diff < 0) {
            r.d[i] = (uint32_t)(diff + 0x100000000ULL);
            borrow = 1;
        } else {
            r.d[i] = (uint32_t)diff;
            borrow = 0;
        }
    }
    if (borrow) {
        uint64_t carry = 0;
        for (int i = 0; i < 8; ++i) {
            uint64_t sum = (uint64_t)r.d[i] + (uint64_t)P_LIMBS[i] + carry;
            r.d[i] = (uint32_t)sum;
            carry = sum >> 32;
        }
    }
    return r;
}

inline U256 u256_mul(thread const U256& a, thread const U256& b) {
    uint32_t r[16] = {0};
    for (int i = 0; i < 8; ++i) {
        uint64_t carry = 0;
        for (int j = 0; j < 8; ++j) {
            uint64_t prod = (uint64_t)a.d[i] * (uint64_t)b.d[j] + (uint64_t)r[i + j] + carry;
            r[i + j] = (uint32_t)prod;
            carry = prod >> 32;
        }
        r[i + 8] += (uint32_t)carry;
    }

    // Reduce 512-bit r[0..15] modulo P (2^256 = 0x1000003D1 mod P)
    // 0x1000003D1 = (1 << 32) + 977
    uint32_t low[8];
    uint32_t high[8];
    for (int i = 0; i < 8; ++i) {
        low[i] = r[i];
        high[i] = r[i + 8];
    }

    // Multiply high by 0x1000003D1:
    // high * 0x1000003D1 = (high << 32) + high * 977
    uint32_t h_prod[10] = {0};
    uint64_t c = 0;
    for (int i = 0; i < 8; ++i) {
        uint64_t prod = (uint64_t)high[i] * 977ULL + c;
        h_prod[i] = (uint32_t)prod;
        c = prod >> 32;
    }
    h_prod[8] = (uint32_t)c;

    c = 0;
    for (int i = 0; i < 8; ++i) {
        uint64_t sum = (uint64_t)h_prod[i + 1] + (uint64_t)high[i] + c;
        h_prod[i + 1] = (uint32_t)sum;
        c = sum >> 32;
    }
    h_prod[9] += (uint32_t)c;

    // Add h_prod to low
    uint32_t sum_limbs[10] = {0};
    c = 0;
    for (int i = 0; i < 8; ++i) {
        uint64_t s = (uint64_t)low[i] + (uint64_t)h_prod[i] + c;
        sum_limbs[i] = (uint32_t)s;
        c = s >> 32;
    }
    uint64_t s8 = (uint64_t)h_prod[8] + c;
    sum_limbs[8] = (uint32_t)s8;
    sum_limbs[9] = h_prod[9] + (uint32_t)(s8 >> 32);

    // Reduce any remaining overflow in sum_limbs[8..9]
    uint64_t extra = (uint64_t)sum_limbs[8] | ((uint64_t)sum_limbs[9] << 32);
    if (extra != 0) {
        uint64_t extra_prod = extra * 977ULL;
        uint64_t extra_shift = extra; // * 2^32

        c = extra_prod;
        for (int i = 0; i < 8; ++i) {
            uint64_t s = (uint64_t)sum_limbs[i] + (c & 0xFFFFFFFFULL);
            sum_limbs[i] = (uint32_t)s;
            c = (s >> 32) + (c >> 32);
        }

        // Add extra_shift at index 1
        c = extra_shift;
        for (int i = 1; i < 8; ++i) {
            uint64_t s = (uint64_t)sum_limbs[i] + (c & 0xFFFFFFFFULL);
            sum_limbs[i] = (uint32_t)s;
            c = (s >> 32) + (c >> 32);
        }
    }

    U256 out;
    for (int i = 0; i < 8; ++i) out.d[i] = sum_limbs[i];

    while (u256_gte_p(out)) {
        uint64_t borrow = 0;
        for (int i = 0; i < 8; ++i) {
            int64_t diff = (int64_t)out.d[i] - (int64_t)P_LIMBS[i] - borrow;
            if (diff < 0) {
                out.d[i] = (uint32_t)(diff + 0x100000000ULL);
                borrow = 1;
            } else {
                out.d[i] = (uint32_t)diff;
                borrow = 0;
            }
        }
    }
    return out;
}

inline U256 u256_sqr(thread const U256& a) {
    return u256_mul(a, a);
}

constant uint32_t P_MINUS_2[8] = {
    0xFFFFFC2D, 0xFFFFFFFE, 0xFFFFFFFF, 0xFFFFFFFF,
    0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF
};

// Modular inverse via addition chain / exponentiation a^(P-2) mod P
inline U256 u256_inv(thread const U256& a) {
    U256 res;
    for (int i = 0; i < 8; ++i) res.d[i] = (i == 0) ? 1 : 0;
    U256 base = a;

    for (int i = 0; i < 8; ++i) {
        uint32_t limb = P_MINUS_2[i];
        for (int b = 0; b < 32; ++b) {
            if (limb & 1) {
                res = u256_mul(res, base);
            }
            base = u256_sqr(base);
            limb >>= 1;
        }
    }
    return res;
}

// ==============================================================================
// secp256k1 Point Operations (Jacobian Coordinates)
// ==============================================================================

struct JacobianPoint {
    U256 x;
    U256 y;
    U256 z;
    bool is_inf;
};

struct AffinePoint {
    U256 x;
    U256 y;
    bool is_inf;
};

inline JacobianPoint jacobian_double(thread const JacobianPoint& p) {
    if (p.is_inf || u256_is_zero(p.y)) {
        JacobianPoint inf = {p.x, p.y, p.z, true};
        return inf;
    }

    // S = 4 * X * Y^2
    U256 ysq = u256_sqr(p.y);
    U256 s = u256_mul(p.x, ysq);
    s = u256_add(s, s);
    s = u256_add(s, s);

    // M = 3 * X^2
    U256 xsq = u256_sqr(p.x);
    U256 m = u256_add(xsq, u256_add(xsq, xsq));

    // X' = M^2 - 2*S
    U256 msq = u256_sqr(m);
    U256 s2 = u256_add(s, s);
    U256 x_out = u256_sub(msq, s2);

    // Y' = M * (S - X') - 8 * Y^4
    U256 ysq_sq = u256_sqr(ysq);
    U256 y8 = u256_add(ysq_sq, ysq_sq);
    y8 = u256_add(y8, y8);
    y8 = u256_add(y8, y8);

    U256 s_sub_x = u256_sub(s, x_out);
    U256 y_out = u256_sub(u256_mul(m, s_sub_x), y8);

    // Z' = 2 * Y * Z
    U256 z_out = u256_mul(p.y, p.z);
    z_out = u256_add(z_out, z_out);

    JacobianPoint r = {x_out, y_out, z_out, false};
    return r;
}

inline JacobianPoint jacobian_add_affine(thread const JacobianPoint& p, thread const AffinePoint& q) {
    if (p.is_inf) {
        JacobianPoint r = {q.x, q.y, {{1,0,0,0,0,0,0,0}}, q.is_inf};
        return r;
    }
    if (q.is_inf) return p;

    U256 z1_sq = u256_sqr(p.z);
    U256 z1_cub = u256_mul(z1_sq, p.z);

    U256 u2 = u256_mul(q.x, z1_sq);
    U256 s2 = u256_mul(q.y, z1_cub);

    // H = U2 - X1
    U256 h = u256_sub(u2, p.x);
    // R = S2 - Y1
    U256 r = u256_sub(s2, p.y);

    if (u256_is_zero(h)) {
        if (u256_is_zero(r)) {
            return jacobian_double(p);
        } else {
            JacobianPoint inf = {p.x, p.y, p.z, true};
            return inf;
        }
    }

    U256 h_sq = u256_sqr(h);
    U256 h_cub = u256_mul(h_sq, h);

    U256 x1_h_sq = u256_mul(p.x, h_sq);
    U256 two_x1_h_sq = u256_add(x1_h_sq, x1_h_sq);

    U256 r_sq = u256_sqr(r);
    U256 x3 = u256_sub(u256_sub(r_sq, h_cub), two_x1_h_sq);

    U256 diff = u256_sub(x1_h_sq, x3);
    U256 y1_h_cub = u256_mul(p.y, h_cub);
    U256 y3 = u256_sub(u256_mul(r, diff), y1_h_cub);

    U256 z3 = u256_mul(p.z, h);

    JacobianPoint res = {x3, y3, z3, false};
    return res;
}

inline AffinePoint jacobian_to_affine(thread const JacobianPoint& p) {
    if (p.is_inf || u256_is_zero(p.z)) {
        AffinePoint inf = {p.x, p.y, true};
        return inf;
    }
    U256 z_inv = u256_inv(p.z);
    U256 z_inv2 = u256_sqr(z_inv);
    U256 z_inv3 = u256_mul(z_inv2, z_inv);

    U256 x = u256_mul(p.x, z_inv2);
    U256 y = u256_mul(p.y, z_inv3);

    AffinePoint res = {x, y, false};
    return res;
}

// ==============================================================================
// Inline Cryptographic Hashing: SHA-256 (33-byte) & RIPEMD-160 (32-byte)
// ==============================================================================

inline uint32_t rotr(uint32_t x, uint32_t n) {
    return (x >> n) | (x << (32 - n));
}

inline uint32_t rol(uint32_t x, uint32_t n) {
    return (x << n) | (x >> (32 - n));
}

constant uint32_t SHA256_K[64] = {
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
    0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
    0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
    0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
    0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
    0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3,
    0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5,
    0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
    0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
};

inline void sha256_33_inline(thread const uint8_t* pubkey, thread uint32_t* hash_words) {
    uint32_t w[64];
    for (int i = 0; i < 16; ++i) {
        w[i] = 0;
    }

    // Pack 33 bytes + 0x80 padding into big-endian words
    // Byte 0: prefix (0x02 or 0x03)
    // Bytes 1..32: x-coordinate
    // Byte 33: 0x80
    // Bytes 34..61: 0x00
    // Bytes 62..63: 0x0108 (264 bits)
    w[0] = ((uint32_t)pubkey[0] << 24) | ((uint32_t)pubkey[1] << 16) | ((uint32_t)pubkey[2] << 8) | (uint32_t)pubkey[3];
    w[1] = ((uint32_t)pubkey[4] << 24) | ((uint32_t)pubkey[5] << 16) | ((uint32_t)pubkey[6] << 8) | (uint32_t)pubkey[7];
    w[2] = ((uint32_t)pubkey[8] << 24) | ((uint32_t)pubkey[9] << 16) | ((uint32_t)pubkey[10] << 8) | (uint32_t)pubkey[11];
    w[3] = ((uint32_t)pubkey[12] << 24) | ((uint32_t)pubkey[13] << 16) | ((uint32_t)pubkey[14] << 8) | (uint32_t)pubkey[15];
    w[4] = ((uint32_t)pubkey[16] << 24) | ((uint32_t)pubkey[17] << 16) | ((uint32_t)pubkey[18] << 8) | (uint32_t)pubkey[19];
    w[5] = ((uint32_t)pubkey[20] << 24) | ((uint32_t)pubkey[21] << 16) | ((uint32_t)pubkey[22] << 8) | (uint32_t)pubkey[23];
    w[6] = ((uint32_t)pubkey[24] << 24) | ((uint32_t)pubkey[25] << 16) | ((uint32_t)pubkey[26] << 8) | (uint32_t)pubkey[27];
    w[7] = ((uint32_t)pubkey[28] << 24) | ((uint32_t)pubkey[29] << 16) | ((uint32_t)pubkey[30] << 8) | (uint32_t)pubkey[31];
    w[8] = ((uint32_t)pubkey[32] << 24) | 0x00800000;
    w[9] = 0;
    w[10] = 0;
    w[11] = 0;
    w[12] = 0;
    w[13] = 0;
    w[14] = 0;
    w[15] = 0x00000108;

    for (int i = 16; i < 64; ++i) {
        uint32_t s0 = rotr(w[i - 15], 7) ^ rotr(w[i - 15], 18) ^ (w[i - 15] >> 3);
        uint32_t s1 = rotr(w[i - 2], 17) ^ rotr(w[i - 2], 19) ^ (w[i - 2] >> 10);
        w[i] = w[i - 16] + s0 + w[i - 7] + s1;
    }

    uint32_t a = 0x6a09e667;
    uint32_t b = 0xbb67ae85;
    uint32_t c = 0x3c6ef372;
    uint32_t d = 0xa54ff53a;
    uint32_t e = 0x510e527f;
    uint32_t f = 0x9b05688c;
    uint32_t g = 0x1f83d9ab;
    uint32_t h = 0x5be0cd19;

    for (int i = 0; i < 64; ++i) {
        uint32_t S1 = rotr(e, 6) ^ rotr(e, 11) ^ rotr(e, 25);
        uint32_t ch = (e & f) ^ ((~e) & g);
        uint32_t temp1 = h + S1 + ch + SHA256_K[i] + w[i];
        uint32_t S0 = rotr(a, 2) ^ rotr(a, 13) ^ rotr(a, 22);
        uint32_t maj = (a & b) ^ (a & c) ^ (b & c);
        uint32_t temp2 = S0 + maj;

        h = g;
        g = f;
        f = e;
        e = d + temp1;
        d = c;
        c = b;
        b = a;
        a = temp1 + temp2;
    }

    hash_words[0] = 0x6a09e667 + a;
    hash_words[1] = 0xbb67ae85 + b;
    hash_words[2] = 0x3c6ef372 + c;
    hash_words[3] = 0xa54ff53a + d;
    hash_words[4] = 0x510e527f + e;
    hash_words[5] = 0x9b05688c + f;
    hash_words[6] = 0x1f83d9ab + g;
    hash_words[7] = 0x5be0cd19 + h;
}

// RIPEMD-160 constants and tables
constant uint32_t RL[80] = {
    0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
    7, 4, 13, 1, 10, 6, 15, 3, 12, 0, 9, 5, 2, 14, 11, 8,
    3, 10, 14, 4, 9, 15, 8, 1, 2, 7, 0, 6, 13, 11, 5, 12,
    1, 9, 11, 10, 0, 8, 12, 4, 13, 3, 7, 15, 14, 5, 6, 2,
    4, 0, 5, 9, 7, 12, 2, 10, 14, 1, 3, 8, 11, 6, 15, 13
};

constant uint32_t RR[80] = {
    5, 14, 7, 0, 9, 2, 11, 4, 13, 6, 15, 8, 1, 10, 3, 12,
    6, 11, 3, 7, 0, 13, 5, 10, 14, 15, 8, 12, 4, 9, 1, 2,
    15, 5, 1, 3, 7, 14, 6, 9, 11, 8, 12, 2, 10, 0, 4, 13,
    8, 6, 4, 1, 3, 11, 15, 0, 5, 12, 2, 13, 9, 7, 10, 14,
    12, 15, 10, 4, 1, 5, 8, 7, 6, 2, 13, 14, 0, 3, 9, 11
};

constant uint32_t SL[80] = {
    11, 14, 15, 12, 5, 8, 7, 9, 11, 13, 14, 15, 6, 7, 9, 8,
    7, 6, 8, 13, 11, 9, 7, 15, 7, 12, 15, 9, 11, 7, 13, 12,
    11, 13, 6, 7, 14, 9, 13, 15, 14, 8, 13, 6, 5, 12, 7, 5,
    11, 12, 14, 15, 14, 15, 9, 8, 9, 14, 5, 6, 8, 6, 5, 12,
    9, 15, 5, 11, 6, 8, 13, 12, 5, 12, 13, 14, 11, 8, 5, 6
};

constant uint32_t SR[80] = {
    8, 9, 9, 11, 13, 15, 15, 5, 7, 7, 8, 11, 14, 14, 12, 6,
    9, 13, 15, 7, 12, 8, 9, 11, 7, 7, 12, 7, 6, 15, 13, 11,
    9, 7, 15, 11, 8, 6, 6, 14, 12, 13, 5, 14, 13, 13, 7, 5,
    15, 5, 8, 11, 14, 14, 6, 14, 6, 9, 12, 9, 12, 5, 15, 8,
    8, 5, 12, 9, 12, 5, 14, 6, 8, 13, 6, 5, 15, 13, 11, 11
};

constant uint32_t KL_CONST[5] = {0x00000000, 0x5a827999, 0x6ed9eba1, 0x8f1bbcdc, 0xa953fd4e};
constant uint32_t KR_CONST[5] = {0x50a28be6, 0x5c4dd124, 0x6d703ef3, 0x7a6d76e9, 0x00000000};

inline void ripemd160_32_inline(thread const uint32_t* sha_words, thread uint32_t* h160_words) {
    uint32_t x[16];
    // Convert 8 big-endian SHA256 words into 8 little-endian RIPEMD160 words
    for (int i = 0; i < 8; ++i) {
        uint32_t w = sha_words[i];
        x[i] = ((w >> 24) & 0xff) | ((w >> 8) & 0xff00) | ((w << 8) & 0xff0000) | ((w << 24) & 0xff000000);
    }
    // Padding: 0x80 at byte 32 -> x[8] = 0x00000080
    x[8] = 0x00000080;
    x[9] = 0;
    x[10] = 0;
    x[11] = 0;
    x[12] = 0;
    x[13] = 0;
    // 256 bits length at x[14]
    x[14] = 256;
    x[15] = 0;

    uint32_t al = 0x67452301;
    uint32_t bl = 0xefcdab89;
    uint32_t cl = 0x98badcfe;
    uint32_t dl = 0x10325476;
    uint32_t el = 0xc3d2e1f0;

    uint32_t ar = 0x67452301;
    uint32_t br = 0xefcdab89;
    uint32_t cr = 0x98badcfe;
    uint32_t dr = 0x10325476;
    uint32_t er = 0xc3d2e1f0;

    for (int i = 0; i < 80; ++i) {
        int round = i / 16;
        uint32_t fl = 0;
        if (round == 0) fl = bl ^ cl ^ dl;
        else if (round == 1) fl = (bl & cl) | ((~bl) & dl);
        else if (round == 2) fl = (bl | (~cl)) ^ dl;
        else if (round == 3) fl = (bl & dl) | (cl & (~dl));
        else fl = bl ^ (cl | (~dl));

        uint32_t tl = al + fl + x[RL[i]] + KL_CONST[round];
        tl = rol(tl, SL[i]) + el;
        al = el; el = dl; dl = rol(cl, 10); cl = bl; bl = tl;

        uint32_t fr = 0;
        if (round == 0) fr = br ^ (cr | (~dr));
        else if (round == 1) fr = (br & dr) | (cr & (~dr));
        else if (round == 2) fr = (br | (~cr)) ^ dr;
        else if (round == 3) fr = (br & cr) | ((~br) & dr);
        else fr = br ^ cr ^ dr;

        uint32_t tr = ar + fr + x[RR[i]] + KR_CONST[round];
        tr = rol(tr, SR[i]) + er;
        ar = er; er = dr; dr = rol(cr, 10); cr = br; br = tr;
    }

    uint32_t t = 0xefcdab89 + cl + dr;
    h160_words[1] = 0x98badcfe + dl + er;
    h160_words[2] = 0x10325476 + el + ar;
    h160_words[3] = 0xc3d2e1f0 + al + br;
    h160_words[4] = 0x67452301 + bl + cr;
    h160_words[0] = t;
}

// ==============================================================================
// Metal Compute Kernel: Batch Incremental Search & Hash160 Match
// ==============================================================================

struct SearchParams {
    uint32_t target_hash160[5]; // 5 x 32-bit words in little endian
    uint32_t step_count;
    uint32_t valid_key_count;
};

struct FoundResult {
    atomic_uint found_flag;
    uint32_t found_thread_id;
    uint32_t found_step_idx;
};

kernel void puzzle71_search_kernel(
    device const AffinePoint* initial_points [[buffer(0)]],
    constant SearchParams& params           [[buffer(1)]],
    device FoundResult* out_result          [[buffer(2)]],
    uint thread_id                          [[thread_position_in_grid]])
{
    AffinePoint base_affine = initial_points[thread_id];
    JacobianPoint curr = {base_affine.x, base_affine.y, {{1,0,0,0,0,0,0,0}}, base_affine.is_inf};

    AffinePoint gen_g = {
        {G_X_LIMBS[0], G_X_LIMBS[1], G_X_LIMBS[2], G_X_LIMBS[3], G_X_LIMBS[4], G_X_LIMBS[5], G_X_LIMBS[6], G_X_LIMBS[7]},
        {G_Y_LIMBS[0], G_Y_LIMBS[1], G_Y_LIMBS[2], G_Y_LIMBS[3], G_Y_LIMBS[4], G_Y_LIMBS[5], G_Y_LIMBS[6], G_Y_LIMBS[7]},
        false
    };

    uint32_t steps = params.step_count;

    for (uint32_t s = 0; s < steps; ++s) {
        uint64_t key_offset = (uint64_t)thread_id * (uint64_t)steps + (uint64_t)s;
        if (key_offset >= (uint64_t)params.valid_key_count) {
            break;
        }

        // Convert to affine to get compressed pubkey
        AffinePoint p_aff = jacobian_to_affine(curr);

        // Serialize 33-byte compressed pubkey
        uint8_t pubkey[33];
        pubkey[0] = (p_aff.y.d[0] & 1) ? 0x03 : 0x02;

        // Big-endian bytes of x-coordinate
        for (int limb = 7; limb >= 0; --limb) {
            uint32_t val = p_aff.x.d[limb];
            int byte_base = 1 + (7 - limb) * 4;
            pubkey[byte_base + 0] = (uint8_t)(val >> 24);
            pubkey[byte_base + 1] = (uint8_t)(val >> 16);
            pubkey[byte_base + 2] = (uint8_t)(val >> 8);
            pubkey[byte_base + 3] = (uint8_t)val;
        }

        // SHA-256
        uint32_t sha_out[8];
        sha256_33_inline(pubkey, sha_out);

        // RIPEMD-160
        uint32_t h160[5];
        ripemd160_32_inline(sha_out, h160);

        // Compare against target_hash160
        if (h160[0] == params.target_hash160[0] &&
            h160[1] == params.target_hash160[1] &&
            h160[2] == params.target_hash160[2] &&
            h160[3] == params.target_hash160[3] &&
            h160[4] == params.target_hash160[4])
        {
            atomic_store_explicit(&out_result->found_flag, 1, memory_order_relaxed);
            out_result->found_thread_id = thread_id;
            out_result->found_step_idx = s;
            return;
        }

        // Advance to next key: curr = curr + G
        curr = jacobian_add_affine(curr, gen_g);
    }
}
