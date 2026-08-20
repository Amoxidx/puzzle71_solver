//! Pure, auditable implementation of RIPEMD-160.

#[inline(always)]
fn rol(x: u32, n: u32) -> u32 {
    x.rotate_left(n)
}

#[inline(always)]
fn f1(x: u32, y: u32, z: u32) -> u32 {
    x ^ y ^ z
}

#[inline(always)]
fn f2(x: u32, y: u32, z: u32) -> u32 {
    (x & y) | (!x & z)
}

#[inline(always)]
fn f3(x: u32, y: u32, z: u32) -> u32 {
    (x | !y) ^ z
}

#[inline(always)]
fn f4(x: u32, y: u32, z: u32) -> u32 {
    (x & z) | (y & !z)
}

#[inline(always)]
fn f5(x: u32, y: u32, z: u32) -> u32 {
    x ^ (y | !z)
}

const RL: [u32; 80] = [
    0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 7, 4, 13, 1, 10, 6, 15, 3, 12, 0, 9, 5,
    2, 14, 11, 8, 3, 10, 14, 4, 9, 15, 8, 1, 2, 7, 0, 6, 13, 11, 5, 12, 1, 9, 11, 10, 0, 8, 12, 4,
    13, 3, 7, 15, 14, 5, 6, 2, 4, 0, 5, 9, 7, 12, 2, 10, 14, 1, 3, 8, 11, 6, 15, 13,
];

const RR: [u32; 80] = [
    5, 14, 7, 0, 9, 2, 11, 4, 13, 6, 15, 8, 1, 10, 3, 12, 6, 11, 3, 7, 0, 13, 5, 10, 14, 15, 8, 12,
    4, 9, 1, 2, 15, 5, 1, 3, 7, 14, 6, 9, 11, 8, 12, 2, 10, 0, 4, 13, 8, 6, 4, 1, 3, 11, 15, 0, 5,
    12, 2, 13, 9, 7, 10, 14, 12, 15, 10, 4, 1, 5, 8, 7, 6, 2, 13, 14, 0, 3, 9, 11,
];

const SL: [u32; 80] = [
    11, 14, 15, 12, 5, 8, 7, 9, 11, 13, 14, 15, 6, 7, 9, 8, 7, 6, 8, 13, 11, 9, 7, 15, 7, 12, 15,
    9, 11, 7, 13, 12, 11, 13, 6, 7, 14, 9, 13, 15, 14, 8, 13, 6, 5, 12, 7, 5, 11, 12, 14, 15, 14,
    15, 9, 8, 9, 14, 5, 6, 8, 6, 5, 12, 9, 15, 5, 11, 6, 8, 13, 12, 5, 12, 13, 14, 11, 8, 5, 6,
];

const SR: [u32; 80] = [
    8, 9, 9, 11, 13, 15, 15, 5, 7, 7, 8, 11, 14, 14, 12, 6, 9, 13, 15, 7, 12, 8, 9, 11, 7, 7, 12,
    7, 6, 15, 13, 11, 9, 7, 15, 11, 8, 6, 6, 14, 12, 13, 5, 14, 13, 13, 7, 5, 15, 5, 8, 11, 14, 14,
    6, 14, 6, 9, 12, 9, 12, 5, 15, 8, 8, 5, 12, 9, 12, 5, 14, 6, 8, 13, 6, 5, 15, 13, 11, 11,
];

const KL: [u32; 5] = [0x00000000, 0x5a827999, 0x6ed9eba1, 0x8f1bbcdc, 0xa953fd4e];
const KR: [u32; 5] = [0x50a28be6, 0x5c4dd124, 0x6d703ef3, 0x7a6d76e9, 0x00000000];

pub fn ripemd160_compress_block(state: &mut [u32; 5], block: &[u8; 64]) {
    let mut x = [0u32; 16];
    for (i, word) in x.iter_mut().enumerate() {
        let offset = i * 4;
        *word = u32::from_le_bytes(block[offset..offset + 4].try_into().unwrap());
    }

    let mut al = state[0];
    let mut bl = state[1];
    let mut cl = state[2];
    let mut dl = state[3];
    let mut el = state[4];

    let mut ar = state[0];
    let mut br = state[1];
    let mut cr = state[2];
    let mut dr = state[3];
    let mut er = state[4];

    for i in 0..80 {
        let round = i / 16;

        let fl = match round {
            0 => f1(bl, cl, dl),
            1 => f2(bl, cl, dl),
            2 => f3(bl, cl, dl),
            3 => f4(bl, cl, dl),
            _ => f5(bl, cl, dl),
        };
        let tl = al
            .wrapping_add(fl)
            .wrapping_add(x[RL[i] as usize])
            .wrapping_add(KL[round]);
        let tl = rol(tl, SL[i]).wrapping_add(el);
        al = el;
        el = dl;
        dl = rol(cl, 10);
        cl = bl;
        bl = tl;

        let fr = match round {
            0 => f5(br, cr, dr),
            1 => f4(br, cr, dr),
            2 => f3(br, cr, dr),
            3 => f2(br, cr, dr),
            _ => f1(br, cr, dr),
        };
        let tr = ar
            .wrapping_add(fr)
            .wrapping_add(x[RR[i] as usize])
            .wrapping_add(KR[round]);
        let tr = rol(tr, SR[i]).wrapping_add(er);
        ar = er;
        er = dr;
        dr = rol(cr, 10);
        cr = br;
        br = tr;
    }

    let t = state[1].wrapping_add(cl).wrapping_add(dr);
    state[1] = state[2].wrapping_add(dl).wrapping_add(er);
    state[2] = state[3].wrapping_add(el).wrapping_add(ar);
    state[3] = state[4].wrapping_add(al).wrapping_add(br);
    state[4] = state[0].wrapping_add(bl).wrapping_add(cr);
    state[0] = t;
}

pub fn ripemd160(data: &[u8]) -> [u8; 20] {
    let mut state = [
        0x67452301u32,
        0xefcdab89u32,
        0x98badcfeu32,
        0x10325476u32,
        0xc3d2e1f0u32,
    ];

    let bit_len = (data.len() as u64) * 8;
    let mut offset = 0;
    while offset + 64 <= data.len() {
        let block: &[u8; 64] = data[offset..offset + 64].try_into().unwrap();
        ripemd160_compress_block(&mut state, block);
        offset += 64;
    }

    let rem = &data[offset..];
    let mut pad_block = [0u8; 64];
    pad_block[..rem.len()].copy_from_slice(rem);
    pad_block[rem.len()] = 0x80;

    if rem.len() >= 56 {
        ripemd160_compress_block(&mut state, &pad_block);
        let mut final_block = [0u8; 64];
        final_block[56..64].copy_from_slice(&bit_len.to_le_bytes());
        ripemd160_compress_block(&mut state, &final_block);
    } else {
        pad_block[56..64].copy_from_slice(&bit_len.to_le_bytes());
        ripemd160_compress_block(&mut state, &pad_block);
    }

    let mut out = [0u8; 20];
    for i in 0..5 {
        out[i * 4..(i + 1) * 4].copy_from_slice(&state[i].to_le_bytes());
    }
    out
}

/// Specialized, single-block RIPEMD-160 for a 32-byte SHA-256 hash input
#[inline(always)]
pub fn ripemd160_32(sha_output: &[u8; 32]) -> [u8; 20] {
    let mut state = [
        0x67452301u32,
        0xefcdab89u32,
        0x98badcfeu32,
        0x10325476u32,
        0xc3d2e1f0u32,
    ];
    let mut block = [0u8; 64];
    block[..32].copy_from_slice(sha_output);
    block[32] = 0x80;
    // 32 bytes * 8 = 256 bits = 0x0100 (in little-endian: index 56 is 0x00, index 57 is 0x01)
    block[56] = 0x00;
    block[57] = 0x01;

    ripemd160_compress_block(&mut state, &block);

    let mut out = [0u8; 20];
    for i in 0..5 {
        out[i * 4..(i + 1) * 4].copy_from_slice(&state[i].to_le_bytes());
    }
    out
}
