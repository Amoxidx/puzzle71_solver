use puzzle71_solver::crypto::address::privkey_u128_to_address;
use puzzle71_solver::crypto::base58::{b58_decode, b58_encode, b58check_decode};
use puzzle71_solver::crypto::hash160::{hash160, hash160_from_pubkey33};
use puzzle71_solver::crypto::ripemd160::{ripemd160, ripemd160_32};
use puzzle71_solver::crypto::secp256k1::{G, scalar_mul_g};
use puzzle71_solver::crypto::sha256::{sha256, sha256_33};
use puzzle71_solver::crypto::u256::U256;
use puzzle71_solver::puzzle_config::{
    RANGE_MAX, RANGE_MIN, RANGE_SIZE, TARGET_ADDRESS, TARGET_HASH160,
};

#[test]
fn test_secp256k1_base_point_on_curve() {
    assert!(
        G.is_valid(),
        "Generator point G must lie on secp256k1 curve"
    );
    assert_eq!(
        G.x.to_hex(),
        "79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"
    );
    assert_eq!(
        G.y.to_hex(),
        "483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8"
    );
}

#[test]
fn test_secp256k1_point_addition_and_doubling() {
    // 1 * G == G
    let p1 = scalar_mul_g(&U256::ONE);
    assert_eq!(p1, G);

    // 2 * G
    let p2 = scalar_mul_g(&U256::from_u64(2));
    let p2_double = G.to_jacobian().double().to_affine();
    assert_eq!(p2, p2_double);
    assert!(p2.is_valid());

    // 3 * G
    let p3 = scalar_mul_g(&U256::from_u64(3));
    let p3_add = G.to_jacobian().double().add_affine(&G).to_affine();
    assert_eq!(p3, p3_add);
    assert!(p3.is_valid());
}

#[test]
fn test_sha256_nist_vectors() {
    // Empty string
    let h = sha256(b"");
    assert_eq!(
        hex::encode(h),
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    );

    // "abc"
    let h = sha256(b"abc");
    assert_eq!(
        hex::encode(h),
        "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
    );

    // 56-byte vector
    let h = sha256(b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq");
    assert_eq!(
        hex::encode(h),
        "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1"
    );
}

#[test]
fn test_sha256_33_specialized() {
    let p1 = scalar_mul_g(&U256::ONE);
    let comp = p1.to_compressed();
    let full = sha256(&comp);
    let specialized = sha256_33(&comp);
    assert_eq!(full, specialized, "sha256_33 must match generic sha256");
}

#[test]
fn test_ripemd160_vectors() {
    assert_eq!(
        hex::encode(ripemd160(b"")),
        "9c1185a5c5e9fc54612808977ee8f548b2258d31"
    );
    assert_eq!(
        hex::encode(ripemd160(b"a")),
        "0bdc9d2d256b3ee9daae347be6f4dc835a467ffe"
    );
    assert_eq!(
        hex::encode(ripemd160(b"abc")),
        "8eb208f7e05d987a9b044a8e98c6b087f15a0bfc"
    );
    assert_eq!(
        hex::encode(ripemd160(b"message digest")),
        "5d0689ef49d2fae572b881b123a85ffa21595f36"
    );
}

#[test]
fn test_ripemd160_32_specialized() {
    let dummy_sha: [u8; 32] = sha256(b"test_key_compression_input");
    let full = ripemd160(&dummy_sha);
    let specialized = ripemd160_32(&dummy_sha);
    assert_eq!(
        full, specialized,
        "ripemd160_32 must match generic ripemd160"
    );
}

#[test]
fn test_hash160_pubkey_pipeline() {
    let p1 = scalar_mul_g(&U256::ONE);
    let comp = p1.to_compressed();
    let h1 = hash160(&comp);
    let h2 = hash160_from_pubkey33(&comp);
    assert_eq!(h1, h2);
}

#[test]
fn test_base58_roundtrip() {
    let data = b"Hello Bitcoin World!";
    let encoded = b58_encode(data);
    let decoded = b58_decode(&encoded).expect("Decode should succeed");
    assert_eq!(data, decoded.as_slice());
}

#[test]
fn test_bitcoin_compressed_address_derivation_vectors() {
    // Vector 1: k = 0x1
    let (addr1, h1, _) = privkey_u128_to_address(1);
    assert_eq!(addr1, "1BgGZ9tcN4rm9KBzDn7KprQz87SZ26SAMH");
    assert_eq!(hex::encode(h1), "751e76e8199196d454941c45d1b3a323f1433bd6");

    // Vector 2: k = 0x2
    let (addr2, h2, _) = privkey_u128_to_address(0x2);
    assert_eq!(addr2, "1cMh228HTCiwS8ZsaakH8A8wze1JR5ZsP");
    assert_eq!(hex::encode(h2), "06afd46bcdfd22ef94ac122aa11f241244a37ecc");

    // Vector 3: k = 0x3
    let (addr3, h3, _) = privkey_u128_to_address(0x3);
    assert_eq!(addr3, "1CUNEBjYrCn2y1SdiUMohaKUi4wpP326Lb");
    assert_eq!(hex::encode(h3), "7dd65592d0ab2fe0d0257d571abf032cd9db93dc");

    // Vector 4: k = 0x4
    let (addr4, h4, _) = privkey_u128_to_address(0x4);
    assert_eq!(addr4, "1JtK9CQw1syfWj1WtFMWomrYdV3W2tWBF9");
    assert_eq!(hex::encode(h4), "c42e7ef92fdb603af844d064faad95db9bcdfd3d");

    // Vector 5: k = 0x8
    let (addr8, h8, _) = privkey_u128_to_address(0x8);
    assert_eq!(addr8, "1EhqbyUMvvs7BfL8goY6qcPbD6YKfPqb7e");
    assert_eq!(hex::encode(h8), "9652d86bedf43ad264362e6e6eba6eb764508127");

    // Vector 6: k = 0x123456
    let (addr_hex, h_hex, _) = privkey_u128_to_address(0x123456);
    assert_eq!(addr_hex, "1CemFrerZEwKapRKvRNSz3u8hcDusZkbcG");
    assert_eq!(
        hex::encode(h_hex),
        "7fcdb7a5b7f08d852a4d8d0ff4f7dff215351cc3"
    );
}

#[test]
fn test_puzzle71_target_hash160_verification() {
    let (version, payload) = b58check_decode(TARGET_ADDRESS).expect("Decode target address");
    assert_eq!(version, 0x00, "Mainnet P2PKH version byte must be 0x00");
    assert_eq!(
        payload.as_slice(),
        &TARGET_HASH160,
        "Target address payload must match TARGET_HASH160"
    );
}

#[test]
fn test_range_bounds_and_endianness() {
    assert_eq!(RANGE_MIN, 1u128 << 70);
    assert_eq!(RANGE_MAX, (1u128 << 71) - 1);
    assert_eq!(RANGE_SIZE, 1u128 << 70);
    assert_eq!(RANGE_MAX - RANGE_MIN + 1, RANGE_SIZE);
}

// Helper to display hex in test
trait ToHexStr {
    fn to_hex(&self) -> String;
}

impl ToHexStr for U256 {
    fn to_hex(&self) -> String {
        format!("{}", self)
    }
}

mod hex {
    pub fn encode<T: AsRef<[u8]>>(data: T) -> String {
        let mut s = String::new();
        for &b in data.as_ref() {
            s.push_str(&format!("{:02x}", b));
        }
        s
    }
}
