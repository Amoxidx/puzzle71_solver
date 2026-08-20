//! Base58 and Base58Check encoding / decoding for Bitcoin addresses.

use crate::crypto::sha256::double_sha256;

const ALPHABET: &[u8; 58] = b"123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

const MAP: [i8; 256] = {
    let mut map = [-1i8; 256];
    let mut i = 0;
    while i < 58 {
        map[ALPHABET[i] as usize] = i as i8;
        i += 1;
    }
    map
};

/// Encode arbitrary bytes to a Base58 string (with leading zero preservation)
pub fn b58_encode(bytes: &[u8]) -> String {
    let mut zeroes = 0;
    while zeroes < bytes.len() && bytes[zeroes] == 0 {
        zeroes += 1;
    }

    // Allocate buffer for 58-radix digits
    let size = (bytes.len() - zeroes) * 138 / 100 + 1;
    let mut digits = vec![0u8; size];
    let mut length = 0;

    for &b in &bytes[zeroes..] {
        let mut carry = b as u32;
        let mut i = 0;
        while i < length || carry != 0 {
            if i == length {
                length += 1;
            }
            let acc = (digits[i] as u32) * 256 + carry;
            digits[i] = (acc % 58) as u8;
            carry = acc / 58;
            i += 1;
        }
    }

    let mut result = String::with_capacity(zeroes + length);
    for _ in 0..zeroes {
        result.push('1');
    }
    for &d in digits[..length].iter().rev() {
        result.push(ALPHABET[d as usize] as char);
    }
    result
}

/// Decode a Base58 string to bytes
pub fn b58_decode(s: &str) -> Result<Vec<u8>, &'static str> {
    let bytes = s.as_bytes();
    let mut zeroes = 0;
    while zeroes < bytes.len() && bytes[zeroes] == b'1' {
        zeroes += 1;
    }

    let size = (bytes.len() - zeroes) * 733 / 1000 + 1;
    let mut digits = vec![0u8; size];
    let mut length = 0;

    for &c in &bytes[zeroes..] {
        let val = MAP[c as usize];
        if val < 0 {
            return Err("Invalid Base58 character");
        }
        let mut carry = val as u32;
        let mut i = 0;
        while i < length || carry != 0 {
            if i == length {
                length += 1;
            }
            let acc = (digits[i] as u32) * 58 + carry;
            digits[i] = (acc % 256) as u8;
            carry = acc / 256;
            i += 1;
        }
    }

    let mut result = vec![0u8; zeroes];
    for &d in digits[..length].iter().rev() {
        result.push(d);
    }
    Ok(result)
}

/// Base58Check encode: version byte + payload + 4-byte checksum
pub fn b58check_encode(version: u8, payload: &[u8]) -> String {
    let mut data = Vec::with_capacity(1 + payload.len() + 4);
    data.push(version);
    data.extend_from_slice(payload);

    let checksum = double_sha256(&data);
    data.extend_from_slice(&checksum[0..4]);

    b58_encode(&data)
}

/// Base58Check decode: returns (version, payload) after verifying checksum
pub fn b58check_decode(s: &str) -> Result<(u8, Vec<u8>), &'static str> {
    let raw = b58_decode(s)?;
    if raw.len() < 5 {
        return Err("Base58Check data too short");
    }

    let payload_len = raw.len() - 4;
    let (data_to_verify, expected_checksum) = raw.split_at(payload_len);

    let calculated_hash = double_sha256(data_to_verify);
    let calculated_checksum = &calculated_hash[0..4];

    if calculated_checksum != expected_checksum {
        return Err("Invalid Base58Check checksum");
    }

    let version = data_to_verify[0];
    let payload = data_to_verify[1..].to_vec();
    Ok((version, payload))
}
