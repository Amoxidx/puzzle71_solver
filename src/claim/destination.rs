//! Parsing and validating the owner-supplied claim destination address.

use bitcoin::address::NetworkUnchecked;
use bitcoin::{Address, AddressType, Network, Script};

use crate::claim::error::ClaimError;

/// Parses `input` as a Bitcoin address for `network`, accepting only the standard spendable
/// address types (P2PKH, P2SH, P2WPKH, P2WSH, P2TR) and refusing `forbidden_script` — the
/// puzzle address's own scriptPubkey. Claiming into the puzzle address itself would be a no-op
/// that burns the entire balance as fee, so it is rejected explicitly rather than merely being
/// pointless.
pub fn parse_destination(
    input: &str,
    network: Network,
    forbidden_script: &Script,
) -> Result<Address, ClaimError> {
    let trimmed = input.trim();
    let unchecked: Address<NetworkUnchecked> =
        trimmed.parse().map_err(|_| ClaimError::InvalidAddress)?;
    let address = unchecked
        .require_network(network)
        .map_err(|_| ClaimError::WrongNetwork)?;

    match address.address_type() {
        Some(AddressType::P2pkh)
        | Some(AddressType::P2sh)
        | Some(AddressType::P2wpkh)
        | Some(AddressType::P2wsh)
        | Some(AddressType::P2tr) => {}
        _ => return Err(ClaimError::UnsupportedAddressType),
    }

    if address.script_pubkey().as_script() == forbidden_script {
        return Err(ClaimError::DestinationIsPuzzleAddress);
    }

    Ok(address)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::claim::prevout::p2pkh_script_for_hash160;
    use bitcoin::hashes::Hash;

    // All addresses below are public constants: mainnet/testnet examples taken verbatim from
    // rust-bitcoin's own address test suite (bitcoin-0.32.11/src/address/mod.rs:1048-1064,929),
    // not the puzzle owner's destination.
    const P2PKH: &str = "1QJVDzdqb1VpbDK7uDeyVXy9mR27CJiyhY";
    const P2SH: &str = "33iFwdLuRpW1uK1RTRqsoi8rR4NpDzk66k";
    const P2WPKH: &str = "bc1qvzvkjn4q3nszqxrv3nraga2r822xjty3ykvkuw";
    const P2WSH: &str = "bc1qwqdg6squsna38e46795at95yu9atm8azzmyvckulcc7kytlcckxswvvzej";
    const P2TR: &str = "bc1p5cyxnuxmeuwuvkwfem96lqzszd02n6xdcjrs20cac6yqjjwudpxqkedrcr";
    // Valid bech32 (segwit v1, program length != 32) but has no recognized `AddressType`.
    const UNSUPPORTED_SEGWIT: &str =
        "bc1pw508d6qejxtdg4y5r3zarvary0c5xw7kw508d6qejxtdg4y5r3zarvary0c5xw7kt5nd6y";
    const TESTNET_P2PKH: &str = "mqkhEMH6NCeYjFybv7pvFC22MFeaNT9AQC";

    fn unrelated_script() -> bitcoin::ScriptBuf {
        p2pkh_script_for_hash160([0xAB; 20])
    }

    #[test]
    fn rejects_unparseable_input() {
        let err = parse_destination(
            "not-a-bitcoin-address",
            Network::Bitcoin,
            &unrelated_script(),
        )
        .unwrap_err();
        assert_eq!(err, ClaimError::InvalidAddress);
    }

    #[test]
    fn rejects_address_valid_for_a_different_network() {
        let err =
            parse_destination(TESTNET_P2PKH, Network::Bitcoin, &unrelated_script()).unwrap_err();
        assert_eq!(err, ClaimError::WrongNetwork);
    }

    #[test]
    fn rejects_unsupported_address_type() {
        let err = parse_destination(UNSUPPORTED_SEGWIT, Network::Bitcoin, &unrelated_script())
            .unwrap_err();
        assert_eq!(err, ClaimError::UnsupportedAddressType);
    }

    #[test]
    fn rejects_the_puzzle_address_itself_as_destination() {
        let forbidden = p2pkh_script_for_hash160([0xCD; 20]);
        let address = bitcoin::Address::p2pkh(
            bitcoin::PubkeyHash::from_byte_array([0xCD; 20]),
            bitcoin::NetworkKind::Main,
        );
        let err =
            parse_destination(&address.to_string(), Network::Bitcoin, &forbidden).unwrap_err();
        assert_eq!(err, ClaimError::DestinationIsPuzzleAddress);
    }

    #[test]
    fn accepts_each_of_the_five_supported_address_types() {
        for address in [P2PKH, P2SH, P2WPKH, P2WSH, P2TR] {
            let result = parse_destination(address, Network::Bitcoin, &unrelated_script());
            assert!(
                result.is_ok(),
                "expected {address} to be accepted, got {result:?}"
            );
        }
    }

    #[test]
    fn trims_surrounding_whitespace_before_parsing() {
        let padded = format!("  {P2PKH}  \n");
        assert!(parse_destination(&padded, Network::Bitcoin, &unrelated_script()).is_ok());
    }
}
