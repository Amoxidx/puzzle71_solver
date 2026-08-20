use puzzle71_solver::crypto::cpu_engine::run_mini_puzzle_test;

#[test]
fn test_24bit_mini_puzzle_end_to_end() {
    let res = run_mini_puzzle_test().expect("Mini-puzzle test must succeed");
    assert!(res.verified, "Derived address must match test target");
    assert_eq!(
        res.found_key, 0x82A7F3,
        "Found private key must match secret test key"
    );
    println!(
        "Mini-puzzle solved in {:.3}s ({:.1} keys/s, {} keys scanned)",
        res.elapsed_secs, res.keys_per_sec, res.keys_scanned
    );
}
