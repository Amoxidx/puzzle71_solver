//! The real binary must reject bad configuration before starting work, including with help.

use std::process::Command;

fn rejects_before_work(args: &[&str], option: &str) {
    let output = Command::new(env!("CARGO_BIN_EXE_puzzle71_solver"))
        .args(args)
        .output()
        .expect("run CLI");
    assert!(
        !output.status.success(),
        "invalid {option} was silently accepted"
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains(option),
        "error must identify the invalid option"
    );
    assert!(!String::from_utf8_lossy(&output.stdout).contains("Executing mandatory"));
}

macro_rules! bad_cli {
    ($name:ident, $option:literal, [$($argument:literal),+]) => {
        #[test]
        fn $name() {
            rejects_before_work(&[$($argument),+], $option);
        }
    };
}

bad_cli!(
    rejects_non_numeric_block_size,
    "--block-size",
    ["--block-size", "not-a-number", "--help"]
);
bad_cli!(
    rejects_overflowing_block_size,
    "--block-size",
    [
        "--block-size",
        "340282366920938463463374607431768211456",
        "--help"
    ]
);
bad_cli!(
    rejects_zero_block_size,
    "--block-size",
    ["--block-size", "0", "--help"]
);
bad_cli!(
    rejects_non_numeric_port,
    "--port",
    ["--port", "not-a-port", "--help"]
);
bad_cli!(rejects_zero_port, "--port", ["--port", "0", "--help"]);
bad_cli!(
    rejects_bad_electricity_price,
    "--electricity-price",
    ["--electricity-price", "invalid", "--help"]
);
bad_cli!(
    rejects_nan_electricity_price,
    "--electricity-price",
    ["--electricity-price", "NaN", "--help"]
);
bad_cli!(
    rejects_negative_electricity_price,
    "--electricity-price",
    ["--electricity-price", "-1", "--help"]
);
bad_cli!(
    rejects_missing_port_after_help,
    "--port",
    ["--help", "--port"]
);
bad_cli!(
    rejects_missing_block_size_after_help,
    "--block-size",
    ["--help", "--block-size"]
);
bad_cli!(
    rejects_missing_mode_after_help,
    "--mode",
    ["--help", "--mode"]
);
bad_cli!(
    rejects_non_loopback_host_even_with_help,
    "--host",
    ["--host", "localhost", "--help"]
);

#[test]
fn accepts_valid_explicit_configuration_with_help_without_work() {
    let output = Command::new(env!("CARGO_BIN_EXE_puzzle71_solver"))
        .args([
            "--mode",
            "balanced",
            "--port",
            "18080",
            "--electricity-price",
            "0",
            "--block-size",
            "16777216",
            "--help",
        ])
        .output()
        .unwrap();
    assert!(output.status.success());
    assert!(output.stderr.is_empty());
    assert!(!String::from_utf8_lossy(&output.stdout).contains("Executing mandatory"));
}
