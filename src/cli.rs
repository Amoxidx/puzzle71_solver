//! Validate the complete command line before executing any action.

use crate::power::controller::PowerMode;
use crate::puzzle_config::RANGE_SIZE;
use std::path::PathBuf;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CliAction {
    Search,
    Help,
    Benchmark,
    SelfTest,
    TelegramTest,
    PrepareRecheck,
}

#[derive(Debug)]
pub struct CliOptions {
    pub mode: PowerMode,
    pub electricity_price: f64,
    pub block_size: u128,
    pub web_host: String,
    pub web_port: u16,
    pub enable_tui: bool,
    pub action: CliAction,
    pub recheck_source: Option<PathBuf>,
    pub prepare_recheck_from: Option<PathBuf>,
}

impl CliOptions {
    pub fn parse(args: impl IntoIterator<Item = String>) -> Result<Self, String> {
        let mut options = Self {
            mode: PowerMode::Auto,
            electricity_price: 0.34,
            block_size: 1 << 24,
            web_host: "127.0.0.1".into(),
            web_port: 8080,
            enable_tui: true,
            action: CliAction::Search,
            recheck_source: None,
            prepare_recheck_from: None,
        };
        let mut args = args.into_iter().peekable();
        let mut help = false;
        let mut actions = Vec::new();
        while let Some(argument) = args.next() {
            match argument.as_str() {
                "--help" | "-h" => help = true,
                "--bench" | "benchmark" => actions.push(CliAction::Benchmark),
                "--test-mini" => actions.push(CliAction::SelfTest),
                "--telegram-test" => actions.push(CliAction::TelegramTest),
                "--no-tui" => options.enable_tui = false,
                "--recheck-source" => {
                    options.recheck_source = Some(value(&argument, &mut args)?.into());
                }
                "--prepare-recheck-from" => {
                    options.prepare_recheck_from = Some(value(&argument, &mut args)?.into());
                    actions.push(CliAction::PrepareRecheck);
                }
                "--mode" => {
                    let value = value(&argument, &mut args)?;
                    options.mode = value.parse().map_err(|_| {
                        "Invalid --mode; use eco, balanced, high, full or auto".to_string()
                    })?;
                }
                "--host" => options.web_host = value(&argument, &mut args)?,
                "--port" => {
                    options.web_port = value(&argument, &mut args)?.parse().map_err(|_| {
                        "Invalid --port; use an integer from 1 to 65535".to_string()
                    })?;
                }
                "--electricity-price" => {
                    options.electricity_price =
                        value(&argument, &mut args)?.parse().map_err(|_| {
                            "Invalid --electricity-price; use a finite non-negative number"
                                .to_string()
                        })?;
                }
                "--block-size" => {
                    options.block_size = value(&argument, &mut args)?.parse().map_err(|_| {
                        "Invalid --block-size; use a positive u128 integer".to_string()
                    })?;
                }
                _ => return Err(format!("Unknown argument: {argument}")),
            }
        }
        if options.web_host != "127.0.0.1" {
            return Err("Invalid --host; use 127.0.0.1".into());
        }
        if options.web_port == 0 {
            return Err("Invalid --port; use an integer from 1 to 65535".into());
        }
        if !options.electricity_price.is_finite() || options.electricity_price < 0.0 {
            return Err("Invalid --electricity-price; use a finite non-negative number".into());
        }
        if options.block_size == 0
            || options.block_size > RANGE_SIZE
            || !RANGE_SIZE.is_multiple_of(options.block_size)
            || RANGE_SIZE / options.block_size > u64::MAX as u128
        {
            return Err("Invalid --block-size; it must divide 2^70 exactly and produce at most 2^64-1 blocks".into());
        }
        if options.prepare_recheck_from.is_some() && options.recheck_source.is_none() {
            return Err("--prepare-recheck-from requires --recheck-source".into());
        }
        if help {
            options.action = CliAction::Help;
        } else if let Some(&action) = actions.first() {
            if actions.iter().any(|&other| other != action) {
                return Err(
                    "Choose only one action: --bench, --test-mini, --telegram-test or --prepare-recheck-from".into(),
                );
            }
            options.action = action;
        }
        if options.recheck_source.is_some()
            && !matches!(
                options.action,
                CliAction::Search | CliAction::PrepareRecheck | CliAction::Help
            )
        {
            return Err("--recheck-source applies only to search or --prepare-recheck-from".into());
        }
        Ok(options)
    }
}

fn value(
    option: &str,
    args: &mut std::iter::Peekable<impl Iterator<Item = String>>,
) -> Result<String, String> {
    match args.peek() {
        Some(next) if !next.starts_with("--") && next != "-h" => Ok(args.next().unwrap()),
        _ => Err(format!("Missing value for {option}")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(args: &[&str]) -> Result<CliOptions, String> {
        CliOptions::parse(args.iter().map(|value| value.to_string()))
    }

    #[test]
    fn values_after_an_action_are_applied_before_it_runs() {
        let options = parse(&["--bench", "--electricity-price", "0.51", "--mode", "eco"]).unwrap();
        assert_eq!(options.action, CliAction::Benchmark);
        assert_eq!(options.electricity_price, 0.51);
        assert_eq!(options.mode, PowerMode::Eco);
    }

    #[test]
    fn help_is_selected_over_outbound_or_compute_actions() {
        for action in ["--telegram-test", "--bench", "--test-mini"] {
            assert_eq!(parse(&[action, "--help"]).unwrap().action, CliAction::Help);
        }
    }

    #[test]
    fn missing_values_do_not_consume_another_option() {
        for option in [
            "--port",
            "--mode",
            "--host",
            "--electricity-price",
            "--block-size",
        ] {
            let error = parse(&[option, "--help"]).unwrap_err();
            assert!(error.contains("Missing value"));
        }
    }

    #[test]
    fn documented_block_index_boundary_is_validated() {
        assert!(parse(&["--block-size", "64"]).is_err());
        assert_eq!(parse(&["--block-size", "128"]).unwrap().block_size, 128);
        assert_eq!(
            parse(&["--block-size", &RANGE_SIZE.to_string()])
                .unwrap()
                .block_size,
            RANGE_SIZE
        );
        assert!(parse(&["--block-size", "3"]).is_err());
    }

    #[test]
    fn conflicting_actions_are_rejected_without_running_them() {
        assert!(parse(&["--bench", "--telegram-test"]).is_err());
    }

    #[test]
    fn recheck_preparation_requires_source_and_excludes_other_actions() {
        assert!(parse(&["--prepare-recheck-from", "copy.json"]).is_err());
        assert!(parse(&["--recheck-source", "--help"]).is_err());
        assert!(parse(&["--recheck-source", "old.json", "--bench"]).is_err());
        assert!(
            parse(&[
                "--recheck-source",
                "old.json",
                "--prepare-recheck-from",
                "copy.json",
                "--test-mini"
            ])
            .is_err()
        );
        let options = parse(&[
            "--recheck-source",
            "old.json",
            "--prepare-recheck-from",
            "copy.json",
        ])
        .unwrap();
        assert_eq!(options.action, CliAction::PrepareRecheck);
        assert_eq!(options.recheck_source.unwrap(), PathBuf::from("old.json"));
        assert_eq!(
            options.prepare_recheck_from.unwrap(),
            PathBuf::from("copy.json")
        );
        assert_eq!(
            parse(&["--recheck-source", "old.json"]).unwrap().action,
            CliAction::Search
        );
    }
}
