//! Zero-Telemetry Terminal UI and Statistical Analytics.
//!
//! Renders clean, real-time metrics including estimated power efficiency,
//! electricity cost projections, and unique-search keyspace odds.

use crate::power::controller::PowerMode;
use crate::power::monitor::SystemMetrics;
use crate::puzzle_config::{PUZZLE_NUMBER, RANGE_SIZE, TARGET_ADDRESS, TARGET_REWARD_BTC};
use std::io::{Write, stdout};
use std::time::Duration;

#[derive(Debug, Clone)]
pub struct SolverStats {
    pub mode: PowerMode,
    pub keys_tested: u128,
    pub blocks_tested: u64,
    pub elapsed_duration: Duration,
    pub current_keys_per_sec: f64,
    pub avg_keys_per_sec: f64,
    pub system_metrics: SystemMetrics,
    pub electricity_eur_per_kwh: f64,
}

impl SolverStats {
    pub fn render(&self) {
        let total_secs = self.elapsed_duration.as_secs_f64().max(0.001);

        // Energy calculations
        let current_watts = self.system_metrics.package_power_watts.max(0.1);
        let keys_per_joule = self.current_keys_per_sec / (current_watts as f64);
        let keys_per_kwh = keys_per_joule * 3_600_000.0;

        // Electricity Cost calculations
        let kwh_consumed_total = (current_watts as f64 * total_secs) / 3_600_000.0;
        let cost_total_eur = kwh_consumed_total * self.electricity_eur_per_kwh;
        let cost_per_day_eur =
            (current_watts as f64 * 24.0 / 1000.0) * self.electricity_eur_per_kwh;
        let cost_per_month_eur = cost_per_day_eur * 30.416;
        let cost_per_year_eur = cost_per_day_eur * 365.25;

        // Keyspace coverage
        let keyspace_f64 = RANGE_SIZE as f64; // 2^70
        let coverage_fraction = (self.keys_tested as f64) / keyspace_f64;
        let coverage_pct = coverage_fraction * 100.0;

        // Unique non-overlapping search: probability equals searched keyspace fraction.
        let rate = self.avg_keys_per_sec.max(1.0);
        let keys_1h = rate * 3600.0;
        let keys_24h = rate * 86400.0;
        let keys_30d = keys_24h * 30.0;
        let keys_1y = keys_24h * 365.25;

        let prob_1h = (keys_1h / keyspace_f64).min(1.0);
        let prob_24h = (keys_24h / keyspace_f64).min(1.0);
        let prob_30d = (keys_30d / keyspace_f64).min(1.0);
        let prob_1y = (keys_1y / keyspace_f64).min(1.0);

        let one_in_1h = 1.0 / prob_1h.max(1e-30);
        let one_in_24h = 1.0 / prob_24h.max(1e-30);
        let one_in_30d = 1.0 / prob_30d.max(1e-30);
        let one_in_1y = 1.0 / prob_1y.max(1e-30);

        // Format Runtime (hh:mm:ss)
        let hrs = (total_secs as u64) / 3600;
        let mins = ((total_secs as u64) % 3600) / 60;
        let secs = (total_secs as u64) % 60;

        // ANSI Clean Refresh
        print!("\x1B[2J\x1B[H"); // Clear screen & move to top-left

        println!(
            "=========================================================================================="
        );
        println!(
            "  BITCOIN PUZZLE #{} SOLVER [APPLE SILICON M4 METAL + PURE RUST CPU]  ",
            PUZZLE_NUMBER
        );
        println!(
            "=========================================================================================="
        );
        println!("  Target Address:     {}", TARGET_ADDRESS);
        println!(
            "  Reward:             {:.2} BTC (Unsolved)",
            TARGET_REWARD_BTC
        );
        println!(
            "  Search Range:       2^70 .. 2^71 - 1 (0x400000000000000000 .. 0x7FFFFFFFFFFFFFFFFF)"
        );
        println!("  Keyspace Size:      2^70 = 1,180,591,620,717,411,303,424 keys");
        println!(
            "------------------------------------------------------------------------------------------"
        );
        println!(
            "  Operating Mode:     \x1B[1;32m{:?}\x1B[0m | Runtime: {:02}:{:02}:{:02}",
            self.mode, hrs, mins, secs
        );
        println!(
            "  Speed (Current):    \x1B[1;36m{:.2} Mkeys/s\x1B[0m ({} keys/s)",
            self.current_keys_per_sec / 1_000_000.0,
            format_int(self.current_keys_per_sec as u128)
        );
        println!(
            "  Speed (Average):    \x1B[1;36m{:.2} Mkeys/s\x1B[0m ({} keys/s)",
            self.avg_keys_per_sec / 1_000_000.0,
            format_int(self.avg_keys_per_sec as u128)
        );
        println!(
            "  Total Keys Tested:  {:>22} | Blocks: {:>10}",
            format_int(self.keys_tested),
            format_int(self.blocks_tested as u128)
        );
        println!(
            "  Keyspace Scanned:   {:.12}% ({:.4e} fraction)",
            coverage_pct, coverage_fraction
        );
        println!(
            "------------------------------------------------------------------------------------------"
        );
        println!("  ESTIMATED POWER & EFFICIENCY (not hardware sensor readings)");
        println!(
            "  Estimated Package:  \x1B[1;33m{:.1} W\x1B[0m | Estimated Temp: {:.1} °C | Process CPU: {:.1}%",
            current_watts, self.system_metrics.soc_temp_celsius, self.system_metrics.cpu_load_pct
        );
        println!(
            "  Efficiency:         \x1B[1;32m{:.2} Mkeys/Joule\x1B[0m ({:.2} Bkeys/kWh)",
            keys_per_joule / 1_000_000.0,
            keys_per_kwh / 1_000_000_000.0
        );
        println!(
            "------------------------------------------------------------------------------------------"
        );
        println!(
            "  ELECTRICITY COSTS (@ {:.2} EUR/kWh)",
            self.electricity_eur_per_kwh
        );
        println!(
            "  Cost Since Start:   {:.4} EUR ({:.4} kWh)",
            cost_total_eur, kwh_consumed_total
        );
        println!(
            "  Projected Cost:     Day: {:.3} EUR | Month: {:.2} EUR | Year: {:.2} EUR",
            cost_per_day_eur, cost_per_month_eur, cost_per_year_eur
        );
        println!(
            "------------------------------------------------------------------------------------------"
        );
        println!("  UNIQUE-SEARCH HIT CHANCE (fraction of the 2^70 keyspace)");
        println!(
            "  Per 1 Hour:         {:.3e}% (1 in {:.2e})",
            prob_1h * 100.0,
            one_in_1h
        );
        println!(
            "  Per 24 Hours:       {:.3e}% (1 in {:.2e})",
            prob_24h * 100.0,
            one_in_24h
        );
        println!(
            "  Per 30 Days:        {:.3e}% (1 in {:.2e})",
            prob_30d * 100.0,
            one_in_30d
        );
        println!(
            "  Per 1 Year:         {:.3e}% (1 in {:.2e})",
            prob_1y * 100.0,
            one_in_1y
        );
        println!(
            "=========================================================================================="
        );
        println!(
            "  Press CTRL+C to pause cleanly (auto-checkpoints to disk). Offline & Zero-Telemetry."
        );
        println!(
            "=========================================================================================="
        );

        let _ = stdout().flush();
    }
}

fn format_int(mut n: u128) -> String {
    if n == 0 {
        return "0".to_string();
    }
    let mut s = String::new();
    let mut count = 0;
    while n > 0 {
        if count > 0 && count % 3 == 0 {
            s.insert(0, ',');
        }
        s.insert(0, (b'0' + (n % 10) as u8) as char);
        n /= 10;
        count += 1;
    }
    s
}
