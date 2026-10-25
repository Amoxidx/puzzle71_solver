//! Comprehensive Benchmark Suite for CPU vs Metal GPU and Efficiency Optimization.

use crate::crypto::cpu_engine::cpu_incremental_scan;
use crate::metal_engine::metal_solver::{DispatchOutcome, MetalSolver};
use crate::power::controller::PowerGovernor;
use crate::power::monitor::PowerMonitor;
use crate::puzzle_config::RANGE_MIN;
use crate::search::profile::{ALL_POWER_MODES, DispatchProfile, dispatch_profile};
use std::thread;
use std::time::{Duration, Instant};

#[derive(Debug, Clone)]
pub struct BenchRow {
    pub engine_name: String,
    pub mode_name: String,
    pub power_watts: f32,
    pub keys_per_sec: f64,
    pub keys_per_joule: f64,
    pub temp_celsius: f32,
    pub monthly_cost_eur: f64,
}

pub fn run_comprehensive_benchmark(electricity_price: f64) -> Result<(), String> {
    println!(
        "=========================================================================================="
    );
    println!("  RUNNING APPLE SILICON BENCHMARK (CPU VS METAL GPU)  ");
    println!(
        "=========================================================================================="
    );
    println!(
        "  Production profiles; power, temperature, efficiency and cost use model estimates.\n"
    );

    let mut results: Vec<BenchRow> = Vec::new();
    let dummy_target = [0xffu8; 20]; // Dummy target to scan full batch

    // 1. CPU Benchmark (Pure Rust CPU Reference)
    println!("-> Benchmarking Pure Rust CPU Reference Engine (100,000 keys)...");
    let mut cpu_monitor = PowerMonitor::new();
    let cpu_start = Instant::now();
    let cpu_keys = 100_000u128;
    if cpu_incremental_scan(RANGE_MIN, RANGE_MIN + cpu_keys - 1, &dummy_target).is_some() {
        return Err(
            "CPU benchmark stopped at an unexpected target; incomplete work is not counted".into(),
        );
    }
    let cpu_elapsed = cpu_start.elapsed().as_secs_f64();
    let cpu_metrics = cpu_monitor.sample(0.0);
    let cpu_rate = (cpu_keys as f64) / cpu_elapsed.max(0.001);
    let cpu_watts = cpu_metrics.package_power_watts.max(0.1);
    let cpu_kpj = cpu_rate / (cpu_watts as f64);
    let cpu_monthly = (cpu_watts as f64 * 24.0 * 30.416 / 1000.0) * electricity_price;

    results.push(BenchRow {
        engine_name: "Pure Rust CPU (1 Thread)".to_string(),
        mode_name: "STANDARD".to_string(),
        power_watts: cpu_watts,
        keys_per_sec: cpu_rate,
        keys_per_joule: cpu_kpj,
        temp_celsius: cpu_metrics.soc_temp_celsius,
        monthly_cost_eur: cpu_monthly,
    });

    // Benchmark the exact dispatch sizes used by the main search, including HIGH.
    let solver = MetalSolver::new()?;
    for mode in ALL_POWER_MODES {
        let profile = dispatch_profile(mode);
        println!(
            "-> Benchmarking Metal GPU [{}] (Threads: {}, Steps: {})...",
            mode.name(),
            profile.threads,
            profile.steps
        );
        let mut gov = PowerGovernor::new(mode);
        let bench_duration = Duration::from_secs(3);
        let start_time = Instant::now();
        let mut progress = BenchmarkProgress::new(RANGE_MIN);

        while start_time.elapsed() < bench_duration {
            let gpu_duration = progress.dispatch_next(profile, |start, profile| {
                solver.dispatch_exact(
                    start,
                    profile.threads,
                    profile.steps,
                    profile.batch_keys() as usize,
                    &dummy_target,
                )
            })?;
            gov.update();
            let idle_duration = gov.required_idle_duration(gpu_duration);
            if idle_duration > Duration::ZERO {
                thread::sleep(idle_duration);
            }
        }

        let elapsed = start_time.elapsed().as_secs_f64();
        let metrics = gov.update();
        let rate = (progress.total_keys as f64) / elapsed.max(0.001);
        let watts = metrics.package_power_watts.max(0.1);
        let kpj = rate / (watts as f64);
        let monthly = (watts as f64 * 24.0 * 30.416 / 1000.0) * electricity_price;

        results.push(BenchRow {
            engine_name: format!("Apple Metal GPU ({})", profile.threads),
            mode_name: mode.name().to_string(),
            power_watts: watts,
            keys_per_sec: rate,
            keys_per_joule: kpj,
            temp_celsius: metrics.soc_temp_celsius,
            monthly_cost_eur: monthly,
        });
    }

    // Print Results Table
    println!(
        "\n=========================================================================================="
    );
    println!("  FINAL BENCHMARK RESULTS TABLE (CURRENT HOST)");
    println!(
        "=========================================================================================="
    );
    println!(
        "| {:<24} | {:<9} | {:<7} | {:<12} | {:<12} | {:<6} | {:<10} |",
        "Engine", "Mode", "Est. W", "Keys/s", "Est. Keys/J", "Est. C", "Est. EUR/mo"
    );
    println!(
        "|--------------------------|-----------|---------|--------------|--------------|--------|------------|"
    );

    let mut best_perf_idx = 0;
    let mut best_eff_idx = 0;

    for (idx, r) in results.iter().enumerate() {
        println!(
            "| {:<24} | {:<9} | {:>5.1} W | {:>10.2} M | {:>10.2} M | {:>4.1}C | {:>8.2} € |",
            r.engine_name,
            r.mode_name,
            r.power_watts,
            r.keys_per_sec / 1_000_000.0,
            r.keys_per_joule / 1_000_000.0,
            r.temp_celsius,
            r.monthly_cost_eur
        );

        if r.keys_per_sec > results[best_perf_idx].keys_per_sec {
            best_perf_idx = idx;
        }
        if r.keys_per_joule > results[best_eff_idx].keys_per_joule {
            best_eff_idx = idx;
        }
    }
    println!(
        "=========================================================================================="
    );
    println!(
        "  [*] BEST PERFORMANCE: {} [{}] ({:.2} Mkeys/s @ est. {:.1} W)",
        results[best_perf_idx].engine_name,
        results[best_perf_idx].mode_name,
        results[best_perf_idx].keys_per_sec / 1_000_000.0,
        results[best_perf_idx].power_watts
    );
    println!(
        "  [*] BEST ESTIMATED EFFICIENCY: {} [{}] ({:.2} Mkeys/Joule @ est. {:.1} W)",
        results[best_eff_idx].engine_name,
        results[best_eff_idx].mode_name,
        results[best_eff_idx].keys_per_joule / 1_000_000.0,
        results[best_eff_idx].power_watts
    );
    println!(
        "==========================================================================================\n"
    );
    Ok(())
}

struct BenchmarkProgress {
    total_keys: u128,
    next_key: u128,
}

impl BenchmarkProgress {
    fn new(start: u128) -> Self {
        Self {
            total_keys: 0,
            next_key: start,
        }
    }

    fn dispatch_next<F>(
        &mut self,
        profile: DispatchProfile,
        dispatch: F,
    ) -> Result<Duration, String>
    where
        F: FnOnce(u128, DispatchProfile) -> Result<DispatchOutcome, String>,
    {
        let outcome = dispatch(self.next_key, profile)?;
        if outcome.found_key.is_some() {
            return Err(
                "GPU benchmark stopped at an unexpected target; incomplete work is not counted"
                    .into(),
            );
        }
        self.total_keys += profile.batch_keys();
        self.next_key += profile.batch_keys();
        Ok(outcome.gpu_duration)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::power::controller::PowerMode;

    #[test]
    fn failed_dispatch_does_not_count_or_advance_the_search_range() {
        let mut progress = BenchmarkProgress::new(RANGE_MIN);
        let profile = dispatch_profile(PowerMode::Balanced);
        let error = progress
            .dispatch_next(profile, |start, actual_profile| {
                assert_eq!(start, RANGE_MIN);
                assert_eq!(actual_profile, dispatch_profile(PowerMode::Balanced));
                Err("injected GPU failure".into())
            })
            .unwrap_err();
        assert_eq!(error, "injected GPU failure");
        assert_eq!(progress.total_keys, 0);
        assert_eq!(progress.next_key, RANGE_MIN);
        progress
            .dispatch_next(profile, |start, _| {
                assert_eq!(start, RANGE_MIN);
                Ok(DispatchOutcome {
                    found_key: None,
                    gpu_duration: Duration::from_millis(1),
                })
            })
            .unwrap();
        assert_eq!(progress.total_keys, profile.batch_keys());
        assert_eq!(progress.next_key, RANGE_MIN + profile.batch_keys());
    }

    #[test]
    fn early_target_does_not_count_a_partially_completed_dispatch() {
        let mut progress = BenchmarkProgress::new(RANGE_MIN);
        let result = progress.dispatch_next(dispatch_profile(PowerMode::Eco), |_, _| {
            Ok(DispatchOutcome {
                found_key: Some(RANGE_MIN),
                gpu_duration: Duration::ZERO,
            })
        });
        assert!(result.is_err());
        assert_eq!(progress.total_keys, 0);
        assert_eq!(progress.next_key, RANGE_MIN);
    }
}
