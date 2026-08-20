//! Comprehensive Benchmark Suite for CPU vs Metal GPU and Efficiency Optimization.

use crate::crypto::cpu_engine::cpu_incremental_scan;
use crate::metal_engine::metal_solver::MetalSolver;
use crate::power::controller::{PowerGovernor, PowerMode};
use crate::puzzle_config::RANGE_MIN;
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

pub fn run_comprehensive_benchmark(electricity_price: f64) {
    println!(
        "=========================================================================================="
    );
    println!("  RUNNING COMPREHENSIVE M4 SILICON BENCHMARK (CPU VS METAL GPU)  ");
    println!(
        "=========================================================================================="
    );
    println!("  Benchmarking across multiple compute configurations and power profiles...\n");

    let mut results: Vec<BenchRow> = Vec::new();
    let dummy_target = [0xffu8; 20]; // Dummy target to scan full batch

    // 1. CPU Benchmark (Pure Rust CPU Reference)
    println!("-> Benchmarking Pure Rust CPU Reference Engine (100,000 keys)...");
    let mut cpu_gov = PowerGovernor::new(PowerMode::Balanced);
    let cpu_start = Instant::now();
    let cpu_keys = 100_000u128;
    let _ = cpu_incremental_scan(RANGE_MIN, RANGE_MIN + cpu_keys, &dummy_target);
    let cpu_elapsed = cpu_start.elapsed().as_secs_f64();
    let cpu_metrics = cpu_gov.update();
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

    // 2. Metal GPU Benchmarks across Power Modes (ECO, BALANCED, FULL, AUTO)
    let solver = MetalSolver::new().expect("Failed to initialize Metal GPU Solver");

    let modes = [
        (PowerMode::Eco, 8192, 128),
        (PowerMode::Balanced, 16384, 256),
        (PowerMode::Auto, 32768, 256),
        (PowerMode::Full, 65536, 512),
    ];

    for &(mode, threads, steps) in &modes {
        println!(
            "-> Benchmarking Metal GPU [{}] (Threads: {}, Steps: {})...",
            mode.name(),
            threads,
            steps
        );
        let mut gov = PowerGovernor::new(mode);
        let bench_duration = Duration::from_secs(3);
        let start_time = Instant::now();
        let mut total_keys = 0u128;

        let batch_keys = (threads * steps) as u128;
        let mut curr_key = RANGE_MIN;

        while start_time.elapsed() < bench_duration {
            let dispatch_started = Instant::now();
            let _ = solver.dispatch_block(curr_key, threads, steps as u32, &dummy_target);
            let dispatch_duration = dispatch_started.elapsed();
            total_keys += batch_keys;
            curr_key += batch_keys;
            gov.update();
            let idle_duration = gov.required_idle_duration(dispatch_duration);
            if idle_duration > Duration::ZERO {
                thread::sleep(idle_duration);
            }
        }

        let elapsed = start_time.elapsed().as_secs_f64();
        let metrics = gov.update();
        let rate = (total_keys as f64) / elapsed.max(0.001);
        let watts = metrics.package_power_watts.max(0.1);
        let kpj = rate / (watts as f64);
        let monthly = (watts as f64 * 24.0 * 30.416 / 1000.0) * electricity_price;

        results.push(BenchRow {
            engine_name: format!("Apple Metal GPU ({})", threads),
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
    println!("  FINAL BENCHMARK RESULTS TABLE (Mac mini M4 Target System)");
    println!(
        "=========================================================================================="
    );
    println!(
        "| {:<24} | {:<9} | {:<7} | {:<12} | {:<12} | {:<6} | {:<10} |",
        "Engine", "Mode", "Power", "Keys/s", "Keys/Joule", "Temp", "EUR/Month"
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
        "  [*] BEST PERFORMANCE: {} [{}] ({:.2} Mkeys/s @ {:.1} W)",
        results[best_perf_idx].engine_name,
        results[best_perf_idx].mode_name,
        results[best_perf_idx].keys_per_sec / 1_000_000.0,
        results[best_perf_idx].power_watts
    );
    println!(
        "  [*] BEST EFFICIENCY:  {} [{}] ({:.2} Mkeys/Joule @ {:.1} W)",
        results[best_eff_idx].engine_name,
        results[best_eff_idx].mode_name,
        results[best_eff_idx].keys_per_joule / 1_000_000.0,
        results[best_eff_idx].power_watts
    );
    println!(
        "==========================================================================================\n"
    );
}
