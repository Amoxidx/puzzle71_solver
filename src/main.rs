//! Bitcoin Puzzle #71 Local Energy-Efficient Lottery Solver & Web Control Center.
//!
//! Exclusively targets Bitcoin Puzzle #71.
//! Zero-Telemetry, fully offline, audit-ready for Apple Silicon Mac mini M4.

use puzzle71_solver::bench::run_comprehensive_benchmark;
use puzzle71_solver::crypto::cpu_engine::run_mini_puzzle_test;
use puzzle71_solver::hit_handler::verify_and_save_candidate;
use puzzle71_solver::metal_engine::metal_solver::MetalSolver;
use puzzle71_solver::power::controller::{PowerGovernor, PowerMode};
use puzzle71_solver::puzzle_config::{RANGE_MIN, RANGE_SIZE, TARGET_HASH160};
use puzzle71_solver::search::block_progress::BlockProgress;
use puzzle71_solver::search::checkpoint::{CheckpointState, DEFAULT_CHECKPOINT_FILE};
use puzzle71_solver::search::duplicate_filter::DuplicateFilter;
use puzzle71_solver::search::rng::select_random_block_start;
use puzzle71_solver::ui::terminal::SolverStats;
use puzzle71_solver::web::server::{PublicHitStatus, SharedSolverState, start_web_server};

use std::env;
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread;
use std::time::{Duration, Instant};

fn main() {
    let args: Vec<String> = env::args().collect();

    // Default configuration
    let mut mode = PowerMode::Auto;
    let mut electricity_price = 0.34; // EUR/kWh
    let mut block_size: u128 = 16_777_216; // 2^24 keys per block (~16.7M keys)
    let mut web_host = "127.0.0.1".to_string();
    let mut web_port: u16 = 8080;
    let mut enable_tui = true;

    // Parse CLI options
    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "--bench" | "benchmark" => {
                run_comprehensive_benchmark(electricity_price);
                return;
            }
            "--test-mini" => {
                run_self_test();
                return;
            }
            "--mode" => {
                if i + 1 < args.len() {
                    mode = args[i + 1].parse().unwrap_or_else(|_| {
                        eprintln!(
                            "Invalid mode '{}'. Options: eco, balanced, high, full, auto",
                            args[i + 1]
                        );
                        std::process::exit(1);
                    });
                    i += 1;
                }
            }
            "--host" => {
                if i + 1 < args.len() {
                    web_host = args[i + 1].clone();
                    i += 1;
                }
            }
            "--port" => {
                if i + 1 < args.len() {
                    web_port = args[i + 1].parse().unwrap_or(8080);
                    i += 1;
                }
            }
            "--no-tui" => {
                enable_tui = false;
            }
            "--electricity-price" => {
                if i + 1 < args.len() {
                    electricity_price = args[i + 1].parse().unwrap_or(0.34);
                    i += 1;
                }
            }
            "--block-size" => {
                if i + 1 < args.len() {
                    block_size = args[i + 1].parse().unwrap_or(16_777_216);
                    i += 1;
                }
            }
            "--help" | "-h" => {
                print_help();
                return;
            }
            other => {
                eprintln!("Unknown argument: {}", other);
                print_help();
                std::process::exit(1);
            }
        }
        i += 1;
    }

    let block_count_fits_index = block_size > 0 && RANGE_SIZE / block_size <= u64::MAX as u128;
    if block_size == 0
        || block_size > RANGE_SIZE
        || !RANGE_SIZE.is_multiple_of(block_size)
        || !block_count_fits_index
    {
        eprintln!(
            "Invalid block size {}. It must divide 2^70 exactly and produce at most 2^64-1 blocks.",
            block_size
        );
        std::process::exit(1);
    }

    // Step 1: Execute mandatory CPU cryptographic and 24-bit Mini-Puzzle test
    println!("Executing mandatory cryptographic and 24-bit Mini-Puzzle self-test...");
    run_self_test();

    // Step 2: Set up graceful SIGINT / SIGTERM signal handling
    unsafe {
        libc::signal(libc::SIGINT, handle_sigint as *const () as usize);
        libc::signal(libc::SIGTERM, handle_sigint as *const () as usize);
    }
    SHUTDOWN_SIGNAL.store(false, Ordering::SeqCst);

    // Step 3: Load existing checkpoint if available
    let mut checkpoint =
        CheckpointState::load_from_file(DEFAULT_CHECKPOINT_FILE).unwrap_or_else(|e| {
            eprintln!("CRITICAL: Refusing to ignore invalid checkpoint: {}", e);
            std::process::exit(1);
        });
    checkpoint
        .validate_for_block_size(block_size)
        .unwrap_or_else(|e| {
            eprintln!("CRITICAL: Refusing inconsistent checkpoint: {}", e);
            eprintln!(
                "Preserve the file for audit and start with an explicitly repaired checkpoint."
            );
            std::process::exit(1);
        });

    let mut dup_filter = DuplicateFilter::from_intervals(checkpoint.to_interval_set());
    println!(
        "Loaded checkpoint: {} keys previously tested across {} blocks.",
        checkpoint.total_keys_tested, checkpoint.total_blocks_tested
    );

    // Step 4: Setup shared state & launch Localhost Web Dashboard Server
    let shared_state = SharedSolverState::new();
    *shared_state.mode.lock().unwrap() = mode;
    *shared_state.total_keys_tested.lock().unwrap() = checkpoint.total_keys_tested;
    shared_state
        .total_blocks_tested
        .store(checkpoint.total_blocks_tested, Ordering::SeqCst);
    shared_state
        .checkpoint_saved_timestamp
        .store(checkpoint.last_saved_timestamp, Ordering::SeqCst);

    start_web_server(&web_host, web_port, shared_state.clone()).unwrap_or_else(|e| {
        eprintln!(
            "CRITICAL: Could not start web server on {}:{}: {}",
            web_host, web_port, e
        );
        std::process::exit(1);
    });

    // Step 5: Initialize Metal GPU solver and Power Governor
    let solver = MetalSolver::new().expect("Failed to initialize Metal GPU Solver");
    let mut governor = PowerGovernor::new(mode);
    *shared_state.target_gpu_duty_pct.lock().unwrap() = governor.target_duty_cycle() * 100.0;

    let mut total_keys_session = 0u128;
    let mut active_runtime_session = Duration::ZERO;
    let runtime_before_session = checkpoint.total_runtime_secs;
    let mut last_render_instant = Instant::now();
    let mut last_save_instant = Instant::now();
    let mut pause_checkpoint_saved = false;
    let mut terminal_state = false;

    println!(
        "Starting Bitcoin Puzzle #71 lottery search in [{}] mode...",
        mode.name()
    );

    // Step 6: Main Lottery Search Loop
    'search: while !SHUTDOWN_SIGNAL.load(Ordering::SeqCst) {
        if !shared_state.is_running.load(Ordering::SeqCst) {
            *shared_state.current_keys_per_sec.lock().unwrap() = 0.0;
            if !pause_checkpoint_saved {
                if let Err(error) = persist_checkpoint(
                    &mut checkpoint,
                    runtime_before_session,
                    active_runtime_session,
                    &shared_state,
                ) {
                    set_fatal_error(&shared_state, error);
                    terminal_state = true;
                    break 'search;
                }
                pause_checkpoint_saved = true;
            }
            thread::sleep(Duration::from_millis(200));
            continue;
        }
        pause_checkpoint_saved = false;

        let web_mode = *shared_state.mode.lock().unwrap();
        governor.set_mode(web_mode);

        // Select a random block start aligned to block_size
        let block_start = match select_random_block_start(block_size) {
            Ok(k) => k,
            Err(e) => {
                set_fatal_error(&shared_state, format!("Secure RNG failed: {}", e));
                terminal_state = true;
                break 'search;
            }
        };

        let block_index = ((block_start - RANGE_MIN) / block_size) as u64;

        // Skip if already scanned
        if dup_filter.is_scanned(block_index) {
            continue;
        }

        let mut progress = BlockProgress::new(block_size).expect("validated block size");

        while !progress.is_complete() && !SHUTDOWN_SIGNAL.load(Ordering::SeqCst) {
            if !shared_state.is_running.load(Ordering::SeqCst) {
                *shared_state.current_keys_per_sec.lock().unwrap() = 0.0;
                if !pause_checkpoint_saved {
                    if let Err(error) = persist_checkpoint(
                        &mut checkpoint,
                        runtime_before_session,
                        active_runtime_session,
                        &shared_state,
                    ) {
                        set_fatal_error(&shared_state, error);
                        terminal_state = true;
                        break 'search;
                    }
                    pause_checkpoint_saved = true;
                }
                thread::sleep(Duration::from_millis(100));
                continue;
            }
            pause_checkpoint_saved = false;

            let requested_mode = *shared_state.mode.lock().unwrap();
            governor.set_mode(requested_mode);
            let profile = dispatch_profile(requested_mode);
            let sub_keys = progress.remaining_keys().min(profile.batch_keys());
            let thread_count = sub_keys.div_ceil(profile.steps as u128) as usize;
            let curr_sub_start = block_start + progress.completed_keys();
            let cycle_started = Instant::now();

            let dispatch_result = solver.dispatch_exact(
                curr_sub_start,
                thread_count,
                profile.steps,
                sub_keys as usize,
                &TARGET_HASH160,
            );

            match dispatch_result {
                Ok(outcome) if outcome.found_key.is_some() => {
                    let found_key = outcome.found_key.expect("checked above");
                    // STOP ALL WORKERS IMMEDIATELY AND VERIFY
                    println!(
                        "\n\n=========================================================================================="
                    );
                    println!("  POTENTIAL MATCH DETECTED ON METAL GPU");
                    println!(
                        "  Halting search and initiating 100% independent pure-CPU re-verification..."
                    );
                    println!(
                        "=========================================================================================="
                    );

                    match verify_and_save_candidate(found_key) {
                        Ok(hit) => {
                            shared_state.is_running.store(false, Ordering::SeqCst);
                            *shared_state.hit.lock().unwrap() = Some(PublicHitStatus {
                                bitcoin_address: hit.bitcoin_address.clone(),
                                saved_filename: hit.saved_filename.clone(),
                                timestamp_unix: hit.timestamp_unix,
                            });

                            println!("\n  PUZZLE #71 MATCH VERIFIED AND CONFIRMED!");
                            println!("  Bitcoin Adresse:   {}", hit.bitcoin_address);
                            println!("  Saved locally to:  {} (mode 0600)", hit.saved_filename);
                            println!("  DO NOT UPLOAD OR SHARE THIS KEY!");
                            terminal_state = true;
                            break 'search;
                        }
                        Err(e) => {
                            set_fatal_error(
                                &shared_state,
                                format!("CPU re-verification failed for GPU candidate: {}", e),
                            );
                            terminal_state = true;
                            break 'search;
                        }
                    }
                }
                Ok(outcome) => {
                    progress
                        .record_completed(sub_keys)
                        .expect("exact Metal dispatch cannot overrun block");
                    total_keys_session += sub_keys;

                    let metrics = governor.update();
                    let throttle_sleep = governor.required_idle_duration(outcome.gpu_duration);
                    if throttle_sleep > Duration::ZERO {
                        thread::sleep(throttle_sleep);
                    }

                    let cycle_elapsed = cycle_started.elapsed();
                    active_runtime_session += cycle_elapsed;
                    let current_rate = sub_keys as f64 / cycle_elapsed.as_secs_f64().max(0.001);
                    let avg_rate =
                        total_keys_session as f64 / active_runtime_session.as_secs_f64().max(0.001);

                    *shared_state.current_keys_per_sec.lock().unwrap() = current_rate;
                    *shared_state.avg_keys_per_sec.lock().unwrap() = avg_rate;
                    *shared_state.estimated_package_power_watts.lock().unwrap() =
                        metrics.package_power_watts;
                    *shared_state.estimated_soc_temp_celsius.lock().unwrap() =
                        metrics.soc_temp_celsius;
                    *shared_state.process_cpu_load_pct.lock().unwrap() = metrics.cpu_load_pct;
                    *shared_state.runtime_secs.lock().unwrap() =
                        runtime_before_session + active_runtime_session.as_secs_f64();
                    *shared_state.target_gpu_duty_pct.lock().unwrap() =
                        governor.target_duty_cycle() * 100.0;
                    *shared_state.last_gpu_active_ms.lock().unwrap() =
                        outcome.gpu_duration.as_secs_f64() * 1000.0;
                    *shared_state.last_throttle_sleep_ms.lock().unwrap() =
                        throttle_sleep.as_secs_f64() * 1000.0;
                }
                Err(error) => {
                    set_fatal_error(&shared_state, format!("Metal dispatch failed: {}", error));
                    terminal_state = true;
                    break 'search;
                }
            }

            if last_save_instant.elapsed() >= Duration::from_secs(10) {
                if let Err(error) = persist_checkpoint(
                    &mut checkpoint,
                    runtime_before_session,
                    active_runtime_session,
                    &shared_state,
                ) {
                    set_fatal_error(&shared_state, error);
                    terminal_state = true;
                    break 'search;
                }
                last_save_instant = Instant::now();
            }
        }

        if !progress.is_complete() {
            break 'search;
        }

        // Commit only a completely processed block to durable coverage.
        dup_filter.mark_scanned(block_index);
        checkpoint.scanned_intervals = dup_filter.intervals.intervals.clone();
        checkpoint.total_blocks_tested = dup_filter.intervals.total_blocks_count();
        checkpoint.total_keys_tested = checkpoint.total_blocks_tested as u128 * block_size;
        *shared_state.total_keys_tested.lock().unwrap() = checkpoint.total_keys_tested;
        shared_state
            .total_blocks_tested
            .store(checkpoint.total_blocks_tested, Ordering::SeqCst);

        // Render TUI periodically (every 1 second if enabled)
        if enable_tui && last_render_instant.elapsed() >= Duration::from_secs(1) {
            let avg_rate =
                total_keys_session as f64 / active_runtime_session.as_secs_f64().max(0.001);
            let current_metrics = governor.update();

            let stats = SolverStats {
                mode: governor.mode,
                keys_tested: checkpoint.total_keys_tested,
                blocks_tested: checkpoint.total_blocks_tested,
                elapsed_duration: Duration::from_secs_f64(
                    runtime_before_session + active_runtime_session.as_secs_f64(),
                ),
                current_keys_per_sec: *shared_state.current_keys_per_sec.lock().unwrap(),
                avg_keys_per_sec: avg_rate,
                system_metrics: current_metrics,
                electricity_eur_per_kwh: electricity_price,
            };

            stats.render();
            last_render_instant = Instant::now();
        }

        // Save checkpoint periodically (every 10 seconds)
        if last_save_instant.elapsed() >= Duration::from_secs(10) {
            if let Err(error) = persist_checkpoint(
                &mut checkpoint,
                runtime_before_session,
                active_runtime_session,
                &shared_state,
            ) {
                set_fatal_error(&shared_state, error);
                terminal_state = true;
                break 'search;
            }
            last_save_instant = Instant::now();
        }
    }

    shared_state.is_running.store(false, Ordering::SeqCst);
    *shared_state.current_keys_per_sec.lock().unwrap() = 0.0;
    if let Err(error) = persist_checkpoint(
        &mut checkpoint,
        runtime_before_session,
        active_runtime_session,
        &shared_state,
    ) {
        set_fatal_error(&shared_state, error);
    }

    if terminal_state && !SHUTDOWN_SIGNAL.load(Ordering::SeqCst) {
        println!("Dashboard remains available for the final status. Press CTRL+C to exit.");
        while !SHUTDOWN_SIGNAL.load(Ordering::SeqCst) {
            thread::sleep(Duration::from_millis(250));
        }
    }

    println!("\nShutdown complete. Final checkpoint is synchronized.");
}

#[derive(Clone, Copy)]
struct DispatchProfile {
    threads: usize,
    steps: u32,
}

impl DispatchProfile {
    fn batch_keys(self) -> u128 {
        self.threads as u128 * self.steps as u128
    }
}

fn dispatch_profile(mode: PowerMode) -> DispatchProfile {
    match mode {
        PowerMode::Eco => DispatchProfile {
            threads: 1024,
            steps: 128,
        },
        PowerMode::Balanced | PowerMode::Auto => DispatchProfile {
            threads: 2048,
            steps: 128,
        },
        PowerMode::High => DispatchProfile {
            threads: 4096,
            steps: 128,
        },
        PowerMode::Full => DispatchProfile {
            threads: 4096,
            steps: 256,
        },
    }
}

fn persist_checkpoint(
    checkpoint: &mut CheckpointState,
    runtime_before_session: f64,
    active_runtime_session: Duration,
    shared_state: &SharedSolverState,
) -> Result<(), String> {
    checkpoint.total_runtime_secs = runtime_before_session + active_runtime_session.as_secs_f64();
    checkpoint.save_to_file(DEFAULT_CHECKPOINT_FILE)?;
    shared_state
        .checkpoint_saved_timestamp
        .store(checkpoint.last_saved_timestamp, Ordering::SeqCst);
    Ok(())
}

fn set_fatal_error(shared_state: &SharedSolverState, error: String) {
    eprintln!("CRITICAL: {}", error);
    shared_state.is_running.store(false, Ordering::SeqCst);
    *shared_state.last_error.lock().unwrap() = Some(error);
}

static SHUTDOWN_SIGNAL: AtomicBool = AtomicBool::new(false);

extern "C" fn handle_sigint(_: libc::c_int) {
    SHUTDOWN_SIGNAL.store(true, Ordering::SeqCst);
}

fn run_self_test() {
    let result =
        run_mini_puzzle_test().expect("Mini-puzzle self-test failed! Solver cannot proceed.");
    println!(
        "Mini-puzzle self-test passed: Solved in {:.3}s ({:.1} keys/s). Derived address matched target.",
        result.elapsed_secs, result.keys_per_sec
    );
}

fn print_help() {
    println!("Bitcoin Puzzle #71 Local Lottery Solver & Web Control Center");
    println!("Usage: puzzle71_solver [OPTIONS]");
    println!();
    println!("Options:");
    println!("  --mode <eco|balanced|high|full|auto>   Operating power profile (default: auto)");
    println!("  --host <host>                     Loopback host only (default: 127.0.0.1)");
    println!("  --port <port>                     Local Web Dashboard port (default: 8080)");
    println!("  --no-tui                          Disable terminal ANSI rendering");
    println!("  --bench                           Run comprehensive CPU vs Metal power benchmark");
    println!("  --test-mini                       Run 24-bit Mini-Puzzle self-test verification");
    println!("  --electricity-price <EUR/kWh>     Configure electricity cost (default: 0.34)");
    println!("  --block-size <keys>               Divisor of 2^70 yielding at most 2^64-1 blocks");
    println!("  --help, -h                        Show this help message");
}
