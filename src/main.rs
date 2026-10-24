//! Bitcoin Puzzle #71 Local Energy-Efficient Lottery Solver & Web Control Center.
//!
//! Exclusively targets Bitcoin Puzzle #71.
//! Local search for Apple Silicon; hit notifications and claims use network services.

use puzzle71_solver::bench::run_comprehensive_benchmark;
use puzzle71_solver::claim::{
    ClaimService, CurlTransport, EsploraUtxoSource, FoundKeyFile, SlipstreamSubmitter,
    TelegramNotifier, find_verified_found_key,
};
use puzzle71_solver::crypto::cpu_engine::run_mini_puzzle_test;
use puzzle71_solver::hit_handler::{
    FOUND_KEY_FILENAME, VerifiedHit, recover_staged_hit, verify_candidate,
};
use puzzle71_solver::metal_engine::metal_solver::MetalSolver;
use puzzle71_solver::power::controller::{PowerGovernor, PowerMode};
use puzzle71_solver::puzzle_config::{
    RANGE_MAX, RANGE_MIN, RANGE_SIZE, TARGET_ADDRESS, TARGET_HASH160,
};
use puzzle71_solver::search::block_progress::BlockProgress;
use puzzle71_solver::search::checkpoint::DEFAULT_CHECKPOINT_FILE;
use puzzle71_solver::search::profile::dispatch_profile;
use puzzle71_solver::search::rng::select_random_block_start;
use puzzle71_solver::search::store::{CheckpointLock, CheckpointStore};
use puzzle71_solver::ui::terminal::SolverStats;
use puzzle71_solver::web::server::{PublicHitStatus, SharedSolverState, start_web_server};

use std::env;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread;
use std::time::{Duration, Instant, UNIX_EPOCH};

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
                if let Err(error) = run_comprehensive_benchmark(electricity_price) {
                    eprintln!("Benchmark failed: {error}");
                    std::process::exit(1);
                }
                return;
            }
            "--test-mini" => {
                run_self_test();
                return;
            }
            "--telegram-test" => {
                let notifier = TelegramNotifier::new(CurlTransport, telegram_config_path());
                match notifier.send_test_alert() {
                    Ok(()) => {
                        println!("Telegram-Test gesendet");
                        return;
                    }
                    Err(e) => {
                        eprintln!("Telegram-Test fehlgeschlagen: {e}");
                        std::process::exit(1);
                    }
                }
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

    // Protect search progress and recovered claims before either path can write.
    let checkpoint_lock =
        CheckpointLock::acquire(DEFAULT_CHECKPOINT_FILE).unwrap_or_else(|error| {
            eprintln!("CRITICAL: {error}");
            std::process::exit(1);
        });

    let found_key_scan =
        find_verified_found_key(Path::new("."), TARGET_HASH160, RANGE_MIN..=RANGE_MAX);
    if let Some(found_path) = found_key_scan.found {
        resume_from_found_key(&web_host, web_port, found_path);
        return;
    }
    if !found_key_scan.unloadable.is_empty() {
        let details = found_key_scan
            .unloadable
            .iter()
            .map(|(name, reason)| format!("{name}: {reason:?}"))
            .collect::<Vec<_>>()
            .join(", ");
        eprintln!("WARNING: FOUND_KEY file present but not loadable ({details})");
    }
    match recover_staged_hit(Path::new(".")) {
        Ok(Some(hit)) => {
            resume_from_staged_hit(&web_host, web_port, hit);
            return;
        }
        Ok(None) => {}
        Err(error) => {
            eprintln!("Cannot inspect recoverable hit files: {error}");
            std::process::exit(1);
        }
    }

    // Step 3: Load existing checkpoint if available
    let mut checkpoint = CheckpointStore::open(checkpoint_lock, block_size).unwrap_or_else(|e| {
        eprintln!("CRITICAL: Refusing to ignore invalid checkpoint: {}", e);
        std::process::exit(1);
    });
    println!(
        "Loaded checkpoint: {} keys previously tested across {} blocks.",
        checkpoint.total_keys_tested(),
        checkpoint.total_blocks_tested()
    );

    // Step 4: Setup shared state & launch Localhost Web Dashboard Server
    let shared_state = SharedSolverState::new();
    *shared_state.mode.lock().unwrap() = mode;
    *shared_state.total_keys_tested.lock().unwrap() = checkpoint.total_keys_tested();
    shared_state
        .total_blocks_tested
        .store(checkpoint.total_blocks_tested(), Ordering::SeqCst);
    shared_state
        .checkpoint_saved_timestamp
        .store(checkpoint.last_saved_timestamp(), Ordering::SeqCst);

    start_web_server(&web_host, web_port, shared_state.clone()).unwrap_or_else(|e| {
        eprintln!(
            "CRITICAL: Could not start web server on {}:{}: {}",
            web_host, web_port, e
        );
        std::process::exit(1);
    });

    // Step 5: Initialize Metal GPU solver and Power Governor
    let solver = MetalSolver::new().expect("Failed to initialize Metal GPU Solver");
    solver
        .self_test()
        .expect("Independent GPU self-test failed; refusing to search");
    let mut governor = PowerGovernor::new(mode);
    *shared_state.target_gpu_duty_pct.lock().unwrap() = governor.target_duty_cycle() * 100.0;

    let mut total_keys_session = 0u128;
    let mut active_runtime_session = Duration::ZERO;
    let runtime_before_session = checkpoint.total_runtime_secs();
    let mut last_render_instant = Instant::now();
    let mut last_save_instant = Instant::now();
    let mut pause_checkpoint_saved = false;
    let mut terminal_state = false;
    let mut pending_hit: Option<VerifiedHit> = None;

    println!(
        "Starting Bitcoin Puzzle #71 lottery search in [{}] mode...",
        mode.name()
    );

    // Step 6: Main Lottery Search Loop
    'search: while !SHUTDOWN_SIGNAL.load(Ordering::SeqCst) {
        if checkpoint.is_complete() {
            println!("Every block in the configured keyspace has completed.");
            break 'search;
        }
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
        if checkpoint.is_scanned(block_index) {
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

                    match verify_candidate(found_key) {
                        Ok(hit) => {
                            shared_state.is_running.store(false, Ordering::SeqCst);
                            *shared_state.hit.lock().unwrap() = Some(PublicHitStatus {
                                bitcoin_address: hit.bitcoin_address().to_string(),
                                saved_filename: String::new(),
                                timestamp_unix: hit.timestamp_unix(),
                                storage_pending: true,
                            });

                            println!("\n  PUZZLE #71 MATCH VERIFIED AND CONFIRMED!");
                            println!("  Bitcoin Adresse:   {}", hit.bitcoin_address());
                            println!(
                                "  Saving the verified hit locally with owner-only permissions..."
                            );
                            println!("  DO NOT UPLOAD OR SHARE THIS KEY!");
                            pending_hit = Some(hit);
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
                    let throttle_started = Instant::now();
                    if throttle_sleep > Duration::ZERO {
                        thread::sleep(throttle_sleep);
                    }
                    let actual_throttle_sleep = throttle_started.elapsed();

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
                        actual_throttle_sleep.as_secs_f64() * 1000.0;
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
        if let Err(error) = checkpoint.complete_block(
            block_index,
            runtime_before_session + active_runtime_session.as_secs_f64(),
        ) {
            set_fatal_error(&shared_state, error);
            terminal_state = true;
            break 'search;
        }
        *shared_state.total_keys_tested.lock().unwrap() = checkpoint.total_keys_tested();
        shared_state
            .total_blocks_tested
            .store(checkpoint.total_blocks_tested(), Ordering::SeqCst);
        shared_state
            .checkpoint_saved_timestamp
            .store(checkpoint.last_saved_timestamp(), Ordering::SeqCst);

        // Render TUI periodically (every 1 second if enabled)
        if enable_tui && last_render_instant.elapsed() >= Duration::from_secs(1) {
            let avg_rate =
                total_keys_session as f64 / active_runtime_session.as_secs_f64().max(0.001);
            let current_metrics = governor.update();

            let stats = SolverStats {
                mode: governor.mode,
                keys_tested: checkpoint.total_keys_tested(),
                blocks_tested: checkpoint.total_blocks_tested(),
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
    let final_checkpoint_saved = match persist_checkpoint(
        &mut checkpoint,
        runtime_before_session,
        active_runtime_session,
        &shared_state,
    ) {
        Ok(()) => true,
        Err(error) => {
            set_fatal_error(&shared_state, error);
            false
        }
    };

    if let Some(hit) = pending_hit {
        let saved_path = wait_for_hit_persistence(hit, &shared_state);
        if !SHUTDOWN_SIGNAL.load(Ordering::SeqCst) {
            init_claim_service(&shared_state, saved_path);
        }
    }

    if terminal_state && !SHUTDOWN_SIGNAL.load(Ordering::SeqCst) {
        println!("Dashboard remains available for the final status. Press CTRL+C to exit.");
        while !SHUTDOWN_SIGNAL.load(Ordering::SeqCst) {
            thread::sleep(Duration::from_millis(250));
        }
    }

    if final_checkpoint_saved {
        println!("\nShutdown complete. Final checkpoint is synchronized.");
    } else {
        eprintln!(
            "\nShutdown complete with a checkpoint error; preserve the snapshot and journal for recovery."
        );
    }
}

fn resume_from_found_key(web_host: &str, web_port: u16, found_path: PathBuf) {
    let shared_state = SharedSolverState::new();
    shared_state.is_running.store(false, Ordering::SeqCst);
    let timestamp_unix = std::fs::metadata(&found_path)
        .and_then(|meta| meta.modified())
        .ok()
        .and_then(|mtime| mtime.duration_since(UNIX_EPOCH).ok())
        .map(|duration| duration.as_secs())
        .unwrap_or(0);
    let saved_filename = found_path
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or("FOUND_KEY.txt")
        .to_string();
    *shared_state.hit.lock().unwrap() = Some(PublicHitStatus {
        bitcoin_address: TARGET_ADDRESS.to_string(),
        saved_filename,
        timestamp_unix,
        storage_pending: false,
    });
    start_web_server(web_host, web_port, shared_state.clone()).unwrap_or_else(|e| {
        eprintln!(
            "CRITICAL: Could not start web server on {}:{}: {}",
            web_host, web_port, e
        );
        std::process::exit(1);
    });
    init_claim_service(&shared_state, found_path);
    println!("Dashboard remains available for the recovered claim. Press CTRL+C to exit.");
    while !SHUTDOWN_SIGNAL.load(Ordering::SeqCst) {
        thread::sleep(Duration::from_millis(250));
    }
    println!("\nShutdown complete.");
}

/// A graceful shutdown waits for the only verified candidate to become durable.
/// Forced process termination or permanently unavailable storage cannot be made lossless.
fn wait_for_hit_persistence(mut hit: VerifiedHit, shared_state: &SharedSolverState) -> PathBuf {
    let mut last_reported_error = None;
    loop {
        match hit.persist(Path::new(FOUND_KEY_FILENAME)) {
            Ok(path) => {
                let filename = path
                    .file_name()
                    .and_then(|name| name.to_str())
                    .unwrap_or(FOUND_KEY_FILENAME)
                    .to_string();
                *shared_state.hit.lock().unwrap() = Some(PublicHitStatus {
                    bitcoin_address: hit.bitcoin_address().to_string(),
                    saved_filename: filename.clone(),
                    timestamp_unix: hit.timestamp_unix(),
                    storage_pending: false,
                });
                *shared_state.last_error.lock().unwrap() = None;
                println!("Verified hit saved locally to {filename} (mode 0600).");
                return path;
            }
            Err(error) => {
                if last_reported_error.as_ref() != Some(&error) {
                    eprintln!("Verified hit retained; secure storage will retry: {error}");
                    last_reported_error = Some(error.clone());
                }
                *shared_state.last_error.lock().unwrap() = Some(error);
                // Do not discard the only confirmed key on SIGTERM/SIGINT while storage fails.
                thread::sleep(Duration::from_secs(2));
            }
        }
    }
}

fn resume_from_staged_hit(web_host: &str, web_port: u16, hit: VerifiedHit) {
    let shared_state = SharedSolverState::new();
    shared_state.is_running.store(false, Ordering::SeqCst);
    *shared_state.hit.lock().unwrap() = Some(PublicHitStatus {
        bitcoin_address: hit.bitcoin_address().to_string(),
        saved_filename: String::new(),
        timestamp_unix: hit.timestamp_unix(),
        storage_pending: true,
    });
    start_web_server(web_host, web_port, shared_state.clone()).unwrap_or_else(|error| {
        eprintln!("Cannot start recovered-hit dashboard: {error}");
        std::process::exit(1);
    });
    let path = wait_for_hit_persistence(hit, &shared_state);
    if !SHUTDOWN_SIGNAL.load(Ordering::SeqCst) {
        init_claim_service(&shared_state, path);
        while !SHUTDOWN_SIGNAL.load(Ordering::SeqCst) {
            thread::sleep(Duration::from_millis(250));
        }
    }
}

fn telegram_config_path() -> PathBuf {
    let home = env::var_os("HOME").unwrap_or_default();
    PathBuf::from(home).join("Library/Application Support/puzzle71/telegram.json")
}

fn init_claim_service(shared_state: &SharedSolverState, found_key_path: PathBuf) {
    let mut service = ClaimService::new(
        EsploraUtxoSource::new(CurlTransport),
        SlipstreamSubmitter::new(CurlTransport),
        FoundKeyFile::new(found_key_path),
        PathBuf::from("CLAIM_SUBMITTED.json"),
    );
    service.on_verified_hit();
    {
        let mut slot = shared_state.claim.lock().unwrap();
        *slot = Some(Box::new(service));
        if let Some(svc) = slot.as_ref() {
            *shared_state.claim_snapshot.lock().unwrap() = Some(svc.state());
        }
    }
    let claim = shared_state.claim.clone();
    let snapshot = shared_state.claim_snapshot.clone();
    thread::spawn(move || {
        loop {
            thread::sleep(Duration::from_secs(60));
            let mut slot = match claim.lock() {
                Ok(guard) => guard,
                Err(poisoned) => poisoned.into_inner(),
            };
            let Some(svc) = slot.as_mut() else {
                continue;
            };
            svc.poll();
            *snapshot.lock().unwrap() = Some(svc.state());
        }
    });
}

fn persist_checkpoint(
    checkpoint: &mut CheckpointStore,
    runtime_before_session: f64,
    active_runtime_session: Duration,
    shared_state: &SharedSolverState,
) -> Result<(), String> {
    checkpoint.persist_runtime(runtime_before_session + active_runtime_session.as_secs_f64())?;
    shared_state
        .checkpoint_saved_timestamp
        .store(checkpoint.last_saved_timestamp(), Ordering::SeqCst);
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
    println!("  --telegram-test                   Send one Telegram test message and exit");
    println!("  --electricity-price <EUR/kWh>     Configure electricity cost (default: 0.34)");
    println!("  --block-size <keys>               Divisor of 2^70 yielding at most 2^64-1 blocks");
    println!("  --help, -h                        Show this help message");
}
