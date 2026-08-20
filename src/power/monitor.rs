//! macOS System Metrics and SoC Power Monitoring.
//!
//! Provides lightweight, non-blocking sampling of CPU load, system activity,
//! and SoC package power without external dependencies.

use std::time::Instant;

#[derive(Debug, Clone, Copy)]
pub struct SystemMetrics {
    pub cpu_load_pct: f32,
    pub system_load_1m: f32,
    pub package_power_watts: f32,
    pub soc_temp_celsius: f32,
    pub timestamp: Instant,
}

pub struct PowerMonitor {
    last_sample: Instant,
    last_process_cpu_secs: f64,
    logical_cpu_count: f32,
    base_idle_power_watts: f32,
    tdp_power_watts: f32,
}

impl Default for PowerMonitor {
    fn default() -> Self {
        Self::new()
    }
}

impl PowerMonitor {
    pub fn new() -> Self {
        Self {
            last_sample: Instant::now(),
            last_process_cpu_secs: get_process_cpu_seconds(),
            logical_cpu_count: logical_cpu_count(),
            base_idle_power_watts: 4.5, // Base idle power for M4 / Apple Silicon Mac
            tdp_power_watts: 28.0,      // Max package target for standard Mac mini
        }
    }

    /// Sample system metrics (load, estimated SoC power, temperature)
    pub fn sample(&mut self, gpu_active_ratio: f32) -> SystemMetrics {
        let now = Instant::now();
        let process_cpu_secs = get_process_cpu_seconds();
        let wall_secs = now.duration_since(self.last_sample).as_secs_f64();
        let cpu_delta = (process_cpu_secs - self.last_process_cpu_secs).max(0.0);

        let cpu_load = if wall_secs > 0.0 {
            ((cpu_delta / wall_secs) / self.logical_cpu_count as f64 * 100.0).clamp(0.0, 100.0)
                as f32
        } else {
            0.0
        };

        self.last_process_cpu_secs = process_cpu_secs;
        self.last_sample = now;

        // Load average (1 min)
        let mut loadavg = [0.0f64; 3];
        let sys_load_1m = unsafe {
            if libc::getloadavg(loadavg.as_mut_ptr(), 3) > 0 {
                loadavg[0] as f32
            } else {
                0.0
            }
        };

        // Realistically estimate SoC Package Power based on active CPU & GPU compute ratio
        // Idle base: ~4-5W, Full GPU+CPU load: ~22-30W on Mac mini M4
        let estimated_power = self.base_idle_power_watts
            + (gpu_active_ratio.clamp(0.0, 1.0)
                * (self.tdp_power_watts - self.base_idle_power_watts)
                * 0.85)
            + ((cpu_load / 100.0).clamp(0.0, 1.0) * 4.0);

        // Approximate SoC thermal junction temperature
        let estimated_temp = 38.0 + (estimated_power / self.tdp_power_watts) * 32.0;

        SystemMetrics {
            cpu_load_pct: cpu_load,
            system_load_1m: sys_load_1m,
            package_power_watts: estimated_power,
            soc_temp_celsius: estimated_temp,
            timestamp: now,
        }
    }
}

fn get_process_cpu_seconds() -> f64 {
    let mut usage = std::mem::MaybeUninit::<libc::rusage>::zeroed();
    let result = unsafe { libc::getrusage(libc::RUSAGE_SELF, usage.as_mut_ptr()) };
    if result != 0 {
        return 0.0;
    }

    let usage = unsafe { usage.assume_init() };
    timeval_seconds(usage.ru_utime) + timeval_seconds(usage.ru_stime)
}

fn timeval_seconds(value: libc::timeval) -> f64 {
    value.tv_sec as f64 + value.tv_usec as f64 / 1_000_000.0
}

fn logical_cpu_count() -> f32 {
    let count = unsafe { libc::sysconf(libc::_SC_NPROCESSORS_ONLN) };
    if count > 0 { count as f32 } else { 1.0 }
}
