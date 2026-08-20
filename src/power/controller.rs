//! Dynamic Power Controller and Hysteresis Governor.

use crate::power::monitor::{PowerMonitor, SystemMetrics};
use std::time::Duration;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PowerMode {
    Eco,
    Balanced,
    High,
    Full,
    Auto,
}

impl std::str::FromStr for PowerMode {
    type Err = &'static str;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "eco" => Ok(Self::Eco),
            "balanced" => Ok(Self::Balanced),
            "high" => Ok(Self::High),
            "full" => Ok(Self::Full),
            "auto" => Ok(Self::Auto),
            _ => Err("Invalid power mode"),
        }
    }
}

impl PowerMode {
    pub fn name(&self) -> &'static str {
        match self {
            Self::Eco => "ECO",
            Self::Balanced => "BALANCED",
            Self::High => "HIGH",
            Self::Full => "FULL",
            Self::Auto => "AUTO",
        }
    }
}

pub struct PowerGovernor {
    pub mode: PowerMode,
    pub monitor: PowerMonitor,
    pub current_duty_cycle: f32,
    target_power_watts: f32,
    smoothing_factor: f32,
}

pub const MAX_GPU_DUTY_CYCLE: f32 = 0.90;

impl PowerGovernor {
    pub fn new(mode: PowerMode) -> Self {
        let (duty, target_w) = Self::mode_targets(mode);

        Self {
            mode,
            monitor: PowerMonitor::new(),
            current_duty_cycle: duty.min(MAX_GPU_DUTY_CYCLE),
            target_power_watts: target_w,
            smoothing_factor: 0.15, // Exponential smoothing for hysteresis
        }
    }

    pub fn set_mode(&mut self, mode: PowerMode) {
        if self.mode == mode {
            return;
        }

        self.mode = mode;
        let (duty, target_w) = Self::mode_targets(mode);
        self.current_duty_cycle = duty;
        self.target_power_watts = target_w;
    }

    pub fn target_duty_cycle(&self) -> f32 {
        self.current_duty_cycle.min(MAX_GPU_DUTY_CYCLE)
    }

    pub fn required_idle_duration(&self, gpu_active_duration: Duration) -> Duration {
        let duty = self.target_duty_cycle().clamp(0.05, MAX_GPU_DUTY_CYCLE) as f64;
        Duration::from_secs_f64(gpu_active_duration.as_secs_f64() * ((1.0 / duty) - 1.0))
    }

    fn mode_targets(mode: PowerMode) -> (f32, f32) {
        match mode {
            PowerMode::Eco => (0.40, 15.0),
            PowerMode::Balanced => (0.70, 22.0),
            PowerMode::High => (0.85, 26.0),
            PowerMode::Full => (MAX_GPU_DUTY_CYCLE, 28.0),
            PowerMode::Auto => (0.70, 22.0),
        }
    }

    /// Update power governor state based on recent system activity and mode
    pub fn update(&mut self) -> SystemMetrics {
        let metrics = self.monitor.sample(self.current_duty_cycle);

        match self.mode {
            PowerMode::Eco => {
                self.current_duty_cycle = 0.40;
            }
            PowerMode::Balanced => {
                self.current_duty_cycle = 0.70;
            }
            PowerMode::High => {
                self.current_duty_cycle = 0.85;
            }
            PowerMode::Full => {
                self.current_duty_cycle = MAX_GPU_DUTY_CYCLE;
            }
            PowerMode::Auto => {
                // In AUTO mode: Adjust duty cycle dynamically based on background load
                // If system load > 2.0 (other apps working), smoothly reduce duty cycle
                let external_load_pressure = metrics.system_load_1m.max(0.0);

                let desired_duty = if external_load_pressure > 3.0 {
                    0.20 // Heavy external activity: Drop to low ECO
                } else if external_load_pressure > 1.5 {
                    0.45 // Moderate activity: Drop to moderate
                } else if metrics.package_power_watts > self.target_power_watts + 3.0 {
                    (self.current_duty_cycle - 0.05).max(0.30)
                } else if metrics.package_power_watts < self.target_power_watts - 2.0 {
                    (self.current_duty_cycle + 0.05).min(MAX_GPU_DUTY_CYCLE)
                } else {
                    self.current_duty_cycle
                };

                // Apply exponential smoothing (hysteresis) to prevent rapid bouncing
                self.current_duty_cycle = self.current_duty_cycle * (1.0 - self.smoothing_factor)
                    + desired_duty * self.smoothing_factor;
            }
        }

        self.current_duty_cycle = self.current_duty_cycle.min(MAX_GPU_DUTY_CYCLE);

        metrics
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_mode_is_capped_at_ninety_percent() {
        for mode in [
            PowerMode::Eco,
            PowerMode::Balanced,
            PowerMode::High,
            PowerMode::Full,
            PowerMode::Auto,
        ] {
            let mut governor = PowerGovernor::new(mode);
            governor.update();
            assert!(governor.target_duty_cycle() <= 0.90);
        }
    }

    #[test]
    fn full_mode_adds_required_idle_time_for_ninety_percent_duty() {
        let governor = PowerGovernor::new(PowerMode::Full);
        let idle = governor.required_idle_duration(Duration::from_millis(900));
        assert!(idle >= Duration::from_millis(100));
        assert!(idle < Duration::from_micros(100_100));
    }

    #[test]
    fn changing_mode_refreshes_all_targets() {
        let mut governor = PowerGovernor::new(PowerMode::High);
        governor.set_mode(PowerMode::Auto);
        assert_eq!(governor.mode, PowerMode::Auto);
        assert!((governor.target_duty_cycle() - 0.70).abs() < f32::EPSILON);
        assert!((governor.target_power_watts - 22.0).abs() < f32::EPSILON);
    }
}
