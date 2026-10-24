//! Dispatch sizes shared by the actual search and its benchmark.

use crate::power::controller::PowerMode;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DispatchProfile {
    pub threads: usize,
    pub steps: u32,
}

impl DispatchProfile {
    pub fn batch_keys(self) -> u128 {
        self.threads as u128 * self.steps as u128
    }
}

pub const ALL_POWER_MODES: [PowerMode; 5] = [
    PowerMode::Eco,
    PowerMode::Balanced,
    PowerMode::High,
    PowerMode::Full,
    PowerMode::Auto,
];

pub fn dispatch_profile(mode: PowerMode) -> DispatchProfile {
    match mode {
        PowerMode::Eco => DispatchProfile {
            threads: 1024,
            steps: 128,
        },
        PowerMode::Balanced | PowerMode::Auto => DispatchProfile {
            threads: 2048,
            steps: 1024,
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn production_profiles_cover_all_modes_with_the_documented_batch_sizes() {
        let sizes: Vec<_> = ALL_POWER_MODES
            .into_iter()
            .map(|mode| dispatch_profile(mode).batch_keys())
            .collect();
        assert_eq!(
            sizes,
            vec![131_072, 2_097_152, 524_288, 1_048_576, 2_097_152]
        );
    }
}
