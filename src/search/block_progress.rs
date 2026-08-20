//! Tracks one selected block until every key in it has completed successfully.

#[derive(Debug, Clone, Copy)]
pub struct BlockProgress {
    expected_keys: u128,
    completed_keys: u128,
}

impl BlockProgress {
    pub fn new(expected_keys: u128) -> Result<Self, &'static str> {
        if expected_keys == 0 {
            return Err("Block size must be greater than zero");
        }
        Ok(Self {
            expected_keys,
            completed_keys: 0,
        })
    }

    pub fn record_completed(&mut self, keys: u128) -> Result<(), &'static str> {
        let next = self
            .completed_keys
            .checked_add(keys)
            .ok_or("Block progress overflow")?;
        if next > self.expected_keys {
            return Err("Dispatch completed more keys than the selected block contains");
        }
        self.completed_keys = next;
        Ok(())
    }

    pub fn remaining_keys(&self) -> u128 {
        self.expected_keys - self.completed_keys
    }

    pub fn completed_keys(&self) -> u128 {
        self.completed_keys
    }

    pub fn is_complete(&self) -> bool {
        self.completed_keys == self.expected_keys
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn partial_block_is_never_complete() {
        let mut progress = BlockProgress::new(100).unwrap();
        progress.record_completed(60).unwrap();
        assert!(!progress.is_complete());
        assert_eq!(progress.remaining_keys(), 40);
    }

    #[test]
    fn exact_block_is_complete() {
        let mut progress = BlockProgress::new(100).unwrap();
        progress.record_completed(60).unwrap();
        progress.record_completed(40).unwrap();
        assert!(progress.is_complete());
        assert_eq!(progress.remaining_keys(), 0);
    }

    #[test]
    fn overrun_is_rejected() {
        let mut progress = BlockProgress::new(100).unwrap();
        assert!(progress.record_completed(101).is_err());
        assert!(!progress.is_complete());
    }
}
