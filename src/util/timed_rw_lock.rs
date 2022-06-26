use parking_lot::Mutex;
use parking_lot::RwLock;
use std::time::{Duration, Instant};

/// Adds instrumentation for timing the performance of the lock.
pub struct TimedRwLock<T> {
    id: String,
    lock: RwLock<T>,
    log_threshold: Duration,
}

impl<T> TimedRwLock<T> {
    pub fn new(x: T, id: impl Into<String>, timeout: Duration) -> Self {
        TimedRwLock {
            id: id.into(),
            lock: RwLock::new(x),
            log_threshold: timeout,
        }
    }

    pub fn write(&self) -> parking_lot::RwLockWriteGuard<T> {
        loop {
            let mut elapsed = Duration::from_secs(0);
            match self.lock.try_write_for(self.log_threshold) {
                Some(guard) => break guard,
                None => {
                    elapsed += self.log_threshold;
                    warn!(
                        "Write lock taking a long time to acquire, id {} wait_ms {}",
                        &self.id,
                        elapsed.as_millis()
                    );
                }
            }
        }
    }

    pub fn read(&self) -> parking_lot::RwLockReadGuard<T> {
        loop {
            let mut elapsed = Duration::from_secs(0);
            match self.lock.try_read_for(self.log_threshold) {
                Some(guard) => break guard,
                None => {
                    elapsed += self.log_threshold;
                    warn!(
                        "Read lock taking a long time to acquire, id {} wait_ms {}",
                        &self.id,
                        elapsed.as_millis(),
                    );
                }
            }
        }
    }
}

/// Adds instrumentation for timing the performance of the lock.
pub struct TimedMutex<T> {
    id: String,
    lock: Mutex<T>,
    log_threshold: Duration,
}

impl<T> TimedMutex<T> {
    pub fn new(x: T, id: impl Into<String>, timeout: Duration) -> Self {
        TimedMutex {
            id: id.into(),
            lock: Mutex::new(x),
            log_threshold: timeout.clone(),
        }
    }

    pub fn lock(&self) -> parking_lot::MutexGuard<T> {
        let start = Instant::now();
        let guard = self.lock.lock();
        let elapsed = start.elapsed();
        if elapsed > self.log_threshold {
            warn!(
                "Mutex lock took a long time to acquire id {} wait_ms {}",
                &self.id,
                elapsed.as_millis(),
            );
        }
        guard
    }
}
