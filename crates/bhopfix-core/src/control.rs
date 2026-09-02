//! Cross-process control block shared by the Windows patcher and hook DLL.

use std::sync::atomic::{AtomicU8, AtomicU32, AtomicU64, Ordering};

/// Magic identifying a mapped bunnyhopfix control block (`BHFX`).
pub const MAGIC: u32 = u32::from_le_bytes(*b"BHFX");
/// Version of the shared layout.
pub const VERSION: u32 = 5;
/// Number of fixed log records retained in shared memory.
pub const LOG_SLOTS: usize = 64;
/// Maximum UTF-8 bytes in one shared log record.
pub const LOG_BYTES: usize = 240;

/// Severity carried with one Windows hook log record.
#[repr(u8)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LogLevel {
    /// A feature or cleanup operation failed.
    Error = 1,
    /// A recoverable condition requires user attention.
    Warn = 2,
    /// Normal lifecycle and feature status.
    Info = 3,
    /// Opt-in resolver or input instrumentation.
    Debug = 4,
}

impl TryFrom<u8> for LogLevel {
    type Error = ();

    fn try_from(value: u8) -> Result<Self, ()> {
        match value {
            value if value == Self::Error as u8 => Ok(Self::Error),
            value if value == Self::Warn as u8 => Ok(Self::Warn),
            value if value == Self::Info as u8 => Ok(Self::Info),
            value if value == Self::Debug as u8 => Ok(Self::Debug),
            _ => Err(()),
        }
    }
}

/// Hook worker has not started.
pub const STATE_CREATED: u32 = 0;
/// Hook worker is resolving and installing features.
pub const STATE_STARTING: u32 = 1;
/// Hook worker finished installation and is servicing the game.
pub const STATE_READY: u32 = 2;
/// Controller requested shutdown and hooks are being restored.
pub const STATE_STOPPING: u32 = 3;
/// Every installed hook and patch has been restored.
pub const STATE_STOPPED: u32 = 4;
/// Hook worker refused startup; [`ControlBlock::error`] contains a code.
pub const STATE_FAILED: u32 = 5;

/// Enable resolver and input instrumentation logs.
pub const FLAG_DEBUG: u32 = 1 << 0;
/// Stamp `m_rawinput` to 2 once after spawn.
pub const FLAG_FORCE_RAWINPUT2: u32 = 1 << 1;
/// Automatically record one POV demo per map.
pub const FLAG_DEMOS: u32 = 1 << 2;
/// Do not install the viewpunch remover.
pub const FLAG_KEEP_VIEWPUNCH: u32 = 1 << 3;
/// Disable SourceJump API lookups.
pub const FLAG_NO_SOURCEJUMP: u32 = 1 << 4;

/// Tick-aligned raw-input hooks are fully installed.
pub const FEATURE_RAWINPUT2: u64 = 1 << 0;
/// Viewpunch application sites are disabled.
pub const FEATURE_VIEWPUNCH: u64 = 1 << 1;
/// Fastdl map-version interception is installed.
pub const FEATURE_FASTDL: u64 = 1 << 2;
/// Validated `IVEngineClient::ClientCmd` integration is available.
pub const FEATURE_CONSOLE: u64 = 1 << 3;
/// Download progress polling and completion flash are available.
pub const FEATURE_DOWNLOADS: u64 = 1 << 4;
/// Windows exclusive-fullscreen preservation patches are available.
pub const FEATURE_FULLSCREEN: u64 = 1 << 5;
/// SourceJump lookups and in-console results are enabled.
pub const FEATURE_SOURCEJUMP: u64 = 1 << 6;

/// One fixed-size record in the cross-process log ring.
#[repr(C)]
pub struct LogSlot {
    sequence: AtomicU32,
    len: AtomicU32,
    level: AtomicU8,
    data: [AtomicU8; LOG_BYTES],
}

impl LogSlot {
    const fn new() -> Self {
        Self {
            sequence: AtomicU32::new(0),
            len: AtomicU32::new(0),
            level: AtomicU8::new(LogLevel::Info as u8),
            data: [const { AtomicU8::new(0) }; LOG_BYTES],
        }
    }
}

/// Shared Windows hook lifecycle, feature status, counters and bounded logs.
#[repr(C)]
pub struct ControlBlock {
    /// [`MAGIC`].
    pub magic: u32,
    /// [`VERSION`].
    pub version: u32,
    /// PID of the patcher that owns this session.
    pub controller_pid: u32,
    /// Session configuration flags.
    pub flags: u32,
    /// One of the `STATE_*` constants.
    pub state: AtomicU32,
    /// Nonzero platform error or resolver-specific failure code.
    pub error: AtomicU32,
    /// Controller sets this to request restoration and shutdown.
    pub stop: AtomicU32,
    /// One only after the hook worker has exited every callback path and no
    /// process memory still points into the DLL. The controller must not call
    /// `FreeLibrary` unless this is set.
    pub unload_safe: AtomicU32,
    /// Installed `FEATURE_*` bits.
    pub features: AtomicU64,
    /// Number of captured raw mouse messages.
    pub raw_events: AtomicU64,
    /// Number of tick-aligned accumulator serves.
    pub raw_serves: AtomicU64,
    log_writer: AtomicU32,
    log_write: AtomicU32,
    logs: [LogSlot; LOG_SLOTS],
}

// The block lives in pagefile-backed shared memory and all mutable fields are
// atomics or slots following the publication protocol above.

impl ControlBlock {
    /// Construct a fresh controller-owned block before copying it into a mapped
    /// view.
    pub const fn new(controller_pid: u32, flags: u32) -> Self {
        Self {
            magic: MAGIC,
            version: VERSION,
            controller_pid,
            flags,
            state: AtomicU32::new(STATE_CREATED),
            error: AtomicU32::new(0),
            stop: AtomicU32::new(0),
            unload_safe: AtomicU32::new(0),
            features: AtomicU64::new(0),
            raw_events: AtomicU64::new(0),
            raw_serves: AtomicU64::new(0),
            log_writer: AtomicU32::new(0),
            log_write: AtomicU32::new(0),
            logs: [const { LogSlot::new() }; LOG_SLOTS],
        }
    }

    /// Publish one bounded UTF-8 log record. A tiny global writer lock keeps
    /// sequence allocation and slot publication ordered even when callbacks
    /// from several game threads log concurrently.
    pub fn push_log(&self, level: LogLevel, message: &str) {
        while self
            .log_writer
            .compare_exchange_weak(0, 1, Ordering::Acquire, Ordering::Relaxed)
            .is_err()
        {
            std::hint::spin_loop();
        }
        let sequence = self
            .log_write
            .fetch_add(1, Ordering::Relaxed)
            .wrapping_add(1);
        let slot = &self.logs[(sequence.wrapping_sub(1) as usize) % LOG_SLOTS];
        slot.sequence.store(0, Ordering::Release);
        let bytes = message.as_bytes();
        let len = bytes.len().min(LOG_BYTES);
        for (destination, &byte) in slot.data.iter().zip(&bytes[..len]) {
            destination.store(byte, Ordering::Relaxed);
        }
        slot.level.store(level as u8, Ordering::Relaxed);
        slot.len.store(len as u32, Ordering::Relaxed);
        slot.sequence.store(sequence, Ordering::Release);
        self.log_writer.store(0, Ordering::Release);
    }

    /// Copy log record `sequence` if it is still present and fully published.
    pub fn read_log(&self, sequence: u32, out: &mut [u8; LOG_BYTES]) -> Option<(LogLevel, usize)> {
        if sequence == 0 {
            return None;
        }
        let slot = &self.logs[(sequence.wrapping_sub(1) as usize) % LOG_SLOTS];
        if slot.sequence.load(Ordering::Acquire) != sequence {
            return None;
        }
        let level = LogLevel::try_from(slot.level.load(Ordering::Relaxed)).ok()?;
        let len = (slot.len.load(Ordering::Relaxed) as usize).min(LOG_BYTES);
        // Atomic bytes avoid a data race if a writer starts reusing this slot
        // after the first sequence check. The second check rejects that torn
        // snapshot.
        for (destination, source) in out[..len].iter_mut().zip(&slot.data[..len]) {
            *destination = source.load(Ordering::Relaxed);
        }
        (slot.sequence.load(Ordering::Acquire) == sequence).then_some((level, len))
    }

    /// Latest sequence allocated by a writer.
    pub fn latest_log_sequence(&self) -> u32 {
        self.log_write.load(Ordering::Acquire)
    }
}

#[cfg(test)]
mod tests {
    use std::sync::{Arc, atomic::Ordering};

    use super::*;

    #[test]
    fn log_records_are_bounded() {
        let block = ControlBlock::new(7, 0);
        block.push_log(LogLevel::Warn, &"x".repeat(LOG_BYTES + 32));
        let mut output = [0u8; LOG_BYTES];
        let (level, length) = block.read_log(1, &mut output).unwrap();
        assert_eq!(level, LogLevel::Warn);
        assert_eq!(length, LOG_BYTES);
        assert!(output.iter().all(|&byte| byte == b'x'));
    }

    #[test]
    fn unknown_log_levels_are_rejected() {
        let block = ControlBlock::new(7, 0);
        block.push_log(LogLevel::Info, "message");
        block.logs[0].level.store(u8::MAX, Ordering::Relaxed);

        assert!(block.read_log(1, &mut [0u8; LOG_BYTES]).is_none());
    }

    #[test]
    fn concurrent_log_writers_publish_the_latest_ring() {
        const WRITERS: usize = 8;
        const RECORDS: usize = 128;
        let block = Arc::new(ControlBlock::new(7, 0));
        let workers: Vec<_> = (0..WRITERS)
            .map(|worker| {
                let block = Arc::clone(&block);
                std::thread::spawn(move || {
                    for record in 0..RECORDS {
                        block.push_log(LogLevel::Info, &format!("writer={worker} record={record}"));
                    }
                })
            })
            .collect();
        for worker in workers {
            worker.join().unwrap();
        }

        let latest = block.latest_log_sequence();
        assert_eq!(latest, (WRITERS * RECORDS) as u32);
        for sequence in latest - LOG_SLOTS as u32 + 1..=latest {
            let mut output = [0u8; LOG_BYTES];
            let (level, length) = block.read_log(sequence, &mut output).unwrap();
            assert_eq!(level, LogLevel::Info);
            let message = std::str::from_utf8(&output[..length]).unwrap();
            assert!(message.starts_with("writer="));
        }
    }
}
