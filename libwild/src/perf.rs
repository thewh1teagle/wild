use crate::args::CounterKind;

/// Process-global counters used to prove that PE performance work removes redundant work.
///
/// The counters are enabled by the existing `wip` feature. Keeping the API present in all builds
/// lets instrumented call sites remain unconditional; without `wip`, increments inline to no-ops.
#[allow(dead_code, unused_imports)]
pub(crate) mod removal_counters {
    /// Whether removal counters collect data in this build.
    pub(crate) const ENABLED: bool = cfg!(any(feature = "wip", test));

    /// A point-in-time, per-counter snapshot.
    ///
    /// Snapshots use relaxed loads and are therefore not a transactional view while other threads
    /// are incrementing counters. Take milestone snapshots only after the measured phase joins its
    /// worker threads.
    #[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
    pub(crate) struct Snapshot {
        pub(crate) name_bytes_allocated: u64,
        pub(crate) name_hash_ops: u64,
        pub(crate) relocation_decodes: u64,
        pub(crate) bytes_copied: u64,
        pub(crate) object_full_parse_passes: u64,
        pub(crate) archive_member_probes: u64,
        pub(crate) selected_members: u64,
        pub(crate) hot_phase_allocations: u64,
    }

    impl Snapshot {
        /// Computes a saturating per-counter delta from an earlier snapshot.
        pub(crate) fn delta_since(self, earlier: Self) -> Self {
            Self {
                name_bytes_allocated: self
                    .name_bytes_allocated
                    .saturating_sub(earlier.name_bytes_allocated),
                name_hash_ops: self.name_hash_ops.saturating_sub(earlier.name_hash_ops),
                relocation_decodes: self
                    .relocation_decodes
                    .saturating_sub(earlier.relocation_decodes),
                bytes_copied: self.bytes_copied.saturating_sub(earlier.bytes_copied),
                object_full_parse_passes: self
                    .object_full_parse_passes
                    .saturating_sub(earlier.object_full_parse_passes),
                archive_member_probes: self
                    .archive_member_probes
                    .saturating_sub(earlier.archive_member_probes),
                selected_members: self
                    .selected_members
                    .saturating_sub(earlier.selected_members),
                hot_phase_allocations: self
                    .hot_phase_allocations
                    .saturating_sub(earlier.hot_phase_allocations),
            }
        }
    }

    #[cfg(any(feature = "wip", test))]
    mod implementation {
        use super::Snapshot;
        use std::sync::atomic::{AtomicU64, Ordering};

        static NAME_BYTES_ALLOCATED: AtomicU64 = AtomicU64::new(0);
        static NAME_HASH_OPS: AtomicU64 = AtomicU64::new(0);
        static RELOCATION_DECODES: AtomicU64 = AtomicU64::new(0);
        static BYTES_COPIED: AtomicU64 = AtomicU64::new(0);
        static OBJECT_FULL_PARSE_PASSES: AtomicU64 = AtomicU64::new(0);
        static ARCHIVE_MEMBER_PROBES: AtomicU64 = AtomicU64::new(0);
        static SELECTED_MEMBERS: AtomicU64 = AtomicU64::new(0);
        static HOT_PHASE_ALLOCATIONS: AtomicU64 = AtomicU64::new(0);

        macro_rules! counter_api {
            ($add:ident, $increment:ident, $counter:ident) => {
                #[inline]
                pub(crate) fn $add(amount: u64) {
                    $counter.fetch_add(amount, Ordering::Relaxed);
                }

                #[inline]
                pub(crate) fn $increment() {
                    $add(1);
                }
            };
        }

        counter_api!(
            add_name_bytes_allocated,
            increment_name_bytes_allocated,
            NAME_BYTES_ALLOCATED
        );
        counter_api!(add_name_hash_ops, increment_name_hash_ops, NAME_HASH_OPS);
        counter_api!(
            add_relocation_decodes,
            increment_relocation_decodes,
            RELOCATION_DECODES
        );
        counter_api!(add_bytes_copied, increment_bytes_copied, BYTES_COPIED);
        counter_api!(
            add_object_full_parse_passes,
            increment_object_full_parse_passes,
            OBJECT_FULL_PARSE_PASSES
        );
        counter_api!(
            add_archive_member_probes,
            increment_archive_member_probes,
            ARCHIVE_MEMBER_PROBES
        );
        counter_api!(
            add_selected_members,
            increment_selected_members,
            SELECTED_MEMBERS
        );
        counter_api!(
            add_hot_phase_allocations,
            increment_hot_phase_allocations,
            HOT_PHASE_ALLOCATIONS
        );

        pub(crate) fn snapshot() -> Snapshot {
            Snapshot {
                name_bytes_allocated: NAME_BYTES_ALLOCATED.load(Ordering::Relaxed),
                name_hash_ops: NAME_HASH_OPS.load(Ordering::Relaxed),
                relocation_decodes: RELOCATION_DECODES.load(Ordering::Relaxed),
                bytes_copied: BYTES_COPIED.load(Ordering::Relaxed),
                object_full_parse_passes: OBJECT_FULL_PARSE_PASSES.load(Ordering::Relaxed),
                archive_member_probes: ARCHIVE_MEMBER_PROBES.load(Ordering::Relaxed),
                selected_members: SELECTED_MEMBERS.load(Ordering::Relaxed),
                hot_phase_allocations: HOT_PHASE_ALLOCATIONS.load(Ordering::Relaxed),
            }
        }

        pub(crate) fn reset() {
            NAME_BYTES_ALLOCATED.store(0, Ordering::Relaxed);
            NAME_HASH_OPS.store(0, Ordering::Relaxed);
            RELOCATION_DECODES.store(0, Ordering::Relaxed);
            BYTES_COPIED.store(0, Ordering::Relaxed);
            OBJECT_FULL_PARSE_PASSES.store(0, Ordering::Relaxed);
            ARCHIVE_MEMBER_PROBES.store(0, Ordering::Relaxed);
            SELECTED_MEMBERS.store(0, Ordering::Relaxed);
            HOT_PHASE_ALLOCATIONS.store(0, Ordering::Relaxed);
        }
    }

    #[cfg(not(any(feature = "wip", test)))]
    mod implementation {
        use super::Snapshot;

        macro_rules! disabled_counter_api {
            ($add:ident, $increment:ident) => {
                #[inline(always)]
                pub(crate) fn $add(_amount: u64) {}

                #[inline(always)]
                pub(crate) fn $increment() {}
            };
        }

        disabled_counter_api!(add_name_bytes_allocated, increment_name_bytes_allocated);
        disabled_counter_api!(add_name_hash_ops, increment_name_hash_ops);
        disabled_counter_api!(add_relocation_decodes, increment_relocation_decodes);
        disabled_counter_api!(add_bytes_copied, increment_bytes_copied);
        disabled_counter_api!(
            add_object_full_parse_passes,
            increment_object_full_parse_passes
        );
        disabled_counter_api!(add_archive_member_probes, increment_archive_member_probes);
        disabled_counter_api!(add_selected_members, increment_selected_members);
        disabled_counter_api!(add_hot_phase_allocations, increment_hot_phase_allocations);

        #[inline(always)]
        pub(crate) fn snapshot() -> Snapshot {
            Snapshot::default()
        }

        #[inline(always)]
        pub(crate) fn reset() {}
    }

    pub(crate) use implementation::{
        add_archive_member_probes, add_bytes_copied, add_hot_phase_allocations,
        add_name_bytes_allocated, add_name_hash_ops, add_object_full_parse_passes,
        add_relocation_decodes, add_selected_members, increment_archive_member_probes,
        increment_bytes_copied, increment_hot_phase_allocations, increment_name_bytes_allocated,
        increment_name_hash_ops, increment_object_full_parse_passes, increment_relocation_decodes,
        increment_selected_members, reset, snapshot,
    };

    #[cfg(test)]
    mod tests {
        use super::*;
        use std::sync::Mutex;

        // The counters are process-global, so serialize tests that reset them.
        static TEST_LOCK: Mutex<()> = Mutex::new(());

        #[test]
        fn add_increment_snapshot_reset_and_delta() {
            let _lock = TEST_LOCK.lock().unwrap();
            reset();
            let before = snapshot();

            add_name_bytes_allocated(11);
            increment_name_bytes_allocated();
            add_name_hash_ops(12);
            increment_name_hash_ops();
            add_relocation_decodes(13);
            increment_relocation_decodes();
            add_bytes_copied(14);
            increment_bytes_copied();
            add_object_full_parse_passes(15);
            increment_object_full_parse_passes();
            add_archive_member_probes(16);
            increment_archive_member_probes();
            add_selected_members(17);
            increment_selected_members();
            add_hot_phase_allocations(18);
            increment_hot_phase_allocations();

            let expected = Snapshot {
                name_bytes_allocated: 12,
                name_hash_ops: 13,
                relocation_decodes: 14,
                bytes_copied: 15,
                object_full_parse_passes: 16,
                archive_member_probes: 17,
                selected_members: 18,
                hot_phase_allocations: 19,
            };
            assert_eq!(snapshot(), expected);
            assert_eq!(snapshot().delta_since(before), expected);

            reset();
            assert_eq!(snapshot(), Snapshot::default());
        }

        #[test]
        fn relaxed_counters_do_not_lose_concurrent_updates() {
            let _lock = TEST_LOCK.lock().unwrap();
            reset();
            const THREADS: u64 = 8;
            const ITERATIONS: u64 = 10_000;
            let handles = (0..THREADS)
                .map(|_| {
                    std::thread::spawn(|| {
                        for _ in 0..ITERATIONS {
                            increment_name_hash_ops();
                            add_bytes_copied(2);
                            increment_relocation_decodes();
                        }
                    })
                })
                .collect::<Vec<_>>();
            for handle in handles {
                handle.join().unwrap();
            }

            let result = snapshot();
            // These counters are intentionally process-global, so unrelated tests running in
            // parallel may add work after our reset. Our own increments must never be lost.
            assert!(result.name_hash_ops >= THREADS * ITERATIONS);
            assert!(result.bytes_copied >= THREADS * ITERATIONS * 2);
            assert!(result.relocation_decodes >= THREADS * ITERATIONS);
            reset();
        }
    }
}

pub(crate) struct CounterList {
    counters: Vec<perf_event::Counter>,
}

impl CounterList {
    pub(crate) fn from_kinds(opts: &[CounterKind]) -> Self {
        let counters = opts
            .iter()
            .filter_map(|kind| {
                perf_event::Builder::new()
                    .inherit(true)
                    .kind(counter_to_perf_event(*kind))
                    .build()
                    .ok()
            })
            .collect();

        CounterList { counters }
    }

    pub(crate) fn start(&mut self) {
        for counter in &mut self.counters {
            let _ = counter.reset();
            let _ = counter.enable();
        }
    }

    pub(crate) fn disable_and_read(&mut self) -> Vec<u64> {
        self.counters
            .iter_mut()
            .filter_map(|counter| counter.disable().ok().and_then(|()| counter.read().ok()))
            .collect()
    }
}

fn counter_to_perf_event(kind: CounterKind) -> perf_event::events::Event {
    match kind {
        CounterKind::Cycles => perf_event::events::Hardware::CPU_CYCLES.into(),
        CounterKind::Instructions => perf_event::events::Hardware::INSTRUCTIONS.into(),
        CounterKind::CacheMisses => perf_event::events::Hardware::CACHE_MISSES.into(),
        CounterKind::BranchMisses => perf_event::events::Hardware::BRANCH_MISSES.into(),
        CounterKind::PageFaults => perf_event::events::Software::PAGE_FAULTS.into(),
        CounterKind::PageFaultsMinor => perf_event::events::Software::PAGE_FAULTS_MIN.into(),
        CounterKind::PageFaultsMajor => perf_event::events::Software::PAGE_FAULTS_MAJ.into(),
        CounterKind::L1dRead => perf_event::events::Cache {
            which: perf_event::events::WhichCache::L1D,
            operation: perf_event::events::CacheOp::READ,
            result: perf_event::events::CacheResult::ACCESS,
        }
        .into(),
        CounterKind::L1dMiss => perf_event::events::Cache {
            which: perf_event::events::WhichCache::L1D,
            operation: perf_event::events::CacheOp::READ,
            result: perf_event::events::CacheResult::MISS,
        }
        .into(),
    }
}
