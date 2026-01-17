//! Benchmarks for the domain blocker.

use criterion::{BenchmarkId, Criterion, black_box, criterion_group, criterion_main};
use hickory_proto::rr::Name;
use std::str::FromStr;

use bluebox::dns::Blocker;

fn generate_blocklist(size: usize) -> Vec<String> {
    (0..size)
        .map(|i| {
            if i % 2 == 0 {
                format!("blocked{i}.com")
            } else {
                format!("*.ads{i}.net")
            }
        })
        .collect()
}

fn bench_is_blocked(c: &mut Criterion) {
    let mut group = c.benchmark_group("blocker_lookup");

    for size in &[10, 100, 1000, 10000] {
        let blocklist = generate_blocklist(*size);
        let blocker = Blocker::new(&blocklist);

        // Test blocked exact match (early in list)
        let blocked_exact = Name::from_str("blocked0.com").unwrap();
        group.bench_with_input(
            BenchmarkId::new("exact_hit", size),
            &(&blocker, &blocked_exact),
            |b, (blocker, name)| {
                b.iter(|| blocker.is_blocked(black_box(name)));
            },
        );

        // Test blocked wildcard match
        let blocked_wildcard = Name::from_str("tracking.ads1.net").unwrap();
        group.bench_with_input(
            BenchmarkId::new("wildcard_hit", size),
            &(&blocker, &blocked_wildcard),
            |b, (blocker, name)| {
                b.iter(|| blocker.is_blocked(black_box(name)));
            },
        );

        // Test not blocked (worst case - must check all patterns)
        let not_blocked = Name::from_str("google.com").unwrap();
        group.bench_with_input(
            BenchmarkId::new("miss", size),
            &(&blocker, &not_blocked),
            |b, (blocker, name)| {
                b.iter(|| blocker.is_blocked(black_box(name)));
            },
        );
    }

    group.finish();
}

fn bench_blocker_creation(c: &mut Criterion) {
    let mut group = c.benchmark_group("blocker_creation");

    for size in &[10, 100, 1000, 10000] {
        let blocklist = generate_blocklist(*size);
        group.bench_with_input(BenchmarkId::new("new", size), &blocklist, |b, list| {
            b.iter(|| Blocker::new(black_box(list)));
        });
    }

    group.finish();
}

criterion_group!(benches, bench_is_blocked, bench_blocker_creation);
criterion_main!(benches);
