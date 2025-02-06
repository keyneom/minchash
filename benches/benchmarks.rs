use criterion::{black_box, criterion_group, criterion_main, Criterion};
use minchash::MultisetHash;

fn benchmark_add_individual(c: &mut Criterion) {
    let elements: Vec<String> = (0..10_000).map(|i| format!("item{}", i)).collect();

    c.bench_function("Add elements individually", |b| {
        b.iter(|| {
            let mut ms = MultisetHash::new();
            for elem in &elements {
                ms.add(black_box(elem));
            }
        })
    });
}

fn benchmark_add_elements_parallel(c: &mut Criterion) {
    let elements: Vec<String> = (0..10_000).map(|i| format!("item{}", i)).collect();

    c.bench_function("Add elements in parallel", |b| {
        b.iter(|| {
            let mut ms = MultisetHash::new();
            ms.add_elements(&elements);
        })
    });
}

criterion_group!(benches, benchmark_add_individual, benchmark_add_elements_parallel);
criterion_main!(benches);
